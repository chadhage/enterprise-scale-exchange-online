#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:EvidenceScript = Join-Path $script:SampleRoot 'scripts\Test-ExchangeOnlineBaseline.ps1'
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts\ExchangeOnlineBaseline.Common.psm1'
    Import-Module $script:ModulePath -Force -DisableNameChecking

    function Import-ApplicabilityEntitlementProjection {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:EvidenceScript,
            [ref]$tokens,
            [ref]$errors
        )
        @($errors) | Should -BeNullOrEmpty
        $functionAst = @($ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq 'Resolve-BaselineRegistryDecisionProjection'
                }, $true))
        $functionAst.Count | Should -Be 1
        $bodyText = $functionAst[0].Body.Extent.Text
        Set-Item -Path function:script:Resolve-BaselineRegistryDecisionProjection `
            -Value ([scriptblock]::Create($bodyText.Substring(1, $bodyText.Length - 2)))
    }

    function New-RegistryEntry {
        param(
            [string]$ControlId = 'PP-001',
            [object[]]$ApplicableProfile = @('Native', 'Gateway'),
            [string[]]$Omit = @()
        )

        $entry = [ordered]@{
            ControlId = $ControlId
            ApplicableProfile = @($ApplicableProfile)
        }
        foreach ($name in $Omit) { $entry.Remove($name) }
        [pscustomobject]$entry
    }

    function New-EntitlementDecision {
        param(
            [object]$Determined = $true,
            [object]$Entitled = $true,
            [string]$Status = 'Pass',
            [string]$Reason = 'The required service plan is enabled.',
            [string[]]$Omit = @()
        )

        $decision = [ordered]@{
            Determined = $Determined
            Entitled = $Entitled
            Status = $Status
            Reason = $Reason
        }
        foreach ($name in $Omit) { $decision.Remove($name) }
        [pscustomobject]$decision
    }

    function Invoke-Projection {
        param(
            [object[]]$Registry = @(
                (New-RegistryEntry -ControlId 'PP-001'),
                (New-RegistryEntry -ControlId 'PP-005' -ApplicableProfile @('Native'))
            ),
            [hashtable]$EntitlementByControl = @{
                'PP-001' = (New-EntitlementDecision)
            },
            [hashtable]$EvaluatedResultByControl = @{
                'PP-001' = [pscustomobject]@{ ControlId = 'PP-001'; Status = 'Fail'; Reason = 'Synthetic drift remains a failure.' }
            },
            [string]$SelectedProfile = 'Gateway'
        )

        Resolve-BaselineRegistryDecisionProjection -Registry $Registry `
            -SelectedProfile $SelectedProfile -EntitlementByControl $EntitlementByControl `
            -EvaluatedResultByControl $EvaluatedResultByControl
    }

    function Assert-UnresolvedProjection {
        param(
            [object[]]$Actual,
            [string]$Reason
        )

        @($Actual).Count | Should -Be 1
        $Actual[0].Status | Should -BeExactly 'Error'
        $Actual[0].Reason | Should -Match ([regex]::Escape($Reason))
        $Actual[0].Status | Should -Not -BeIn @('Pass', 'NotApplicable', 'ApprovedException')
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GATE-007 resolved applicability and entitlement projection' {
    Context 'Negative: unresolved applicability fails closed for its named reason' {
        It 'refuses an absent registry entry' {
            # Arrange
            Import-ApplicabilityEntitlementProjection
            $registry = @()

            # Act
            $actual = @(Invoke-Projection -Registry $registry)

            # Assert
            Assert-UnresolvedProjection -Actual $actual -Reason 'ApplicabilityRegistryEmpty'
        }

        It 'refuses a registry entry with no applicability declaration' {
            # Arrange
            Import-ApplicabilityEntitlementProjection
            $registry = @(New-RegistryEntry -Omit @('ApplicableProfile'))

            # Act
            $actual = @(Invoke-Projection -Registry $registry)

            # Assert
            Assert-UnresolvedProjection -Actual $actual -Reason 'ApplicabilityDeclarationMissing'
        }

        It 'refuses a partial applicability declaration containing a blank profile' {
            # Arrange
            Import-ApplicabilityEntitlementProjection
            $registry = @(New-RegistryEntry -ApplicableProfile @('Gateway', ''))

            # Act
            $actual = @(Invoke-Projection -Registry $registry)

            # Assert
            Assert-UnresolvedProjection -Actual $actual -Reason 'ApplicabilityDeclarationPartial'
        }

        It 'refuses an unknown selected profile' {
            # Arrange
            Import-ApplicabilityEntitlementProjection

            # Act
            $actual = @(Invoke-Projection -SelectedProfile 'Hybrid')

            # Assert
            Assert-UnresolvedProjection -Actual $actual -Reason 'ApplicabilityProfileUnknown'
        }

        It 'refuses conflicting registry declarations for one control' {
            # Arrange
            Import-ApplicabilityEntitlementProjection
            $registry = @(
                (New-RegistryEntry -ControlId 'PP-001' -ApplicableProfile @('Gateway')),
                (New-RegistryEntry -ControlId 'PP-001' -ApplicableProfile @('Native'))
            )

            # Act
            $actual = @(Invoke-Projection -Registry $registry)

            # Assert
            Assert-UnresolvedProjection -Actual $actual -Reason 'ApplicabilityDeclarationConflicting'
        }

        It 'does not turn a non-profile priority exclusion into NotApplicable' {
            # Arrange
            $control = [pscustomobject]@{
                Id = 'MDO-006'
                DeploymentProfile = @('MicrosoftNative', 'ThirdPartyGateway')
                RequiredServicePlan = @('ATP_ENTERPRISE')
                Priority = 'Low'
            }

            # Act
            $actual = Get-ControlApplicability -Control $control -DeploymentProfile 'ThirdPartyGateway' `
                -TenantServicePlan @('ATP_ENTERPRISE') -PriorityInScope @('Critical', 'High')

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match 'ApplicabilityPriorityUnresolved'
            $actual.Status | Should -Not -BeIn @('Pass', 'NotApplicable', 'ApprovedException')
        }
    }

    Context 'Negative: unresolved entitlement fails closed for its named reason' {
        It 'refuses an absent entitlement decision for an applicable control' {
            # Arrange
            Import-ApplicabilityEntitlementProjection
            $entitlement = @{}

            # Act
            $actual = @(Invoke-Projection -EntitlementByControl $entitlement)

            # Assert
            Assert-UnresolvedProjection -Actual @($actual | Where-Object ControlId -EQ 'PP-001') -Reason 'EntitlementDecisionMissing'
        }

        It 'refuses a partial entitlement decision' {
            # Arrange
            Import-ApplicabilityEntitlementProjection
            $entitlement = @{ 'PP-001' = (New-EntitlementDecision -Omit @('Reason')) }

            # Act
            $actual = @(Invoke-Projection -EntitlementByControl $entitlement)

            # Assert
            Assert-UnresolvedProjection -Actual @($actual | Where-Object ControlId -EQ 'PP-001') -Reason 'EntitlementDecisionPartial'
        }

        It 'refuses an entitlement decision that was not determined' {
            # Arrange
            Import-ApplicabilityEntitlementProjection
            $entitlement = @{ 'PP-001' = (New-EntitlementDecision -Determined $false -Entitled $false -Status 'NotEntitled') }

            # Act
            $actual = @(Invoke-Projection -EntitlementByControl $entitlement)

            # Assert
            Assert-UnresolvedProjection -Actual @($actual | Where-Object ControlId -EQ 'PP-001') -Reason 'EntitlementDecisionUnresolved'
        }

        It 'refuses a conflicting entitled status' {
            # Arrange
            Import-ApplicabilityEntitlementProjection
            $entitlement = @{ 'PP-001' = (New-EntitlementDecision -Entitled $true -Status 'NotEntitled') }

            # Act
            $actual = @(Invoke-Projection -EntitlementByControl $entitlement)

            # Assert
            Assert-UnresolvedProjection -Actual @($actual | Where-Object ControlId -EQ 'PP-001') -Reason 'EntitlementDecisionConflicting'
        }

        It 'does not let an unresolved entitlement inherit a successful evaluator status' {
            # Arrange
            Import-ApplicabilityEntitlementProjection
            $entitlement = @{ 'PP-001' = (New-EntitlementDecision -Determined $false -Status 'Pass') }
            $evaluated = @{ 'PP-001' = [pscustomobject]@{ ControlId = 'PP-001'; Status = 'ApprovedException'; Reason = 'Must not survive.' } }

            # Act
            $actual = @(Invoke-Projection -EntitlementByControl $entitlement -EvaluatedResultByControl $evaluated)

            # Assert
            Assert-UnresolvedProjection -Actual @($actual | Where-Object ControlId -EQ 'PP-001') -Reason 'EntitlementDecisionUnresolved'
        }

        It 'does not use NotApplicable for a resolved entitlement denial' {
            # Arrange
            Import-ApplicabilityEntitlementProjection
            $entitlement = @{ 'PP-001' = (New-EntitlementDecision -Entitled $false -Status 'NotEntitled') }

            # Act
            $actual = @(Invoke-Projection -EntitlementByControl $entitlement)

            # Assert
            @($actual | Where-Object ControlId -EQ 'PP-001').Status | Should -BeExactly 'NotEntitled'
            @($actual | Where-Object ControlId -EQ 'PP-001').Status | Should -Not -BeIn @('Pass', 'NotApplicable', 'ApprovedException')
        }
    }

    Context 'Positive: resolved authority preserves the only legitimate profile exclusion and evaluator result' {
        It 'projects a registry exclusion as NotApplicable and leaves an applicable entitled failure unchanged' {
            # Arrange
            Import-ApplicabilityEntitlementProjection

            # Act
            $actual = @(Invoke-Projection)

            # Assert
            @($actual | Sort-Object ControlId | ForEach-Object { "$($_.ControlId)|$($_.Status)|$($_.Reason)" }) | Should -Be @(
                'PP-001|Fail|Synthetic drift remains a failure.'
                "PP-005|NotApplicable|ProfileNotApplicable: 'PP-005' is outside the selected 'Gateway' profile."
            )
        }
    }
}
