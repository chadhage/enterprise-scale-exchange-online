#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:EvidenceScript = Join-Path $script:SampleRoot 'scripts\Test-ExchangeOnlineBaseline.ps1'
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts\ExchangeOnlineBaseline.Common.psm1'
    Import-Module $script:ModulePath -Force -DisableNameChecking

    function Import-ProfileApplicabilityProjection {
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
                    $node.Name -ceq 'Get-BaselineProfileExclusion'
                }, $true))
        $functionAst.Count | Should -Be 1
        $bodyText = $functionAst[0].Body.Extent.Text
        Set-Item -Path function:script:Get-BaselineProfileExclusion `
            -Value ([scriptblock]::Create($bodyText.Substring(1, $bodyText.Length - 2)))
    }

    function Get-PpRegistry {
        @(@(Get-BaselineControlRegistry -Profile Historical)[0] | Where-Object ControlId -Like 'PP-*')
    }
}

Describe 'EVD-007 profile applicability and PP-005 identity' {
    Context 'Negative: only controls outside the selected profile become NotApplicable' {
        It 'rejects an unknown selected profile instead of excluding the complete PP family' {
            # Arrange
            Import-ProfileApplicabilityProjection
            $registry = Get-PpRegistry

            # Act
            $operation = { Get-BaselineProfileExclusion -Registry $registry -SelectedProfile 'Hybrid' }

            # Assert
            $operation | Should -Throw -ExpectedMessage '*SelectedProfile*'
        }

        It 'does not emit NotApplicable for a control that applies to both profiles' {
            # Arrange
            Import-ProfileApplicabilityProjection
            $registry = @(
                [pscustomobject]@{ ControlId = 'PP-900'; ApplicableProfile = @('Native', 'Gateway') }
                [pscustomobject]@{ ControlId = 'PP-901'; ApplicableProfile = @('Gateway') }
            )

            # Act
            $actual = @(Get-BaselineProfileExclusion -Registry $registry -SelectedProfile Native)

            # Assert
            @($actual.ControlId) | Should -Be @('PP-901')
            @($actual.Status | Sort-Object -Unique) | Should -Be @('NotApplicable')
        }

        It 'does not exclude any PP control declared applicable to the selected shipped profile' {
            # Arrange
            Import-ProfileApplicabilityProjection
            $registry = Get-PpRegistry

            # Act
            $gatewayExcluded = @(Get-BaselineProfileExclusion -Registry $registry -SelectedProfile Gateway)
            $nativeExcluded = @(Get-BaselineProfileExclusion -Registry $registry -SelectedProfile Native)

            # Assert
            @($gatewayExcluded.ControlId | Sort-Object) | Should -Be @('PP-005')
            @($nativeExcluded.ControlId | Sort-Object) | Should -Be @('PP-001', 'PP-002', 'PP-003', 'PP-004')
        }

        It 'does not misidentify the Microsoft-native connector result as a Gateway control' {
            # Arrange
            $evidence = Get-PartnerInboundConnectorEvidence -InboundConnectorCollection { @() }

            # Act
            $actual = Test-PartnerInboundConnectorControl -Evidence $evidence

            # Assert
            $actual.ControlId | Should -BeExactly 'PP-005'
            $actual.Status | Should -BeExactly 'Pass'
        }
    }

    Context 'Positive: one exact applicability projection covers both shipped profiles' {
        It 'projects every PP catalog control exactly once for Gateway and Native' {
            # Arrange
            Import-ProfileApplicabilityProjection
            $registry = Get-PpRegistry
            $applicable = @{
                Gateway = @('PP-001', 'PP-002', 'PP-003', 'PP-004')
                Native = @('PP-005')
            }

            # Act
            $actual = foreach ($profile in 'Gateway', 'Native') {
                $excluded = @(Get-BaselineProfileExclusion -Registry $registry -SelectedProfile $profile)
                $projected = @($applicable[$profile] | ForEach-Object { "$_|Evaluated" }) +
                    @($excluded | ForEach-Object { "$($_.ControlId)|$($_.Status)" })
                '{0}:{1}' -f $profile, (@($projected | Sort-Object) -join ',')
            }

            # Assert
            $actual | Should -Be @(
                'Gateway:PP-001|Evaluated,PP-002|Evaluated,PP-003|Evaluated,PP-004|Evaluated,PP-005|NotApplicable'
                'Native:PP-001|NotApplicable,PP-002|NotApplicable,PP-003|NotApplicable,PP-004|NotApplicable,PP-005|Evaluated'
            )
        }
    }
}