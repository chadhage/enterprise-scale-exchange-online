#requires -Version 7.0

$UnresolvedOutcomeScenario = @(
    @{ Status = 'Error'; ExpectedOutcome = 'Collection'; ExpectedReason = "ControlNotCollected: 'EXO-001' was decided 'Error'." }
    @{ Status = 'Fail'; ExpectedOutcome = 'Compliance'; ExpectedReason = "ControlNotPassed: 'EXO-001' was decided 'Fail'." }
    @{ Status = 'Manual'; ExpectedOutcome = 'Compliance'; ExpectedReason = "ControlNotPassed: 'EXO-001' was decided 'Manual'." }
    @{ Status = 'NotEntitled'; ExpectedOutcome = 'Compliance'; ExpectedReason = "ControlNotPassed: 'EXO-001' was decided 'NotEntitled'." }
    @{ Status = 'Unverified'; ExpectedOutcome = 'Compliance'; ExpectedReason = "ControlNotPassed: 'EXO-001' was decided 'Unverified'." }
)

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:EvidenceCommandPath = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'
    Import-Module -Name $script:ModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:TenantId = 'f1a3b5c7-0000-4000-8000-0123456789ab'
    $script:Profile = 'MicrosoftNative'
    $script:Hash = 'a3f1c9d2b4e6708192a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f809'
    $script:AsOf = [datetimeoffset]::Parse('2026-09-19T12:00:00Z').UtcDateTime

    function New-ResolvedOutcomeCatalog {
        $path = Join-Path $TestDrive 'resolved-exception-catalog.md'
        Set-Content -LiteralPath $path -Encoding utf8 -Value @(
            '| ID | Priority | Profile | Licence | Control | Desired state | Evidence | Runbook |'
            '| --- | --- | --- | --- | --- | --- | --- | --- |'
            '| EXO-001 | MUST | Both | EOP | Accepted domain | Authoritative | `Get-AcceptedDomain` | R-EXO-001 |'
        )
        return $path
    }

    function New-ResolvedOutcomeCheck {
        param([Parameter(Mandatory)][string]$Status)

        if ($Status -ceq 'Pass') {
            return New-ControlResult -ControlId 'EXO-001' -Status 'Pass'
        }

        return New-ControlResult -ControlId 'EXO-001' -Status $Status -Reason "EXO-001 was decided '$Status'."
    }

    function New-ResolvedOutcomeEnvelope {
        param([Parameter(Mandatory)][object]$Check)

        $evidence = New-BaselineEvidence -ControlId 'EXO-001' -Source 'ExchangeOnline' -Command 'Get-AcceptedDomain' -Value @{ observed = $true }
        return [pscustomobject]@{
            TenantId          = $script:TenantId
            DeploymentProfile = $script:Profile
            ConfigurationHash = "sha256:$($script:Hash)"
            CollectedAtUtc     = $script:AsOf.AddMinutes(-1).ToString('o')
            ServicePlan        = [pscustomobject]@{ NotEntitled = @() }
            Evidence           = @($evidence)
            Check              = @($Check)
        }
    }

    function New-ResolvedRiskAcceptance {
        param([hashtable]$Override = @{})

        $member = [ordered]@{
            SchemaVersion       = '1.0.0'
            ControlId           = 'EXO-001'
            TenantId            = $script:TenantId
            ConfigurationHash   = $script:Hash
            Owner               = 'risk-owner@contoso.example'
            Justification       = 'A bounded operational exception remains under active review.'
            CompensatingControl = @('Daily review of the affected control')
            ExternalReference   = 'RISK-2026-0042'
            ApprovalIdentity    = 'approver@contoso.example'
            ApprovalAuthority   = 'ExchangeOnlineChangeApproval'
            ApprovalTimeUtc     = $script:AsOf.AddDays(-2)
            EffectiveTimeUtc    = $script:AsOf.AddDays(-1)
            ExpiryTimeUtc       = $script:AsOf.AddDays(7)
            Signature           = [pscustomobject]@{ Model = 'DetachedCms'; Value = 'AQIDBA==' }
        }

        foreach ($name in $Override.Keys) { $member[$name] = $Override[$name] }
        return [pscustomobject]$member
    }

    function New-ResolvedSignatureProof {
        param(
            [Parameter(Mandatory)][object]$Envelope,
            [bool]$Verified = $true,
            [string]$Value = 'AQIDBA=='
        )

        return [pscustomobject]@{
            Model        = 'DetachedCms'
            Value        = $Value
            ContentHash  = [string](Get-BaselineEvidenceContentHash -Envelope $Envelope).Hash
            Verified     = $Verified
            Verification = [pscustomobject]@{
                Verified        = $Verified
                ChainTrusted    = $Verified
                RevocationStatus = if ($Verified) { 'Good' } else { 'Unknown' }
            }
        }
    }

    function Invoke-ResolvedExceptionGate {
        param(
            [Parameter(Mandatory)][string]$Status,
            [object[]]$RiskAcceptance = @(),
            [bool]$SignatureVerified = $true,
            [string]$SignatureValue = 'AQIDBA=='
        )

        $check = New-ResolvedOutcomeCheck -Status $Status
        $envelope = New-ResolvedOutcomeEnvelope -Check $check
        return Test-BaselineGoLive -Envelope $envelope `
            -CatalogPath (New-ResolvedOutcomeCatalog) `
            -ExpectedTenantId $script:TenantId `
            -ExpectedDeploymentProfile $script:Profile `
            -ExpectedConfigurationHash $script:Hash `
            -MaximumEvidenceAge ([timespan]::FromDays(7)) `
            -RequestedBy 'operator@contoso.example' `
            -RiskAcceptance $RiskAcceptance `
            -Signature (New-ResolvedSignatureProof -Envelope $envelope -Verified $SignatureVerified -Value $SignatureValue) `
            -TargetEntitlement ([pscustomobject]@{ Missing = @() }) `
            -AsOf $script:AsOf
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GATE-007 resolved exception authority and public outcome' {
    Context 'Negative: only verified exception authority can produce ApprovedException' {
        It 'refuses a schema-valid risk acceptance whose detached CMS proof is unresolved' {
            # Arrange
            $acceptance = New-ResolvedRiskAcceptance

            # Act
            $decision = Invoke-ResolvedExceptionGate -Status 'Fail' -RiskAcceptance @($acceptance) -SignatureVerified $false

            # Assert
            $decision.Admitted | Should -BeFalse
            @($decision.Exception) | Should -BeNullOrEmpty
            @($decision.Finding) -join ' | ' | Should -BeLike '*GoLiveExceptionRefused*EXO-001*RiskAcceptanceSignatureUnverified*'
        }

        It 'refuses a risk acceptance rejected by the published schema without producing ApprovedException' {
            # Arrange
            $acceptance = New-ResolvedRiskAcceptance -Override @{ Justification = 'Too short.' }

            # Act
            $decision = Invoke-ResolvedExceptionGate -Status 'Fail' -RiskAcceptance @($acceptance)

            # Assert
            $decision.Admitted | Should -BeFalse
            @($decision.Exception) | Should -BeNullOrEmpty
            @($decision.Finding) -join ' | ' | Should -BeLike '*GoLiveExceptionRefused*EXO-001*RiskAcceptanceSchemaViolation*'
        }

        It 'refuses a verified detached CMS proof bound to a different risk acceptance signature' {
            # Arrange
            $acceptance = New-ResolvedRiskAcceptance

            # Act
            $decision = Invoke-ResolvedExceptionGate -Status 'Fail' -RiskAcceptance @($acceptance) -SignatureValue 'BQYHCA=='

            # Assert
            $decision.Admitted | Should -BeFalse
            @($decision.Exception) | Should -BeNullOrEmpty
            @($decision.Finding) -join ' | ' | Should -BeLike '*GoLiveExceptionRefused*EXO-001*RiskAcceptanceSignatureMismatch*'
        }

        It 'refuses a correctly signed acceptance bound to another configuration' {
            # Arrange
            $acceptance = New-ResolvedRiskAcceptance -Override @{ ConfigurationHash = ('b' * 64) }

            # Act
            $decision = Invoke-ResolvedExceptionGate -Status 'Fail' -RiskAcceptance @($acceptance)

            # Assert
            $decision.Admitted | Should -BeFalse
            @($decision.Exception) | Should -BeNullOrEmpty
            @($decision.Finding) -join ' | ' | Should -BeLike '*GoLiveExceptionRefused*EXO-001*ConfigurationHashMismatch*'
        }
    }

    Context 'Negative: every unresolved public outcome is nonzero for its exact reason' {
        It 'maps <Status> to nonzero <ExpectedOutcome> with its exact reason' -ForEach $UnresolvedOutcomeScenario {
            # Arrange
            $check = New-ResolvedOutcomeCheck -Status $Status

            # Act
            $outcome = Get-BaselineRunOutcome -Check @($check) -GoLive $null

            # Assert
            $outcome.Outcome | Should -BeExactly $ExpectedOutcome
            $outcome.ExitCode | Should -BeExactly (Get-BaselineExitCodeContract).$ExpectedOutcome
            $outcome.ExitCode | Should -Not -Be 0
            $outcome.ControlId | Should -BeExactly 'EXO-001'
            $outcome.Reason | Should -BeExactly $ExpectedReason
        }

        It 'maps an unverified exception refusal to the nonzero approval exit and preserves the exact refusal reason' {
            # Arrange
            $acceptance = New-ResolvedRiskAcceptance
            $decision = Invoke-ResolvedExceptionGate -Status 'Fail' -RiskAcceptance @($acceptance) -SignatureVerified $false
            $check = New-ResolvedOutcomeCheck -Status 'Fail'

            # Act
            $outcome = Get-BaselineRunOutcome -Check @($check) -GoLive $decision

            # Assert
            $outcome.Outcome | Should -BeExactly 'Approval'
            $outcome.ExitCode | Should -BeExactly (Get-BaselineExitCodeContract).Approval
            $outcome.ExitCode | Should -Not -Be 0
            $outcome.ControlId | Should -BeExactly 'GATE-003'
            $outcome.Reason | Should -BeLike '*GoLiveExceptionRefused*EXO-001*RiskAcceptanceSignatureUnverified*'
        }
    }

    Context 'Negative: the public command cannot bypass the resolved outcome' {
        It 'passes every verdict and the real go-live decision to the outcome seam and exits only with its code' {
            # Arrange
            $tokens = $null
            $errors = $null

            # Act
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:EvidenceCommandPath, [ref]$tokens, [ref]$errors)

            # Assert
            @($errors) | Should -BeNullOrEmpty
            @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Get-BaselineRunOutcome' }, $true)).Count | Should -Be 1
            @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true))[-1].Extent.Text | Should -BeExactly 'exit $outcome.ExitCode'
        }
    }

    Context 'Positive: one fully resolved verified exception admits a successful public outcome' {
        It 'reports ApprovedException and exits zero for the one correctly bound signed failing control' {
            # Arrange
            $acceptance = New-ResolvedRiskAcceptance
            $decision = Invoke-ResolvedExceptionGate -Status 'Fail' -RiskAcceptance @($acceptance)
            $check = New-ResolvedOutcomeCheck -Status 'Fail'

            # Act
            $outcome = Get-BaselineRunOutcome -Check @($check) -GoLive $decision

            # Assert
            $decision.Admitted | Should -BeTrue -Because (@($decision.Finding) -join ' | ')
            @($decision.Exception).Count | Should -Be 1
            @($decision.Exception)[0].ControlId | Should -BeExactly 'EXO-001'
            @($decision.Exception)[0].Status | Should -BeExactly 'ApprovedException'
            $outcome.Outcome | Should -BeExactly 'Success'
            $outcome.ExitCode | Should -Be 0
        }
    }
}