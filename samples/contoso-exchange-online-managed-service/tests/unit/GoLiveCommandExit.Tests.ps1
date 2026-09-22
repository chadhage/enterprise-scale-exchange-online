#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:EvidenceScriptPath = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:TenantId = 'f1a3b5c7-0000-4000-8000-0123456789ab'
    $script:DeploymentProfile = 'MicrosoftNative'
    $script:ConfigurationHash = 'a3f1c9d2b4e6708192a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f809'

    function New-CommandExitCatalog {
        [CmdletBinding()]
        param()

        $path = Join-Path $TestDrive ('catalog-{0}.md' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $path -Encoding utf8 -Value @(
            '| ID | Priority | Profile | Licence | Control | Desired state | Evidence | Runbook |'
            '| --- | --- | --- | --- | --- | --- | --- | --- |'
            '| EXO-001 | MUST | Both | EOP | Accepted domain | Authoritative | `Get-AcceptedDomain` | R-EXO-001 |'
        )
        return $path
    }

    function New-CommandExitCheck {
        [CmdletBinding()]
        param([Parameter(Mandatory)][ValidateSet('Pass', 'Fail', 'Error')][string]$Status)

        if ($Status -ceq 'Pass') {
            return New-ControlResult -ControlId 'EXO-001' -Status 'Pass'
        }

        return New-ControlResult -ControlId 'EXO-001' -Status $Status -Reason "EXO-001 was decided '$Status'."
    }

    function New-CommandExitEnvelope {
        [CmdletBinding()]
        param([Parameter(Mandatory)][object[]]$Check)

        $evidence = New-BaselineEvidence -ControlId 'EXO-001' -Source 'ExchangeOnline' `
            -Command 'Get-AcceptedDomain' -Value @{ domainType = 'Authoritative' }
        return [pscustomobject]@{
            TenantId           = $script:TenantId
            DeploymentProfile  = $script:DeploymentProfile
            ConfigurationHash  = "sha256:$($script:ConfigurationHash)"
            CollectedAtUtc      = [datetime]::UtcNow.AddMinutes(-1).ToString('o')
            ServicePlan         = [pscustomobject]@{ NotEntitled = @() }
            Evidence            = @($evidence)
            Check               = @($Check)
        }
    }

    function New-CommandExitSignature {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][object]$Envelope,
            [switch]$Tampered
        )

        $hash = if ($Tampered) {
            'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
        }
        else {
            [string](Get-BaselineEvidenceContentHash -Envelope $Envelope).Hash
        }

        return [pscustomobject]@{
            Model       = 'DetachedCms'
            Value       = 'MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExDzANBglghkgBZQMEAgEFADA='
            ContentHash = $hash
        }
    }

    function Get-CommandExitWiringResult {
        [CmdletBinding()]
        param([Parameter(Mandatory)][string]$ScriptPath)

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
        $violation = [System.Collections.Generic.List[string]]::new()

        if (@($errors).Count -gt 0) {
            $violation.Add('EvidenceCommandUnparsable')
        }

        $outcomeCall = @($ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.CommandAst] -and
                    $node.GetCommandName() -ceq 'Get-BaselineRunOutcome'
                }, $true))

        if ($outcomeCall.Count -ne 1) {
            $violation.Add("RunOutcomeInvocationCount:$($outcomeCall.Count)")
        }
        else {
            $callText = $outcomeCall[0].Extent.Text
            if ($callText -cnotmatch '(?s)-Check\s+@\(\$verdict\)') {
                $violation.Add('EveryCheckNotPassed')
            }
            if ($callText -cnotmatch '(?s)-GoLive\s+\$goLiveDecision') {
                $violation.Add('RealDecisionNotPassed')
            }
        }

        $decisionAssignment = @($ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                    $node.Left.VariablePath.UserPath -ceq 'goLiveDecision'
                }, $true))
        $realDecision = @($decisionAssignment | Where-Object { $_.Right.Extent.Text -cmatch '\bTest-BaselineGoLive\b' })
        $fabricatedDecision = @($decisionAssignment | Where-Object {
                $_.Right.Extent.Text -cne '$null' -and $_.Right.Extent.Text -cnotmatch '\bTest-BaselineGoLive\b'
            })
        if ($realDecision.Count -ne 1 -or $fabricatedDecision.Count -gt 0) {
            $violation.Add('GoLiveDecisionNotReal')
        }

        $exitStatement = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true))
        if ($exitStatement.Count -eq 0 -or $exitStatement[-1].Extent.Text -cne 'exit $outcome.ExitCode') {
            $violation.Add('FinalExitNotFromOutcome')
        }

        return [pscustomobject]@{
            Satisfied  = ($violation.Count -eq 0)
            Violations = @($violation)
        }
    }

    function Invoke-CommandExitScenario {
        [CmdletBinding()]
        param([Parameter(Mandatory)][ValidateSet('ExceptionAuthorityRefusal', 'OtherGateRefusal', 'CollectionFault', 'Compliant')][string]$Scenario)

        $wiring = Get-CommandExitWiringResult -ScriptPath $script:EvidenceScriptPath
        if (-not $wiring.Satisfied) {
            return [pscustomobject]@{
                ExitCode   = $null
                Decision   = $null
                Outcome    = $null
                Violations = @($wiring.Violations)
            }
        }

        $status = switch ($Scenario) {
            'ExceptionAuthorityRefusal' { 'Fail' }
            'CollectionFault' { 'Error' }
            default { 'Pass' }
        }
        $check = @(New-CommandExitCheck -Status $status)
        $envelope = New-CommandExitEnvelope -Check $check
        $signature = New-CommandExitSignature -Envelope $envelope -Tampered:($Scenario -ceq 'OtherGateRefusal')
        $riskAcceptance = if ($Scenario -ceq 'ExceptionAuthorityRefusal') {
            @([pscustomobject]@{ ControlId = 'EXO-001' })
        }
        else {
            @()
        }

        $decision = Test-BaselineGoLive -Envelope $envelope `
            -CatalogPath (New-CommandExitCatalog) `
            -ExpectedTenantId $script:TenantId `
            -ExpectedDeploymentProfile $script:DeploymentProfile `
            -ExpectedConfigurationHash $script:ConfigurationHash `
            -MaximumEvidenceAge ([timespan]::FromDays(7)) `
            -RequestedBy 'operator@contoso.example' `
            -RiskAcceptance $riskAcceptance `
            -Signature $signature `
            -TargetEntitlement ([pscustomobject]@{ Missing = @() })

        $outcome = Get-BaselineRunOutcome -Check @($check) -GoLive $decision
        return [pscustomobject]@{
            ExitCode   = $outcome.ExitCode
            Decision   = $decision
            Outcome    = $outcome
            Violations = @()
        }
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GATE-006 public go-live outcome and exit integration' {

    Context 'Negative: the public command cannot decide around the run-outcome seam' {

        It 'passes every check and the real gate decision to the outcome seam exactly once' {
            # Arrange
            $scriptPath = $script:EvidenceScriptPath

            # Act
            $wiring = Get-CommandExitWiringResult -ScriptPath $scriptPath

            # Assert
            $wiring.Violations | Should -BeNullOrEmpty
        }
    }

    Context 'Negative: a refused exception authority is an approval failure' {

        It 'exits with the declared approval code after the real gate refuses the exception' {
            # Arrange
            $expected = (Get-BaselineExitCodeContract).Approval

            # Act
            $run = Invoke-CommandExitScenario -Scenario 'ExceptionAuthorityRefusal'

            # Assert
            $run.Decision.Finding | Should -BeLike '*GoLiveExceptionRefused*'
            $run.ExitCode | Should -BeExactly $expected
        }
    }

    Context 'Negative: any other real gate refusal is a compliance failure' {

        It 'exits with the declared compliance code after the real gate refuses tampered evidence' {
            # Arrange
            $expected = (Get-BaselineExitCodeContract).Compliance

            # Act
            $run = Invoke-CommandExitScenario -Scenario 'OtherGateRefusal'

            # Assert
            $run.Decision.Finding | Should -BeLike '*GoLiveEvidenceTampered*'
            $run.ExitCode | Should -BeExactly $expected
        }
    }

    Context 'Negative: a collection fault keeps its stronger outcome' {

        It 'retains the declared collection code when the real gate also refuses' {
            # Arrange
            $expected = (Get-BaselineExitCodeContract).Collection

            # Act
            $run = Invoke-CommandExitScenario -Scenario 'CollectionFault'

            # Assert
            $run.Decision.Admitted | Should -BeFalse
            $run.ExitCode | Should -BeExactly $expected
        }
    }

    Context 'Positive: one signed compliant run earns success' {

        It 'exits zero after the real gate admits every check and the signed evidence' {
            # Arrange
            $expected = (Get-BaselineExitCodeContract).Success

            # Act
            $run = Invoke-CommandExitScenario -Scenario 'Compliant'

            # Assert
            $run.Decision.Admitted | Should -BeTrue
            $run.ExitCode | Should -BeExactly $expected
        }
    }
}