#requires -Version 7.0

# GATE-005-A: what exit `0` from the shipped command is allowed to mean. Every case below runs
# `Test-ExchangeOnlineBaseline.ps1` for real in a child process against stubbed Exchange Online
# outcomes. Only registry observations are doubled; the current public command, context,
# evidence writer and exit resolver execute unchanged. Collection behavior has its own raw-contract
# tests. Nothing here connects to a tenant or imports ExchangeOnlineManagement or Microsoft.Graph.

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:CommonManifestPath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psd1'
    $script:EvidenceScriptPath = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'
    $script:ConfigurationPath = Join-Path $script:SampleRoot 'config' 'exchange-only.v1.json'
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
    $script:ParameterPath = Join-Path $TestDrive 'exit-contract.parameters.json'
    $parameters = Get-Content (Join-Path $script:SampleRoot 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable -DateKind String
    $parameters.MICROSOFT_ENTRA_TENANT_GUID = '11111111-2222-3333-4444-555555555555'
    $parameters.domainInventory.tenantId = $parameters.MICROSOFT_ENTRA_TENANT_GUID
    $parameters.entitlement.tenantId = $parameters.MICROSOFT_ENTRA_TENANT_GUID
    $parameters.entitlement.verified = $true
    $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
    $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE', 'ATP_ENTERPRISE')
    $parameters | ConvertTo-Json -Depth 40 | Set-Content $script:ParameterPath

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # The tenant the run observes. Every member the shipped command reads is answered here, so a
    # control that does not pass fails for the reason the case declares rather than for a member
    # the stub forgot.
    $script:TenantObservation = @'
$global:ExitContractTenant = '__TENANT__'
function global:Import-Module {
    [CmdletBinding()]
    param([Parameter(Position = 0)]$Name, [switch]$Force, [switch]$DisableNameChecking)
    if ((Split-Path $Name -Leaf) -ne 'ExchangeOnlineBaseline.Common.psm1') {
        throw "OfflineImportUnexpected: $Name"
    }
    $module = Microsoft.PowerShell.Core\Import-Module @PSBoundParameters -PassThru
    & $module {
        function script:Invoke-BaselineExchangeRegistry {
            param($Context)
            if ($global:ExitContractTenant -eq 'AcceptedDomainUnreadable') { throw 'Offline registry collection refused.' }
            foreach ($controlId in $Context.Manifest.ControlId) {
                $status = switch ($controlId) {
                    'EXO-010' { 'Manual' }
                    'MDO-008' { 'NotEntitled' }
                    'AUTH-001' { 'Error' }
                    'EXO-002' { if ($global:ExitContractTenant -eq 'SmtpAuthEnabled') { 'Fail' } else { 'Pass' } }
                    default { 'Pass' }
                }
                $evidence = New-BaselineEvidence -ControlId $controlId -Source 'OfflineExitContract' `
                    -Command 'OfflineOutcomeFixture' -Value @{ Fixture = 'ExitContractOnly' }
                [pscustomobject]@{
                    ControlId = $controlId
                    Evidence = $evidence
                    Result = New-ControlResult -ControlId $controlId -Status $status -Evidence $evidence `
                        -Reason 'Synthetic exit-contract observation; not tenant evidence.'
                }
            }
        }
    }
}
'@

    function New-TenantHarness {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$Directory,
            [Parameter(Mandatory)][string]$Tenant,
            [switch]$ConnectedSession
        )

        $connectionInformation = if ($ConnectedSession) {
            "function Get-ConnectionInformation { [pscustomobject]@{ State = 'Connected' } }"
        }
        else {
            ''
        }

        $observation = ($script:TenantObservation + [Environment]::NewLine + $connectionInformation).
        Replace('__TENANT__', $Tenant)

        $invocation = @'
& $args[0] -ParameterPath $args[1] -ConfigurationPath $args[2] -SchemaPath $args[3] -OutputPath $args[4] -SkipConnection
exit $LASTEXITCODE
'@

        $path = Join-Path $Directory 'Invoke-StubbedTenant.ps1'
        Set-Content -LiteralPath $path -Value (($observation, $invocation) -join [Environment]::NewLine) -Encoding utf8
        return $path
    }

    # A copy of the shipped command with exactly one thing done to it. A perturbation that changed
    # nothing is thrown rather than run, because a fixture that is quietly identical to the shipped
    # command turns a negative into a second positive nobody notices.
    function New-PerturbedEvidenceCommand {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$Directory,
            [Parameter(Mandatory)][string]$Perturbation
        )

        $text = Get-Content -LiteralPath $script:EvidenceScriptPath -Raw
        $original = $text
        $moduleText = Get-Content -LiteralPath $script:CommonModulePath -Raw
        $originalModule = $moduleText

        switch ($Perturbation) {
            'InternalFault' {
                $text = [regex]::Replace($text,
                    '(?m)^    try \{\r?\n(?=        \$exchangeOutcome = Invoke-BaselineExchangeEvidence)',
                    '    $faultInjected.Never()' + [Environment]::NewLine + '    try {' + [Environment]::NewLine)
            }
            'LegacyFailureExit' {
                $text = $text.Replace(
                    'exit $exchangeOutcome.ExitCode',
                    'exit $exitCode.Success')
            }
            'UndecidableVerdictDropped' {
                $moduleText = $moduleText.Replace(
                    'Get-BaselineRunOutcome -Check @($envelope.Check)',
                    'Get-BaselineRunOutcome -Check @($envelope.Check | Where-Object Status -CNotIn @(''Error'', ''Manual'', ''NotEntitled''))')
            }
            'AlwaysSuccessExit' {
                $text = $text.Replace('exit $exchangeOutcome.ExitCode', 'exit $exitCode.Success')
            }
            'ApprovalExit' {
                $text = $text.Replace('exit $exchangeOutcome.ExitCode', 'exit $exitCode.Approval')
            }
            'CollectionFaultSwallowed' {
                $text = $text.Replace('exit $exitCode.Collection', 'exit $exitCode.Success')
            }
            'AdmittedVerdictsRefused' {
                $moduleText = $moduleText.Replace(
                    '$execution = @(Invoke-BaselineExchangeRegistry -Context $Context)',
                    '$execution = @(Invoke-BaselineExchangeRegistry -Context $Context); foreach ($entry in $execution) { $entry.Result = New-ControlResult -ControlId $entry.ControlId -Status Pass }')
                $text = $text.Replace('exit $exchangeOutcome.ExitCode', 'exit $exitCode.Compliance')
            }
            default { throw "UnknownPerturbation: '$Perturbation' is not a way this test perturbs the shipped command." }
        }

        if ($text -ceq $original -and $moduleText -ceq $originalModule) {
            throw "PerturbationNotApplied: '$Perturbation' matched nothing in the shipped command, so the fixture would be the shipped command."
        }

        $path = Join-Path $Directory 'Test-ExchangeOnlineBaseline.ps1'
        Set-Content -LiteralPath $path -Value $text -Encoding utf8
        Set-Content -LiteralPath (Join-Path $Directory 'ExchangeOnlineBaseline.Common.psm1') -Value $moduleText -Encoding utf8
        Copy-Item -LiteralPath $script:CommonManifestPath -Destination (Join-Path $Directory 'ExchangeOnlineBaseline.Common.psd1')
        Copy-Item -LiteralPath (Join-Path $script:SampleRoot 'scripts/ExchangeOnlineBaseline.ApprovedAdapters.ps1') -Destination $Directory
        return $path
    }

    function Invoke-EvidenceCommand {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$ScriptPath,
            [Parameter(Mandatory)][string]$Tenant,
            [switch]$ConnectedSession
        )

        $runRoot = Join-Path $script:FixtureRoot ('run-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
        $outputPath = Join-Path $runRoot 'evidence'

        $harnessPath = New-TenantHarness -Directory $runRoot -Tenant $Tenant -ConnectedSession:$ConnectedSession
        $shell = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

        $output = & $shell -NoProfile -NonInteractive -File $harnessPath `
            $ScriptPath $script:ParameterPath $script:ConfigurationPath $script:SchemaPath $outputPath 2>&1
        $exitCode = $LASTEXITCODE

        $envelopeFile = @(Get-ChildItem -LiteralPath $outputPath -Filter '*.json' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTimeUtc)

        $check = @()
        if ($envelopeFile.Count -gt 0) {
            $envelope = Get-Content -LiteralPath $envelopeFile[-1].FullName -Raw | ConvertFrom-Json
            $check = @($envelope.Check)
        }

        return [pscustomobject]@{
            ExitCode = $exitCode
            Check    = $check
            Output   = @($output | ForEach-Object { [string]$_ })
        }
    }

    function Get-EvidenceCommandExitZeroResult {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [AllowEmptyString()]
            [string]$ScriptPath,

            [ValidateSet('Compliant', 'SmtpAuthEnabled', 'AcceptedDomainUnreadable')]
            [string]$Tenant = 'Compliant'
        )

        $result = [ordered]@{
            Satisfied  = $false
            Reason     = $null
            ExitCode   = $null
            Outcome    = $null
            Violations = @()
        }

        if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
            $result.Reason = 'EvidenceCommandPathNotSupplied'
            return [pscustomobject]$result
        }

        if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
            $result.Reason = 'EvidenceCommandMissing'
            return [pscustomobject]$result
        }

        $run = Invoke-EvidenceCommand -ScriptPath $ScriptPath -Tenant $Tenant
        $result.ExitCode = $run.ExitCode

        $contract = Get-BaselineExitCodeContract
        $outcomeName = @{}
        foreach ($name in $contract.Keys) { $outcomeName[[int]$contract[$name]] = [string]$name }
        $result.Outcome = $outcomeName[[int]$run.ExitCode]

        # A defect in this tool is not a finding about the tenant, so it is reported as the fault it
        # is rather than read as a verdict the run never reached.
        if ($run.ExitCode -eq $contract.Internal) {
            $result.Reason = 'RunFaultedInternally'
            $result.Violations = @($run.Output | Select-Object -Last 5)
            return [pscustomobject]$result
        }

        if (@($run.Check).Count -eq 0) {
            if ($run.ExitCode -eq $contract.Success) {
                $result.Reason = 'ExitZeroWithoutVerdict'
                $result.Violations = @($run.Output | Select-Object -Last 5)
                return [pscustomobject]$result
            }

            if ([int]$run.ExitCode -notin @($outcomeName.Keys)) {
                $result.Reason = 'ExitCodeNotDeclared'
                $result.Violations = @([string]$run.ExitCode)
                return [pscustomobject]$result
            }

            $result.Satisfied = $true
            $result.Reason = 'RunRefusedBeforeAnyVerdict'
            return [pscustomobject]$result
        }

        # DES-001 names the only statuses that admit a successful go-live. Everything else is a
        # control that was measured and found wanting, or one nobody could decide at all, and a run
        # that exits `0` over either has reported a tenant it never verified as verified.
        $admitted = @((Get-BaselineResultContract).GoLiveSuccessStatus)
        $unverified = @(foreach ($check in $run.Check) {
                $status = [string]$check.Status
                if ($status -cin $admitted) { continue }
                '{0}:{1}' -f [string]$check.ControlId, $status
            })

        if ($run.ExitCode -eq $contract.Success -and $unverified.Count -gt 0) {
            $result.Reason = 'ExitZeroWithUnverifiedControl'
            $result.Violations = @($unverified)
            return [pscustomobject]$result
        }

        if ($run.ExitCode -ne $contract.Success -and $unverified.Count -eq 0) {
            $result.Reason = 'ExitNonZeroWithEveryControlAdmitted'
            $result.Violations = @([string]$run.ExitCode)
            return [pscustomobject]$result
        }

        $required = [int](Get-BaselineRunOutcome -Check @($run.Check) -GoLive $null).ExitCode
        if ([int]$run.ExitCode -ne $required) {
            $result.Reason = 'ExitCodeNotFromVerdict'
            $result.Violations = @('{0} was exited where the verdicts it recorded resolve to {1}.' -f $run.ExitCode, $required)
            return [pscustomobject]$result
        }

        $result.Satisfied = $true
        $result.Reason = 'EvidenceCommandExitZeroSemanticsSatisfied'
        return [pscustomobject]$result
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GATE-005-A exit zero from the shipped command means every applicable control was verified' {

    BeforeAll {
        $script:FixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('evidence-exit-zero-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:FixtureRoot -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:SampleRoot 'config') -Destination (Join-Path $script:FixtureRoot 'config') -Recurse

        function New-PerturbedRunDirectory {
            [CmdletBinding()]
            param([Parameter(Mandatory)][string]$Perturbation)

            $directory = Join-Path $script:FixtureRoot ('fixture-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
            return New-PerturbedEvidenceCommand -Directory $directory -Perturbation $Perturbation
        }
    }

    AfterAll {
        Remove-Item -LiteralPath $script:FixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    Context 'Negative: a command nothing can run decides nothing about exit zero' {

        It 'refuses a run it was handed no command to make' {
            # Arrange
            $scriptPath = ''

            # Act
            $result = Get-EvidenceCommandExitZeroResult -ScriptPath $scriptPath

            # Assert
            $result.Reason | Should -BeExactly 'EvidenceCommandPathNotSupplied'
        }

        It 'refuses a command path that names no file' {
            # Arrange
            $scriptPath = Join-Path $script:FixtureRoot 'Absent-ExchangeOnlineBaseline.ps1'

            # Act
            $result = Get-EvidenceCommandExitZeroResult -ScriptPath $scriptPath

            # Assert
            $result.Reason | Should -BeExactly 'EvidenceCommandMissing'
        }
    }

    Context 'Negative: offline connection bypass refuses a live Exchange session' {

        It 'refuses to collect evidence when SkipConnection is used with a connected session' {
            # Arrange
            $scriptPath = $script:EvidenceScriptPath

            # Act
            $run = Invoke-EvidenceCommand -ScriptPath $scriptPath -Tenant 'Compliant' -ConnectedSession

            # Assert
            $run.ExitCode | Should -Be (Get-BaselineExitCodeContract).Connection
            ($run.Output -join "`n") | Should -Match 'ExchangeConnectionBypassRefused'
        }
    }

    Context 'Negative: a run that faulted before it decided anything is not an answer about the tenant' {

        It 'reports a run that faulted internally rather than reading its exit as a verdict' {
            # Arrange
            $scriptPath = New-PerturbedRunDirectory -Perturbation 'InternalFault'

            # Act
            $result = Get-EvidenceCommandExitZeroResult -ScriptPath $scriptPath

            # Assert
            $result.Reason | Should -BeExactly 'RunFaultedInternally'
        }

        It 'refuses a run that exits zero having collected nothing and written no evidence' {
            # Arrange
            $scriptPath = New-PerturbedRunDirectory -Perturbation 'CollectionFaultSwallowed'

            # Act
            $result = Get-EvidenceCommandExitZeroResult -ScriptPath $scriptPath -Tenant 'AcceptedDomainUnreadable'

            # Assert
            $result.Reason | Should -BeExactly 'ExitZeroWithoutVerdict'
        }
    }

    Context 'Negative: exit zero while a control was never verified' {

        It 'refuses the legacy exit that counted only failures' {
            # Arrange
            $scriptPath = New-PerturbedRunDirectory -Perturbation 'LegacyFailureExit'

            # Act
            $result = Get-EvidenceCommandExitZeroResult -ScriptPath $scriptPath

            # Assert
            $result.Reason | Should -BeExactly 'ExitZeroWithUnverifiedControl'
        }

        It 'refuses a run that dropped its Error, Manual, and NotEntitled verdicts before deciding its exit' {
            # Arrange
            $scriptPath = New-PerturbedRunDirectory -Perturbation 'UndecidableVerdictDropped'

            # Act
            $result = Get-EvidenceCommandExitZeroResult -ScriptPath $scriptPath

            # Assert
            $result.Violations | Should -Contain 'EXO-010:Manual'
            $result.Violations | Should -Contain 'MDO-008:NotEntitled'
            $result.Reason | Should -BeExactly 'ExitZeroWithUnverifiedControl'
        }

        It 'refuses a run that exits success while a control it decided failed' {
            # Arrange
            $scriptPath = New-PerturbedRunDirectory -Perturbation 'AlwaysSuccessExit'

            # Act
            $result = Get-EvidenceCommandExitZeroResult -ScriptPath $scriptPath -Tenant 'SmtpAuthEnabled'

            # Assert
            $result.Violations | Should -Contain 'EXO-002:Fail'
            $result.Reason | Should -BeExactly 'ExitZeroWithUnverifiedControl'
        }
    }

    Context 'Negative: an exit the verdicts the run recorded do not account for' {

        It 'refuses a run whose exit is not the one its own verdicts resolve to' {
            # Arrange
            $scriptPath = New-PerturbedRunDirectory -Perturbation 'ApprovalExit'

            # Act
            $result = Get-EvidenceCommandExitZeroResult -ScriptPath $scriptPath

            # Assert
            $result.Reason | Should -BeExactly 'ExitCodeNotFromVerdict'
        }

        It 'refuses a run that exits nonzero although every verdict it recorded admits a successful go-live' {
            # Arrange
            $scriptPath = New-PerturbedRunDirectory -Perturbation 'AdmittedVerdictsRefused'

            # Act
            $result = Get-EvidenceCommandExitZeroResult -ScriptPath $scriptPath

            # Assert
            $result.Reason | Should -BeExactly 'ExitNonZeroWithEveryControlAdmitted'
        }
    }

    Context 'Positive: the shipped command resolves its exit from the verdicts it recorded' {

        It 'exits at the collection code when live RBAC collection has no admitted fallback' {
            # Arrange
            $scriptPath = $script:EvidenceScriptPath

            # Act
            $result = Get-EvidenceCommandExitZeroResult -ScriptPath $scriptPath

            # Assert
            $result.Satisfied | Should -BeTrue
            $result.Reason | Should -BeExactly 'EvidenceCommandExitZeroSemanticsSatisfied'
            $result.Outcome | Should -BeExactly 'Collection'
            $result.ExitCode | Should -Be (Get-BaselineExitCodeContract).Collection
        }
    }
}
