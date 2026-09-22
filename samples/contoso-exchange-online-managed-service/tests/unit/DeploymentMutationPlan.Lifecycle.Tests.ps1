#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # The finding codes this partition owns. Wave B implements precisely these spellings: a test
    # that only asserted `Planned -eq $false` could not tell one missing lifecycle step from
    # another, and five indistinguishable failures are one failure reported five times.
    $script:LifecycleCode = [ordered]@{
        Capture  = 'MutationPlanLifecycleStateNotCaptured'
        Journal  = 'MutationPlanLifecycleMutationNotJournalled'
        Rollback = 'MutationPlanLifecycleRollbackNotGeneratedFromCapture'
        Resolve  = 'MutationPlanLifecyclePartialApplicationNotResolved'
        Success  = 'MutationPlanLifecycleSuccessNotDecidedFromPostChange'
    }

    # Synthetic scripts only. The shipped script is never written to, nothing here connects to a
    # tenant and nothing applies: every fixture is parsed as text and judged on its shape alone.
    function New-FixtureScript {
        param([string]$Path, [string]$Text)

        Set-Content -LiteralPath $Path -Value $Text -Encoding utf8
        return $Path
    }

    # One template, five fixtures. Every fixture runs the entire mutation lifecycle except the one
    # step it omits, so a wave-B implementation that conflates two steps fails: a fixture missing
    # everything would satisfy all five assertions at once and prove none of them.
    function New-LifecycleScript {
        param(
            [ValidateSet('Capture', 'Journal', 'Rollback', 'Resolve', 'Success')]
            [string]$Omit
        )

        $header = @'
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigurationPath,
    [string]$PreviewPath,
    [string]$ApprovalPath,
    [string]$ChangeId,
    [string]$ArtifactRoot,
    [switch]$Apply
)

$configuration = Get-BaselineConfiguration -ConfigurationPath $ConfigurationPath
$tenant = [string]$configuration.Tenant
$plan = @(
    [ordered]@{ OperationId = 'op-1'; Command = 'Set-TransportConfig'; Identity = 'Default'; Before = [ordered]@{ Exists = $true; Value = 'False' } }
)

if ($Apply) {
    $decision = Test-BaselineApplyPrerequisite -Apply -PreviewPath $PreviewPath -ApprovalPath $ApprovalPath -ArtifactRoot $ArtifactRoot

    if (-not $decision.Permitted) {
        throw ('ApplyRefused: {0}' -f (@($decision.Finding) -join '; '))
    }
'@

        $capture = if ($Omit -eq 'Capture') {
            @'
    $capture = Get-Content -LiteralPath (Join-Path $ArtifactRoot 'prior-state.json') -Raw | ConvertFrom-Json
'@
        }
        else {
            @'
    $capture = New-BaselineChangeStateCapture -ChangeId $ChangeId -Tenant $tenant -Operation $plan
'@
        }

        $rollback = if ($Omit -eq 'Rollback') { '' }
        else {
            @'
    $rollback = New-BaselineRollbackScript -Capture $capture
    $null = Write-BaselineChangeArtifact -ChangeId $ChangeId -Artifact 'Rollback' -Root $ArtifactRoot -Content $rollback
'@
        }

        $mutation = @'
    if ($PSCmdlet.ShouldProcess('Default', 'Set-TransportConfig')) {
        Set-TransportConfig -Identity 'Default' -Confirm:$false
    }

    $outcome = @(
        [ordered]@{ OperationId = 'op-1'; Command = 'Set-TransportConfig'; Identity = 'Default'; State = 'Succeeded'; Fault = '' }
    )
'@

        $journal = if ($Omit -eq 'Journal') {
            @'
    $journal = @(
        [ordered]@{ Sequence = 1; OperationId = 'op-1'; Command = 'Set-TransportConfig'; Identity = 'Default'; State = 'Succeeded'; Fault = '' }
    )
'@
        }
        else {
            @'
    $journal = New-BaselineMutationJournal -Operation $outcome
'@
        }

        $resolve = if ($Omit -eq 'Resolve') {
            @'
    $application = [ordered]@{ ChangeId = $ChangeId; Failed = @(); Halted = @(); Outstanding = @() }
'@
        }
        else {
            @'
    $application = Resolve-BaselinePartialApplication -ChangeId $ChangeId -Operation $plan -Journal $journal -Root $ArtifactRoot
'@
        }

        $postChange = @'
    $postChange = [ordered]@{
        Permitted = $true
        Evidence  = ('postchange-{0}.json' -f $ChangeId)
        Finding   = @()
    }
'@

        $success = if ($Omit -eq 'Success') {
            @'
    $verdict = [ordered]@{ Successful = $true; ChangeId = $ChangeId }

    if (-not $verdict.Successful) {
        throw 'ChangeNotSuccessful: this run decided its own verdict.'
    }
}
'@
        }
        else {
            @'
    $verdict = Test-BaselineChangeSuccess -Application $application -PostChange $postChange

    if (-not $verdict.Successful) {
        throw ('ChangeNotSuccessful: {0}' -f (@($verdict.Finding) -join '; '))
    }
}
'@
        }

        return (@($header, $capture, $rollback, $mutation, $journal, $resolve, $postChange, $success) |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join [System.Environment]::NewLine
    }

    # Planned, whether the expected code was raised, and which of the codes that must stay silent
    # were raised anyway - one string, so a single assertion carries the whole verdict.
    function Format-Lifecycle {
        param([object]$Node, [string]$Expected, [string[]]$Silent)

        $finding = @($Node['Finding'])
        $raised = @($finding | Where-Object { $_ -like "$Expected*" }).Count -gt 0
        $leaked = @(
            $Silent | Where-Object {
                $code = $_
                @($finding | Where-Object { $_ -like "$code*" }).Count -gt 0
            }
        )

        return '{0}|{1}|{2}' -f $Node['Planned'], $raised, ($leaked -join ',')
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-007-A3 the shipped script runs the whole mutation lifecycle' {

    Context 'Negative: the run never writes down what the tenant held before it' {

        It 'does not call a script planned when it never captures the pre-change state' {
            # Arrange
            $path = New-FixtureScript -Path (Join-Path $TestDrive 'lifecycle-no-capture.ps1') `
                -Text (New-LifecycleScript -Omit 'Capture')

            # Act
            $node = Test-BaselineDeploymentMutationPlan -ScriptPath $path

            # Assert
            (Format-Lifecycle -Node $node -Expected $script:LifecycleCode['Capture'] -Silent @(
                    $script:LifecycleCode['Journal']
                    $script:LifecycleCode['Resolve']
                    $script:LifecycleCode['Success']
                )) |
                Should -BeExactly 'False|True|' -Because 'a prior state read from a file nobody wrote during this run is whatever the last run left there, and a run that never records what it is about to overwrite has nothing to put back'
        }
    }

    Context 'Negative: the run never records what each mutation reached' {

        It 'does not call a script planned when it never journals its mutations' {
            # Arrange
            $path = New-FixtureScript -Path (Join-Path $TestDrive 'lifecycle-no-journal.ps1') `
                -Text (New-LifecycleScript -Omit 'Journal')

            # Act
            $node = Test-BaselineDeploymentMutationPlan -ScriptPath $path

            # Assert
            (Format-Lifecycle -Node $node -Expected $script:LifecycleCode['Journal'] -Silent @(
                    $script:LifecycleCode['Capture']
                    $script:LifecycleCode['Rollback']
                    $script:LifecycleCode['Resolve']
                    $script:LifecycleCode['Success']
                )) |
                Should -BeExactly 'False|True|' -Because 'a literal that says every mutation succeeded says so whether they ran or not, so the run reports its plan back to itself instead of the state its mutations actually reached'
        }
    }

    Context 'Negative: the run never turns the capture into a restoration' {

        It 'does not call a script planned when it never generates a rollback from the capture' {
            # Arrange
            $path = New-FixtureScript -Path (Join-Path $TestDrive 'lifecycle-no-rollback.ps1') `
                -Text (New-LifecycleScript -Omit 'Rollback')

            # Act
            $node = Test-BaselineDeploymentMutationPlan -ScriptPath $path

            # Assert
            (Format-Lifecycle -Node $node -Expected $script:LifecycleCode['Rollback'] -Silent @(
                    $script:LifecycleCode['Capture']
                    $script:LifecycleCode['Journal']
                    $script:LifecycleCode['Resolve']
                    $script:LifecycleCode['Success']
                )) |
                Should -BeExactly 'False|True|' -Because 'a capture taken and never turned into a restoration is a record of a tenant nobody can get back, which reads as reversible and is not'
        }
    }

    Context 'Negative: the run never reconciles what it planned against what it managed' {

        It 'does not call a script planned when it never resolves the partial application' {
            # Arrange
            $path = New-FixtureScript -Path (Join-Path $TestDrive 'lifecycle-no-resolution.ps1') `
                -Text (New-LifecycleScript -Omit 'Resolve')

            # Act
            $node = Test-BaselineDeploymentMutationPlan -ScriptPath $path

            # Assert
            (Format-Lifecycle -Node $node -Expected $script:LifecycleCode['Resolve'] -Silent @(
                    $script:LifecycleCode['Capture']
                    $script:LifecycleCode['Journal']
                    $script:LifecycleCode['Rollback']
                    $script:LifecycleCode['Success']
                )) |
                Should -BeExactly 'False|True|' -Because 'an application record the run assembles with no failed, halted or outstanding operations declares the change complete without ever comparing the plan to the journal, so a half-applied tenant is indistinguishable from a finished one'
        }
    }

    Context 'Negative: the run decides its own success before anything looked at the tenant' {

        It 'does not call a script planned when it never decides success from post-change evidence' {
            # Arrange
            $path = New-FixtureScript -Path (Join-Path $TestDrive 'lifecycle-no-verdict.ps1') `
                -Text (New-LifecycleScript -Omit 'Success')

            # Act
            $node = Test-BaselineDeploymentMutationPlan -ScriptPath $path

            # Assert
            (Format-Lifecycle -Node $node -Expected $script:LifecycleCode['Success'] -Silent @(
                    $script:LifecycleCode['Capture']
                    $script:LifecycleCode['Journal']
                    $script:LifecycleCode['Rollback']
                    $script:LifecycleCode['Resolve']
                )) |
                Should -BeExactly 'False|True|' -Because 'a verdict the run writes for itself is true before the post-change evidence exists and stays true after it contradicts it, so the run proves only that its commands returned'
        }
    }
}
