#requires -Version 7.0

# Every way a run can end that is not success, named with the outcome it has to resolve to and the
# control that has to be named by it. Held in discovery scope rather than inside `BeforeAll`,
# because a `-ForEach` table that only exists at run time expands to no tests at all and a suite
# that silently ran nothing reads exactly like a suite that passed.
$FaultScenario = @(
    @{ Name = 'NothingDecided'; Outcome = 'Collection'; ControlId = '' }
    @{ Name = 'Error'; Outcome = 'Collection'; ControlId = 'EXO-002' }
    @{ Name = 'Fail'; Outcome = 'Compliance'; ControlId = 'EXO-002' }
    @{ Name = 'Manual'; Outcome = 'Compliance'; ControlId = 'EXO-002' }
    @{ Name = 'NotEntitled'; Outcome = 'Compliance'; ControlId = 'EXO-002' }
    @{ Name = 'Unverified'; Outcome = 'Compliance'; ControlId = 'EXO-002' }
    @{ Name = 'ExceptionRefused'; Outcome = 'Approval'; ControlId = 'GATE-003' }
    @{ Name = 'RefusedOtherwise'; Outcome = 'Compliance'; ControlId = 'GATE-003' }
)

$NamedFaultScenario = @($FaultScenario | Where-Object { $_.ControlId -ne '' })

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-OutcomeCheck {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ControlId,

            [Parameter(Mandatory)]
            [string]$Status
        )

        if ($Status -ceq 'Pass') {
            return New-ControlResult -ControlId $ControlId -Status $Status
        }

        return New-ControlResult -ControlId $ControlId -Status $Status -Reason "$ControlId was decided '$Status'."
    }

    # The shape `Test-BaselineGoLive` returns, built here rather than run, because the seam under
    # test reads a decision and must not be able to tell a real one from a fabricated one.
    function New-OutcomeDecision {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [bool]$Admitted,

            [string[]]$Finding = @()
        )

        $result = if ($Admitted) {
            New-ControlResult -ControlId 'GATE-003' -Status 'Pass'
        }
        else {
            New-ControlResult -ControlId 'GATE-003' -Status 'Fail' -Reason "GoLiveRefused: $($Finding -join ' ')"
        }

        return [pscustomobject]@{
            Admitted    = $Admitted
            RequestedBy = 'operator@contoso.com'
            Finding     = @($Finding)
            Exception   = @()
            Result      = $result
        }
    }

    function Invoke-OutcomeScenario {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Name
        )

        switch ($Name) {
            'NothingDecided' {
                return Get-BaselineRunOutcome -Check @() -GoLive (New-OutcomeDecision -Admitted $true)
            }
            'ExceptionRefused' {
                return Get-BaselineRunOutcome -Check @(New-OutcomeCheck -ControlId 'EXO-001' -Status 'Pass') `
                    -GoLive (New-OutcomeDecision -Admitted $false -Finding @("GoLiveExceptionRefused: the risk acceptance raised for 'EXO-002' does not excuse it. The acceptance expired."))
            }
            'RefusedOtherwise' {
                return Get-BaselineRunOutcome -Check @(New-OutcomeCheck -ControlId 'EXO-001' -Status 'Pass') `
                    -GoLive (New-OutcomeDecision -Admitted $false -Finding @('GoLiveEvidenceStale: the evidence is 90 days old and the maximum evidence age is 7 days.'))
            }
            default {
                return Get-BaselineRunOutcome -Check @(
                    (New-OutcomeCheck -ControlId 'EXO-001' -Status 'Pass')
                    (New-OutcomeCheck -ControlId 'EXO-002' -Status $Name)
                ) -GoLive (New-OutcomeDecision -Admitted $true)
            }
        }
    }

    function Get-OutcomeMemberName {
        [CmdletBinding()]
        param([Parameter(Mandatory)][object]$Contract)

        if ($Contract -is [System.Collections.IDictionary]) { return @($Contract.Keys) }

        return @($Contract.PSObject.Properties | Where-Object { $_.MemberType -ne 'Method' } | ForEach-Object { $_.Name })
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GATE-004-A2 the run-outcome seam' {

    Context 'Negative: a seam nothing can reach is a seam the shipped script decides around' {

        It 'exposes the run-outcome seam' {
            # Arrange
            $name = 'Get-BaselineRunOutcome'

            # Act
            $command = Get-Command -Name $name -Module 'ExchangeOnlineBaseline.Common' -ErrorAction SilentlyContinue

            # Assert
            $command | Should -Not -BeNullOrEmpty -Because 'an entry script that cannot reach the seam is an entry script that resolves its own exit'
        }
    }

    Context 'Negative: a run the seam was never handed is a run it must refuse to judge' {

        It 'refuses a run it was handed no checks to read' {
            # Arrange
            $decision = New-OutcomeDecision -Admitted $true

            # Act
            $act = { Get-BaselineRunOutcome -Check $null -GoLive $decision }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RunOutcomeCheckRequired*' -Because 'a seam handed nothing to read has nothing to fail on and would report success'
        }
    }

    Context 'Negative: a run nothing could be collected from has not passed, it has failed to start' {

        It 'resolves a run that decided nothing at all to the collection outcome' {
            # Arrange
            $decision = New-OutcomeDecision -Admitted $true

            # Act
            $outcome = Get-BaselineRunOutcome -Check @() -GoLive $decision

            # Assert
            $outcome.Outcome | Should -BeExactly 'Collection' -Because 'a run that decided nothing observed nothing, and nothing observed is not everything clean'
        }

        It 'resolves a check decided Error to the collection outcome' {
            # Arrange
            $check = @(
                (New-OutcomeCheck -ControlId 'EXO-001' -Status 'Pass')
                (New-OutcomeCheck -ControlId 'EXO-002' -Status 'Error')
            )

            # Act
            $outcome = Get-BaselineRunOutcome -Check $check -GoLive (New-OutcomeDecision -Admitted $true)

            # Assert
            $outcome.Outcome | Should -BeExactly 'Collection' -Because 'a control the run could not collect is a rerun the caller can act on, not a compliance gap it must escalate'
        }
    }

    Context 'Negative: a control nobody could decide is not a control that passed' {

        It 'resolves a check decided <_> to the compliance outcome' -ForEach @('Fail', 'Manual', 'NotEntitled', 'Unverified') {
            # Arrange
            $check = @(
                (New-OutcomeCheck -ControlId 'EXO-001' -Status 'Pass')
                (New-OutcomeCheck -ControlId 'EXO-002' -Status $_)
            )

            # Act
            $outcome = Get-BaselineRunOutcome -Check $check -GoLive (New-OutcomeDecision -Admitted $true)

            # Assert
            $outcome.Outcome | Should -BeExactly 'Compliance' -Because "a '$_' verdict the seam treats as success is a control that was never actually verified"
        }
    }

    Context 'Negative: a refused go-live is not a run that passed' {

        It 'resolves a go-live refused because a risk acceptance did not hold to the approval outcome' {
            # Arrange
            $decision = New-OutcomeDecision -Admitted $false -Finding @("GoLiveExceptionRefused: the risk acceptance raised for 'EXO-002' does not excuse it. The acceptance expired.")

            # Act
            $outcome = Get-BaselineRunOutcome -Check @(New-OutcomeCheck -ControlId 'EXO-001' -Status 'Pass') -GoLive $decision

            # Assert
            $outcome.Outcome | Should -BeExactly 'Approval' -Because 'an approval the caller must go and obtain is not a control it must go and fix'
        }

        It 'resolves a go-live refused for any other reason to the compliance outcome' {
            # Arrange
            $decision = New-OutcomeDecision -Admitted $false -Finding @('GoLiveEvidenceStale: the evidence is 90 days old and the maximum evidence age is 7 days.')

            # Act
            $outcome = Get-BaselineRunOutcome -Check @(New-OutcomeCheck -ControlId 'EXO-001' -Status 'Pass') -GoLive $decision

            # Assert
            $outcome.Outcome | Should -BeExactly 'Compliance' -Because 'a refusal reported as an approval gap sends the caller to an approver for a gap no approver can close'
        }
    }

    Context 'Negative: an outcome that does not carry its declared code tells an automation caller nothing' {

        It 'resolves the <Name> run to the code the contract declares for <Outcome>' -ForEach $FaultScenario {
            # Arrange
            $expected = (Get-BaselineExitCodeContract).$Outcome

            # Act
            $resolved = Invoke-OutcomeScenario -Name $Name

            # Assert
            $resolved.ExitCode | Should -BeExactly $expected -Because 'an outcome and a code that disagree leave the caller acting on the wrong one'
        }

        It 'never resolves the <Name> run to the success code' -ForEach $FaultScenario {
            # Arrange
            $success = (Get-BaselineExitCodeContract).Success

            # Act
            $resolved = Invoke-OutcomeScenario -Name $Name

            # Assert
            $resolved.ExitCode | Should -Not -BeExactly $success -Because 'a failure that resolves to the success code is a failure nothing downstream will ever notice'
        }
    }

    Context 'Negative: an outcome that names no control leaves the caller nothing to act on' {

        It 'names the control that decided the <Name> run' -ForEach $NamedFaultScenario {
            # Arrange
            $expected = $ControlId

            # Act
            $resolved = Invoke-OutcomeScenario -Name $Name

            # Assert
            $resolved.ControlId | Should -BeExactly $expected -Because 'a refusal that names no control is a refusal nobody can start from'
        }
    }

    Context 'Negative: an outcome the contract never declared is a code nobody was told to expect' {

        It 'resolves the <Name> run to an outcome the contract declares' -ForEach $FaultScenario {
            # Arrange
            $declared = Get-OutcomeMemberName -Contract (Get-BaselineExitCodeContract)

            # Act
            $resolved = Invoke-OutcomeScenario -Name $Name

            # Assert
            $declared | Should -Contain $resolved.Outcome -Because 'an outcome nothing declared is an exit no caller was told how to handle'
        }
    }

    Context 'Negative: an outcome a later stage can rewrite is an outcome a later stage can open' {

        It 'refuses assignment to the outcome it resolved' {
            # Arrange
            $outcome = Invoke-OutcomeScenario -Name 'Fail'

            # Act
            $act = { $outcome.Outcome = 'Success' }

            # Assert
            $act | Should -Throw -Because 'an exit a later stage can overwrite is an exit the gate does not control'
        }
    }

    Context 'Positive: a run whose every check passed and whose go-live was admitted succeeds' {

        It 'resolves a clean, admitted run to the success outcome at code zero' {
            # Arrange
            $check = @(
                (New-OutcomeCheck -ControlId 'EXO-001' -Status 'Pass')
                (New-OutcomeCheck -ControlId 'EXO-002' -Status 'NotApplicable')
                (New-OutcomeCheck -ControlId 'EXO-003' -Status 'ApprovedException')
            )

            # Act
            $outcome = Get-BaselineRunOutcome -Check $check -GoLive (New-OutcomeDecision -Admitted $true)

            # Assert
            ('Outcome={0}:ExitCode={1}' -f $outcome.Outcome, $outcome.ExitCode) |
                Should -BeExactly 'Outcome=Success:ExitCode=0' -Because 'the one run that earned a zero is the run where every control passed, did not apply, or was properly excused'
        }
    }
}
