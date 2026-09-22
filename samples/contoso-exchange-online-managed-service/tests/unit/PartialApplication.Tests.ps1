#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ChangeId = 'CHG0012345'

    function New-Step {
        param(
            [string]$Id,
            [string]$Command,
            [string]$Identity,
            [string[]]$DependsOn = @(),
            [string]$State = 'Pending',
            [string]$Fault = ''
        )

        return [pscustomobject]@{
            Id        = $Id
            Command   = $Command
            Identity  = $Identity
            DependsOn = @($DependsOn)
            State     = $State
            Fault     = $Fault
        }
    }

    # One object failed, the two that depend on it never ran, and one unrelated object is still
    # owed - the shape every partly-applied run takes.
    function New-DefaultStep {
        return @(
            (New-Step -Id 'op-1' -Command 'Set-TransportConfig' -Identity 'Default' -State 'Succeeded')
            (New-Step -Id 'op-2' -Command 'New-RemoteDomain' -Identity 'Fabrikam' -DependsOn @('op-1') -State 'Failed' -Fault 'RemoteDomainNotFound')
            (New-Step -Id 'op-3' -Command 'Set-RemoteDomain' -Identity 'Fabrikam' -DependsOn @('op-2'))
            (New-Step -Id 'op-4' -Command 'Set-CASMailbox' -Identity 'ceo@contoso.com' -DependsOn @('op-3'))
            (New-Step -Id 'op-5' -Command 'Set-OwaMailboxPolicy' -Identity 'OwaMailboxPolicy-Default')
        )
    }

    function ConvertTo-Plan {
        param([object[]]$Step)

        return @($Step | ForEach-Object {
                [ordered]@{
                    OperationId = $_.Id
                    Command     = $_.Command
                    Identity    = $_.Identity
                    DependsOn   = @($_.DependsOn)
                }
            })
    }

    function ConvertTo-Journal {
        param([object[]]$Step)

        return New-BaselineMutationJournal -Operation @($Step | ForEach-Object {
                [ordered]@{
                    OperationId = $_.Id
                    Command     = $_.Command
                    Identity    = $_.Identity
                    State       = $_.State
                    Fault       = $_.Fault
                }
            })
    }

    function Invoke-Application {
        param([object[]]$Step, [hashtable]$Override = @{})

        if (-not $PSBoundParameters.ContainsKey('Step')) { $Step = New-DefaultStep }

        $argument = @{
            ChangeId  = $script:ChangeId
            Operation = (ConvertTo-Plan -Step $Step)
            Journal   = (ConvertTo-Journal -Step $Step)
        }
        foreach ($name in $Override.Keys) { $argument[$name] = $Override[$name] }

        return Resolve-BaselinePartialApplication @argument
    }

    function Format-Recovery {
        param([object]$Application)

        return (@($Application['Recovery']) | ForEach-Object {
                '{0}:{1}:{2}:{3}' -f $_['Sequence'], $_['OperationId'], $_['Action'], $_['Reason']
            }) -join ';'
    }

    function New-ApplicationRoot {
        $path = Join-Path ([System.IO.Path]::GetTempPath()) ('partial-application-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        return $path
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-006-A1 partial-application record' {

    Context 'Negative: the run cannot be reconciled against the plan it declared' {

        It 'refuses a record that names no change' {
            # Arrange
            $override = @{ ChangeId = '   ' }

            # Act
            $act = { Invoke-Application -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeIdentifierNotRecognized*' -Because 'partial state nobody can tie to a change is partial state no recovery can find'
        }

        It 'refuses a plan of no operations at all' {
            # Arrange
            $override = @{ Operation = @() }

            # Act
            $act = { Invoke-Application -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'PartialApplicationOperationNotSupplied*' -Because 'a run reconciled against no plan can call any amount of damage a complete application'
        }

        It 'refuses an operation that does not name the object it touched' {
            # Arrange
            $step = @((New-Step -Id 'op-1' -Command 'Set-TransportConfig' -Identity '   ' -State 'Succeeded'))

            # Act
            $act = { Invoke-Application -Override @{ Operation = (ConvertTo-Plan -Step $step) } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'PartialApplicationOperationNotRecognized*' -Because 'a recovery instruction with no object in it is an instruction nobody can carry out'
        }

        It 'refuses a run that produced no journal at all' {
            # Arrange
            $override = @{ Journal = $null }

            # Act
            $act = { Invoke-Application -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'PartialApplicationJournalNotSupplied*' -Because 'a run with no journal behind it has no partial state to persist, only an assumption'
        }

        It 'refuses a journal entry naming an operation the plan never declared' {
            # Arrange
            $surplus = @((New-Step -Id 'op-9' -Command 'Set-Mailbox' -Identity 'ceo@contoso.com' -State 'Succeeded'))

            # Act
            $act = { Invoke-Application -Override @{ Journal = (ConvertTo-Journal -Step ((New-DefaultStep) + $surplus)) } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'PartialApplicationJournalNotReconciled*' -Because 'an object mutated outside the approved plan is the one change nobody previewed'
        }

        It 'refuses a declared operation the journal never recorded' {
            # Arrange
            $step = New-DefaultStep

            # Act
            $act = { Invoke-Application -Override @{ Journal = (ConvertTo-Journal -Step @($step[0..3])) } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'PartialApplicationJournalNotReconciled*' -Because 'a declared mutation nobody journalled is a change whose state the run cannot state either way'
        }
    }

    Context 'Negative: the dependencies do not describe an order anything can be stopped in' {

        It 'refuses a dependency naming an operation the plan never declared' {
            # Arrange
            $step = @(
                (New-Step -Id 'op-1' -Command 'Set-TransportConfig' -Identity 'Default' -State 'Succeeded')
                (New-Step -Id 'op-2' -Command 'New-RemoteDomain' -Identity 'Fabrikam' -DependsOn @('op-7'))
            )

            # Act
            $act = { Invoke-Application -Step $step }

            # Assert
            $act | Should -Throw -ExpectedMessage 'PartialApplicationDependencyNotDeclared*' -Because 'an operation waiting on something outside the plan can never be shown to be safe to run'
        }

        It 'refuses an operation that depends on itself' {
            # Arrange
            $step = @((New-Step -Id 'op-1' -Command 'Set-TransportConfig' -Identity 'Default' -DependsOn @('op-1')))

            # Act
            $act = { Invoke-Application -Step $step }

            # Assert
            $act | Should -Throw -ExpectedMessage 'PartialApplicationDependencyNotOrdered*' -Because 'an operation that blocks itself can never be stopped or resumed'
        }

        It 'refuses a cycle of dependencies' {
            # Arrange
            $step = @(
                (New-Step -Id 'op-1' -Command 'Set-TransportConfig' -Identity 'Default' -DependsOn @('op-3'))
                (New-Step -Id 'op-2' -Command 'New-RemoteDomain' -Identity 'Fabrikam' -DependsOn @('op-1'))
                (New-Step -Id 'op-3' -Command 'Set-RemoteDomain' -Identity 'Fabrikam' -DependsOn @('op-2'))
            )

            # Act
            $act = { Invoke-Application -Step $step }

            # Assert
            $act | Should -Throw -ExpectedMessage 'PartialApplicationDependencyNotOrdered*' -Because 'a cycle makes every operation in it both the blocker and the blocked, so no recovery order exists'
        }
    }

    Context 'Negative: the record does not say what the run actually left behind' {

        It 'does not report an operation whose dependency failed as merely outstanding' {
            # Arrange
            $step = New-DefaultStep

            # Act
            $application = Invoke-Application -Step $step

            # Assert
            '{0}|{1}' -f (@($application['Halted']) -contains 'op-3'), (@($application['Outstanding']) -contains 'op-3') |
                Should -BeExactly 'True|False' -Because 'an operation whose prerequisite failed is not waiting its turn, it is stopped, and a run that resumes it applies a change onto a state that never arrived'
        }

        It 'does not report an operation halted only through another halted operation as outstanding' {
            # Arrange
            $step = New-DefaultStep

            # Act
            $application = Invoke-Application -Step $step

            # Assert
            '{0}|{1}' -f (@($application['Halted']) -contains 'op-4'), (@($application['Outstanding']) -contains 'op-4') |
                Should -BeExactly 'True|False' -Because 'stopping only the immediate dependents leaves everything behind them free to run on a state that never arrived'
        }

        It 'does not report an operation that already succeeded as halted because a later one failed' {
            # Arrange
            $step = @(
                (New-Step -Id 'op-1' -Command 'Set-TransportConfig' -Identity 'Default' -State 'Failed' -Fault 'TransportConfigLocked')
                (New-Step -Id 'op-2' -Command 'New-RemoteDomain' -Identity 'Fabrikam' -DependsOn @('op-1') -State 'Succeeded')
            )

            # Act
            $application = Invoke-Application -Step $step

            # Assert
            '{0}|{1}' -f (@($application['Applied']) -contains 'op-2'), (@($application['Halted']) -contains 'op-2') |
                Should -BeExactly 'True|False' -Because 'a change that is already on the tenant is not stopped, and calling it stopped hides a mutation the recovery has to account for'
        }

        It 'does not omit the recovery step for a failed operation' {
            # Arrange
            $step = New-DefaultStep

            # Act
            $application = Invoke-Application -Step $step

            # Assert
            (Format-Recovery -Application $application) | Should -BeLike '*op-2:Investigate:RemoteDomainNotFound*' -Because 'a failure with no recovery step is a failure the run expects somebody to remember'
        }

        It 'does not omit the recovery step for a halted operation' {
            # Arrange
            $step = New-DefaultStep

            # Act
            $application = Invoke-Application -Step $step

            # Assert
            (Format-Recovery -Application $application) | Should -BeLike "*op-3:Resume:blocked by 'op-2'*" -Because 'an operation nobody was told is stopped is an operation somebody assumes ran'
        }

        It 'does not emit a recovery step for an operation that already succeeded' {
            # Arrange
            $step = New-DefaultStep

            # Act
            $application = Invoke-Application -Step $step

            # Assert
            (Format-Recovery -Application $application) | Should -Not -BeLike '*op-1*' -Because 'reapplying a change that already landed turns recovery into a second unreviewed change'
        }

        It 'does not produce two different records from one plan and journal' {
            # Arrange
            $first = Invoke-Application

            # Act
            $second = Invoke-Application

            # Assert
            (ConvertTo-CanonicalJson -InputObject $second) | Should -BeExactly (ConvertTo-CanonicalJson -InputObject $first) -Because 'recovery instructions that differ run to run are instructions nobody reviewed'
        }

        It 'does not leave the partial state unwritten when a root is supplied' {
            # Arrange
            $root = New-ApplicationRoot

            # Act
            $null = Invoke-Application -Override @{ Root = $root }

            # Assert
            (Test-Path -LiteralPath (Join-Path $root "apply-$script:ChangeId.json")) |
                Should -BeTrue -Because 'partial state that only ever existed in the memory of the run that died is partial state nobody can recover from'
        }

        It 'does not admit a record a caller can edit after the fact' {
            # Arrange
            $application = Invoke-Application

            # Act
            $act = { $application['Halted'] = @() }

            # Assert
            $act | Should -Throw -Because 'a partial state a caller can rewrite is a partial state nobody observed'
        }
    }

    Context 'Positive: one partly-failed run yields one persisted record of what it left behind' {

        It 'names what applied, what failed, what was halted and the deterministic recovery for each' {
            # Arrange
            $root = New-ApplicationRoot

            # Act
            $application = Invoke-Application -Override @{ Root = $root }

            # Assert
            $persisted = Get-Content -LiteralPath (Join-Path $root "apply-$script:ChangeId.json") -Raw

            '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f
            $application['ChangeId'],
            (@($application['Applied']) -join ','),
            (@($application['Failed']) -join ','),
            (@($application['Halted']) -join ','),
            (@($application['Outstanding']) -join ','),
            (Format-Recovery -Application $application),
            ($persisted -eq (ConvertTo-CanonicalJson -InputObject $application)) |
                Should -BeExactly ("$script:ChangeId|op-1|op-2|op-3,op-4|op-5|" +
                    "1:op-2:Investigate:RemoteDomainNotFound;" +
                    "2:op-3:Resume:blocked by 'op-2';" +
                    "3:op-4:Resume:blocked by 'op-3';" +
                    "4:op-5:Apply:|True") -Because 'a run that stopped halfway can only be recovered from a record that says exactly which objects it reached, which it stopped, and what is owed on each'
        }
    }
}
