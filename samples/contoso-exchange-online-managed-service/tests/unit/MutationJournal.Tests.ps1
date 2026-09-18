#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-Mutation {
        param(
            [string]$OperationId = 'op-1',
            [string]$Command = 'Set-TransportConfig',
            [string]$Identity = 'Default',
            [hashtable]$Member = @{},
            [string[]]$Remove = @()
        )

        $mutation = [ordered]@{
            OperationId = $OperationId
            Command     = $Command
            Identity    = $Identity
        }

        foreach ($name in $Member.Keys) { $mutation[$name] = $Member[$name] }
        foreach ($name in $Remove) { $mutation.Remove($name) }

        return $mutation
    }

    function Invoke-Journal {
        param([object[]]$Operation)

        if (-not $PSBoundParameters.ContainsKey('Operation')) { $Operation = @((New-Mutation)) }

        return New-BaselineMutationJournal -Operation $Operation
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-005-A2 mutation journal' {

    Context 'Negative: the journal does not know which mutations the run declared' {

        It 'refuses a journal of no mutations at all' {
            # Arrange
            $operation = @()

            # Act
            $act = { Invoke-Journal -Operation $operation }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MutationJournalOperationNotSupplied*' -Because 'a run that journals nothing reports the same empty record whether it changed one object or every object'
        }

        It 'refuses a mutation carrying no operation identifier' {
            # Arrange
            $operation = @((New-Mutation -Remove @('OperationId')))

            # Act
            $act = { Invoke-Journal -Operation $operation }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MutationJournalOperationNotRecognized*' -Because 'an entry nobody can tie back to a declared mutation cannot be reconciled against the plan'
        }

        It 'refuses a mutation carrying no command' {
            # Arrange
            $operation = @((New-Mutation -Remove @('Command')))

            # Act
            $act = { Invoke-Journal -Operation $operation }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MutationJournalOperationNotRecognized*' -Because 'a recorded state with no command behind it says something happened without saying what'
        }

        It 'refuses a mutation carrying no identity' {
            # Arrange
            $operation = @((New-Mutation -Remove @('Identity')))

            # Act
            $act = { Invoke-Journal -Operation $operation }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MutationJournalOperationNotRecognized*' -Because 'an entry that does not name the object it touched leaves the run unable to say what it changed'
        }

        It 'refuses a mutation carrying a blank identity' {
            # Arrange
            $operation = @((New-Mutation -Identity '   '))

            # Act
            $act = { Invoke-Journal -Operation $operation }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MutationJournalOperationNotRecognized*' -Because 'whitespace where an object should be names whichever object the cmdlet defaults to'
        }

        It 'refuses the same operation identifier recorded twice' {
            # Arrange
            $operation = @(
                (New-Mutation -OperationId 'op-1' -Identity 'Default')
                (New-Mutation -OperationId 'op-1' -Identity 'Fabrikam')
            )

            # Act
            $act = { Invoke-Journal -Operation $operation }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MutationJournalOperationNotUnique*' -Because 'one declared mutation holding two entries means neither of them is the state it reached'
        }
    }

    Context 'Negative: the state an entry claims is not one the contract declares' {

        It 'refuses a state the contract never declared' {
            # Arrange
            $operation = @((New-Mutation -Member @{ State = 'Skipped' }))

            # Act
            $act = { Invoke-Journal -Operation $operation }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MutationJournalStateNotDeclared*' -Because 'a state nobody declared is a state no reader knows whether to roll back'
        }

        It 'refuses a declared state recorded in the wrong case' {
            # Arrange
            $operation = @((New-Mutation -Member @{ State = 'succeeded' }))

            # Act
            $act = { Invoke-Journal -Operation $operation }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MutationJournalStateNotDeclared*' -Because 'a journal matched loosely turns a typo into a state the contract appears to declare'
        }

        It 'refuses a failed mutation that records no fault' {
            # Arrange
            $operation = @((New-Mutation -Member @{ State = 'Failed' }))

            # Act
            $act = { Invoke-Journal -Operation $operation }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MutationJournalFaultNotRecorded*' -Because 'a failure with no fault behind it cannot be diagnosed and cannot be recovered from'
        }

        It 'refuses a failed mutation whose fault is blank' {
            # Arrange
            $operation = @((New-Mutation -Member @{ State = 'Failed'; Fault = '   ' }))

            # Act
            $act = { Invoke-Journal -Operation $operation }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MutationJournalFaultNotRecorded*' -Because 'whitespace where a fault should be reads as a recorded cause while carrying none'
        }
    }

    Context 'Negative: the journal does not record the state the mutation actually reached' {

        It 'does not record a declared but unattempted mutation as anything other than pending' {
            # Arrange
            $operation = @((New-Mutation))

            # Act
            $journal = Invoke-Journal -Operation $operation

            # Assert
            $journal[0]['State'] | Should -BeExactly 'Pending' -Because 'a mutation the run never reached is still owed to the tenant and has to stay outstanding'
        }

        It 'does not record a mutation the guard declined as anything other than pending' {
            # Arrange
            $operation = @((New-Mutation -Member @{ Approved = $false; State = 'Succeeded' }))

            # Act
            $journal = Invoke-Journal -Operation $operation

            # Assert
            $journal[0]['State'] | Should -BeExactly 'Pending' -Because 'a mutation the operator declined never ran, so recording it as done is a change the journal invented'
        }

        It 'does not record a mutation that returned as anything other than succeeded' {
            # Arrange
            $operation = @((New-Mutation -Member @{ Approved = $true; State = 'Succeeded' }))

            # Act
            $journal = Invoke-Journal -Operation $operation

            # Assert
            $journal[0]['State'] | Should -BeExactly 'Succeeded' -Because 'a mutation that completed and reads as outstanding is applied a second time by whoever resumes the run'
        }

        It 'does not record a mutation that threw as anything other than failed carrying the fault' {
            # Arrange
            $operation = @((New-Mutation -Member @{ Approved = $true; State = 'Failed'; Fault = 'RemoteDomainNotFound' }))

            # Act
            $journal = Invoke-Journal -Operation $operation

            # Assert
            '{0}|{1}' -f $journal[0]['State'], $journal[0]['Fault'] |
                Should -BeExactly 'Failed|RemoteDomainNotFound' -Because 'a failure recorded without its cause is a failure nobody can act on'
        }

        It 'does not record a mutation restored from its captured prior state as anything other than rolled-back' {
            # Arrange
            $operation = @((New-Mutation -Member @{ Approved = $true; State = 'RolledBack' }))

            # Act
            $journal = Invoke-Journal -Operation $operation

            # Assert
            $journal[0]['State'] | Should -BeExactly 'RolledBack' -Because 'a restored object recorded as succeeded leaves the run claiming a change it deliberately undid'
        }

        It 'does not drop a declared mutation from the journal' {
            # Arrange
            $operation = @(
                (New-Mutation -OperationId 'op-1' -Identity 'Default' -Member @{ Approved = $true; State = 'Succeeded' })
                (New-Mutation -OperationId 'op-2' -Command 'New-RemoteDomain' -Identity 'Fabrikam')
                (New-Mutation -OperationId 'op-3' -Command 'Set-RemoteDomain' -Identity 'Contoso' -Member @{ Approved = $false })
            )

            # Act
            $journal = Invoke-Journal -Operation $operation

            # Assert
            @($journal).Count | Should -Be 3 -Because 'a mutation the run declared and the journal never mentions is a change nobody knows to check or to undo'
        }

        It 'does not admit an entry a caller can edit after the fact' {
            # Arrange
            $journal = Invoke-Journal

            # Act
            $act = { $journal[0]['State'] = 'Succeeded' }

            # Assert
            $act | Should -Throw -Because 'a state a caller can rewrite is a state nobody observed'
        }
    }

    Context 'Positive: one run records one entry per declared mutation' {

        It 'records every declared mutation with the object it touched and the state it reached' {
            # Arrange
            $operation = @(
                (New-Mutation -OperationId 'op-1' -Command 'Set-TransportConfig' -Identity 'Default' -Member @{ Approved = $true; State = 'Succeeded' })
                (New-Mutation -OperationId 'op-2' -Command 'New-RemoteDomain' -Identity 'Fabrikam' -Member @{ Approved = $true; State = 'Failed'; Fault = 'RemoteDomainNotFound' })
                (New-Mutation -OperationId 'op-3' -Command 'Set-RemoteDomain' -Identity 'Contoso' -Member @{ Approved = $true; State = 'RolledBack' })
                (New-Mutation -OperationId 'op-4' -Command 'Set-OwaMailboxPolicy' -Identity 'OwaMailboxPolicy-Default' -Member @{ Approved = $false })
                (New-Mutation -OperationId 'op-5' -Command 'Set-CASMailbox' -Identity 'ceo@contoso.com')
            )

            # Act
            $journal = Invoke-Journal -Operation $operation

            # Assert
            $recorded = (@($journal) | ForEach-Object {
                    '{0}:{1}:{2}:{3}:{4}:{5}' -f $_['Sequence'], $_['OperationId'], $_['Command'], $_['Identity'], $_['State'], $_['Fault']
                }) -join ';'

            $recorded | Should -BeExactly (@(
                    '1:op-1:Set-TransportConfig:Default:Succeeded:'
                    '2:op-2:New-RemoteDomain:Fabrikam:Failed:RemoteDomainNotFound'
                    '3:op-3:Set-RemoteDomain:Contoso:RolledBack:'
                    '4:op-4:Set-OwaMailboxPolicy:OwaMailboxPolicy-Default:Pending:'
                    '5:op-5:Set-CASMailbox:ceo@contoso.com:Pending:'
                ) -join ';') -Because 'a run can only be reconciled against its plan when every declared mutation carries the object it touched and the state it reached'
        }
    }
}
