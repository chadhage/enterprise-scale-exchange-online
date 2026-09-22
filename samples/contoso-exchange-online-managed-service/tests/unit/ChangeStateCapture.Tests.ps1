#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ChangeId = 'CHG0012345'
    $script:Tenant = 'contoso.onmicrosoft.com'
    $script:CapturedOn = [datetime]::new(2026, 9, 18, 7, 30, 0, [System.DateTimeKind]::Utc)

    function New-Operation {
        param(
            [string]$OperationId = 'op-1',
            [string]$Command = 'Set-TransportConfig',
            [string]$Identity = 'Default',
            [hashtable]$Remove = @{},
            [hashtable]$Before = @{ Exists = $true; Value = 'False' }
        )

        $operation = [ordered]@{
            OperationId = $OperationId
            Command     = $Command
            Identity    = $Identity
            Before      = [ordered]@{}
        }

        foreach ($name in @('Exists', 'Value')) {
            if ($Before.ContainsKey($name)) { $operation['Before'][$name] = $Before[$name] }
        }

        if ($Remove.ContainsKey('Before')) { $operation.Remove('Before') }
        foreach ($name in @('OperationId', 'Command', 'Identity')) {
            if ($Remove.ContainsKey($name)) { $operation.Remove($name) }
        }

        return $operation
    }

    function Invoke-Capture {
        param([hashtable]$Override = @{})

        $argument = @{
            ChangeId   = $script:ChangeId
            Tenant     = $script:Tenant
            Operation  = @((New-Operation))
            CapturedOn = $script:CapturedOn
        }
        foreach ($name in $Override.Keys) { $argument[$name] = $Override[$name] }

        return New-BaselineChangeStateCapture @argument
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-004-A1 pre-change state capture' {

    Context 'Negative: the capture does not know which change, tenant or objects it is about' {

        It 'refuses a capture that names no change' {
            # Arrange
            $override = @{ ChangeId = '' }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeIdentifierNotRecognized*' -Because 'a snapshot nobody can tie to a change is a snapshot no rollback can find'
        }

        It 'refuses a change identifier carrying a directory separator' {
            # Arrange
            $override = @{ ChangeId = '../CHG0012345' }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeIdentifierNotRecognized*' -Because 'an identifier that survives into a path writes the snapshot wherever the caller pointed'
        }

        It 'refuses a capture that names no tenant' {
            # Arrange
            $override = @{ Tenant = '   ' }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeCaptureTenantNotSupplied*' -Because 'prior values restored into the wrong tenant are a second outage, not a rollback'
        }

        It 'refuses a capture of no operations at all' {
            # Arrange
            $override = @{ Operation = @() }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeCaptureOperationNotSupplied*' -Because 'a snapshot of nothing lets a run mutate anything and still claim it captured the state first'
        }

        It 'refuses a capture taken at no particular instant' {
            # Arrange
            $override = @{ CapturedOn = 'shortly before the change' }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeCaptureTimeNotSupplied*' -Because 'a snapshot with no instant cannot be shown to predate the mutation it is supposed to precede'
        }
    }

    Context 'Negative: an operation does not say what it is about to touch' {

        It 'refuses an operation carrying no operation identifier' {
            # Arrange
            $override = @{ Operation = @((New-Operation -Remove @{ OperationId = $true })) }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeCaptureOperationNotRecognized*' -Because 'a captured state nothing can be matched back to is a state nothing restores'
        }

        It 'refuses an operation carrying a blank operation identifier' {
            # Arrange
            $override = @{ Operation = @((New-Operation -OperationId '  ')) }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeCaptureOperationNotRecognized*' -Because 'an identifier that is only whitespace names nothing'
        }

        It 'refuses an operation carrying no command' {
            # Arrange
            $override = @{ Operation = @((New-Operation -Remove @{ Command = $true })) }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeCaptureOperationNotRecognized*' -Because 'a prior value with no command against it cannot be restored by anything'
        }

        It 'refuses an operation carrying no identity' {
            # Arrange
            $override = @{ Operation = @((New-Operation -Remove @{ Identity = $true })) }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeCaptureOperationNotRecognized*' -Because 'a capture that does not name the object it captured restores nothing in particular'
        }

        It 'refuses an operation carrying a blank identity' {
            # Arrange
            $override = @{ Operation = @((New-Operation -Identity '')) }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeCaptureOperationNotRecognized*' -Because 'an empty identity is the default object of whichever cmdlet runs next'
        }
    }

    Context 'Negative: the prior state is not restorable' {

        It 'refuses an operation carrying no prior state at all' {
            # Arrange
            $override = @{ Operation = @((New-Operation -Remove @{ Before = $true })) }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeCaptureStateNotRecognized*' -Because 'a mutation whose prior state was never captured is a mutation nothing can undo'
        }

        It 'refuses a prior state that does not declare whether the object exists' {
            # Arrange
            $override = @{ Operation = @((New-Operation -Before @{ Value = 'False' })) }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeCaptureStateNotRecognized*' -Because 'restoring a value onto an object that never existed creates one nobody approved'
        }

        It 'refuses a prior state that does not declare the value the object held' {
            # Arrange
            $override = @{ Operation = @((New-Operation -Before @{ Exists = $true })) }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeCaptureStateNotRecognized*' -Because 'knowing an object existed without knowing what it held restores it to a guess'
        }

        It 'refuses an object declared absent that nonetheless carries a value' {
            # Arrange
            $override = @{ Operation = @((New-Operation -Before @{ Exists = $false; Value = 'False' })) }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeCaptureStateNotRestorable*' -Because 'an object that did not exist and held a value is two different prior states at once'
        }
    }

    Context 'Negative: the same object is captured more than once' {

        It 'refuses two operations sharing an operation identifier' {
            # Arrange
            $override = @{ Operation = @(
                    (New-Operation -OperationId 'op-1' -Identity 'Default')
                    (New-Operation -OperationId 'op-1' -Identity 'Contoso')
                ) }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeCaptureOperationNotUnique*' -Because 'two captures under one identifier make every restore of it ambiguous'
        }

        It 'refuses the same object captured twice under the same command' {
            # Arrange
            $override = @{ Operation = @(
                    (New-Operation -OperationId 'op-1' -Before @{ Exists = $true; Value = 'False' })
                    (New-Operation -OperationId 'op-2' -Before @{ Exists = $true; Value = 'True' })
                ) }

            # Act
            $act = { Invoke-Capture -Override $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeCaptureObjectNotUnique*' -Because 'an object with two recorded prior values has no restorable prior value'
        }
    }

    Context 'Negative: the snapshot can be rewritten or does not seal what it carries' {

        It 'refuses assignment to the capture' {
            # Arrange
            $capture = Invoke-Capture

            # Act
            $act = { $capture['Hash'] = 'whatever the caller wanted' }

            # Assert
            $act | Should -Throw -Because 'a snapshot a caller can rewrite restores the tenant to whatever that caller preferred'
        }

        It 'refuses assignment to a captured entry' {
            # Arrange
            $capture = Invoke-Capture

            # Act
            $act = { $capture['Entry'][0] = 'restored' }

            # Assert
            $act | Should -Throw -Because 'a prior value a caller can edit is a prior value nobody observed'
        }

        It 'does not seal two different captured states under one hash' {
            # Arrange
            $first = Invoke-Capture

            # Act
            $second = Invoke-Capture -Override @{ Operation = @((New-Operation -Before @{ Exists = $true; Value = 'True' })) }

            # Assert
            $second['Hash'] | Should -Not -BeExactly $first['Hash'] -Because 'a seal that does not move when the captured state moves seals nothing'
        }

        It 'does not produce two different captures from one set of inputs' {
            # Arrange
            $first = Invoke-Capture

            # Act
            $second = Invoke-Capture

            # Assert
            $second['Hash'] | Should -BeExactly $first['Hash'] -Because 'a snapshot that differs run to run can never be shown to be the state the run found'
        }
    }

    Context 'Positive: one run captures every touched object with its existence and restorable prior value' {

        It 'yields one immutable hashed snapshot of every touched object' {
            # Arrange
            $operation = @(
                (New-Operation -OperationId 'op-1' -Command 'Set-TransportConfig' -Identity 'Default' -Before @{ Exists = $true; Value = 'False' })
                (New-Operation -OperationId 'op-2' -Command 'New-RemoteDomain' -Identity 'Fabrikam' -Before @{ Exists = $false; Value = '' })
            )

            # Act
            $capture = Invoke-Capture -Override @{ Operation = $operation }

            # Assert
            $sealed = [System.Convert]::ToHexString(
                [System.Security.Cryptography.SHA256]::HashData(
                    [System.Text.UTF8Encoding]::new($false).GetBytes(
                        (ConvertTo-CanonicalJson -InputObject $capture['Entry'])))).ToLowerInvariant()
            $touched = (@($capture['Entry']) | ForEach-Object { '{0}:{1}:{2}:{3}:{4}:{5}' -f $_['Sequence'], $_['OperationId'], $_['Command'], $_['Identity'], $_['Exists'], [string]$_['Value'] }) -join ';'

            '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f
            $capture['ChangeId'], $capture['Tenant'], $capture['CapturedOn'], $capture['Algorithm'],
            ($capture['Hash'] -eq $sealed), @($capture['Entry']).Count, $touched |
                Should -BeExactly ('{0}|{1}|2026-09-18T07:30:00.0000000Z|SHA256|True|2|1:op-1:Set-TransportConfig:Default:True:False;2:op-2:New-RemoteDomain:Fabrikam:False:' -f $script:ChangeId, $script:Tenant) -Because 'a rollback can only restore what the capture wrote down, exactly as it wrote it down'
        }
    }
}
