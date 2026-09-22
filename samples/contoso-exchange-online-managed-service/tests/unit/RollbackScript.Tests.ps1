#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ChangeId = 'CHG0012345'
    $script:Tenant = 'contoso.onmicrosoft.com'
    $script:CapturedOn = [datetime]::new(2026, 9, 18, 7, 30, 0, [System.DateTimeKind]::Utc)

    function New-Capture {
        param([object[]]$Operation)

        if (-not $PSBoundParameters.ContainsKey('Operation')) {
            $Operation = @(
                [ordered]@{ OperationId = 'op-1'; Command = 'Set-TransportConfig'; Identity = 'Default'; Before = [ordered]@{ Exists = $true; Value = 'False' } }
                [ordered]@{ OperationId = 'op-2'; Command = 'New-RemoteDomain'; Identity = 'Fabrikam'; Before = [ordered]@{ Exists = $false; Value = '' } }
            )
        }

        return New-BaselineChangeStateCapture -ChangeId $script:ChangeId -Tenant $script:Tenant -Operation $Operation -CapturedOn $script:CapturedOn
    }

    # A capture the generator has to refuse is one the generator cannot be handed through the real
    # capture, so the negatives build the shape by hand rather than by perturbing a sealed snapshot.
    function New-HandBuiltCapture {
        param([hashtable]$Override = @{}, [string[]]$Remove = @())

        $entry = [ordered]@{ Sequence = 1; OperationId = 'op-1'; Command = 'Set-TransportConfig'; Identity = 'Default'; Exists = $true; Value = 'False' }
        foreach ($name in $Override.Keys) {
            if ($name -like 'Entry.*') { $entry[$name.Substring(6)] = $Override[$name] }
        }
        foreach ($name in $Remove) {
            if ($name -like 'Entry.*') { $entry.Remove($name.Substring(6)) }
        }

        $capture = [ordered]@{
            SchemaVersion = '1.0.0'
            ChangeId      = $script:ChangeId
            Tenant        = $script:Tenant
            CapturedOn    = $script:CapturedOn.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
            Algorithm     = 'SHA256'
            Hash          = ''
            Entry         = @($entry)
        }

        foreach ($name in $Override.Keys) {
            if ($name -notlike 'Entry.*') { $capture[$name] = $Override[$name] }
        }
        foreach ($name in $Remove) {
            if ($name -notlike 'Entry.*') { $capture.Remove($name) }
        }

        if (-not $Override.ContainsKey('Hash') -and $capture.Contains('Hash') -and $capture.Contains('Entry')) {
            $capture['Hash'] = [System.Convert]::ToHexString(
                [System.Security.Cryptography.SHA256]::HashData(
                    [System.Text.UTF8Encoding]::new($false).GetBytes(
                        (ConvertTo-CanonicalJson -InputObject $capture['Entry'])))).ToLowerInvariant()
        }

        return $capture
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-004-A2 rollback script generated from the capture' {

    Context 'Negative: there is no sealed capture to generate from' {

        It 'refuses a generation handed no capture at all' {
            # Arrange
            $capture = $null

            # Act
            $act = { New-BaselineRollbackScript -Capture $capture }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeRollbackCaptureNotRecognized*' -Because 'a rollback invented without a capture restores the tenant to whatever the generator assumed'
        }

        It 'refuses a capture carrying no entries at all' {
            # Arrange
            $capture = New-HandBuiltCapture -Override @{ Entry = @() }

            # Act
            $act = { New-BaselineRollbackScript -Capture $capture }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeRollbackCaptureNotRecognized*' -Because 'a rollback that restores nothing is a file that makes a change look reversible'
        }

        It 'refuses a capture carrying no change identifier' {
            # Arrange
            $capture = New-HandBuiltCapture -Remove @('ChangeId')

            # Act
            $act = { New-BaselineRollbackScript -Capture $capture }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeRollbackCaptureNotRecognized*' -Because 'a rollback nobody can tie to a change is a script nobody dares run'
        }

        It 'refuses a capture carrying no tenant' {
            # Arrange
            $capture = New-HandBuiltCapture -Remove @('Tenant')

            # Act
            $act = { New-BaselineRollbackScript -Capture $capture }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeRollbackCaptureNotRecognized*' -Because 'a restore run against the wrong tenant is a second outage'
        }

        It 'refuses a capture whose seal is not the seal of what it carries' {
            # Arrange
            $capture = New-HandBuiltCapture -Override @{ Hash = ('0' * 64) }

            # Act
            $act = { New-BaselineRollbackScript -Capture $capture }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeRollbackCaptureNotSealed*' -Because 'a snapshot edited after it was sealed is a prior state nobody observed'
        }

        It 'refuses a capture carrying no seal at all' {
            # Arrange
            $capture = New-HandBuiltCapture -Remove @('Hash')

            # Act
            $act = { New-BaselineRollbackScript -Capture $capture }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeRollbackCaptureNotSealed*' -Because 'an unsealed snapshot cannot be shown to be the one the run took'
        }
    }

    Context 'Negative: an entry does not say what to restore or how' {

        It 'refuses an entry carrying no identity' {
            # Arrange
            $capture = New-HandBuiltCapture -Remove @('Entry.Identity')

            # Act
            $act = { New-BaselineRollbackScript -Capture $capture }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeRollbackEntryNotRecognized*' -Because 'a restore with no identity is a restore of whichever object the cmdlet defaults to'
        }

        It 'refuses an entry carrying no command' {
            # Arrange
            $capture = New-HandBuiltCapture -Remove @('Entry.Command')

            # Act
            $act = { New-BaselineRollbackScript -Capture $capture }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeRollbackEntryNotRecognized*' -Because 'a prior value with nothing to restore it through cannot be restored'
        }

        It 'refuses an entry that does not say whether the object existed' {
            # Arrange
            $capture = New-HandBuiltCapture -Remove @('Entry.Exists')

            # Act
            $act = { New-BaselineRollbackScript -Capture $capture }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeRollbackEntryNotRecognized*' -Because 'restoring a value onto an object that never existed creates one nobody approved'
        }

        It 'refuses an entry that does not say what the object held' {
            # Arrange
            $capture = New-HandBuiltCapture -Remove @('Entry.Value')

            # Act
            $act = { New-BaselineRollbackScript -Capture $capture }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeRollbackEntryNotRecognized*' -Because 'a restore to an unrecorded value is a guess with a cmdlet behind it'
        }

        It 'refuses a command no removal can be derived from' {
            # Arrange
            $capture = New-HandBuiltCapture -Override @{ 'Entry.Command' = 'Invoke'; 'Entry.Exists' = $false; 'Entry.Value' = '' }

            # Act
            $act = { New-BaselineRollbackScript -Capture $capture }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeRollbackCommandNotRecognized*' -Because 'guessing how to remove an object the change created is worse than admitting it cannot be rolled back'
        }
    }

    Context 'Negative: the generated script cannot be trusted to run or to repeat' {

        It 'does not emit a script the parser rejects' {
            # Arrange
            $capture = New-Capture

            # Act
            $script = New-BaselineRollbackScript -Capture $capture

            # Assert
            $parseError = $null
            [System.Management.Automation.Language.Parser]::ParseInput($script, [ref]$null, [ref]$parseError) | Out-Null
            @($parseError).Count | Should -Be 0 -Because 'a rollback nobody can run is not a rollback'
        }

        It 'does not interpolate a captured value into the script it emits' {
            # Arrange
            $capture = New-Capture -Operation @(
                [ordered]@{ OperationId = 'op-1'; Command = 'Set-TransportConfig'; Identity = 'Default'; Before = [ordered]@{ Exists = $true; Value = "'; Remove-Mailbox -Identity 'ceo@contoso.com' #" } }
            )

            # Act
            $script = New-BaselineRollbackScript -Capture $capture

            # Assert
            $parseError = $null
            [System.Management.Automation.Language.Parser]::ParseInput($script, [ref]$null, [ref]$parseError) | Out-Null
            '{0}|{1}' -f @($parseError).Count, ($script -match "''; Remove-Mailbox -Identity ''ceo@contoso\.com'' #") |
                Should -BeExactly '0|True' -Because 'a captured value that reaches the parser as code makes every rollback an arbitrary script the tenant runs'
        }

        It 'does not restore an object the change created by setting it' {
            # Arrange
            $capture = New-Capture

            # Act
            $script = New-BaselineRollbackScript -Capture $capture

            # Assert
            '{0}|{1}' -f ($script -match 'Set-RemoteDomain'), ($script -match "Remove-RemoteDomain -Identity 'Fabrikam'") |
                Should -BeExactly 'False|True' -Because 'setting a value on an object the change created leaves the object behind'
        }

        It 'does not restore an object the change only edited by removing it' {
            # Arrange
            $capture = New-Capture

            # Act
            $script = New-BaselineRollbackScript -Capture $capture

            # Assert
            '{0}|{1}' -f ($script -match 'Remove-TransportConfig'), ($script -match "Set-TransportConfig -Identity 'Default'") |
                Should -BeExactly 'False|True' -Because 'deleting an object the change merely edited turns a rollback into an outage'
        }

        It 'does not emit the restores in the order the mutations were captured in' {
            # Arrange
            $capture = New-Capture

            # Act
            $script = New-BaselineRollbackScript -Capture $capture

            # Assert
            ($script.IndexOf('Remove-RemoteDomain') -lt $script.IndexOf('Set-TransportConfig')) |
                Should -BeTrue -Because 'unwinding in the order the change was made restores objects that depend on ones not yet restored'
        }

        It 'does not produce two different scripts from one capture' {
            # Arrange
            $first = New-BaselineRollbackScript -Capture (New-Capture)

            # Act
            $second = New-BaselineRollbackScript -Capture (New-Capture)

            # Assert
            $second | Should -BeExactly $first -Because 'a rollback that differs run to run is a rollback nobody reviewed'
        }
    }

    Context 'Positive: one capture yields one deterministic restoring script' {

        It 'restores every touched object to exactly the value the capture recorded' {
            # Arrange
            $capture = New-Capture

            # Act
            $script = New-BaselineRollbackScript -Capture $capture

            # Assert
            $expected = @(
                '#requires -Version 7.0'
                "# SAFE-004 rollback for change $script:ChangeId in tenant $script:Tenant."
                "# Generated from capture $($capture['Hash']) taken at $($capture['CapturedOn'])."
                '# Restores run in the reverse of the order the mutations were captured in.'
                '[CmdletBinding(SupportsShouldProcess)]'
                'param()'
                ''
                "`$ErrorActionPreference = 'Stop'"
                ''
                '# op-2 restores Fabrikam, which did not exist before the change.'
                "if (`$PSCmdlet.ShouldProcess('Fabrikam', 'Remove-RemoteDomain')) {"
                "    Remove-RemoteDomain -Identity 'Fabrikam' -Confirm:`$false"
                '}'
                ''
                '# op-1 restores Default to the value the capture recorded.'
                "if (`$PSCmdlet.ShouldProcess('Default', 'Set-TransportConfig')) {"
                "    Set-TransportConfig -Identity 'Default' -Value 'False' -Confirm:`$false"
                '}'
                ''
            ) -join "`n"

            $script | Should -BeExactly $expected -Because 'a rollback can only restore what the capture wrote down, exactly as it wrote it down'
        }
    }
}
