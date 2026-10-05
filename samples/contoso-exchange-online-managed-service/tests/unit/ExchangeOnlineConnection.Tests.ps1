BeforeAll {
    $script:root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:modulePath = Join-Path $script:root 'scripts/ExchangeOnlineBaseline.Connection.psm1'
    Import-Module $script:modulePath -Force
    $script:tenant = '11111111-2222-3333-4444-555555555555'

    function global:Get-ConnectionInformation { @($global:connectionTestSessions) }
    function global:Connect-ExchangeOnline {
        param([string]$UserPrincipalName, [switch]$Device, [bool]$ShowBanner)
        $global:connectionTestCalls.Add(@{ Command = 'Connect'; UserPrincipalName = $UserPrincipalName; Device = [bool]$Device })
        if ($global:connectionTestConnectError) { throw $global:connectionTestConnectError }
        $signInUser = if ($global:connectionTestSignInUserPrincipalName) { $global:connectionTestSignInUserPrincipalName } elseif ($UserPrincipalName) { $UserPrincipalName } else { 'signed-in@contoso.example' }
        $global:connectionTestSessions = @(New-TestSession -UserPrincipalName $signInUser)
    }
    function global:Disconnect-ExchangeOnline {
        [CmdletBinding()]
        param([bool]$Confirm)
        $global:connectionTestCalls.Add(@{ Command = 'Disconnect' })
        $global:connectionTestSessions = @()
    }
    function global:Get-ConnectionTestPresentCmdlet { }

    function global:New-TestSession {
        param([string]$UserPrincipalName = 'admin@contoso.example', [string]$TenantId = '11111111-2222-3333-4444-555555555555', [string]$Uri = 'https://outlook.office365.com')
        [pscustomobject]@{ State = 'Connected'; UserPrincipalName = $UserPrincipalName; TenantID = $TenantId; ConnectionUri = $Uri; IsEopSession = $false }
    }
}

AfterAll {
    Remove-Module ExchangeOnlineBaseline.Connection -ErrorAction Ignore
    foreach ($name in 'Get-ConnectionInformation', 'Connect-ExchangeOnline', 'Disconnect-ExchangeOnline', 'Get-ConnectionTestPresentCmdlet', 'New-TestSession') {
        Remove-Item -LiteralPath "function:global:$($name)" -ErrorAction Ignore
    }
}

Describe 'ExchangeOnlineBaseline.Connection' {
    BeforeEach {
        $global:connectionTestSessions = @()
        $global:connectionTestCalls = [System.Collections.Generic.List[hashtable]]::new()
        $global:connectionTestConnectError = $null
        $global:connectionTestSignInUserPrincipalName = $null
        Mock -ModuleName ExchangeOnlineBaseline.Connection Test-ExchangeInteractiveHost { $true }
        Mock -ModuleName ExchangeOnlineBaseline.Connection Read-ExchangeSessionConfirmation { $true }
    }

    Context 'module check' {
        It 'refuses when ExchangeOnlineManagement is not installed and prints the install command' {
            # Arrange
            Mock -ModuleName ExchangeOnlineBaseline.Connection Get-Module { @() }
            # Act
            $act = { Assert-ExchangeOnlineModule -MinimumVersion '3.10.0' }
            # Assert
            $act | Should -Throw '*ExchangeModuleMissing*Install-Module ExchangeOnlineManagement -MinimumVersion 3.10.0 -Scope CurrentUser*'
        }

        It 'refuses an outdated module and prints the update command' {
            # Arrange
            Mock -ModuleName ExchangeOnlineBaseline.Connection Get-Module { [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.4.0' } } -ParameterFilter { $ListAvailable }
            # Act
            $act = { Assert-ExchangeOnlineModule -MinimumVersion '3.10.0' }
            # Assert
            $act | Should -Throw '*ExchangeModuleOutdated*3.4.0*Update-Module ExchangeOnlineManagement*'
        }
    }

    Context 'parameter tenant validation' {
        It 'returns a valid tenant GUID from the parameter file' {
            # Arrange
            $path = Join-Path $TestDrive 'parameters.json'
            '{"MICROSOFT_ENTRA_TENANT_GUID":"11111111-2222-3333-4444-555555555555"}' | Set-Content -LiteralPath $path
            # Act / Assert
            Get-ExchangeExpectedTenantId -ParameterPath $path | Should -Be '11111111-2222-3333-4444-555555555555'
        }

        It 'refuses missing, malformed, invalid, and all-zero tenant identifiers' {
            # Arrange / Act / Assert
            $path = Join-Path $TestDrive 'parameters.json'
            foreach ($json in @(
                    '{}',
                    '{"MICROSOFT_ENTRA_TENANT_GUID":"not-a-guid"}',
                    '{"MICROSOFT_ENTRA_TENANT_GUID":"00000000-0000-0000-0000-000000000000"}',
                    'not json'
                )) {
                $json | Set-Content -LiteralPath $path
                $act = { Get-ExchangeExpectedTenantId -ParameterPath $path }
                $act | Should -Throw '*ExchangeParameterTenantInvalid*'
            }
        }

        It 'refuses an unreadable or missing parameter file' {
            # Arrange
            $path = Join-Path $TestDrive 'missing.json'
            # Act / Assert
            $act = { Get-ExchangeExpectedTenantId -ParameterPath $path }
            $act | Should -Throw '*ExchangeParameterTenantInvalid*'
        }
    }

    Context 'session selection and sign-in' {
        It 'refuses more than one session and says how to reset' {
            # Arrange
            $global:connectionTestSessions = @((New-TestSession), (New-TestSession -UserPrincipalName 'other@contoso.example'))
            # Act
            $act = { Connect-ExchangeOnlineSession -SkipModuleCheck -InformationAction Ignore }
            # Assert
            $act | Should -Throw '*ExchangeSessionAmbiguous*Disconnect-ExchangeOnline -Confirm:$false*'
        }

        It 'never prompts in a non-interactive run and prints the sign-in command instead' {
            # Arrange
            Mock -ModuleName ExchangeOnlineBaseline.Connection Test-ExchangeInteractiveHost { $false }
            # Act
            $act = { Connect-ExchangeOnlineSession -SkipModuleCheck -UserPrincipalName 'admin@contoso.example' -InformationAction Ignore }
            # Assert
            $act | Should -Throw "*ExchangeSessionMissing*Connect-ExchangeOnline -UserPrincipalName 'admin@contoso.example'*"
            $global:connectionTestCalls.Count | Should -Be 0
        }

        It 'requires an explicit override to reuse a session without confirmation in a non-interactive run' {
            # Arrange
            $global:connectionTestSessions = @(New-TestSession)
            # Act
            $act = { Connect-ExchangeOnlineSession -SkipModuleCheck -NonInteractive -InformationAction Ignore }
            # Assert
            $act | Should -Throw '*ExchangeSessionConfirmationRequired*-ConfirmSession:$false*'
        }

        It 'refuses an existing session for a different account in a non-interactive run' {
            # Arrange
            $global:connectionTestSessions = @(New-TestSession -UserPrincipalName 'someone@contoso.example')
            # Act
            $act = { Connect-ExchangeOnlineSession -SkipModuleCheck -NonInteractive -ConfirmSession:$false -UserPrincipalName 'admin@contoso.example' -InformationAction Ignore }
            # Assert
            $act | Should -Throw '*ExchangeSessionWrongAccount*someone@contoso.example*admin@contoso.example*'
        }

        It 'signs out and signs in again when the operator rejects the current session' {
            # Arrange
            $global:connectionTestSessions = @(New-TestSession -UserPrincipalName 'someone@contoso.example')
            Mock -ModuleName ExchangeOnlineBaseline.Connection Read-ExchangeSessionConfirmation { $false }
            # Act
            $session = Connect-ExchangeOnlineSession -SkipModuleCheck -UserPrincipalName 'admin@contoso.example' -InformationAction Ignore
            # Assert
            @($global:connectionTestCalls.Command) | Should -Be @('Disconnect', 'Connect')
            $session.UserPrincipalName | Should -Be 'admin@contoso.example'
        }

        It 'turns a failed sign-in into actionable guidance' {
            # Arrange
            $global:connectionTestConnectError = 'AADSTS50076: multi-factor authentication required'
            # Act
            $act = { Connect-ExchangeOnlineSession -SkipModuleCheck -UserPrincipalName 'admin@contoso.example' -InformationAction Ignore }
            # Assert
            $act | Should -Throw '*ExchangeSignInFailed*AADSTS50076*-UseDeviceCode*'
        }

        It 'uses device-code sign-in when asked' {
            # Arrange
            # Act
            $null = Connect-ExchangeOnlineSession -SkipModuleCheck -UseDeviceCode -InformationAction Ignore
            # Assert
            $global:connectionTestCalls[0].Device | Should -BeTrue
        }

        It 'shows the existing session and reuses it after confirmation' {
            # Arrange
            $global:connectionTestSessions = @(New-TestSession)
            # Act
            $output = Connect-ExchangeOnlineSession -SkipModuleCheck 6>&1
            # Assert
            $session = @($output | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] })
            $session.Count | Should -Be 1
            $session[0].UserPrincipalName | Should -Be 'admin@contoso.example'
            ($output | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }) -join "`n" | Should -Match "admin@contoso\.example.*$($script:tenant)"
            $global:connectionTestCalls.Count | Should -Be 0
            Should -Invoke -ModuleName ExchangeOnlineBaseline.Connection Read-ExchangeSessionConfirmation -Times 1 -Exactly
        }

        It 'signs in interactively when no session exists' {
            # Arrange
            # Act
            $session = Connect-ExchangeOnlineSession -SkipModuleCheck -UserPrincipalName 'admin@contoso.example' -InformationAction Ignore
            # Assert
            $global:connectionTestCalls[0].Command | Should -Be 'Connect'
            $global:connectionTestCalls[0].UserPrincipalName | Should -Be 'admin@contoso.example'
            $session.UserPrincipalName | Should -Be 'admin@contoso.example'
        }

        It 'disconnects and refuses an interactive sign-in for a different account than requested' {
            # Arrange
            $global:connectionTestSignInUserPrincipalName = 'other@contoso.example'

            # Act
            $act = { Connect-ExchangeOnlineSession -SkipModuleCheck -UserPrincipalName 'admin@contoso.example' -InformationAction Ignore }

            # Assert
            $act | Should -Throw '*ExchangeSessionWrongAccount*other@contoso.example*admin@contoso.example*Disconnect-ExchangeOnline -Confirm:$false*Connect-ExchangeOnline -UserPrincipalName*'
            @($global:connectionTestCalls.Command) | Should -Be @('Connect', 'Disconnect')
            $global:connectionTestSessions.Count | Should -Be 0
        }
    }

    Context 'session validation' {
        It 'refuses a session in another tenant' {
            # Arrange
            $session = New-TestSession -TenantId '99999999-2222-3333-4444-555555555555'
            # Act
            $act = { Assert-ExchangeOnlineSession -Session $session -ExpectedTenantId $script:tenant }
            # Assert
            $act | Should -Throw "*ExchangeSessionTenantMismatch*99999999-2222-3333-4444-555555555555*$($script:tenant)*"
        }

        It 'refuses a sovereign-cloud endpoint' {
            # Arrange
            $session = New-TestSession -Uri 'https://outlook.office365.us'
            # Act
            $act = { Assert-ExchangeOnlineSession -Session $session -ExpectedTenantId $script:tenant }
            # Assert
            $act | Should -Throw '*ExchangeSessionEndpointUnsupported*'
        }

        It 'names the cmdlets the signed-in role cannot run' {
            # Arrange
            $session = New-TestSession
            # Act
            $act = { Assert-ExchangeOnlineSession -Session $session -ExpectedTenantId $script:tenant -RequiredCommand 'Get-ConnectionTestPresentCmdlet', 'Get-ConnectionTestMissingCmdlet' }
            # Assert
            $act | Should -Throw '*ExchangeRoleMissing*admin@contoso.example*Get-ConnectionTestMissingCmdlet*'
        }

        It 'maps every supported change scope to a read cmdlet' {
            # Arrange
            $adapters = Get-Content -LiteralPath (Join-Path $script:root 'scripts/ExchangeOnlineBaseline.ApprovedAdapters.ps1') -Raw
            $block = [regex]::Match($adapters, '(?s)function Assert-ApprovedAdapterScope.*?\$supported = @\((.*?)\)').Groups[1].Value
            $supported = @([regex]::Matches($block, "'([A-Za-z]+)'") | ForEach-Object { $_.Groups[1].Value })
            # Act
            $map = Get-ExchangeScopeReadCommand
            # Assert
            $supported.Count | Should -Be 32
            @($supported | Where-Object { -not $map.Contains($_) }) | Should -BeNullOrEmpty
        }

        It 'maps every read dependency for scopes that inspect multiple object types' {
            # Arrange
            $requiredByScope = @{
                Forwarding = @('Get-InboxRule', 'Get-Mailbox', 'Get-AcceptedDomain')
                OrganizationAllowList = @('Get-HostedConnectionFilterPolicy', 'Get-HostedContentFilterPolicy')
                ConnectorTrust = @('Get-InboundConnector', 'Get-OutboundConnector')
                ApplicationAssignmentScope = @('Get-ServicePrincipal', 'Get-ManagementScope', 'Get-ManagementRoleAssignment')
                ReportSubmission = @('Get-Mailbox', 'Get-ReportSubmissionPolicy', 'Get-ReportSubmissionRule')
                SharingPolicyBinding = @('Get-SharingPolicy', 'Get-Mailbox')
            }
            $map = Get-ExchangeScopeReadCommand
            # Act / Assert
            foreach ($scope in $requiredByScope.Keys) {
                foreach ($command in $requiredByScope[$scope]) {
                    @($map[$scope]) | Should -Contain $command
                    @(Get-ExchangeScopeReadCommand -Scope $scope) | Should -Contain $command
                }
            }
        }

        It 'refuses a Security & Compliance session in another tenant that apply would refuse later' {
            # Arrange
            $eop = New-TestSession -TenantId '99999999-2222-3333-4444-555555555555'
            $eop.IsEopSession = $true
            $global:connectionTestSessions = @((New-TestSession), $eop)
            Mock -ModuleName ExchangeOnlineBaseline.Connection Assert-ExchangeOnlineModule { }
            # Act
            $act = { Initialize-ExchangeOnlineSession -ExpectedTenantId $script:tenant -ConfirmSession $false -InformationAction Ignore }
            # Assert
            $act | Should -Throw '*ExchangeSessionTenantMismatch*99999999-2222-3333-4444-555555555555*Disconnect-ExchangeOnline*'
        }

        It 'accepts a matching Worldwide session with the required cmdlets' {
            # Arrange
            $session = New-TestSession
            # Act
            $result = Assert-ExchangeOnlineSession -Session $session -ExpectedTenantId $script:tenant -RequiredCommand 'Get-ConnectionTestPresentCmdlet'
            # Assert
            $result.TenantID | Should -Be $script:tenant
        }
    }

    Context 'Invoke-ExchangeOnlineChange pre-flight' {
        BeforeEach {
            $script:wrapper = Join-Path $script:root 'scripts/Invoke-ExchangeOnlineChange.ps1'
            Mock -ModuleName ExchangeOnlineBaseline.Connection Assert-ExchangeOnlineModule { }
            $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory $directory
            $parameters = Get-Content (Join-Path $script:root 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
            $parameters.MICROSOFT_ENTRA_TENANT_GUID = $script:tenant
            $parameterPath = Join-Path $directory 'parameters.json'
            $parameters | ConvertTo-Json -Depth 20 | Set-Content $parameterPath
            $script:changeArguments = @{
                ParameterPath     = $parameterPath
                ConfigurationPath = Join-Path $script:root 'config/exchange-only.v1.json'
                ArtifactRoot      = $directory
                ChangeId          = 'CHG-CONNECT'
                RequestedBy       = 'requester@contoso.example'
                Scope             = @('Transport')
                InformationAction = 'Ignore'
                Confirm           = $false
            }
        }

        It 'stops Preview before any tenant work when no session exists and it cannot sign in' {
            # Arrange
            $global:connectionTestSessions = @()
            # Act
            $act = { & $script:wrapper -Stage Preview @script:changeArguments -NonInteractive }
            # Assert
            $act | Should -Throw '*ExchangeSessionMissing*Connect-ExchangeOnline*'
            $global:connectionTestCalls.Count | Should -Be 0
        }

        It 'stops Preview when the confirmed session belongs to another tenant' {
            # Arrange
            $global:connectionTestSessions = @(New-TestSession -TenantId '99999999-2222-3333-4444-555555555555')
            # Act
            $act = { & $script:wrapper -Stage Preview @script:changeArguments -ConfirmSession:$false }
            # Assert
            $act | Should -Throw '*ExchangeSessionTenantMismatch*'
        }

        It 'never signs in for the offline Approve stage' {
            # Arrange
            $global:connectionTestSessions = @()
            # Act
            $message = try { & $script:wrapper -Stage Approve @script:changeArguments -NonInteractive; '' } catch { $_.Exception.Message }
            # Assert
            $message | Should -Not -Match '^Exchange(Session|SignIn|Module|Role)'
            $global:connectionTestCalls.Count | Should -Be 0
        }

        It 'signs in, then hands the change to the approved workflow without the sign-in parameters' {
            # Arrange
            $global:connectionTestSessions = @()
            function global:Get-TransportConfig { [pscustomobject]@{ SmtpClientAuthenticationDisabled = $true } }
            # Act
            $message = try { & $script:wrapper -Stage Preview @script:changeArguments -UserPrincipalName 'admin@contoso.example'; '' } catch { $_.Exception.Message }
            Remove-Item -LiteralPath 'function:global:Get-TransportConfig' -ErrorAction Ignore
            # Assert
            $global:connectionTestCalls.Command | Should -Contain 'Connect'
            $message | Should -Not -Match 'Exchange(Session|SignIn|Module)'
            $message | Should -Not -Match 'cannot be found that matches parameter name'
        }
    }
}
