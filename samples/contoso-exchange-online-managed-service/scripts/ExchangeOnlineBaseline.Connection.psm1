#requires -Version 7.5
<#
Sign-in, session confirmation and permission pre-flight for the Exchange Online change kit.

Every tenant-touching script calls Initialize-ExchangeOnlineSession before it reads or changes anything:
  1. ExchangeOnlineManagement is installed, recent enough and loaded.
  2. An existing session is shown (account, tenant, endpoint) and the operator confirms it; with no session
     an interactive run signs in (browser/WAM with MFA, or -UseDeviceCode), a non-interactive run stops
     with the exact command to run.
  3. The session is in the parameter-file tenant, on the Worldwide endpoint, and the signed-in role
     exposes the cmdlets the requested scopes need.
Every failure is a terminating error that starts with a stable code and ends with the fix.
#>

Set-StrictMode -Version Latest

$script:ScopeReadCommand = [ordered]@{
    AcceptedDomains            = @('Get-AcceptedDomain')
    AddInAcquisition           = @('Get-ManagementRoleAssignment', 'Get-RoleAssignmentPolicy')
    ApplicationAssignmentScope = @('Get-ManagementScope', 'Get-ManagementRoleAssignment', 'Get-ServicePrincipal')
    AtpPresets                 = @('Get-ATPProtectionPolicyRule')
    BuiltInProtection          = @('Get-ATPBuiltInProtectionRule')
    ConnectorTrust             = @('Get-InboundConnector', 'Get-OutboundConnector')
    Dkim                       = @('Get-DkimSigningConfig')
    EopPresets                 = @('Get-EOPProtectionPolicyRule')
    ExternalSender             = @('Get-ExternalInOutlook')
    Forwarding                 = @('Get-InboxRule', 'Get-Mailbox', 'Get-AcceptedDomain')
    FullAccess                 = @('Get-MailboxPermission', 'Get-Mailbox')
    GovernanceEncryption       = @('Get-IRMConfiguration', 'Get-TransportRule')
    GovernanceMailboxPolicy    = @('Get-Mailbox')
    GovernanceMrm              = @('Get-RetentionPolicyTag', 'Get-RetentionPolicy', 'Get-Mailbox')
    Impersonation              = @('Get-AntiPhishPolicy', 'Get-AntiPhishRule', 'Get-ATPProtectionPolicyRule')
    MailboxPlans               = @('Get-CASMailboxPlan')
    MailboxProtocols           = @('Get-CASMailbox')
    MailboxSafeSender          = @('Get-MailboxJunkEmailConfiguration', 'Get-Mailbox')
    Organization               = @('Get-OrganizationConfig', 'Get-CASMailbox')
    OrganizationAllowList      = @('Get-HostedConnectionFilterPolicy', 'Get-HostedContentFilterPolicy')
    OrganizationRelationship   = @('Get-OrganizationRelationship')
    OutboundSpam               = @('Get-HostedOutboundSpamFilterPolicy', 'Get-HostedOutboundSpamFilterRule')
    Quarantine                 = @('Get-QuarantinePolicy', 'Get-HostedContentFilterPolicy', 'Get-MalwareFilterPolicy', 'Get-AntiPhishPolicy')
    RemoteDomains              = @('Get-RemoteDomain')
    ReportSubmission           = @('Get-ReportSubmissionPolicy', 'Get-ReportSubmissionRule', 'Get-Mailbox')
    SecOpsOverride             = @('Get-SecOpsOverridePolicy', 'Get-ExoSecOpsOverrideRule')
    SendAs                     = @('Get-RecipientPermission', 'Get-Mailbox')
    SendOnBehalf               = @('Get-Mailbox')
    SharingPolicyBinding       = @('Get-SharingPolicy', 'Get-Mailbox')
    TenantAllowBlockList       = @('Get-TenantAllowBlockListItems')
    Transport                  = @('Get-TransportConfig')
    TransportBypass            = @('Get-TransportRule')
}

function Get-ExchangeScopeReadCommand {
    <#
    .SYNOPSIS
    Returns the read cmdlet each change scope needs, or the distinct cmdlets for the given scopes.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary], [System.Array])]
    param([string[]]$Scope)
    if (-not $PSBoundParameters.ContainsKey('Scope')) { return $script:ScopeReadCommand }
    @($Scope | Where-Object { $script:ScopeReadCommand.Contains($_) } | ForEach-Object { $script:ScopeReadCommand[$_] } | Select-Object -Unique)
}

function Get-ExchangeExpectedTenantId {
    <#
    .SYNOPSIS
    Reads MICROSOFT_ENTRA_TENANT_GUID from a parameter file; returns an empty string when it is not a GUID.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$ParameterPath)
    try {
        $value = [string](Get-Content -LiteralPath $ParameterPath -Raw | ConvertFrom-Json -Depth 50).MICROSOFT_ENTRA_TENANT_GUID
        $guid = [guid]::Empty
        if ([guid]::TryParse($value, [ref]$guid) -and $guid -ne [guid]::Empty) { return $value }
    }
    catch {
        Write-Verbose "Parameter file tenant not readable: $($_.Exception.Message)"
    }
    ''
}

function Test-ExchangeInteractiveHost {
    <#
    .SYNOPSIS
    True when a person can answer prompts and complete a browser sign-in in this terminal.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $nonInteractiveSwitch = @([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^-noni' }).Count -gt 0
    [Environment]::UserInteractive -and -not [Console]::IsInputRedirected -and -not $nonInteractiveSwitch
}

function Read-ExchangeSessionConfirmation {
    <#
    .SYNOPSIS
    Asks the operator whether the shown session is the right one. Returns $true for yes.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $answer = Read-Host 'Use this session? [Y] Yes  [N] No, sign out and sign in as someone else (default Y)'
    $answer -notmatch '^\s*n'
}

function Get-ExchangeConnectedSession {
    [CmdletBinding()]
    [OutputType([object[]], [System.Array])]
    param()
    if (-not (Get-Command -Name Get-ConnectionInformation -ErrorAction SilentlyContinue)) { return @() }
    @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object {
            $_.State -eq 'Connected' -and -not ($_.PSObject.Properties['IsEopSession'] -and $_.IsEopSession)
        })
}

function Format-ExchangeSignInCommand {
    param([string]$UserPrincipalName, [switch]$UseDeviceCode)
    $account = if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) { 'admin@contoso.onmicrosoft.com' } else { $UserPrincipalName }
    "Connect-ExchangeOnline -UserPrincipalName '$($account -replace "'", "''")'$(if ($UseDeviceCode) { ' -Device' }) -ShowBanner:`$false"
}

function Assert-ExchangeOnlineModule {
    <#
    .SYNOPSIS
    Ensures ExchangeOnlineManagement is installed at the minimum version and loaded in this terminal.
    #>
    [CmdletBinding()]
    param([version]$MinimumVersion = '3.10.0')
    $installed = @(Get-Module -ListAvailable -Name ExchangeOnlineManagement | Sort-Object Version -Descending) | Select-Object -First 1
    if ($null -eq $installed) {
        throw ("ExchangeModuleMissing: the ExchangeOnlineManagement module is not installed. Run:`n" +
            "  Install-Module ExchangeOnlineManagement -MinimumVersion $($MinimumVersion) -Scope CurrentUser`n" +
            'then rerun this script in the same PowerShell 7 terminal.')
    }
    if ([version]$installed.Version -lt $MinimumVersion) {
        throw ("ExchangeModuleOutdated: ExchangeOnlineManagement $($installed.Version) is installed; $($MinimumVersion) or later is required. Run:`n" +
            "  Update-Module ExchangeOnlineManagement`n" +
            "  (or Install-Module ExchangeOnlineManagement -MinimumVersion $($MinimumVersion) -Scope CurrentUser -Force)`n" +
            'then open a new PowerShell 7 terminal and rerun this script.')
    }
    $loaded = @(Get-Module -Name ExchangeOnlineManagement) | Select-Object -First 1
    if ($null -ne $loaded -and [version]$loaded.Version -lt $MinimumVersion) {
        throw ("ExchangeModuleOutdated: this terminal already loaded ExchangeOnlineManagement $($loaded.Version). " +
            'Open a new PowerShell 7 terminal so the newer version loads, then rerun this script.')
    }
    if ($null -eq $loaded) {
        Import-Module ExchangeOnlineManagement -MinimumVersion $MinimumVersion -ErrorAction Stop -Verbose:$false
    }
}

function Connect-ExchangeOnlineSession {
    <#
    .SYNOPSIS
    Reuses a confirmed Exchange Online session or signs in (MFA supported). Returns the session.

    .PARAMETER ConfirmSession
    Ask before reusing an existing session. Pass -ConfirmSession:$false for unattended runs.

    .PARAMETER NonInteractive
    Never prompt or open a sign-in window; fail with the command to run instead.
    #>
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [switch]$UseDeviceCode,
        [bool]$ConfirmSession = $true,
        [switch]$NonInteractive,
        [version]$MinimumModuleVersion = '3.10.0',
        [switch]$SkipModuleCheck
    )
    if (-not $SkipModuleCheck) { Assert-ExchangeOnlineModule -MinimumVersion $MinimumModuleVersion }
    $interactive = -not $NonInteractive -and (Test-ExchangeInteractiveHost)
    $signIn = Format-ExchangeSignInCommand -UserPrincipalName $UserPrincipalName -UseDeviceCode:$UseDeviceCode

    $sessions = @(Get-ExchangeConnectedSession)
    if ($sessions.Count -gt 1) {
        $list = ($sessions | ForEach-Object { "$($_.UserPrincipalName) ($($_.TenantID))" }) -join ', '
        throw ("ExchangeSessionAmbiguous: this terminal has $($sessions.Count) Exchange Online sessions: $($list). Run:`n" +
            "  Disconnect-ExchangeOnline -Confirm:`$false`n" +
            'then rerun this script; it will sign you in once.')
    }

    if ($sessions.Count -eq 1) {
        $session = $sessions[0]
        Write-Information "Exchange Online session found: $($session.UserPrincipalName) in tenant $($session.TenantID) ($($session.ConnectionUri))"
        $reuse = $true
        if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName) -and [string]$session.UserPrincipalName -ne $UserPrincipalName) {
            if (-not $interactive) {
                throw ("ExchangeSessionWrongAccount: this terminal is signed in as $($session.UserPrincipalName), not $($UserPrincipalName). Run:`n" +
                    "  Disconnect-ExchangeOnline -Confirm:`$false`n  $($signIn)`nthen rerun this script.")
            }
            Write-Information "That is not $($UserPrincipalName); signing out so you can sign in with the right account."
            $reuse = $false
        }
        elseif ($ConfirmSession) {
            if (-not $interactive) {
                throw ('ExchangeSessionConfirmationRequired: an existing session must be confirmed, and this run cannot prompt. ' +
                    'Check the account and tenant above, then rerun with -ConfirmSession:$false to accept it without a prompt.')
            }
            $reuse = Read-ExchangeSessionConfirmation
        }
        if ($reuse) { return $session }
        Disconnect-ExchangeOnline -Confirm:$false
    }

    if (-not $interactive) {
        throw ("ExchangeSessionMissing: no Exchange Online session in this terminal and this run cannot sign in. Sign in first (MFA prompts appear in the browser):`n" +
            "  $($signIn)`nthen rerun this script in the same terminal. Add -UseDeviceCode to the script on a machine without a browser.")
    }

    Write-Information "Signing in to Exchange Online$(if ($UserPrincipalName) { " as $($UserPrincipalName)" }). Complete the sign-in and MFA prompt in the window or browser that opens$(if ($UseDeviceCode) { ' (device code: open the URL shown below on any device)' })."
    $arguments = @{ ShowBanner = $false }
    if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) { $arguments.UserPrincipalName = $UserPrincipalName }
    if ($UseDeviceCode) { $arguments.Device = $true }
    try {
        Connect-ExchangeOnline @arguments
    }
    catch {
        throw ("ExchangeSignInFailed: $($_.Exception.Message)`n" +
            "Try:`n" +
            "  - Complete the MFA prompt; if it timed out, rerun this script.`n" +
            "  - No browser window (remote desktop, SSH, server core)? Rerun this script with -UseDeviceCode.`n" +
            "  - Wrong account remembered by the browser? Rerun with -UserPrincipalName 'you@yourtenant.com'.`n" +
            '  - AADSTS errors about Conditional Access or device compliance: ask your identity team to allow this device.')
    }
    $sessions = @(Get-ExchangeConnectedSession)
    if ($sessions.Count -ne 1) {
        throw "ExchangeSignInFailed: sign-in finished but $($sessions.Count) Exchange Online sessions are connected. Run Disconnect-ExchangeOnline -Confirm:`$false and rerun this script."
    }
    Write-Information "Signed in as $($sessions[0].UserPrincipalName) in tenant $($sessions[0].TenantID)."
    $sessions[0]
}

function Assert-ExchangeOnlineSession {
    <#
    .SYNOPSIS
    Checks that a session is in the expected tenant, on the Worldwide endpoint, and exposes the required cmdlets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Session,
        [string]$ExpectedTenantId,
        [string[]]$RequiredCommand = @()
    )
    if (-not [string]::IsNullOrWhiteSpace($ExpectedTenantId) -and [string]$Session.TenantID -ne $ExpectedTenantId) {
        throw ("ExchangeSessionTenantMismatch: signed in to tenant $($Session.TenantID) as $($Session.UserPrincipalName), but the parameter file is for tenant $($ExpectedTenantId). Run:`n" +
            "  Disconnect-ExchangeOnline -Confirm:`$false`n" +
            'then rerun this script and sign in with an administrator account from the parameter-file tenant.')
    }
    if ([string]$Session.ConnectionUri -notmatch '^https://outlook\.office365\.com') {
        throw "ExchangeSessionEndpointUnsupported: the session uses $($Session.ConnectionUri). Only Worldwide (O365Default) tenants are supported; stop here for sovereign clouds."
    }
    $missing = @($RequiredCommand | Where-Object { -not (Get-Command -Name $_ -ErrorAction SilentlyContinue) } | Select-Object -Unique)
    if ($missing.Count -gt 0) {
        throw ("ExchangeRoleMissing: $($Session.UserPrincipalName) cannot run $($missing -join ', '). Exchange Online only shows the cmdlets your role groups allow.`n" +
            "Fix: ask your Exchange role administrator to add this account to a role group that includes these cmdlets (least privilege; Organization Management covers all of them), wait for the assignment to apply (up to an hour), then run:`n" +
            "  Disconnect-ExchangeOnline -Confirm:`$false`n" +
            'and rerun this script.')
    }
    $Session
}

function Initialize-ExchangeOnlineSession {
    <#
    .SYNOPSIS
    Module check, confirmed sign-in, tenant/endpoint check and role pre-flight in one call.
    #>
    [CmdletBinding()]
    param(
        [string]$ExpectedTenantId,
        [string[]]$Scope = @(),
        [string[]]$RequiredCommand = @(),
        [string]$UserPrincipalName,
        [switch]$UseDeviceCode,
        [bool]$ConfirmSession = $true,
        [switch]$NonInteractive,
        [version]$MinimumModuleVersion = '3.10.0'
    )
    $session = Connect-ExchangeOnlineSession -UserPrincipalName $UserPrincipalName -UseDeviceCode:$UseDeviceCode `
        -ConfirmSession $ConfirmSession -NonInteractive:$NonInteractive -MinimumModuleVersion $MinimumModuleVersion
    $commands = @(@($RequiredCommand) + @(Get-ExchangeScopeReadCommand -Scope $Scope) | Where-Object { $_ } | Select-Object -Unique)
    $null = Assert-ExchangeOnlineSession -Session $session -ExpectedTenantId $ExpectedTenantId -RequiredCommand $commands
    if (-not [string]::IsNullOrWhiteSpace($ExpectedTenantId)) {
        # Apply/Rollback refuse if any connected session (including Security & Compliance) is another tenant; fail here first.
        $foreign = @(Get-ConnectionInformation -ErrorAction SilentlyContinue |
                Where-Object { $_.State -eq 'Connected' -and [string]$_.TenantID -ne $ExpectedTenantId })
        if ($foreign.Count -gt 0) {
            throw ("ExchangeSessionTenantMismatch: another connected session is in tenant $(($foreign | ForEach-Object { [string]$_.TenantID } | Select-Object -Unique) -join ', '), but the parameter file is for tenant $($ExpectedTenantId). Run:`n" +
                "  Disconnect-ExchangeOnline -Confirm:`$false`n" +
                'then rerun this script and sign in only to the parameter-file tenant.')
        }
    }
    Write-Information "Exchange Online session ready: $($session.UserPrincipalName), tenant $($session.TenantID)$(if ($commands.Count) { ", $($commands.Count) required cmdlet(s) available" })."
    $session
}

Export-ModuleMember -Function Get-ExchangeScopeReadCommand, Get-ExchangeExpectedTenantId, Test-ExchangeInteractiveHost,
    Read-ExchangeSessionConfirmation, Assert-ExchangeOnlineModule, Connect-ExchangeOnlineSession,
    Assert-ExchangeOnlineSession, Initialize-ExchangeOnlineSession
