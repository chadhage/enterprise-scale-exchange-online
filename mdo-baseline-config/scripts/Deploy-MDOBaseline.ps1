#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Microsoft Defender for Office 365 Baseline Configuration Deployment Script
    
.DESCRIPTION
    Parameterized IaC deployment script for MDO baseline configurations.
    Supports both Standard and Strict protection levels. Tenant-specific values
    are supplied as parameters rather than hardcoded.
    
.PARAMETER ConfigPath
    Path to the configuration JSON file (e.g., baseline-standard.json)
    
.PARAMETER TenantId
    Azure AD Tenant ID (GUID format)
    
.PARAMETER TenantName
    Organization display name
    
.PARAMETER TenantDomain
    Primary tenant domain (e.g., contoso.com)
    
.PARAMETER SecurityAdminEmail
    Email address for security alerts and notifications
    
.PARAMETER DryRun
    If specified, shows what would be deployed without making changes
    
.PARAMETER SkipConfirmation
    If specified, skips confirmation prompts
    
.EXAMPLE
    .\Deploy-MDOBaseline.ps1 `
        -ConfigPath "./baseline-standard.json" `
        -TenantId "12345678-1234-1234-1234-123456789012" `
        -TenantName "Contoso Inc" `
        -TenantDomain "contoso.com" `
        -SecurityAdminEmail "security@contoso.com"

.EXAMPLE
    # With dry run
    .\Deploy-MDOBaseline.ps1 `
        -ConfigPath "./baseline-strict.json" `
        -TenantId "12345678-1234-1234-1234-123456789012" `
        -TenantName "Contoso Inc" `
        -TenantDomain "contoso.com" `
        -SecurityAdminEmail "security@contoso.com" `
        -DryRun

#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ConfigPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', `
        ErrorMessage = "TenantId must be a valid GUID")]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\w+(\.\w+)*$')]
    [string]$TenantDomain,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[^@]+@[^@]+\.[^@]+$')]
    [string]$SecurityAdminEmail,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun,

    [Parameter(Mandatory = $false)]
    [switch]$SkipConfirmation,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Audit', 'Enforce')]
    [string]$DeploymentMode = 'Audit'
)

#region Initialize
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'

$ScriptVersion = "1.0.0"
$ScriptName = $MyInvocation.MyCommand.Name
$LogPath = Join-Path (Split-Path -Parent $ConfigPath) "deploy-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('Info', 'Warn', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Info' { Write-Host $logMessage -ForegroundColor Cyan }
        'Warn' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error' { Write-Host $logMessage -ForegroundColor Red }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
    }
    
    Add-Content -Path $LogPath -Value $logMessage
}

function Test-Prerequisites {
    Write-Log "Validating prerequisites..." -Level Info
    
    try {
        # Check PowerShell version
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            Write-Log "PowerShell 7.0 or higher is required. Current version: $($PSVersionTable.PSVersion)" -Level Warn
        }
        
        # Check for required modules
        $requiredModules = @(
            'ExchangeOnlineManagement',
            'Microsoft.Graph.Authentication',
            'Microsoft.Graph.Users'
        )
        
        foreach ($module in $requiredModules) {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-Log "Required module '$module' not found. Installing..." -Level Warn
                Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
            }
        }
        
        Write-Log "Prerequisites validated successfully" -Level Success
        return $true
    }
    catch {
        Write-Log "Prerequisites validation failed: $_" -Level Error
        throw
    }
}

function Connect-ExchangeOnline {
    param(
        [string]$TenantId
    )
    
    Write-Log "Connecting to Exchange Online..." -Level Info
    
    try {
        # Attempt to connect using managed identity if available
        Connect-ExchangeOnline -ManagedIdentity -Organization "$TenantDomain" -ErrorAction Stop
        Write-Log "Connected to Exchange Online using managed identity" -Level Success
    }
    catch {
        Write-Log "Managed identity connection failed, attempting interactive connection..." -Level Warn
        try {
            Connect-ExchangeOnline -UserPrincipalName $SecurityAdminEmail -ErrorAction Stop
            Write-Log "Connected to Exchange Online interactively" -Level Success
        }
        catch {
            Write-Log "Failed to connect to Exchange Online: $_" -Level Error
            throw
        }
    }
}

function Resolve-ConfigParameters {
    param(
        [object]$ConfigObject,
        [hashtable]$Parameters
    )
    
    Write-Log "Resolving configuration parameters..." -Level Info
    
    $configJson = $ConfigObject | ConvertTo-Json -Depth 100
    
    foreach ($key in $Parameters.Keys) {
        $pattern = "{{\s*$key\s*}}"
        $configJson = $configJson -replace $pattern, $Parameters[$key]
    }
    
    $resolved = $configJson | ConvertFrom-Json
    Write-Log "Configuration parameters resolved successfully" -Level Success
    return $resolved
}

function Deploy-AntiPhishingPolicy {
    param(
        [object]$PolicyConfig,
        [bool]$DryRun
    )
    
    foreach ($policy in $PolicyConfig) {
        Write-Log "Processing Anti-Phishing policy: $($policy.name)" -Level Info
        
        $policyParams = @{
            Identity                        = $policy.name
            Enabled                         = $policy.enabled
            EnableSpoofIntelligence        = $policy.spoofSettings.intraOrgSpoof
            SpoofIntelligenceAction        = $policy.spoofSettings.spoofingAction
            ExternalPartnerDomainSpoof     = $policy.spoofSettings.externalPartnerSpoof
            EnableUnauthenticatedSender    = $true
            PhishThresholdLevel            = $policy.phishingThreshold
            EnableImpersonationProtection  = $policy.impersonationProtection.enableUserImpersonationProtection
            ImpersonationProtectionAction  = $policy.impersonationProtection.userImpersonationAction
            EnableDomainImpersonationProtection = $policy.impersonationProtection.enableDomainImpersonationProtection
            DomainImpersonationProtectionAction = $policy.impersonationProtection.domainImpersonationAction
            ProtectedDomains              = $policy.impersonationProtection.protectedDomains
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would create/update anti-phishing policy with parameters: $(ConvertTo-Json $policyParams)" -Level Info
        }
        else {
            try {
                # Check if policy exists
                $existingPolicy = Get-AntiPhishPolicy -Identity $policy.name -ErrorAction SilentlyContinue
                
                if ($null -ne $existingPolicy) {
                    Write-Log "Updating existing anti-phishing policy: $($policy.name)" -Level Info
                    Set-AntiPhishPolicy @policyParams | Out-Null
                }
                else {
                    Write-Log "Creating new anti-phishing policy: $($policy.name)" -Level Info
                    New-AntiPhishPolicy @policyParams | Out-Null
                }
                
                Write-Log "Successfully deployed anti-phishing policy: $($policy.name)" -Level Success
            }
            catch {
                Write-Log "Failed to deploy anti-phishing policy $($policy.name): $_" -Level Error
                throw
            }
        }
    }
}

function Deploy-AntiMalwarePolicy {
    param(
        [object]$PolicyConfig,
        [bool]$DryRun
    )
    
    foreach ($policy in $PolicyConfig) {
        Write-Log "Processing Anti-Malware policy: $($policy.name)" -Level Info
        
        $policyParams = @{
            Identity                  = $policy.name
            EnableFileTypeFilter      = $policy.enableFileTypeFilter
            FileTypeAction            = $policy.scanResultAction
            ZeroHourAutoPurgeEnabled  = $true
            Enabled                   = $policy.enabled
        }
        
        if ($null -ne $policy.fileTypes -and $policy.fileTypes.Count -gt 0) {
            $policyParams.FileTypes = $policy.fileTypes
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would create/update anti-malware policy with parameters: $(ConvertTo-Json $policyParams)" -Level Info
        }
        else {
            try {
                $existingPolicy = Get-MalwareFilterPolicy -Identity $policy.name -ErrorAction SilentlyContinue
                
                if ($null -ne $existingPolicy) {
                    Write-Log "Updating existing anti-malware policy: $($policy.name)" -Level Info
                    Set-MalwareFilterPolicy @policyParams | Out-Null
                }
                else {
                    Write-Log "Creating new anti-malware policy: $($policy.name)" -Level Info
                    New-MalwareFilterPolicy @policyParams | Out-Null
                }
                
                Write-Log "Successfully deployed anti-malware policy: $($policy.name)" -Level Success
            }
            catch {
                Write-Log "Failed to deploy anti-malware policy $($policy.name): $_" -Level Error
                throw
            }
        }
    }
}

function Deploy-AntiSpamPolicy {
    param(
        [object]$PolicyConfig,
        [bool]$DryRun
    )
    
    foreach ($policy in $PolicyConfig) {
        Write-Log "Processing Anti-Spam policy: $($policy.name)" -Level Info
        
        $policyParams = @{
            Identity              = $policy.name
            SpamAction            = $policy.spamAction
            HighConfidenceSpamAction = $policy.highConfidenceSpamAction
            BulkThreshold         = $policy.bulkThreshold
            BulkSpamAction        = $policy.bulkSpamAction
            PhishSpamAction       = $policy.phishSpamAction
            Enabled               = $policy.enabled
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would create/update anti-spam policy with parameters: $(ConvertTo-Json $policyParams)" -Level Info
        }
        else {
            try {
                $existingPolicy = Get-HostedContentFilterPolicy -Identity $policy.name -ErrorAction SilentlyContinue
                
                if ($null -ne $existingPolicy) {
                    Write-Log "Updating existing anti-spam policy: $($policy.name)" -Level Info
                    Set-HostedContentFilterPolicy @policyParams | Out-Null
                }
                else {
                    Write-Log "Creating new anti-spam policy: $($policy.name)" -Level Info
                    New-HostedContentFilterPolicy @policyParams | Out-Null
                }
                
                Write-Log "Successfully deployed anti-spam policy: $($policy.name)" -Level Success
            }
            catch {
                Write-Log "Failed to deploy anti-spam policy $($policy.name): $_" -Level Error
                throw
            }
        }
    }
}

function Deploy-SafeAttachmentsPolicy {
    param(
        [object]$PolicyConfig,
        [bool]$DryRun
    )
    
    foreach ($policy in $PolicyConfig) {
        Write-Log "Processing Safe Attachments policy: $($policy.name)" -Level Info
        
        $policyParams = @{
            Identity            = $policy.name
            Action              = $policy.action
            Enable              = $policy.enable
            ActionOnError       = $policy.actionOnError
            Redirect            = if ($policy.redirectToRecipients.Count -gt 0) { $true } else { $false }
            RedirectAddress     = $policy.redirectToRecipients
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would create/update Safe Attachments policy: $(ConvertTo-Json $policyParams)" -Level Info
        }
        else {
            try {
                $existingPolicy = Get-SafeAttachmentPolicy -Identity $policy.name -ErrorAction SilentlyContinue
                
                if ($null -ne $existingPolicy) {
                    Write-Log "Updating existing Safe Attachments policy: $($policy.name)" -Level Info
                    Set-SafeAttachmentPolicy @policyParams | Out-Null
                }
                else {
                    Write-Log "Creating new Safe Attachments policy: $($policy.name)" -Level Info
                    New-SafeAttachmentPolicy @policyParams | Out-Null
                }
                
                Write-Log "Successfully deployed Safe Attachments policy: $($policy.name)" -Level Success
            }
            catch {
                Write-Log "Failed to deploy Safe Attachments policy $($policy.name): $_" -Level Error
                throw
            }
        }
    }
}

function Deploy-SafeLinksPolicy {
    param(
        [object]$PolicyConfig,
        [bool]$DryRun
    )
    
    foreach ($policy in $PolicyConfig) {
        Write-Log "Processing Safe Links policy: $($policy.name)" -Level Info
        
        $policyParams = @{
            Identity        = $policy.name
            IsEnabled       = $policy.enabled
            ScanUrls        = $policy.scanUrls
            AllowClickThrough = $policy.allowClickThrough
            TrackClicks     = $policy.trackClicks
            DeliverMessageAfterScan = $true
            EnableForTeams  = $policy.enableForTeams
            DisableUrlRewrite = $false
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would create/update Safe Links policy: $(ConvertTo-Json $policyParams)" -Level Info
        }
        else {
            try {
                $existingPolicy = Get-SafeLinksPolicy -Identity $policy.name -ErrorAction SilentlyContinue
                
                if ($null -ne $existingPolicy) {
                    Write-Log "Updating existing Safe Links policy: $($policy.name)" -Level Info
                    Set-SafeLinksPolicy @policyParams | Out-Null
                }
                else {
                    Write-Log "Creating new Safe Links policy: $($policy.name)" -Level Info
                    New-SafeLinksPolicy @policyParams | Out-Null
                }
                
                Write-Log "Successfully deployed Safe Links policy: $($policy.name)" -Level Success
            }
            catch {
                Write-Log "Failed to deploy Safe Links policy $($policy.name): $_" -Level Error
                throw
            }
        }
    }
}

function Deploy-OutboundSpamPolicy {
    param(
        [object]$PolicyConfig,
        [bool]$DryRun
    )
    
    foreach ($policy in $PolicyConfig) {
        Write-Log "Processing Outbound Spam policy: $($policy.name)" -Level Info
        
        $policyParams = @{
            Identity                = $policy.name
            SpamOutboundAction      = $policy.spamOutboundAction
            NotifyOutboundSpam      = $policy.notifyOutboundSpam
            OutboundSpamNotificationRecipients = $policy.notifyOutboundSpamRecipients
        }
        
        if ($DryRun) {
            Write-Log "[DRY RUN] Would create/update outbound spam policy: $(ConvertTo-Json $policyParams)" -Level Info
        }
        else {
            try {
                $existingPolicy = Get-OutboundFilterPolicy -ErrorAction SilentlyContinue
                
                if ($null -ne $existingPolicy) {
                    Write-Log "Updating outbound spam policy" -Level Info
                    Set-OutboundFilterPolicy @policyParams | Out-Null
                }
                
                Write-Log "Successfully deployed outbound spam policy" -Level Success
            }
            catch {
                Write-Log "Failed to deploy outbound spam policy: $_" -Level Error
                throw
            }
        }
    }
}

function Deploy-TenantAllowBlockList {
    param(
        [object]$AllowBlockConfig,
        [bool]$DryRun
    )
    
    Write-Log "Processing Tenant Allow/Block List entries..." -Level Info
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would process $(($AllowBlockConfig.allowedSenders | Measure-Object).Count + ($AllowBlockConfig.blockedSenders | Measure-Object).Count) sender entries" -Level Info
        Write-Log "[DRY RUN] Would process $(($AllowBlockConfig.allowedUrls | Measure-Object).Count + ($AllowBlockConfig.blockedUrls | Measure-Object).Count) URL entries" -Level Info
    }
    else {
        # Add allowed senders
        foreach ($sender in $AllowBlockConfig.allowedSenders) {
            try {
                New-TenantAllowBlockListSpoofItems -SpoofedUser $sender -Action Allow -ErrorAction SilentlyContinue
                Write-Log "Added allowed sender: $sender" -Level Info
            }
            catch {
                Write-Log "Warning: Could not add allowed sender $sender`: $_" -Level Warn
            }
        }
        
        # Add blocked senders
        foreach ($sender in $AllowBlockConfig.blockedSenders) {
            try {
                New-TenantAllowBlockListItems -ListType Sender -Entries $sender -Action Block -ErrorAction SilentlyContinue
                Write-Log "Added blocked sender: $sender" -Level Info
            }
            catch {
                Write-Log "Warning: Could not add blocked sender $sender`: $_" -Level Warn
            }
        }
        
        # Add allowed URLs
        foreach ($url in $AllowBlockConfig.allowedUrls) {
            try {
                New-TenantAllowBlockListItems -ListType Url -Entries $url -Action Allow -ErrorAction SilentlyContinue
                Write-Log "Added allowed URL: $url" -Level Info
            }
            catch {
                Write-Log "Warning: Could not add allowed URL $url`: $_" -Level Warn
            }
        }
        
        # Add blocked URLs
        foreach ($url in $AllowBlockConfig.blockedUrls) {
            try {
                New-TenantAllowBlockListItems -ListType Url -Entries $url -Action Block -ErrorAction SilentlyContinue
                Write-Log "Added blocked URL: $url" -Level Info
            }
            catch {
                Write-Log "Warning: Could not add blocked URL $url`: $_" -Level Warn
            }
        }
    }
}

function Deploy-Configuration {
    param(
        [object]$Config,
        [bool]$DryRun
    )
    
    Write-Log "Starting MDO baseline configuration deployment..." -Level Info
    Write-Log "Deployment Mode: $DeploymentMode" -Level Info
    Write-Log "Dry Run: $DryRun" -Level Info
    
    try {
        # Deploy policies in order
        if ($null -ne $Config.policies.antiMalware) {
            Write-Log "Deploying Anti-Malware policies..." -Level Info
            Deploy-AntiMalwarePolicy -PolicyConfig $Config.policies.antiMalware -DryRun $DryRun
        }
        
        if ($null -ne $Config.policies.antiPhishing) {
            Write-Log "Deploying Anti-Phishing policies..." -Level Info
            Deploy-AntiPhishingPolicy -PolicyConfig $Config.policies.antiPhishing -DryRun $DryRun
        }
        
        if ($null -ne $Config.policies.antiSpam) {
            Write-Log "Deploying Anti-Spam policies..." -Level Info
            Deploy-AntiSpamPolicy -PolicyConfig $Config.policies.antiSpam -DryRun $DryRun
        }
        
        if ($null -ne $Config.policies.safeAttachments) {
            Write-Log "Deploying Safe Attachments policies..." -Level Info
            Deploy-SafeAttachmentsPolicy -PolicyConfig $Config.policies.safeAttachments -DryRun $DryRun
        }
        
        if ($null -ne $Config.policies.safeLinks) {
            Write-Log "Deploying Safe Links policies..." -Level Info
            Deploy-SafeLinksPolicy -PolicyConfig $Config.policies.safeLinks -DryRun $DryRun
        }
        
        if ($null -ne $Config.policies.outboundSpam) {
            Write-Log "Deploying Outbound Spam policy..." -Level Info
            Deploy-OutboundSpamPolicy -PolicyConfig $Config.policies.outboundSpam -DryRun $DryRun
        }
        
        if ($null -ne $Config.allowBlockList) {
            Write-Log "Deploying Tenant Allow/Block List..." -Level Info
            Deploy-TenantAllowBlockList -AllowBlockConfig $Config.allowBlockList -DryRun $DryRun
        }
        
        Write-Log "Configuration deployment completed successfully" -Level Success
        return $true
    }
    catch {
        Write-Log "Configuration deployment failed: $_" -Level Error
        throw
    }
}

#endregion

#region Main execution
try {
    Write-Log "=====================================================================" -Level Info
    Write-Log "MDO Baseline Configuration Deployment v$ScriptVersion" -Level Info
    Write-Log "Script: $ScriptName" -Level Info
    Write-Log "=====================================================================" -Level Info
    Write-Log "Tenant ID: $TenantId" -Level Info
    Write-Log "Tenant Name: $TenantName" -Level Info
    Write-Log "Tenant Domain: $TenantDomain" -Level Info
    Write-Log "Log Path: $LogPath" -Level Info
    
    # Validate prerequisites
    Test-Prerequisites | Out-Null
    
    # Load configuration
    Write-Log "Loading configuration from: $ConfigPath" -Level Info
    $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    
    # Resolve parameters
    $parameters = @{
        'TENANT_ID' = $TenantId
        'TENANT_NAME' = $TenantName
        'TENANT_DOMAIN' = $TenantDomain
        'SECURITY_ADMIN_EMAIL' = $SecurityAdminEmail
    }
    $config = Resolve-ConfigParameters -ConfigObject $config -Parameters $parameters
    
    # Connect to Exchange Online
    Connect-ExchangeOnline -TenantId $TenantId
    
    # Show confirmation if not dry run
    if (-not $DryRun -and -not $SkipConfirmation) {
        Write-Log "=====================================================================" -Level Warn
        Write-Log "Review deployment details above. This will modify your organization's MDO policies." -Level Warn
        Write-Log "=====================================================================" -Level Warn
        $continue = Read-Host "Continue with deployment? (yes/no)"
        if ($continue -ne 'yes') {
            Write-Log "Deployment cancelled by user" -Level Info
            exit 0
        }
    }
    
    # Deploy configuration
    Deploy-Configuration -Config $config -DryRun $DryRun
    
    # Disconnect
    Disconnect-ExchangeOnline -Confirm:$false
    
    Write-Log "=====================================================================" -Level Success
    Write-Log "Deployment process completed" -Level Success
    Write-Log "Log file saved to: $LogPath" -Level Success
    Write-Log "=====================================================================" -Level Success
}
catch {
    Write-Log "FATAL ERROR: $_" -Level Error
    Write-Log $_.Exception.StackTrace -Level Error
    exit 1
}
#endregion
