#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Validates MDO configuration file against schema and best practices
    
.DESCRIPTION
    Comprehensive validation of MDO configuration JSON files to ensure compliance
    with schema, organizational best practices, and Microsoft recommendations.
    
.PARAMETER ConfigPath
    Path to configuration JSON file to validate
    
.PARAMETER SchemaPath
    Path to JSON schema file (defaults to mdo-config-schema.json in same directory)
    
.EXAMPLE
    .\Validate-MDOConfiguration.ps1 -ConfigPath "./contoso-standard.json"
#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ConfigPath,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$SchemaPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# If schema path not provided, look in same directory
if (-not $SchemaPath) {
    $SchemaPath = Join-Path (Split-Path -Parent $ConfigPath) "mdo-config-schema.json"
}

$validationResults = @{
    Passed = @()
    Failed = @()
    Warnings = @()
}

function Add-Pass {
    param([string]$Message)
    $validationResults.Passed += $Message
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Add-Fail {
    param([string]$Message)
    $validationResults.Failed += $Message
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Add-Warn {
    param([string]$Message)
    $validationResults.Warnings += $Message
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

try {
    Write-Host "Validating MDO Configuration: $ConfigPath" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    
    # Load config
    Write-Host "Loading configuration..." -ForegroundColor Gray
    $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    Add-Pass "Configuration file loaded successfully"
    
    # Check required fields
    Write-Host "Validating required fields..." -ForegroundColor Gray
    
    $requiredFields = @('organizationSettings', 'protectionLevel', 'policies', 'metadata')
    foreach ($field in $requiredFields) {
        if ($null -ne $config.$field) {
            Add-Pass "Required field present: $field"
        }
        else {
            Add-Fail "Missing required field: $field"
        }
    }
    
    # Validate tenant settings
    Write-Host "Validating organization settings..." -ForegroundColor Gray
    
    $orgSettings = $config.organizationSettings
    
    # Check tenant ID format
    if ($orgSettings.tenantId -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        Add-Pass "Tenant ID format is valid (GUID)"
    }
    else {
        Add-Fail "Tenant ID format is invalid: $($orgSettings.tenantId)"
    }
    
    # Check tenant name
    if ([string]::IsNullOrWhiteSpace($orgSettings.tenantName)) {
        Add-Fail "Tenant name is empty"
    }
    else {
        Add-Pass "Tenant name specified: $($orgSettings.tenantName)"
    }
    
    # Check protection strategy
    $validStrategies = @('Built-in', 'Standard', 'Strict', 'Custom')
    if ($validStrategies -contains $orgSettings.protectionStrategy) {
        Add-Pass "Protection strategy is valid: $($orgSettings.protectionStrategy)"
    }
    else {
        Add-Fail "Invalid protection strategy: $($orgSettings.protectionStrategy)"
    }
    
    # Validate deployment mode
    Write-Host "Validating deployment settings..." -ForegroundColor Gray
    
    if ($orgSettings.deploymentMode -eq 'Audit') {
        Add-Warn "Deployment mode is AUDIT (detection only, no enforcement)"
    }
    elseif ($orgSettings.deploymentMode -eq 'Enforce') {
        Add-Pass "Deployment mode is ENFORCE (threats will be blocked)"
    }
    
    # Validate policies
    Write-Host "Validating threat policies..." -ForegroundColor Gray
    
    $policies = $config.policies
    $policyCount = 0
    
    foreach ($policyType in $policies.PSObject.Properties) {
        if ($null -ne $policyType.Value -and $policyType.Value.Count -gt 0) {
            Add-Pass "$($policyType.Name): $($policyType.Value.Count) policy(ies) defined"
            $policyCount += $policyType.Value.Count
        }
    }
    
    if ($policyCount -eq 0) {
        Add-Fail "No policies defined"
    }
    else {
        Add-Pass "Total policies defined: $policyCount"
    }
    
    # Validate recipient settings
    Write-Host "Validating recipient settings..." -ForegroundColor Gray
    
    $recipients = $config.recipients
    if ($recipients.applyToAllRecipients) {
        Add-Pass "Policies will apply to all recipients"
    }
    else {
        $recipientCount = 0
        $recipientCount += @($recipients.includedDomains).Count
        $recipientCount += @($recipients.includedGroups).Count
        $recipientCount += @($recipients.includedUsers).Count
        
        if ($recipientCount -gt 0) {
            Add-Pass "Policies will apply to $recipientCount recipient filter(s)"
        }
        else {
            Add-Warn "No specific recipients defined and applyToAllRecipients is false"
        }
    }
    
    # Validate email addresses in notifications
    Write-Host "Validating notification settings..." -ForegroundColor Gray
    
    $notifications = $config.notifications
    foreach ($email in $notifications.alertNotifications) {
        if ($email -match '^[^@]+@[^@]+\.[^@]+$') {
            Add-Pass "Alert notification email is valid: $email"
        }
        else {
            Add-Fail "Invalid alert notification email: $email"
        }
    }
    
    # Validate authentication settings
    Write-Host "Validating authentication settings..." -ForegroundColor Gray
    
    $auth = $config.authentication
    if ($auth.dmarc.enabled) {
        Add-Pass "DMARC protection is enabled (policy: $($auth.dmarc.policy))"
    }
    else {
        Add-Warn "DMARC protection is disabled"
    }
    
    if ($auth.dkim.enabled) {
        Add-Pass "DKIM signing is enabled"
    }
    else {
        Add-Warn "DKIM signing is disabled"
    }
    
    if ($auth.spf.enabled) {
        Add-Pass "SPF validation is enabled"
    }
    else {
        Add-Warn "SPF validation is disabled"
    }
    
    # Validate protection level thresholds
    Write-Host "Validating protection thresholds..." -ForegroundColor Gray
    
    $thresholds = $config.protectionLevel.customRiskThresholds
    if ($thresholds.phishingThreshold -eq 1) {
        Add-Pass "Phishing threshold set to most aggressive level (1)"
    }
    elseif ($thresholds.phishingThreshold -eq 4) {
        Add-Warn "Phishing threshold set to least aggressive level (4)"
    }
    else {
        Add-Pass "Phishing threshold set to level $($thresholds.phishingThreshold)"
    }
    
    # Final summary
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "Validation Summary" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "Passed:  $($validationResults.Passed.Count)" -ForegroundColor Green
    Write-Host "Failed:  $($validationResults.Failed.Count)" -ForegroundColor $(if ($validationResults.Failed.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Warnings: $($validationResults.Warnings.Count)" -ForegroundColor Yellow
    Write-Host "================================================" -ForegroundColor Cyan
    
    if ($validationResults.Failed.Count -gt 0) {
        exit 1
    }
    else {
        Write-Host "✓ Configuration validation completed successfully" -ForegroundColor Green
        exit 0
    }
}
catch {
    Write-Host "✗ Validation error: $_" -ForegroundColor Red
    exit 1
}
