#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Generate parameterized MDO configuration files with environment-specific values
    
.DESCRIPTION
    Creates configuration files from baseline templates by substituting organization-specific parameters.
    
.PARAMETER TemplateFile
    Path to baseline configuration template file (e.g., baseline-standard.json)
    
.PARAMETER OutputFile
    Path for output configuration file
    
.PARAMETER ParametersFile
    Path to JSON file containing parameter values
    
.PARAMETER TenantId
    Azure AD Tenant ID
    
.PARAMETER TenantName
    Organization display name
    
.PARAMETER TenantDomain
    Primary tenant domain
    
.PARAMETER SecurityAdminEmail
    Security admin email for notifications
    
.EXAMPLE
    .\Generate-ConfigFromTemplate.ps1 `
        -TemplateFile "./baseline-standard.json" `
        -OutputFile "./contoso-standard.json" `
        -TenantId "12345678-1234-1234-1234-123456789012" `
        -TenantName "Contoso Inc" `
        -TenantDomain "contoso.com" `
        -SecurityAdminEmail "security@contoso.com"

.EXAMPLE
    # Using parameters file
    .\Generate-ConfigFromTemplate.ps1 `
        -TemplateFile "./baseline-strict.json" `
        -OutputFile "./fabrikam-strict.json" `
        -ParametersFile "./fabrikam-params.json"
#>

param (
    [Parameter(Mandatory = $true, ParameterSetName = 'DirectParameters')]
    [Parameter(Mandatory = $true, ParameterSetName = 'ParametersFile')]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$TemplateFile,

    [Parameter(Mandatory = $true, ParameterSetName = 'DirectParameters')]
    [Parameter(Mandatory = $true, ParameterSetName = 'ParametersFile')]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFile,

    [Parameter(Mandatory = $true, ParameterSetName = 'ParametersFile')]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ParametersFile,

    [Parameter(Mandatory = $true, ParameterSetName = 'DirectParameters')]
    [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory = $true, ParameterSetName = 'DirectParameters')]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [Parameter(Mandatory = $true, ParameterSetName = 'DirectParameters')]
    [ValidatePattern('^\w+(\.\w+)*$')]
    [string]$TenantDomain,

    [Parameter(Mandatory = $true, ParameterSetName = 'DirectParameters')]
    [ValidatePattern('^[^@]+@[^@]+\.[^@]+$')]
    [string]$SecurityAdminEmail
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error-Msg {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

try {
    Write-Info "Loading configuration template: $TemplateFile"
    $templateContent = Get-Content -Path $TemplateFile -Raw
    
    # Load parameters
    if ($PSCmdlet.ParameterSetName -eq 'ParametersFile') {
        Write-Info "Loading parameters from: $ParametersFile"
        $parameters = Get-Content -Path $ParametersFile -Raw | ConvertFrom-Json
        $TenantId = $parameters.tenantId
        $TenantName = $parameters.tenantName
        $TenantDomain = $parameters.tenantDomain
        $SecurityAdminEmail = $parameters.securityAdminEmail
    }
    
    # Replace tokens
    Write-Info "Substituting parameters..."
    $resolvedContent = $templateContent `
        -replace '\{\{TENANT_ID\}\}', $TenantId `
        -replace '\{\{TENANT_NAME\}\}', $TenantName `
        -replace '\{\{TENANT_DOMAIN\}\}', $TenantDomain `
        -replace '\{\{SECURITY_ADMIN_EMAIL\}\}', $SecurityAdminEmail
    
    # Validate JSON structure
    Write-Info "Validating JSON structure..."
    $resolvedContent | ConvertFrom-Json | Out-Null
    
    # Write output
    Write-Info "Writing configuration to: $OutputFile"
    $resolvedContent | Out-File -FilePath $OutputFile -Encoding UTF8
    
    Write-Success "Configuration file generated successfully"
    Write-Success "Output: $OutputFile"
}
catch {
    Write-Error-Msg "Failed to generate configuration: $_"
    exit 1
}
