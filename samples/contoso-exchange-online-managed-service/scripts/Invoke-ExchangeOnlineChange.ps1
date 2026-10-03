#requires -Version 7.5
<#
.SYNOPSIS
Runs one stage of an approved Exchange Online change: Preview, Approve, Validate, Apply or Rollback.

.DESCRIPTION
Preview, Apply and Rollback read or change the tenant. Before they start, the script checks the
ExchangeOnlineManagement module, shows any existing Exchange Online session and asks you to confirm it
(or signs you in with MFA), then checks the tenant, endpoint and that your role exposes the cmdlets the
change scopes need. Approve and Validate are offline and never connect.

.PARAMETER UserPrincipalName
Account to sign in with, and the account an existing session must belong to.

.PARAMETER UseDeviceCode
Sign in with a device code (for machines without a browser).

.PARAMETER ConfirmSession
Ask before reusing an existing session. Pass -ConfirmSession:$false for unattended runs.

.PARAMETER NonInteractive
Never prompt or open a sign-in window; stop with the exact command to run instead.

.PARAMETER SkipConnectionCheck
Skip the sign-in and permission pre-flight (offline test doubles only).
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidateSet('Preview','Approve','Validate','Apply','Rollback')][string]$Stage,
    [Parameter(Mandatory)][string]$ParameterPath,
    [Parameter(Mandatory)][string]$ConfigurationPath,
    [Parameter(Mandatory)][string]$ArtifactRoot,
    [Parameter(Mandatory)][string]$ChangeId,
    [Parameter(Mandatory)][string]$RequestedBy,
    [string]$PreviewPath,
    [string]$ApprovalPath,
    [string]$AuthorizedSignerPath,
    [string[]]$Scope = @(),
    [string]$ApprovalIdentity,
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,
    [switch]$Apply,
    [string]$UserPrincipalName,
    [switch]$UseDeviceCode,
    [bool]$ConfirmSession = $true,
    [switch]$NonInteractive,
    [switch]$SkipConnectionCheck
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psm1') -DisableNameChecking

$changeParameters = @{} + $PSBoundParameters
foreach ($name in @('UserPrincipalName', 'UseDeviceCode', 'ConfirmSession', 'NonInteractive', 'SkipConnectionCheck')) {
    $null = $changeParameters.Remove($name)
}

if ($Stage -in @('Preview', 'Apply', 'Rollback') -and -not $SkipConnectionCheck) {
    Import-Module (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Connection.psm1') -DisableNameChecking
    $sessionScope = @($Scope)
    if ($Stage -ne 'Preview' -and -not [string]::IsNullOrWhiteSpace($PreviewPath) -and (Test-Path -LiteralPath $PreviewPath -PathType Leaf)) {
        try {
            $sessionScope = @((Get-Content -LiteralPath $PreviewPath -Raw | ConvertFrom-Json -Depth 64).Scope)
        }
        catch {
            $sessionScope = @()
        }
    }
    $null = Initialize-ExchangeOnlineSession -ExpectedTenantId (Get-ExchangeExpectedTenantId -ParameterPath $ParameterPath) `
        -Scope $sessionScope -UserPrincipalName $UserPrincipalName -UseDeviceCode:$UseDeviceCode `
        -ConfirmSession $ConfirmSession -NonInteractive:$NonInteractive -InformationAction $(if ($PSBoundParameters.ContainsKey('InformationAction')) { $InformationPreference } else { 'Continue' })
}

Invoke-BaselineApprovedChange @changeParameters
