#requires -Version 7.5
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
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psm1') -DisableNameChecking
Invoke-BaselineApprovedChange @PSBoundParameters