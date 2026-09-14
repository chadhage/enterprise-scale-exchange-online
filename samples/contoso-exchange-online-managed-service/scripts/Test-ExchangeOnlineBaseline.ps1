#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Tests live Exchange Online state and writes machine-readable evidence.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ParameterPath,

    [string]$OutputPath = (Join-Path $PSScriptRoot '..\evidence'),

    [switch]$SkipConnection
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$parameters = Get-Content -Path $ParameterPath -Raw | ConvertFrom-Json
$unresolved = Get-Content -Path $ParameterPath -Raw | Select-String '__ADMIN_REQUIRED:'
if ($unresolved) {
    throw 'Parameter file contains unresolved __ADMIN_REQUIRED tokens.'
}

if (-not $SkipConnection) {
    Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0
    Connect-ExchangeOnline -ShowBanner:$false
}

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$domain = $parameters.PRIMARY_SMTP_DOMAIN
$inboundName = 'Proofpoint Inbound'
$outboundName = 'Proofpoint Outbound'

$evidence = [ordered]@{
    collectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    acceptedDomain = Get-AcceptedDomain -Identity $domain | Select-Object Name, DomainName, DomainType
    inboundConnector = Get-InboundConnector -Identity $inboundName | Select-Object Name, Enabled, ConnectorType, RequireTls, SenderIPAddresses, EFSkipLastIP, EFSkipIPs, EFUsers
    outboundConnector = Get-OutboundConnector -Identity $outboundName | Select-Object Name, Enabled, ConnectorType, RecipientDomains, SmartHosts, TlsSettings, TlsDomain
    transport = Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled, ExternalPostmasterAddress
    outboundSpam = Get-HostedOutboundSpamFilterPolicy -Identity Default | Select-Object Name, AutoForwardingMode
    atpGlobal = Get-AtpPolicyForO365 | Select-Object EnableATPForSPOTeamsODB, EnableSafeDocs, AllowSafeDocsOpen
    dkim = Get-DkimSigningConfig -Identity $domain | Select-Object Name, Enabled, Status, Selector1CNAME, Selector2CNAME, Selector1KeySize, Selector2KeySize
    standardEop = Get-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' | Select-Object Name, State, RecipientDomainIs, ExceptIfSentTo, ExceptIfSentToMemberOf
    standardAtp = Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' | Select-Object Name, State, RecipientDomainIs, ExceptIfSentTo, ExceptIfSentToMemberOf
    strictEop = Get-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' | Select-Object Name, State, SentToMemberOf
    strictAtp = Get-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' | Select-Object Name, State, SentToMemberOf
    bypassRules = @(Get-TransportRule | Where-Object { $_.SetSCL -eq '-1' } | Select-Object Name, State, SetSCL)
}

$checks = [ordered]@{
    acceptedDomainAuthoritative = $evidence.acceptedDomain.DomainType -eq 'Authoritative'
    proofpointInboundEnabled = [bool]$evidence.inboundConnector.Enabled
    proofpointInboundTls = [bool]$evidence.inboundConnector.RequireTls
    enhancedFilteringEnabled = @($evidence.inboundConnector.EFSkipIPs).Count -gt 0 -or [bool]$evidence.inboundConnector.EFSkipLastIP
    proofpointOutboundEnabled = [bool]$evidence.outboundConnector.Enabled
    smtpAuthDisabled = [bool]$evidence.transport.SmtpClientAuthenticationDisabled
    automaticForwardingOff = $evidence.outboundSpam.AutoForwardingMode -eq 'Off'
    mdoFilesProtectionEnabled = [bool]$evidence.atpGlobal.EnableATPForSPOTeamsODB
    safeDocumentsBypassBlocked = -not [bool]$evidence.atpGlobal.AllowSafeDocsOpen
    dkimEnabledAndValid = [bool]$evidence.dkim.Enabled -and $evidence.dkim.Status -eq 'Valid'
    standardPresetEnabled = $evidence.standardEop.State -eq 'Enabled' -and $evidence.standardAtp.State -eq 'Enabled'
    strictPresetEnabled = $evidence.strictEop.State -eq 'Enabled' -and $evidence.strictAtp.State -eq 'Enabled'
    noSclMinusOneBypassRules = $evidence.bypassRules.Count -eq 0
}

$result = [ordered]@{ evidence = $evidence; checks = $checks }
$resultPath = Join-Path $OutputPath "exchange-online-evidence-$timestamp.json"
$result | ConvertTo-Json -Depth 20 | Set-Content -Path $resultPath -Encoding utf8
$checks.GetEnumerator() | ForEach-Object {
    $label = if ($_.Value) { 'PASS' } else { 'FAIL' }
    Write-Host "[$label] $($_.Key)"
}

Write-Host "Evidence written to $resultPath"
if ($checks.Values -contains $false) { exit 1 }