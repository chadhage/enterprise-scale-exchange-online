#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Tests live Exchange Online state and writes machine-readable evidence.
.DESCRIPTION
    Builds the shared baseline context to learn the deployment profile and licence
    tier, then collects evidence for every control that the tenant is entitled to
    run. Controls above the declared licence tier are reported as NotEntitled and
    do not fail the run. Controls owned by another system are reported as Manual.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ParameterPath,

    [string]$ConfigurationPath = (Join-Path $PSScriptRoot '..\config\exchange-online-secure-baseline.json'),

    [string]$SchemaPath = (Join-Path $PSScriptRoot '..\config\exchange-online-secure-baseline.schema.json'),

    [string]$OutputPath = (Join-Path $PSScriptRoot '..\evidence'),

    [switch]$SkipConnection
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking

# COM-007: evidence and deployment draw from this one context, so neither can evaluate a desired
# state or report an identity the other never saw. Unresolved administrator inputs are rejected here.
$context = Get-BaselineContext -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath -SchemaPath $SchemaPath
$configuration = $context.Configuration
$entitlement = $context.Entitlement

$gatewayDeclared = $context.GatewayDeclared
$messagingTier = $entitlement.MessagingTier
$complianceTier = $entitlement.ComplianceTier
$mdoLicensed = $entitlement.AtpPresets
$safeDocsLicensed = $entitlement.SafeDocuments
$purviewLicensed = $entitlement.PurviewRetention

if (-not $SkipConnection) {
    Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0
    Connect-ExchangeOnline -ShowBanner:$false
}

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$domain = $configuration.administratorInputs.primaryDomain

$evidence = [ordered]@{
    collectedAtUtc     = (Get-Date).ToUniversalTime().ToString('o')
    deploymentProfile  = $configuration.metadata.deploymentProfile
    configurationHash  = '{0}:{1}' -f $context.Algorithm.ToLowerInvariant(), $context.Hash
    licensing          = [ordered]@{ messagingTier = $messagingTier; complianceTier = $complianceTier }
    acceptedDomain     = Get-AcceptedDomain -Identity $domain | Select-Object Name, DomainName, DomainType
    transport          = Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled, ExternalPostmasterAddress
    organization       = Get-OrganizationConfig | Select-Object AuditDisabled, EwsEnabled, EwsAllowList
    externalInOutlook  = @(Get-ExternalInOutlook | Select-Object Enabled, AllowList)
    remoteDomain       = Get-RemoteDomain -Identity Default | Select-Object Name, AutoForwardEnabled, AutoReplyEnabled, AllowedOOFType, DeliveryReportEnabled, NDREnabled
    casMailboxPlans    = @(Get-CASMailboxPlan -ResultSize Unlimited | Select-Object Identity, PopEnabled, ImapEnabled)
    outboundSpam       = Get-HostedOutboundSpamFilterPolicy -Identity Default | Select-Object Name, AutoForwardingMode
    quarantineGlobal   = Get-QuarantinePolicy -Identity DefaultGlobalTag | Select-Object Name, EndUserSpamNotificationFrequency
    quarantinePolicies = @(Get-QuarantinePolicy | Select-Object Name, EndUserQuarantinePermissionsValue, ESNEnabled)
    dkim               = Get-DkimSigningConfig -Identity $domain | Select-Object Name, Enabled, Status, Selector1CNAME, Selector2CNAME, Selector1KeySize, Selector2KeySize
    standardEop        = Get-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' | Select-Object Name, State, RecipientDomainIs, ExceptIfSentTo, ExceptIfSentToMemberOf
    strictEop          = Get-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' | Select-Object Name, State, SentToMemberOf
    roleGroups         = @(Get-RoleGroup -ResultSize Unlimited | Select-Object Name, Members)
    bypassRules        = @(Get-TransportRule | Where-Object { $_.SetSCL -eq '-1' } | Select-Object Name, State, SetSCL)
}

if ($gatewayDeclared) {
    $inboundName = $configuration.administratorInputs.gatewayInboundConnectorName
    $outboundName = $configuration.administratorInputs.gatewayOutboundConnectorName
    $evidence.inboundConnector = Get-InboundConnector -Identity $inboundName | Select-Object Name, Enabled, ConnectorType, RequireTls, SenderIPAddresses, EFSkipLastIP, EFSkipIPs, EFUsers
    $evidence.outboundConnector = Get-OutboundConnector -Identity $outboundName | Select-Object Name, Enabled, ConnectorType, RecipientDomains, SmartHosts, TlsSettings, TlsDomain
}
else {
    $evidence.partnerInboundConnectors = @(Get-InboundConnector | Where-Object { $_.ConnectorType -eq 'Partner' -and $_.Enabled } | Select-Object Name, SenderIPAddresses)
}

if ($mdoLicensed) {
    $evidence.atpGlobal = Get-AtpPolicyForO365 | Select-Object EnableATPForSPOTeamsODB, EnableSafeDocs, AllowSafeDocsOpen
    $evidence.standardAtp = Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' | Select-Object Name, State, RecipientDomainIs, ExceptIfSentTo, ExceptIfSentToMemberOf
    $evidence.strictAtp = Get-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' | Select-Object Name, State, SentToMemberOf
    $evidence.builtInProtection = Get-ATPBuiltInProtectionRule | Select-Object Name, State, ExceptIfRecipientDomainIs, ExceptIfSentTo, ExceptIfSentToMemberOf
}

$checks = [ordered]@{}

function Add-Check {
    param([string]$Name, [string]$Status, [string]$Detail = '')
    $checks[$Name] = [ordered]@{ status = $Status; detail = $Detail }
}

function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail = '')
    Add-Check -Name $Name -Status $(if ($Passed) { 'Pass' } else { 'Fail' }) -Detail $Detail
}

Add-Result 'EXO-001 acceptedDomainAuthoritative' ($evidence.acceptedDomain.DomainType -eq 'Authoritative')
Add-Result 'EXO-002 smtpAuthDisabled' ([bool]$evidence.transport.SmtpClientAuthenticationDisabled)
Add-Check  'EXO-003 legacyAuthBlocked' 'Manual' 'Verify the Conditional Access legacy authentication block in Microsoft Entra'
Add-Result 'EXO-004 automaticForwardingOff' ($evidence.outboundSpam.AutoForwardingMode -eq 'Off')
Add-Result 'EXO-005 externalPostmasterSet' ([bool]$evidence.transport.ExternalPostmasterAddress)
Add-Result 'EXO-006 mailboxAuditingOn' (-not [bool]$evidence.organization.AuditDisabled)
Add-Result 'EXO-007 externalSenderTagging' ([bool]($evidence.externalInOutlook | Where-Object { $_.Enabled }))
Add-Result 'EXO-008 remoteDomainHardened' (
    -not $evidence.remoteDomain.AutoForwardEnabled -and
    -not $evidence.remoteDomain.AutoReplyEnabled -and
    -not $evidence.remoteDomain.NDREnabled
)
Add-Result 'EXO-009 legacyProtocolsRestricted' (
    -not [bool]$evidence.organization.EwsEnabled -and
    -not ($evidence.casMailboxPlans | Where-Object { $_.PopEnabled -or $_.ImapEnabled })
)
Add-Check  'EXO-010 rbacHygiene' 'Manual' "Review $($evidence.roleGroups.Count) role groups and confirm no standing Global Administrator for messaging"
Add-Check  'EXO-011 mtaStsAndTlsRpt' 'Manual' "Resolve _mta-sts.$domain and _smtp._tls.$domain and confirm the policy endpoint returns mode=enforce"

Add-Result 'MDO-001 standardPresetEnabled' (
    $evidence.standardEop.State -eq 'Enabled' -and
    (-not $mdoLicensed -or $evidence.standardAtp.State -eq 'Enabled')
)
Add-Result 'MDO-002 strictPresetEnabled' (
    $evidence.strictEop.State -eq 'Enabled' -and
    (-not $mdoLicensed -or $evidence.strictAtp.State -eq 'Enabled')
)

if ($mdoLicensed) {
    Add-Result 'MDO-003 builtInProtectionUnexcluded' (
        $evidence.builtInProtection.State -eq 'Enabled' -and
        -not $evidence.builtInProtection.ExceptIfRecipientDomainIs -and
        -not $evidence.builtInProtection.ExceptIfSentToMemberOf
    )
    Add-Result 'MDO-004 filesProtectionEnabled' ([bool]$evidence.atpGlobal.EnableATPForSPOTeamsODB)
    if ($safeDocsLicensed) {
        Add-Result 'MDO-005 safeDocumentsNoBypass' (
            [bool]$evidence.atpGlobal.EnableSafeDocs -and -not [bool]$evidence.atpGlobal.AllowSafeDocsOpen
        )
    }
    else {
        Add-Check 'MDO-005 safeDocumentsNoBypass' 'NotEntitled' "messagingTier is $messagingTier"
    }
}
else {
    foreach ($control in 'MDO-003 builtInProtectionUnexcluded', 'MDO-004 filesProtectionEnabled', 'MDO-005 safeDocumentsNoBypass') {
        Add-Check $control 'NotEntitled' "messagingTier is $messagingTier"
    }
}

Add-Check  'MDO-006 userSubmissions' 'Manual' 'Confirm the user submission policy and the SecOps copy in the Defender portal'
Add-Check  'MDO-007 tenantAllowBlockList' 'Manual' 'Export TABL entries and confirm every allow has an owner, ticket, and expiry'
Add-Result 'MDO-008 quarantineNotificationCadence' ([bool]$evidence.quarantineGlobal.EndUserSpamNotificationFrequency)

Add-Result 'AUTH-001 dkimEnabledAndValid' ([bool]$evidence.dkim.Enabled -and $evidence.dkim.Status -eq 'Valid')
Add-Check  'AUTH-002 spfHardFail' 'Manual' "Query the authoritative TXT record for $domain and confirm a single record ending -all"
Add-Check  'AUTH-003 dmarcReject' 'Manual' "Query _dmarc.$domain and confirm p=reject; pct=100; sp=reject"

if ($gatewayDeclared) {
    Add-Result 'PP-001 gatewayInboundConstrained' (
        [bool]$evidence.inboundConnector.Enabled -and
        [bool]$evidence.inboundConnector.RequireTls -and
        @($evidence.inboundConnector.SenderIPAddresses).Count -gt 0
    )
    Add-Result 'PP-002 enhancedFilteringEnabled' (
        @($evidence.inboundConnector.EFSkipIPs).Count -gt 0 -or [bool]$evidence.inboundConnector.EFSkipLastIP
    )
    Add-Result 'PP-003 gatewayOutboundEnabled' ([bool]$evidence.outboundConnector.Enabled)
}
else {
    Add-Check 'PP-001 gatewayInboundConstrained' 'NotApplicable' 'Microsoft-native profile: no gateway declared'
    Add-Result 'PP-002 noUndeclaredPartnerInbound' ($evidence.partnerInboundConnectors.Count -eq 0) `
        'A Microsoft-native tenant should have no enabled Partner inbound connector'
    Add-Check 'PP-003 gatewayOutboundEnabled' 'NotApplicable' 'Microsoft-native profile: no gateway declared'
}

Add-Result 'BAD-001 noSclMinusOneBypassRules' ($evidence.bypassRules.Count -eq 0)

Add-Check 'MON-001 siemIngestion' 'Manual' 'Confirm connector health and a synthetic alert in the central SIEM'
Add-Check 'MON-002 unifiedAudit' 'Manual' 'Run a Purview audit search and export the result'

if ($purviewLicensed) {
    foreach ($control in 'GOV-002 exchangeDlpPolicy', 'GOV-003 mailboxRetentionPolicy', 'GOV-004 litigationHoldPriorityUsers') {
        Add-Check $control 'Manual' 'Verify in Security & Compliance PowerShell; not reachable from the Exchange Online session'
    }
}
else {
    foreach ($control in 'GOV-002 exchangeDlpPolicy', 'GOV-003 mailboxRetentionPolicy', 'GOV-004 litigationHoldPriorityUsers') {
        Add-Check $control 'NotEntitled' "complianceTier is $complianceTier"
    }
}
Add-Check 'GOV-001 auditRetention' $(if ($complianceTier -eq 'E5Compliance') { 'Manual' } else { 'NotEntitled' }) `
    "complianceTier is $complianceTier"

$summary = [ordered]@{}
$checks.Values | Group-Object { $_.status } | ForEach-Object { $summary[$_.Name] = $_.Count }

$result = [ordered]@{ evidence = $evidence; checks = $checks; summary = $summary }
$resultPath = Join-Path $OutputPath "exchange-online-evidence-$timestamp.json"
$result | ConvertTo-Json -Depth 20 | Set-Content -Path $resultPath -Encoding utf8

$checks.GetEnumerator() | ForEach-Object {
    $colour = switch ($_.Value.status) {
        'Pass'          { 'Green' }
        'Fail'          { 'Red' }
        'NotEntitled'   { 'Yellow' }
        'NotApplicable' { 'DarkGray' }
        default         { 'Cyan' }
    }
    Write-Host ("[{0,-13}] {1} {2}" -f $_.Value.status, $_.Key, $_.Value.detail) -ForegroundColor $colour
}

Write-Host ''
$summary.GetEnumerator() | ForEach-Object { Write-Host "$($_.Key): $($_.Value)" }
Write-Host "Evidence written to $resultPath"

$failed = @($checks.Values | Where-Object { $_.status -eq 'Fail' })
if ($failed.Count -gt 0) { exit 1 }