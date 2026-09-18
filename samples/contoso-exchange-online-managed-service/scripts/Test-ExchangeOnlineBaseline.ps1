#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Tests live Exchange Online state and writes machine-readable evidence.
.DESCRIPTION
    Builds the shared baseline context to learn the deployment profile and the
    entitlement the tenant service-plan inventory reports, then collects evidence
    for every control the tenant is entitled to run. Controls the tenant does not
    hold an enabled service plan for are reported as NotEntitled and do not fail
    the run. Controls owned by another system are reported as Manual.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ParameterPath,

    [string]$ConfigurationPath = (Join-Path $PSScriptRoot '..\config\exchange-online-secure-baseline.json'),

    [string]$SchemaPath = (Join-Path $PSScriptRoot '..\config\exchange-online-secure-baseline.schema.json'),

    [string]$OutputPath = (Join-Path $PSScriptRoot '..\evidence'),

    # GATE-001: the go-live request and everything a fail-closed decision has to be measured
    # against. All four are optional, because an ordinary evidence run must stay able to collect
    # without being asked to decide, and a gate that every run is forced through is a gate that
    # gets switched off. None of them is read until GATE-003 wires the decision.
    [switch]$GoLive,

    [string]$RiskAcceptancePath,

    [timespan]$MaximumEvidenceAge,

    [string]$ExpectedConfigurationHash,

    [switch]$SkipConnection
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking

# GATE-004: every exit this command produces is resolved from the one contract, so an automation
# caller can tell a configuration it can fix from a connection it can retry, a collection it can
# rerun, a compliance gap it must escalate, an approval it must obtain, and a defect in this tool.
# A run that reported all six as `1` told the caller none of that.
$exitCode = Get-BaselineExitCodeContract

# A fault nothing below anticipated is a defect in this tool rather than a finding about the
# tenant, and reporting it as a finding sends the operator to fix a tenant that was never at fault.
trap {
    Write-Error "InternalFault: $($_.Exception.Message)" -ErrorAction Continue
    exit $exitCode.Internal
}

# LIC-008: DES-003 makes the runtime tenant service-plan inventory the only entitlement authority,
# so Graph is connected before the context is built and the same seam feeds both entry scripts.
# With no connection nothing is collected and every capability is reported unentitled.
$graphRequest = $null
if (-not $SkipConnection) {
    try {
        Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0
        Connect-ExchangeOnline -ShowBanner:$false

        Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.0.0
        Connect-MgGraph -Scopes 'Organization.Read.All' -NoWelcome
    }
    catch {
        Write-Error "ConnectionFailed: $($_.Exception.Message)" -ErrorAction Continue
        exit $exitCode.Connection
    }

    $graphRequest = {
        param($Resource)
        Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/$Resource" -OutputType PSObject
    }
}

# COM-007: evidence and deployment draw from this one context, so neither can evaluate a desired
# state or report an identity the other never saw. Unresolved administrator inputs are rejected here.
try {
    $context = Get-BaselineContext -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath -SchemaPath $SchemaPath -GraphRequest $graphRequest
    $configuration = $context.Configuration
    $entitlement = $context.Entitlement
}
catch {
    Write-Error "ConfigurationUnusable: $($_.Exception.Message)" -ErrorAction Continue
    exit $exitCode.Configuration
}

$gatewayDeclared = $context.GatewayDeclared
$mdoLicensed = $entitlement.AtpPresets
$safeDocsLicensed = $entitlement.SafeDocuments
$purviewLicensed = $entitlement.PurviewRetention
$auditPremiumLicensed = $entitlement.AuditPremium
$entitlementReason = @{}
foreach ($capability in @($entitlement.Capability)) { $entitlementReason[$capability.Name] = $capability.Reason }

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$domain = $configuration.administratorInputs.primaryDomain

# A tenant this run could not read is a rerun the caller can act on, not a control it must escalate,
# so every observation is taken inside one boundary that reports the collection fault on its own.
try {
    $evidence = [ordered]@{
        licensing          = [ordered]@{
            entitlementSource      = $entitlement.Source
            entitlementDetermined  = $entitlement.Determined
            enabledServicePlanId   = @($entitlement.EnabledServicePlanId)
            capability             = @($entitlement.Capability)
            notEntitled            = @($entitlement.NotEntitled)
            declaredMessagingTier  = $entitlement.DeclaredMessagingTier
            declaredComplianceTier = $entitlement.DeclaredComplianceTier
        }
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
}
catch {
    Write-Error "CollectionFailed: $($_.Exception.Message)" -ErrorAction Continue
    exit $exitCode.Collection
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
        Add-Check 'MDO-005 safeDocumentsNoBypass' 'NotEntitled' $entitlementReason['SafeDocuments']
    }
}
else {
    foreach ($control in 'MDO-003 builtInProtectionUnexcluded', 'MDO-004 filesProtectionEnabled', 'MDO-005 safeDocumentsNoBypass') {
        Add-Check $control 'NotEntitled' $entitlementReason['AtpPresets']
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
        Add-Check $control 'NotEntitled' $entitlementReason['PurviewRetention']
    }
}
Add-Check 'GOV-001 auditRetention' $(if ($auditPremiumLicensed) { 'Manual' } else { 'NotEntitled' }) `
    $entitlementReason['AuditPremium']

$summary = [ordered]@{}
$checks.Values | Group-Object { $_.status } | ForEach-Object { $summary[$_.Name] = $_.Count }

# EVD-004: which control each raw observation belongs to, and the command that actually produced
# it. The envelope carries evidence records rather than a blob, so every observation has to name a
# control; a control this run does not observe is recorded as an uncollected record rather than
# left out, because a missing member reads exactly like a control that was checked and found clean.
$observation = [ordered]@{
    'EXO-001'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-AcceptedDomain'; Key = @('acceptedDomain') }
    'EXO-002'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-TransportConfig'; Key = @('transport') }
    'EXO-004'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-HostedOutboundSpamFilterPolicy'; Key = @('outboundSpam') }
    'EXO-005'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-TransportConfig'; Key = @('transport') }
    'EXO-006'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-OrganizationConfig'; Key = @('organization') }
    'EXO-007'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-ExternalInOutlook'; Key = @('externalInOutlook') }
    'EXO-008'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-RemoteDomain'; Key = @('remoteDomain') }
    'EXO-009'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-CASMailboxPlan'; Key = @('organization', 'casMailboxPlans') }
    'EXO-010'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-RoleGroup'; Key = @('roleGroups') }
    'MDO-001'  = [ordered]@{ Source = 'Defender'; Command = 'Get-EOPProtectionPolicyRule'; Key = @('standardEop', 'standardAtp') }
    'MDO-002'  = [ordered]@{ Source = 'Defender'; Command = 'Get-EOPProtectionPolicyRule'; Key = @('strictEop', 'strictAtp') }
    'MDO-003'  = [ordered]@{ Source = 'Defender'; Command = 'Get-ATPBuiltInProtectionRule'; Key = @('builtInProtection') }
    'MDO-004'  = [ordered]@{ Source = 'Defender'; Command = 'Get-AtpPolicyForO365'; Key = @('atpGlobal') }
    'MDO-005'  = [ordered]@{ Source = 'Defender'; Command = 'Get-AtpPolicyForO365'; Key = @('atpGlobal') }
    'MDO-008'  = [ordered]@{ Source = 'Defender'; Command = 'Get-QuarantinePolicy'; Key = @('quarantineGlobal', 'quarantinePolicies') }
    'AUTH-001' = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-DkimSigningConfig'; Key = @('dkim') }
    'PP-001'   = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-InboundConnector'; Key = @('inboundConnector') }
    'PP-002'   = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-InboundConnector'; Key = @('inboundConnector') }
    'PP-003'   = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-OutboundConnector'; Key = @('outboundConnector') }
    'PP-005'   = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-InboundConnector'; Key = @('partnerInboundConnectors') }
    'BAD-001'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-TransportRule'; Key = @('bypassRules') }
}

$observed = foreach ($id in @($observation.Keys)) {
    $declaration = $observation[$id]
    $absent = @(@($declaration.Key) | Where-Object { -not $evidence.Contains($_) })
    if ($absent.Count -gt 0) {
        New-BaselineEvidence -ControlId $id -Source $declaration.Source -Command $declaration.Command -Value $null `
            -Failed -FailureReason "CollectionNotRun: '$($absent -join "', '")' was not collected in this run."
        continue
    }

    $payload = [ordered]@{}
    foreach ($name in @($declaration.Key)) { $payload[$name] = $evidence[$name] }
    New-BaselineEvidence -ControlId $id -Source $declaration.Source -Command $declaration.Command -Value $payload
}

# The registry is returned as one collection, so it is enumerated through a variable: iterating the
# command itself binds the whole registry to `$control` and the run faults before it decides anything.
$registry = Get-BaselineControlRegistry

$uncollected = foreach ($control in $registry) {
    if ($observation.Contains($control.ControlId)) { continue }
    New-BaselineEvidence -ControlId $control.ControlId -Source $control.EvidencePath.Split('.')[0] -Command $control.Collector -Value $null `
        -Failed -FailureReason "CollectorNotRun: '$($control.Collector)' observes '$($control.ControlId)' and did not run."
}

# The check names carry the control they decide, so the verdicts reach the envelope through the
# result contract instead of as free-form text nothing downstream can reason about.
$verdict = foreach ($check in $checks.GetEnumerator()) {
    $decided = ($check.Key -split '\s+', 2)[0]
    $reason = $check.Value.detail
    if ($check.Value.status -cne 'Pass' -and [string]::IsNullOrWhiteSpace($reason)) {
        $reason = "$($check.Key) did not pass."
    }

    New-ControlResult -ControlId $decided -Status $check.Value.status -Reason $reason
}

$envelope = New-BaselineEvidenceEnvelope -Context $context `
    -TenantId $configuration.administratorInputs.tenantId `
    -OrganizationName $configuration.administratorInputs.organizationName `
    -ParameterPath $ParameterPath `
    -Evidence (@($observed) + @($uncollected)) `
    -Check @($verdict)

$resultPath = Join-Path $OutputPath "exchange-online-evidence-$timestamp.json"
$envelope | ConvertTo-Json -Depth 20 | Set-Content -Path $resultPath -Encoding utf8

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
Write-Host "Failed: $($failed.Count)"

# GATE-006 wires `Test-BaselineGoLive` in behind `-GoLive`. Until the signing pipeline exists no
# run can produce signed evidence, so a decision asked for here could only ever refuse, and a flag
# that always refuses is a flag operators route around. The seam reads the checks in the meantime.
$goLiveDecision = $null

# GATE-004: the run's exit is resolved by the seam and nowhere else. The previous `exit 1` fired on
# `Fail` alone, so a control nobody could decide - a `Manual`, a `NotEntitled`, an `Error` - left
# this command reporting success, which is a gate that passes every tenant it never looked at.
$outcome = Get-BaselineRunOutcome -Check @($verdict) -GoLive $goLiveDecision
Write-Host ("Outcome: {0} ({1}) {2}" -f $outcome.Outcome, $outcome.ExitCode, $outcome.Reason)

exit $outcome.ExitCode