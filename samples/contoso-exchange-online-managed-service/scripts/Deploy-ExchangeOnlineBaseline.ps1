#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Applies the Contoso Exchange Online managed-service baseline.
.DESCRIPTION
    Resolves administrator inputs, validates the resulting desired state, and
    configures Exchange Online. The default mode is read-only; use -Apply only
    after reviewing the generated plan and vendor-specific values.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ParameterPath,

    [string]$ConfigurationPath = (Join-Path $PSScriptRoot '..\config\exchange-online-secure-baseline.json'),

    [string]$SchemaPath = (Join-Path $PSScriptRoot '..\config\exchange-online-secure-baseline.schema.json'),

    [switch]$Apply,

    [switch]$EnableDkim,

    [switch]$SkipConnection
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking

$script:Outcomes = [System.Collections.Generic.List[object]]::new()

function Add-Outcome {
    param([string]$Control, [string]$Status, [string]$Detail)

    $script:Outcomes.Add([pscustomobject]@{ Control = $Control; Status = $Status; Detail = $Detail })
    $colour = switch ($Status) {
        'Applied'     { 'Green' }
        'Planned'     { 'Cyan' }
        'NotEntitled' { 'Yellow' }
        'Manual'      { 'Yellow' }
        default       { 'Gray' }
    }
    Write-Host ("[{0,-11}] {1} {2}" -f $Status, $Control, $Detail) -ForegroundColor $colour
}

function Set-InboundGatewayConnector {
    param([object]$Configuration, [bool]$UseWhatIf)

    $name = $Configuration.administratorInputs.gatewayInboundConnectorName
    $settings = $Configuration.desiredState.mailFlow.gatewayInboundConnector
    $parameters = @{
        Enabled                      = $settings.enabled
        ConnectorType                = $settings.connectorType
        SenderDomains                = $settings.senderDomains
        SenderIPAddresses            = $settings.senderIpAddresses
        RequireTls                   = $settings.requireTls
        RestrictDomainsToIPAddresses = $settings.restrictDomainsToIpAddresses
        RestrictDomainsToCertificate = $settings.restrictDomainsToCertificate
        WhatIf                       = $UseWhatIf
    }

    if (Get-InboundConnector -Identity $name -ErrorAction SilentlyContinue) {
        Set-InboundConnector -Identity $name @parameters
    }
    else {
        New-InboundConnector -Name $name @parameters
    }

    $filter = $Configuration.desiredState.mailFlow.enhancedFiltering
    Set-InboundConnector -Identity $name -EFSkipLastIP $filter.skipLastIp `
        -EFSkipIPs $filter.skipIpAddresses -EFUsers $null -WhatIf:$UseWhatIf

    Add-Outcome -Control 'PP-001/PP-002' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail "Inbound connector '$name' with Enhanced Filtering"
}

function Set-OutboundGatewayConnector {
    param([object]$Configuration, [bool]$UseWhatIf)

    $name = $Configuration.administratorInputs.gatewayOutboundConnectorName
    $settings = $Configuration.desiredState.mailFlow.gatewayOutboundConnector
    $parameters = @{
        Enabled                       = $settings.enabled
        ConnectorType                 = $settings.connectorType
        RecipientDomains              = $settings.recipientDomains
        RouteAllMessagesViaOnPremises = $settings.routeAllMessagesViaOnPremises
        UseMXRecord                   = $settings.useMxRecord
        SmartHosts                    = $settings.smartHosts
        TlsSettings                   = $settings.tlsSettings
        TlsDomain                     = $settings.tlsDomain
        WhatIf                        = $UseWhatIf
    }

    if (Get-OutboundConnector -Identity $name -ErrorAction SilentlyContinue) {
        Set-OutboundConnector -Identity $name @parameters
    }
    else {
        New-OutboundConnector -Name $name @parameters
    }

    Add-Outcome -Control 'PP-003' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail "Outbound connector '$name'"
}

function Set-PresetProtection {
    param([object]$Configuration, [bool]$UseWhatIf, [object]$Entitlement)

    $domain = $Configuration.administratorInputs.primaryDomain
    $priorityGroup = $Configuration.administratorInputs.priorityUsersGroup
    $secOps = $Configuration.administratorInputs.securityOperationsMailbox

    $ruleTypes = @('EOP')
    if ($Entitlement.AtpPresets) { $ruleTypes += 'ATP' }

    foreach ($ruleType in $ruleTypes) {
        $getCommand = "Get-${ruleType}ProtectionPolicyRule"
        if (-not (& $getCommand -Identity 'Standard Preset Security Policy' -ErrorAction SilentlyContinue)) {
            throw 'Initialize the Standard and Strict preset policies once in the Defender portal before running this script.'
        }
    }

    Set-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -RecipientDomainIs $domain `
        -ExceptIfSentToMemberOf $priorityGroup -ExceptIfSentTo $secOps -WhatIf:$UseWhatIf
    Set-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -SentToMemberOf $priorityGroup `
        -WhatIf:$UseWhatIf
    Enable-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -WhatIf:$UseWhatIf
    Enable-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -WhatIf:$UseWhatIf
    Add-Outcome -Control 'MDO-001/MDO-002' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail 'EOP Standard and Strict preset assignment'

    if (-not $Entitlement.AtpPresets) {
        Add-Outcome -Control 'MDO-001/MDO-002 (ATP)' -Status 'NotEntitled' `
            -Detail "messagingTier is $($Entitlement.MessagingTier); Safe Links and Safe Attachments presets require Defender for Office 365"
        return
    }

    Set-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -RecipientDomainIs $domain `
        -ExceptIfSentToMemberOf $priorityGroup -ExceptIfSentTo $secOps -WhatIf:$UseWhatIf
    Set-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -SentToMemberOf $priorityGroup `
        -WhatIf:$UseWhatIf
    Enable-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -WhatIf:$UseWhatIf
    Enable-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -WhatIf:$UseWhatIf
    Set-ATPBuiltInProtectionRule -Identity 'ATP Built-In Protection Rule' `
        -ExceptIfRecipientDomainIs $null -ExceptIfSentTo $null -ExceptIfSentToMemberOf $null -WhatIf:$UseWhatIf
    Add-Outcome -Control 'MDO-001/MDO-002/MDO-003' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail 'ATP preset assignment and unexcluded Built-in protection'
}

function Set-OrganizationControls {
    param([object]$Configuration, [bool]$UseWhatIf, [object]$Entitlement)

    $state = $Configuration.desiredState
    $verb = if ($UseWhatIf) { 'Planned' } else { 'Applied' }

    Set-TransportConfig -SmtpClientAuthenticationDisabled $state.exchangeOnline.smtpClientAuthenticationDisabled `
        -ExternalPostmasterAddress $state.exchangeOnline.externalPostmasterAddress -WhatIf:$UseWhatIf
    Add-Outcome -Control 'EXO-002/EXO-005' -Status $verb -Detail 'SMTP AUTH disabled, external postmaster set'

    Set-HostedOutboundSpamFilterPolicy -Identity Default `
        -AutoForwardingMode $state.exchangeOnline.automaticExternalForwarding -WhatIf:$UseWhatIf
    Add-Outcome -Control 'EXO-004' -Status $verb -Detail 'Automatic external forwarding Off'

    Set-OrganizationConfig -AuditDisabled (-not $state.exchangeOnline.mailboxAuditingDefault) -WhatIf:$UseWhatIf
    Add-Outcome -Control 'EXO-006' -Status $verb -Detail 'Default mailbox auditing on'

    $externalId = $state.exchangeOnline.externalSenderIdentification
    Set-ExternalInOutlook -Enabled $externalId.enabled -AllowList $externalId.allowList -WhatIf:$UseWhatIf
    Add-Outcome -Control 'EXO-007' -Status $verb -Detail 'External sender identification enabled'

    $remote = $state.exchangeOnline.remoteDomainDefault
    Set-RemoteDomain -Identity Default -AutoForwardEnabled $remote.autoForwardEnabled `
        -AutoReplyEnabled $remote.autoReplyEnabled -AllowedOOFType $remote.allowedOOFType `
        -DeliveryReportEnabled $remote.deliveryReportEnabled -NDREnabled $remote.nonDeliveryReportEnabled `
        -WhatIf:$UseWhatIf
    Add-Outcome -Control 'EXO-008' -Status $verb -Detail 'Default remote domain hardened'

    $protocols = $state.exchangeOnline.protocolRestriction
    Set-OrganizationConfig -EwsEnabled $protocols.ewsEnabled -EwsAllowList $protocols.ewsAllowList -WhatIf:$UseWhatIf
    Get-CASMailboxPlan -ResultSize Unlimited | ForEach-Object {
        Set-CASMailboxPlan -Identity $_.Identity -PopEnabled $protocols.popEnabledByDefault `
            -ImapEnabled $protocols.imapEnabledByDefault -WhatIf:$UseWhatIf
    }
    Add-Outcome -Control 'EXO-009' -Status $verb -Detail 'EWS off, POP/IMAP off for new mailboxes'

    $quarantine = $state.defenderForOffice365.quarantinePolicies
    Set-QuarantinePolicy -Identity DefaultGlobalTag `
        -EndUserSpamNotificationFrequency (New-TimeSpan -Days $quarantine.endUserSpamNotificationFrequencyInDays) `
        -WhatIf:$UseWhatIf
    Add-Outcome -Control 'MDO-008' -Status $verb `
        -Detail 'Global quarantine notification cadence set; preset policies keep Microsoft-managed quarantine tags'

    if ($Entitlement.SafeAttachmentsSpo) {
        $atpParameters = @{
            EnableATPForSPOTeamsODB = $state.defenderForOffice365.safeAttachmentsForSharePointOneDriveTeams
            WhatIf                  = $UseWhatIf
        }
        if ($Entitlement.SafeDocuments) {
            $atpParameters.EnableSafeDocs = $state.defenderForOffice365.safeDocuments.enabled
            $atpParameters.AllowSafeDocsOpen = $state.defenderForOffice365.safeDocuments.allowBypass
        }
        Set-AtpPolicyForO365 @atpParameters
        Add-Outcome -Control 'MDO-004' -Status $verb -Detail 'Safe Attachments for SharePoint, OneDrive, and Teams'

        if (-not $Entitlement.SafeDocuments) {
            Add-Outcome -Control 'MDO-005' -Status 'NotEntitled' `
                -Detail "messagingTier is $($Entitlement.MessagingTier); Safe Documents requires Defender for Office 365 Plan 2 or the Defender suite"
        }
    }
    else {
        Add-Outcome -Control 'MDO-004/MDO-005' -Status 'NotEntitled' `
            -Detail "messagingTier is $($Entitlement.MessagingTier); file protection requires Defender for Office 365"
    }
}

function Set-DomainAuthentication {
    param([object]$Configuration, [bool]$UseWhatIf, [bool]$ActivateDkim)

    $domain = $Configuration.administratorInputs.primaryDomain
    if (-not (Get-DkimSigningConfig -Identity $domain -ErrorAction SilentlyContinue)) {
        New-DkimSigningConfig -DomainName $domain -Enabled $false -KeySize 2048 -WhatIf:$UseWhatIf
    }
    if ($ActivateDkim) {
        Set-DkimSigningConfig -Identity $domain -Enabled $true -WhatIf:$UseWhatIf
        Add-Outcome -Control 'AUTH-001' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) -Detail 'DKIM signing enabled'
    }
    else {
        Add-Outcome -Control 'AUTH-001' -Status 'Manual' `
            -Detail 'DKIM config staged disabled. Publish the exact CNAMEs from Get-DkimSigningConfig, then rerun with -EnableDkim'
    }
}

function Write-ManualControlPlan {
    param([object]$Configuration, [object]$Entitlement)

    Add-Outcome -Control 'EXO-003' -Status 'Manual' -Detail 'Block legacy authentication in Conditional Access (Microsoft Entra)'
    Add-Outcome -Control 'EXO-010' -Status 'Manual' -Detail 'Review role groups and remove standing privilege (Entra PIM)'
    Add-Outcome -Control 'EXO-011' -Status 'Manual' -Detail 'Publish MTA-STS policy, DNS record, and TLS-RPT record'
    Add-Outcome -Control 'AUTH-002/AUTH-003' -Status 'Manual' -Detail 'Publish SPF and DMARC records in authoritative DNS'
    Add-Outcome -Control 'MDO-006' -Status 'Manual' -Detail 'Configure user submission policy in the Defender portal'
    Add-Outcome -Control 'MON-001' -Status 'Manual' -Detail 'Connect Microsoft and vendor telemetry to the SIEM'

    if ($Entitlement.PurviewRetention) {
        Add-Outcome -Control 'GOV-002/GOV-003/GOV-004' -Status 'Manual' `
            -Detail 'Create DLP, retention, and litigation hold in Microsoft Purview (Security & Compliance PowerShell)'
    }
    else {
        Add-Outcome -Control 'GOV-002/GOV-003/GOV-004' -Status 'NotEntitled' `
            -Detail "complianceTier is $($Entitlement.ComplianceTier); DLP, retention, and hold require Microsoft 365 E3 or higher"
    }

    if ($Entitlement.AuditPremium) {
        Add-Outcome -Control 'GOV-001' -Status 'Manual' -Detail 'Set Audit (Premium) retention policy to the required period'
    }
    else {
        Add-Outcome -Control 'GOV-001' -Status 'NotEntitled' `
            -Detail "complianceTier is $($Entitlement.ComplianceTier); audit retention beyond the standard period requires E5 Compliance"
    }
}

$context = Get-BaselineContext -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath -SchemaPath $SchemaPath
$configuration = $context.Configuration
$entitlement = $context.Entitlement

if (-not $SkipConnection) {
    Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0
    Connect-ExchangeOnline -ShowBanner:$false
}

$useWhatIf = -not $Apply
$gatewayDeclared = $context.GatewayDeclared

Write-Host "Profile:       $($configuration.metadata.deploymentProfile)"
Write-Host "Gateway:       $(if ($gatewayDeclared) { $configuration.desiredState.mailFlow.gateway.vendor } else { 'none (Microsoft-native)' })"
Write-Host "Licensing:     messaging=$($entitlement.MessagingTier) compliance=$($entitlement.ComplianceTier)"
Write-Host "Configuration: $($context.Algorithm.ToLowerInvariant()):$($context.Hash)"
Write-Host "Mode:          $(if ($useWhatIf) { 'AUDIT / WHATIF' } else { 'APPLY' })"
Write-Host ''

if ($gatewayDeclared) {
    Set-InboundGatewayConnector -Configuration $configuration -UseWhatIf $useWhatIf
    Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $useWhatIf
}
else {
    Add-Outcome -Control 'PP-001/PP-002/PP-003' -Status 'Skipped' `
        -Detail 'No mail gateway declared; the tenant receives directly on its Microsoft 365 MX target'
}

Set-PresetProtection -Configuration $configuration -UseWhatIf $useWhatIf -Entitlement $entitlement
Set-OrganizationControls -Configuration $configuration -UseWhatIf $useWhatIf -Entitlement $entitlement
Set-DomainAuthentication -Configuration $configuration -UseWhatIf $useWhatIf -ActivateDkim $EnableDkim
Write-ManualControlPlan -Configuration $configuration -Entitlement $entitlement

Write-Host ''
$script:Outcomes | Group-Object Status | ForEach-Object { Write-Host "$($_.Name): $($_.Count)" }
Write-Host 'Configuration processing completed. Run Test-ExchangeOnlineBaseline.ps1 to collect evidence.'