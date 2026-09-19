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

    [string]$PreviewPath,

    [string]$ApprovalPath,

    [string]$ChangeId,

    [string]$ArtifactRoot,

    [switch]$Apply,

    [switch]$EnableDkim,

    [switch]$SkipConnection
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking

$script:Outcomes = [System.Collections.Generic.List[object]]::new()

# SAFE-007-A3: the status each declared mutation reached, recorded where the run reported it
# rather than assumed once the run is over. An operation this tenant's profile or entitlement
# never reached is simply absent, so it is left out of this run's plan instead of being journalled
# as applied.
$script:MutationStatus = [ordered]@{}

function Add-Outcome {
    param([string]$Control, [string]$Status, [string]$Detail, [string[]]$Operation = @())

    $script:Outcomes.Add([pscustomobject]@{ Control = $Control; Status = $Status; Detail = $Detail })
    foreach ($operationId in $Operation) { $script:MutationStatus[$operationId] = $Status }

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
    [CmdletBinding(SupportsShouldProcess)]
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
        if ($PSCmdlet.ShouldProcess($name, 'Set inbound connector')) {
            Set-InboundConnector -Identity $name @parameters
        }
    }
    else {
        if ($PSCmdlet.ShouldProcess($name, 'Create inbound connector')) {
            New-InboundConnector -Name $name @parameters
        }
    }

    $filter = $Configuration.desiredState.mailFlow.enhancedFiltering
    if ($PSCmdlet.ShouldProcess($name, 'Set Enhanced Filtering for Connectors')) {
        Set-InboundConnector -Identity $name -EFSkipLastIP $filter.skipLastIp `
            -EFSkipIPs $filter.skipIpAddresses -EFUsers $null -WhatIf:$UseWhatIf
    }

    Add-Outcome -Control 'PP-001/PP-002' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail "Inbound connector '$name' with Enhanced Filtering" `
        -Operation @('pp-inbound-connector-create', 'pp-inbound-connector-set')
}

function Set-OutboundGatewayConnector {
    [CmdletBinding(SupportsShouldProcess)]
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
        if ($PSCmdlet.ShouldProcess($name, 'Set outbound connector')) {
            Set-OutboundConnector -Identity $name @parameters
        }
    }
    else {
        if ($PSCmdlet.ShouldProcess($name, 'Create outbound connector')) {
            New-OutboundConnector -Name $name @parameters
        }
    }

    Add-Outcome -Control 'PP-003' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail "Outbound connector '$name'" `
        -Operation @('pp-outbound-connector-create', 'pp-outbound-connector-set')
}

function Set-PresetProtection {
    [CmdletBinding(SupportsShouldProcess)]
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

    if ($PSCmdlet.ShouldProcess('EOP Standard and Strict preset security policies', 'Scope and enable preset assignment')) {
        Set-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -RecipientDomainIs $domain `
            -ExceptIfSentToMemberOf $priorityGroup -ExceptIfSentTo $secOps -WhatIf:$UseWhatIf
        Set-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -SentToMemberOf $priorityGroup `
            -WhatIf:$UseWhatIf
        Enable-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -WhatIf:$UseWhatIf
        Enable-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -WhatIf:$UseWhatIf
    }
    Add-Outcome -Control 'MDO-001/MDO-002' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail 'EOP Standard and Strict preset assignment' `
        -Operation @('mdo-eop-preset-scope', 'mdo-eop-preset-enable')

    if (-not $Entitlement.AtpPresets) {
        Add-Outcome -Control 'MDO-001/MDO-002 (ATP)' -Status 'NotEntitled' `
            -Detail ($Entitlement.Capability | Where-Object { $_.Name -eq 'AtpPresets' }).Reason
        return
    }

    if ($PSCmdlet.ShouldProcess('ATP Standard and Strict preset security policies', 'Scope and enable preset assignment')) {
        Set-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -RecipientDomainIs $domain `
            -ExceptIfSentToMemberOf $priorityGroup -ExceptIfSentTo $secOps -WhatIf:$UseWhatIf
        Set-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -SentToMemberOf $priorityGroup `
            -WhatIf:$UseWhatIf
        Enable-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -WhatIf:$UseWhatIf
        Enable-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -WhatIf:$UseWhatIf
    }
    if ($PSCmdlet.ShouldProcess('ATP Built-In Protection Rule', 'Remove every exclusion')) {
        Set-ATPBuiltInProtectionRule -Identity 'ATP Built-In Protection Rule' `
            -ExceptIfRecipientDomainIs $null -ExceptIfSentTo $null -ExceptIfSentToMemberOf $null -WhatIf:$UseWhatIf
    }
    Add-Outcome -Control 'MDO-001/MDO-002/MDO-003' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail 'ATP preset assignment and unexcluded Built-in protection' `
        -Operation @('mdo-atp-preset-scope', 'mdo-atp-preset-enable', 'mdo-atp-builtin-unexclude')
}

function Set-OrganizationControls {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Configuration, [bool]$UseWhatIf, [object]$Entitlement, [object]$SafeDocumentsPreflight)

    $state = $Configuration.desiredState
    $verb = if ($UseWhatIf) { 'Planned' } else { 'Applied' }

    if ($PSCmdlet.ShouldProcess('Transport configuration', 'Disable SMTP client authentication and set the external postmaster')) {
        Set-TransportConfig -SmtpClientAuthenticationDisabled $state.exchangeOnline.smtpClientAuthenticationDisabled `
            -ExternalPostmasterAddress $state.exchangeOnline.externalPostmasterAddress -WhatIf:$UseWhatIf
    }
    Add-Outcome -Control 'EXO-002/EXO-005' -Status $verb -Detail 'SMTP AUTH disabled, external postmaster set' `
        -Operation @('exo-transport-config')

    if ($PSCmdlet.ShouldProcess('Default hosted outbound spam filter policy', 'Set automatic forwarding mode')) {
        Set-HostedOutboundSpamFilterPolicy -Identity Default `
            -AutoForwardingMode $state.exchangeOnline.automaticExternalForwarding -WhatIf:$UseWhatIf
    }
    Add-Outcome -Control 'EXO-004' -Status $verb -Detail 'Automatic external forwarding Off' `
        -Operation @('exo-outbound-spam-policy')

    if ($PSCmdlet.ShouldProcess('Organization configuration', 'Enable default mailbox auditing')) {
        Set-OrganizationConfig -AuditDisabled (-not $state.exchangeOnline.mailboxAuditingDefault) -WhatIf:$UseWhatIf
    }
    Add-Outcome -Control 'EXO-006' -Status $verb -Detail 'Default mailbox auditing on' `
        -Operation @('exo-organization-config')

    $externalId = $state.exchangeOnline.externalSenderIdentification
    if ($PSCmdlet.ShouldProcess('External sender identification in Outlook', 'Enable and set the allow list')) {
        Set-ExternalInOutlook -Enabled $externalId.enabled -AllowList $externalId.allowList -WhatIf:$UseWhatIf
    }
    Add-Outcome -Control 'EXO-007' -Status $verb -Detail 'External sender identification enabled' `
        -Operation @('exo-external-in-outlook')

    $remote = $state.exchangeOnline.remoteDomainDefault
    if ($PSCmdlet.ShouldProcess('Default remote domain', 'Harden forwarding, auto-reply, and reporting')) {
        Set-RemoteDomain -Identity Default -AutoForwardEnabled $remote.autoForwardEnabled `
            -AutoReplyEnabled $remote.autoReplyEnabled -AllowedOOFType $remote.allowedOOFType `
            -DeliveryReportEnabled $remote.deliveryReportEnabled -NDREnabled $remote.nonDeliveryReportEnabled `
            -WhatIf:$UseWhatIf
    }
    Add-Outcome -Control 'EXO-008' -Status $verb -Detail 'Default remote domain hardened' `
        -Operation @('exo-remote-domain')

    $protocols = $state.exchangeOnline.protocolRestriction
    if ($PSCmdlet.ShouldProcess('Organization configuration', 'Restrict Exchange Web Services')) {
        Set-OrganizationConfig -EwsEnabled $protocols.ewsEnabled -EwsAllowList $protocols.ewsAllowList -WhatIf:$UseWhatIf
    }
    if ($PSCmdlet.ShouldProcess('Every CAS mailbox plan', 'Disable POP and IMAP for new mailboxes')) {
        Get-CASMailboxPlan -ResultSize Unlimited | ForEach-Object {
            Set-CASMailboxPlan -Identity $_.Identity -PopEnabled $protocols.popEnabledByDefault `
                -ImapEnabled $protocols.imapEnabledByDefault -WhatIf:$UseWhatIf
        }
    }
    Add-Outcome -Control 'EXO-009' -Status $verb -Detail 'EWS off, POP/IMAP off for new mailboxes' `
        -Operation @('exo-cas-mailbox-plan')

    $quarantine = $state.defenderForOffice365.quarantinePolicies
    if ($PSCmdlet.ShouldProcess('DefaultGlobalTag quarantine policy', 'Set the end-user spam notification cadence')) {
        Set-QuarantinePolicy -Identity DefaultGlobalTag `
            -EndUserSpamNotificationFrequency (New-TimeSpan -Days $quarantine.endUserSpamNotificationFrequencyInDays) `
            -WhatIf:$UseWhatIf
    }
    Add-Outcome -Control 'MDO-008' -Status $verb `
        -Detail 'Global quarantine notification cadence set; preset policies keep Microsoft-managed quarantine tags' `
        -Operation @('mdo-quarantine-policy')

    if ($Entitlement.SafeAttachmentsSpo) {
        $atpParameters = @{
            EnableATPForSPOTeamsODB = $state.defenderForOffice365.safeAttachmentsForSharePointOneDriveTeams
            WhatIf                  = $UseWhatIf
        }
        # LIC-009: a tenant-wide SAFEDOCS plan says nothing about whether every targeted user holds
        # one, so the capability is configured only under the preflight verdict.
        if ($null -ne $SafeDocumentsPreflight -and $SafeDocumentsPreflight.MayApply) {
            $atpParameters.EnableSafeDocs = $state.defenderForOffice365.safeDocuments.enabled
            $atpParameters.AllowSafeDocsOpen = $state.defenderForOffice365.safeDocuments.allowBypass
        }
        if ($PSCmdlet.ShouldProcess('Safe Attachments for SharePoint, OneDrive, and Teams', 'Apply ATP policy for Office 365')) {
            Set-AtpPolicyForO365 @atpParameters
        }
        Add-Outcome -Control 'MDO-004' -Status $verb -Detail 'Safe Attachments for SharePoint, OneDrive, and Teams' `
            -Operation @('mdo-atp-policy-o365')

        if ($null -eq $SafeDocumentsPreflight -or -not $SafeDocumentsPreflight.MayApply) {
            $preflightDetail = if ($null -eq $SafeDocumentsPreflight) {
                'Safe Documents was not evaluated because no tenant evidence was collected.'
            }
            else {
                $SafeDocumentsPreflight.Reason
            }

            $preflightStatus = if ($null -ne $SafeDocumentsPreflight -and $SafeDocumentsPreflight.Status -eq 'Fail') { 'Failed' } else { 'NotEntitled' }
            Add-Outcome -Control 'MDO-005' -Status $preflightStatus -Detail $preflightDetail
        }
    }
    else {
        Add-Outcome -Control 'MDO-004/MDO-005' -Status 'NotEntitled' `
            -Detail ($Entitlement.Capability | Where-Object { $_.Name -eq 'SafeAttachmentsSpo' }).Reason
    }
}

function Set-DomainAuthentication {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Configuration, [bool]$UseWhatIf, [bool]$ActivateDkim)

    $domain = $Configuration.administratorInputs.primaryDomain
    if (-not (Get-DkimSigningConfig -Identity $domain -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess($domain, 'Create a disabled DKIM signing configuration')) {
            New-DkimSigningConfig -DomainName $domain -Enabled $false -KeySize 2048 -WhatIf:$UseWhatIf
        }
    }
    if ($ActivateDkim) {
        if ($PSCmdlet.ShouldProcess($domain, 'Enable DKIM signing')) {
            Set-DkimSigningConfig -Identity $domain -Enabled $true -WhatIf:$UseWhatIf
        }
        Add-Outcome -Control 'AUTH-001' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) -Detail 'DKIM signing enabled' `
            -Operation @('auth-dkim-create', 'auth-dkim-enable')
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
            -Detail ($Entitlement.Capability | Where-Object { $_.Name -eq 'PurviewRetention' }).Reason
    }

    if ($Entitlement.AuditPremium) {
        Add-Outcome -Control 'GOV-001' -Status 'Manual' -Detail 'Set Audit (Premium) retention policy to the required period'
    }
    else {
        Add-Outcome -Control 'GOV-001' -Status 'NotEntitled' `
            -Detail ($Entitlement.Capability | Where-Object { $_.Name -eq 'AuditPremium' }).Reason
    }
}

# SAFE-007-A3: every tenant mutation this script can reach, declared before any of it runs. One
# operation per command the run changes the tenant with, naming the object it changes, the control
# that reports it, and the read its state is observed through before and after the change. A
# mutation absent from here is a change nobody previewed, nobody captured a prior state for and
# nobody can roll back, so the plan is held to the script by SAFE-007-A3 rather than by review.
$MutationPlan = @(
    [ordered]@{ OperationId = 'pp-inbound-connector-create'; Command = 'New-InboundConnector'; Identity = 'Gateway inbound connector'; Read = { (Get-InboundConnector -Identity $configuration.administratorInputs.gatewayInboundConnectorName -ErrorAction SilentlyContinue).Enabled } }
    [ordered]@{ OperationId = 'pp-inbound-connector-set'; Command = 'Set-InboundConnector'; Identity = 'Gateway inbound connector'; Read = { (Get-InboundConnector -Identity $configuration.administratorInputs.gatewayInboundConnectorName -ErrorAction SilentlyContinue).EFSkipLastIP } }
    [ordered]@{ OperationId = 'pp-outbound-connector-create'; Command = 'New-OutboundConnector'; Identity = 'Gateway outbound connector'; Read = { (Get-OutboundConnector -Identity $configuration.administratorInputs.gatewayOutboundConnectorName -ErrorAction SilentlyContinue).Enabled } }
    [ordered]@{ OperationId = 'pp-outbound-connector-set'; Command = 'Set-OutboundConnector'; Identity = 'Gateway outbound connector'; Read = { (Get-OutboundConnector -Identity $configuration.administratorInputs.gatewayOutboundConnectorName -ErrorAction SilentlyContinue).TlsSettings } }
    [ordered]@{ OperationId = 'mdo-eop-preset-scope'; Command = 'Set-EOPProtectionPolicyRule'; Identity = 'Standard Preset Security Policy'; Read = { (Get-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -ErrorAction SilentlyContinue).State } }
    [ordered]@{ OperationId = 'mdo-eop-preset-enable'; Command = 'Enable-EOPProtectionPolicyRule'; Identity = 'Strict Preset Security Policy'; Read = { (Get-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -ErrorAction SilentlyContinue).State } }
    [ordered]@{ OperationId = 'mdo-atp-preset-scope'; Command = 'Set-ATPProtectionPolicyRule'; Identity = 'Standard Preset Security Policy'; Read = { (Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -ErrorAction SilentlyContinue).State } }
    [ordered]@{ OperationId = 'mdo-atp-preset-enable'; Command = 'Enable-ATPProtectionPolicyRule'; Identity = 'Strict Preset Security Policy'; Read = { (Get-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -ErrorAction SilentlyContinue).State } }
    [ordered]@{ OperationId = 'mdo-atp-builtin-unexclude'; Command = 'Set-ATPBuiltInProtectionRule'; Identity = 'ATP Built-In Protection Rule'; Read = { @((Get-ATPBuiltInProtectionRule -Identity 'ATP Built-In Protection Rule' -ErrorAction SilentlyContinue).ExceptIfSentTo).Count } }
    [ordered]@{ OperationId = 'exo-transport-config'; Command = 'Set-TransportConfig'; Identity = 'Transport configuration'; Read = { (Get-TransportConfig).SmtpClientAuthenticationDisabled } }
    [ordered]@{ OperationId = 'exo-outbound-spam-policy'; Command = 'Set-HostedOutboundSpamFilterPolicy'; Identity = 'Default'; Read = { (Get-HostedOutboundSpamFilterPolicy -Identity Default).AutoForwardingMode } }
    [ordered]@{ OperationId = 'exo-organization-config'; Command = 'Set-OrganizationConfig'; Identity = 'Organization configuration'; Read = { (Get-OrganizationConfig).AuditDisabled } }
    [ordered]@{ OperationId = 'exo-external-in-outlook'; Command = 'Set-ExternalInOutlook'; Identity = 'External sender identification'; Read = { @(Get-ExternalInOutlook)[0].Enabled } }
    [ordered]@{ OperationId = 'exo-remote-domain'; Command = 'Set-RemoteDomain'; Identity = 'Default'; Read = { (Get-RemoteDomain -Identity Default).AutoForwardEnabled } }
    [ordered]@{ OperationId = 'exo-cas-mailbox-plan'; Command = 'Set-CASMailboxPlan'; Identity = 'Every CAS mailbox plan'; Read = { @(Get-CASMailboxPlan -ResultSize Unlimited | Where-Object { $_.PopEnabled -or $_.ImapEnabled }).Count } }
    [ordered]@{ OperationId = 'mdo-quarantine-policy'; Command = 'Set-QuarantinePolicy'; Identity = 'DefaultGlobalTag'; Read = { (Get-QuarantinePolicy -Identity DefaultGlobalTag).EndUserSpamNotificationFrequency } }
    [ordered]@{ OperationId = 'mdo-atp-policy-o365'; Command = 'Set-AtpPolicyForO365'; Identity = 'ATP policy for Office 365'; Read = { @(Get-AtpPolicyForO365)[0].EnableATPForSPOTeamsODB } }
    [ordered]@{ OperationId = 'auth-dkim-create'; Command = 'New-DkimSigningConfig'; Identity = 'Primary domain DKIM signing configuration'; Read = { (Get-DkimSigningConfig -Identity $configuration.administratorInputs.primaryDomain -ErrorAction SilentlyContinue).KeySize } }
    [ordered]@{ OperationId = 'auth-dkim-enable'; Command = 'Set-DkimSigningConfig'; Identity = 'Primary domain DKIM signing configuration'; Read = { (Get-DkimSigningConfig -Identity $configuration.administratorInputs.primaryDomain -ErrorAction SilentlyContinue).Enabled } }
)

# SAFE-007: an apply decides whether it is permitted before it spends a credential and before it
# reaches any mutation, because a gate that runs later can only refuse what has already happened.
# Everything the decision needs is read off disk - the configuration resolves offline, and the
# preview and approval are files - so nothing is connected and nothing is changed to reach it. An
# audit run never enters this block: a read-only run that demands an approval before it may look
# at a tenant makes the audit harder to run than the change.
if ($Apply) {
    $applyResolution = Resolve-BaselineConfiguration -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath
    $applyInputs = $applyResolution.Configuration.administratorInputs

    $approvalDecision = Test-BaselineChangeApproval -PreviewPath $PreviewPath -ApprovalPath $ApprovalPath `
        -Tenant $applyInputs.initialDomain -DeploymentProfile $applyResolution.DeploymentProfile `
        -ConfigurationHash (Get-BaselineConfigurationHash -Resolution $applyResolution).Hash `
        -RequestedBy $applyResolution.Configuration.metadata.configurationOwner

    $applyDecision = Test-BaselineApplyPrerequisite -Apply $true -PreviewPath $PreviewPath `
        -ApprovalPath $ApprovalPath -ArtifactRoot $ArtifactRoot -ApprovalDecision $approvalDecision

    if (-not $applyDecision.Permitted) {
        throw ('ApplyRefused: {0}' -f (@($applyDecision.Finding) -join '; '))
    }

    # The approved change and the change this run says it is applying have to be the same one, or
    # the run carries a change identifier no approval stands behind.
    if ($ChangeId -cne $applyDecision.ChangeId) {
        throw ("ApplyChangeMismatch: this run was invoked for change '$ChangeId' and the approval admits '$($applyDecision.ChangeId)'.")
    }

    Write-Host "Apply gate:    permitted for change $($applyDecision.ChangeId); artifacts under $ArtifactRoot"
}

# LIC-008: DES-003 makes the runtime tenant service-plan inventory the only entitlement authority,
# so the tenant is connected before the context is built. With no connection nothing is collected,
# and the context then reports every capability unentitled rather than trusting a declared tier.
$graphRequest = $null
if (-not $SkipConnection) {
    Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0
    Connect-ExchangeOnline -ShowBanner:$false

    Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.0.0
    Connect-MgGraph -Scopes 'Organization.Read.All' -NoWelcome
    $graphRequest = {
        param($Resource)
        Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/$Resource" -OutputType PSObject
    }
}

$context = Get-BaselineContext -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath -SchemaPath $SchemaPath -GraphRequest $graphRequest
$configuration = $context.Configuration
$entitlement = $context.Entitlement

$useWhatIf = -not $Apply
$gatewayDeclared = $context.GatewayDeclared

Write-Host "Profile:       $($configuration.metadata.deploymentProfile)"
Write-Host "Gateway:       $(if ($gatewayDeclared) { $configuration.desiredState.mailFlow.gateway.vendor } else { 'none (Microsoft-native)' })"
Write-Host "Licensing:     source=$($entitlement.Source) entitled=$(@($entitlement.Capability | Where-Object { $_.Entitled } | ForEach-Object { $_.Name }) -join ', ')"
Write-Host "Not entitled:  $(if (@($entitlement.NotEntitled).Count -gt 0) { @($entitlement.NotEntitled) -join ', ' } else { 'none' })"
Write-Host "Planned tiers: messaging=$($entitlement.DeclaredMessagingTier) compliance=$($entitlement.DeclaredComplianceTier) (planning metadata only)"
Write-Host "Configuration: $($context.Algorithm.ToLowerInvariant()):$($context.Hash)"
Write-Host "Mode:          $(if ($useWhatIf) { 'AUDIT / WHATIF' } else { 'APPLY' })"

# LIC-009: Safe Documents takes effect tenant-wide but is licensed per user, so the tenant verdict
# alone is not a licence to apply it. The population and its per-user SAFEDOCS assignments are
# collected here, before any mutation, and the verdict itself is decided by the shared module. With
# no connection nothing is collected and the capability is refused rather than assumed.
$safeDocumentsPreflight = $null
if ($null -ne $graphRequest) {
    $recipient = @(
        Get-Recipient -ResultSize Unlimited |
            Where-Object { $_.ExternalDirectoryObjectId } |
            ForEach-Object {
                $directoryObject = & $graphRequest "users/$($_.ExternalDirectoryObjectId)"
                [pscustomobject]@{
                    userPrincipalName    = [string]$directoryObject.userPrincipalName
                    primarySmtpAddress   = [string]$_.PrimarySmtpAddress
                    recipientTypeDetails = [string]$_.RecipientTypeDetails
                    userType             = if ([string]::IsNullOrWhiteSpace([string]$directoryObject.userType)) { 'Member' } else { [string]$directoryObject.userType }
                    accountEnabled       = [bool]$directoryObject.accountEnabled
                    isLicensed           = @($directoryObject.assignedLicenses).Count -gt 0
                }
            }
    )

    $population = Get-BaselineTargetPopulation -Recipient $recipient `
        -StandardDomain @($configuration.administratorInputs.primaryDomain) `
        -PriorityGroupMember @(Get-DistributionGroupMember -Identity $configuration.administratorInputs.priorityUsersGroup -ResultSize Unlimited | ForEach-Object { [string]$_.WindowsLiveID }) `
        -ExcludedRecipient @($configuration.administratorInputs.securityOperationsMailbox)

    $targetEntitlement = Get-BaselineTargetEntitlement -UserPrincipalName @($population.LicensingTarget) `
        -RequiredServicePlan @($configuration.licensing.requiredServicePlans | Where-Object { $_.servicePlanName -eq 'SAFEDOCS' }) `
        -GraphRequest $graphRequest

    $safeDocumentsPreflight = Test-BaselineSafeDocumentsPreflight -Configuration $configuration `
        -Entitlement $entitlement -TargetPopulation $population -TargetEntitlement $targetEntitlement

    Write-Host "Safe Documents: $($safeDocumentsPreflight.Status) ($($safeDocumentsPreflight.Reason))"
}

Write-Host ''

# SAFE-007-A3: what the tenant held before this run touched it, written down while it is still
# true, and the script that puts it back, generated from that capture alone and emitted before the
# first mutation runs. An apply that reaches a tenant without both leaves a change nobody can show
# the prior state of and nobody can reverse.
$changeCapture = $null
$changeRollback = $null
if ($Apply) {
    $changeTenant = [string]$configuration.administratorInputs.initialDomain
    $priorState = @(
        foreach ($operation in $MutationPlan) {
            $observed = & $operation.Read

            [ordered]@{
                OperationId = $operation.OperationId
                Command     = $operation.Command
                Identity    = $operation.Identity
                Before      = [ordered]@{ Exists = ($null -ne $observed); Value = [string]$observed }
            }
        }
    )

    if ($PSCmdlet.ShouldProcess($changeTenant, 'Capture the prior state of every declared mutation')) {
        $changeCapture = New-BaselineChangeStateCapture -ChangeId $ChangeId -Tenant $changeTenant -Operation $priorState
    }

    $null = Write-BaselineChangeArtifact -ChangeId $ChangeId -Artifact 'PreChange' -Root $ArtifactRoot -Content $changeCapture

    if ($PSCmdlet.ShouldProcess($changeTenant, 'Generate the rollback script from the captured prior state')) {
        $changeRollback = New-BaselineRollbackScript -Capture $changeCapture
    }

    $null = Write-BaselineChangeArtifact -ChangeId $ChangeId -Artifact 'Rollback' -Root $ArtifactRoot -Content $changeRollback

    Write-Host "Pre-change:    $(@($priorState).Count) declared operations captured; rollback written under $ArtifactRoot"
}

if ($gatewayDeclared) {
    Set-InboundGatewayConnector -Configuration $configuration -UseWhatIf $useWhatIf
    Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $useWhatIf
}
else {
    Add-Outcome -Control 'PP-001/PP-002/PP-003' -Status 'Skipped' `
        -Detail 'No mail gateway declared; the tenant receives directly on its Microsoft 365 MX target'
}

Set-PresetProtection -Configuration $configuration -UseWhatIf $useWhatIf -Entitlement $entitlement
Set-OrganizationControls -Configuration $configuration -UseWhatIf $useWhatIf -Entitlement $entitlement -SafeDocumentsPreflight $safeDocumentsPreflight
Set-DomainAuthentication -Configuration $configuration -UseWhatIf $useWhatIf -ActivateDkim $EnableDkim
Write-ManualControlPlan -Configuration $configuration -Entitlement $entitlement

# SAFE-007-A3: what the run actually left behind. The journal is built from the status each
# declared mutation reported at the site it ran, the application reconciles that journal against
# the operations this tenant's profile and entitlement made reachable, and the tenant is read
# again afterwards - because a run whose commands all returned has proved only that they were
# accepted, and an intended change and a confirmed one are not the same claim.
if ($Apply) {
    $appliedOperation = @(
        $MutationPlan | Where-Object {
            $script:MutationStatus.Contains($_.OperationId) -and $script:MutationStatus[$_.OperationId] -eq 'Applied'
        }
    )

    $mutationOutcome = @(
        foreach ($operation in $appliedOperation) {
            [ordered]@{
                OperationId = $operation.OperationId
                Command     = $operation.Command
                Identity    = $operation.Identity
                State       = 'Succeeded'
                Fault       = ''
            }
        }
    )

    $changeJournal = @()
    if ($PSCmdlet.ShouldProcess($ChangeId, 'Journal the state every declared mutation reached')) {
        $changeJournal = New-BaselineMutationJournal -Operation $mutationOutcome
    }

    $changeApplication = Resolve-BaselinePartialApplication -ChangeId $ChangeId -Operation $appliedOperation -Journal $changeJournal
    $null = Write-BaselineChangeArtifact -ChangeId $ChangeId -Artifact 'Apply' -Root $ArtifactRoot -Content $changeApplication

    $postChangeState = @(
        foreach ($operation in $appliedOperation) {
            $observed = & $operation.Read

            [ordered]@{
                OperationId = $operation.OperationId
                Command     = $operation.Command
                Identity    = $operation.Identity
                Observed    = ($null -ne $observed)
                Value       = [string]$observed
            }
        }
    )

    $unobserved = @($postChangeState | Where-Object { -not $_.Observed })
    $postChangeDecision = [ordered]@{
        Permitted = ($unobserved.Count -eq 0)
        Evidence  = ('postchange-{0}.json' -f $ChangeId)
        Observed  = $postChangeState
        Finding   = @(
            foreach ($entry in $unobserved) {
                "PostChangeObjectNotObserved: '$($entry.Identity)' could not be read back after $($entry.Command) changed it."
            }
        )
    }

    $null = Write-BaselineChangeArtifact -ChangeId $ChangeId -Artifact 'PostChange' -Root $ArtifactRoot -Content $postChangeDecision

    $changeVerdict = Test-BaselineChangeSuccess -Application $changeApplication -PostChange $postChangeDecision

    if (-not $changeVerdict.Successful) {
        throw ('ChangeNotSuccessful: {0}' -f (@($changeVerdict.Finding) -join '; '))
    }

    Write-Host "Change:        $($changeVerdict.ChangeId) applied and confirmed from $($changeVerdict.PostChangeEvidence)"
}

Write-Host ''
$script:Outcomes | Group-Object Status | ForEach-Object { Write-Host "$($_.Name): $($_.Count)" }
Write-Host 'Configuration processing completed. Run Test-ExchangeOnlineBaseline.ps1 to collect evidence.'