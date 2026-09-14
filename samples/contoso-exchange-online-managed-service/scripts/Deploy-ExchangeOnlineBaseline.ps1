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

    [switch]$Apply,

    [switch]$EnableDkim,

    [switch]$SkipConnection
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-ResolvedConfiguration {
    param([string]$TemplatePath, [string]$ValuesPath)

    $template = Get-Content -Path $TemplatePath -Raw
    $values = Get-Content -Path $ValuesPath -Raw | ConvertFrom-Json -AsHashtable

    foreach ($entry in $values.GetEnumerator()) {
        $token = "__ADMIN_REQUIRED:$($entry.Key)__"
        $replacement = if ($entry.Value -is [array]) {
            ($entry.Value | ConvertTo-Json -Compress)
        }
        else {
            [string]$entry.Value
        }

        if ($entry.Value -is [array]) {
            $arrayPattern = '\[\s*"' + [regex]::Escape($token) + '"\s*\]'
            $template = [regex]::Replace($template, $arrayPattern, $replacement)
        }
        else {
            $template = $template.Replace($token, $replacement.Replace('\', '\\').Replace('"', '\"'))
        }
    }

    if ($template -match '__ADMIN_REQUIRED:[A-Z0-9_]+__') {
        $unresolved = [regex]::Matches($template, '__ADMIN_REQUIRED:[A-Z0-9_]+__').Value | Sort-Object -Unique
        throw "Unresolved administrator inputs: $($unresolved -join ', ')"
    }

    $template | ConvertFrom-Json
}

function Assert-Configuration {
    param([object]$Configuration)

    $state = $Configuration.desiredState
    if ($state.mailFlow.prohibitedBypass.sclMinusOneTransportRules) {
        throw 'SCL -1 bypass rules are prohibited when Enhanced Filtering is enabled.'
    }
    if (-not $state.mailFlow.enhancedFiltering.enabled) {
        throw 'Enhanced Filtering must be enabled for the Proofpoint inbound path.'
    }
    if (-not $state.exchangeOnline.smtpClientAuthenticationDisabled) {
        throw 'SMTP AUTH must be disabled at the organization level.'
    }
    if ($state.abnormalSecurity.integrationMode -ne 'Microsoft API post-delivery') {
        throw 'Abnormal Security must use API post-delivery integration, not SMTP routing.'
    }
}

function Set-InboundGatewayConnector {
    param([object]$Configuration, [bool]$UseWhatIf)

    $name = $Configuration.administratorInputs.proofpointInboundConnectorName
    $settings = $Configuration.desiredState.mailFlow.proofpointInboundConnector
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
}

function Set-OutboundGatewayConnector {
    param([object]$Configuration, [bool]$UseWhatIf)

    $name = $Configuration.administratorInputs.proofpointOutboundConnectorName
    $settings = $Configuration.desiredState.mailFlow.proofpointOutboundConnector
    $parameters = @{
        Enabled                       = $settings.enabled
        ConnectorType                 = $settings.connectorType
        RecipientDomains              = $settings.recipientDomains
        RouteAllMessagesViaOnPremises = $settings.routeAllMessagesViaOnPremises
        UseMXRecord                    = $settings.useMxRecord
        SmartHosts                     = $settings.smartHosts
        TlsSettings                    = $settings.tlsSettings
        TlsDomain                      = $settings.tlsDomain
        WhatIf                         = $UseWhatIf
    }

    if (Get-OutboundConnector -Identity $name -ErrorAction SilentlyContinue) {
        Set-OutboundConnector -Identity $name @parameters
    }
    else {
        New-OutboundConnector -Name $name @parameters
    }
}

function Set-PresetProtection {
    param([object]$Configuration, [bool]$UseWhatIf)

    $domain = $Configuration.administratorInputs.primaryDomain
    $priorityGroup = $Configuration.administratorInputs.priorityUsersGroup
    $secOps = $Configuration.administratorInputs.securityOperationsMailbox

    foreach ($ruleType in @('EOP', 'ATP')) {
        $getCommand = "Get-${ruleType}ProtectionPolicyRule"
        if (-not (& $getCommand -Identity 'Standard Preset Security Policy' -ErrorAction SilentlyContinue)) {
            throw 'Initialize the Standard and Strict preset policies once in the Defender portal before running this script.'
        }
    }

    Set-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -RecipientDomainIs $domain `
        -ExceptIfSentToMemberOf $priorityGroup -ExceptIfSentTo $secOps -WhatIf:$UseWhatIf
    Set-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -RecipientDomainIs $domain `
        -ExceptIfSentToMemberOf $priorityGroup -ExceptIfSentTo $secOps -WhatIf:$UseWhatIf
    Set-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -SentToMemberOf $priorityGroup `
        -WhatIf:$UseWhatIf
    Set-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -SentToMemberOf $priorityGroup `
        -WhatIf:$UseWhatIf

    Enable-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -WhatIf:$UseWhatIf
    Enable-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -WhatIf:$UseWhatIf
    Enable-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -WhatIf:$UseWhatIf
    Enable-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -WhatIf:$UseWhatIf
    Set-ATPBuiltInProtectionRule -Identity 'ATP Built-In Protection Rule' `
        -ExceptIfRecipientDomainIs $null -ExceptIfSentTo $null -ExceptIfSentToMemberOf $null -WhatIf:$UseWhatIf
}

function Set-OrganizationControls {
    param([object]$Configuration, [bool]$UseWhatIf)

    $state = $Configuration.desiredState
    Set-TransportConfig -SmtpClientAuthenticationDisabled $state.exchangeOnline.smtpClientAuthenticationDisabled `
        -ExternalPostmasterAddress $state.exchangeOnline.externalPostmasterAddress -WhatIf:$UseWhatIf
    Set-HostedOutboundSpamFilterPolicy -Identity Default `
        -AutoForwardingMode $state.exchangeOnline.automaticExternalForwarding -WhatIf:$UseWhatIf
    Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $state.defenderForOffice365.safeAttachmentsForSharePointOneDriveTeams `
        -EnableSafeDocs $state.defenderForOffice365.safeDocuments.enabled `
        -AllowSafeDocsOpen $state.defenderForOffice365.safeDocuments.allowBypass -WhatIf:$UseWhatIf
}

function Set-DomainAuthentication {
    param([object]$Configuration, [bool]$UseWhatIf, [bool]$ActivateDkim)

    $domain = $Configuration.administratorInputs.primaryDomain
    if (-not (Get-DkimSigningConfig -Identity $domain -ErrorAction SilentlyContinue)) {
        New-DkimSigningConfig -DomainName $domain -Enabled $false -KeySize 2048 -WhatIf:$UseWhatIf
    }
    if ($ActivateDkim) {
        Set-DkimSigningConfig -Identity $domain -Enabled $true -WhatIf:$UseWhatIf
    }
}

$configuration = ConvertTo-ResolvedConfiguration -TemplatePath $ConfigurationPath -ValuesPath $ParameterPath
Assert-Configuration -Configuration $configuration

if (-not $SkipConnection) {
    Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0
    Connect-ExchangeOnline -ShowBanner:$false
}

$useWhatIf = -not $Apply
Write-Host "Deployment mode: $(if ($useWhatIf) { 'AUDIT / WHATIF' } else { 'APPLY' })"
Set-InboundGatewayConnector -Configuration $configuration -UseWhatIf $useWhatIf
Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $useWhatIf
Set-PresetProtection -Configuration $configuration -UseWhatIf $useWhatIf
Set-OrganizationControls -Configuration $configuration -UseWhatIf $useWhatIf
Set-DomainAuthentication -Configuration $configuration -UseWhatIf $useWhatIf -ActivateDkim $EnableDkim

Write-Host 'Configuration processing completed. Run Test-ExchangeOnlineBaseline.ps1 to collect evidence.'