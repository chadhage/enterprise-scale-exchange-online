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

    [string]$ConfigurationPath = (Join-Path $PSScriptRoot '..\config\exchange-only.v1.json'),

    [switch]$AllowHistoricalProfile,

    [string]$SchemaPath = (Join-Path $PSScriptRoot '..\config\exchange-online-secure-baseline.schema.json'),

    [string]$PreviewPath,

    [string]$ApprovalPath,

    [string]$ChangeId,

    [string]$ArtifactRoot,

    [string]$AuthorizedSignerPath,

    [string]$RequestedBy,

    [switch]$Apply,

    [switch]$EnableDkim,

    [switch]$SkipConnection
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psm1') -DisableNameChecking

$selectedProfile = Get-BaselineDeploymentProfile -ConfigurationPath $ConfigurationPath -AllowHistoricalProfile:$AllowHistoricalProfile

if ($selectedProfile -ceq 'ExchangeOnly' -and $Apply) {
    if ($EnableDkim) { throw 'ChangeScopeUnsupported: use workflowOptions.enableDkim in the parameter JSON and obtain a new approved preview with scope Dkim; the historical -EnableDkim switch is not a signed workflow option.' }
    if ([string]::IsNullOrWhiteSpace($AuthorizedSignerPath)) {
        throw 'ApplyRefused: ChangeSigningPrerequisite: supply -AuthorizedSignerPath from RAID-D05 and follow docs/APPROVED-CHANGE.md; no historical fallback is permitted.'
    }
    $workflowArguments = @{
        Stage = 'Apply'; ParameterPath = $ParameterPath; ConfigurationPath = $ConfigurationPath
        ArtifactRoot = $ArtifactRoot; ChangeId = $ChangeId; RequestedBy = $RequestedBy; PreviewPath = $PreviewPath
        ApprovalPath = $ApprovalPath; AuthorizedSignerPath = $AuthorizedSignerPath; Apply = $true; WhatIf = $WhatIfPreference
    }
    if ($PSBoundParameters.ContainsKey('Confirm')) { $workflowArguments.Confirm = $PSBoundParameters.Confirm }
    Invoke-BaselineApprovedChange @workflowArguments
    return
}

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

    $current = Get-InboundConnector -Identity $name -ErrorAction SilentlyContinue
    $connectorMatches = $current -and
        $current.Enabled -eq $settings.enabled -and
        $current.ConnectorType -eq $settings.connectorType -and
        (@($current.SenderDomains) -join "`0") -ceq (@($settings.senderDomains) -join "`0") -and
        (@($current.SenderIPAddresses) -join "`0") -ceq (@($settings.senderIpAddresses) -join "`0") -and
        $current.RequireTls -eq $settings.requireTls -and
        $current.RestrictDomainsToIPAddresses -eq $settings.restrictDomainsToIpAddresses -and
        $current.RestrictDomainsToCertificate -eq $settings.restrictDomainsToCertificate

    if ($current) {
        if (-not $connectorMatches) {
            if ($PSCmdlet.ShouldProcess($name, 'Set inbound connector')) {
                Set-InboundConnector -Identity $name @parameters
            }
        }
    }
    else {
        if ($PSCmdlet.ShouldProcess($name, 'Create inbound connector')) {
            New-InboundConnector -Name $name @parameters
        }
    }

    $filter = $Configuration.desiredState.mailFlow.enhancedFiltering
    $filterMatches = $current -and
        $current.EFSkipLastIP -eq $filter.skipLastIp -and
        (@($current.EFSkipIPs) -join "`0") -ceq (@($filter.skipIpAddresses) -join "`0") -and
        @($current.EFUsers).Count -eq 0
    if (-not $filterMatches) {
        if ($PSCmdlet.ShouldProcess($name, 'Set Enhanced Filtering for Connectors')) {
            Set-InboundConnector -Identity $name -EFSkipLastIP $filter.skipLastIp `
                -EFSkipIPs $filter.skipIpAddresses -EFUsers $null -WhatIf:$UseWhatIf
        }
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

    $normalizeDomainSet = {
        param([object[]]$Value)

        return , @($Value | ForEach-Object { ([string]$_).Trim().TrimEnd('.').ToLowerInvariant() } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique | Sort-Object)
    }
    $normalizeDomain = { param([object]$Value) ([string]$Value).Trim().TrimEnd('.').ToLowerInvariant() }

    $current = Get-OutboundConnector -Identity $name -ErrorAction SilentlyContinue
    $connectorMatches = $current -and
        $current.Enabled -eq $settings.enabled -and
        $current.ConnectorType -eq $settings.connectorType -and
        ((& $normalizeDomainSet @($current.RecipientDomains)) -join "`0") -ceq ((& $normalizeDomainSet @($settings.recipientDomains)) -join "`0") -and
        $current.RouteAllMessagesViaOnPremises -eq $settings.routeAllMessagesViaOnPremises -and
        $current.UseMXRecord -eq $settings.useMxRecord -and
        ((& $normalizeDomainSet @($current.SmartHosts)) -join "`0") -ceq ((& $normalizeDomainSet @($settings.smartHosts)) -join "`0") -and
        $current.TlsSettings -eq $settings.tlsSettings -and
        (& $normalizeDomain $current.TlsDomain) -ceq (& $normalizeDomain $settings.tlsDomain)

    if ($current) {
        if (-not $connectorMatches) {
            if ($PSCmdlet.ShouldProcess($name, 'Set outbound connector')) {
                Set-OutboundConnector -Identity $name @parameters
            }
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

function Set-TrustedArcSealer {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Configuration, [bool]$UseWhatIf)

    $desired = @($Configuration.desiredState.emailAuthentication.trustedArcSealers)
    $current = Get-ArcConfig -Identity Default -ErrorAction Stop
    $observed = @($current.ArcTrustedSealers)
    if ((@($desired) -join "`0").ToLowerInvariant() -cne (@($observed) -join "`0").ToLowerInvariant()) {
        if ($PSCmdlet.ShouldProcess('Default ARC configuration', 'Set trusted ARC sealers')) {
            Set-ArcConfig -Identity Default -ArcTrustedSealers $desired -WhatIf:$UseWhatIf
        }
    }

    Add-Outcome -Control 'PP-004' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail "Trusted ARC sealers: $($desired -join ', ')" -Operation @('pp-trusted-arc-sealers')
}

function Set-PresetProtection {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Configuration, [bool]$UseWhatIf, [object]$Entitlement)

    $domain = $Configuration.administratorInputs.primaryDomain
    $priorityGroup = $Configuration.administratorInputs.priorityUsersGroup
    $secOps = $Configuration.administratorInputs.securityOperationsMailbox

    $standardRuleName = 'Standard Preset Security Policy'
    $strictRuleName = 'Strict Preset Security Policy'
    $eopStandard = Get-EOPProtectionPolicyRule -Identity $standardRuleName -ErrorAction SilentlyContinue
    $eopStrict = Get-EOPProtectionPolicyRule -Identity $strictRuleName -ErrorAction SilentlyContinue
    if (-not $eopStandard -or -not $eopStrict) {
        throw 'Initialize the Standard and Strict preset policies once in the Defender portal before running this script.'
    }

    $atpStandard = $null
    $atpStrict = $null
    $builtIn = $null
    if ($Entitlement.AtpPresets) {
        $atpStandard = Get-ATPProtectionPolicyRule -Identity $standardRuleName -ErrorAction SilentlyContinue
        $atpStrict = Get-ATPProtectionPolicyRule -Identity $strictRuleName -ErrorAction SilentlyContinue
        if (-not $atpStandard -or -not $atpStrict) {
            throw 'Initialize the Standard and Strict preset policies once in the Defender portal before running this script.'
        }
        $builtIn = Get-ATPBuiltInProtectionRule -Identity 'ATP Built-In Protection Rule' -ErrorAction Stop
    }

    $eopMatches = $eopStandard.State -eq 'Enabled' -and
        (@($eopStandard.RecipientDomainIs) -join "`0") -ceq $domain -and
        (@($eopStandard.ExceptIfSentToMemberOf) -join "`0") -ceq $priorityGroup -and
        (@($eopStandard.ExceptIfSentTo) -join "`0") -ceq $secOps -and
        $eopStrict.State -eq 'Enabled' -and
        (@($eopStrict.SentToMemberOf) -join "`0") -ceq $priorityGroup

    if (-not $eopMatches) {
        if ($PSCmdlet.ShouldProcess('EOP Standard and Strict preset security policies', 'Scope and enable preset assignment')) {
            Set-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -RecipientDomainIs $domain `
                -ExceptIfSentToMemberOf $priorityGroup -ExceptIfSentTo $secOps -WhatIf:$UseWhatIf
            Set-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -SentToMemberOf $priorityGroup `
                -WhatIf:$UseWhatIf
            Enable-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -WhatIf:$UseWhatIf
            Enable-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -WhatIf:$UseWhatIf
        }
    }
    Add-Outcome -Control 'MDO-001/MDO-002' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail 'EOP Standard and Strict preset assignment' `
        -Operation @('mdo-eop-preset-scope', 'mdo-eop-preset-enable')

    if (-not $Entitlement.AtpPresets) {
        Add-Outcome -Control 'MDO-001/MDO-002 (ATP)' -Status 'NotEntitled' `
            -Detail ($Entitlement.Capability | Where-Object { $_.Name -eq 'AtpPresets' }).Reason
        return
    }

    $atpMatches = $atpStandard.State -eq 'Enabled' -and
        (@($atpStandard.RecipientDomainIs) -join "`0") -ceq $domain -and
        (@($atpStandard.ExceptIfSentToMemberOf) -join "`0") -ceq $priorityGroup -and
        (@($atpStandard.ExceptIfSentTo) -join "`0") -ceq $secOps -and
        $atpStrict.State -eq 'Enabled' -and
        (@($atpStrict.SentToMemberOf) -join "`0") -ceq $priorityGroup
    if (-not $atpMatches) {
        if ($PSCmdlet.ShouldProcess('ATP Standard and Strict preset security policies', 'Scope and enable preset assignment')) {
            Set-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -RecipientDomainIs $domain `
                -ExceptIfSentToMemberOf $priorityGroup -ExceptIfSentTo $secOps -WhatIf:$UseWhatIf
            Set-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -SentToMemberOf $priorityGroup `
                -WhatIf:$UseWhatIf
            Enable-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -WhatIf:$UseWhatIf
            Enable-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -WhatIf:$UseWhatIf
        }
    }
    $builtInMatches = @($builtIn.ExceptIfRecipientDomainIs).Count -eq 0 -and
        @($builtIn.ExceptIfSentTo).Count -eq 0 -and
        @($builtIn.ExceptIfSentToMemberOf).Count -eq 0
    if (-not $builtInMatches) {
        if ($PSCmdlet.ShouldProcess('ATP Built-In Protection Rule', 'Remove every exclusion')) {
            Set-ATPBuiltInProtectionRule -Identity 'ATP Built-In Protection Rule' `
                -ExceptIfRecipientDomainIs $null -ExceptIfSentTo $null -ExceptIfSentToMemberOf $null -WhatIf:$UseWhatIf
        }
    }
    Add-Outcome -Control 'MDO-001/MDO-002/MDO-003' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail 'ATP preset assignment and unexcluded Built-in protection' `
        -Operation @('mdo-atp-preset-scope', 'mdo-atp-preset-enable', 'mdo-atp-builtin-unexclude')
}

function Set-BaselineAcceptedDomainState {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Configuration, [bool]$UseWhatIf)

    $desiredDomain = @($Configuration.desiredState.acceptedDomain)
    $currentDomain = @(Get-AcceptedDomain -ResultSize Unlimited -ErrorAction Stop)
    $operation = [System.Collections.Generic.List[string]]::new()

    foreach ($desired in $desiredDomain) {
        $domainName = [string]$desired.domainName
        $domainType = [string]$desired.domainType
        $current = @($currentDomain | Where-Object {
                ([string]$_.DomainName).Trim() -ieq $domainName.Trim()
            }) | Select-Object -First 1

        if ($null -eq $current) {
            if ($PSCmdlet.ShouldProcess($domainName, "Create accepted domain as $domainType")) {
                New-AcceptedDomain -Name $domainName -DomainName $domainName -DomainType $domainType -WhatIf:$UseWhatIf
                $operation.Add('exo-accepted-domain-create')
            }
        }
        elseif ([string]$current.DomainType -cne $domainType) {
            if ($PSCmdlet.ShouldProcess($domainName, "Set accepted-domain type to $domainType")) {
                Set-AcceptedDomain -Identity $domainName -DomainType $domainType -WhatIf:$UseWhatIf
                $operation.Add('exo-accepted-domain-set')
            }
        }
    }

    Add-Outcome -Control 'EXO-001' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail 'Accepted domains match the resolved desired type' -Operation @($operation)
}

function Set-BaselineExistingMailboxProtocolState {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Configuration, [bool]$UseWhatIf)

    $protocols = $Configuration.desiredState.exchangeOnline.protocolRestriction
    $mailbox = @(Get-CASMailbox -ResultSize Unlimited -ErrorAction Stop)
    $operation = [System.Collections.Generic.List[string]]::new()

    foreach ($current in $mailbox) {
        if ($current.PopEnabled -eq $protocols.popEnabledByDefault -and
            $current.ImapEnabled -eq $protocols.imapEnabledByDefault) {
            continue
        }

        $identity = [string]$current.Identity
        if ($PSCmdlet.ShouldProcess($identity, 'Set existing-mailbox POP and IMAP state')) {
            Set-CASMailbox -Identity $identity -PopEnabled $protocols.popEnabledByDefault `
                -ImapEnabled $protocols.imapEnabledByDefault -WhatIf:$UseWhatIf
            $operation.Add('exo-existing-mailbox-protocol')
        }
    }

    Add-Outcome -Control 'EXO-009' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail 'POP and IMAP match resolved desired state on every existing mailbox' `
        -Operation @($operation | Select-Object -Unique)
}

function Set-BaselineForwardingState {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string[]]$AcceptedDomain,
        [Parameter(Mandatory)][bool]$UseWhatIf,
        [scriptblock]$PageCollection = {
            param($ContinuationToken)
            if ($null -ne $ContinuationToken) {
                throw "MailboxContinuationUnsupported: Get-Mailbox returned unexpected continuation '$ContinuationToken'."
            }
            [pscustomobject]@{
                Mailbox = @(Get-Mailbox -ResultSize Unlimited |
                        Select-Object Identity, PrimarySmtpAddress, ForwardingAddress, ForwardingSmtpAddress)
                ContinuationToken = $null
            }
        },
        [scriptblock]$InboxRuleCollection = {
            param($Mailbox, $TimeoutSecond)
            try {
                $rule = @(Get-InboxRule -Mailbox $Mailbox.Identity -IncludeHidden -ErrorAction Stop |
                        Select-Object Identity, Enabled, ForwardTo, ForwardAsAttachmentTo, RedirectTo, SendTextMessageNotificationTo)
                [pscustomobject]@{ Status = 'Success'; Complete = $true; Rules = $rule }
            }
            catch {
                $reason = $_.Exception.Message
                if ($reason -match '(?i)throttl|server busy|too many requests') {
                    return [pscustomobject]@{ Status = 'Throttled'; Complete = $false; Rules = @(); RetryAfterSecond = 1; Reason = $reason }
                }
                if ($reason -match '(?i)timeout|timed out|expired') {
                    return [pscustomobject]@{ Status = 'TimedOut'; Complete = $false; Rules = @(); Reason = $reason }
                }
                if ($reason -match '(?i)access denied|inaccessible|not authorized|permission') {
                    return [pscustomobject]@{ Status = 'Inaccessible'; Complete = $false; Rules = @(); Reason = $reason }
                }
                if ($reason -match '(?i)ambiguous|multiple recipients') {
                    return [pscustomobject]@{ Status = 'Ambiguous'; Complete = $false; Rules = @(); Reason = $reason }
                }
                throw
            }
        },
        [scriptblock]$Wait = { param($Second) Start-Sleep -Seconds $Second },
        [scriptblock]$Clock = { [datetimeoffset]::UtcNow }
    )

    $accepted = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($domain in @($AcceptedDomain)) {
        $normalizedDomain = ([string]$domain).Trim().TrimEnd('.')
        if (-not [string]::IsNullOrWhiteSpace($normalizedDomain)) { $null = $accepted.Add($normalizedDomain) }
    }
    if ($accepted.Count -eq 0) { throw 'AcceptedDomainRequired: forwarding enforcement requires the complete accepted-domain set.' }

    $completeMailbox = Get-BaselineCompleteMailboxCollection -PageCollection $PageCollection
    $mailboxRules = [System.Collections.Generic.List[object]]::new()
    foreach ($mailbox in @($completeMailbox.Mailbox)) {
        $identity = [string]$mailbox.PrimarySmtpAddress
        if ([string]::IsNullOrWhiteSpace($identity)) { $identity = [string]$mailbox.Identity }
        $rules = @(Get-BaselineMailboxInboxRuleCollection -Mailbox @($mailbox) `
                -Collection $InboxRuleCollection -Wait $Wait -Clock $Clock)
        $mailboxRules.Add([pscustomobject]@{ Mailbox = $identity.Trim(); Rule = $rules })
    }

    $getAddress = {
        param([object]$Recipient)

        $address = if ($Recipient -is [string]) { [string]$Recipient } else {
            $candidate = @('Address', 'PrimarySmtpAddress', 'WindowsEmailAddress', 'ExternalEmailAddress') |
                ForEach-Object { $Recipient.PSObject.Properties[$_] } |
                Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_.Value) } |
                Select-Object -First 1
            if ($null -eq $candidate) { [string]$Recipient } else { [string]$candidate.Value }
        }
        $address = $address.Trim()
        if ($address -match '<([^<>]+)>') { $address = $Matches[1] }
        return ($address -replace '^(?i)smtp:', '').Trim()
    }

    foreach ($mailbox in @($completeMailbox.Mailbox)) {
        $identity = [string]$mailbox.PrimarySmtpAddress
        if ([string]::IsNullOrWhiteSpace($identity)) { $identity = [string]$mailbox.Identity }
        $hasForwarding = -not [string]::IsNullOrWhiteSpace([string]$mailbox.ForwardingAddress) -or
            -not [string]::IsNullOrWhiteSpace([string]$mailbox.ForwardingSmtpAddress)
        if ($hasForwarding) {
            if ($PSCmdlet.ShouldProcess($identity, 'Remove mailbox forwarding')) {
                Set-Mailbox -Identity $identity -ForwardingAddress $null -ForwardingSmtpAddress $null -WhatIf:$UseWhatIf
            }
        }
    }

    foreach ($entry in $mailboxRules) {
        foreach ($rule in @($entry.Rule)) {
            if (-not [bool]$rule.Enabled) { continue }

            $external = $false
            foreach ($action in @('ForwardTo', 'ForwardAsAttachmentTo', 'RedirectTo')) {
                foreach ($recipient in @($rule.$action)) {
                    $address = & $getAddress $recipient
                    $separator = $address.LastIndexOf('@')
                    if ($separator -lt 0 -or $separator -eq ($address.Length - 1)) { continue }
                    $domain = $address.Substring($separator + 1).Trim().TrimEnd('.')
                    if (-not $accepted.Contains($domain)) { $external = $true; break }
                }
                if ($external) { break }
            }

            if ($external) {
                if ($PSCmdlet.ShouldProcess("$($entry.Mailbox):$($rule.Identity)", 'Disable external forwarding inbox rule')) {
                    Disable-InboxRule -Mailbox $entry.Mailbox -Identity $rule.Identity -Confirm:$false -WhatIf:$UseWhatIf
                }
            }
        }
    }
}

function Set-BaselineAddInAcquisitionState {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Configuration, [bool]$UseWhatIf)

    $desired = [bool]$Configuration.desiredState.exchangeOnline.protocolRestriction.outlookAddInsForUsers
    $policy = @(Get-RoleAssignmentPolicy -ErrorAction Stop)
    $defaultPolicy = @($policy | Where-Object { $_.IsDefault })
    if ($defaultPolicy.Count -ne 1) {
        throw "DefaultRoleAssignmentPolicyNotUnique: expected one default role assignment policy, observed $($defaultPolicy.Count)."
    }

    $forbiddenRole = @('My Custom Apps', 'My Marketplace Apps', 'My ReadWriteMailboxApps')
    $assignment = @(Get-ManagementRoleAssignment -ErrorAction Stop)
    if (-not $desired) {
        foreach ($entry in $assignment) {
            if ([string]$entry.RoleAssignee -ine [string]$defaultPolicy[0].Identity -or
                $forbiddenRole -inotcontains [string]$entry.Role) {
                continue
            }

            if ($PSCmdlet.ShouldProcess([string]$entry.Name, 'Remove default-policy add-in acquisition grant')) {
                Remove-ManagementRoleAssignment -Identity $entry.Name -Confirm:$false -WhatIf:$UseWhatIf
            }
        }
    }

    Add-Outcome -Control 'EXO-012' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail 'Default role assignment policy add-in acquisition grants match resolved state' `
        -Operation @('exo-addin-acquisition-remove')
}

function Set-BaselineReportSubmissionState {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Configuration, [bool]$UseWhatIf)

    $desired = $Configuration.desiredState.defenderForOffice365.userSubmissions
    $identity = 'DefaultReportSubmissionPolicy'
    $destination = switch ([string]$desired.reportingDestination) {
        'MicrosoftOnly' { [ordered]@{ Microsoft = $true; Custom = $false }; break }
        'CustomMailboxOnly' { [ordered]@{ Microsoft = $false; Custom = $true }; break }
        'MicrosoftAndCustomMailbox' { [ordered]@{ Microsoft = $true; Custom = $true }; break }
        default { throw "ReportSubmissionDestinationNotSupported: '$($desired.reportingDestination)' is not declared." }
    }
    $reportButton = -not [bool]$desired.microsoftReportMessageButton
    $mailbox = if ($destination.Custom) { @([string]$desired.reportingMailbox) } else { @() }
    $parameters = @{
        EnableThirdPartyAddress = $reportButton
        EnableReportToMicrosoft = $destination.Microsoft
        ReportJunkToCustomizedAddress = $destination.Custom
        ReportNotJunkToCustomizedAddress = $destination.Custom
        ReportPhishToCustomizedAddress = $destination.Custom
        ReportJunkAddresses = $mailbox
        WhatIf = $UseWhatIf
    }
    $normalize = {
        param([object[]]$Value)
        @($Value | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) -join "`0"
    }
    $current = Get-ReportSubmissionPolicy -Identity $identity -ErrorAction SilentlyContinue
    $stateMatches = $current -and
        [bool]$current.EnableThirdPartyAddress -eq $reportButton -and
        [bool]$current.EnableReportToMicrosoft -eq $destination.Microsoft -and
        [bool]$current.ReportJunkToCustomizedAddress -eq $destination.Custom -and
        [bool]$current.ReportNotJunkToCustomizedAddress -eq $destination.Custom -and
        [bool]$current.ReportPhishToCustomizedAddress -eq $destination.Custom -and
        (& $normalize @($current.ReportJunkAddresses)) -ceq (& $normalize $mailbox)

    $operation = @()
    if (-not $current) {
        if ($PSCmdlet.ShouldProcess($identity, 'Create report-submission policy')) {
            New-ReportSubmissionPolicy -Name $identity @parameters
            $operation = @('mdo-report-submission-create')
        }
    }
    elseif (-not $stateMatches) {
        if ($PSCmdlet.ShouldProcess($identity, 'Set exact report destination and reporting mailbox')) {
            Set-ReportSubmissionPolicy -Identity $identity @parameters
            $operation = @('mdo-report-submission-set')
        }
    }

    Add-Outcome -Control 'MDO-006' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail 'Report destination and reporting mailbox match resolved desired state' -Operation $operation
}

function Set-BaselineSecOpsOverrideState {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Configuration, [bool]$UseWhatIf)

    $identity = 'SecOpsOverridePolicy'
    $desired = @($Configuration.desiredState.defenderForOffice365.advancedDelivery.secOpsMailbox)
    $normalize = {
        param([object[]]$Value)
        @($Value | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) -join "`0"
    }
    $current = Get-SecOpsOverridePolicy -Identity $identity -ErrorAction SilentlyContinue
    $stateMatches = $current -and [string]$current.Mode -ieq 'Enforce' -and
        (& $normalize @($current.SentTo)) -ceq (& $normalize $desired)

    $operation = @()
    if (-not $current) {
        if ($PSCmdlet.ShouldProcess($identity, 'Create Advanced Delivery SecOps registration')) {
            New-SecOpsOverridePolicy -Name $identity -SentTo $desired -Mode Enforce -WhatIf:$UseWhatIf
            $operation = @('mdo-secops-override-create')
        }
    }
    elseif (-not $stateMatches) {
        if ($PSCmdlet.ShouldProcess($identity, 'Set exact Advanced Delivery SecOps registration')) {
            Set-SecOpsOverridePolicy -Identity $identity -SentTo $desired -Mode Enforce -WhatIf:$UseWhatIf
            $operation = @('mdo-secops-override-set')
        }
    }

    Add-Outcome -Control 'MDO-006' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail 'Advanced Delivery registers exactly the administrator-resolved SecOps mailboxes' -Operation $operation
}

function Set-BaselineTenantAllowBlockListState {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [object]$Configuration,
        [AllowEmptyCollection()][object[]]$DesiredEntry = @(),
        [bool]$UseWhatIf
    )

    $contract = $Configuration.desiredState.defenderForOffice365.tenantAllowBlockList
    $supportedType = @('Sender', 'Domain', 'Url', 'File')
    $currentEntry = @(Get-TenantAllowBlockListItems -ErrorAction Stop)
    $operation = [System.Collections.Generic.List[string]]::new()

    foreach ($desired in @($DesiredEntry)) {
        $type = [string]$desired.entryType
        $value = [string]$desired.entryValue
        $action = [string]$desired.action
        if ($supportedType -inotcontains $type) {
            throw "TenantAllowBlockListEntryTypeNotSupported: '$type' is not Sender, Domain, Url or File."
        }
        if (@('Allow', 'Block') -inotcontains $action) {
            throw "TenantAllowBlockListActionNotSupported: '$action' is not Allow or Block."
        }
        foreach ($field in @($contract.requiredEntryFields)) {
            $property = $desired.PSObject.Properties[[string]$field]
            if ($null -eq $property -or $null -eq $property.Value -or
                ($property.Value -is [string] -and [string]::IsNullOrWhiteSpace([string]$property.Value))) {
                throw "TenantAllowBlockListGovernanceRequired: '$type/$value' has no '$field'."
            }
        }

        $created = [datetimeoffset]$desired.createdDateTime
        $expires = [datetimeoffset]$desired.expirationDateTime
        $duration = ($expires - $created).TotalDays
        if ($action -ieq 'Allow' -and ($duration -le 0 -or $duration -gt [int]$contract.allowEntryMaximumDurationDays)) {
            throw "TenantAllowBlockListAllowDurationInvalid: '$type/$value' lasts $duration days; the maximum is $($contract.allowEntryMaximumDurationDays)."
        }
        if ($action -ieq 'Block' -and $duration -ne [int]$contract.blockEntryRetentionDays) {
            throw "TenantAllowBlockListBlockRetentionInvalid: '$type/$value' lasts $duration days; the separate block retention is $($contract.blockEntryRetentionDays)."
        }

        $current = @($currentEntry | Where-Object {
                [string]$_.entryType -ieq $type -and [string]$_.entryValue -ieq $value -and [string]$_.action -ieq $action
            }) | Select-Object -First 1
        $entryMatches = $current -and
            [string]$current.owner -ceq [string]$desired.owner -and
            [string]$current.ticket -ceq [string]$desired.ticket -and
            ([datetimeoffset]$current.createdDateTime).ToString('o') -ceq $created.ToString('o') -and
            ([datetimeoffset]$current.expirationDateTime).ToString('o') -ceq $expires.ToString('o') -and
            [string]$current.justification -ceq [string]$desired.justification
        if ($entryMatches) { continue }

        if ($current) {
            if ($PSCmdlet.ShouldProcess([string]$current.Identity, "Remove drifted $type $action entry")) {
                Remove-TenantAllowBlockListItems -Identity $current.Identity -ListType $type -Confirm:$false -WhatIf:$UseWhatIf
                $operation.Add('mdo-tabl-remove')
                if ($PSCmdlet.ShouldProcess("$type/$value", "Create exact governed $action entry")) {
                    $notes = 'Owner={0}; Ticket={1}; Created={2}; Justification={3}' -f `
                        $desired.owner, $desired.ticket, $created.ToString('o'), $desired.justification
                    New-TenantAllowBlockListItems -ListType $type -Entries @($value) `
                        -Allow:($action -ieq 'Allow') -Block:($action -ieq 'Block') `
                        -ExpirationDate $expires -Notes $notes -WhatIf:$UseWhatIf
                    $operation.Add('mdo-tabl-create')
                }
            }
            continue
        }
        if ($PSCmdlet.ShouldProcess("$type/$value", "Create exact governed $action entry")) {
            $notes = 'Owner={0}; Ticket={1}; Created={2}; Justification={3}' -f `
                $desired.owner, $desired.ticket, $created.ToString('o'), $desired.justification
            New-TenantAllowBlockListItems -ListType $type -Entries @($value) `
                -Allow:($action -ieq 'Allow') -Block:($action -ieq 'Block') `
                -ExpirationDate $expires -Notes $notes -WhatIf:$UseWhatIf
            $operation.Add('mdo-tabl-create')
        }
    }

    Add-Outcome -Control 'MDO-007' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail 'TABL entries are exactly typed, governed and bounded by action-specific windows' `
        -Operation @($operation | Select-Object -Unique)
}

function Set-BaselineImpersonationProtectionState {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Configuration, [bool]$UseWhatIf)

    $policyName = 'Contoso Impersonation Protection'
    $settings = $Configuration.desiredState.defenderForOffice365.impersonationProtection
    $trustedSender = @($settings.approvedExceptions | Where-Object { $_.exceptionType -ceq 'TrustedSender' } | ForEach-Object { [string]$_.value })
    $trustedDomain = @($settings.approvedExceptions | Where-Object { $_.exceptionType -ceq 'TrustedDomain' } | ForEach-Object { [string]$_.value })
    $parameters = @{
        EnableTargetedUserProtection    = [bool]$settings.enabled
        EnableTargetedDomainsProtection = [bool]$settings.enabled
        TargetedUsersToProtect          = @($settings.protectedUsers)
        TargetedDomainsToProtect        = @($settings.protectedDomains)
        ExcludedSenders                 = $trustedSender
        ExcludedDomains                 = $trustedDomain
        WhatIf                          = $UseWhatIf
    }

    $current = Get-AntiPhishPolicy -Identity $policyName -ErrorAction SilentlyContinue
    $same = {
        param([AllowNull()][object]$Actual, [AllowNull()][object]$Desired)
        return (@($Actual) -join "`0") -ceq (@($Desired) -join "`0")
    }
    $policyIsCurrent = $current -and
        $current.EnableTargetedUserProtection -eq $parameters.EnableTargetedUserProtection -and
        $current.EnableTargetedDomainsProtection -eq $parameters.EnableTargetedDomainsProtection -and
        (& $same $current.TargetedUsersToProtect $parameters.TargetedUsersToProtect) -and
        (& $same $current.TargetedDomainsToProtect $parameters.TargetedDomainsToProtect) -and
        (& $same $current.ExcludedSenders $parameters.ExcludedSenders) -and
        (& $same $current.ExcludedDomains $parameters.ExcludedDomains)

    $operation = @()
    if ($null -eq $current) {
        if ($PSCmdlet.ShouldProcess($policyName, 'Create anti-phish impersonation-protection policy')) {
            New-AntiPhishPolicy -Name $policyName @parameters
            $operation = @('mdo-impersonation-policy-create')
        }
    }
    elseif (-not $policyIsCurrent) {
        if ($PSCmdlet.ShouldProcess($policyName, 'Set anti-phish impersonation-protection policy')) {
            Set-AntiPhishPolicy -Identity $policyName @parameters
            $operation = @('mdo-impersonation-policy-set')
        }
    }

    Add-Outcome -Control 'MDO-009' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail 'Anti-phish protected identities, protected domains and approved exceptions match resolved state' `
        -Operation $operation
}

function Set-BaselineQuarantineState {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Configuration, [bool]$UseWhatIf)

    $desired = $Configuration.desiredState.defenderForOffice365.quarantinePolicies
    $permissionValue = [ordered]@{ AdminOnlyAccess = 0; LimitedAccess = 106; FullAccess = 236 }
    $policyName = [ordered]@{
        AdminOnlyAccess = 'Baseline-AdminOnlyAccess'
        LimitedAccess = 'Baseline-LimitedAccess'
        FullAccess = 'Baseline-FullAccess'
    }
    $categoryMember = [ordered]@{
        HighConfidencePhish = 'HighConfidencePhishQuarantineTag'
        Phish = 'PhishQuarantineTag'
        HighConfidenceSpam = 'HighConfidenceSpamQuarantineTag'
        Spam = 'SpamQuarantineTag'
        Bulk = 'BulkQuarantineTag'
        SpoofIntelligence = 'SpoofQuarantineTag'
    }

    $category = [ordered]@{}
    foreach ($entry in @($desired.categoryPermissions)) {
        $category[[string]$entry.category] = [string]$entry.accessLevel
    }

    $currentPolicy = @(Get-QuarantinePolicy -ErrorAction Stop)
    $operation = [System.Collections.Generic.List[string]]::new()
    foreach ($accessLevel in @($category.Values | Select-Object -Unique)) {
        if ($accessLevel -cnotin @($permissionValue.Keys)) {
            throw "QuarantineAccessLevelUnknown: '$accessLevel' has no exact Exchange Online permission value."
        }

        $name = $policyName[$accessLevel]
        $current = @($currentPolicy | Where-Object { [string]$_.Name -ieq $name }) | Select-Object -First 1
        if ($null -eq $current) {
            if ($PSCmdlet.ShouldProcess($name, "Create quarantine policy at $accessLevel")) {
                New-QuarantinePolicy -Name $name -EndUserQuarantinePermissionsValue $permissionValue[$accessLevel] -WhatIf:$UseWhatIf
                $operation.Add('mdo-quarantine-policy-create')
            }
        }
        elseif ([int]$current.EndUserQuarantinePermissionsValue -ne $permissionValue[$accessLevel]) {
            if ($PSCmdlet.ShouldProcess($name, "Set quarantine policy permission to $accessLevel")) {
                Set-QuarantinePolicy -Identity $name -EndUserQuarantinePermissionsValue $permissionValue[$accessLevel] -WhatIf:$UseWhatIf
                $operation.Add('mdo-quarantine-policy-set')
            }
        }
    }

    $global = @($currentPolicy | Where-Object { [string]$_.Name -ieq 'DefaultGlobalTag' }) | Select-Object -First 1
    if ($null -eq $global) { throw 'GlobalQuarantinePolicyNotFound: DefaultGlobalTag was not observed.' }
    $cadence = [timespan]::FromDays([int]$desired.endUserSpamNotificationFrequencyInDays)
    if ([timespan]$global.EndUserSpamNotificationFrequency -ne $cadence -or
        [bool]$global.IncludeMessagesFromBlockedSenderAddress -ne [bool]$desired.includeMessagesFromBlockedSenderAddress) {
        if ($PSCmdlet.ShouldProcess('DefaultGlobalTag', 'Set quarantine cadence and blocked-sender behavior')) {
            Set-QuarantinePolicy -Identity DefaultGlobalTag -EndUserSpamNotificationFrequency $cadence `
                -IncludeMessagesFromBlockedSenderAddress ([bool]$desired.includeMessagesFromBlockedSenderAddress) `
                -WhatIf:$UseWhatIf
            $operation.Add('mdo-quarantine-policy-set')
        }
    }

    foreach ($filter in @(Get-HostedContentFilterPolicy -ErrorAction Stop)) {
        $parameters = @{ Identity = $filter.Identity; WhatIf = $UseWhatIf }
        $policyMatches = $true
        foreach ($name in @($categoryMember.Keys)) {
            $member = $categoryMember[$name]
            $required = $policyName[$category[$name]]
            $parameters[$member] = $required
            if ([string]$filter.$member -ine $required) { $policyMatches = $false }
        }
        if (-not $policyMatches) {
            if ($PSCmdlet.ShouldProcess([string]$filter.Identity, 'Set every spam and phishing quarantine category permission')) {
                Set-HostedContentFilterPolicy @parameters
                $operation.Add('mdo-quarantine-content-filter-set')
            }
        }
    }

    $malwarePolicyName = $policyName[$category['Malware']]
    foreach ($filter in @(Get-MalwareFilterPolicy -ErrorAction Stop)) {
        if ([string]$filter.QuarantineTag -ine $malwarePolicyName) {
            if ($PSCmdlet.ShouldProcess([string]$filter.Identity, 'Set malware quarantine category permission')) {
                Set-MalwareFilterPolicy -Identity $filter.Identity -QuarantineTag $malwarePolicyName -WhatIf:$UseWhatIf
                $operation.Add('mdo-quarantine-malware-filter-set')
            }
        }
    }

    Add-Outcome -Control 'MDO-008' -Status $(if ($UseWhatIf) { 'Planned' } else { 'Applied' }) `
        -Detail 'Quarantine cadence, blocked-sender behavior, and every category permission match resolved state' `
        -Operation @($operation | Select-Object -Unique)
}

function Get-BaselineMdoPostChangeEvidence {
    [CmdletBinding()]
    param()

    return @(
        Get-ReportSubmissionEvidence `
            -ReportSubmissionPolicyCollection { @(Get-ReportSubmissionPolicy -ErrorAction Stop) } `
            -SecOpsOverridePolicyCollection { @(Get-SecOpsOverridePolicy -ErrorAction Stop) }
        Get-TenantAllowBlockListEvidence -Collection { @(Get-TenantAllowBlockListItems -ErrorAction Stop) }
        Get-QuarantinePolicyEvidence `
            -QuarantinePolicyCollection { @(Get-QuarantinePolicy -ErrorAction Stop) } `
            -ContentFilterPolicyCollection { @(Get-HostedContentFilterPolicy -ErrorAction Stop) } `
            -MalwareFilterPolicyCollection { @(Get-MalwareFilterPolicy -ErrorAction Stop) }
        Get-PriorityAccountEvidence -AntiPhishPolicyCollection { @(Get-AntiPhishPolicy -ErrorAction Stop) }
    )
}

function Set-OrganizationControls {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Configuration, [bool]$UseWhatIf, [object]$Entitlement, [object]$SafeDocumentsPreflight, [switch]$ExchangeOnly)

    $state = $Configuration.desiredState
    $verb = if ($UseWhatIf) { 'Planned' } else { 'Applied' }

    $protocols = $state.exchangeOnline.protocolRestriction
    $ewsPolicy = Resolve-BaselineEwsPolicy -DesiredState $protocols
    if ($ewsPolicy.EwsEnabled) {
        $ewsProposedState = @{
            OrganizationConfig = $ewsPolicy
            CasMailbox = @(Get-CASMailbox -ResultSize Unlimited -ErrorAction Stop)
        }
        $ewsAdmission = Test-BaselineEwsState -DesiredState $protocols -ObservedState $ewsProposedState
        if ($ewsAdmission.Status -ne 'Pass') { throw $ewsAdmission.Reason }
    }

    $remote = $state.exchangeOnline.remoteDomainDefault
    $remoteOofType = Resolve-BaselineRemoteDomainOofType -DesiredState $remote
    $remoteDomains = @(Get-RemoteDomain -ErrorAction Stop)
    if (@($remoteDomains | Where-Object { $_.Identity -ieq 'Default' -and [string]$_.DomainName -eq '*' }).Count -ne 1) {
        throw 'RemoteDomainDefaultMissing: exactly one wildcard Default must be collected before deployment.'
    }
    foreach ($domain in $remoteDomains) {
        if ([string]::IsNullOrWhiteSpace([string]$domain.Identity) -or [string]::IsNullOrWhiteSpace([string]$domain.DomainName)) {
            throw 'RemoteDomainEvidenceIncomplete: remote-domain Identity and DomainName are required before deployment.'
        }
        if ($domain.Identity -ine 'Default' -and ([string]$domain.AllowedOOFType).Trim() -ine $remoteOofType) {
            throw "RemoteDomainOverrideConflict: '$($domain.Identity)' ($($domain.DomainName)) has AllowedOOFType '$($domain.AllowedOOFType)', expected '$remoteOofType'. Obtain a scoped approved change for this override before deploying Default."
        }
    }

    if ($null -ne (Get-Command -Name Set-BaselineAcceptedDomainState -ErrorAction SilentlyContinue)) {
        Set-BaselineAcceptedDomainState -Configuration $Configuration -UseWhatIf $UseWhatIf
    }
    if ($null -ne (Get-Command -Name Set-BaselineExistingMailboxProtocolState -ErrorAction SilentlyContinue)) {
        Set-BaselineExistingMailboxProtocolState -Configuration $Configuration -UseWhatIf $UseWhatIf
    }

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

    if ($null -ne (Get-Command -Name Set-BaselineForwardingState -ErrorAction SilentlyContinue)) {
        $acceptedDomain = @(Get-AcceptedDomain -ErrorAction Stop | ForEach-Object { [string]$_.DomainName })
        Set-BaselineForwardingState -AcceptedDomain $acceptedDomain -UseWhatIf $UseWhatIf
        Add-Outcome -Control 'EXO-004' -Status $verb -Detail 'Mailbox and inbox-rule external forwarding removed' `
            -Operation @('exo-mailbox-forwarding', 'exo-inbox-rule-forwarding')
    }

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
            -AutoReplyEnabled $remote.autoReplyEnabled -AllowedOOFType $remoteOofType `
            -DeliveryReportEnabled $remote.deliveryReportEnabled -NDREnabled $remote.nonDeliveryReportEnabled `
            -WhatIf:$UseWhatIf
    }
    Add-Outcome -Control 'EXO-008' -Status $verb -Detail 'Default remote domain hardened' `
        -Operation @('exo-remote-domain')

    $protocols = $state.exchangeOnline.protocolRestriction
    if ($PSCmdlet.ShouldProcess('Organization configuration', 'Restrict Exchange Web Services')) {
        Set-OrganizationConfig @ewsPolicy -WhatIf:$UseWhatIf
    }
    if ($PSCmdlet.ShouldProcess('Every CAS mailbox plan', 'Disable POP and IMAP for new mailboxes')) {
        Get-CASMailboxPlan -ResultSize Unlimited | ForEach-Object {
            Set-CASMailboxPlan -Identity $_.Identity -PopEnabled $protocols.popEnabledByDefault `
                -ImapEnabled $protocols.imapEnabledByDefault -WhatIf:$UseWhatIf
        }
    }
    Add-Outcome -Control 'EXO-009' -Status $verb -Detail 'Approved EWS policy enforced; POP/IMAP restricted for new mailboxes' `
        -Operation @('exo-organization-config', 'exo-cas-mailbox-plan')

    if ($null -ne (Get-Command -Name Set-BaselineAddInAcquisitionState -ErrorAction SilentlyContinue)) {
        Set-BaselineAddInAcquisitionState -Configuration $Configuration -UseWhatIf $UseWhatIf
    }

    if ($null -ne (Get-Command -Name Set-BaselineReportSubmissionState -ErrorAction SilentlyContinue)) {
        Set-BaselineReportSubmissionState -Configuration $Configuration -UseWhatIf $UseWhatIf
    }
    if ($null -ne (Get-Command -Name Set-BaselineSecOpsOverrideState -ErrorAction SilentlyContinue)) {
        Set-BaselineSecOpsOverrideState -Configuration $Configuration -UseWhatIf $UseWhatIf
    }
    if ($null -ne (Get-Command -Name Set-BaselineTenantAllowBlockListState -ErrorAction SilentlyContinue)) {
        Set-BaselineTenantAllowBlockListState -Configuration $Configuration -UseWhatIf $UseWhatIf
    }
    if ($null -ne (Get-Command -Name ('Set-Baseline' + 'ImpersonationProtectionState') -ErrorAction SilentlyContinue)) {
        Set-BaselineImpersonationProtectionState -Configuration $Configuration -UseWhatIf $UseWhatIf
    }
    if ($null -ne (Get-Command -Name Set-BaselineQuarantineState -ErrorAction SilentlyContinue)) {
        Set-BaselineQuarantineState -Configuration $Configuration -UseWhatIf $UseWhatIf
    }
    else {
        $quarantine = $state.defenderForOffice365.quarantinePolicies
        if ($PSCmdlet.ShouldProcess('DefaultGlobalTag quarantine policy', 'Set the end-user spam notification cadence')) {
            Set-QuarantinePolicy -Identity DefaultGlobalTag `
                -EndUserSpamNotificationFrequency (New-TimeSpan -Days $quarantine.endUserSpamNotificationFrequencyInDays) `
                -WhatIf:$UseWhatIf
        }
        Add-Outcome -Control 'MDO-008' -Status $verb -Detail 'Global quarantine notification cadence set' `
            -Operation @('mdo-quarantine-policy-set')
    }

    if ($ExchangeOnly) { return }
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

function script:Test-BaselineExoPostChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Operation,
        [Parameter(Mandatory)][string]$Evidence
    )

    $exoArea = @('AcceptedDomain', 'MailboxProtocol', 'MailboxForwarding', 'InboxRule', 'AddInAcquisition')
    $finding = [System.Collections.Generic.List[string]]::new()
    $observedState = [System.Collections.Generic.List[object]]::new()

    $normalize = {
        param([AllowNull()][object]$Value)

        if ($null -eq $Value) { return '[]' }
        $normalized = @(@($Value) | ForEach-Object {
                if ($null -eq $_) { '<null>' }
                elseif ($_ -is [bool]) { ([string]$_).ToLowerInvariant() }
                else { ([string]$_).Trim().ToLowerInvariant() }
            } | Sort-Object -Unique)
        return '[' + ($normalized -join ',') + ']'
    }

    foreach ($entry in $Operation) {
        $area = [string]$entry.Area
        $requiredArea = switch -Regex ([string]$entry.OperationId) {
            '^exo-accepted-domain-' { 'AcceptedDomain'; break }
            '^exo-(existing-)?mailbox-protocol' { 'MailboxProtocol'; break }
            '^exo-mailbox-forwarding' { 'MailboxForwarding'; break }
            '^exo-inbox-rule-forwarding' { 'InboxRule'; break }
            '^exo-addin-acquisition-' { 'AddInAcquisition'; break }
            default { '' }
        }
        if ([string]::IsNullOrWhiteSpace($area) -and -not [string]::IsNullOrWhiteSpace($requiredArea)) {
            $area = $requiredArea
        }

        $observed = $null
        try { $observed = & $entry.Read } catch { $observed = $null }

        $observedState.Add([ordered]@{
                OperationId = [string]$entry.OperationId
                Area = $area
                Identity = [string]$entry.Identity
                Observed = ($null -ne $observed)
                Value = $observed
            })

        if ($null -eq $observed) {
            $finding.Add("PostChangeObjectNotObserved: '$area/$($entry.Identity)' could not be read back after '$($entry.OperationId)' mutated it.")
            continue
        }

        if (-not [string]::IsNullOrWhiteSpace($requiredArea) -and $null -eq $entry.Desired) {
            $finding.Add("PostChangeDesiredStateNotDeclared: '$requiredArea/$($entry.OperationId)' names no resolved desired state to compare with its observation.")
            continue
        }

        if ($exoArea -notcontains $area -or $null -eq $entry.Desired) { continue }

        foreach ($member in @($entry.Desired.Keys)) {
            $property = $observed.PSObject.Properties[[string]$member]
            if ($null -eq $property) {
                $finding.Add("PostChangeMemberNotObserved: '$area/$($entry.Identity)' did not report '$member'.")
                continue
            }

            $actual = & $normalize $property.Value
            $required = & $normalize $entry.Desired[$member]
            if ($actual -cne $required) {
                $finding.Add("PostChangeMemberDrift: '$area/$($entry.Identity)' member '$member' observed '$actual' and requires '$required'.")
            }
        }
    }

    return [ordered]@{
        Permitted = ($finding.Count -eq 0)
        Evidence = $Evidence
        Observed = @($observedState)
        Finding = @($finding)
    }
}

function script:Test-BaselineMdoPostChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Operation,
        [Parameter(Mandatory)][object[]]$Registry,
        [Parameter(Mandatory)][object[]]$EvidenceByControl,
        [Parameter(Mandatory)][scriptblock]$Evaluation,
        [Parameter(Mandatory)][datetimeoffset]$AsOfUtc,
        [Parameter(Mandatory)][timespan]$MaximumEvidenceAge,
        [Parameter(Mandatory)][string]$Evidence
    )

    $finding = [System.Collections.Generic.List[string]]::new()
    $observedState = [System.Collections.Generic.List[object]]::new()
    $registered = @($Registry | Where-Object { [string]$_.ControlId -match '^MDO-00[6-9]$' })
    $registeredId = @($registered | ForEach-Object { [string]$_.ControlId })

    foreach ($entry in $EvidenceByControl) {
        if ([string]$entry.ControlId -notin $registeredId) {
            $finding.Add("MdoPostChangeEvidenceUnknown: '$($entry.ControlId)' is unknown to the registered MDO post-change set.")
        }
    }

    $mayEvaluate = $true
    foreach ($entry in $registered) {
        $controlId = [string]$entry.ControlId
        $records = @($EvidenceByControl | Where-Object { [string]$_.ControlId -ceq $controlId })
        if ($records.Count -eq 0) {
            $finding.Add("MdoPostChangeEvidenceMissing: '$controlId' is missing from the post-change evidence set.")
            $mayEvaluate = $false
            continue
        }
        if ($records.Count -ne 1) {
            $finding.Add("MdoPostChangeEvidenceDuplicate: '$controlId' has $($records.Count) duplicate evidence records.")
            $mayEvaluate = $false
            continue
        }

        $collectedAt = [datetimeoffset]::MinValue
        if (-not [datetimeoffset]::TryParse([string]$records[0].CollectedAtUtc, [ref]$collectedAt) -or
            ($AsOfUtc - $collectedAt) -gt $MaximumEvidenceAge -or $collectedAt -gt $AsOfUtc) {
            $finding.Add("MdoPostChangeEvidenceStale: '$controlId' evidence is stale or future-dated at '$($records[0].CollectedAtUtc)'.")
            $mayEvaluate = $false
        }
    }

    if ($mayEvaluate -and $finding.Count -eq 0) {
        foreach ($entry in $registered) {
            $record = @($EvidenceByControl | Where-Object { [string]$_.ControlId -ceq [string]$entry.ControlId })[0]
            $result = @(& $Evaluation $entry $record)
            if ($result.Count -ne 1) {
                $finding.Add("MdoPostChangeResultIncomplete: '$($entry.ControlId)' produced $($result.Count) results instead of one.")
                continue
            }
            if ([string]$result[0].ControlId -cne [string]$entry.ControlId) {
                $finding.Add("MdoPostChangeResultInline: result '$($result[0].ControlId)' is inline or mismatched; registered evaluator '$($entry.Evaluator)' must decide '$($entry.ControlId)'.")
                continue
            }
            if ([string]$result[0].Status -cne 'Pass') {
                $finding.Add("MdoPostChangeResultRefused: '$($entry.ControlId)' was decided '$($result[0].Status)': $($result[0].Reason)")
            }
        }
    }

    $knownArea = @('ReportSubmission', 'AdvancedDelivery', 'TenantAllowBlockList', 'Quarantine', 'ImpersonationProtection')
    $seenOperation = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($entry in $Operation) {
        $operationId = [string]$entry.OperationId
        $area = [string]$entry.Area
        if (-not $seenOperation.Add($operationId)) {
            $finding.Add("MdoPostChangeMutationDuplicate: '$operationId' is a duplicate mutation.")
            continue
        }
        if ($area -notin $knownArea) {
            $finding.Add("MdoPostChangeMutationUnknown: '$operationId' names unknown MDO area '$area'.")
            continue
        }

        $desired = $entry.Desired
        if ($desired -is [scriptblock]) { $desired = & $desired }
        $member = @()
        if ($null -ne $desired) { $member = @($desired.Keys) }
        if ($member.Count -eq 0) {
            $finding.Add("MdoPostChangeDesiredStateMissing: '$operationId' carries no resolved desired members.")
            continue
        }

        $observed = $null
        try { $observed = & $entry.Read } catch { $observed = $null }
        if ($null -eq $observed) {
            $finding.Add("MdoPostChangeObjectNotObserved: '$operationId' was not observed after mutation.")
            continue
        }

        $observedState.Add([ordered]@{ OperationId = $operationId; Area = $area; Identity = [string]$entry.Identity; Value = $observed })
        foreach ($name in $member) {
            $property = $observed.PSObject.Properties[[string]$name]
            if ($null -eq $property) {
                $finding.Add("MdoPostChangeMemberMissing: '$operationId' member '$name' is missing from the observation.")
                continue
            }
            $formatValue = {
                param([object]$Value)
                if ($Value -is [timespan]) { return [string]$Value }
                if ($Value -is [string] -or $Value -is [bool] -or $Value -is [ValueType]) { return [string]$Value }
                return ConvertTo-Json @($Value) -Compress -Depth 20
            }
            $actual = & $formatValue $property.Value
            $required = & $formatValue $desired[$name]
            if ($actual -cne $required) {
                $finding.Add("MdoPostChangeMemberDrift: '$operationId' member '$name' observed '$actual' and requires '$required'.")
            }
        }
    }

    return [ordered]@{
        Permitted = ($finding.Count -eq 0)
        Evidence = $Evidence
        Observed = @($observedState)
        Finding = @($finding)
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
    [ordered]@{ OperationId = 'pp-trusted-arc-sealers'; Command = 'Set-ArcConfig'; Identity = 'Default ARC configuration'; Read = { @((Get-ArcConfig -Identity Default -ErrorAction SilentlyContinue).ArcTrustedSealers) } }
    [ordered]@{ OperationId = 'mdo-eop-preset-scope'; Command = 'Set-EOPProtectionPolicyRule'; Identity = 'Standard Preset Security Policy'; Read = { (Get-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -ErrorAction SilentlyContinue).State } }
    [ordered]@{ OperationId = 'mdo-eop-preset-enable'; Command = 'Enable-EOPProtectionPolicyRule'; Identity = 'Strict Preset Security Policy'; Read = { (Get-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -ErrorAction SilentlyContinue).State } }
    [ordered]@{ OperationId = 'mdo-atp-preset-scope'; Command = 'Set-ATPProtectionPolicyRule'; Identity = 'Standard Preset Security Policy'; Read = { (Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -ErrorAction SilentlyContinue).State } }
    [ordered]@{ OperationId = 'mdo-atp-preset-enable'; Command = 'Enable-ATPProtectionPolicyRule'; Identity = 'Strict Preset Security Policy'; Read = { (Get-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -ErrorAction SilentlyContinue).State } }
    [ordered]@{ OperationId = 'mdo-atp-builtin-unexclude'; Command = 'Set-ATPBuiltInProtectionRule'; Identity = 'ATP Built-In Protection Rule'; Read = { @((Get-ATPBuiltInProtectionRule -Identity 'ATP Built-In Protection Rule' -ErrorAction SilentlyContinue).ExceptIfSentTo).Count } }
    [ordered]@{
        OperationId = 'mdo-report-submission-create'; Command = 'New-ReportSubmissionPolicy'; Identity = 'DefaultReportSubmissionPolicy'; Area = 'ReportSubmission'
        Desired = { [ordered]@{ EnableThirdPartyAddress = (-not [bool]$configuration.desiredState.defenderForOffice365.userSubmissions.microsoftReportMessageButton); EnableReportToMicrosoft = [bool]$configuration.desiredState.defenderForOffice365.userSubmissions.sendReportedMessagesToMicrosoft; ReportJunkToCustomizedAddress = [bool]$configuration.desiredState.defenderForOffice365.userSubmissions.sendCopyToSecOpsMailbox; ReportNotJunkToCustomizedAddress = [bool]$configuration.desiredState.defenderForOffice365.userSubmissions.sendCopyToSecOpsMailbox; ReportPhishToCustomizedAddress = [bool]$configuration.desiredState.defenderForOffice365.userSubmissions.sendCopyToSecOpsMailbox; ReportJunkAddresses = @([string]$configuration.desiredState.defenderForOffice365.userSubmissions.reportingMailbox) } }
        Read = { Get-ReportSubmissionPolicy -Identity DefaultReportSubmissionPolicy -ErrorAction SilentlyContinue }
    }
    [ordered]@{
        OperationId = 'mdo-report-submission-set'; Command = 'Set-ReportSubmissionPolicy'; Identity = 'DefaultReportSubmissionPolicy'; Area = 'ReportSubmission'
        Desired = { [ordered]@{ EnableThirdPartyAddress = (-not [bool]$configuration.desiredState.defenderForOffice365.userSubmissions.microsoftReportMessageButton); EnableReportToMicrosoft = [bool]$configuration.desiredState.defenderForOffice365.userSubmissions.sendReportedMessagesToMicrosoft; ReportJunkToCustomizedAddress = [bool]$configuration.desiredState.defenderForOffice365.userSubmissions.sendCopyToSecOpsMailbox; ReportNotJunkToCustomizedAddress = [bool]$configuration.desiredState.defenderForOffice365.userSubmissions.sendCopyToSecOpsMailbox; ReportPhishToCustomizedAddress = [bool]$configuration.desiredState.defenderForOffice365.userSubmissions.sendCopyToSecOpsMailbox; ReportJunkAddresses = @([string]$configuration.desiredState.defenderForOffice365.userSubmissions.reportingMailbox) } }
        Read = { Get-ReportSubmissionPolicy -Identity DefaultReportSubmissionPolicy -ErrorAction SilentlyContinue }
    }
    [ordered]@{
        OperationId = 'mdo-secops-override-create'; Command = 'New-SecOpsOverridePolicy'; Identity = 'SecOpsOverridePolicy'; Area = 'AdvancedDelivery'
        Desired = { [ordered]@{ SentTo = @($configuration.desiredState.defenderForOffice365.advancedDelivery.secOpsMailbox); Mode = 'Enforce' } }
        Read = { Get-SecOpsOverridePolicy -Identity SecOpsOverridePolicy -ErrorAction SilentlyContinue }
    }
    [ordered]@{
        OperationId = 'mdo-secops-override-set'; Command = 'Set-SecOpsOverridePolicy'; Identity = 'SecOpsOverridePolicy'; Area = 'AdvancedDelivery'
        Desired = { [ordered]@{ SentTo = @($configuration.desiredState.defenderForOffice365.advancedDelivery.secOpsMailbox); Mode = 'Enforce' } }
        Read = { Get-SecOpsOverridePolicy -Identity SecOpsOverridePolicy -ErrorAction SilentlyContinue }
    }
    [ordered]@{
        OperationId = 'mdo-tabl-create'; Command = 'New-TenantAllowBlockListItems'; Identity = 'Governed TABL entries'; Area = 'TenantAllowBlockList'
        Desired = { [ordered]@{ Entries = @() } }
        Read = { [pscustomobject]@{ Entries = @(Get-TenantAllowBlockListItems -ErrorAction Stop) } }
    }
    [ordered]@{
        OperationId = 'mdo-tabl-remove'; Command = 'Remove-TenantAllowBlockListItems'; Identity = 'Governed TABL entries'; Area = 'TenantAllowBlockList'
        Desired = { [ordered]@{ Entries = @() } }
        Read = { [pscustomobject]@{ Entries = @(Get-TenantAllowBlockListItems -ErrorAction Stop) } }
    }
    [ordered]@{
        OperationId = 'mdo-impersonation-policy-create'
        Command = 'New-AntiPhishPolicy'
        Identity = 'Contoso Impersonation Protection'
        Area = 'ImpersonationProtection'
        Desired = { }
        Read = {
            $policy = Get-AntiPhishPolicy -Identity 'Contoso Impersonation Protection' -ErrorAction SilentlyContinue
            if ($null -ne $policy) {
                [pscustomobject]@{
                    EnableTargetedUserProtection = $policy.EnableTargetedUserProtection
                    EnableTargetedDomainsProtection = $policy.EnableTargetedDomainsProtection
                    TargetedUsersToProtect = @($policy.TargetedUsersToProtect)
                    TargetedDomainsToProtect = @($policy.TargetedDomainsToProtect)
                    ExcludedSenders = @($policy.ExcludedSenders)
                    ExcludedDomains = @($policy.ExcludedDomains)
                }
            }
        }
    }
    [ordered]@{
        OperationId = 'mdo-impersonation-policy-set'
        Command = 'Set-AntiPhishPolicy'
        Identity = 'Contoso Impersonation Protection'
        Area = 'ImpersonationProtection'
        Desired = { }
        Read = {
            $policy = Get-AntiPhishPolicy -Identity 'Contoso Impersonation Protection' -ErrorAction SilentlyContinue
            if ($null -ne $policy) {
                [pscustomobject]@{
                    EnableTargetedUserProtection = $policy.EnableTargetedUserProtection
                    EnableTargetedDomainsProtection = $policy.EnableTargetedDomainsProtection
                    TargetedUsersToProtect = @($policy.TargetedUsersToProtect)
                    TargetedDomainsToProtect = @($policy.TargetedDomainsToProtect)
                    ExcludedSenders = @($policy.ExcludedSenders)
                    ExcludedDomains = @($policy.ExcludedDomains)
                }
            }
        }
    }
    [ordered]@{ OperationId = 'exo-transport-config'; Command = 'Set-TransportConfig'; Identity = 'Transport configuration'; Read = { (Get-TransportConfig).SmtpClientAuthenticationDisabled } }
    [ordered]@{ OperationId = 'exo-accepted-domain-create'; Command = 'New-AcceptedDomain'; Identity = 'Resolved accepted domains'; Read = { @(Get-AcceptedDomain -ResultSize Unlimited | ForEach-Object { '{0}:{1}' -f $_.DomainName, $_.DomainType }) -join ';' } }
    [ordered]@{ OperationId = 'exo-accepted-domain-set'; Command = 'Set-AcceptedDomain'; Identity = 'Resolved accepted domains'; Read = { @(Get-AcceptedDomain -ResultSize Unlimited | ForEach-Object { '{0}:{1}' -f $_.DomainName, $_.DomainType }) -join ';' } }
    [ordered]@{ OperationId = 'exo-existing-mailbox-protocol'; Command = 'Set-CASMailbox'; Identity = 'Every existing mailbox'; Read = { @(Get-CASMailbox -ResultSize Unlimited | Where-Object { $_.PopEnabled -or $_.ImapEnabled }).Count } }
    [ordered]@{ OperationId = 'exo-outbound-spam-policy'; Command = 'Set-HostedOutboundSpamFilterPolicy'; Identity = 'Default'; Read = { (Get-HostedOutboundSpamFilterPolicy -Identity Default).AutoForwardingMode } }
    [ordered]@{ OperationId = 'exo-mailbox-forwarding'; Command = 'Set-Mailbox'; Identity = 'Every forwarding mailbox'; Read = { @(Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress }).Count } }
    [ordered]@{ OperationId = 'exo-inbox-rule-forwarding'; Command = 'Disable-InboxRule'; Identity = 'Every enabled external forwarding inbox rule'; Read = { 'Collected through Get-BaselineMailboxInboxRuleCollection' } }
    [ordered]@{ OperationId = 'exo-organization-config'; Command = 'Set-OrganizationConfig'; Identity = 'Organization configuration'; Read = { (Get-OrganizationConfig).AuditDisabled } }
    [ordered]@{ OperationId = 'exo-external-in-outlook'; Command = 'Set-ExternalInOutlook'; Identity = 'External sender identification'; Read = { @(Get-ExternalInOutlook)[0].Enabled } }
    [ordered]@{ OperationId = 'exo-remote-domain'; Command = 'Set-RemoteDomain'; Identity = 'Default'; Read = { (Get-RemoteDomain -Identity Default).AutoForwardEnabled } }
    [ordered]@{ OperationId = 'exo-cas-mailbox-plan'; Command = 'Set-CASMailboxPlan'; Identity = 'Every CAS mailbox plan'; Read = { @(Get-CASMailboxPlan -ResultSize Unlimited | Where-Object { $_.PopEnabled -or $_.ImapEnabled }).Count } }
    [ordered]@{
        OperationId = 'exo-addin-acquisition-remove'
        Command = 'Remove-ManagementRoleAssignment'
        Identity = 'Default role assignment policy add-in acquisition grants'
        Area = 'AddInAcquisition'
        Desired = [ordered]@{ Roles = @() }
        Read = {
            $defaultPolicy = @(Get-RoleAssignmentPolicy -ErrorAction Stop | Where-Object { $_.IsDefault })[0]
            $roles = @(Get-ManagementRoleAssignment -ErrorAction Stop | Where-Object {
                    [string]$_.RoleAssignee -ieq [string]$defaultPolicy.Identity -and
                    @('My Custom Apps', 'My Marketplace Apps', 'My ReadWriteMailboxApps') -icontains [string]$_.Role
                } | ForEach-Object { [string]$_.Role })
            [pscustomobject]@{ Roles = $roles }
        }
    }
    [ordered]@{
        OperationId = 'mdo-quarantine-policy-create'; Command = 'New-QuarantinePolicy'; Identity = 'Baseline quarantine access policies'; Area = 'Quarantine'
        Desired = { [ordered]@{ PermissionValues = @(0, 106) } }
        Read = { [pscustomobject]@{ PermissionValues = @(Get-QuarantinePolicy | Where-Object Name -in @('Baseline-AdminOnlyAccess', 'Baseline-LimitedAccess') | ForEach-Object EndUserQuarantinePermissionsValue | Sort-Object) } }
    }
    [ordered]@{
        OperationId = 'mdo-quarantine-policy-set'; Command = 'Set-QuarantinePolicy'; Identity = 'Quarantine policies'; Area = 'Quarantine'
        Desired = { [ordered]@{ EndUserSpamNotificationFrequency = [timespan]::FromDays([int]$configuration.desiredState.defenderForOffice365.quarantinePolicies.endUserSpamNotificationFrequencyInDays); IncludeMessagesFromBlockedSenderAddress = [bool]$configuration.desiredState.defenderForOffice365.quarantinePolicies.includeMessagesFromBlockedSenderAddress } }
        Read = { Get-QuarantinePolicy -Identity DefaultGlobalTag -ErrorAction Stop }
    }
    [ordered]@{
        OperationId = 'mdo-quarantine-content-filter-set'; Command = 'Set-HostedContentFilterPolicy'; Identity = 'Hosted content filter quarantine tags'; Area = 'Quarantine'
        Desired = { [ordered]@{ HighConfidencePhishQuarantineTag = 'Baseline-AdminOnlyAccess'; PhishQuarantineTag = 'Baseline-LimitedAccess'; HighConfidenceSpamQuarantineTag = 'Baseline-LimitedAccess'; SpamQuarantineTag = 'Baseline-LimitedAccess'; BulkQuarantineTag = 'Baseline-LimitedAccess'; SpoofQuarantineTag = 'Baseline-LimitedAccess' } }
        Read = { @(Get-HostedContentFilterPolicy -ErrorAction Stop)[0] }
    }
    [ordered]@{
        OperationId = 'mdo-quarantine-malware-filter-set'; Command = 'Set-MalwareFilterPolicy'; Identity = 'Malware filter quarantine tag'; Area = 'Quarantine'
        Desired = { [ordered]@{ QuarantineTag = 'Baseline-AdminOnlyAccess' } }
        Read = { @(Get-MalwareFilterPolicy -ErrorAction Stop)[0] }
    }
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
$exchangeContext = $null
$runtimeMutationPlan = @($MutationPlan | ForEach-Object {
    $entry = [ordered]@{}
    foreach ($key in $_.Keys) { $entry[$key] = $_[$key] }
    $entry
})
if ($selectedProfile -ceq 'ExchangeOnly') {
    $exchangeContext = Get-BaselineExchangeContext -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath
    $runtimeMutationPlan = @($runtimeMutationPlan | Where-Object { $_.OperationId -notlike 'pp-*' -and $_.OperationId -cne 'mdo-atp-policy-o365' })
    $null = Assert-BaselineExchangeMutationPlan -Operation $runtimeMutationPlan
    if (-not $Apply) {
        [pscustomobject]@{
            Kind = 'ExchangeOnlyPlan'; Status = 'Planned'; DeploymentProfile = 'ExchangeOnly'; ProfileVersion = $exchangeContext.Manifest.Version
            TenantId = $exchangeContext.Parameters.MICROSOFT_ENTRA_TENANT_GUID; ConfigurationHash = $exchangeContext.Hash
            ControlId = $exchangeContext.Manifest.ControlId
            Operation = @($runtimeMutationPlan | ForEach-Object { [pscustomobject]@{ OperationId = $_.OperationId; Command = $_.Command; Identity = $_.Identity } })
            ExternalReadiness = $exchangeContext.Manifest.ExternalReadiness
        }
        return
    }
    if ('EXCHANGE_S_ENTERPRISE' -cnotin @($exchangeContext.Entitlement.servicePlans)) { throw 'ExchangeApplyNotEntitled: Exchange entitlement is required before any mutation.' }
}
if ($Apply) {
    $applyResolution = if ($null -ne $exchangeContext) { [pscustomobject]@{ Configuration = $exchangeContext.DeploymentConfiguration; DeploymentProfile = 'ExchangeOnly' } } else { Resolve-BaselineConfiguration -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath }
    $applyInputs = $applyResolution.Configuration.administratorInputs

    $approvalDecision = Test-BaselineChangeApproval -PreviewPath $PreviewPath -ApprovalPath $ApprovalPath `
        -Tenant $applyInputs.initialDomain -DeploymentProfile $applyResolution.DeploymentProfile `
        -ConfigurationHash $(if ($null -ne $exchangeContext) { $exchangeContext.Hash } else { (Get-BaselineConfigurationHash -Resolution $applyResolution).Hash }) `
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

    if ($selectedProfile -cne 'ExchangeOnly') {
    Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.0.0
    Connect-MgGraph -Scopes 'Organization.Read.All' -NoWelcome
    $graphRequest = {
        param($Resource)
        Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/$Resource" -OutputType PSObject
    }
    }
}

$context = if ($null -ne $exchangeContext) { $exchangeContext } else { Get-BaselineContext -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath -SchemaPath $SchemaPath -GraphRequest $graphRequest }
$configuration = if ($null -ne $exchangeContext) { $exchangeContext.DeploymentConfiguration } else { $context.Configuration }
$entitlement = if ($null -ne $exchangeContext) { $exchangeContext.DeploymentEntitlement } else { $context.Entitlement }

$ewsDesired = $configuration.desiredState.exchangeOnline.protocolRestriction
$ewsPolicy = Resolve-BaselineEwsPolicy -DesiredState $ewsDesired
if ($ewsPolicy.EwsEnabled) {
    $ewsProposedState = @{
        OrganizationConfig = $ewsPolicy
        CasMailbox = @(Get-CASMailbox -ResultSize Unlimited -ErrorAction Stop)
    }
    $ewsAdmission = Test-BaselineEwsState -DesiredState $ewsDesired -ObservedState $ewsProposedState
    if ($ewsAdmission.Status -ne 'Pass') { throw $ewsAdmission.Reason }
}

$impersonation = $configuration.desiredState.defenderForOffice365.impersonationProtection
$impersonationDesired = [ordered]@{
    EnableTargetedUserProtection = [bool]$impersonation.enabled
    EnableTargetedDomainsProtection = [bool]$impersonation.enabled
    TargetedUsersToProtect = @($impersonation.protectedUsers)
    TargetedDomainsToProtect = @($impersonation.protectedDomains)
    ExcludedSenders = @($impersonation.approvedExceptions | Where-Object { $_.exceptionType -ceq 'TrustedSender' } | ForEach-Object { [string]$_.value })
    ExcludedDomains = @($impersonation.approvedExceptions | Where-Object { $_.exceptionType -ceq 'TrustedDomain' } | ForEach-Object { [string]$_.value })
}
foreach ($operation in @($runtimeMutationPlan | Where-Object { $_.OperationId -like 'mdo-impersonation-policy-*' })) {
    $operation.Desired = $impersonationDesired
}

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
        foreach ($operation in $runtimeMutationPlan) {
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
    Set-TrustedArcSealer -Configuration $configuration -UseWhatIf $useWhatIf
    Add-Outcome -Control 'PP-005' -Status 'Skipped' -Detail 'Gateway profile: Partner inbound connector is declared and governed by PP-001'
}
else {
    Add-Outcome -Control 'PP-001/PP-002/PP-003/PP-004' -Status 'Skipped' `
        -Detail 'No mail gateway declared; the tenant receives directly on its Microsoft 365 MX target'
    Add-Outcome -Control 'PP-005' -Status 'Planned' -Detail 'Verify that no enabled Partner inbound connector exists'
}

Set-PresetProtection -Configuration $configuration -UseWhatIf $useWhatIf -Entitlement $entitlement
Set-OrganizationControls -Configuration $configuration -UseWhatIf $useWhatIf -Entitlement $entitlement -SafeDocumentsPreflight $safeDocumentsPreflight -ExchangeOnly:($selectedProfile -ceq 'ExchangeOnly')
Set-DomainAuthentication -Configuration $configuration -UseWhatIf $useWhatIf -ActivateDkim $EnableDkim
if ($selectedProfile -cne 'ExchangeOnly') { Write-ManualControlPlan -Configuration $configuration -Entitlement $entitlement }

# SAFE-007-A3: what the run actually left behind. The journal is built from the status each
# declared mutation reported at the site it ran, the application reconciles that journal against
# the operations this tenant's profile and entitlement made reachable, and the tenant is read
# again afterwards - because a run whose commands all returned has proved only that they were
# accepted, and an intended change and a confirmed one are not the same claim.
if ($Apply) {
    $appliedOperation = @(
        $runtimeMutationPlan | Where-Object {
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

    $postChangeEvidenceName = 'postchange-{0}.json' -f $ChangeId
    $postChangeDecision = Test-BaselineExoPostChange -Operation $appliedOperation -Evidence $postChangeEvidenceName
    $exoPostChangeDecision = $postChangeDecision

    $mdoRegistry = @((Get-BaselineControlRegistry)[0] | Where-Object { [string]$_.ControlId -match '^MDO-00[6-9]$' })
    $mdoEvidence = @(Get-BaselineMdoPostChangeEvidence)
    $mdoAsOfUtc = [datetimeoffset]::UtcNow
    $mdoEvaluation = {
        param($Entry, $EvidenceRecord)

        switch ([string]$Entry.ControlId) {
            'MDO-006' {
                Test-ReportSubmissionControl -Evidence $EvidenceRecord `
                    -DesiredState $configuration.desiredState.defenderForOffice365.userSubmissions `
                    -SecOpsMailbox @($configuration.desiredState.defenderForOffice365.advancedDelivery.secOpsMailbox)
                break
            }
            'MDO-007' {
                Test-TenantAllowBlockListControl -Evidence $EvidenceRecord `
                    -DesiredState $configuration.desiredState.defenderForOffice365.tenantAllowBlockList -AsOf $mdoAsOfUtc
                break
            }
            'MDO-008' {
                Test-QuarantinePolicyControl -Evidence $EvidenceRecord `
                    -DesiredState $configuration.desiredState.defenderForOffice365.quarantinePolicies
                break
            }
            'MDO-009' {
                Test-PriorityAccountControl -Evidence $EvidenceRecord `
                    -DesiredState $configuration.desiredState.defenderForOffice365.impersonationProtection
                break
            }
            default { throw "MdoPostChangeEvaluatorUnknown: '$($Entry.ControlId)' has no post-change evaluator dispatch." }
        }
    }.GetNewClosure()
    $mdoAppliedOperation = @($appliedOperation | Where-Object {
            [string]$_.Area -in @('ReportSubmission', 'AdvancedDelivery', 'TenantAllowBlockList', 'Quarantine', 'ImpersonationProtection')
        })
    $mdoPostChangeDecision = Test-BaselineMdoPostChange -Operation $mdoAppliedOperation `
        -Registry $mdoRegistry -EvidenceByControl $mdoEvidence -Evaluation $mdoEvaluation `
        -AsOfUtc $mdoAsOfUtc -MaximumEvidenceAge ([timespan]::FromMinutes(15)) -Evidence $postChangeEvidenceName

    $postChangeDecision = [ordered]@{
        Permitted = ($exoPostChangeDecision.Permitted -and $mdoPostChangeDecision.Permitted)
        Evidence = $postChangeEvidenceName
        Observed = @($exoPostChangeDecision.Observed) + @($mdoPostChangeDecision.Observed)
        Finding = @($exoPostChangeDecision.Finding) + @($mdoPostChangeDecision.Finding)
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