function Initialize-AdapterDoubles {
    $global:adapterCalls = [Collections.Generic.List[object]]::new()
    $global:adapterReadFault = ''
    $global:adapterWriteFault = ''
    $global:adapterReadbackFault = ''
    $global:adapterState = @{
        TransportConfig = @(@{ Identity = 'Transport'; SmtpClientAuthenticationDisabled = $false; ExternalPostmasterAddress = 'old@example.test' })
        OrganizationConfig = @(@{ Identity = 'Organization'; AuditDisabled = $true; EwsEnabled = $true; EwsApplicationAccessPolicy = $null; EwsAllowList = @('old-agent') })
        ExternalInOutlook = @(@{ Identity = 'External'; Enabled = $false; AllowList = @('old.example') })
        HostedOutboundSpamFilterPolicy = @(@{ Identity = 'Default'; AutoForwardingMode = 'On' })
        RemoteDomain = @(@{ Identity = 'Default'; DomainName = '*'; AutoForwardEnabled = $true; AutoReplyEnabled = $true; AllowedOOFType = 'External'; DeliveryReportEnabled = $true; NDREnabled = $true })
        CASMailbox = @(@{ Identity = 'user@example.test'; PopEnabled = $true; ImapEnabled = $true })
        CASMailboxPlan = @(@{ Identity = 'PlanA'; PopEnabled = $true; ImapEnabled = $true })
        AcceptedDomain = @(@{ Identity = 'contoso.example'; Name = 'contoso.example'; DomainName = 'contoso.example'; DomainType = 'InternalRelay' })
        ReportSubmissionPolicy = @(@{ Identity = 'DefaultReportSubmissionPolicy'; EnableThirdPartyAddress = $true; EnableReportToMicrosoft = $false; ReportJunkToCustomizedAddress = $false; ReportNotJunkToCustomizedAddress = $false; ReportPhishToCustomizedAddress = $false; ReportJunkAddresses = @('old@example.test'); ReportNotJunkAddresses = @('old@example.test'); ReportPhishAddresses = @('old@example.test'); PreSubmitMessageEnabled = $false; PostSubmitMessageEnabled = $false })
        ReportSubmissionRule = @(@{ Identity = 'DefaultReportSubmissionRule'; ReportSubmissionPolicy = 'DefaultReportSubmissionPolicy'; State = 'Disabled'; SentTo = @('old@example.test') })
        SecOpsOverridePolicy = @(@{ Identity = 'SecOpsOverridePolicy'; SentTo = @('old@example.test') })
        ExoSecOpsOverrideRule = @(@{ Identity = 'SecOpsRule'; Mode = 'Enforce' })
        AntiPhishPolicy = @(@{ Identity = 'Contoso Impersonation Protection'; EnableTargetedUserProtection = $false; EnableTargetedDomainsProtection = $false; TargetedUsersToProtect = @(); TargetedDomainsToProtect = @(); ExcludedSenders = @('old@example.test'); ExcludedDomains = @('old.example'); SpoofQuarantineTag = 'Old' })
        AntiPhishRule = @(@{ Identity = 'Contoso Impersonation Protection Rule'; AntiPhishPolicy = 'Contoso Impersonation Protection'; State = 'Enabled'; RecipientDomainIs = @('contoso.example'); SentTo = @(); SentToMemberOf = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @(); ExceptIfRecipientDomainIs = @() })
        EOPProtectionPolicyRule = @(@{ Identity = 'Standard Preset Security Policy'; State = 'Disabled'; RecipientDomainIs = @('old.example'); ExceptIfSentToMemberOf = @(); ExceptIfSentTo = @() }, @{ Identity = 'Strict Preset Security Policy'; State = 'Disabled'; SentToMemberOf = @('old@example.test') })
        ATPProtectionPolicyRule = @(@{ Identity = 'Standard Preset Security Policy'; State = 'Disabled'; RecipientDomainIs = @('old.example'); ExceptIfSentToMemberOf = @(); ExceptIfSentTo = @() }, @{ Identity = 'Strict Preset Security Policy'; State = 'Disabled'; SentToMemberOf = @('old@example.test') })
        ATPBuiltInProtectionRule = @(@{ Identity = 'ATP Built-In Protection Rule'; ExceptIfRecipientDomainIs = @('old.example'); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @() })
        QuarantinePolicy = @(@{ Identity = 'Baseline-AdminOnlyAccess'; Name = 'Baseline-AdminOnlyAccess'; EndUserQuarantinePermissionsValue = 236 }, @{ Identity = 'Baseline-LimitedAccess'; Name = 'Baseline-LimitedAccess'; EndUserQuarantinePermissionsValue = 236 }, @{ Identity = 'DefaultGlobalTag'; Name = 'DefaultGlobalTag'; EndUserSpamNotificationFrequency = [timespan]::FromDays(3); IncludeMessagesFromBlockedSenderAddress = $true })
        HostedContentFilterPolicy = @(@{ Identity = 'Default'; HighConfidencePhishQuarantineTag = 'Old'; PhishQuarantineTag = 'Old'; HighConfidenceSpamQuarantineTag = 'Old'; SpamQuarantineTag = 'Old'; BulkQuarantineTag = 'Old'; SpoofQuarantineTag = 'Old' })
        MalwareFilterPolicy = @(@{ Identity = 'Default'; QuarantineTag = 'Old' })
        Mailbox = @(@{ Identity = 'user@example.test'; PrimarySmtpAddress = 'user@example.test'; ForwardingAddress = $null; ForwardingSmtpAddress = 'smtp:external@example.net' })
        InboxRule = @(@{ Identity = 'rule-1'; Mailbox = 'user@example.test'; Enabled = $true; ForwardTo = @('external@example.net'); ForwardAsAttachmentTo = @(); RedirectTo = @() })
        RoleAssignmentPolicy = @(@{ Identity = 'Default Policy'; IsDefault = $true })
        ManagementRoleAssignment = @(@{ Identity = 'GrantA'; Name = 'GrantA'; Role = 'My Custom Apps'; RoleAssignee = 'Default Policy'; RoleAssigneeType = 'RoleAssignmentPolicy'; Delegating = $false; RecipientWriteScope = 'Self'; ConfigWriteScope = 'None'; CustomRecipientWriteScope = $null; CustomConfigWriteScope = $null; ExclusiveRecipientWriteScope = $null; ExclusiveConfigWriteScope = $null })
        DkimSigningConfig = @(@{ Identity = 'contoso.example'; Domain = 'contoso.example'; Enabled = $false; KeySize = 2048; Status = 'Valid'; Selector1CNAME = 'selector1-contoso-example._domainkey.contoso.onmicrosoft.com'; Selector2CNAME = 'selector2-contoso-example._domainkey.contoso.onmicrosoft.com'; Selector1KeySize = 2048; Selector2KeySize = 2048 })
        TenantAllowBlockListItems = @(@{ Identity = 'block-1'; Value = 'blocked.example'; ListType = 'Sender'; Action = 'Block'; ExpirationDate = [datetimeoffset]::UtcNow.AddDays(80).ToUniversalTime().ToString('o'); Notes = 'Old governed block' })
    }
    $specifications = @(
        @{ Noun = 'TransportConfig'; Read = ''; Fields = '[bool]$SmtpClientAuthenticationDisabled,[string]$ExternalPostmasterAddress'; Target = '' },
        @{ Noun = 'OrganizationConfig'; Read = ''; Fields = '[bool]$AuditDisabled,[AllowNull()][object]$EwsEnabled,[AllowNull()][object]$EwsApplicationAccessPolicy,[string[]]$EwsAllowList,[string]$EwsAllowedAppIDs'; Target = '' },
        @{ Noun = 'ExternalInOutlook'; Read = ''; Fields = '[bool]$Enabled,[string[]]$AllowList'; Target = '' },
        @{ Noun = 'HostedOutboundSpamFilterPolicy'; Read = '[string]$Identity'; Fields = '[string]$AutoForwardingMode'; Target = '[Parameter(Mandatory)][string]$Identity' },
        @{ Noun = 'RemoteDomain'; Read = '[string]$Identity'; Fields = '[bool]$AutoForwardEnabled,[bool]$AutoReplyEnabled,[string]$AllowedOOFType,[bool]$DeliveryReportEnabled,[bool]$NDREnabled'; Target = '[Parameter(Mandatory)][string]$Identity' },
        @{ Noun = 'CASMailbox'; Read = '[string]$Identity,[string]$ResultSize'; Fields = '[bool]$PopEnabled,[bool]$ImapEnabled'; Target = '[Parameter(Mandatory)][string]$Identity' },
        @{ Noun = 'CASMailboxPlan'; Read = '[string]$Identity,[string]$ResultSize'; Fields = '[bool]$PopEnabled,[bool]$ImapEnabled'; Target = '[Parameter(Mandatory)][string]$Identity' },
        @{ Noun = 'AcceptedDomain'; Read = '[string]$Identity,[string]$ResultSize'; Fields = '[string]$DomainType'; Target = '[Parameter(Mandatory)][string]$Identity'; Create = '[Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][string]$DomainName' },
        @{ Noun = 'ReportSubmissionPolicy'; Read = '[string]$Identity'; Fields = '[bool]$EnableThirdPartyAddress,[bool]$EnableReportToMicrosoft,[bool]$ReportJunkToCustomizedAddress,[bool]$ReportNotJunkToCustomizedAddress,[bool]$ReportPhishToCustomizedAddress,[string[]]$ReportJunkAddresses,[string[]]$ReportNotJunkAddresses,[string[]]$ReportPhishAddresses,[bool]$PreSubmitMessageEnabled,[bool]$PostSubmitMessageEnabled'; Target = '[Parameter(Mandatory)][string]$Identity'; Create = '[Parameter(Mandatory)][string]$Name' },
        @{ Noun = 'ReportSubmissionRule'; Read = '[string]$Identity'; Fields = '[string[]]$SentTo'; Target = '[Parameter(Mandatory)][string]$Identity'; Toggle = $true },
        @{ Noun = 'SecOpsOverridePolicy'; Read = '[string]$Identity'; Fields = '[string[]]$AddSentTo,[string[]]$RemoveSentTo'; Target = '[Parameter(Mandatory)][string]$Identity' },
        @{ Noun = 'ExoSecOpsOverrideRule'; Read = '[string]$Identity,[string]$Policy'; ReadOnly = $true },
        @{ Noun = 'AntiPhishPolicy'; Read = '[string]$Identity'; Fields = '[bool]$EnableTargetedUserProtection,[bool]$EnableTargetedDomainsProtection,[string[]]$TargetedUsersToProtect,[string[]]$TargetedDomainsToProtect,[string[]]$ExcludedSenders,[string[]]$ExcludedDomains,[string]$SpoofQuarantineTag'; Target = '[Parameter(Mandatory)][string]$Identity'; Create = '[Parameter(Mandatory)][string]$Name' },
        @{ Noun = 'AntiPhishRule'; Read = '[string]$Identity'; ReadOnly = $true },
        @{ Noun = 'EOPProtectionPolicyRule'; Read = '[string]$Identity'; Fields = '[string[]]$RecipientDomainIs,[string[]]$ExceptIfSentToMemberOf,[string[]]$ExceptIfSentTo,[string[]]$SentToMemberOf'; Target = '[Parameter(Mandatory)][string]$Identity'; Toggle = $true },
        @{ Noun = 'ATPProtectionPolicyRule'; Read = '[string]$Identity'; Fields = '[string[]]$RecipientDomainIs,[string[]]$ExceptIfSentToMemberOf,[string[]]$ExceptIfSentTo,[string[]]$SentToMemberOf'; Target = '[Parameter(Mandatory)][string]$Identity'; Toggle = $true },
        @{ Noun = 'ATPBuiltInProtectionRule'; Read = '[string]$Identity'; Fields = '[string[]]$ExceptIfRecipientDomainIs,[string[]]$ExceptIfSentTo,[string[]]$ExceptIfSentToMemberOf'; Target = '[Parameter(Mandatory)][string]$Identity' },
        @{ Noun = 'QuarantinePolicy'; Read = '[string]$Identity'; Fields = '[int]$EndUserQuarantinePermissionsValue,[timespan]$EndUserSpamNotificationFrequency,[bool]$IncludeMessagesFromBlockedSenderAddress'; Target = '[Parameter(Mandatory)][string]$Identity'; Create = '[Parameter(Mandatory)][string]$Name' },
        @{ Noun = 'HostedContentFilterPolicy'; Read = '[string]$Identity'; Fields = '[string]$HighConfidencePhishQuarantineTag,[string]$PhishQuarantineTag,[string]$HighConfidenceSpamQuarantineTag,[string]$SpamQuarantineTag,[string]$BulkQuarantineTag,[string]$SpoofQuarantineTag'; Target = '[Parameter(Mandatory)][string]$Identity' },
        @{ Noun = 'MalwareFilterPolicy'; Read = '[string]$Identity'; Fields = '[string]$QuarantineTag'; Target = '[Parameter(Mandatory)][string]$Identity' },
        @{ Noun = 'Mailbox'; Read = '[string]$Identity,[string]$ResultSize'; Fields = '[AllowNull()][object]$ForwardingAddress,[AllowNull()][object]$ForwardingSmtpAddress'; Target = '[Parameter(Mandatory)][string]$Identity' },
        @{ Noun = 'InboxRule'; Read = '[string]$Identity,[Parameter(Mandatory)][string]$Mailbox,[switch]$IncludeHidden'; Fields = ''; Target = '[Parameter(Mandatory)][string]$Identity,[Parameter(Mandatory)][string]$Mailbox'; Toggle = $true },
        @{ Noun = 'RoleAssignmentPolicy'; Read = '[string]$Identity'; ReadOnly = $true },
        @{ Noun = 'ManagementRoleAssignment'; Read = '[string]$Identity'; Fields = ''; Target = '[Parameter(Mandatory)][string]$Identity'; Create = '[Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][string]$Role,[Parameter(Mandatory)][string]$Policy' },
        @{ Noun = 'DkimSigningConfig'; Read = '[string]$Identity'; Fields = '[bool]$Enabled'; Target = '[Parameter(Mandatory)][string]$Identity'; Create = '[Parameter(Mandatory)][string]$DomainName,[int]$KeySize' },
        @{ Noun = 'TenantAllowBlockListItems'; Read = '[Parameter(Mandatory)][ValidateSet("Sender","Url","FileHash")][string]$ListType,[string]$Entry'; Fields = '[switch]$Allow,[switch]$Block,[datetime]$ExpirationDate,[string]$Notes'; Target = '[Parameter(Mandatory)][ValidateSet("Sender","Url","FileHash")][string]$ListType,[Parameter(Mandatory)][string[]]$Entries'; Create = '[Parameter(Mandatory)][ValidateSet("Sender","Url","FileHash")][string]$ListType,[Parameter(Mandatory)][string[]]$Entries'; NoConfirm = $true }
    )
    $global:adapterCommands = [Collections.Generic.List[string]]::new()
    foreach ($spec in $specifications) {
        $verbs = @('Get')
        if (-not $spec['ReadOnly']) { $verbs += 'Set' }
        if ($spec['Create']) { $verbs += @('New','Remove') }
        if ($spec['Toggle']) { $verbs += @('Enable','Disable') }
        foreach ($verb in $verbs) {
            if ($spec.Noun -eq 'TenantAllowBlockListItems' -and $verb -eq 'Set') { continue }
            $name = "$verb-$($spec.Noun)"
            $declarations = switch ($verb) {
                Get { $spec.Read }
                New { @($spec.Create,$spec.Fields | Where-Object { $_ }) -join ',' }
                Set { @($spec.Target,$spec.Fields | Where-Object { $_ }) -join ',' }
                default { $spec.Target }
            }
            $binding = if ($verb -eq 'Get' -or $spec['NoConfirm']) { '[CmdletBinding()]' } else { '[CmdletBinding(SupportsShouldProcess)]' }
            $body = "$binding param($declarations) Invoke-OfflineAdapterCommand '$verb' '$($spec.Noun)' `$PSBoundParameters"
            Set-Item "Function:global:$name" ([scriptblock]::Create($body))
            $global:adapterCommands.Add($name)
        }
    }
    function global:Get-ConnectionInformation { [pscustomobject]@{ TenantID = '00000000-0000-0000-0000-000000000000'; State = 'Connected' } }
}

function global:Invoke-OfflineAdapterCommand {
    param($Verb, $Noun, $Bound)
    if ($Verb -eq 'Get' -and ($global:adapterReadFault -eq $Noun -or ($global:adapterReadbackFault -eq $Noun -and $global:adapterCalls.Count))) { throw "ChangeReadIncomplete: offline $Noun collection failure." }
    $rows = @($global:adapterState[$Noun])
    $selected = @($rows | Where-Object {
        (-not $Bound.ContainsKey('Identity') -or $_.Identity -eq $Bound.Identity) -and
        (-not $Bound.ContainsKey('Mailbox') -or $_.Mailbox -eq $Bound.Mailbox) -and
        (-not $Bound.ContainsKey('ListType') -or $_.ListType -eq $Bound.ListType) -and
        (-not $Bound.ContainsKey('Entries') -or $_.Value -in $Bound.Entries)
    })
    if ($Verb -eq 'Get') { foreach ($row in $selected) { [pscustomobject]$row.Clone() }; return }
    $global:adapterCalls.Add(@{ Command = "$Verb-$Noun"; Parameters = @{} + $Bound })
    if ($global:adapterWriteFault -eq "$Verb-$Noun") { throw "Offline write refused: $Verb-$Noun" }
    if ($Verb -eq 'New') {
        $identity = if ($Bound.ContainsKey('Name')) { $Bound.Name } elseif ($Bound.ContainsKey('DomainName')) { $Bound.DomainName } else { $Bound.Entries[0] }
        if (@($rows | Where-Object Identity -EQ $identity).Count) { throw 'Offline duplicate create.' }
        $row = @{ Identity = $identity }
        if ($Noun -eq 'ManagementRoleAssignment') {
            $row += @{ RoleAssignee = $Bound.Policy; RoleAssigneeType = 'RoleAssignmentPolicy'; Delegating = $false; RecipientWriteScope = 'Self'; ConfigWriteScope = 'None'; CustomRecipientWriteScope = $null; CustomConfigWriteScope = $null; ExclusiveRecipientWriteScope = $null; ExclusiveConfigWriteScope = $null }
        }
        if ($Noun -eq 'TenantAllowBlockListItems') { $row += @{ Value = $Bound.Entries[0]; ListType = $Bound.ListType; Action = $(if ($Bound['Allow']) { 'Allow' } else { 'Block' }); ExpirationDate = $Bound.ExpirationDate.ToUniversalTime().ToString('o') } }
        foreach ($field in $Bound.Keys) { if ($field -notin @('ErrorAction','Confirm','WhatIf','Policy','Entries','Allow','Block','ExpirationDate')) { $row[$field] = $Bound[$field] } }
        $global:adapterState[$Noun] += $row
        return
    }
    if ($selected.Count -ne 1) { throw "Offline target not unique: $Verb-$Noun ($($selected.Count))." }
    if ($Noun -eq 'SecOpsOverridePolicy' -and $Verb -eq 'Set') {
        $selected[0].SentTo = @(@($selected[0].SentTo | Where-Object { $_ -notin $Bound.RemoveSentTo }) + @($Bound.AddSentTo) | Where-Object { $_ } | Sort-Object -Unique)
        return
    }
    if ($Verb -eq 'Remove') { $global:adapterState[$Noun] = @($rows | Where-Object { $_ -ne $selected[0] }); return }
    if ($Verb -in @('Enable','Disable')) {
        if ($Noun -eq 'InboxRule') { $selected[0].Enabled = $Verb -eq 'Enable' } else { $selected[0].State = if ($Verb -eq 'Enable') { 'Enabled' } else { 'Disabled' } }
        return
    }
    foreach ($field in $Bound.Keys) {
        if ($field -notin @('Identity','Mailbox','Confirm','WhatIf','ErrorAction')) { $selected[0][$field] = $Bound[$field] }
    }
}

function New-StatefulAdapterFixture {
    param([string[]]$Scope, [switch]$Approved)
    $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory $directory
    $parameters = Get-Content (Join-Path $script:adapterRoot 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable -DateKind String
    $parameters.entitlement.verified = $true
    $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
    $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE')
    $parameters.entitlement.recipients = @(
        @{ address = "user@$($parameters.PRIMARY_SMTP_DOMAIN)"; servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE') }
        @{ address = $parameters.SECURITY_OPERATIONS_MAILBOX; servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE') }
    )
    $created = [datetimeoffset]::UtcNow
    $parameters.workflowOptions = @{ enableDkim = $true; tenantAllowBlockEntries = @(@{ entryType = 'Domain'; entryValue = 'blocked.example'; action = 'Block'; owner = 'SecOps'; ticket = 'CHG004'; createdDateTime = $created.ToString('o'); expirationDateTime = $created.AddDays(90).ToString('o'); justification = 'Approved test block' }) }
    $parameterPath = Join-Path $directory 'parameters.json'
    $parameters | ConvertTo-Json -Depth 30 | Set-Content $parameterPath
    $authorityPath = Join-Path $directory 'authority.json'
    @(@{ Identity = 'reviewer@example.test'; Subject = 'CN=Offline Adapter'; Authority = 'ExchangeOnlineChangeApproval' }) | ConvertTo-Json -AsArray | Set-Content $authorityPath
    $arguments = @{ ParameterPath = $parameterPath; ConfigurationPath = (Join-Path $script:adapterRoot 'config/exchange-only.v1.json'); ArtifactRoot = $directory; ChangeId = 'ADAPTER004'; RequestedBy = 'operator@example.test'; PreviewPath = (Join-Path $directory 'preview-ADAPTER004.json'); ApprovalPath = (Join-Path $directory 'approval-ADAPTER004.json'); AuthorizedSignerPath = $authorityPath }
    $configuration = Get-Content $arguments.ConfigurationPath -Raw | ConvertFrom-Json -AsHashtable
    $configuration.controls['MDO-006'].approval = @{ reference = 'OFFLINE-010'; owner = 'security'; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') }
    $arguments.ConfigurationPath = Join-Path $directory 'configuration.json'
    $configuration | ConvertTo-Json -Depth 60 | Set-Content $arguments.ConfigurationPath
    if ($Approved) {
        & $script:adapterCommand -Stage Preview @arguments -Scope $Scope -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Approve @arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
    }
    $arguments
}

function Invoke-AdapterRoundTrip {
    param($Arguments, [string[]]$Scope)
    & $script:adapterCommand -Stage Preview @Arguments -Scope $Scope -Confirm:$false | Out-Null
    & $script:adapterCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
    & $script:adapterCommand -Stage Validate @Arguments | Out-Null
    & (Join-Path $script:adapterRoot 'scripts/Deploy-ExchangeOnlineBaseline.ps1') @Arguments -Apply -SkipConnection -Confirm:$false | Out-Null
    $result = & (Join-Path $Arguments.ArtifactRoot 'rollback-ADAPTER004.ps1') -Apply -Confirm:$false
    $writes = $global:adapterCalls.Count
    $repeated = & $script:adapterCommand -Stage Rollback @Arguments -Apply -Confirm:$false
    @{ Status = $result.Status; RepeatedStatus = $repeated.Status; RepeatedWrites = $global:adapterCalls.Count - $writes }
}

function Get-AdapterSnapshot {
    $state = $global:adapterState | ConvertTo-Json -Depth 40 | ConvertFrom-Json -AsHashtable -DateKind String
    foreach ($row in $state.TenantAllowBlockListItems) {
        $row.Remove('Identity')
        $row.ExpirationDate = ([datetimeoffset]$row.ExpirationDate).UtcDateTime.ToString('o')
    }
    ConvertTo-CanonicalJson $state
}