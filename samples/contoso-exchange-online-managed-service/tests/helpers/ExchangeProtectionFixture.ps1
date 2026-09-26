function Get-ProtectionReferenceValues {
    param([ValidateSet('Standard','Strict')][string]$Level = 'Standard')
    $strict = $Level -eq 'Strict'
    $notify = 'DefaultFullAccessWithNotificationPolicy'
    $full = 'DefaultFullAccessPolicy'
    $values = @{
        MalwareFilter = @{
            EnableFileFilter = $true; FileTypeAction = 'Reject'; ZapEnabled = $true; QuarantineTag = 'AdminOnlyAccessPolicy'
            FileTypes = @('ace','ani','apk','app','appx','arj','bat','cab','cmd','com','deb','dex','dll','docm','elf','exe','hta','img','iso','jar','jnlp','kext','lha','lib','library','lnk','lzh','macho','msc','msi','msix','msp','mst','pif','ppa','ppam','reg','rev','scf','scr','sct','sys','uif','vb','vbe','vbs','vxd','wsc','wsf','wsh','xll','xz','z')
            EnableInternalSenderAdminNotifications = $false; InternalSenderAdminAddress = ''; EnableExternalSenderAdminNotifications = $false; ExternalSenderAdminAddress = ''; CustomNotifications = $false; CustomFromName = ''; CustomFromAddress = ''; CustomInternalSubject = ''; CustomInternalBody = ''; CustomExternalSubject = ''; CustomExternalBody = ''
        }
        HostedContentFilter = @{
            BulkThreshold = $(if ($strict) { 5 } else { 6 }); MarkAsSpamBulkMail = 'On'
            EnableLanguageBlockList = $false; LanguageBlockList = @(); EnableRegionBlockList = $false; RegionBlockList = @()
            SpamAction = $(if ($strict) { 'Quarantine' } else { 'MoveToJmf' }); SpamQuarantineTag = $(if ($strict) { $notify } else { $full })
            HighConfidenceSpamAction = 'Quarantine'; HighConfidenceSpamQuarantineTag = $notify; PhishSpamAction = 'Quarantine'; PhishQuarantineTag = $notify
            HighConfidencePhishAction = 'Quarantine'; HighConfidencePhishQuarantineTag = 'AdminOnlyAccessPolicy'
            BulkSpamAction = $(if ($strict) { 'Quarantine' } else { 'MoveToJmf' }); BulkQuarantineTag = $(if ($strict) { $notify } else { $full })
            BulkMovesEnabled = 'NotSet'; IntraOrgFilterState = 'Default'; QuarantineRetentionPeriod = 30; InlineSafetyTipsEnabled = $true; PhishZapEnabled = $true; SpamZapEnabled = $true
            AllowedSenders = @(); AllowedSenderDomains = @(); BlockedSenders = @(); BlockedSenderDomains = @(); TestModeAction = 'None'
        }
        HostedOutboundSpamFilter = @{
            RecipientLimitExternalPerHour = $(if ($strict) { 400 } else { 500 }); RecipientLimitInternalPerHour = $(if ($strict) { 800 } else { 1000 }); RecipientLimitPerDay = $(if ($strict) { 800 } else { 1000 })
            ActionWhenThresholdReached = 'BlockUser'; AutoForwardingMode = 'Off'; BccSuspiciousOutboundMail = $false; BccSuspiciousOutboundAdditionalRecipients = @(); NotifyOutboundSpam = $false; NotifyOutboundSpamRecipients = @()
        }
        AntiPhish = @{
            EnableSpoofIntelligence = $true; HonorDmarcPolicy = $true; DmarcQuarantineAction = 'Quarantine'; DmarcRejectAction = 'Reject'
            AuthenticationFailAction = $(if ($strict) { 'Quarantine' } else { 'MoveToJmf' }); SpoofQuarantineTag = $(if ($strict) { $notify } else { $full })
            EnableFirstContactSafetyTips = $true; EnableUnauthenticatedSender = $true; EnableViaTag = $true
            PhishThresholdLevel = $(if ($strict) { 4 } else { 3 }); EnableTargetedUserProtection = $true; EnableOrganizationDomainsProtection = $true; EnableTargetedDomainsProtection = $true
            TargetedUsersToProtect = @('Security;secops@contoso.example'); TargetedDomainsToProtect = @('contoso.example'); ExcludedSenders = @(); ExcludedDomains = @()
            EnableMailboxIntelligence = $true; EnableMailboxIntelligenceProtection = $true; TargetedUserProtectionAction = 'Quarantine'; TargetedDomainProtectionAction = 'Quarantine'
            TargetedUserQuarantineTag = $notify; TargetedDomainQuarantineTag = $notify; MailboxIntelligenceProtectionAction = $(if ($strict) { 'Quarantine' } else { 'MoveToJmf' }); MailboxIntelligenceQuarantineTag = $(if ($strict) { $notify } else { $full })
            EnableSimilarUsersSafetyTips = $true; EnableSimilarDomainsSafetyTips = $true; EnableUnusualCharactersSafetyTips = $true
        }
        SafeAttachment = @{
            Enable = $true; Action = 'Block'; QuarantineTag = 'AdminOnlyAccessPolicy'; Redirect = $false; RedirectAddress = ''
            EnableBlockingEncryptedAttachments = $false; ExcludedTypesFromBlockingEncryptedAttachments = @(); QuarantineTagForBlockingEncryptedAttachments = $notify
        }
        SafeLinks = @{
            EnableSafeLinksForEmail = $true; EnableForInternalSenders = $true; ScanUrls = $true; DeliverMessageAfterScan = $true; DisableURLRewrite = $false
            DoNotRewriteUrls = @(); TrackClicks = $true; AllowClickThrough = $false; EnableOrganizationBranding = $false; CustomNotificationText = ''; UseTranslatedNotificationText = $false
        }
    }
    foreach ($field in @('IncreaseScoreWithImageLinks','IncreaseScoreWithNumericIps','IncreaseScoreWithRedirectToOtherPort','IncreaseScoreWithBizOrInfoUrls','MarkAsSpamEmptyMessages','MarkAsSpamEmbedTagsInHtml','MarkAsSpamJavaScriptInHtml','MarkAsSpamFormTagsInHtml','MarkAsSpamFramesInHtml','MarkAsSpamWebBugsInHtml','MarkAsSpamObjectTagsInHtml','MarkAsSpamSensitiveWordList','MarkAsSpamSpfRecordHardFail','MarkAsSpamFromAddressAuthFail','MarkAsSpamNdrBackscatter')) { $values.HostedContentFilter[$field] = 'Off' }
    $values
}

function Add-ProtectionGovernanceFixture {
    param($Fixture, $Parameters)
    $raw = $Fixture.Raw
    $configuration = $Fixture.Configuration
    $domain = $Parameters.PRIMARY_SMTP_DOMAIN
    $secops = $Parameters.SECURITY_OPERATIONS_MAILBOX
    $addresses = @("user@$domain", $secops)
    $approval = @{ reference = 'SYNTHETIC-OFFLINE-010'; owner = $secops; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') }
    $standard = Get-ProtectionReferenceValues Standard
    $strict = Get-ProtectionReferenceValues Strict
    foreach ($values in @($standard.AntiPhish,$strict.AntiPhish)) {
        $values.TargetedUsersToProtect = @("SecOps;$secops")
        $values.TargetedDomainsToProtect = @($domain)
    }
    foreach ($family in $standard.Keys) {
        $policies = @()
        foreach ($name in @('Default','Standard Preset Security Policy','Strict Preset Security Policy')) {
            if ($family -eq 'HostedOutboundSpamFilter' -and $name -ne 'Default') { continue }
            $values = if ($name -eq 'Strict Preset Security Policy') { $strict[$family].Clone() } else { $standard[$family].Clone() }
            $values.Name = $name; $values.Identity = $name; $values.IsDefault = $name -eq 'Default'
            if ($family -in @('SafeLinks','SafeAttachment') -and $name -eq 'Default') { $values.Name = 'Built-In Protection Policy'; $values.Identity = $values.Name }
            $policies += $values
        }
        $raw["Get-${family}Policy"] = @{ Items = $policies }
        if ($family -ne 'AntiPhish') { $raw["Get-${family}Rule"] = @{ Items = @() } }
    }
    $custom = $standard.AntiPhish.Clone(); $custom.Name = 'Contoso Impersonation'; $custom.Identity = $custom.Name; $custom.IsDefault = $false
    $raw['Get-AntiPhishPolicy'].Items += $custom
    $raw['Get-AntiPhishRule'].Items[0].Priority = 0
    foreach ($kind in @('EOP','ATP')) {
        foreach ($level in @('Standard','Strict')) {
            $rule = $raw["Get-${kind}ProtectionPolicyRule"].ByIdentity["$level Preset Security Policy"][0]
            foreach ($field in @('SentTo','SentToMemberOf','RecipientDomainIs','ExceptIfSentTo','ExceptIfSentToMemberOf','ExceptIfRecipientDomainIs')) { if (-not $rule.ContainsKey($field)) { $rule[$field] = @() } }
            if ($level -eq 'Standard') { $rule.ExceptIfSentTo = @() }
        }
    }
    $raw['Get-Recipient'] = @{ Items = @($addresses | ForEach-Object { @{ Identity = $_; PrimarySmtpAddress = $_; RecipientTypeDetails = 'UserMailbox' } }) }
    $raw['Get-DistributionGroupMember'] = @{ Items = @() }
    $configuration.controls['MDO-001'].approval = $approval.Clone()
    $configuration.controls['MDO-001'].recipientMatrix = @($addresses | ForEach-Object { @{ address = $_; defender = $true; level = 'Standard'; expectedPolicy = 'Standard Preset Security Policy' } })
    $configuration.controls['MDO-001'].excludedSecOpsMailbox = @()
    $configuration.controls['MDO-006'].approval = $approval.Clone()
    $Parameters.entitlement.recipients = @($addresses | ForEach-Object { @{ address = $_; servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE') } })
    $raw['Get-Mailbox'].ByIdentity = @{
        $secops = @(@{ Identity = $secops; PrimarySmtpAddress = $secops; RecipientTypeDetails = 'SharedMailbox'; ForwardingAddress = $null; ForwardingSmtpAddress = $null; DeliverToMailboxAndForward = $false })
        "user@$domain" = @($raw['Get-Mailbox'].Items[0])
        'Mailbox One' = @($raw['Get-Mailbox'].Items[0])
    }
    $raw['Get-ReportSubmissionPolicy'].Items[0].PreSubmitMessageEnabled = $true
    $raw['Get-ReportSubmissionPolicy'].Items[0].PostSubmitMessageEnabled = $true
    $Parameters.reportingEvidence = @{
        mailbox = $secops; approval = $approval.Clone(); dlp = @{ mailbox = $secops; status = 'NotApplicable'; approval = $approval.Clone() }
        deliveries = @(foreach ($category in @('Junk','NotJunk','Phish')) {
            @{ category = $category; recipient = $secops; reporter = "user@$domain"; messageId = "$category-message"; microsoftSubmissionId = "$category-submission"; feedbackMessageId = "$category-feedback"; receivedAt = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o'); originalMessagePreserved = $true }
        })
    }
    foreach ($category in $configuration.controls['MDO-008'].categoryPermissions) { if ($category.accessLevel -ne 'AdminOnlyAccess') { $category.accessLevel = 'FullAccess' } }
    $raw['Get-QuarantinePolicy'].ByType.QuarantinePolicy += @(
        @{ Name = 'DefaultFullAccessPolicy'; QuarantinePolicyType = 'QuarantinePolicy'; EndUserQuarantinePermissionsValue = 236 }
        @{ Name = 'DefaultFullAccessWithNotificationPolicy'; QuarantinePolicyType = 'QuarantinePolicy'; EndUserQuarantinePermissionsValue = 236 }
    )
}

function New-ProtectionFixture {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $parameters = Get-Content (Join-Path $sampleRoot 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
    . (Join-Path $PSScriptRoot 'ExchangeGovernanceRawFixture.ps1')
    $fixture = New-ExchangeGovernanceRawFixture $parameters
    $raw = $fixture.Raw
    $standard = Get-ProtectionReferenceValues Standard
    $strict = Get-ProtectionReferenceValues Strict
    $addresses = @('user@contoso.example','strict@contoso.example','custom@contoso.example','default@contoso.example','secops@contoso.example')
    $configuration = $fixture.Configuration
    $configuration.controls['MDO-001'].recipientMatrix = @(
        @{ address = $addresses[0]; level = 'Standard'; defender = $true; expectedPolicy = 'Standard Preset Security Policy' }
        @{ address = $addresses[1]; level = 'Strict'; defender = $true; expectedPolicy = 'Strict Preset Security Policy' }
        @{ address = $addresses[2]; level = 'Standard'; defender = $true; expectedPolicy = 'Custom email' }
        @{ address = $addresses[3]; level = 'Standard'; defender = $true; expectedPolicy = 'Default' }
        @{ address = $addresses[4]; level = 'Standard'; defender = $true; expectedPolicy = 'Default' }
    )
    $configuration.controls['MDO-001'].settingExceptions = @()
    $configuration.controls['MDO-001'].approval = @{ reference = 'OFFLINE-010'; owner = 'security@contoso.example'; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') }
    $parameters.entitlement.verified = $true
    $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
    $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE')
    $parameters.entitlement.recipients = @($addresses | ForEach-Object { @{ address = $_; servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE') } })
    $raw['Get-Recipient'] = @{ Items = @($addresses | ForEach-Object { @{ Identity = $_; PrimarySmtpAddress = $_; RecipientTypeDetails = 'UserMailbox' } }) }
    $raw['Get-DistributionGroupMember'] = @{ Items = @(@{ Identity = $addresses[1]; PrimarySmtpAddress = $addresses[1]; RecipientType = 'UserMailbox' }) }
    foreach ($noun in @('EOPProtectionPolicyRule','ATPProtectionPolicyRule')) {
        foreach ($level in @('Standard','Strict')) {
            $rule = $raw["Get-$noun"].ByIdentity["$level Preset Security Policy"][0]
            foreach ($field in @('SentTo','SentToMemberOf','RecipientDomainIs','ExceptIfSentTo','ExceptIfSentToMemberOf','ExceptIfRecipientDomainIs')) { if (-not $rule.ContainsKey($field)) { $rule[$field] = @() } }
            if ($level -eq 'Standard') { $rule.ExceptIfSentTo = @($addresses[2],$addresses[3],$addresses[4]) }
        }
    }
    $configuration.controls['MDO-001'].excludedSecOpsMailbox = @($addresses[2],$addresses[3],$addresses[4])
    foreach ($family in $standard.Keys) {
        $policies = @()
        foreach ($name in @('Standard Preset Security Policy','Strict Preset Security Policy','Custom email','Default')) {
            if ($family -eq 'HostedOutboundSpamFilter' -and $name -like '*Preset*') { continue }
            $values = if ($name -eq 'Strict Preset Security Policy') { $strict[$family].Clone() } else { $standard[$family].Clone() }
            $values.Name = $name; $values.Identity = $name; $values.IsDefault = $name -eq 'Default'
            $policies += $values
        }
        if ($family -in @('SafeLinks','SafeAttachment')) { $policies[-1].Name = 'Built-In Protection Policy'; $policies[-1].Identity = 'Built-In Protection Policy' }
        if ($family -eq 'SafeLinks') {
            $policies[-1].EnableForInternalSenders = $false
            $policies[-1].DisableURLRewrite = $true
            $policies[-1].AllowClickThrough = $true
        }
        if ($family -eq 'HostedOutboundSpamFilter') { $policy = $strict[$family].Clone(); $policy.Name = 'Strict outbound'; $policy.Identity = 'Strict outbound'; $policy.IsDefault = $false; $policies += $policy }
        $raw["Get-${family}Policy"] = @{ Items = $policies }
        $rule = @{ Name = 'Custom email rule'; Identity = 'Custom email rule'; State = 'Enabled'; Priority = 1; SentTo = @($addresses[2]); SentToMemberOf = @(); RecipientDomainIs = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @(); ExceptIfRecipientDomainIs = @() }
        $rule["${family}Policy"] = 'Custom email'
        if ($family -eq 'HostedOutboundSpamFilter') {
            $rule["${family}Policy"] = 'Strict outbound'; $rule.From = @($addresses[1]); $rule.FromMemberOf = @(); $rule.SenderDomainIs = @(); $rule.ExceptIfFrom = @(); $rule.ExceptIfFromMemberOf = @(); $rule.ExceptIfSenderDomainIs = @()
        }
        $raw["Get-${family}Rule"] = @{ Items = @($rule) }
    }
    @{ Context = @{ Configuration = $configuration; Parameters = $parameters; Entitlement = $parameters.entitlement }; Raw = $raw }
}

function Invoke-ProtectionRawRegistry {
    param($Fixture, $Module)
    & $Module {
        param($context, $protectionRawFixture)
        $context.Configuration = Convert-BaselinePlaceholderNode $context.Configuration $context.Parameters
        $installedCommands = @($protectionRawFixture.Keys)
        $originalFunctions = @{}
        foreach ($command in $installedCommands) {
            $original = Microsoft.PowerShell.Management\Get-Item "Function:\$command" -ErrorAction SilentlyContinue
            if ($null -ne $original) {
                $originalFunctions[$command] = $original.ScriptBlock
            }
            $body = @'
            [CmdletBinding()]
            param($Identity,$ResultSize,$QuarantinePolicyType,$Policy,$ListType,[switch]$Allow,[switch]$Block,$Mailbox,[switch]$IncludeHidden,[switch]$RetrieveEwsOperationAccessPolicy,[switch]$GetEffectiveUsers,[switch]$InactiveMailboxOnly,[switch]$SoftDeletedMailbox,[switch]$IncludeSoftDeletedRecipients,[switch]$ExtendedProperties,$Sender,$Recipient)
            $response = $protectionRawFixture[$MyInvocation.MyCommand.Name]
            if ($response['Error']) { throw $response['Error'] }
            if ($response['Warning']) { Write-Warning $response['Warning'] }
            $items = $response['Items']
            if ($response['ByIdentity'] -and $Identity) { $items = $response['ByIdentity'][$Identity] }
            elseif ($Identity -and $MyInvocation.MyCommand.Name -notin @('Get-DistributionGroupMember','Get-RoleGroupMember','Export-MailboxDiagnosticLogs','Get-MailboxStatistics')) { $items = @($items | Where-Object { $_['Identity'] -eq $Identity -or $_['Name'] -eq $Identity -or $_['PrimarySmtpAddress'] -eq $Identity }) }
            if ($response['ByType'] -and $QuarantinePolicyType) { $items = $response['ByType'][$QuarantinePolicyType] }
            if ($GetEffectiveUsers) { $items = $response['Effective'] }
            if ($InactiveMailboxOnly) { $items = $response['Inactive'] }
            if ($SoftDeletedMailbox) { $items = $response['SoftDeleted'] }
            foreach ($item in $items) { [pscustomobject]$item }
'@
            Set-Item "Function:$command" ([scriptblock]::Create($body).GetNewClosure())
        }
        try {
            @(Invoke-BaselineExchangeRegistry $context)
        }
        finally {
            foreach ($command in $installedCommands) {
                if ($originalFunctions.ContainsKey($command)) {
                    Set-Item "Function:$command" $originalFunctions[$command]
                }
                else {
                    Remove-Item "Function:$command" -ErrorAction SilentlyContinue
                }
            }
        }
    } $Fixture.Context $Fixture.Raw
}