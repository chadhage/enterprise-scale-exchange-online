function ConvertTo-ApprovedAdapterValue {
    param($Value, [string]$Type, [string]$Field)
    if ($null -eq $Value) {
        if ($Type -like 'Nullable*') { return $null }
        if ($Type -eq 'Strings') { return ,@() }
        throw "ChangeReadIncomplete: $Field cannot be null."
    }
    switch ($Type) {
        Boolean { if ($Value -isnot [bool]) { throw "ChangeReadIncomplete: $Field must be Boolean." }; return $Value }
        NullableBoolean { if ($Value -isnot [bool]) { throw "ChangeReadIncomplete: $Field must be Boolean or null." }; return $Value }
        Integer { if ($Value -isnot [int] -and $Value -isnot [long]) { throw "ChangeReadIncomplete: $Field must be integer." }; return [long]$Value }
        Strings {
            $result = @($Value | ForEach-Object {
                if ($_ -isnot [string] -and $_.GetType().IsPrimitive) { throw "ChangeReadIncomplete: $Field must contain strings." }
                [string]$_
            } | Sort-Object -Unique)
            return ,$result
        }
        Duration { try { return ([timespan]$Value).ToString('c') } catch { throw "ChangeReadIncomplete: $Field must be a TimeSpan." } }
        DateTime { try { return ([datetimeoffset]$Value).ToUniversalTime().ToString('o') } catch { throw "ChangeReadIncomplete: $Field must be an instant." } }
        default {
            if ($Value -is [bool] -or $Value -is [ValueType] -and $Value -isnot [enum]) { throw "ChangeReadIncomplete: $Field must be text." }
            return [string]$Value
        }
    }
}

function New-ApprovedAdapterDefinition {
    param([string]$Adapter, [string]$Noun, [hashtable]$Target, [hashtable]$Desired, [hashtable]$Types,
        [switch]$Create, [switch]$Delete, [switch]$Toggle, [hashtable]$CreateTarget = @{})
    @{ Adapter = $Adapter; Get = "Get-$Noun"; Set = "Set-$Noun"; New = $(if ($Create -or $Delete) { "New-$Noun" }); Remove = $(if ($Create -or $Delete) { "Remove-$Noun" }); Target = $Target; CreateTarget = $CreateTarget; Desired = $Desired; Types = $Types; Delete = [bool]$Delete; Toggle = [bool]$Toggle; Noun = $Noun }
}

function Get-ApprovedAdapterCollection {
    param([string]$Command, [hashtable]$Arguments = @{}, [string[]]$Required = @('Identity'))
    $rows = @(& $Command @Arguments -ErrorAction Stop)
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $rows) {
        foreach ($field in $Required) {
            if (-not (Test-BaselineNodeMember $row $field) -or [string]::IsNullOrWhiteSpace([string]$row.$field)) { throw "ChangeReadIncomplete: $Command omitted $field." }
        }
        if ($Required.Count -gt 0 -and -not $seen.Add([string]$row.($Required[0]))) { throw "ChangeReadIncomplete: $Command returned duplicate identities." }
    }
    return ,$rows
}

function Get-ApprovedAdapterDefinitions {
    param($Context, [string[]]$Scope, $Approved, [switch]$DesiredOnly)
    $controls = $Context.Configuration.controls
    $parameters = $Context.Parameters
    $options = $parameters['workflowOptions']
    if ($null -eq $options) { $options = @{} }
    foreach ($key in $options.Keys) { if ($key -cnotin @('enableDkim','tenantAllowBlockEntries')) { throw "ChangeOptionsInvalid: unsupported option $key." } }
    if ($options.ContainsKey('enableDkim') -and $options.enableDkim -isnot [bool]) { throw 'ChangeOptionsInvalid: enableDkim must be Boolean.' }
    $fixed = {
        param($Adapter, $Noun, $Target, $Desired, $Types, [bool]$Create = $false, $CreateTarget = @{})
        New-ApprovedAdapterDefinition $Adapter $Noun $Target $Desired $Types -Create:$Create -CreateTarget $CreateTarget
    }
    $targets = {
        param($Adapter, $Command, $Arguments = @{}, $Required = @('Identity'))
        if ($null -ne $Approved) {
            foreach ($operation in @($Approved | Where-Object { $_.OperationId -clike "$Adapter-*" })) {
                $target = ConvertFrom-Json -InputObject $operation.Identity -AsHashtable
                if (-not $target.ContainsKey('Identity') -or [string]::IsNullOrWhiteSpace([string]$target.Identity)) { throw 'ChangeOperationMismatch: target Identity is required.' }
                $target
            }
        } else {
            foreach ($row in (Get-ApprovedAdapterCollection $Command $Arguments $Required)) { @{ Identity = [string]$row.Identity } }
        }
    }
    foreach ($area in $Scope) {
        switch -CaseSensitive ($area) {
            GovernanceMailboxPolicy {
                $settings = $controls['EXO-010']
                Assert-ExchangeGovernanceApproval (Get-BaselineRecordMember $settings approval) ([datetimeoffset]::UtcNow)
                if (@($settings.mailboxPolicies).Count -eq 0) { throw 'ChangeOptionsInvalid: approved mailbox policy bindings are required.' }
                foreach ($binding in $settings.mailboxPolicies) {
                    if ([string]::IsNullOrWhiteSpace($binding.mailbox) -or [string]::IsNullOrWhiteSpace($binding.policy)) { throw 'ChangeOptionsInvalid: mailbox and role policy are required.' }
                    & $fixed GovernanceMailboxPolicy Mailbox @{ Identity = [string]$binding.mailbox } @{ RoleAssignmentPolicy = [string]$binding.policy } @{ RoleAssignmentPolicy = 'String' }
                }
            }
            GovernanceMrm {
                $settings = $controls['GOV-003']
                Assert-ExchangeGovernanceApproval (Get-BaselineRecordMember $settings approval) ([datetimeoffset]::UtcNow)
                if ($settings.policyType -cne 'ExchangeMRM') { throw 'PolicyTypeInvalid: only Exchange MRM lifecycle settings are supported.' }
                if ([string]::IsNullOrWhiteSpace($settings.policyName) -or @($settings.tags).Count -eq 0 -or @($settings.mailboxEntitlement).Count -eq 0) { throw 'ChangeOptionsInvalid: explicit policy, tags and mailbox inventory are required.' }
                foreach ($tag in $settings.tags) {
                    if ([string]::IsNullOrWhiteSpace($tag.name) -or $tag.enabled -isnot [bool] -or $tag.ageDays -lt 0 -or $tag.action -cnotin @('MoveToArchive','DeleteAndAllowRecovery','PermanentlyDelete')) { throw 'ChangeOptionsInvalid: invalid approved MRM tag semantics.' }
                    $definition = & $fixed GovernanceMrmTag RetentionPolicyTag @{ Identity = [string]$tag.name } @{ RetentionAction = $tag.action; AgeLimitForRetention = [timespan]::FromDays($tag.ageDays).ToString('c'); RetentionEnabled = $tag.enabled } @{ RetentionAction = 'String'; AgeLimitForRetention = 'Duration'; RetentionEnabled = 'Boolean' }
                    $definition.Guard = @{ Type = [string]$tag.type }
                    $definition
                }
                & $fixed GovernanceMrmPolicy RetentionPolicy @{ Identity = [string]$settings.policyName } @{ RetentionPolicyTagLinks = @($settings.tags.name) } @{ RetentionPolicyTagLinks = 'Strings' }
                foreach ($mailbox in $settings.mailboxEntitlement) {
                    if ([string]::IsNullOrWhiteSpace($mailbox.identity)) { throw 'ChangeOptionsInvalid: explicit MRM mailbox identity is required.' }
                    if (@($settings.tags | Where-Object { $_.enabled -and $_.action -ceq 'MoveToArchive' }).Count -and ($mailbox.archive -isnot [bool] -or -not $mailbox.archive)) { throw 'ArchiveNotEntitled: archive entitlement is required for every target.' }
                    & $fixed GovernanceMrmMailbox Mailbox @{ Identity = [string]$mailbox.identity } @{ RetentionPolicy = [string]$settings.policyName } @{ RetentionPolicy = 'NullableString' }
                }
            }
            GovernanceEncryption {
                $settings = $controls['GOV-005']
                Assert-ExchangeGovernanceApproval (Get-BaselineRecordMember $settings approval) ([datetimeoffset]::UtcNow)
                if ($settings.decryptionApproval.transport -cne $settings.transportDecryptionSetting -or $settings.decryptionApproval.journal -isnot [bool] -or $settings.decryptionApproval.journal -ne $settings.journalReportDecryptionEnabled) { throw 'DecryptionUnapproved: explicit matching transport and journal authorization is required.' }
                if (@($settings.messageClasses).Count -eq 0) { throw 'ChangeOptionsInvalid: approved encryption message classes are required.' }
                & $fixed GovernanceEncryptionIrm IRMConfiguration @{} @{ InternalLicensingEnabled = $settings.internalLicensingEnabled; AzureRMSLicensingEnabled = $settings.azureRmsLicensingEnabled; TransportDecryptionSetting = $settings.transportDecryptionSetting; JournalReportDecryptionEnabled = $settings.journalReportDecryptionEnabled } @{ InternalLicensingEnabled = 'Boolean'; AzureRMSLicensingEnabled = 'Boolean'; TransportDecryptionSetting = 'String'; JournalReportDecryptionEnabled = 'Boolean' }
                foreach ($class in $settings.messageClasses) {
                    if ($class.entitled -isnot [bool] -or -not $class.entitled) { throw 'EncryptionNotEntitled: each approved flow requires entitlement.' }
                    foreach ($field in @('rule','name','header','template','sender')) { if ([string]::IsNullOrWhiteSpace([string]$class[$field])) { throw "ChangeOptionsInvalid: encryption $field is required." } }
                    if (@($class.recipients).Count -eq 0) { throw 'ChangeOptionsInvalid: encryption recipients are required.' }
                    $definition = & $fixed GovernanceEncryptionRule TransportRule @{ Identity = [string]$class.rule } @{ Mode = 'Enforce'; HeaderContainsMessageHeader = $class.header; HeaderContainsWords = @($class.name); SentTo = @($class.recipients); ApplyRightsProtectionTemplate = $class.template } @{ Mode = 'String'; HeaderContainsMessageHeader = 'NullableString'; HeaderContainsWords = 'Strings'; SentTo = 'Strings'; ApplyRightsProtectionTemplate = 'NullableString' }
                    $definition.Guard = @{ State = 'Enabled'; RemoveOME = $false; RemoveOMEv2 = $false }
                    $definition
                }
            }
            Organization {
                $desired = @{ AuditDisabled = -not $controls['EXO-006'].mailboxAuditingDefault }
                $types = @{ AuditDisabled = 'Boolean'; EwsEnabled = 'NullableBoolean'; EwsApplicationAccessPolicy = 'NullableString'; EwsAllowList = 'Strings' }
                $ews = Resolve-BaselineEwsPolicy $controls['EXO-009']
                foreach ($key in $ews.Keys) { $desired[$key] = $ews[$key] }
                if ($ews.Contains('EwsAllowedAppIDs')) { $types.EwsAllowedAppIDs = 'NullableString' }
                if ($ews.EwsEnabled -and -not $DesiredOnly) {
                    $admission = Test-BaselineEwsState -DesiredState $controls['EXO-009'] -ObservedState @{ OrganizationConfig = $ews; CasMailbox = @(Get-CASMailbox -ResultSize Unlimited -ErrorAction Stop) }
                    if ($admission.Status -ne 'Pass') { throw $admission.Reason }
                }
                & $fixed Organization OrganizationConfig @{} $desired $types
            }
            ExternalSender { & $fixed ExternalSender ExternalInOutlook @{} @{ Enabled = $true; AllowList = @($controls['EXO-007'].allowList) } @{ Enabled = 'Boolean'; AllowList = 'Strings' } }
            OutboundSpam { & $fixed OutboundSpam HostedOutboundSpamFilterPolicy @{ Identity = 'Default' } @{ AutoForwardingMode = $controls['EXO-004'].automaticExternalForwarding } @{ AutoForwardingMode = 'String' } }
            RemoteDomains {
                $remote = $controls['EXO-008']
                $oof = Resolve-BaselineRemoteDomainOofType $remote
                if (-not $DesiredOnly) {
                    $rows = Get-ApprovedAdapterCollection Get-RemoteDomain @{} @('Identity','DomainName','AllowedOOFType')
                    if (@($rows | Where-Object { $_.Identity -ieq 'Default' -and $_.DomainName -eq '*' }).Count -ne 1) { throw 'ChangeReadIncomplete: wildcard Default remote domain is required.' }
                    if (@($rows | Where-Object { $_.Identity -ine 'Default' -and $_.AllowedOOFType -ine $oof }).Count) { throw 'RemoteDomainOverrideConflict: resolve unapproved OOF overrides first.' }
                }
                & $fixed RemoteDomains RemoteDomain @{ Identity = 'Default' } @{ AutoForwardEnabled = $remote.autoForwardEnabled; AutoReplyEnabled = $remote.autoReplyEnabled; AllowedOOFType = $oof; DeliveryReportEnabled = $remote.deliveryReportEnabled; NDREnabled = $remote.nonDeliveryReportEnabled } @{ AutoForwardEnabled = 'Boolean'; AutoReplyEnabled = 'Boolean'; AllowedOOFType = 'String'; DeliveryReportEnabled = 'Boolean'; NDREnabled = 'Boolean' }
            }
            { $_ -cin @('MailboxProtocols','MailboxPlans') } {
                $noun = if ($area -ceq 'MailboxProtocols') { 'CASMailbox' } else { 'CASMailboxPlan' }
                foreach ($target in (& $targets $area "Get-$noun" @{ ResultSize = 'Unlimited' })) {
                    & $fixed $area $noun $target @{ PopEnabled = $controls['EXO-009'].popEnabledByDefault; ImapEnabled = $controls['EXO-009'].imapEnabledByDefault } @{ PopEnabled = 'Boolean'; ImapEnabled = 'Boolean' }
                }
            }
            AcceptedDomains {
                & $fixed AcceptedDomains AcceptedDomain @{ Identity = [string]$parameters.PRIMARY_SMTP_DOMAIN } @{ DomainType = $controls['EXO-001'].domainType } @{ DomainType = 'String' } $true @{ Name = $parameters.PRIMARY_SMTP_DOMAIN; DomainName = $parameters.PRIMARY_SMTP_DOMAIN }
            }
            ReportSubmission {
                $settings = $controls['MDO-006']
                Assert-ExchangeGovernanceApproval (Get-BaselineRecordMember $settings approval) ([datetimeoffset]::UtcNow)
                if ($settings.reportingMailbox -notmatch '^[^@\s*]+@[^@\s*]+\.[^@\s*]+$' -or $settings.reportingDestination -cne 'MicrosoftAndCustomMailbox' -or -not $settings.microsoftReportMessageButton -or -not $settings.sendCopyToSecOpsMailbox -or -not $settings.sendReportedMessagesToMicrosoft) { throw 'ChangeReportingContract: the supported workflow requires built-in email reporting to Microsoft and one exact Exchange mailbox.' }
                $desired = @{ EnableThirdPartyAddress = $false; EnableReportToMicrosoft = $true; ReportJunkToCustomizedAddress = $true; ReportNotJunkToCustomizedAddress = $true; ReportPhishToCustomizedAddress = $true; PreSubmitMessageEnabled = $settings.preSubmitMessageEnabled; PostSubmitMessageEnabled = $settings.postSubmitMessageEnabled }
                $types = @{}; foreach ($field in $desired.Keys) { $types[$field] = 'Boolean' }
                foreach ($field in @('ReportJunkAddresses','ReportNotJunkAddresses','ReportPhishAddresses')) { $desired[$field] = @($settings.reportingMailbox); $types[$field] = 'Strings' }
                & $fixed ReportSubmission ReportSubmissionPolicy @{ Identity = 'DefaultReportSubmissionPolicy' } $desired $types
                $definition = & $fixed ReportSubmissionRule ReportSubmissionRule @{ Identity = 'DefaultReportSubmissionRule' } @{ SentTo = @($settings.reportingMailbox) } @{ SentTo = 'Strings' }
                $definition.Guard = @{ ReportSubmissionPolicy = 'DefaultReportSubmissionPolicy' }
                $definition
                New-ApprovedAdapterDefinition ReportSubmissionRuleState ReportSubmissionRule @{ Identity = 'DefaultReportSubmissionRule' } @{ Enabled = $true } @{ Enabled = 'Boolean' } -Toggle
            }
            SecOpsOverride {
                $settings = $controls['MDO-006']
                Assert-ExchangeGovernanceApproval (Get-BaselineRecordMember $settings approval) ([datetimeoffset]::UtcNow)
                if ($settings.reportingMailbox -notmatch '^[^@\s*]+@[^@\s*]+\.[^@\s*]+$' -or $settings.reportingMailbox -ine $parameters.SECURITY_OPERATIONS_MAILBOX) { throw 'ChangeReportingContract: SecOps scope must be the exact approved reporting mailbox.' }
                if (-not $DesiredOnly) {
                    $rules = Get-ApprovedAdapterCollection Get-ExoSecOpsOverrideRule @{ Policy = 'SecOpsOverridePolicy' } @('Identity','Mode')
                    if ($rules.Count -ne 1 -or $rules[0].Mode -cne 'Enforce') { throw 'ChangeReportingPrerequisite: initialize and enforce the SecOps override rule in Advanced Delivery before preview.' }
                }
                & $fixed SecOpsOverride SecOpsOverridePolicy @{ Identity = 'SecOpsOverridePolicy' } @{ SentTo = @($settings.reportingMailbox) } @{ SentTo = 'Strings' }
            }
            Impersonation {
                if ('ATP_ENTERPRISE' -cnotin @($Context.Entitlement.servicePlans)) { throw 'ChangeScopeNotEntitled: Impersonation requires ATP_ENTERPRISE.' }
                $settings = $controls['MDO-009']
                & $fixed Impersonation AntiPhishPolicy @{ Identity = 'Contoso Impersonation Protection' } @{ EnableTargetedUserProtection = $settings.enabled; EnableTargetedDomainsProtection = $settings.enabled; TargetedUsersToProtect = @($settings.protectedUsers); TargetedDomainsToProtect = @($settings.protectedDomains); ExcludedSenders = @($settings.approvedExceptions | Where-Object exceptionType -CEQ TrustedSender | ForEach-Object value); ExcludedDomains = @($settings.approvedExceptions | Where-Object exceptionType -CEQ TrustedDomain | ForEach-Object value) } @{ EnableTargetedUserProtection = 'Boolean'; EnableTargetedDomainsProtection = 'Boolean'; TargetedUsersToProtect = 'Strings'; TargetedDomainsToProtect = 'Strings'; ExcludedSenders = 'Strings'; ExcludedDomains = 'Strings' } $true @{ Name = 'Contoso Impersonation Protection' }
            }
            { $_ -cin @('EopPresets','AtpPresets') } {
                if ($area -ceq 'AtpPresets' -and 'ATP_ENTERPRISE' -cnotin @($Context.Entitlement.servicePlans)) { throw 'ChangeScopeNotEntitled: AtpPresets requires ATP_ENTERPRISE.' }
                $standard = $controls['MDO-001']
                $strict = $controls['MDO-002']
                if (@($standard.excludedGroups).Count -ne 1 -or $standard.excludedGroups[0] -ine $parameters.MAIL_ENABLED_PRIORITY_USERS_GROUP -or @($standard.excludedSecOpsMailbox).Count -ne 1 -or $standard.excludedSecOpsMailbox[0] -ine $parameters.SECURITY_OPERATIONS_MAILBOX) { throw 'ChangePresetExclusionUnapproved: preset exclusions must match the approved priority group and security operations mailbox.' }
                if (@($standard.sentToDomains).Count -ne 1 -or $standard.sentToDomains[0] -ine $parameters.PRIMARY_SMTP_DOMAIN -or $strict.scopeGroup -ine $parameters.MAIL_ENABLED_PRIORITY_USERS_GROUP) { throw 'ChangePresetScopeUnapproved: preset assignments must match the approved domain and priority group.' }
                $noun = if ($area -ceq 'EopPresets') { 'EOPProtectionPolicyRule' } else { 'ATPProtectionPolicyRule' }
                foreach ($level in @('Standard','Strict')) {
                    $target = @{ Identity = "$level Preset Security Policy" }
                    $desired = @{ RecipientDomainIs = @(); SentTo = @(); SentToMemberOf = @(); ExceptIfRecipientDomainIs = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @() }
                    if ($level -ceq 'Standard') {
                        $desired.RecipientDomainIs = @($standard.sentToDomains)
                        $desired.ExceptIfSentToMemberOf = @($standard.excludedGroups)
                        $desired.ExceptIfSentTo = @($standard.excludedSecOpsMailbox)
                    } else { $desired.SentToMemberOf = @($strict.scopeGroup) }
                    $types = @{}; foreach ($key in $desired.Keys) { $types[$key] = 'Strings' }
                    if ($null -eq $Approved -and -not $DesiredOnly) {
                        $rows = Get-ApprovedAdapterCollection "Get-$noun" $target
                        if ($rows.Count -ne 1) { throw "ChangeReadIncomplete: $level preset must be initialized exactly once." }
                        foreach ($field in $desired.Keys) {
                            if (-not (Test-BaselineNodeMember $rows[0] $field)) {
                                if ($types[$field] -ceq 'Strings' -and @($desired[$field]).Count -eq 0) { continue }
                                throw "ChangeReadIncomplete: $level preset omitted $field."
                            }
                            if (@($desired[$field]).Count -eq 0 -and @($rows[0].$field).Count) { throw "ChangePresetScopeResidual: $level preset has residual $field assignments." }
                        }
                    }
                    & $fixed "$area$level" $noun $target $desired $types
                    New-ApprovedAdapterDefinition "$area$($level)State" $noun $target @{ Enabled = [bool]$(if ($level -ceq 'Standard') { $controls['MDO-001'].enabled } else { $controls['MDO-002'].enabled }) } @{ Enabled = 'Boolean' } -Toggle
                }
            }
            BuiltInProtection {
                if ('ATP_ENTERPRISE' -cnotin @($Context.Entitlement.servicePlans)) { throw 'ChangeScopeNotEntitled: BuiltInProtection requires ATP_ENTERPRISE.' }
                & $fixed BuiltInProtection ATPBuiltInProtectionRule @{ Identity = 'ATP Built-In Protection Rule' } @{ ExceptIfRecipientDomainIs = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @() } @{ ExceptIfRecipientDomainIs = 'Strings'; ExceptIfSentTo = 'Strings'; ExceptIfSentToMemberOf = 'Strings' }
            }
            Quarantine {
                $settings = $controls['MDO-008']
                $permission = @{ AdminOnlyAccess = 0; LimitedAccess = 106; FullAccess = 236 }
                foreach ($level in @($settings.categoryPermissions.accessLevel | Sort-Object -Unique)) {
                    if (-not $permission.ContainsKey($level)) { throw 'ChangeOptionsInvalid: unsupported quarantine permission.' }
                    & $fixed QuarantinePolicy QuarantinePolicy @{ Identity = "Baseline-$level" } @{ EndUserQuarantinePermissionsValue = $permission[$level] } @{ EndUserQuarantinePermissionsValue = 'Integer' } $true @{ Name = "Baseline-$level" }
                }
                & $fixed QuarantineGlobal QuarantinePolicy @{ Identity = 'DefaultGlobalTag' } @{ EndUserSpamNotificationFrequency = [timespan]::FromDays($settings.endUserSpamNotificationFrequencyInDays).ToString('c'); IncludeMessagesFromBlockedSenderAddress = $settings.includeMessagesFromBlockedSenderAddress } @{ EndUserSpamNotificationFrequency = 'Duration'; IncludeMessagesFromBlockedSenderAddress = 'Boolean' }
                $desired = @{}; $types = @{}
                foreach ($category in @('HighConfidencePhish','Phish','HighConfidenceSpam','Spam','Bulk')) {
                    $member = $category + 'QuarantineTag'
                    $level = @($settings.categoryPermissions | Where-Object category -CEQ $category).accessLevel
                    $desired[$member] = "Baseline-$level"; $types[$member] = 'NullableString'
                }
                $managedPolicies = @('Standard Preset Security Policy','Strict Preset Security Policy','Built-In Protection Policy')
                foreach ($target in (& $targets QuarantineContent Get-HostedContentFilterPolicy)) {
                    if ($target.Identity -in $managedPolicies) { continue }
                    & $fixed QuarantineContent HostedContentFilterPolicy $target $desired $types
                }
                $level = @($settings.categoryPermissions | Where-Object category -CEQ Malware).accessLevel
                foreach ($target in (& $targets QuarantineMalware Get-MalwareFilterPolicy)) {
                    if ($target.Identity -in $managedPolicies) { continue }
                    & $fixed QuarantineMalware MalwareFilterPolicy $target @{ QuarantineTag = "Baseline-$level" } @{ QuarantineTag = 'NullableString' }
                }
                $level = @($settings.categoryPermissions | Where-Object category -CEQ SpoofIntelligence).accessLevel
                foreach ($target in (& $targets QuarantinePhish Get-AntiPhishPolicy)) {
                    if ($target.Identity -in $managedPolicies) { continue }
                    & $fixed QuarantinePhish AntiPhishPolicy $target @{ SpoofQuarantineTag = "Baseline-$level" } @{ SpoofQuarantineTag = 'NullableString' }
                }
            }
            Dkim {
                & $fixed Dkim DkimSigningConfig @{ Identity = [string]$parameters.PRIMARY_SMTP_DOMAIN } @{ Enabled = [bool]$options['enableDkim'] } @{ Enabled = 'Boolean' } $true @{ DomainName = $parameters.PRIMARY_SMTP_DOMAIN; KeySize = [int]$controls['AUTH-001'].keySize }
            }
            Forwarding {
                foreach ($target in (& $targets ForwardingMailbox Get-Mailbox @{ ResultSize = 'Unlimited' } @('Identity','PrimarySmtpAddress'))) {
                    & $fixed ForwardingMailbox Mailbox $target @{ ForwardingAddress = $null; ForwardingSmtpAddress = $null } @{ ForwardingAddress = 'NullableString'; ForwardingSmtpAddress = 'NullableString' }
                }
                $ruleTargets = @()
                if ($null -ne $Approved) {
                    $ruleTargets = @(& $targets ForwardingRule Get-InboxRule)
                } else {
                    $domains = Get-ApprovedAdapterCollection Get-AcceptedDomain @{ ResultSize = 'Unlimited' } @('Identity','DomainName')
                    if ($domains.Count -eq 0) { throw 'ChangeReadIncomplete: accepted domains are required for forwarding classification.' }
                    foreach ($mailbox in (Get-ApprovedAdapterCollection Get-Mailbox @{ ResultSize = 'Unlimited' } @('Identity','PrimarySmtpAddress'))) {
                        foreach ($rule in (Get-ApprovedAdapterCollection Get-InboxRule @{ Mailbox = [string]$mailbox.Identity; IncludeHidden = $true } @('Identity'))) {
                            foreach ($field in @('Enabled','ForwardTo','ForwardAsAttachmentTo','RedirectTo')) { if (-not (Test-BaselineNodeMember $rule $field)) { throw "ChangeReadIncomplete: inbox rule omitted $field." } }
                            $external = $false
                            foreach ($recipient in @($rule.ForwardTo) + @($rule.ForwardAsAttachmentTo) + @($rule.RedirectTo)) {
                                if ($null -eq $recipient) { continue }
                                $address = [string]$recipient
                                if ($address -match '<([^<>]+)>') { $address = $Matches[1] }
                                $address = $address -replace '^(?i)smtp:', ''
                                if ($address -notmatch '^[^@\s]+@([^@\s]+)$') { throw 'ChangeReadIncomplete: an inbox forwarding recipient is unresolved.' }
                                if (@($domains.DomainName) -inotcontains $Matches[1].TrimEnd('.')) { $external = $true }
                            }
                            if ($external) { $ruleTargets += @{ Mailbox = [string]$mailbox.Identity; Identity = [string]$rule.Identity } }
                        }
                    }
                }
                foreach ($target in $ruleTargets) { New-ApprovedAdapterDefinition ForwardingRule InboxRule $target @{ Enabled = $false } @{ Enabled = 'Boolean' } -Toggle }
            }
            AddInAcquisition {
                $assignmentTargets = @()
                if ($null -ne $Approved) { $assignmentTargets = @(& $targets AddInAcquisition Get-ManagementRoleAssignment) } else {
                    $policies = Get-ApprovedAdapterCollection Get-RoleAssignmentPolicy @{} @('Identity','IsDefault')
                    $default = @($policies | Where-Object { $_.IsDefault -is [bool] -and $_.IsDefault })
                    if ($default.Count -ne 1) { throw 'ChangeReadIncomplete: exactly one default role assignment policy is required.' }
                    foreach ($assignment in (Get-ApprovedAdapterCollection Get-ManagementRoleAssignment @{} @('Identity','Name','Role','RoleAssignee','RoleAssigneeType','Delegating'))) {
                        if ($assignment.RoleAssignee -ieq $default[0].Identity -and $assignment.Role -iin @('My Custom Apps','My Marketplace Apps','My ReadWriteMailboxApps')) {
                            if ($assignment.RoleAssigneeType -ne 'RoleAssignmentPolicy' -or $assignment.Delegating) { throw 'ChangeReadIncomplete: only regular role-assignment-policy grants can be restored.' }
                            $assignmentTargets += @{ Identity = [string]$assignment.Name }
                        }
                    }
                }
                foreach ($target in $assignmentTargets) {
                    New-ApprovedAdapterDefinition AddInAcquisition ManagementRoleAssignment $target @{} @{ Name = 'String'; Role = 'String'; RoleAssignee = 'String'; RoleAssigneeType = 'String'; Delegating = 'Boolean'; RecipientWriteScope = 'String'; ConfigWriteScope = 'String'; CustomRecipientWriteScope = 'NullableString'; CustomConfigWriteScope = 'NullableString'; ExclusiveRecipientWriteScope = 'NullableString'; ExclusiveConfigWriteScope = 'NullableString' } -Delete
                }
            }
            TenantAllowBlockList {
                $entries = @($options['tenantAllowBlockEntries'] | Where-Object { $null -ne $_ })
                if (-not $DesiredOnly) { $null = Get-ApprovedAdapterCollection Get-TenantAllowBlockListItems @{ ListType = 'Sender' } @('Identity','Value','Action') }
                $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($entry in $entries) {
                    foreach ($field in @('entryType','entryValue','action','owner','ticket','createdDateTime','expirationDateTime','justification')) { if ([string]::IsNullOrWhiteSpace([string]$entry[$field])) { throw "ChangeOptionsInvalid: TABL requires $field." } }
                    if ($entry.entryType -cnotin @('Sender','Domain','Url','File') -or $entry.action -cnotin @('Allow','Block')) { throw 'ChangeOptionsInvalid: unsupported TABL type or action.' }
                    $entryValue = [string]$entry.entryValue
                    if ($null -ne $Approved -and -not $DesiredOnly) {
                        switch -CaseSensitive ($entry.entryType) {
                            Sender {
                                $mailbox = $null
                                try { $mailbox = [Net.Mail.MailAddress]::new($entryValue) } catch {}
                                if ($entryValue -match '[*?]' -or $null -eq $mailbox -or $mailbox.Address -ine $entryValue -or $mailbox.Host -notmatch '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') { throw 'ChangeOptionsInvalid: TenantAllowBlockList Sender requires an exact mailbox address.' }
                            }
                            Domain {
                                if ($entryValue -notmatch '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') { throw 'ChangeOptionsInvalid: TenantAllowBlockList Domain requires an exact domain.' }
                            }
                            Url {
                                $absoluteUri = $null
                                if ($entryValue -match '[*]' -or -not [uri]::TryCreate($entryValue, [UriKind]::Absolute, [ref]$absoluteUri) -or $absoluteUri.Scheme -cnotin @('http','https') -or [string]::IsNullOrWhiteSpace($absoluteUri.Host)) { throw 'ChangeOptionsInvalid: TenantAllowBlockList Url requires an absolute non-wildcard HTTP or HTTPS URL.' }
                            }
                            File {
                                if ($entryValue -notmatch '^[a-f0-9]{64}$') { throw 'ChangeOptionsInvalid: TenantAllowBlockList File requires an exact SHA-256 hash.' }
                            }
                        }
                    }
                    $listType = switch ($entry.entryType) { Domain { 'Sender' } File { 'FileHash' } default { $entry.entryType } }
                    if (-not $seen.Add("$listType/$($entry.entryValue)")) { throw 'ChangeOptionsInvalid: duplicate TABL target.' }
                    $created = [datetimeoffset]$entry.createdDateTime; $expiry = [datetimeoffset]$entry.expirationDateTime
                    $days = ($expiry - $created).TotalDays
                    if ($expiry -le [datetimeoffset]::UtcNow -or $days -le 0 -or ($entry.action -ceq 'Allow' -and $days -gt $controls['MDO-007'].allowEntryMaximumDurationDays) -or ($entry.action -ceq 'Block' -and $days -ne $controls['MDO-007'].blockEntryRetentionDays)) { throw 'ChangeOptionsInvalid: TABL duration violates governance.' }
                    $notes = 'Owner={0}; Ticket={1}; Created={2}; Justification={3}' -f $entry.owner,$entry.ticket,$created.ToString('o'),$entry.justification
                    & $fixed TenantAllowBlockList TenantAllowBlockListItems @{ ListType = $listType; Entries = @([string]$entry.entryValue) } @{ Action = $entry.action; ExpirationDate = $expiry.ToUniversalTime().ToString('o'); Notes = $notes } @{ Action = 'String'; ExpirationDate = 'DateTime'; Notes = 'NullableString' } $true @{ ListType = $listType; Entries = @([string]$entry.entryValue) }
                }
            }
        }
    }
}

function Read-ApprovedAdapterState {
    param($Definition, [System.Collections.IDictionary]$Observation)
    $arguments = $Definition.Target.Clone()
    if ($Definition.New -and -not $Definition.Delete) {
        $arguments = @{}
        if ($Definition.Adapter -ceq 'TenantAllowBlockList') { $arguments.ListType = $Definition.Target.ListType }
        $required = if ($Definition.Adapter -ceq 'TenantAllowBlockList') { @('Identity','Value','Action') } else { @('Identity') }
        $all = Get-ApprovedAdapterCollection $Definition.Get $arguments $required
        $rows = @($all | Where-Object {
            if ($Definition.Adapter -ceq 'TenantAllowBlockList') { $_.Value -ieq $Definition.Target.Entries[0] }
            elseif ($Definition.Adapter -ceq 'AcceptedDomains') { [string](Get-BaselineRecordMember $_ DomainName) -ieq $Definition.Target.Identity }
            else { [string]$_.Identity -ieq $Definition.Target.Identity -or [string](Get-BaselineRecordMember $_ Name) -ieq $Definition.Target.Identity -or [string](Get-BaselineRecordMember $_ Domain) -ieq $Definition.Target.Identity }
        })
    } elseif ($Definition.Delete) {
        $all = Get-ApprovedAdapterCollection $Definition.Get
        $rows = @($all | Where-Object { $_.Identity -ieq $Definition.Target.Identity -or $_.Name -ieq $Definition.Target.Identity })
    } else { $rows = @(& $Definition.Get @arguments -ErrorAction Stop) }
    if ($rows.Count -gt 1 -or ($rows.Count -eq 0 -and -not $Definition.New)) { throw "ChangeReadIncomplete: $($Definition.Adapter) requires exactly one target." }
    if ($rows.Count -eq 0) { return @{ Exists = $false; Value = $null } }
    $row = $rows[0]
    $guards = Get-BaselineRecordMember $Definition Guard
    if ($null -ne $guards) {
        foreach ($field in $guards.Keys) {
            if (-not (Test-BaselineNodeMember $row $field) -or [string](Get-BaselineRecordMember $row $field) -cne [string]$guards[$field]) { throw "ChangeGovernancePrerequisite: '$field' must already match the approved prerequisite." }
        }
    }
    if ($Definition.Adapter -ceq 'GovernanceEncryptionRule') {
        if (-not (Test-BaselineNodeMember $row Conditions) -or -not (Test-BaselineNodeMember $row Exceptions) -or @($row.Exceptions).Count) { throw 'ChangeGovernancePrerequisite: complete encryption predicates with no exceptions are required.' }
        try { Assert-ExchangeGovernanceSet @($row.Conditions | ForEach-Object { Get-BaselineRecordMember $_ Name }) @('HeaderContains','SentTo') 'Encryption predicates' }
        catch { throw "ChangeGovernancePrerequisite: $($_.Exception.Message)" }
    }
    if ($Definition.Target.ContainsKey('Identity') -and -not $Definition.New) {
        if (-not (Test-BaselineNodeMember $row Identity) -or [string]$row.Identity -ine $Definition.Target.Identity) { throw 'ChangeReadIncomplete: read returned another target.' }
    }
    $value = @{}
    foreach ($field in $Definition.Types.Keys) {
        $source = if ($Definition.Toggle -and $Definition.Noun -ne 'InboxRule') { 'State' } else { $field }
        if (-not (Test-BaselineNodeMember $row $source)) {
            if ($Definition.Adapter -cmatch '^(?:Eop|Atp)Presets(?:Standard|Strict)$' -and $Definition.Types[$field] -ceq 'Strings' -and @($Definition.Desired[$field]).Count -eq 0) { $actual = @() }
            else { throw "ChangeReadIncomplete: $($Definition.Adapter) omitted $source." }
        } else { $actual = $row.$source }
        if ($source -ceq 'State') {
            if ($actual -cnotin @('Enabled','Disabled')) { throw 'ChangeReadIncomplete: preset State must be Enabled or Disabled.' }
            $actual = $actual -ceq 'Enabled'
        }
        $value[$field] = ConvertTo-ApprovedAdapterValue $actual $Definition.Types[$field] $field
    }
    if ($Definition.Delete) {
        if ($value.RoleAssigneeType -cne 'RoleAssignmentPolicy' -or $value.Delegating -or $value.Role -cnotin @('My Custom Apps','My Marketplace Apps','My ReadWriteMailboxApps') -or $value.RecipientWriteScope -cne 'Self' -or $value.ConfigWriteScope -cne 'None' -or $value.CustomRecipientWriteScope -or $value.CustomConfigWriteScope -or $value.ExclusiveRecipientWriteScope -or $value.ExclusiveConfigWriteScope) { throw 'ChangeReadIncomplete: role grant has unsupported restoration scope.' }
    }
    if ($null -ne $Observation) {
        $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson (ConvertTo-BaselineHashableNode $row)))
        $Observation.ObjectFingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    }
    @{ Exists = $true; Value = $value }
}

function Get-BaselineConcreteOperation {
    param($Context, [string[]]$Scope, [switch]$DesiredOnly, $Approved)
    foreach ($definition in @(Get-ApprovedAdapterDefinitions $Context $Scope $Approved -DesiredOnly:$DesiredOnly)) {
        $identity = ConvertTo-CanonicalJson $definition.Target
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($identity))).Substring(0,16).ToLowerInvariant()
        $operationId = "$($definition.Adapter)-$hash"
        $previous = @($Approved | Where-Object { $null -ne $_ -and $_.OperationId -ceq $operationId })
        $before = if ($DesiredOnly) { if ($previous.Count -eq 1) { ConvertTo-BaselineHashableNode $previous[0].Before } else { @{ Exists = $true; Value = $definition.Desired } } } else { Read-ApprovedAdapterState $definition }
        $after = @{ Exists = -not $definition.Delete; Value = $null }
        if (-not $definition.Delete) {
            $after.Value = @{}
            foreach ($field in $definition.Desired.Keys) { $after.Value[$field] = ConvertTo-ApprovedAdapterValue $definition.Desired[$field] $definition.Types[$field] $field }
        }
        $origin = if ($previous.Count -eq 1) { $previous[0].Before } else { $before }
        $command = if ($definition.Delete -or $definition.Adapter -ceq 'TenantAllowBlockList' -and $origin.Exists) { $definition.Remove } elseif ($definition.Toggle) { "$(if ($after.Value.Enabled) { 'Enable' } else { 'Disable' })-$($definition.Noun)" } elseif (-not $origin.Exists) { $definition.New } else { $definition.Set }
        @{ OperationId = $operationId; Command = $command; Identity = $identity; Before = $before; After = $after; DependsOn = @(); Sequence = 0 }
    }
}

function Test-ApprovedPresetFieldOmission {
    param($Definition, [string]$Field, $DesiredValue, $Current)
    $Definition.Adapter -cmatch '^(?:Eop|Atp)Presets(?:Standard|Strict)$' -and
        $Definition.Types.ContainsKey($Field) -and $Definition.Types[$Field] -ceq 'Strings' -and
        (Test-BaselineNodeMember $DesiredValue $Field) -and @($DesiredValue[$Field]).Count -eq 0 -and
        $Current.Exists -and (Test-BaselineNodeMember $Current.Value $Field) -and @($Current.Value[$Field]).Count -eq 0
}

function Assert-ApprovedAdapterCommands {
    param($Definitions)
    foreach ($definition in $Definitions) {
        $contracts = @(@{ Command = $definition.Get; Fields = @() })
        if ($definition.Toggle) {
            foreach ($verb in @('Enable','Disable')) { $contracts += @{ Command = "$verb-$($definition.Noun)"; Fields = @($definition.Target.Keys) } }
        } else {
            if (-not $definition.Delete -and $definition.Adapter -cne 'TenantAllowBlockList') {
                $fields = if ($definition.Adapter -ceq 'SecOpsOverride') { @('Identity','AddSentTo','RemoveSentTo') } else { @($definition.Target.Keys) + @($definition.Desired.Keys) }
                $contracts += @{ Command = $definition.Set; Fields = $fields }
            }
            if ($definition.New) {
                $fields = if ($definition.Delete) { @('Name','Role','Policy') } elseif ($definition.Adapter -ceq 'TenantAllowBlockList') { @('Entries','ListType','ExpirationDate','Notes','Allow','Block') } else { @($definition.CreateTarget.Keys) + @($definition.Desired.Keys) }
                $contracts += @{ Command = $definition.New; Fields = $fields }
                $contracts += @{ Command = $definition.Remove; Fields = @($definition.Target.Keys) }
            }
        }
        foreach ($contract in $contracts) {
            $command = Get-Command -Name $contract.Command -ErrorAction SilentlyContinue
            if ($null -eq $command) { throw "ChangeCommandUnavailable: $($contract.Command) is required for apply and restoration." }
            $current = $null
            foreach ($field in $contract.Fields) {
                if (-not $command.Parameters.ContainsKey($field)) {
                    if ($null -eq $current) { $current = Read-ApprovedAdapterState $definition }
                    if (Test-ApprovedPresetFieldOmission $definition $field $definition.Desired $current) { continue }
                    throw "ChangeCommandUnavailable: $($contract.Command) has no $field parameter."
                }
            }
        }
    }
}

function Invoke-BaselineConcreteOperation {
    param($Definition, $Current, $Desired, $Journal)
    if ((ConvertTo-CanonicalJson $Current) -ceq (ConvertTo-CanonicalJson $Desired)) { return }
    if ($Definition.Adapter -ceq 'SecOpsOverride') {
        if (-not $Current.Exists -or -not $Desired.Exists) { throw 'ChangeReportingPrerequisite: SecOps policy creation and removal are not supported by this scoped adapter.' }
        $arguments = $Definition.Target.Clone()
        $add = @($Desired.Value.SentTo | Where-Object { $_ -notin $Current.Value.SentTo })
        $remove = @($Current.Value.SentTo | Where-Object { $_ -notin $Desired.Value.SentTo })
        if ($add.Count) { $arguments.AddSentTo = $add }
        if ($remove.Count) { $arguments.RemoveSentTo = $remove }
        $null = Set-SecOpsOverridePolicy @arguments -Confirm:$false -ErrorAction Stop
        return
    }
    if ($Definition.Adapter -ceq 'TenantAllowBlockList') {
        $target = $Definition.Target
        if ($Current.Exists) {
            $null = Remove-TenantAllowBlockListItems @target -ErrorAction Stop
            $Journal.Progress = 'Removed'
            if ((Read-ApprovedAdapterState $Definition).Exists) { throw 'ChangePostStateMismatch: TABL removal was not confirmed.' }
        }
        if ($Desired.Exists) {
            $arguments = $target.Clone()
            $arguments[$Desired.Value.Action] = $true
            $arguments.ExpirationDate = ([datetimeoffset]$Desired.Value.ExpirationDate).UtcDateTime
            $arguments.Notes = $Desired.Value.Notes
            $null = New-TenantAllowBlockListItems @arguments -ErrorAction Stop
            $Journal.Progress = 'Created'
            $null = Read-ApprovedAdapterState $Definition -Observation $Journal
        }
        return
    }
    $arguments = $Definition.Target.Clone()
    $command = $Definition.Set
    if (-not $Desired.Exists) { $command = $Definition.Remove }
    elseif (-not $Current.Exists) {
        $command = $Definition.New
        $arguments = $Definition.CreateTarget.Clone()
        if ($Definition.Delete) {
            $arguments = @{ Name = $Desired.Value.Name; Role = $Desired.Value.Role; Policy = $Desired.Value.RoleAssignee }
        }
    }
    if ($Definition.Toggle) { $command = "$(if ($Desired.Value.Enabled) { 'Enable' } else { 'Disable' })-$($Definition.Noun)" }
    elseif ($Desired.Exists -and -not $Definition.Delete) {
        $commandInfo = Get-Command -Name $command -ErrorAction SilentlyContinue
        if ($null -eq $commandInfo) { throw "ChangeCommandUnavailable: $command is required for apply and restoration." }
        foreach ($field in $Desired.Value.Keys) {
            if (-not $commandInfo.Parameters.ContainsKey($field)) {
                if (Test-ApprovedPresetFieldOmission $Definition $field $Desired.Value $Current) { continue }
                throw "ChangeCommandUnavailable: $command has no $field parameter."
            }
            $arguments[$field] = $Desired.Value[$field]
            if ($Definition.Types[$field] -ceq 'Duration') { $arguments[$field] = [timespan]$Desired.Value[$field] }
            if ($Definition.Types[$field] -ceq 'DateTime') { $arguments[$field] = [datetimeoffset]$Desired.Value[$field] }
        }
    }
    if ([string]::IsNullOrWhiteSpace($command)) { throw 'ChangeOperationMismatch: no concrete mutation adapter exists.' }
    $null = & $command @arguments -Confirm:$false -ErrorAction Stop
    if (-not $Current.Exists -and $Desired.Exists) {
        $null = Read-ApprovedAdapterState $Definition -Observation $Journal
    }
}