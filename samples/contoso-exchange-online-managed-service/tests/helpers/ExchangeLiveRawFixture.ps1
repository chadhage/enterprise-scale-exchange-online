function New-ExchangeLiveRawFixture {
    param($Parameters)
    $domain = $Parameters.PRIMARY_SMTP_DOMAIN
    $secops = $Parameters.SECURITY_OPERATIONS_MAILBOX
    $priority = $Parameters.MAIL_ENABLED_PRIORITY_USERS_GROUP
    $retention = $Parameters.MAILBOX_RETENTION_POLICY_NAME
    @{
        'Get-AcceptedDomain' = @{ Items = @(@{ Identity = $domain; Name = $domain; DomainName = $domain; DomainType = 'Authoritative' }) }
        'Get-TransportConfig' = @{ Items = @(@{ Identity = 'Transport Settings'; SmtpClientAuthenticationDisabled = $true; ExternalPostmasterAddress = $Parameters.EXTERNAL_POSTMASTER_SMTP_ADDRESS }) }
        'Get-CASMailbox' = @{ Items = @(@{ Identity = 'Mailbox One'; PrimarySmtpAddress = "user@$domain"; SmtpClientAuthenticationDisabled = $null; PopEnabled = $false; ImapEnabled = $false; EwsEnabled = $null; EwsApplicationAccessPolicy = $null; EwsAllowList = @() }) }
        'Get-HostedOutboundSpamFilterPolicy' = @{ Items = @(@{ Identity = 'Default'; Name = 'Default'; AutoForwardingMode = 'Off' }) }
        'Get-Mailbox' = @{ Items = @(@{ Identity = 'Mailbox One'; PrimarySmtpAddress = "user@$domain"; ForwardingAddress = $null; ForwardingSmtpAddress = $null; RetentionPolicy = $retention; LitigationHoldEnabled = $false }) }
        'Get-InboxRule' = @{ Items = @() }
        'Get-OrganizationConfig' = @{ Items = @(@{ Identity = 'Tenant'; AuditDisabled = $false; EwsEnabled = $false; EwsApplicationAccessPolicy = 'EnforceAllowList'; EwsAllowList = @(); EwsAllowedAppIDs = @() }) }
        'Get-MailboxAuditBypassAssociation' = @{ Items = @(@{ Identity = 'Mailbox One'; AuditBypassEnabled = $false }) }
        'Get-ExternalInOutlook' = @{ Items = @(@{ Identity = 'Tenant'; Enabled = $true; AllowList = @() }) }
        'Get-RemoteDomain' = @{ Items = @(@{ Identity = 'Default'; Name = 'Default'; DomainName = '*'; AutoForwardEnabled = $false; AutoReplyEnabled = $false; AllowedOOFType = 'None'; DeliveryReportEnabled = $false; NDREnabled = $false }) }
        'Get-CASMailboxPlan' = @{ Items = @(@{ Identity = 'ExchangeOnlineEnterprise'; PopEnabled = $false; ImapEnabled = $false }) }
        'Get-RoleGroup' = @{ Items = @(@{ Identity = 'Organization Management'; Name = 'Organization Management' }) }
        'Get-RoleGroupMember' = @{ Items = @() }
        'Get-ManagementRoleAssignment' = @{ Items = @(@{ Identity = 'MyBaseOptions-Default Role Assignment Policy'; Role = 'MyBaseOptions'; RoleAssignee = 'Default Role Assignment Policy'; RoleAssigneeType = 'RoleAssignmentPolicy' }) }
        'Get-RoleAssignmentPolicy' = @{ Items = @(@{ Identity = 'Default Role Assignment Policy'; IsDefault = $true }) }
        'Get-EOPProtectionPolicyRule' = @{ ByIdentity = @{
            'Standard Preset Security Policy' = @(@{ Name = 'Standard Preset Security Policy'; State = 'Enabled'; RecipientDomainIs = @($domain); ExceptIfSentToMemberOf = @($priority); ExceptIfSentTo = @($secops) })
            'Strict Preset Security Policy' = @(@{ Name = 'Strict Preset Security Policy'; State = 'Enabled'; SentToMemberOf = @($priority); SentTo = @(); RecipientDomainIs = @() })
        }; Items = @() }
        'Get-ATPProtectionPolicyRule' = @{ ByIdentity = @{
            'Standard Preset Security Policy' = @(@{ Name = 'Standard Preset Security Policy'; State = 'Enabled'; RecipientDomainIs = @($domain); ExceptIfSentToMemberOf = @($priority); ExceptIfSentTo = @($secops) })
            'Strict Preset Security Policy' = @(@{ Name = 'Strict Preset Security Policy'; State = 'Enabled'; SentToMemberOf = @($priority); SentTo = @(); RecipientDomainIs = @() })
        }; Items = @() }
        'Get-ATPBuiltInProtectionRule' = @{ Items = @(@{ Name = 'ATP Built-In Protection Rule'; State = 'Enabled'; ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @(); ExceptIfRecipientDomainIs = @() }) }
        'Get-DistributionGroup' = @{ Items = @(@{ Identity = $priority; PrimarySmtpAddress = $priority; RecipientTypeDetails = 'MailUniversalSecurityGroup' }) }
        'Get-ReportSubmissionPolicy' = @{ Items = @(@{ Identity = 'DefaultReportSubmissionPolicy'; EnableThirdPartyAddress = $false; EnableReportToMicrosoft = $true; ReportJunkToCustomizedAddress = $true; ReportJunkAddresses = @($secops); ReportNotJunkToCustomizedAddress = $true; ReportNotJunkAddresses = @($secops); ReportPhishToCustomizedAddress = $true; ReportPhishAddresses = @($secops) }) }
        'Get-ReportSubmissionRule' = @{ Items = @(@{ Identity = 'DefaultReportSubmissionRule'; State = 'Enabled'; ReportSubmissionPolicy = 'DefaultReportSubmissionPolicy'; SentTo = @($secops) }) }
        'Get-SecOpsOverridePolicy' = @{ Items = @(@{ Identity = 'SecOpsOverridePolicy'; Name = 'SecOpsOverridePolicy'; SentTo = @($secops) }) }
        'Get-ExoSecOpsOverrideRule' = @{ Items = @(@{ Identity = '_Exe:SecOpsOverrid:11111111-1111-1111-1111-111111111111'; Mode = 'Enforce' }) }
        'Get-TenantAllowBlockListItems' = @{ Items = @() }
        'Get-QuarantinePolicy' = @{ ByType = @{
            GlobalQuarantinePolicy = @(@{ Name = 'DefaultGlobalTag'; QuarantinePolicyType = 'GlobalQuarantinePolicy'; EndUserSpamNotificationFrequency = '1.00:00:00'; IncludeMessagesFromBlockedSenderAddress = $false })
            QuarantinePolicy = @(@{ Name = 'AdminOnlyAccessPolicy'; QuarantinePolicyType = 'QuarantinePolicy'; EndUserQuarantinePermissionsValue = 0 }, @{ Name = 'LimitedAccess'; QuarantinePolicyType = 'QuarantinePolicy'; EndUserQuarantinePermissionsValue = 106 })
        }; Items = @(@{ Name = 'AdminOnlyAccessPolicy'; QuarantinePolicyType = 'QuarantinePolicy'; EndUserQuarantinePermissionsValue = 0 }, @{ Name = 'LimitedAccess'; QuarantinePolicyType = 'QuarantinePolicy'; EndUserQuarantinePermissionsValue = 106 }) }
        'Get-HostedContentFilterPolicy' = @{ Items = @(@{ Name = 'Default'; HighConfidencePhishQuarantineTag = 'AdminOnlyAccessPolicy'; PhishQuarantineTag = 'LimitedAccess'; HighConfidenceSpamQuarantineTag = 'LimitedAccess'; SpamQuarantineTag = 'LimitedAccess'; BulkQuarantineTag = 'LimitedAccess' }) }
        'Get-MalwareFilterPolicy' = @{ Items = @(@{ Name = 'Default'; QuarantineTag = 'AdminOnlyAccessPolicy' }) }
        'Get-AntiPhishPolicy' = @{ Items = @(@{ Name = 'Contoso Impersonation'; IsDefault = $false; EnableTargetedUserProtection = $true; EnableTargetedDomainsProtection = $true; TargetedUsersToProtect = @("SecOps;$secops"); TargetedDomainsToProtect = @($domain); ExcludedSenders = @(); ExcludedDomains = @(); SpoofQuarantineTag = 'LimitedAccess' }) }
        'Get-AntiPhishRule' = @{ Items = @(@{ Name = 'Contoso Impersonation'; State = 'Enabled'; AntiPhishPolicy = 'Contoso Impersonation'; RecipientDomainIs = @($domain); SentTo = @(); SentToMemberOf = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @(); ExceptIfRecipientDomainIs = @() }) }
        'Get-InboundConnector' = @{ Items = @() }
        'Get-DkimSigningConfig' = @{ Items = @(@{ Identity = $domain; Name = $domain; Domain = $domain; Enabled = $true; Status = 'Valid'; Selector1KeySize = 2048; Selector2KeySize = 2048; Selector1CNAME = "selector1-$domain._domainkey.tenant.onmicrosoft.com"; Selector2CNAME = "selector2-$domain._domainkey.tenant.onmicrosoft.com" }) }
        'Get-RetentionPolicy' = @{ Items = @(@{ Identity = $retention; Name = $retention; RetentionPolicyTagLinks = @('Never Delete') }) }
        'Get-IRMConfiguration' = @{ Items = @(@{ InternalLicensingEnabled = $true; AzureRMSLicensingEnabled = $true; TransportDecryptionSetting = 'Mandatory'; JournalReportDecryptionEnabled = $true }) }
        'Test-IRMConfiguration' = @{ Items = @(@{ Results = "Acquiring RMS Templates ...`n - PASS: RMS Templates acquired.`nVerifying encryption ...`n - PASS: Encryption verified successfully.`nVerifying decryption ...`n - PASS: Decryption verified successfully.`nVerifying IRM is enabled ...`n - PASS: IRM verified successfully.`nOVERALL RESULT: PASS" }) }
    }
}