$script:ExchangeLiveBaseRawConstructor = & {
    . (Join-Path $PSScriptRoot 'ExchangeLiveRawFixture.ps1')
    (Get-Item Function:\New-ExchangeLiveBaseRawFixture).ScriptBlock
}
$script:ExchangeProtectionGovernanceScope = New-Module -Name ExchangeProtectionGovernanceFixtureScope `
    -ArgumentList (Join-Path $PSScriptRoot 'ExchangeProtectionFixture.ps1') -ScriptBlock {
    param($ProtectionFixturePath)
    . $ProtectionFixturePath
}

function New-ExchangeGovernanceRawFixture {
    param($Parameters)
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $raw = & $script:ExchangeLiveBaseRawConstructor $Parameters
    $configuration = Get-Content (Join-Path $sampleRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
    $mailbox = 'user@' + $Parameters.PRIMARY_SMTP_DOMAIN
    $policy = $Parameters.MAILBOX_RETENTION_POLICY_NAME
    $approval = @{ reference = 'SYNTHETIC-OFFLINE-009'; owner = 'legal@contoso.com'; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') }
    $assignment = @{ Identity = 'MyBaseOptions-Default Role Assignment Policy'; Name = 'MyBaseOptions-Default Role Assignment Policy'; Role = 'MyBaseOptions'; RoleAssignee = 'Default Role Assignment Policy'; RoleAssigneeType = 'RoleAssignmentPolicy'; Delegating = $false; Enabled = $true; RecipientReadScope = 'Self'; RecipientWriteScope = 'Self'; ConfigReadScope = 'None'; ConfigWriteScope = 'None'; CustomRecipientWriteScope = ''; CustomConfigWriteScope = ''; ExclusiveRecipientWriteScope = ''; ExclusiveConfigWriteScope = '' }
    $configuration.controls['EXO-010'] = @{
        approvedRoleGroups = @('Organization Management'); approvedMembers = @(); approval = $approval.Clone()
        assignments = @($assignment.Clone()); scopes = @()
        mailboxPolicies = @(@{ mailbox = $mailbox; policy = 'Default Role Assignment Policy' })
        effectiveUsers = @(@{ assignment = $assignment.Identity; user = 'Mailbox One' })
    }
    $configuration.controls['GOV-003'] = @{
        policyName = $policy; policyType = 'ExchangeMRM'; approval = $approval.Clone()
        tags = @(@{ name = 'Approved archive'; type = 'All'; action = 'MoveToArchive'; ageDays = 365; enabled = $true })
        maximumProcessingAgeDays = 7; mailboxEntitlement = @(@{ identity = $mailbox; archive = $true })
    }
    $configuration.controls['GOV-004'] = @{
        enabled = $true; custodians = @($mailbox); approval = $approval.Clone()
        holds = @(@{ mailbox = $mailbox; durationDays = 90; owner = 'legal@contoso.com'; mailboxClass = 'Active'; entitled = $true })
        minimumRecoverableItemsFreeBytes = 1073741824
    }
    $configuration.controls['GOV-005'] = @{
        internalLicensingEnabled = $true; azureRmsLicensingEnabled = $true; transportDecryptionSetting = 'Disabled'; journalReportDecryptionEnabled = $false
        approval = $approval.Clone(); decryptionApproval = @{ transport = 'Disabled'; journal = $false }
        messageClasses = @(@{ name = 'LegalAdvice'; rule = 'Approved legal encryption'; header = 'X-Business-Class'; recipients = @($mailbox); template = 'Do Not Forward'; sender = $Parameters.SECURITY_OPERATIONS_MAILBOX; entitled = $true })
    }
    $raw['Get-Mailbox'].Items[0]['ExchangeGuid'] = '00000000-0000-0000-0000-000000000009'
    $raw['Get-Mailbox'].Items[0]['RoleAssignmentPolicy'] = 'Default Role Assignment Policy'
    $raw['Get-Mailbox'].Items[0]['RetentionHoldEnabled'] = $false
    $raw['Get-Mailbox'].Items[0]['ElcProcessingDisabled'] = $false
    $raw['Get-Mailbox'].Items[0]['ArchiveStatus'] = 'Active'
    $raw['Get-Mailbox'].Items[0].LitigationHoldEnabled = $true
    $raw['Get-Mailbox'].Items[0]['LitigationHoldDuration'] = '90'
    $raw['Get-Mailbox'].Items[0]['LitigationHoldOwner'] = 'legal@contoso.com'
    $raw['Get-Mailbox'].Items[0]['RecoverableItemsQuota'] = '100 GB (107,374,182,400 bytes)'
    $raw['Get-Mailbox']['Inactive'] = @()
    $raw['Get-Mailbox']['SoftDeleted'] = @()
    $raw['Get-MailboxStatistics'] = @{ Items = @(@{ DisplayName = 'Mailbox One'; TotalDeletedItemSize = '1 GB (1,073,741,824 bytes)' }) }
    $raw['Get-OrganizationConfig'].Items[0]['ElcProcessingDisabled'] = $false
    $raw['Get-RoleGroup'].Items[0]['RoleGroupType'] = 'Standard'
    $raw['Get-RoleGroup'].Items[0]['LinkedPartnerGroupId'] = ''
    $raw['Get-RoleGroup'].Items[0]['LinkedPartnerOrganizationId'] = ''
    $raw['Get-ManagementRoleAssignment'].Items = @($assignment)
    $raw['Get-ManagementRoleAssignment']['Effective'] = @(@{ Identity = $assignment.Identity; EffectiveUserName = 'Mailbox One'; AssignmentMethod = 'RoleAssignmentPolicy'; AssignmentChain = @('Default Role Assignment Policy') })
    $raw['Get-ManagementScope'] = @{ Items = @() }
    $raw['Get-RetentionPolicy'].Items[0].RetentionPolicyTagLinks = @('Approved archive')
    $raw['Get-RetentionPolicyTag'] = @{ Items = @(@{ Identity = 'Approved archive'; Name = 'Approved archive'; Type = 'All'; RetentionAction = 'MoveToArchive'; AgeLimitForRetention = '365.00:00:00'; RetentionEnabled = $true }) }
    $raw['Export-MailboxDiagnosticLogs'] = @{ Items = @(@{ MailboxLog = '<Properties><MailboxTable><Property Name="ELCLastSuccessTimestamp" Value="' + [datetimeoffset]::UtcNow.AddHours(-1).ToString('o') + '" /></MailboxTable></Properties>' }) }
    $raw['Get-IRMConfiguration'].Items[0].TransportDecryptionSetting = 'Disabled'
    $raw['Get-IRMConfiguration'].Items[0].JournalReportDecryptionEnabled = $false
    $raw['Get-TransportRule'] = @{ Items = @(@{ Identity = 'Approved legal encryption'; Name = 'Approved legal encryption'; State = 'Enabled'; Mode = 'Enforce'; HeaderContainsMessageHeader = 'X-Business-Class'; HeaderContainsWords = @('LegalAdvice'); SentTo = @($mailbox); ApplyRightsProtectionTemplate = 'Do Not Forward'; RemoveOME = $false; RemoveOMEv2 = $false; StopRuleProcessing = $false; Priority = 0 }) }
    $flows = @(@{ Class = 'LegalAdvice'; Recipient = $mailbox; Protected = $true; AuthorizedDecryption = $true; UnauthorizedRejected = $true; EvidenceReference = 'SYNTHETIC-OFFLINE-RECIPIENT-FLOW'; ObservedAtUtc = [datetimeoffset]::UtcNow.AddHours(-1).ToString('o') })
    $raw['Get-TransportRule'].Items[0]['Conditions'] = @(@{ Name = 'HeaderContains' },@{ Name = 'SentTo' })
    $raw['Get-TransportRule'].Items[0]['Exceptions'] = @()
    $fixture = @{ Raw = $raw; Configuration = $configuration; RecipientFlows = $flows }
    & $script:ExchangeProtectionGovernanceScope {
        param($Fixture, $Parameters)
        Add-ProtectionGovernanceFixture $Fixture $Parameters
    } $fixture $Parameters

    foreach ($casMailbox in @($raw['Get-CASMailbox'].Items)) {
        $casMailbox['EwsEnabled'] = $false
    }
    foreach ($contentPolicy in @($raw['Get-HostedContentFilterPolicy'].Items)) {
        $contentPolicy['SpoofQuarantineTag'] = if (
            [string]$contentPolicy.Name -ceq 'Strict Preset Security Policy'
        ) {
            'DefaultFullAccessWithNotificationPolicy'
        }
        else {
            'DefaultFullAccessPolicy'
        }
    }

    foreach ($mailboxPlan in @($raw['Get-CASMailboxPlan'].Items)) {
        $mailboxPlan['EwsAllowList'] = @()
    }
    foreach ($policyType in @('GlobalQuarantinePolicy', 'QuarantinePolicy')) {
        foreach ($quarantinePolicy in @($raw['Get-QuarantinePolicy'].ByType[$policyType])) {
            if (-not $quarantinePolicy.ContainsKey('EndUserSpamNotificationFrequency')) {
                $quarantinePolicy['EndUserSpamNotificationFrequency'] = $null
            }
            if (-not $quarantinePolicy.ContainsKey('IncludeMessagesFromBlockedSenderAddress')) {
                $quarantinePolicy['IncludeMessagesFromBlockedSenderAddress'] = $null
            }
        }
    }
    foreach ($quarantinePolicy in @($raw['Get-QuarantinePolicy'].Items)) {
        if (-not $quarantinePolicy.ContainsKey('EndUserSpamNotificationFrequency')) {
            $quarantinePolicy['EndUserSpamNotificationFrequency'] = $null
        }
        if (-not $quarantinePolicy.ContainsKey('IncludeMessagesFromBlockedSenderAddress')) {
            $quarantinePolicy['IncludeMessagesFromBlockedSenderAddress'] = $null
        }
    }
    $raw['Get-IRMConfiguration'].Items[0]['LicensingLocation'] = 'Online'

    $raw['Get-ActivePimAssignment'] = @{ Items = @() }
    $raw['Get-EligiblePimAssignment'] = @{ Items = @() }
    $raw['Get-AccessReview'] = @{ Items = @(
        $configuration.controls['EXO-010'].assignments |
            ForEach-Object {
                @{
                    displayName = "Offline $($_.Role) access review"
                    scopeRoleDefinitionId = [string]$_.Role
                    lastCompletedDateTime = [datetimeoffset]::UtcNow.AddHours(-1).ToString('o')
                }
            }
    ) }
    $dkim = @($raw['Get-DkimSigningConfig'].Items)[0]
    $raw['Resolve-DkimSelectorDns'] = @{ Items = @(); ByIdentity = @{
        "selector1._domainkey.$($Parameters.PRIMARY_SMTP_DOMAIN)" = @(@{
            Authoritative = $true
            CanonicalName = [string]$dkim.Selector1CNAME
        })
        "selector2._domainkey.$($Parameters.PRIMARY_SMTP_DOMAIN)" = @(@{
            Authoritative = $true
            CanonicalName = [string]$dkim.Selector2CNAME
        })
    } }
    $raw['Get-MailboxRetentionDistribution'] = @{ Items = @(@{
        Status = 'Success'
        CoveredMailboxes = @($raw['Get-Mailbox'].Items | ForEach-Object { [string]$_.PrimarySmtpAddress })
        ProcessedAtUtc = [datetimeoffset]::UtcNow.AddHours(-1).ToString('o')
        Refused = @()
    }) }
    $raw['Resolve-PriorityIdentity'] = @{ Items = @(@{
        Resolved = $true
        Identities = @($configuration.controls['GOV-004'].holds | ForEach-Object { [string]$_.mailbox })
        Unresolved = @()
    }) }
    $raw['Resolve-Custodian'] = @{ Items = @(@{
        Resolved = $true
        Identities = @($configuration.controls['GOV-004'].custodians | ForEach-Object { [string]$_ })
        Unresolved = @()
    }) }
    foreach ($command in @(
        'Get-ActivePimAssignment',
        'Get-EligiblePimAssignment',
        'Get-AccessReview',
        'Get-MailboxRetentionDistribution',
        'Resolve-PriorityIdentity',
        'Resolve-Custodian'
    )) {
        if (-not $raw.Contains($command) -or $null -eq $raw[$command]) {
            throw "Protection governance fixture did not create '$command'."
        }
    }

    $tenantIdentity = [string]$Parameters.MICROSOFT_ENTRA_TENANT_GUID
    foreach ($command in @('Get-ActivePimAssignment', 'Get-EligiblePimAssignment')) {
        $raw[$command]['ByIdentity'] = @{ $tenantIdentity = @($raw[$command].Items) }
    }
    $governedRole = @($configuration.controls['EXO-010'].assignments | ForEach-Object { [string]$_.Role } | Sort-Object -Unique)
    $raw['Get-AccessReview']['ByIdentity'] = @{ ($governedRole -join '|') = @($raw['Get-AccessReview'].Items) }
    $raw['Get-MailboxRetentionDistribution']['ByIdentity'] = @{ $policy = @($raw['Get-MailboxRetentionDistribution'].Items) }
    $priorityIdentity = @($configuration.controls['GOV-004'].holds | ForEach-Object { [string]$_.mailbox })
    $raw['Resolve-PriorityIdentity']['ByIdentity'] = @{ ($priorityIdentity -join '|') = @($raw['Resolve-PriorityIdentity'].Items) }
    $configuredCustodian = @($configuration.controls['GOV-004'].custodians | ForEach-Object { [string]$_ })
    $raw['Resolve-Custodian']['ByIdentity'] = @{ ($configuredCustodian -join '|') = @($raw['Resolve-Custodian'].Items) }
    $omeClass = @($configuration.controls['GOV-005'].messageClasses)[0]
    $omeRoute = '{0}|{1}' -f [string]$omeClass.sender, [string]@($omeClass.recipients)[0]
    $raw['Test-IRMConfiguration']['BySenderRecipient'] = @{ $omeRoute = @($raw['Test-IRMConfiguration'].Items) }
    $fixture
}