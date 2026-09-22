BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:governanceModule = Import-Module (Join-Path $sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force -PassThru
    function New-MrmGovernanceCase {
        @{
            Desired = @{
                policyName = 'Approved lifecycle'
                policyType = 'ExchangeMRM'
                approval = @{ reference = 'OFFLINE-LEGAL-009'; owner = 'records@contoso.com'; expiresOn = '2099-01-01T00:00:00Z' }
                tags = @(@{ name = 'Approved archive'; type = 'All'; action = 'MoveToArchive'; ageDays = 365; enabled = $true })
                maximumProcessingAgeDays = 7
                mailboxEntitlement = @(@{ identity = 'custodian@contoso.com'; archive = $true })
            }
            Value = @{
                Policies = @(@{ Identity = 'Approved lifecycle'; Name = 'Approved lifecycle'; RetentionPolicyTagLinks = @('Approved archive') })
                Tags = @(@{ Identity = 'Approved archive'; Name = 'Approved archive'; Type = 'All'; RetentionAction = 'MoveToArchive'; AgeLimitForRetention = [timespan]::FromDays(365); RetentionEnabled = $true })
                Mailboxes = @(@{ Identity = 'custodian'; PrimarySmtpAddress = 'custodian@contoso.com'; RetentionPolicy = 'Approved lifecycle'; RetentionHoldEnabled = $false; ElcProcessingDisabled = $false; ArchiveStatus = 'Active' })
                Processing = @(@{ Identity = 'custodian'; LastSuccess = [datetimeoffset]::UtcNow.AddDays(-1).ToString('o') })
                Organization = @{ ElcProcessingDisabled = $false }
            }
        }
    }
    function New-RbacGovernanceCase {
        $assignment = @{ Identity = 'Scoped recipients'; Role = 'Mail Recipients'; RoleAssignee = 'Approved operators'; RoleAssigneeType = 'RoleGroup'; Delegating = $false; Enabled = $true; RecipientReadScope = 'Organization'; RecipientWriteScope = 'CustomRecipientScope'; ConfigReadScope = 'OrganizationConfig'; ConfigWriteScope = 'None'; CustomRecipientWriteScope = 'Approved recipients'; CustomConfigWriteScope = ''; ExclusiveRecipientWriteScope = ''; ExclusiveConfigWriteScope = '' }
        @{
            Desired = @{
                approvedRoleGroups = @('Approved operators'); approvedMembers = @('operator@contoso.com')
                approval = @{ reference = 'OFFLINE-RBAC-009'; owner = 'security@contoso.com'; expiresOn = '2099-01-01T00:00:00Z' }
                assignments = @($assignment.Clone())
                scopes = @(@{ Identity = 'Approved recipients'; RecipientRoot = ''; RecipientRestrictionFilter = "CustomAttribute1 -eq 'Approved'"; ServerRestrictionFilter = ''; Exclusive = $false })
                mailboxPolicies = @(@{ mailbox = 'custodian@contoso.com'; policy = 'Restricted users' })
                effectiveUsers = @(@{ assignment = 'Scoped recipients'; user = 'operator@contoso.com' })
            }
            Value = @{
                Groups = @(@{ Identity = 'Approved operators'; Name = 'Approved operators'; RoleGroupType = 'Standard'; LinkedPartnerGroupId = ''; LinkedPartnerOrganizationId = '' })
                Members = @(@{ Group = 'Approved operators'; Member = 'operator@contoso.com'; Raw = @{ RecipientType = 'UserMailbox' } })
                Assignments = @($assignment.Clone())
                EffectiveAssignments = @(@{ Identity = 'Scoped recipients'; EffectiveUserName = 'operator@contoso.com'; AssignmentMethod = 'RoleGroup'; AssignmentChain = @('Approved operators') })
                Scopes = @(@{ Identity = 'Approved recipients'; RecipientRoot = ''; RecipientRestrictionFilter = "CustomAttribute1 -eq 'Approved'"; ServerRestrictionFilter = ''; Exclusive = $false })
                Policies = @(@{ Identity = 'Restricted users'; IsDefault = $false })
                Mailboxes = @(@{ Identity = 'custodian'; PrimarySmtpAddress = 'custodian@contoso.com'; RoleAssignmentPolicy = 'Restricted users' })
            }
        }
    }
    function New-HoldGovernanceCase {
        @{
            Desired = @{
                enabled = $true; custodians = @('custodian@contoso.com')
                approval = @{ reference = 'OFFLINE-LEGAL-009'; owner = 'legal@contoso.com'; expiresOn = '2099-01-01T00:00:00Z' }
                holds = @(@{ mailbox = 'custodian@contoso.com'; durationDays = 90; owner = 'legal@contoso.com'; mailboxClass = 'Active'; entitled = $true })
                minimumRecoverableItemsFreeBytes = 1073741824
            }
            Value = @{
                Mailboxes = @(@{ Identity = 'custodian'; ExchangeGuid = '00000000-0000-0000-0000-000000000009'; PrimarySmtpAddress = 'custodian@contoso.com'; LitigationHoldEnabled = $true; LitigationHoldDuration = '90'; LitigationHoldOwner = 'legal@contoso.com'; RecoverableItemsQuota = '100 GB (107,374,182,400 bytes)'; MailboxClass = 'Active' })
                Classes = @('Active','Inactive','SoftDeleted')
                Statistics = @(@{ Identity = 'custodian'; TotalDeletedItemSize = '1 GB (1,073,741,824 bytes)' })
            }
        }
    }
    function New-IrmGovernanceCase {
        @{
            Desired = @{
                internalLicensingEnabled = $true; azureRmsLicensingEnabled = $true; transportDecryptionSetting = 'Disabled'; journalReportDecryptionEnabled = $false
                approval = @{ reference = 'OFFLINE-LEGAL-009'; owner = 'legal@contoso.com'; expiresOn = '2099-01-01T00:00:00Z' }
                decryptionApproval = @{ transport = 'Disabled'; journal = $false }
                messageClasses = @(@{ name = 'LegalAdvice'; rule = 'Approved legal encryption'; header = 'X-Business-Class'; recipients = @('custodian@contoso.com'); template = 'Do Not Forward'; sender = 'legal@contoso.com'; entitled = $true })
            }
            Value = @{
                Configuration = @{ InternalLicensingEnabled = $true; AzureRMSLicensingEnabled = $true; TransportDecryptionSetting = 'Disabled'; JournalReportDecryptionEnabled = $false }
                Functional = @(@{ Class = 'LegalAdvice'; Sender = 'legal@contoso.com'; Recipient = 'custodian@contoso.com'; Results = 'OVERALL RESULT: PASS' })
                Rules = @(@{ Identity = 'Approved legal encryption'; Name = 'Approved legal encryption'; State = 'Enabled'; Mode = 'Enforce'; HeaderContainsMessageHeader = 'X-Business-Class'; HeaderContainsWords = @('LegalAdvice'); SentTo = @('custodian@contoso.com'); ApplyRightsProtectionTemplate = 'Do Not Forward'; RemoveOME = $false; RemoveOMEv2 = $false; StopRuleProcessing = $false; Priority = 0; Conditions = @(@{ Name = 'HeaderContains' },@{ Name = 'SentTo' }); Exceptions = @() })
                RecipientFlows = @(@{ Class = 'LegalAdvice'; Recipient = 'custodian@contoso.com'; Protected = $true; AuthorizedDecryption = $true; UnauthorizedRejected = $true; EvidenceReference = 'OFFLINE-FLOW-009'; ObservedAtUtc = [datetimeoffset]::UtcNow.AddHours(-1).ToString('o') })
            }
        }
    }
}

Describe 'EXR-009 Exchange MRM semantic evaluation' {
    It 'rejects <Case>' -ForEach @(
        @{ Case = 'unapproved policy type'; Mutation = { param($fixture) $fixture.Desired.policyType = 'PurviewRetention' } }
        @{ Case = 'missing legal approval'; Mutation = { param($fixture) $fixture.Desired.Remove('approval') } }
        @{ Case = 'expired legal approval'; Mutation = { param($fixture) $fixture.Desired.approval.expiresOn = '2000-01-01T00:00:00Z' } }
        @{ Case = 'wrong tag link'; Mutation = { param($fixture) $fixture.Value.Policies[0].RetentionPolicyTagLinks = @('Other') } }
        @{ Case = 'missing linked tag'; Mutation = { param($fixture) $fixture.Value.Tags = @() } }
        @{ Case = 'wrong retention action'; Mutation = { param($fixture) $fixture.Value.Tags[0].RetentionAction = 'PermanentlyDelete' } }
        @{ Case = 'wrong retention age'; Mutation = { param($fixture) $fixture.Value.Tags[0].AgeLimitForRetention = [timespan]::FromDays(2555) } }
        @{ Case = 'disabled retention tag'; Mutation = { param($fixture) $fixture.Value.Tags[0].RetentionEnabled = $false } }
        @{ Case = 'wrong retention tag type'; Mutation = { param($fixture) $fixture.Value.Tags[0].Type = 'DeletedItems' } }
        @{ Case = 'mailbox retention hold'; Mutation = { param($fixture) $fixture.Value.Mailboxes[0].RetentionHoldEnabled = $true } }
        @{ Case = 'mailbox processing disabled'; Mutation = { param($fixture) $fixture.Value.Mailboxes[0].ElcProcessingDisabled = $true } }
        @{ Case = 'organization processing disabled'; Mutation = { param($fixture) $fixture.Value.Organization.ElcProcessingDisabled = $true } }
        @{ Case = 'missing processing evidence'; Mutation = { param($fixture) $fixture.Value.Processing = @() } }
        @{ Case = 'stale processing evidence'; Mutation = { param($fixture) $fixture.Value.Processing[0].LastSuccess = '2000-01-01T00:00:00Z' } }
        @{ Case = 'archive not active'; Mutation = { param($fixture) $fixture.Value.Mailboxes[0].ArchiveStatus = 'None' } }
        @{ Case = 'archive entitlement absent'; Mutation = { param($fixture) $fixture.Desired.mailboxEntitlement = @() } }
        @{ Case = 'future processing evidence'; Mutation = { param($fixture) $fixture.Value.Processing[0].LastSuccess = '2099-01-01T00:00:00Z' } }
        @{ Case = 'unbounded processing age'; Mutation = { param($fixture) $fixture.Desired.maximumProcessingAgeDays = 0 } }
        @{ Case = 'missing retention enabled state'; Mutation = { param($fixture) $fixture.Value.Tags[0].Remove('RetentionEnabled') } }
        @{ Case = 'duplicate tag identity'; Mutation = { param($fixture) $fixture.Value.Tags += $fixture.Value.Tags[0] } }
        @{ Case = 'malformed retention age'; Mutation = { param($fixture) $fixture.Value.Tags[0].AgeLimitForRetention = 'unknown' } }
        @{ Case = 'approval owner absent'; Mutation = { param($fixture) $fixture.Desired.approval.owner = '' } }
    ) {
        # Arrange
        $fixture = New-MrmGovernanceCase
        & $Mutation $fixture
        $evidence = New-BaselineEvidence -ControlId GOV-003 -Source ExchangeOnline -Command 'Get-RetentionPolicy; Get-RetentionPolicyTag; Get-Mailbox; Export-MailboxDiagnosticLogs' -Value $fixture.Value
        # Act
        $result = & $governanceModule { param($evidence, $desired) Test-BaselineExchangeBoundaryControl -ControlId GOV-003 -Evidence $evidence -DesiredState $desired } $evidence $fixture.Desired
        # Assert
        $result.Status | Should -Not -Be Pass
        $result.Reason | Should -Match 'ExchangeMrm'
    }
    It 'passes one approved MRM lifecycle without certifying preservation policy' {
        # Arrange
        $fixture = New-MrmGovernanceCase
        $evidence = New-BaselineEvidence -ControlId GOV-003 -Source ExchangeOnline -Command 'Get-RetentionPolicy; Get-RetentionPolicyTag; Get-Mailbox; Export-MailboxDiagnosticLogs' -Value $fixture.Value
        # Act
        $result = & $governanceModule { param($evidence, $desired) Test-BaselineExchangeBoundaryControl -ControlId GOV-003 -Evidence $evidence -DesiredState $desired } $evidence $fixture.Desired
        # Assert
        $result.Status | Should -Be Pass
        $result.Reason | Should -Match 'ExchangeMrmVerified.*ExternalPreservationUnverified'
    }
}

Describe 'EXR-009 effective Exchange RBAC evaluation' {
    It 'rejects <Case>' -ForEach @(
        @{ Case = 'missing RBAC approval'; Mutation = { param($fixture) $fixture.Desired.Remove('approval') } }
        @{ Case = 'excess direct assignment'; Mutation = { param($fixture) $extra = $fixture.Value.Assignments[0].Clone(); $extra.Identity = 'Direct bypass'; $extra.RoleAssigneeType = 'User'; $extra.RoleAssignee = 'operator@contoso.com'; $fixture.Value.Assignments += $extra } }
        @{ Case = 'unapproved delegation'; Mutation = { param($fixture) $fixture.Value.Assignments[0].Delegating = $true } }
        @{ Case = 'broader recipient scope'; Mutation = { param($fixture) $fixture.Value.Assignments[0].RecipientWriteScope = 'Organization' } }
        @{ Case = 'changed custom scope'; Mutation = { param($fixture) $fixture.Value.Scopes[0].RecipientRestrictionFilter = "RecipientType -eq 'UserMailbox'" } }
        @{ Case = 'missing custom scope'; Mutation = { param($fixture) $fixture.Value.Scopes = @() } }
        @{ Case = 'nested membership excess'; Mutation = { param($fixture) $fixture.Value.EffectiveAssignments += @{ Identity = 'Scoped recipients'; EffectiveUserName = 'unapproved@contoso.com'; AssignmentMethod = 'SecurityGroup'; AssignmentChain = @('Approved operators','Nested operators') } } }
        @{ Case = 'unresolved effective user'; Mutation = { param($fixture) $fixture.Value.EffectiveAssignments[0].EffectiveUserName = '' } }
        @{ Case = 'partner linked provenance'; Mutation = { param($fixture) $fixture.Value.Groups[0].RoleGroupType = 'PartnerLinked'; $fixture.Value.Groups[0].LinkedPartnerGroupId = 'unverified-partner' } }
        @{ Case = 'unassigned mailbox policy'; Mutation = { param($fixture) $fixture.Value.Mailboxes[0].RoleAssignmentPolicy = 'Default Role Assignment Policy' } }
        @{ Case = 'prohibited nondefault addin grant'; Mutation = { param($fixture) $extra = $fixture.Value.Assignments[0].Clone(); $extra.Identity = 'Nondefault addin bypass'; $extra.Role = 'My Custom Apps'; $extra.RoleAssignee = 'Restricted users'; $extra.RoleAssigneeType = 'RoleAssignmentPolicy'; $fixture.Value.Assignments += $extra; $fixture.Desired.assignments += $extra.Clone() } }
        @{ Case = 'missing effective membership'; Mutation = { param($fixture) $fixture.Value.EffectiveAssignments = @() } }
        @{ Case = 'missing effective assignment provenance'; Mutation = { param($fixture) $fixture.Value.EffectiveAssignments[0].AssignmentChain = @(); $fixture.Value.EffectiveAssignments[0].AssignmentMethod = '' } }
        @{ Case = 'missing mailbox population'; Mutation = { param($fixture) $fixture.Value.Mailboxes = @() } }
        @{ Case = 'missing assignment scope'; Mutation = { param($fixture) $fixture.Value.Assignments[0].Remove('RecipientReadScope') } }
    ) {
        # Arrange
        $fixture = New-RbacGovernanceCase
        & $Mutation $fixture
        $evidence = New-BaselineEvidence -ControlId EXO-010 -Source ExchangeOnline -Command 'Get-ManagementRoleAssignment -GetEffectiveUsers' -Value $fixture.Value
        # Act
        $result = & $governanceModule { param($evidence, $desired) Test-BaselineExchangeBoundaryControl -ControlId EXO-010 -Evidence $evidence -DesiredState $desired } $evidence $fixture.Desired
        # Assert
        $result.Status | Should -Not -Be Pass
        $result.Reason | Should -Match 'ExchangeRbac'
    }
    It 'passes one exact approved assignment graph and nondefault mailbox policy' {
        # Arrange
        $fixture = New-RbacGovernanceCase
        $evidence = New-BaselineEvidence -ControlId EXO-010 -Source ExchangeOnline -Command 'Get-ManagementRoleAssignment -GetEffectiveUsers' -Value $fixture.Value
        # Act
        $result = & $governanceModule { param($evidence, $desired) Test-BaselineExchangeBoundaryControl -ControlId EXO-010 -Evidence $evidence -DesiredState $desired } $evidence $fixture.Desired
        # Assert
        $result.Status | Should -Be Pass
        $result.Reason | Should -Match 'ExchangeRbacVerified.*ExternalIdentityUnverified'
    }
}

Describe 'EXR-009 legally approved hold evaluation' {
    It 'rejects <Case>' -ForEach @(
        @{ Case = 'missing hold approval'; Mutation = { param($fixture) $fixture.Desired.Remove('approval') } }
        @{ Case = 'unauthorized duration'; Mutation = { param($fixture) $fixture.Value.Mailboxes[0].LitigationHoldDuration = 'Unlimited' } }
        @{ Case = 'unauthorized hold owner'; Mutation = { param($fixture) $fixture.Value.Mailboxes[0].LitigationHoldOwner = 'other@contoso.com' } }
        @{ Case = 'missing mailbox entitlement'; Mutation = { param($fixture) $fixture.Desired.holds[0].Remove('entitled') } }
        @{ Case = 'negative mailbox entitlement'; Mutation = { param($fixture) $fixture.Desired.holds[0].entitled = $false } }
        @{ Case = 'omitted inactive inventory'; Mutation = { param($fixture) $fixture.Value.Classes = @('Active','SoftDeleted') } }
        @{ Case = 'omitted soft deleted inventory'; Mutation = { param($fixture) $fixture.Value.Classes = @('Active','Inactive') } }
        @{ Case = 'unapproved mailbox class'; Mutation = { param($fixture) $fixture.Value.Mailboxes[0].MailboxClass = 'Inactive' } }
        @{ Case = 'recoverable items capacity risk'; Mutation = { param($fixture) $fixture.Value.Statistics[0].TotalDeletedItemSize = '100 GB (107,374,182,400 bytes)' } }
        @{ Case = 'missing recoverable items statistics'; Mutation = { param($fixture) $fixture.Value.Statistics = @() } }
        @{ Case = 'unreadable recoverable quota'; Mutation = { param($fixture) $fixture.Value.Mailboxes[0].RecoverableItemsQuota = 'Unknown' } }
        @{ Case = 'unapproved custodian'; Mutation = { param($fixture) $fixture.Desired.holds[0].mailbox = 'unapproved@contoso.com' } }
    ) {
        # Arrange
        $fixture = New-HoldGovernanceCase
        & $Mutation $fixture
        foreach ($mailbox in $fixture.Value.Mailboxes) {
            $mailbox.InventoryClasses = $fixture.Value.Classes
            $mailbox.Statistics = @($fixture.Value.Statistics | Where-Object Identity -EQ $mailbox.Identity)
        }
        $evidence = New-BaselineEvidence -ControlId GOV-004 -Source ExchangeOnline -Command 'Get-Mailbox; Get-MailboxStatistics' -Value $fixture.Value.Mailboxes
        # Act
        $result = & $governanceModule { param($evidence, $desired) Test-BaselineExchangeBoundaryControl -ControlId GOV-004 -Evidence $evidence -DesiredState $desired } $evidence $fixture.Desired
        # Assert
        $result.Status | Should -Not -Be Pass
        $result.Reason | Should -Match 'ExchangeHold'
    }
    It 'passes one approved custodian inventory with duration entitlement and capacity' {
        # Arrange
        $fixture = New-HoldGovernanceCase
        foreach ($mailbox in $fixture.Value.Mailboxes) {
            $mailbox.InventoryClasses = $fixture.Value.Classes
            $mailbox.Statistics = @($fixture.Value.Statistics | Where-Object Identity -EQ $mailbox.Identity)
        }
        $evidence = New-BaselineEvidence -ControlId GOV-004 -Source ExchangeOnline -Command 'Get-Mailbox; Get-MailboxStatistics' -Value $fixture.Value.Mailboxes
        # Act
        $result = & $governanceModule { param($evidence, $desired) Test-BaselineExchangeBoundaryControl -ControlId GOV-004 -Evidence $evidence -DesiredState $desired } $evidence $fixture.Desired
        # Assert
        $result.Status | Should -Be Pass
        $result.Reason | Should -Match 'ExchangeHoldVerified.*ExternalLegalReadinessUnverified'
    }
}

Describe 'EXR-009 approved encryption message flow evaluation' {
    It 'rejects <Case>' -ForEach @(
        @{ Case = 'missing encryption approval'; Mutation = { param($fixture) $fixture.Desired.Remove('approval') } }
        @{ Case = 'evidence authorizes its own message class'; Mutation = { param($fixture) $fixture.Value.Authorization = $fixture.Desired | ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable; $fixture.Desired.messageClasses[0].name = 'IndependentApprovalClass' } }
        @{ Case = 'unobserved encryption predicates'; Mutation = { param($fixture) $fixture.Value.Rules[0].Remove('Conditions') } }
        @{ Case = 'additional scope-restricting encryption condition'; Mutation = { param($fixture) $fixture.Value.Rules[0].Conditions += @{ Name = 'From' } } }
        @{ Case = 'encryption rule exception'; Mutation = { param($fixture) $fixture.Value.Rules[0].Exceptions = @(@{ Name = 'SentTo' }) } }
        @{ Case = 'message class scope gap'; Mutation = { param($fixture) $fixture.Value.Rules[0].HeaderContainsWords = @('OtherClass') } }
        @{ Case = 'encryption recipient scope gap'; Mutation = { param($fixture) $fixture.Value.Rules[0].SentTo = @('other@contoso.com') } }
        @{ Case = 'encryption rule disabled'; Mutation = { param($fixture) $fixture.Value.Rules[0].State = 'Disabled' } }
        @{ Case = 'encryption rule audit only'; Mutation = { param($fixture) $fixture.Value.Rules[0].Mode = 'Audit' } }
        @{ Case = 'wrong rights template'; Mutation = { param($fixture) $fixture.Value.Rules[0].ApplyRightsProtectionTemplate = 'Encrypt' } }
        @{ Case = 'IRM functional failure'; Mutation = { param($fixture) $fixture.Value.Functional[0].Results = 'OVERALL RESULT: FAIL' } }
        @{ Case = 'IRM selftest instead of recipient'; Mutation = { param($fixture) $fixture.Value.Functional[0].Recipient = 'legal@contoso.com' } }
        @{ Case = 'missing recipient evidence'; Mutation = { param($fixture) $fixture.Value.RecipientFlows = @() } }
        @{ Case = 'unauthorized recipient can decrypt'; Mutation = { param($fixture) $fixture.Value.RecipientFlows[0].UnauthorizedRejected = $false } }
        @{ Case = 'authorized recipient cannot decrypt'; Mutation = { param($fixture) $fixture.Value.RecipientFlows[0].AuthorizedDecryption = $false } }
        @{ Case = 'missing encryption entitlement'; Mutation = { param($fixture) $fixture.Desired.messageClasses[0].Remove('entitled') } }
        @{ Case = 'unapproved transport decryption'; Mutation = { param($fixture) $fixture.Desired.transportDecryptionSetting = 'Mandatory'; $fixture.Value.Configuration.TransportDecryptionSetting = 'Mandatory' } }
        @{ Case = 'unapproved journal decryption'; Mutation = { param($fixture) $fixture.Desired.journalReportDecryptionEnabled = $true; $fixture.Value.Configuration.JournalReportDecryptionEnabled = $true } }
        @{ Case = 'encryption removal rule'; Mutation = { param($fixture) $fixture.Value.Rules[0].RemoveOMEv2 = $true } }
    ) {
        # Arrange
        $fixture = New-IrmGovernanceCase
        & $Mutation $fixture
        if (-not $fixture.Value.ContainsKey('Authorization')) { $fixture.Value.Authorization = $fixture.Desired }
        $configuration = $fixture.Desired
        $evidence = New-BaselineEvidence -ControlId GOV-005 -Source ExchangeOnline -Command 'Get-TransportRule; Get-IRMConfiguration; Test-IRMConfiguration' -Value $fixture.Value
        # Act
        $result = & $governanceModule { param($evidence, $desired) Test-BaselineExchangeBoundaryControl -ControlId GOV-005 -Evidence $evidence -DesiredState $desired } $evidence $configuration
        # Assert
        $result.Status | Should -Not -Be Pass
        $result.Reason | Should -Match 'ExchangeIrm'
    }
    It 'passes one approved message-class recipient contract without claiming live delivery' {
        # Arrange
        $fixture = New-IrmGovernanceCase
        $fixture.Value.Authorization = $fixture.Desired
        $configuration = $fixture.Desired
        $evidence = New-BaselineEvidence -ControlId GOV-005 -Source ExchangeOnline -Command 'Get-TransportRule; Get-IRMConfiguration; Test-IRMConfiguration' -Value $fixture.Value
        # Act
        $result = & $governanceModule { param($evidence, $desired) Test-BaselineExchangeBoundaryControl -ControlId GOV-005 -Evidence $evidence -DesiredState $desired } $evidence $configuration
        # Assert
        $result.Status | Should -Be Pass
        $result.Reason | Should -Match 'ExchangeIrmVerified.*ExternalRecipientDeliveryUnverified'
    }
}