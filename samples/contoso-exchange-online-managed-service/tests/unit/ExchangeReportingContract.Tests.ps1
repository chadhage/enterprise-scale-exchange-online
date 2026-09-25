BeforeAll {
    $root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:reportModule = Import-Module (Join-Path $root 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -PassThru
    function New-ReportingContractFixture {
        $mailbox = 'secops@contoso.example'
        $approval = @{ reference = 'OFFLINE-REPORTING'; owner = 'security@contoso.example'; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') }
        $settings = @{ reportingMailbox = $mailbox; approval = $approval; preSubmitMessageEnabled = $true; postSubmitMessageEnabled = $true }
        $proof = @{
            mailbox = $mailbox; approval = $approval
            dlp = @{ mailbox = $mailbox; status = 'NotApplicable'; approval = $approval }
            deliveries = @(foreach ($category in @('Junk','NotJunk','Phish')) {
                @{ category = $category; recipient = $mailbox; reporter = 'user@contoso.example'; messageId = "$category-message"; microsoftSubmissionId = "$category-submission"; feedbackMessageId = "$category-feedback"; receivedAt = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o'); originalMessagePreserved = $true }
            })
        }
        @{
            Context = @{ Configuration = @{ controls = @{ 'MDO-006' = $settings } }; Parameters = @{ reportingEvidence = $proof } }
            State = @{
                Mailbox = @{ PrimarySmtpAddress = $mailbox; RecipientTypeDetails = 'SharedMailbox'; ForwardingAddress = $null; ForwardingSmtpAddress = $null; DeliverToMailboxAndForward = $false }
                Policy = @{ PreSubmitMessageEnabled = $true; PostSubmitMessageEnabled = $true }
                SecOps = @{ SentTo = @($mailbox) }
            }
        }
    }
    function Invoke-ReportingContractFixture {
        param($Fixture)
        & $script:reportModule { param($state,$context) Test-BaselineReportingState $state $context } $Fixture.State $Fixture.Context
    }
    . (Join-Path $PSScriptRoot '../helpers/ExchangeProtectionFixture.ps1')
    function New-ReportingRawFixture {
        $fixture = New-ProtectionFixture
        $contract = New-ReportingContractFixture
        foreach ($key in $contract.Context.Configuration.controls['MDO-006'].Keys) { $fixture.Context.Configuration.controls['MDO-006'][$key] = $contract.Context.Configuration.controls['MDO-006'][$key] }
        $fixture.Context.Parameters.reportingEvidence = $contract.Context.Parameters.reportingEvidence
        $fixture.Raw['Get-Mailbox'].ByIdentity = @{ 'secops@contoso.example' = @($contract.State.Mailbox) }
        foreach ($key in $contract.State.Policy.Keys) { $fixture.Raw['Get-ReportSubmissionPolicy'].Items[0][$key] = $contract.State.Policy[$key] }
        $fixture
    }
}

Describe 'EXR-010 independent Exchange report delivery contract' {
    It 'rejects <Case>' -ForEach @(
        @{ Case = 'external mailbox'; Reason = 'ReportingMailbox'; Mutate = { param($fixture) $fixture.State.Mailbox.RecipientTypeDetails = 'MailUser' } }
        @{ Case = 'wrong mailbox'; Reason = 'ReportingMailbox'; Mutate = { param($fixture) $fixture.State.Mailbox.PrimarySmtpAddress = 'other@contoso.example' } }
        @{ Case = 'forwarding target'; Reason = 'ReportingMailbox'; Mutate = { param($fixture) $fixture.State.Mailbox.ForwardingSmtpAddress = 'external@example.net' } }
        @{ Case = 'forward and deliver'; Reason = 'ReportingMailbox'; Mutate = { param($fixture) $fixture.State.Mailbox.DeliverToMailboxAndForward = $true } }
        @{ Case = 'missing mailbox property'; Reason = 'ReportingMailbox'; Mutate = { param($fixture) $fixture.State.Mailbox.Remove('ForwardingAddress') } }
        @{ Case = 'broad SecOps exception'; Reason = 'ReportingSecOps'; Mutate = { param($fixture) $fixture.State.SecOps.SentTo += '*@contoso.example' } }
        @{ Case = 'feedback drift'; Reason = 'ReportingFeedback'; Mutate = { param($fixture) $fixture.State.Policy.PostSubmitMessageEnabled = $false } }
        @{ Case = 'absent delivery evidence'; Reason = 'ReportingEvidence'; Mutate = { param($fixture) $fixture.Context.Parameters.Remove('reportingEvidence') } }
        @{ Case = 'unapproved reporting'; Reason = 'Approval'; Mutate = { param($fixture) $fixture.Context.Configuration.controls['MDO-006'].approval = $null } }
        @{ Case = 'expired delivery evidence'; Reason = 'ApprovalExpired'; Mutate = { param($fixture) $fixture.Context.Parameters.reportingEvidence.approval = @{ reference = 'expired'; owner = 'security'; expiresOn = '2000-01-01T00:00:00Z' } } }
        @{ Case = 'missing DLP handoff'; Reason = 'ReportingDlp'; Mutate = { param($fixture) $fixture.Context.Parameters.reportingEvidence.Remove('dlp') } }
        @{ Case = 'unverified DLP handoff'; Reason = 'ReportingDlp'; Mutate = { param($fixture) $fixture.Context.Parameters.reportingEvidence.dlp.status = 'Unverified' } }
        @{ Case = 'misbound DLP handoff'; Reason = 'ReportingDlp'; Mutate = { param($fixture) $fixture.Context.Parameters.reportingEvidence.dlp.mailbox = 'other@contoso.example' } }
        @{ Case = 'missing category'; Reason = 'ReportingDelivery'; Mutate = { param($fixture) $fixture.Context.Parameters.reportingEvidence.deliveries = @($fixture.Context.Parameters.reportingEvidence.deliveries | Select-Object -First 2) } }
        @{ Case = 'duplicate category'; Reason = 'ReportingDelivery'; Mutate = { param($fixture) $fixture.Context.Parameters.reportingEvidence.deliveries[1].category = 'Junk' } }
        @{ Case = 'wrong delivery recipient'; Reason = 'ReportingDelivery'; Mutate = { param($fixture) $fixture.Context.Parameters.reportingEvidence.deliveries[0].recipient = 'other@contoso.example' } }
        @{ Case = 'no Microsoft submission'; Reason = 'ReportingDelivery'; Mutate = { param($fixture) $fixture.Context.Parameters.reportingEvidence.deliveries[0].microsoftSubmissionId = '' } }
        @{ Case = 'no feedback proof'; Reason = 'ReportingDelivery'; Mutate = { param($fixture) $fixture.Context.Parameters.reportingEvidence.deliveries[0].feedbackMessageId = '' } }
        @{ Case = 'altered original'; Reason = 'ReportingDelivery'; Mutate = { param($fixture) $fixture.Context.Parameters.reportingEvidence.deliveries[0].originalMessagePreserved = $false } }
        @{ Case = 'future receipt'; Reason = 'ReportingDelivery'; Mutate = { param($fixture) $fixture.Context.Parameters.reportingEvidence.deliveries[0].receivedAt = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') } }
        @{ Case = 'stale receipt'; Reason = 'ReportingDelivery'; Mutate = { param($fixture) $fixture.Context.Parameters.reportingEvidence.deliveries[0].receivedAt = [datetimeoffset]::UtcNow.AddDays(-31).ToString('o') } }
    ) {
        $fixture = New-ReportingContractFixture
        & $Mutate $fixture
        $result = Invoke-ReportingContractFixture $fixture
        $result.Status | Should -BeExactly Fail
        $result.Reason | Should -Match $Reason
    }
    It 'accepts one approved Exchange mailbox and three independently evidenced report categories' {
        $fixture = New-ReportingContractFixture
        $result = Invoke-ReportingContractFixture $fixture
        $result.Status | Should -BeExactly Pass
        $result.Reason | Should -Match 'ReportingVerified'
        $result.ExternalReadiness | Should -BeExactly Unverified
    }
}

Describe 'EXR-010 reporting through raw Exchange registry' {
    It 'rejects <Case> through the public registry' -ForEach @(
        @{ Case = 'missing independent report'; Reason = 'ReportingEvidenceMissing'; Mutate = { param($fixture) $fixture.Context.Parameters.Remove('reportingEvidence') } }
        @{ Case = 'nonmailbox recipient'; Reason = 'ReportingMailbox'; Mutate = { param($fixture) $fixture.Raw['Get-Mailbox'].ByIdentity['secops@contoso.example'][0].RecipientTypeDetails = 'MailUser' } }
        @{ Case = 'missing feedback field'; Reason = 'ExchangeRawPropertyMissing'; Mutate = { param($fixture) $fixture.Raw['Get-ReportSubmissionPolicy'].Items[0].Remove('PostSubmitMessageEnabled') } }
    ) {
        $fixture = New-ReportingRawFixture
        & $Mutate $fixture
        $result = Invoke-ProtectionRawRegistry $fixture $script:reportModule | Where-Object ControlId -eq MDO-006
        $result.Result.Status | Should -Not -Be Pass
        $result.Result.Reason | Should -Match $Reason
    }
    It 'retains raw mailbox and delivery evidence for an approved report workflow' {
        $fixture = New-ReportingRawFixture
        $result = Invoke-ProtectionRawRegistry $fixture $script:reportModule | Where-Object ControlId -eq MDO-006
        $result.Result.Status | Should -BeExactly Pass
        $result.Evidence.Value.ReportingState.Mailbox.PrimarySmtpAddress | Should -BeExactly 'secops@contoso.example'
        @($result.Evidence.Value.ReportingEvidence.deliveries).Count | Should -Be 3
        @($result.Evidence.Observation | Where-Object { $_.Command -eq 'Get-Mailbox' -and $_.Arguments.Identity -eq 'secops@contoso.example' }).Count | Should -Be 1
    }
    It 'refuses an absent report submission rule with a named public result' {
        $fixture = New-ReportingRawFixture
        $fixture.Raw['Get-ReportSubmissionRule'].Items = @()

        $result = Invoke-ProtectionRawRegistry $fixture $script:reportModule | Where-Object ControlId -eq MDO-006

        $result.Result.Status | Should -Not -Be Pass
        $result.Result.Reason | Should -Match 'ReportingRuleMissing'
    }
    It 'refuses a disabled report submission rule with a named public result' {
        $fixture = New-ReportingRawFixture
        $fixture.Raw['Get-ReportSubmissionRule'].Items[0].State = 'Disabled'

        $result = Invoke-ProtectionRawRegistry $fixture $script:reportModule | Where-Object ControlId -eq MDO-006

        $result.Result.Status | Should -Not -Be Pass
        $result.Result.Reason | Should -Match 'ReportingRuleDisabled'
    }
    It 'refuses a report submission rule bound to the wrong policy with a named public result' {
        $fixture = New-ReportingRawFixture
        $fixture.Raw['Get-ReportSubmissionRule'].Items[0].ReportSubmissionPolicy = 'OtherReportSubmissionPolicy'

        $result = Invoke-ProtectionRawRegistry $fixture $script:reportModule | Where-Object ControlId -eq MDO-006

        $result.Result.Status | Should -Not -Be Pass
        $result.Result.Reason | Should -Match 'ReportingRulePolicyMismatch'
    }
    It 'accepts an enabled report submission rule bound to the exact policy with complete receipt evidence' {
        $fixture = New-ReportingRawFixture
        $expectedRule = $fixture.Raw['Get-ReportSubmissionRule'].Items[0]
        $expectedPolicy = $fixture.Raw['Get-ReportSubmissionPolicy'].Items[0]

        $result = Invoke-ProtectionRawRegistry $fixture $script:reportModule | Where-Object ControlId -eq MDO-006

        $result.Result.Status | Should -BeExactly Pass
        $expectedRule.State | Should -BeExactly 'Enabled'
        $expectedRule.ReportSubmissionPolicy | Should -BeExactly $expectedPolicy.Identity
        $result.Evidence.Value.ReportingState.Mailbox.PrimarySmtpAddress | Should -BeExactly 'secops@contoso.example'
        $result.Evidence.Value.ReportingState.Mailbox.ForwardingAddress | Should -BeNullOrEmpty
        $result.Evidence.Value.ReportingState.Mailbox.ForwardingSmtpAddress | Should -BeNullOrEmpty
        $result.Evidence.Value.ReportingState.Mailbox.DeliverToMailboxAndForward | Should -BeFalse
        @($result.Evidence.Value.ReportingState.SecOps.SentTo) | Should -Be @('secops@contoso.example')
        $result.Evidence.Value.ReportingState.Policy.PreSubmitMessageEnabled | Should -BeTrue
        $result.Evidence.Value.ReportingState.Policy.PostSubmitMessageEnabled | Should -BeTrue
        $result.Evidence.Value.ReportingEvidence.dlp.mailbox | Should -BeExactly 'secops@contoso.example'
        $result.Evidence.Value.ReportingEvidence.dlp.status | Should -BeExactly 'NotApplicable'
        $deliveries = @($result.Evidence.Value.ReportingEvidence.deliveries)
        $deliveries.Count | Should -Be 3
        @($deliveries.category | Sort-Object -Unique).Count | Should -Be 3
        @($deliveries.messageId | Sort-Object -Unique).Count | Should -Be 3
        @($deliveries.microsoftSubmissionId | Sort-Object -Unique).Count | Should -Be 3
        @($deliveries.feedbackMessageId | Sort-Object -Unique).Count | Should -Be 3
        @($deliveries | Where-Object { -not $_.originalMessagePreserved }).Count | Should -Be 0
        @($deliveries | Where-Object { ([datetimeoffset]::UtcNow - [datetimeoffset]::Parse($_.receivedAt)).TotalDays -gt 30 }).Count | Should -Be 0
        @($result.Evidence.Observation | Where-Object Command -eq 'Get-ReportSubmissionRule').Count | Should -Be 1
    }
}