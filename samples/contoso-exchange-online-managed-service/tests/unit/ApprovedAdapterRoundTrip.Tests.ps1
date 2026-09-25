BeforeDiscovery {
    $adapterCases = @(
        @{ Scope = 'Organization'; Noun = 'OrganizationConfig'; Field = 'AuditDisabled'; Mutator = 'Set-OrganizationConfig' },
        @{ Scope = 'ExternalSender'; Noun = 'ExternalInOutlook'; Field = 'Enabled'; Mutator = 'Set-ExternalInOutlook' },
        @{ Scope = 'RemoteDomains'; Noun = 'RemoteDomain'; Field = 'NDREnabled'; Mutator = 'Set-RemoteDomain' },
        @{ Scope = 'MailboxProtocols'; Noun = 'CASMailbox'; Field = 'PopEnabled'; Mutator = 'Set-CASMailbox' },
        @{ Scope = 'MailboxPlans'; Noun = 'CASMailboxPlan'; Field = 'PopEnabled'; Mutator = 'Set-CASMailboxPlan' },
        @{ Scope = 'OutboundSpam'; Noun = 'HostedOutboundSpamFilterPolicy'; Field = 'AutoForwardingMode'; Mutator = 'Set-HostedOutboundSpamFilterPolicy' },
        @{ Scope = 'AcceptedDomains'; Noun = 'AcceptedDomain'; Field = 'DomainType'; Mutator = 'Set-AcceptedDomain' },
        @{ Scope = 'ReportSubmission'; Noun = 'ReportSubmissionPolicy'; Field = 'EnableThirdPartyAddress'; Mutator = 'Set-ReportSubmissionPolicy' },
        @{ Scope = 'SecOpsOverride'; Noun = 'SecOpsOverridePolicy'; Field = 'SentTo'; Mutator = 'Set-SecOpsOverridePolicy' },
        @{ Scope = 'Impersonation'; Noun = 'AntiPhishPolicy'; Field = 'EnableTargetedUserProtection'; Mutator = 'Set-AntiPhishPolicy' },
        @{ Scope = 'EopPresets'; Noun = 'EOPProtectionPolicyRule'; Field = 'RecipientDomainIs'; Mutator = 'Set-EOPProtectionPolicyRule' },
        @{ Scope = 'AtpPresets'; Noun = 'ATPProtectionPolicyRule'; Field = 'RecipientDomainIs'; Mutator = 'Set-ATPProtectionPolicyRule' },
        @{ Scope = 'BuiltInProtection'; Noun = 'ATPBuiltInProtectionRule'; Field = 'ExceptIfRecipientDomainIs'; Mutator = 'Set-ATPBuiltInProtectionRule' },
        @{ Scope = 'Quarantine'; Noun = 'QuarantinePolicy'; Field = 'EndUserQuarantinePermissionsValue'; Mutator = 'Set-QuarantinePolicy' },
        @{ Scope = 'Forwarding'; Noun = 'Mailbox'; Field = 'ForwardingSmtpAddress'; Mutator = 'Set-Mailbox' },
        @{ Scope = 'AddInAcquisition'; Noun = 'ManagementRoleAssignment'; Field = 'Role'; Mutator = 'Remove-ManagementRoleAssignment' },
        @{ Scope = 'Dkim'; Noun = 'DkimSigningConfig'; Field = 'Enabled'; Mutator = 'Set-DkimSigningConfig' },
        @{ Scope = 'TenantAllowBlockList'; Noun = 'TenantAllowBlockListItems'; Field = 'Notes'; Mutator = 'Remove-TenantAllowBlockListItems' }
    )
    $tablAdmissionNegativeCases = @(
        @{ Case = 'sender wildcard'; EntryType = 'Sender'; EntryValue = '*@contoso.example' },
        @{ Case = 'domain as sender'; EntryType = 'Sender'; EntryValue = 'contoso.example' },
        @{ Case = 'domain wildcard'; EntryType = 'Domain'; EntryValue = '*.contoso.example' },
        @{ Case = 'address as domain'; EntryType = 'Domain'; EntryValue = 'sender@contoso.example' },
        @{ Case = 'URL wildcard'; EntryType = 'Url'; EntryValue = 'https://contoso.example/*' },
        @{ Case = 'non-absolute URL'; EntryType = 'Url'; EntryValue = '/relative/path' },
        @{ Case = 'file wildcard'; EntryType = 'File'; EntryValue = ('a' * 63 + '*') },
        @{ Case = 'non-hash file'; EntryType = 'File'; EntryValue = 'not-a-sha256-hash' }
    )
}
BeforeAll {
    $script:adapterRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:adapterCommand = Join-Path $script:adapterRoot 'scripts/Invoke-ExchangeOnlineChange.ps1'
    Import-Module (Join-Path $script:adapterRoot 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking
    . (Join-Path $PSScriptRoot '../helpers/ApprovedAdapterDoubles.ps1')
    $script:adapterKey = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Offline Adapter', $script:adapterKey, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $script:adapterCertificate = $request.CreateSelfSigned([datetimeoffset]::UtcNow.AddMinutes(-1), [datetimeoffset]::UtcNow.AddDays(1))
    function New-FailedTablRollbackFixture {
        $arguments = New-StatefulAdapterFixture -Scope TenantAllowBlockList -Approved
        $before = Get-AdapterSnapshot
        $apply = & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false
        $apply.Status | Should -BeExactly 'Succeeded'
        $apply.Operation[0].Progress | Should -BeExactly 'Created'
        $global:adapterWriteFault = 'New-TenantAllowBlockListItems'
        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeExecutionFailed*'
        $global:adapterState.TenantAllowBlockListItems.Count | Should -Be 0
        $global:adapterWriteFault = ''
        $attemptPath = @(Get-ChildItem $arguments.ArtifactRoot -Filter 'rollback-attempt-*.json')[0].FullName
        @{ Arguments = $arguments; Before = $before; AttemptPath = $attemptPath; LockPath = (Join-Path $arguments.ArtifactRoot 'rollback-ADAPTER004.lock') }
    }
    function Update-TestRollbackAttemptIndex {
        param($Fixture)
        $history = Get-Content $Fixture.LockPath -Raw | ConvertFrom-Json -AsHashtable -NoEnumerate
        foreach ($record in $history) {
            if ($record.Name -ceq (Split-Path $Fixture.AttemptPath -Leaf)) { $record.Hash = (Get-FileHash $Fixture.AttemptPath).Hash.ToLowerInvariant() }
        }
        ConvertTo-Json -InputObject @($history) -Depth 40 | Set-Content $Fixture.LockPath
    }
    function New-ApprovedTablAdmissionFixture {
        param([string]$EntryType, [string]$EntryValue)
        $arguments = New-StatefulAdapterFixture -Scope TenantAllowBlockList
        $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions.tenantAllowBlockEntries[0].entryType = $EntryType
        $parameters.workflowOptions.tenantAllowBlockEntries[0].entryValue = $EntryValue
        $parameters | ConvertTo-Json -Depth 30 | Set-Content $arguments.ParameterPath
        & $script:adapterCommand -Stage Preview @arguments -Scope TenantAllowBlockList -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Approve @arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
        $arguments
    }
}
Describe 'EXR-004 stateful approved adapters' {
BeforeEach {
    Initialize-AdapterDoubles
    Mock Test-BaselineDetachedCmsSignature -ModuleName ExchangeOnlineBaseline.Common {
        param($CanonicalBytes, $Signature)
        $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($CanonicalBytes), $true)
        $cms.Decode([Convert]::FromBase64String($Signature.Value)); $cms.CheckSignature($true)
        @{ Verified = $true; SignerSubject = $cms.SignerInfos[0].Certificate.Subject; SigningTimeUtc = [datetimeoffset]::UtcNow; CertificateNotBeforeUtc = [datetimeoffset]::UtcNow.AddDays(-1); CertificateNotAfterUtc = [datetimeoffset]::UtcNow.AddDays(1); ChainTrusted = $true; RevocationStatus = 'Good' }
    }
}
Context 'Concrete <Scope> mutation boundary' -ForEach $adapterCases {
    It 'refuses an unavailable mutation command before any writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope $Scope -Approved
        $global:adapterMissingCommand = $Mutator
        Mock Get-Command -ModuleName ExchangeOnlineBaseline.Common { $null } -ParameterFilter { $Name -eq $global:adapterMissingCommand }
        # Act
        $invoke = { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false }
        # Assert
        $failure = $null
        try { & $invoke } catch { $failure = $_ }
        Should -Invoke Get-Command -ModuleName ExchangeOnlineBaseline.Common -Times 1 -ParameterFilter { $Name -eq $global:adapterMissingCommand }
        $failure.Exception.Message | Should -BeLike '*ChangeCommandUnavailable*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses signed before-state with an extra parameter before any writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope $Scope -Approved
        $preview = Get-Content $arguments.PreviewPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $preview.Operation[0].Before.Value['UnexpectedParameter'] = 'must-not-be-splatted'
        $preview | ConvertTo-Json -Depth 40 | Set-Content $arguments.PreviewPath
        # Act
        $invoke = { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false }
        # Assert
        $invoke | Should -Throw '*ChangeOperationMismatch*'
        $global:adapterCalls.Count | Should -Be 0
    }

    It 'refuses parameter options changed after approval' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope $Scope -Approved
        $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions.enableDkim = $false
        $parameters | ConvertTo-Json -Depth 30 | Set-Content $arguments.ParameterPath
        # Act
        $invoke = { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false }
        # Assert
        $invoke | Should -Throw '*ChangePreviewBindingMismatch*'
        $global:adapterCalls.Count | Should -Be 0
    }

    It 'refuses an incomplete preflight read before any writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope $Scope -Approved
        $global:adapterState[$Noun][0].Remove($Field)
        # Act
        $invoke = { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false }
        # Assert
        $invoke | Should -Throw '*ChangeReadIncomplete*'
        $global:adapterCalls.Count | Should -Be 0
    }

    It 'round trips the exact approved typed state and makes repeated rollback a no-op' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope $Scope
        $before = Get-AdapterSnapshot
        # Act
        $result = Invoke-AdapterRoundTrip -Arguments $arguments -Scope $Scope
        # Assert
        $result.Status | Should -BeExactly 'Succeeded'
        (Get-AdapterSnapshot) | Should -BeExactly $before
        $writes = $global:adapterCalls.Count
        $writes | Should -BeGreaterThan 0
        $result.RepeatedStatus | Should -BeExactly 'Succeeded'
        $result.RepeatedWrites | Should -Be 0
        $preview = Get-Content $arguments.PreviewPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $preview.ParameterHash | Should -Match '^[0-9a-f]{64}$'
        foreach ($operation in $preview.Operation) {
            $operation.Before.ContainsKey('Exists') | Should -BeTrue
            ($operation.Identity | ConvertFrom-Json -AsHashtable) | Should -BeOfType [System.Collections.IDictionary]
        }
    }
}
Context 'Signed TABL value admission' {
    It 'refuses <Case> before any adapter write' -ForEach $tablAdmissionNegativeCases {
        # Arrange
        $arguments = New-ApprovedTablAdmissionFixture -EntryType $EntryType -EntryValue $EntryValue
        # Act
        $invoke = { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false }
        # Assert
        $failure = $null
        try { & $invoke } catch { $failure = $_ }
        $failure.Exception.Message | Should -BeLike '*TenantAllowBlock*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }
    It 'applies one exact sender address through the approved adapter boundary' {
        # Arrange
        $arguments = New-ApprovedTablAdmissionFixture -EntryType Sender -EntryValue 'sender@contoso.example'
        # Act
        $result = & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false
        # Assert
        $result.Status | Should -BeExactly 'Succeeded'
        @($global:adapterCalls).Count | Should -BeGreaterThan 0
        @($global:adapterState.TenantAllowBlockListItems | Where-Object { $_.ListType -eq 'Sender' -and $_.Value -eq 'sender@contoso.example' }).Count | Should -Be 1
    }
}
Context 'Signed TABL governance binding' {
    It 'refuses a TABL ticket changed after approval before any adapter write' {
        # Arrange
        $arguments = New-ApprovedTablAdmissionFixture -EntryType Sender -EntryValue 'governed@contoso.example'
        $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions.tenantAllowBlockEntries[0].ticket = 'CHG004-MUTATED'
        $parameters | ConvertTo-Json -Depth 30 | Set-Content $arguments.ParameterPath
        # Act
        $invoke = { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false }
        # Assert
        $invoke | Should -Throw '*ChangePreviewBindingMismatch*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses a TABL justification changed after approval before any adapter write' {
        # Arrange
        $arguments = New-ApprovedTablAdmissionFixture -EntryType Sender -EntryValue 'governed@contoso.example'
        $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions.tenantAllowBlockEntries[0].justification = 'Mutated after approval'
        $parameters | ConvertTo-Json -Depth 30 | Set-Content $arguments.ParameterPath
        # Act
        $invoke = { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false }
        # Assert
        $invoke | Should -Throw '*ChangePreviewBindingMismatch*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'keeps unchanged approved TABL governance fields bound through apply' {
        # Arrange
        $arguments = New-ApprovedTablAdmissionFixture -EntryType Sender -EntryValue 'governed@contoso.example'
        $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $entry = $parameters.workflowOptions.tenantAllowBlockEntries[0]
        # Act
        $result = & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false
        # Assert
        $entry.ticket | Should -BeExactly 'CHG004'
        $entry.justification | Should -BeExactly 'Approved test block'
        $result.Status | Should -BeExactly 'Succeeded'
        @($global:adapterCalls).Count | Should -BeGreaterThan 0
        @($global:adapterState.TenantAllowBlockListItems | Where-Object { $_.ListType -eq 'Sender' -and $_.Value -eq 'governed@contoso.example' }).Count | Should -Be 1
    }
}
Context 'Creation recovery for <Scope>' -ForEach @(
    @{ Scope = 'AcceptedDomains'; Noun = 'AcceptedDomain'; Identity = 'contoso.example' },
    @{ Scope = 'Impersonation'; Noun = 'AntiPhishPolicy'; Identity = 'Contoso Impersonation Protection' },
    @{ Scope = 'Quarantine'; Noun = 'QuarantinePolicy'; Identity = 'Baseline-AdminOnlyAccess' },
    @{ Scope = 'TenantAllowBlockList'; Noun = 'TenantAllowBlockListItems'; Identity = 'block-1' }
) {
    BeforeEach {
        $global:adapterState[$Noun] = @($global:adapterState[$Noun] | Where-Object Identity -NE $Identity)
    }
    It 'refuses creation if the approved absent object appeared before apply' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope $Scope -Approved
        $global:adapterState[$Noun] += @{ Identity = $Identity; Name = $Identity; DomainName = $Identity; Value = 'blocked.example'; ListType = 'Sender'; Action = 'Block' }
        # Act
        $invoke = { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false }
        # Assert
        $invoke | Should -Throw
        $global:adapterCalls.Count | Should -Be 0
    }
    It 'refuses deletion of a created object whose unrelated properties changed' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope $Scope -Approved
        & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false | Out-Null
        $target = @($global:adapterState[$Noun] | Where-Object { $_.Identity -eq $Identity -or ($Noun -eq 'TenantAllowBlockListItems' -and $_.Value -eq 'blocked.example') })[0]
        $target['UnrelatedSetting'] = 'changed by another administrator'
        $writes = $global:adapterCalls.Count
        # Act
        $invoke = { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false }
        # Assert
        $invoke | Should -Throw '*ChangeStateDrift*'
        $global:adapterCalls.Count | Should -Be $writes
    }
    It 'creates the approved absent object and restores its absence exactly once' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope $Scope
        $before = Get-AdapterSnapshot
        # Act
        $result = Invoke-AdapterRoundTrip -Arguments $arguments -Scope $Scope
        # Assert
        $result.Status | Should -BeExactly 'Succeeded'
        (Get-AdapterSnapshot) | Should -BeExactly $before
        $result.RepeatedStatus | Should -BeExactly 'Succeeded'
        $result.RepeatedWrites | Should -Be 0
        $receipt = Get-Content (Join-Path $arguments.ArtifactRoot 'apply-ADAPTER004.json') -Raw | ConvertFrom-Json -AsHashtable
        @($receipt.Operation | Where-Object { $_['ObjectFingerprint'] -match '^[0-9a-f]{64}$' }).Count | Should -BeGreaterThan 0
    }
}
Context 'Existing reporting prerequisite <Scope>' -ForEach @(
    @{ Scope = 'ReportSubmission'; Noun = 'ReportSubmissionPolicy' },
    @{ Scope = 'ReportSubmission'; Noun = 'ReportSubmissionRule' },
    @{ Scope = 'SecOpsOverride'; Noun = 'SecOpsOverridePolicy' },
    @{ Scope = 'SecOpsOverride'; Noun = 'ExoSecOpsOverrideRule' }
) {
    It 'refuses an absent initialized object without writes' {
        $global:adapterState[$Noun] = @()
        { New-StatefulAdapterFixture -Scope $Scope -Approved } | Should -Throw
        $global:adapterCalls.Count | Should -Be 0
    }
}
Context 'Partial apply recovery' {
    It 'rejects a rollback attempt with <Name> even if its index digest is recomputed' -ForEach @(
        @{ Name = 'wrong change'; Edit = { param($receipt) $receipt.ChangeId = 'OTHER004' } },
        @{ Name = 'wrong tenant'; Edit = { param($receipt) $receipt.Tenant = '11111111-1111-1111-1111-111111111111' } },
        @{ Name = 'wrong profile'; Edit = { param($receipt) $receipt.DeploymentProfile = 'MicrosoftNative' } },
        @{ Name = 'wrong preview'; Edit = { param($receipt) $receipt.PreviewHash = '0' * 64 } },
        @{ Name = 'wrong configuration'; Edit = { param($receipt) $receipt.ConfigurationHash = '0' * 64 } },
        @{ Name = 'wrong apply receipt'; Edit = { param($receipt) $receipt.ApplyReceiptHash = '0' * 64 } },
        @{ Name = 'wrong predecessor'; Edit = { param($receipt) $receipt.PreviousAttemptHash = '0' * 64 } },
        @{ Name = 'wrong sequence'; Edit = { param($receipt) $receipt.AttemptSequence = 2 } },
        @{ Name = 'wrong stage'; Edit = { param($receipt) $receipt.Stage = 'Apply' } },
        @{ Name = 'missing recovery version'; Edit = { param($receipt) $receipt.Remove('RecoveryVersion') } },
        @{ Name = 'successful status'; Edit = { param($receipt) $receipt.Status = 'Succeeded' } },
        @{ Name = 'missing fault'; Edit = { param($receipt) $receipt.Fault = '' } },
        @{ Name = 'stale completion'; Edit = { param($receipt) $receipt.CompletedOn = [datetimeoffset]::UtcNow.AddDays(-1).ToString('o') } },
        @{ Name = 'future completion'; Edit = { param($receipt) $receipt.CompletedOn = [datetimeoffset]::UtcNow.AddHours(1).ToString('o') } },
        @{ Name = 'unparseable completion'; Edit = { param($receipt) $receipt.CompletedOn = 'invalid' } },
        @{ Name = 'unknown operation'; Edit = { param($receipt) $receipt.Operation[0].OperationId = 'Transport' } },
        @{ Name = 'duplicate operation'; Edit = { param($receipt) $receipt.Operation += @($receipt.Operation[0].Clone()) } },
        @{ Name = 'unknown operation state'; Edit = { param($receipt) $receipt.Operation[0].State = 'Unknown' } },
        @{ Name = 'unknown progress'; Edit = { param($receipt) $receipt.Operation[0].Progress = 'Deleted' } },
        @{ Name = 'unknown observed operation'; Edit = { param($receipt) $receipt.Observed[0].OperationId = 'Transport' } },
        @{ Name = 'duplicate observation'; Edit = { param($receipt) $receipt.Observed += @($receipt.Observed[0].Clone()) } },
        @{ Name = 'mismatched target'; Edit = { param($receipt) $receipt.Observed[0].Identity = 'other-target' } },
        @{ Name = 'mismatched command'; Edit = { param($receipt) $receipt.Observed[0].Command = 'Set-TransportConfig' } },
        @{ Name = 'mismatched desired values'; Edit = { param($receipt) $receipt.Observed[0].After.Value.Notes = 'unreviewed' } },
        @{ Name = 'mismatched operation order'; Edit = { param($receipt) $receipt.Observed[0].Sequence = 99 } },
        @{ Name = 'mismatched dependencies'; Edit = { param($receipt) $receipt.Observed[0].DependsOn = @('Transport') } }
    ) {
        $fixture = New-FailedTablRollbackFixture
        $arguments = $fixture.Arguments
        $receipt = Get-Content $fixture.AttemptPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        & $Edit $receipt
        $receipt | ConvertTo-Json -Depth 40 | Set-Content $fixture.AttemptPath
        Update-TestRollbackAttemptIndex $fixture
        $writes = $global:adapterCalls.Count

        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeRollbackReceiptMismatch*'

        $global:adapterCalls.Count | Should -Be $writes
        $global:adapterState.TenantAllowBlockListItems.Count | Should -Be 0
    }
    It 'does not treat <Name> as proof of an absent intermediate state' -ForEach @(
        @{ Name = 'a succeeded journal entry'; Edit = { param($receipt) $receipt.Operation[0].State = 'Succeeded' } },
        @{ Name = 'an unchanged journal entry'; Edit = { param($receipt) $receipt.Operation[0].State = 'Unchanged' } },
        @{ Name = 'missing operation fault'; Edit = { param($receipt) $receipt.Operation[0].Fault = '' } },
        @{ Name = 'missing progress'; Edit = { param($receipt) $receipt.Operation[0].Remove('Progress') } },
        @{ Name = 'created progress'; Edit = { param($receipt) $receipt.Operation[0].Progress = 'Created' } },
        @{ Name = 'no journal entry'; Edit = { param($receipt) $receipt.Operation = @() } },
        @{ Name = 'missing readback'; Edit = { param($receipt) $receipt.Observed = @() } },
        @{ Name = 'present readback'; Edit = { param($receipt) $receipt.Observed[0].Before = $receipt.Observed[0].After } },
        @{ Name = 'malformed absent readback'; Edit = { param($receipt) $receipt.Observed[0].Before.Exists = 'false' } }
    ) {
        $fixture = New-FailedTablRollbackFixture
        $arguments = $fixture.Arguments
        $receipt = Get-Content $fixture.AttemptPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        & $Edit $receipt
        $receipt | ConvertTo-Json -Depth 40 | Set-Content $fixture.AttemptPath
        Update-TestRollbackAttemptIndex $fixture
        $writes = $global:adapterCalls.Count

        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeStateDrift*'

        $global:adapterCalls.Count | Should -Be $writes
    }
    It 'rejects altered receipt bytes without any additional mutation' {
        $fixture = New-FailedTablRollbackFixture
        $arguments = $fixture.Arguments
        Add-Content $fixture.AttemptPath ' '
        $writes = $global:adapterCalls.Count
        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeRollbackReceiptMismatch*'
        $global:adapterCalls.Count | Should -Be $writes
    }
    It 'rejects an unindexed forged attempt instead of authorizing an externally deleted entry' {
        $fixture = New-FailedTablRollbackFixture
        $forged = Get-Content $fixture.AttemptPath -Raw
        Initialize-AdapterDoubles
        $arguments = New-StatefulAdapterFixture -Scope TenantAllowBlockList -Approved
        & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false | Out-Null
        $global:adapterState.TenantAllowBlockListItems = @()
        $forged | Set-Content (Join-Path $arguments.ArtifactRoot ('rollback-attempt-ADAPTER004-' + [guid]::NewGuid().ToString('N') + '.json'))
        $writes = $global:adapterCalls.Count
        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeRollbackReceiptMismatch*'
        $global:adapterCalls.Count | Should -Be $writes
    }
    It 'rejects a missing indexed attempt' {
        $fixture = New-FailedTablRollbackFixture
        $arguments = $fixture.Arguments
        Remove-Item $fixture.AttemptPath
        $writes = $global:adapterCalls.Count
        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeRollbackReceiptMismatch*'
        $global:adapterCalls.Count | Should -Be $writes
    }
    It 'refuses unexplained absence after successful apply without a rollback removal receipt' {
        $arguments = New-StatefulAdapterFixture -Scope TenantAllowBlockList -Approved
        & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false | Out-Null
        $global:adapterState.TenantAllowBlockListItems = @()
        $writes = $global:adapterCalls.Count
        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeStateDrift*'
        $global:adapterCalls.Count | Should -Be $writes
    }
    It 'preserves removal provenance across two failed recreation retries' {
        $fixture = New-FailedTablRollbackFixture
        $arguments = $fixture.Arguments
        $global:adapterWriteFault = 'New-TenantAllowBlockListItems'
        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeExecutionFailed*'
        $attempts = @(Get-ChildItem $arguments.ArtifactRoot -Filter 'rollback-attempt-*.json')
        $attempts.Count | Should -Be 2
        foreach ($attempt in $attempts) { (Get-Content $attempt.FullName -Raw | ConvertFrom-Json).Operation[0].Progress | Should -BeExactly 'Removed' }
        $global:adapterWriteFault = ''
        $result = & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false
        $result.Status | Should -BeExactly 'Succeeded'
        (Get-AdapterSnapshot) | Should -BeExactly $fixture.Before
    }
    It 'does not reuse old Removed progress after a later attempt observed the restored entry' {
        $arguments = New-StatefulAdapterFixture -Scope @('Organization','TenantAllowBlockList') -Approved
        & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false | Out-Null
        $global:adapterWriteFault = 'New-TenantAllowBlockListItems'
        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeExecutionFailed*'
        $global:adapterWriteFault = 'Set-OrganizationConfig'
        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeExecutionFailed*'
        $global:adapterState.TenantAllowBlockListItems.Count | Should -Be 1
        $global:adapterState.TenantAllowBlockListItems = @()
        $global:adapterWriteFault = ''
        $writes = $global:adapterCalls.Count
        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeStateDrift*'
        $global:adapterCalls.Count | Should -Be $writes
    }
    It 'rejects <Damage> in ordered rollback history before any writes' -ForEach @(
        @{ Damage = 'reordered attempts' },
        @{ Damage = 'duplicate indexed attempts' },
        @{ Damage = 'replayed older receipt bytes' },
        @{ Damage = 'missing latest receipt' }
    ) {
        $fixture = New-FailedTablRollbackFixture
        $arguments = $fixture.Arguments
        $global:adapterWriteFault = 'New-TenantAllowBlockListItems'
        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeExecutionFailed*'
        $global:adapterWriteFault = ''
        $history = Get-Content $fixture.LockPath -Raw | ConvertFrom-Json -AsHashtable -NoEnumerate
        $history.Count | Should -Be 2
        switch ($Damage) {
            'reordered attempts' {
                ConvertTo-Json -InputObject @($history[1],$history[0]) -Depth 40 | Set-Content $fixture.LockPath
            }
            'duplicate indexed attempts' {
                ConvertTo-Json -InputObject @($history[0],$history[0]) -Depth 40 | Set-Content $fixture.LockPath
            }
            'replayed older receipt bytes' {
                $fixture.AttemptPath = Join-Path $arguments.ArtifactRoot $history[1].Name
                Get-Content (Join-Path $arguments.ArtifactRoot $history[0].Name) -Raw | Set-Content $fixture.AttemptPath
                Update-TestRollbackAttemptIndex $fixture
            }
            'missing latest receipt' {
                Remove-Item (Join-Path $arguments.ArtifactRoot $history[1].Name)
            }
        }
        $writes = $global:adapterCalls.Count

        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeRollbackReceiptMismatch*'

        $global:adapterCalls.Count | Should -Be $writes
        $global:adapterState.TenantAllowBlockListItems.Count | Should -Be 0
    }
    It 'revalidates attempt history after preflight under exclusive rollback ownership' {
        $fixture = New-FailedTablRollbackFixture
        $arguments = $fixture.Arguments
        $global:adapterForgedPath = Join-Path $arguments.ArtifactRoot ('rollback-attempt-ADAPTER004-' + [guid]::NewGuid().ToString('N') + '.json')
        Mock Get-TenantAllowBlockListItems -ModuleName ExchangeOnlineBaseline.Common {
            param($ListType, $Entry)
            if (-not (Test-Path $global:adapterForgedPath)) { '{}' | Set-Content $global:adapterForgedPath }
            Invoke-OfflineAdapterCommand Get TenantAllowBlockListItems $PSBoundParameters
        }
        $writes = $global:adapterCalls.Count

        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeRollbackReceiptMismatch*'

        $global:adapterCalls.Count | Should -Be $writes
    }
    It 'refuses changed TABL values during recovery preflight' {
        $fixture = New-FailedTablRollbackFixture
        $arguments = $fixture.Arguments
        $preview = Get-Content $arguments.PreviewPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $row = $preview.Operation[0].After.Value.Clone()
        $row.Identity = 'intervening-entry'
        $row.Value = 'blocked.example'
        $row.ListType = 'Sender'
        $row.Notes = 'unreviewed intervening change'
        $global:adapterState.TenantAllowBlockListItems = @($row)
        $writes = $global:adapterCalls.Count
        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeStateDrift*'
        $global:adapterCalls.Count | Should -Be $writes
        $global:adapterState.TenantAllowBlockListItems[0].Notes | Should -BeExactly 'unreviewed intervening change'
    }
    It 'refuses an intervening TABL change between recovery preflight and per-operation execution' {
        $fixture = New-FailedTablRollbackFixture
        $arguments = $fixture.Arguments
        $preview = Get-Content $arguments.PreviewPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $global:adapterIntruder = $preview.Operation[0].After.Value.Clone()
        $global:adapterIntruder.Identity = 'intervening-entry'
        $global:adapterIntruder.Value = 'blocked.example'
        $global:adapterIntruder.ListType = 'Sender'
        $global:adapterIntruder.Notes = 'unreviewed intervening change'
        $global:adapterReadCount = 0
        Mock Get-TenantAllowBlockListItems -ModuleName ExchangeOnlineBaseline.Common {
            param($ListType, $Entry)
            $global:adapterReadCount++
            if ($global:adapterReadCount -eq 2) { $global:adapterState.TenantAllowBlockListItems = @($global:adapterIntruder) }
            Invoke-OfflineAdapterCommand Get TenantAllowBlockListItems $PSBoundParameters
        }
        $writes = $global:adapterCalls.Count
        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeStateDrift*'
        $global:adapterCalls.Count | Should -Be $writes
        $global:adapterState.TenantAllowBlockListItems[0].Notes | Should -BeExactly 'unreviewed intervening change'
    }
    It 'keeps recovery WhatIf read-only and rejects concurrent rollback ownership' {
        $fixture = New-FailedTablRollbackFixture
        $arguments = $fixture.Arguments
        $lockHash = (Get-FileHash $fixture.LockPath).Hash
        $writes = $global:adapterCalls.Count
        & $script:adapterCommand -Stage Rollback @arguments -Apply -WhatIf
        (Get-FileHash $fixture.LockPath).Hash | Should -BeExactly $lockHash
        $global:adapterCalls.Count | Should -Be $writes
        $lock = [IO.File]::Open($fixture.LockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try { { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw } finally { $lock.Dispose() }
        $global:adapterCalls.Count | Should -Be $writes
    }
    It 'restores the original TABL entry on retry after successful apply and failed rollback recreation' {
        $arguments = New-StatefulAdapterFixture -Scope TenantAllowBlockList -Approved
        $before = Get-AdapterSnapshot
        $apply = & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false
        $apply.Status | Should -BeExactly 'Succeeded'
        $apply.Operation[0].Progress | Should -BeExactly 'Created'
        $applyPath = Join-Path $arguments.ArtifactRoot 'apply-ADAPTER004.json'
        $applyHash = (Get-FileHash $applyPath).Hash
        $global:adapterWriteFault = 'New-TenantAllowBlockListItems'
        { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeExecutionFailed*'
        $global:adapterState.TenantAllowBlockListItems.Count | Should -Be 0
        $attempts = @(Get-ChildItem $arguments.ArtifactRoot -Filter 'rollback-attempt-*.json')
        $attempts.Count | Should -Be 1
        $attemptHash = (Get-FileHash $attempts[0].FullName).Hash
        $attempt = Get-Content $attempts[0].FullName -Raw | ConvertFrom-Json
        $attempt.Operation[0].Progress | Should -BeExactly 'Removed'
        $global:adapterWriteFault = ''
        $writes = $global:adapterCalls.Count

        $result = & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false

        $result.Status | Should -BeExactly 'Succeeded'
        (Get-AdapterSnapshot) | Should -BeExactly $before
        $global:adapterCalls.Count | Should -Be ($writes + 1)
        (Get-FileHash $applyPath).Hash | Should -BeExactly $applyHash
        (Get-FileHash $attempts[0].FullName).Hash | Should -BeExactly $attemptHash
        $repeated = & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false
        $repeated.Status | Should -BeExactly 'Succeeded'
        $global:adapterCalls.Count | Should -Be ($writes + 1)
    }
    It 'does not let drift on an unattempted object block restoration of a touched object' {
        # Arrange
        $scope = @('Organization','ExternalSender','OutboundSpam')
        $arguments = New-StatefulAdapterFixture -Scope $scope -Approved
        $global:adapterWriteFault = 'Set-ExternalInOutlook'
        try { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false } catch { }
        $global:adapterWriteFault = ''
        $global:adapterState.HostedOutboundSpamFilterPolicy[0].AutoForwardingMode = 'Automatic'
        $global:adapterReadFault = 'HostedOutboundSpamFilterPolicy'
        $writes = $global:adapterCalls.Count
        # Act
        $result = & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false
        # Assert
        $result.Status | Should -BeExactly 'Succeeded'
        $global:adapterState.OrganizationConfig[0].AuditDisabled | Should -BeTrue
        $global:adapterState.HostedOutboundSpamFilterPolicy[0].AutoForwardingMode | Should -BeExactly 'Automatic'
        $global:adapterCalls.Count | Should -Be ($writes + 1)
    }
    It 'restores a TABL entry when replacement failed after removal' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope TenantAllowBlockList -Approved
        $before = Get-AdapterSnapshot
        $global:adapterWriteFault = 'New-TenantAllowBlockListItems'
        try { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false } catch { }
        $global:adapterWriteFault = ''
        # Act
        $result = & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false
        # Assert
        $result.Status | Should -BeExactly 'Succeeded'
        (Get-AdapterSnapshot) | Should -BeExactly $before
    }
    It 'allows guarded retry after a rollback command failed without replacing receipts' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Organization -Approved
        & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false | Out-Null
        $global:adapterWriteFault = 'Set-OrganizationConfig'
        try { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } catch { }
        $global:adapterWriteFault = ''
        $attempts = @(Get-ChildItem $arguments.ArtifactRoot -Filter 'rollback-attempt-*.json')
        $attempts.Count | Should -Be 1
        $attemptHash = (Get-FileHash $attempts[0].FullName).Hash
        $failedReceipt = Get-Content $attempts[0].FullName -Raw | ConvertFrom-Json
        $failedReceipt.Status | Should -BeExactly 'Failed'
        $failedReceipt.Fault | Should -Not -BeNullOrEmpty
        Test-Path (Join-Path $arguments.ArtifactRoot 'rollback-result-ADAPTER004.json') | Should -BeFalse
        # Act
        $result = & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false
        # Assert
        $result.Status | Should -BeExactly 'Succeeded'
        $global:adapterState.OrganizationConfig[0].AuditDisabled | Should -BeTrue
        @(Get-ChildItem $arguments.ArtifactRoot -Filter 'rollback-attempt-*.json').Count | Should -Be 1
        (Get-FileHash $attempts[0].FullName).Hash | Should -BeExactly $attemptHash
    }
}
}
AfterAll {
    foreach ($name in @($global:adapterCommands) + @('Get-ConnectionInformation','Invoke-OfflineAdapterCommand')) { Remove-Item "Function:global:$name" -ErrorAction SilentlyContinue }
    $script:adapterCertificate.Dispose(); $script:adapterKey.Dispose()
    Get-Variable -Name 'adapter*' -Scope Global | Remove-Variable -Scope Global
}