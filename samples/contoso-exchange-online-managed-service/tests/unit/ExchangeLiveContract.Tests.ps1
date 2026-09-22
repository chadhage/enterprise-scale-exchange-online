BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $command = Join-Path $sampleRoot 'scripts/Test-ExchangeOnlineBaseline.ps1'
    $harness = Join-Path $sampleRoot 'tests/helpers/ExchangeLiveRawHarness.ps1'
    . (Join-Path $sampleRoot 'tests/helpers/ExchangeGovernanceRawFixture.ps1')
    function New-ExchangeLiveRawFixture {
        param($Parameters)
        (New-ExchangeGovernanceRawFixture $Parameters).Raw
    }
    $parameters = Get-Content (Join-Path $sampleRoot 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
    $parameters.entitlement.verified = $true
    $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
    $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE','THREAT_INTELLIGENCE')
    $governanceFixture = New-ExchangeGovernanceRawFixture $parameters
    $parameters.governanceEvidence = @{ recipientFlows = $governanceFixture.RecipientFlows }
    $governanceConfigurationPath = Join-Path $TestDrive 'governance.configuration.json'
    $governanceFixture.Configuration | ConvertTo-Json -Depth 50 | Set-Content $governanceConfigurationPath
    $parameterPath = Join-Path $TestDrive 'parameters.json'
    $parameters | ConvertTo-Json -Depth 30 | Set-Content $parameterPath
}

Describe 'EXR-005 retained raw collection contract' {
    It 'collects beyond the default 1000 result cap for <Cmdlet>' -ForEach @(
        @{ Cmdlet = 'Get-RemoteDomain'; Control = 'EXO-008' }
        @{ Cmdlet = 'Get-RoleGroup'; Control = 'EXO-010' }
    ) {
        $raw = New-ExchangeLiveRawFixture -Parameters $parameters
        $raw[$Cmdlet].Items = @(foreach ($index in 1..1001) {
            if ($Cmdlet -eq 'Get-RemoteDomain') {
                @{ Identity = $(if ($index -eq 1) { 'Default' } else { "remote-$index" }); DomainName = $(if ($index -eq 1) { '*' } else { "domain$index.example" }); AutoForwardEnabled = ($index -eq 1001); AutoReplyEnabled = $false; AllowedOOFType = 'None'; DeliveryReportEnabled = $false; NDREnabled = $false }
            }
            else { @{ Identity = "group-$index"; Name = $(if ($index -eq 1001) { 'Unapproved' } else { 'Organization Management' }); RoleGroupType = 'Standard' } }
        })
        $rawPath = Join-Path $TestDrive "$Cmdlet-cap.json"
        $raw | ConvertTo-Json -Depth 40 | Set-Content $rawPath
        $outputPath = Join-Path $TestDrive "$Cmdlet-cap"
        $callPath = Join-Path $TestDrive "$Cmdlet-cap.calls"
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $rawPath $callPath $governanceConfigurationPath 2>&1 | Out-String
        $envelope = Get-Content (Join-Path $outputPath 'exchange-online-evidence.json') -Raw | ConvertFrom-Json
        $check = $envelope.Check | Where-Object ControlId -EQ $Control
        $check.Status | Should -BeExactly Fail -Because ($check.Reason + $output)
        $evidence = $envelope.Evidence | Where-Object ControlId -EQ $Control
        $observation = $evidence.Observation | Where-Object Command -EQ $Cmdlet
        @($observation.Raw).Count | Should -Be 1001
        $observation.Arguments.ResultSize | Should -BeExactly Unlimited
        $observation.Paging | Should -BeExactly ResultSizeUnlimited
    }

    It 'preserves and compares the defined RBAC identity for a non-mail principal' {
        $raw = New-ExchangeLiveRawFixture -Parameters $parameters
        $raw['Get-RoleGroupMember'].Items = @(@{ Identity = 'non-mail-principal'; RecipientType = 'User'; PrimarySmtpAddress = $null })
        $configuration = Get-Content $governanceConfigurationPath -Raw | ConvertFrom-Json -AsHashtable
        $configuration.controls['EXO-010'].approvedMembers = @('non-mail-principal')
        $configPath = Join-Path $TestDrive 'rbac.configuration.json'
        $configuration | ConvertTo-Json -Depth 40 | Set-Content $configPath
        $rawPath = Join-Path $TestDrive 'rbac.identity.json'
        $raw | ConvertTo-Json -Depth 40 | Set-Content $rawPath
        $outputPath = Join-Path $TestDrive 'rbac.identity'
        $callPath = Join-Path $TestDrive 'rbac.identity.calls'
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $rawPath $callPath $configPath 2>&1 | Out-String
        $envelope = Get-Content (Join-Path $outputPath 'exchange-online-evidence.json') -Raw | ConvertFrom-Json
        ($envelope.Check | Where-Object ControlId -EQ 'EXO-010').Status | Should -BeExactly Pass -Because $output
        $evidence = $envelope.Evidence | Where-Object ControlId -EQ 'EXO-010'
        $evidence.Value.Members[0].Member | Should -BeExactly 'non-mail-principal'
        $evidence.Value.Members[0].IdentitySource | Should -BeExactly Identity
        $evidence.Value.Members[0].Raw.RecipientType | Should -BeExactly User
    }

    It 'joins TABL governance only when exact raw binding matches: <Case>' -ForEach @(
        @{ Case = 'supplied'; Expected = 'Pass' }
        @{ Case = 'missing'; Expected = 'Error' }
        @{ Case = 'wrong identity'; Expected = 'Error' }
        @{ Case = 'duplicate'; Expected = 'Error' }
        @{ Case = 'missing owner'; Expected = 'Fail' }
    ) {
        $raw = New-ExchangeLiveRawFixture -Parameters $parameters
        $expiry = [datetimeoffset]::UtcNow.AddDays(7).ToString('o')
        $raw['Get-TenantAllowBlockListItems'] = @{ ByList = @{ 'Sender:Allow' = @(@{ Identity = 'entry-1'; Value = 'sender@contoso.com'; ExpirationDate = $expiry }) }; Items = @() }
        $localParameters = $parameters | ConvertTo-Json -Depth 40 | ConvertFrom-Json -AsHashtable
        $entry = @{ identity = 'entry-1'; entryType = 'Sender'; entryValue = 'sender@contoso.com'; action = 'Allow'; owner = 'secops@contoso.com'; ticket = 'OFFLINE-123'; justification = 'Offline approved test'; createdDateTime = [datetimeoffset]::UtcNow.AddHours(-1).ToString('o') }
        $localParameters.tenantAllowBlockListGovernance = @{ registerLocation = 'local:offline-governance'; entries = @($entry) }
        switch ($Case) {
            'missing' { $localParameters.Remove('tenantAllowBlockListGovernance') }
            'wrong identity' { $entry.identity = 'other' }
            'duplicate' { $localParameters.tenantAllowBlockListGovernance.entries = @($entry, $entry) }
            'missing owner' { $entry.Remove('owner') }
        }
        $localPath = Join-Path $TestDrive "tabl-$Case.parameters.json"
        $localParameters | ConvertTo-Json -Depth 40 | Set-Content $localPath
        $rawPath = Join-Path $TestDrive "tabl-$Case.json"
        $raw | ConvertTo-Json -Depth 40 | Set-Content $rawPath
        $outputPath = Join-Path $TestDrive "tabl-$Case"
        $callPath = Join-Path $TestDrive "tabl-$Case.calls"
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $localPath $outputPath $rawPath $callPath $governanceConfigurationPath 2>&1 | Out-String
        $envelope = Get-Content (Join-Path $outputPath 'exchange-online-evidence.json') -Raw | ConvertFrom-Json
        $check = $envelope.Check | Where-Object ControlId -EQ 'MDO-007'
        $check.Status | Should -BeExactly $Expected -Because ($check.Reason + $output)
        if ($Expected -eq 'Pass') {
            $evidence = $envelope.Evidence | Where-Object ControlId -EQ 'MDO-007'
            $evidence.Value.owner | Should -BeExactly $entry.owner
            $evidence.Value.ticket | Should -BeExactly $entry.ticket
            @($evidence.Observation).Count | Should -Be 8
        }
    }

    It 'rejects reviewer case <Case> through the default public raw path' -ForEach @(
        @{ Case = 'report disabled'; Cmdlet = 'Get-ReportSubmissionRule'; Field = 'State'; Value = 'Disabled'; Control = 'MDO-006' }
        @{ Case = 'report misbound'; Cmdlet = 'Get-ReportSubmissionRule'; Field = 'ReportSubmissionPolicy'; Value = 'Other'; Control = 'MDO-006' }
        @{ Case = 'report misroute'; Cmdlet = 'Get-ReportSubmissionRule'; Field = 'SentTo'; Value = @('other@contoso.com'); Control = 'MDO-006' }
        @{ Case = 'phish misroute'; Cmdlet = 'Get-ReportSubmissionPolicy'; Field = 'ReportPhishAddresses'; Value = @('other@contoso.com'); Control = 'MDO-006' }
        @{ Case = 'not junk disabled'; Cmdlet = 'Get-ReportSubmissionPolicy'; Field = 'ReportNotJunkToCustomizedAddress'; Value = $false; Control = 'MDO-006' }
        @{ Case = 'secops disabled'; Cmdlet = 'Get-ExoSecOpsOverrideRule'; Field = 'Mode'; Value = 'PendingDeletion'; Control = 'MDO-006' }
        @{ Case = 'secops rule missing'; Cmdlet = 'Get-ExoSecOpsOverrideRule'; Empty = $true; Control = 'MDO-006' }
        @{ Case = 'audit bypass absent'; Cmdlet = 'Get-MailboxAuditBypassAssociation'; Field = 'AuditBypassEnabled'; Remove = $true; Control = 'EXO-006' }
        @{ Case = 'audit bypass null'; Cmdlet = 'Get-MailboxAuditBypassAssociation'; Field = 'AuditBypassEnabled'; Value = $null; Control = 'EXO-006' }
        @{ Case = 'audit bypass string'; Cmdlet = 'Get-MailboxAuditBypassAssociation'; Field = 'AuditBypassEnabled'; Value = 'false'; Control = 'EXO-006' }
        @{ Case = 'audit identity absent'; Cmdlet = 'Get-MailboxAuditBypassAssociation'; Field = 'Identity'; Remove = $true; Control = 'EXO-006' }
        @{ Case = 'IRM failed'; Cmdlet = 'Test-IRMConfiguration'; Field = 'Results'; Value = 'OVERALL RESULT: FAIL'; Control = 'GOV-005' }
        @{ Case = 'IRM ambiguous'; Cmdlet = 'Test-IRMConfiguration'; Field = 'Results'; Value = "OVERALL RESULT: PASS`nOVERALL RESULT: FAIL"; Control = 'GOV-005' }
        @{ Case = 'IRM fabricated result'; Cmdlet = 'Test-IRMConfiguration'; Field = 'Results'; Remove = $true; Control = 'GOV-005' }
        @{ Case = 'MRM identity absent'; Cmdlet = 'Get-Mailbox'; Field = 'Identity'; Remove = $true; Control = 'GOV-003' }
        @{ Case = 'MRM duplicate identity'; Cmdlet = 'Get-Mailbox'; Duplicate = $true; Control = 'GOV-003' }
        @{ Case = 'DKIM wrong returned domain'; Cmdlet = 'Get-DkimSigningConfig'; Field = 'Name'; Value = 'other.example'; Control = 'AUTH-001' }
        @{ Case = 'anti phish no rule'; Cmdlet = 'Get-AntiPhishRule'; Empty = $true; Control = 'MDO-009' }
        @{ Case = 'anti phish disabled'; Cmdlet = 'Get-AntiPhishRule'; Field = 'State'; Value = 'Disabled'; Control = 'MDO-009' }
        @{ Case = 'anti phish misbound'; Cmdlet = 'Get-AntiPhishRule'; Field = 'AntiPhishPolicy'; Value = 'Other'; Control = 'MDO-009' }
        @{ Case = 'anti phish wrong scope'; Cmdlet = 'Get-AntiPhishRule'; Field = 'RecipientDomainIs'; Value = @('other.example'); Control = 'MDO-009' }
    ) {
        $raw = New-ExchangeLiveRawFixture -Parameters $parameters
        if ($Empty) { $raw[$Cmdlet] = @{ Items = @() } }
        elseif ($Duplicate) { $raw[$Cmdlet].Items = @($raw[$Cmdlet].Items[0], $raw[$Cmdlet].Items[0]) }
        elseif ($Remove) { $raw[$Cmdlet].Items[0].Remove($Field) }
        else { $raw[$Cmdlet].Items[0][$Field] = $Value }
        $rawPath = Join-Path $TestDrive "$Case.json"
        $raw | ConvertTo-Json -Depth 40 | Set-Content $rawPath
        $outputPath = Join-Path $TestDrive $Case
        $callPath = Join-Path $TestDrive "$Case.calls"
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $rawPath $callPath $governanceConfigurationPath 2>&1 | Out-String
        $envelope = Get-Content (Join-Path $outputPath 'exchange-online-evidence.json') -Raw | ConvertFrom-Json
        ($envelope.Check | Where-Object ControlId -EQ $Control).Status | Should -Not -Be Pass -Because $output
    }

    It 'refuses a missing report submission rule despite compliant policy objects' {
        $raw = New-ExchangeLiveRawFixture -Parameters $parameters
        $raw['Get-ReportSubmissionRule'] = @{ Items = @() }
        $rawPath = Join-Path $TestDrive 'missing-report-rule.json'
        $raw | ConvertTo-Json -Depth 40 | Set-Content $rawPath
        $outputPath = Join-Path $TestDrive 'missing-report-rule'
        $callPath = Join-Path $TestDrive 'missing-report-rule.calls'
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $rawPath $callPath $governanceConfigurationPath 2>&1 | Out-String
        $envelope = Get-Content (Join-Path $outputPath 'exchange-online-evidence.json') -Raw | ConvertFrom-Json
        ($envelope.Check | Where-Object ControlId -EQ 'MDO-006').Status | Should -Not -Be Pass -Because $output
    }

    It 'retains a refusal for malformed <Cmdlet> in <Control>' -ForEach @(
        @{ Cmdlet = 'Get-AcceptedDomain'; Control = 'EXO-001' }
        @{ Cmdlet = 'Get-TransportConfig'; Control = 'EXO-002' }
        @{ Cmdlet = 'Get-CASMailbox'; Control = 'EXO-002' }
        @{ Cmdlet = 'Get-HostedOutboundSpamFilterPolicy'; Control = 'EXO-004' }
        @{ Cmdlet = 'Get-InboxRule'; Control = 'EXO-004' }
        @{ Cmdlet = 'Get-OrganizationConfig'; Control = 'EXO-006' }
        @{ Cmdlet = 'Get-MailboxAuditBypassAssociation'; Control = 'EXO-006' }
        @{ Cmdlet = 'Get-ExternalInOutlook'; Control = 'EXO-007' }
        @{ Cmdlet = 'Get-RemoteDomain'; Control = 'EXO-008' }
        @{ Cmdlet = 'Get-CASMailboxPlan'; Control = 'EXO-009' }
        @{ Cmdlet = 'Get-RoleGroup'; Control = 'EXO-010' }
        @{ Cmdlet = 'Get-RoleGroupMember'; Control = 'EXO-010' }
        @{ Cmdlet = 'Get-ManagementRoleAssignment'; Control = 'EXO-012' }
        @{ Cmdlet = 'Get-RoleAssignmentPolicy'; Control = 'EXO-012' }
        @{ Cmdlet = 'Get-EOPProtectionPolicyRule'; Control = 'MDO-001' }
        @{ Cmdlet = 'Get-ATPProtectionPolicyRule'; Control = 'MDO-002' }
        @{ Cmdlet = 'Get-ATPBuiltInProtectionRule'; Control = 'MDO-003' }
        @{ Cmdlet = 'Get-DistributionGroup'; Control = 'MDO-001' }
        @{ Cmdlet = 'Get-ReportSubmissionPolicy'; Control = 'MDO-006' }
        @{ Cmdlet = 'Get-ReportSubmissionRule'; Control = 'MDO-006' }
        @{ Cmdlet = 'Get-SecOpsOverridePolicy'; Control = 'MDO-006' }
        @{ Cmdlet = 'Get-ExoSecOpsOverrideRule'; Control = 'MDO-006' }
        @{ Cmdlet = 'Get-TenantAllowBlockListItems'; Control = 'MDO-007' }
        @{ Cmdlet = 'Get-QuarantinePolicy'; Control = 'MDO-008' }
        @{ Cmdlet = 'Get-HostedContentFilterPolicy'; Control = 'MDO-008' }
        @{ Cmdlet = 'Get-MalwareFilterPolicy'; Control = 'MDO-008' }
        @{ Cmdlet = 'Get-AntiPhishPolicy'; Control = 'MDO-009' }
        @{ Cmdlet = 'Get-AntiPhishRule'; Control = 'MDO-009' }
        @{ Cmdlet = 'Get-InboundConnector'; Control = 'PP-005' }
        @{ Cmdlet = 'Get-DkimSigningConfig'; Control = 'AUTH-001' }
        @{ Cmdlet = 'Get-RetentionPolicy'; Control = 'GOV-003' }
        @{ Cmdlet = 'Get-Mailbox'; Control = 'GOV-004' }
        @{ Cmdlet = 'Get-IRMConfiguration'; Control = 'GOV-005' }
        @{ Cmdlet = 'Test-IRMConfiguration'; Control = 'GOV-005' }
    ) {
        # Arrange
        $raw = New-ExchangeLiveRawFixture -Parameters $parameters
        $raw[$Cmdlet] = @{ Items = @(@{ Unexpected = 'raw diagnostic marker' }) }
        $rawPath = Join-Path $TestDrive "$Cmdlet.json"
        $raw | ConvertTo-Json -Depth 40 | Set-Content $rawPath
        $outputPath = Join-Path $TestDrive $Cmdlet
        $callPath = Join-Path $TestDrive "$Cmdlet.calls"
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $rawPath $callPath $governanceConfigurationPath 2>&1 | Out-String
        # Assert
        $envelope = Get-Content (Join-Path $outputPath 'exchange-online-evidence.json') -Raw | ConvertFrom-Json
        ($envelope.Check | Where-Object ControlId -EQ $Control).Status | Should -BeExactly Error -Because $output
        $record = $envelope.Evidence | Where-Object ControlId -EQ $Control
        $observation = @($record.Observation | Where-Object Command -EQ $Cmdlet)[0]
        $observation.Raw[0].Unexpected | Should -BeExactly 'raw diagnostic marker'
        $observation.Complete | Should -BeFalse
        $observation.Error | Should -Match 'ExchangeRaw'
        $observation.StartedAtUtc | Should -Not -BeNullOrEmpty
        $observation.FinishedAtUtc | Should -Not -BeNullOrEmpty
    }

    It 'refuses <Case> while retaining partial raw output' -ForEach @(
        @{ Case = 'warning-only truncated results'; Field = 'Warning'; Message = 'More results available; truncated response.' }
        @{ Case = 'access denied after output'; Field = 'Error'; Message = 'Access is denied.' }
        @{ Case = 'throttling after output'; Field = 'Error'; Message = '429 Too many requests' }
    ) {
        # Arrange
        $raw = New-ExchangeLiveRawFixture -Parameters $parameters
        $raw['Get-TransportConfig'][$Field] = $Message
        $rawPath = Join-Path $TestDrive "$Case.json"
        $raw | ConvertTo-Json -Depth 40 | Set-Content $rawPath
        $outputPath = Join-Path $TestDrive $Case
        $callPath = Join-Path $TestDrive "$Case.calls"
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $rawPath $callPath $governanceConfigurationPath 2>&1 | Out-String
        # Assert
        $envelope = Get-Content (Join-Path $outputPath 'exchange-online-evidence.json') -Raw | ConvertFrom-Json
        ($envelope.Check | Where-Object ControlId -EQ 'EXO-002').Status | Should -BeExactly Error -Because $output
        $record = $envelope.Evidence | Where-Object ControlId -EQ 'EXO-002'
        $record.Observation[0].Raw[0].Identity | Should -BeExactly 'Transport Settings'
        $record.Observation[0].Complete | Should -BeFalse
        $record.Observation[0].Error | Should -Not -BeNullOrEmpty
        if ($Field -eq 'Warning') { $record.Observation[0].Warnings[0] | Should -BeExactly $Message }
    }

    It 'round trips all retained live controls from documented raw cmdlet objects without evaluated injection' {
        # Arrange
        $raw = New-ExchangeLiveRawFixture -Parameters $parameters
        $rawPath = Join-Path $TestDrive 'all-live-success.json'
        $raw | ConvertTo-Json -Depth 40 | Set-Content $rawPath
        $outputPath = Join-Path $TestDrive 'all-live-success'
        $callPath = Join-Path $TestDrive 'all-live-success.calls'
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $rawPath $callPath $governanceConfigurationPath 2>&1 | Out-String
        # Assert
        $envelope = Get-Content (Join-Path $outputPath 'exchange-online-evidence.json') -Raw | ConvertFrom-Json
        $live = @($envelope.Check | Where-Object ControlId -NotIn @('MON-003','OPS-001','OPS-002'))
        $failures = @($live | Where-Object Status -NE Pass)
        $failures.Count | Should -Be 0 -Because ((@($failures | ForEach-Object { "$($_.ControlId): $($_.Reason)" }) -join '; ') + $output)
        $live.Count | Should -Be 22
        foreach ($record in @($envelope.Evidence | Where-Object ControlId -In $live.ControlId)) {
            @($record.Observation).Count | Should -BeGreaterThan 0
            foreach ($observation in $record.Observation) {
                $observation.Complete | Should -BeTrue
                ([datetimeoffset]$observation.FinishedAtUtc) | Should -BeGreaterOrEqual ([datetimeoffset]$observation.StartedAtUtc)
            }
        }
        @($envelope.Check | Where-Object Status -EQ Error).Count | Should -Be 3
        $calls = Get-Content $callPath
        $calls -join ' ' | Should -Not -Match 'EXCLUDED:'
        foreach ($cmdlet in $raw.Keys) { $calls -join ' ' | Should -Match ([regex]::Escape($cmdlet + ':')) }
        $envelope.ExternalReadiness.Status | Should -BeExactly Unverified
    }
}