BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $command = Join-Path $sampleRoot 'scripts/Test-ExchangeOnlineBaseline.ps1'
    $harness = Join-Path $sampleRoot 'tests/helpers/ExchangeLiveRawHarness.ps1'
    $parameters = Get-Content (Join-Path $sampleRoot 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
    $parameters.entitlement.verified = $true
    $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
    $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE','THREAT_INTELLIGENCE')
    $parameters.domainInventory = @{
        schemaVersion = 1; tenantId = $parameters.MICROSOFT_ENTRA_TENANT_GUID; complete = $true
        source = @{ owner = 'Synthetic domain owner'; reference = 'fixture:initial-membership'; suppliedAtUtc = [datetimeoffset]::UtcNow.AddMinutes(-5).ToString('o') }
        domains = @(
            @{ domainName = $parameters.PRIMARY_SMTP_DOMAIN; accepted = $true; sending = $false; parked = $false; parentDomain = $null; domainType = 'Authoritative'; owner = 'Synthetic Exchange owner' }
            @{ domainName = $parameters.INITIAL_ONMICROSOFT_DOMAIN; accepted = $true; sending = $false; parked = $false; parentDomain = $null; domainType = 'Authoritative'; owner = 'Synthetic Exchange owner' }
        )
    }
    $parameterPath = Join-Path $TestDrive 'parameters.json'
    $parameters | ConvertTo-Json -Depth 30 | Set-Content $parameterPath
}

Describe 'EXR-011-A01 public domain applicability denominator' {
    It 'fails EXO-001 when the initial onmicrosoft domain is absent from the raw observation' {
        # Arrange
        $primaryDomain = $parameters.PRIMARY_SMTP_DOMAIN
        $initialDomain = $parameters.INITIAL_ONMICROSOFT_DOMAIN
        if (-not $initialDomain -or $initialDomain -eq $primaryDomain) { throw 'Fixture requires distinct primary and initial domains.' }
        $raw = @{}
        foreach ($serviceCommand in @(
            'Get-AcceptedDomain', 'Get-TransportConfig', 'Get-CASMailbox',
            'Get-HostedOutboundSpamFilterPolicy', 'Get-Mailbox', 'Get-InboxRule',
            'Get-OrganizationConfig', 'Get-MailboxAuditBypassAssociation',
            'Get-ExternalInOutlook', 'Get-RemoteDomain', 'Get-CASMailboxPlan',
            'Get-RoleAssignmentPolicy', 'Get-ManagementRoleAssignment',
            'Get-EOPProtectionPolicyRule', 'Get-ATPProtectionPolicyRule',
            'Get-ATPBuiltInProtectionRule', 'Get-DistributionGroup',
            'Get-DistributionGroupMember', 'Get-Recipient',
            'Get-ReportSubmissionPolicy', 'Get-ReportSubmissionRule',
            'Get-SecOpsOverridePolicy', 'Get-ExoSecOpsOverrideRule',
            'Get-TenantAllowBlockListItems', 'Get-QuarantinePolicy',
            'Get-HostedContentFilterPolicy', 'Get-HostedContentFilterRule',
            'Get-MalwareFilterPolicy', 'Get-MalwareFilterRule',
            'Get-AntiPhishPolicy', 'Get-AntiPhishRule',
            'Get-SafeAttachmentPolicy', 'Get-SafeAttachmentRule',
            'Get-SafeLinksPolicy', 'Get-SafeLinksRule', 'Get-InboundConnector',
            'Get-RoleGroup', 'Get-RoleGroupMember', 'Get-ManagementScope',
            'Get-DkimSigningConfig', 'Get-RetentionPolicy', 'Get-RetentionPolicyTag',
            'Export-MailboxDiagnosticLogs', 'Get-MailboxStatistics',
            'Get-IRMConfiguration', 'Get-TransportRule', 'Test-IRMConfiguration'
        )) { $raw[$serviceCommand] = @{ Items = @() } }
        $primaryObservation = @{ Name = $primaryDomain; DomainName = $primaryDomain; DomainType = 'Authoritative' }
        $raw['Get-AcceptedDomain'].Items = @($primaryObservation)
        $rawPath = Join-Path $TestDrive 'initial-domain-omission.json'
        $raw | ConvertTo-Json -Depth 30 | Set-Content $rawPath
        $outputPath = Join-Path $TestDrive 'initial-domain-omission'
        $callPath = Join-Path $TestDrive 'initial-domain-omission.calls'
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $rawPath $callPath 2>&1 | Out-String
        # Assert
        $evidencePath = Join-Path $outputPath 'exchange-online-evidence.json'
        Test-Path $evidencePath | Should -BeTrue -Because $output
        $envelope = Get-Content $evidencePath -Raw | ConvertFrom-Json
        $calls = @(Get-Content $callPath)
        @($calls | Where-Object { ($_ -split ':', 2)[0] -notin (@($raw.Keys) + 'Connect-ExchangeOnline') }).Count | Should -Be 0
        @($calls | Where-Object { $_ -like 'Get-AcceptedDomain:*' }).Count | Should -BeGreaterThan 0
        $record = @($envelope.Evidence | Where-Object ControlId -EQ 'EXO-001')
        $record.Count | Should -Be 1
        $observations = @($record[0].Observation | Where-Object Command -EQ 'Get-AcceptedDomain')
        $observations.Count | Should -BeGreaterThan 0
        $primaryRaw = @($observations.Raw | Where-Object DomainName -EQ $primaryDomain)
        $primaryRaw.Count | Should -Be 1
        $primaryRaw[0].Name | Should -BeExactly $primaryObservation.Name
        $primaryRaw[0].DomainType | Should -BeExactly $primaryObservation.DomainType
        @($observations.Raw | Where-Object DomainName -EQ $initialDomain).Count | Should -Be 0
        $check = @($envelope.Check | Where-Object ControlId -EQ 'EXO-001')
        $check.Count | Should -Be 1
        $check[0].Status | Should -BeExactly Fail
        $check[0].Reason | Should -Match ([regex]::Escape($initialDomain))
        $check[0].Reason | Should -Match 'missing|absent|omitted|no accepted domain'
    }
}

Describe 'EXR-005 raw forwarding live boundary' {
    It 'rejects <Case> and preserves the raw failed observation' -ForEach @(
        @{ Case = 'missing properties'; Items = @(@{ Identity = 'mailbox-1'; PrimarySmtpAddress = 'user@contoso.com' }); Failure = '' }
        @{ Case = 'empty inventory'; Items = @(); Failure = '' }
        @{ Case = 'throttled partial output'; Items = @(@{ Identity = 'mailbox-1'; PrimarySmtpAddress = 'user@contoso.com'; ForwardingAddress = $null; ForwardingSmtpAddress = $null }); Failure = '429 Too many requests' }
        @{ Case = 'unexpected page envelope'; Items = @(@{ value = @(); '@odata.nextLink' = 'https://invalid.example/next' }); Failure = '' }
    ) {
        # Arrange
        $raw = @{
            'Get-HostedOutboundSpamFilterPolicy' = @{ Items = @(@{ Identity = 'Default'; Name = 'Default'; AutoForwardingMode = 'Off' }) }
            'Get-Mailbox' = @{ Items = $Items }
            'Get-InboxRule' = @{ Items = @() }
        }
        if ($Failure) { $raw['Get-Mailbox'].Error = $Failure }
        $rawPath = Join-Path $TestDrive "$Case.json"
        $raw | ConvertTo-Json -Depth 30 | Set-Content $rawPath
        $outputPath = Join-Path $TestDrive $Case
        $callPath = Join-Path $TestDrive "$Case.calls"
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $rawPath $callPath 2>&1 | Out-String
        # Assert
        $path = Join-Path $outputPath 'exchange-online-evidence.json'
        Test-Path $path | Should -BeTrue -Because $output
        $envelope = Get-Content $path -Raw | ConvertFrom-Json
        ($envelope.Check | Where-Object ControlId -EQ 'EXO-004').Status | Should -BeExactly Error
        $record = $envelope.Evidence | Where-Object ControlId -EQ 'EXO-004'
        $observation = @($record.Observation | Where-Object Command -EQ 'Get-Mailbox')[0]
        $observation.Complete | Should -BeFalse
        @($observation.Raw).Count | Should -Be $Items.Count
        $observation.StartedAtUtc | Should -Not -BeNullOrEmpty
        $observation.FinishedAtUtc | Should -Not -BeNullOrEmpty
        $observation.Error | Should -Not -BeNullOrEmpty
    }

    It 'collects every raw mailbox and its complete hidden inbox rules through the public command' {
        # Arrange
        $raw = @{
            'Get-HostedOutboundSpamFilterPolicy' = @{ Items = @(@{ Identity = 'Default'; Name = 'Default'; AutoForwardingMode = 'Off' }) }
            'Get-Mailbox' = @{ Items = @(
                @{ Identity = 'mailbox-1'; PrimarySmtpAddress = 'user@contoso.com'; ForwardingAddress = $null; ForwardingSmtpAddress = $null }
                @{ Identity = 'mailbox-2'; PrimarySmtpAddress = 'other@contoso.com'; ForwardingAddress = $null; ForwardingSmtpAddress = $null }
            ) }
            'Get-InboxRule' = @{ Items = @() }
        }
        $rawPath = Join-Path $TestDrive 'forwarding-success.json'
        $raw | ConvertTo-Json -Depth 30 | Set-Content $rawPath
        $outputPath = Join-Path $TestDrive 'forwarding-success'
        $callPath = Join-Path $TestDrive 'forwarding-success.calls'
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $rawPath $callPath 2>&1 | Out-String
        # Assert
        $envelope = Get-Content (Join-Path $outputPath 'exchange-online-evidence.json') -Raw | ConvertFrom-Json
        ($envelope.Check | Where-Object ControlId -EQ 'EXO-004').Status | Should -BeExactly Pass -Because $output
        $record = $envelope.Evidence | Where-Object ControlId -EQ 'EXO-004'
        @($record.Observation | Where-Object Command -EQ 'Get-InboxRule').Count | Should -Be 2
        @($record.Observation | Where-Object { -not $_.Complete }).Count | Should -Be 0
        $calls = Get-Content $callPath
        @($calls | Where-Object { $_ -match '^Get-InboxRule:' }).Count | Should -Be 2
        $calls -join ' ' | Should -Match '"Mailbox":"mailbox-1"'
        $calls -join ' ' | Should -Match '"Mailbox":"mailbox-2"'
        $calls -join ' ' | Should -Match '"IncludeHidden":\{"IsPresent":true\}'
        $calls -join ' ' | Should -Not -Match 'EXCLUDED:'
    }
}