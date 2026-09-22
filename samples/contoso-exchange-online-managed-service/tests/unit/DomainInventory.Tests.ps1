#requires -Version 7.0

BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $command = Join-Path $sampleRoot 'scripts/Test-ExchangeOnlineBaseline.ps1'
    $harness = Join-Path $sampleRoot 'tests/helpers/ExchangeLiveRawHarness.ps1'
    function New-DomainInventoryFixture {
        $parameters = Get-Content (Join-Path $sampleRoot 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
        $configuration = Get-Content (Join-Path $sampleRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
        $parameters.entitlement.verified = $true
        $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
        $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE','THREAT_INTELLIGENCE')
        $suppliedAt = [datetimeoffset]::UtcNow.AddMinutes(-5).ToString('o')
        $parameters.domainInventory = @{
            schemaVersion = 1
            tenantId = $parameters.MICROSOFT_ENTRA_TENANT_GUID
            complete = $true
            source = @{ owner = 'Synthetic inventory owner'; reference = 'fixture:inventory-approval'; suppliedAtUtc = $suppliedAt }
            domains = @(
                @{ domainName = $parameters.PRIMARY_SMTP_DOMAIN; accepted = $true; sending = $true; parked = $false; parentDomain = $null; domainType = 'Authoritative'; owner = 'Synthetic Exchange owner'; sendingSystem = 'ExchangeOnline'; senderSource = @{ owner = 'Synthetic sender owner'; reference = 'fixture:sender-inventory'; suppliedAtUtc = $suppliedAt } }
                @{ domainName = $parameters.INITIAL_ONMICROSOFT_DOMAIN; accepted = $true; sending = $false; parked = $false; parentDomain = $null; domainType = 'Authoritative'; owner = 'Synthetic Exchange owner' }
            )
        }
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
        $raw['Get-AcceptedDomain'].Items = @(
            @{ Name = $parameters.PRIMARY_SMTP_DOMAIN; DomainName = $parameters.PRIMARY_SMTP_DOMAIN; DomainType = 'Authoritative' }
            @{ Name = $parameters.INITIAL_ONMICROSOFT_DOMAIN; DomainName = $parameters.INITIAL_ONMICROSOFT_DOMAIN; DomainType = 'Authoritative' }
        )
        $raw['Get-AcceptedDomain'].ByIdentity = @{ ($parameters.PRIMARY_SMTP_DOMAIN) = @($raw['Get-AcceptedDomain'].Items[0]) }
        @{ Parameters = $parameters; Configuration = $configuration; Raw = $raw }
    }

    function Add-DomainInventoryEntry {
        param($Fixture, [string]$Name, [bool]$Accepted = $true, [bool]$Sending = $false, [bool]$Parked = $false, $Parent = $null, [switch]$Observe)
        $entry = @{ domainName = $Name; accepted = $Accepted; sending = $Sending; parked = $Parked; parentDomain = $Parent; domainType = $(if ($Accepted) { 'Authoritative' } else { $null }); owner = 'Synthetic independent owner' }
        if ($Sending) {
            $entry.sendingSystem = $(if ($Accepted) { 'ExchangeOnline' } else { 'External' })
            $entry.senderSource = @{ owner = 'Synthetic external sender owner'; reference = 'fixture:external-sender'; suppliedAtUtc = [datetimeoffset]::UtcNow.AddMinutes(-5).ToString('o') }
        }
        $Fixture.Parameters.domainInventory.domains += $entry
        if ($Observe) { $Fixture.Raw['Get-AcceptedDomain'].Items += @{ Name = $Name; DomainName = $Name; DomainType = 'Authoritative' } }
    }

    function New-CompleteDomainTopologyFixture {
        $fixture = New-DomainInventoryFixture
        $fixture.Configuration.controls['EXO-001'].domainType = 'InternalRelay'
        $primary = $fixture.Parameters.domainInventory.domains[0]
        $primary.domainType = 'InternalRelay'
        $primary.topologyApproval = @{ owner = 'Synthetic routing owner'; reference = 'fixture:split-routing'; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') }
        $fixture.Raw['Get-AcceptedDomain'].Items[0].DomainType = 'InternalRelay'
        $fixture.Raw['Get-AcceptedDomain'].Items[1].DomainName = ' CONTOSO.ONMICROSOFT.COM. '
        Add-DomainInventoryEntry $fixture 'child.contoso.example' -Parent 'contoso.example' -Sending $true -Observe
        Add-DomainInventoryEntry $fixture 'parked.accepted.example' -Parked $true -Observe
        Add-DomainInventoryEntry $fixture 'sender.external.example' -Accepted $false -Sending $true
        Add-DomainInventoryEntry $fixture 'parked.external.example' -Accepted $false -Parked $true
        $fixture
    }

    function Invoke-DomainInventoryPublicFixture {
        param($Fixture, [switch]$AllowAdmissionRefusal)
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $directory
        $parameterPath = Join-Path $directory 'parameters.json'
        $configurationPath = Join-Path $directory 'configuration.json'
        $rawPath = Join-Path $directory 'raw.json'
        $callPath = Join-Path $directory 'calls.txt'
        $outputPath = Join-Path $directory 'output'
        $Fixture.Parameters | ConvertTo-Json -Depth 40 | Set-Content $parameterPath
        $Fixture.Configuration | ConvertTo-Json -Depth 40 | Set-Content $configurationPath
        $Fixture.Raw | ConvertTo-Json -Depth 40 | Set-Content $rawPath
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $rawPath $callPath $configurationPath 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        $evidencePath = Join-Path $outputPath 'exchange-online-evidence.json'
        if ($AllowAdmissionRefusal -and -not (Test-Path $evidencePath)) { return @{ ExitCode = $exitCode; Output = $output; Check = $null } }
        if (-not (Test-Path $evidencePath)) { throw "PublicEvidenceMissing: $output" }
        $envelope = Get-Content $evidencePath -Raw | ConvertFrom-Json -DateKind String
        $checks = @($envelope.Check | Where-Object ControlId -EQ 'EXO-001')
        $records = @($envelope.Evidence | Where-Object ControlId -EQ 'EXO-001')
        if ($checks.Count -ne 1 -or $records.Count -ne 1) { throw 'PublicDomainRecordCardinalityInvalid' }
        $calls = @(Get-Content $callPath)
        if (@($calls | Where-Object { ($_ -split ':', 2)[0] -notin (@($Fixture.Raw.Keys) + 'Connect-ExchangeOnline') }).Count) { throw 'UnexpectedServiceCall' }
        @{ Check = $checks[0]; Evidence = $records[0]; Envelope = $envelope; Calls = $calls; ExitCode = $exitCode; Output = $output }
    }
}

Describe 'EXR-011-A01 supplied domain inventory admission' {
    It 'does not pass an explicitly incomplete inventory through the public path' {
        # Arrange
        $fixture = New-DomainInventoryFixture
        $fixture.Parameters.domainInventory.complete = $false

        # Act
        $result = Invoke-DomainInventoryPublicFixture -Fixture $fixture

        # Assert
        $result.Check.Status | Should -BeIn @('Error', 'Fail')
        $result.Check.Reason | Should -Match 'inventory|complete'
    }

    It 'rejects supplied inventory input: <Case>' -ForEach @(
        @{ Case = 'missing inventory'; Change = { param($fixture) $fixture.Parameters.Remove('domainInventory') }; Reason = 'inventory' }
        @{ Case = 'null inventory'; Change = { param($fixture) $fixture.Parameters.domainInventory = $null }; Reason = 'inventory' }
        @{ Case = 'nonobject inventory'; Change = { param($fixture) $fixture.Parameters.domainInventory = 'complete' }; Reason = 'inventory' }
        @{ Case = 'missing version'; Change = { param($fixture) $fixture.Parameters.domainInventory.Remove('schemaVersion') }; Reason = 'version' }
        @{ Case = 'unsupported version'; Change = { param($fixture) $fixture.Parameters.domainInventory.schemaVersion = 2 }; Reason = 'version' }
        @{ Case = 'string version'; Change = { param($fixture) $fixture.Parameters.domainInventory.schemaVersion = '1' }; Reason = 'version' }
        @{ Case = 'missing completeness'; Change = { param($fixture) $fixture.Parameters.domainInventory.Remove('complete') }; Reason = 'complete' }
        @{ Case = 'string completeness'; Change = { param($fixture) $fixture.Parameters.domainInventory.complete = 'true' }; Reason = 'complete' }
        @{ Case = 'missing tenant binding'; Change = { param($fixture) $fixture.Parameters.domainInventory.Remove('tenantId') }; Reason = 'tenant' }
        @{ Case = 'malformed tenant binding'; Change = { param($fixture) $fixture.Parameters.domainInventory.tenantId = 'not-a-guid' }; Reason = 'tenant' }
        @{ Case = 'wrong tenant'; Change = { param($fixture) $fixture.Parameters.domainInventory.tenantId = '11111111-1111-1111-1111-111111111111' }; Reason = 'tenant' }
        @{ Case = 'missing source'; Change = { param($fixture) $fixture.Parameters.domainInventory.Remove('source') }; Reason = 'source' }
        @{ Case = 'missing source owner'; Change = { param($fixture) $fixture.Parameters.domainInventory.source.Remove('owner') }; Reason = 'owner|source' }
        @{ Case = 'blank source reference'; Change = { param($fixture) $fixture.Parameters.domainInventory.source.reference = ' ' }; Reason = 'reference|source' }
        @{ Case = 'missing source timestamp'; Change = { param($fixture) $fixture.Parameters.domainInventory.source.Remove('suppliedAtUtc') }; Reason = 'supplied|source|timestamp' }
        @{ Case = 'malformed source timestamp'; Change = { param($fixture) $fixture.Parameters.domainInventory.source.suppliedAtUtc = 'yesterday' }; Reason = 'supplied|source|timestamp' }
        @{ Case = 'future source timestamp'; Change = { param($fixture) $fixture.Parameters.domainInventory.source.suppliedAtUtc = [datetimeoffset]::UtcNow.AddDays(3).ToString('o') }; Reason = 'supplied|source|future' }
        @{ Case = 'missing domains'; Change = { param($fixture) $fixture.Parameters.domainInventory.Remove('domains') }; Reason = 'domain' }
        @{ Case = 'empty domains'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains = @() }; Reason = 'domain' }
        @{ Case = 'nonarray domains'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains = @{ domainName = 'contoso.example' } }; Reason = 'domain|array' }
        @{ Case = 'null domain entry'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains += $null }; Reason = 'domain|entry' }
        @{ Case = 'missing domain name'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].Remove('domainName') }; Reason = 'domain|name' }
        @{ Case = 'invalid domain name'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].domainName = 'https://contoso.example/mail' }; Reason = 'domain|name' }
        @{ Case = 'duplicate normalized inventory name'; Change = { param($fixture) $duplicate = $fixture.Parameters.domainInventory.domains[0].Clone(); $duplicate.domainName = ' CONTOSO.EXAMPLE. '; $fixture.Parameters.domainInventory.domains += $duplicate }; Reason = 'duplicate|ambiguous' }
        @{ Case = 'missing accepted classification'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].Remove('accepted') }; Reason = 'accepted|classification' }
        @{ Case = 'string accepted classification'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].accepted = 'true' }; Reason = 'accepted|classification|boolean' }
        @{ Case = 'missing sending classification'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].Remove('sending') }; Reason = 'sending|classification' }
        @{ Case = 'string sending classification'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].sending = 'false' }; Reason = 'sending|classification|boolean' }
        @{ Case = 'missing parked classification'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].Remove('parked') }; Reason = 'parked|classification' }
        @{ Case = 'string parked classification'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].parked = 'false' }; Reason = 'parked|classification|boolean' }
        @{ Case = 'contradictory parked sender'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].parked = $true }; Reason = 'parked|sending|classification' }
        @{ Case = 'unclassified domain'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].accepted = $false; $fixture.Parameters.domainInventory.domains[0].sending = $false }; Reason = 'classification|domain|accepted' }
        @{ Case = 'missing owner'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].Remove('owner') }; Reason = 'owner' }
        @{ Case = 'missing sender provenance'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].Remove('senderSource') }; Reason = 'sender|source' }
        @{ Case = 'sender provenance is not inherited from inventory'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].senderSource = @{} }; Reason = 'sender|source' }
        @{ Case = 'missing sender owner'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].senderSource.Remove('owner') }; Reason = 'sender|owner' }
        @{ Case = 'missing sender reference'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].senderSource.Remove('reference') }; Reason = 'sender|reference' }
        @{ Case = 'missing sender timestamp'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].senderSource.Remove('suppliedAtUtc') }; Reason = 'sender|supplied|timestamp' }
        @{ Case = 'invalid sender timestamp'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].senderSource.suppliedAtUtc = 'invalid' }; Reason = 'sender|supplied|timestamp' }
        @{ Case = 'future sender timestamp'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].senderSource.suppliedAtUtc = [datetimeoffset]::UtcNow.AddDays(3).ToString('o') }; Reason = 'sender|supplied|future' }
        @{ Case = 'missing sending system'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].Remove('sendingSystem') }; Reason = 'sending|system' }
        @{ Case = 'unsupported sending system'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].sendingSystem = 'Unknown' }; Reason = 'sending|system' }
        @{ Case = 'Exchange sender not accepted'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].accepted = $false }; Reason = 'accepted|Exchange|sending' }
        @{ Case = 'invalid initial parameter'; Change = { param($fixture) $fixture.Parameters.INITIAL_ONMICROSOFT_DOMAIN = 'not-an-initial.example' }; Reason = 'initial|onmicrosoft' }
    ) {
        # Arrange
        $fixture = New-DomainInventoryFixture
        $null = & $Change $fixture

        # Act
        $result = Invoke-DomainInventoryPublicFixture -Fixture $fixture

        # Assert
        $result.Check.Status | Should -BeIn @('Error', 'Fail')
        $result.Check.Reason | Should -Match $Reason
    }

    It 'rejects a missing initial parameter at admission or as a non-Pass control' {
        # Arrange
        $fixture = New-DomainInventoryFixture
        $fixture.Parameters.Remove('INITIAL_ONMICROSOFT_DOMAIN')

        # Act
        $result = Invoke-DomainInventoryPublicFixture -Fixture $fixture -AllowAdmissionRefusal

        # Assert
        $result.ExitCode | Should -Not -Be 0
        if ($null -ne $result.Check) { $result.Check.Status | Should -BeIn @('Error', 'Fail') }
        ($result.Output + $result.Check.Reason) | Should -Match 'initial|onmicrosoft'
    }
}

Describe 'EXR-011-A01 complete domain reconciliation and approved topology' {
    It 'refuses evaluation Pass when approved primary InternalRelay conflicts with configured Authoritative' {
        # Arrange
        $fixture = New-CompleteDomainTopologyFixture
        $fixture.Configuration.controls['EXO-001'].domainType = 'Authoritative'

        # Act
        $result = Invoke-DomainInventoryPublicFixture -Fixture $fixture -AllowAdmissionRefusal

        # Assert
        if ($null -ne $result.Check) { $result.Check.Status | Should -BeIn @('Error', 'Fail') }
        else { $result.ExitCode | Should -Not -Be 0 }
        ($result.Output + $result.Check.Reason) | Should -Match 'DomainInventory.*(conflict|topology)|topology.*(conflict|configur)'
    }

    It 'fails known domain drift: <Case>' -ForEach @(
        @{ Case = 'initial omitted from inventory'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains = @($fixture.Parameters.domainInventory.domains[0]) }; Reason = 'initial|onmicrosoft' }
        @{ Case = 'initial omitted from observation'; Change = { param($fixture) $fixture.Raw['Get-AcceptedDomain'].Items = @($fixture.Raw['Get-AcceptedDomain'].Items[0]) }; Reason = 'contoso.onmicrosoft.com' }
        @{ Case = 'primary omitted from observation'; Change = { param($fixture) $fixture.Raw['Get-AcceptedDomain'].Items = @($fixture.Raw['Get-AcceptedDomain'].Items[1]); $fixture.Raw['Get-AcceptedDomain'].Remove('ByIdentity') }; Reason = 'contoso.example' }
        @{ Case = 'complete empty observation'; Change = { param($fixture) $fixture.Raw['Get-AcceptedDomain'].Items = @(); $fixture.Raw['Get-AcceptedDomain'].Remove('ByIdentity') }; Reason = 'contoso.example|missing|absent|accepted' }
        @{ Case = 'extra accepted domain not declared'; Change = { param($fixture) $fixture.Raw['Get-AcceptedDomain'].Items += @{ Name = 'undeclared.example'; DomainName = 'undeclared.example'; DomainType = 'Authoritative' } }; Reason = 'undeclared.example' }
        @{ Case = 'additional accepted domain absent'; Change = { param($fixture) Add-DomainInventoryEntry $fixture 'additional.example' }; Reason = 'additional.example' }
        @{ Case = 'sending domain absent'; Change = { param($fixture) Add-DomainInventoryEntry $fixture 'sender.example' -Sending $true }; Reason = 'sender.example' }
        @{ Case = 'subdomain absent'; Change = { param($fixture) Add-DomainInventoryEntry $fixture 'child.contoso.example' -Parent 'contoso.example' }; Reason = 'child.contoso.example' }
        @{ Case = 'accepted parked domain absent'; Change = { param($fixture) Add-DomainInventoryEntry $fixture 'parked.example' -Parked $true }; Reason = 'parked.example' }
        @{ Case = 'approved Authoritative observed InternalRelay'; Change = { param($fixture) $fixture.Raw['Get-AcceptedDomain'].Items[1].DomainType = 'InternalRelay' }; Reason = 'onmicrosoft|topology|Authoritative|InternalRelay' }
        @{ Case = 'unsupported observed domain type'; Change = { param($fixture) $fixture.Raw['Get-AcceptedDomain'].Items[1].DomainType = 'ExternalRelay' }; Reason = 'ExternalRelay|type|topology' }
        @{ Case = 'approved relay observed Authoritative'; Change = { param($fixture) $fixture.Configuration.controls['EXO-001'].domainType = 'InternalRelay'; $entry = $fixture.Parameters.domainInventory.domains[0]; $entry.domainType = 'InternalRelay'; $entry.topologyApproval = @{ owner = 'Synthetic routing owner'; reference = 'fixture:split-routing'; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') } }; Reason = 'topology|InternalRelay|Authoritative' }
    ) {
        # Arrange
        $fixture = New-DomainInventoryFixture
        $null = & $Change $fixture

        # Act
        $result = Invoke-DomainInventoryPublicFixture -Fixture $fixture

        # Assert
        $result.Check.Status | Should -BeExactly Fail
        $result.Check.Reason | Should -Match $Reason
    }

    It 'refuses ambiguous topology or handoff: <Case>' -ForEach @(
        @{ Case = 'unsupported approved domain type'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].domainType = 'ExternalRelay' }; Reason = 'type|topology' }
        @{ Case = 'missing approved domain type'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].Remove('domainType') }; Reason = 'type|topology' }
        @{ Case = 'InternalRelay without approval'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].domainType = 'InternalRelay' }; Reason = 'approval|topology' }
        @{ Case = 'InternalRelay approval missing owner'; Change = { param($fixture) $entry = $fixture.Parameters.domainInventory.domains[0]; $entry.domainType = 'InternalRelay'; $entry.topologyApproval = @{ reference = 'fixture:split-routing'; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') } }; Reason = 'approval|owner' }
        @{ Case = 'InternalRelay approval missing reference'; Change = { param($fixture) $entry = $fixture.Parameters.domainInventory.domains[0]; $entry.domainType = 'InternalRelay'; $entry.topologyApproval = @{ owner = 'Synthetic routing owner'; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') } }; Reason = 'approval|reference' }
        @{ Case = 'InternalRelay approval missing expiry'; Change = { param($fixture) $entry = $fixture.Parameters.domainInventory.domains[0]; $entry.domainType = 'InternalRelay'; $entry.topologyApproval = @{ owner = 'Synthetic routing owner'; reference = 'fixture:split-routing' } }; Reason = 'approval|expir' }
        @{ Case = 'InternalRelay expired approval'; Change = { param($fixture) $entry = $fixture.Parameters.domainInventory.domains[0]; $entry.domainType = 'InternalRelay'; $entry.topologyApproval = @{ owner = 'Synthetic routing owner'; reference = 'fixture:split-routing'; expiresOn = [datetimeoffset]::UtcNow.AddDays(-1).ToString('o') } }; Reason = 'approval|expir' }
        @{ Case = 'InternalRelay invalid approval expiry'; Change = { param($fixture) $entry = $fixture.Parameters.domainInventory.domains[0]; $entry.domainType = 'InternalRelay'; $entry.topologyApproval = @{ owner = 'Synthetic routing owner'; reference = 'fixture:split-routing'; expiresOn = 'never' } }; Reason = 'approval|expir' }
        @{ Case = 'missing parent classification'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].Remove('parentDomain') }; Reason = 'parent' }
        @{ Case = 'subdomain parent not declared'; Change = { param($fixture) Add-DomainInventoryEntry $fixture 'child.missing.example' -Parent 'missing.example' -Observe }; Reason = 'parent|missing.example' }
        @{ Case = 'subdomain parent mismatches name'; Change = { param($fixture) Add-DomainInventoryEntry $fixture 'child.other.example' -Parent 'contoso.example' -Observe }; Reason = 'parent|subdomain' }
        @{ Case = 'domain is its own parent'; Change = { param($fixture) $fixture.Parameters.domainInventory.domains[0].parentDomain = 'contoso.example' }; Reason = 'parent|cycle' }
        @{ Case = 'subdomain hides known parent'; Change = { param($fixture) Add-DomainInventoryEntry $fixture 'child.contoso.example' -Observe }; Reason = 'parent|subdomain' }
        @{ Case = 'external parked owner missing'; Change = { param($fixture) Add-DomainInventoryEntry $fixture 'parked.external.example' -Accepted $false -Parked $true; $fixture.Parameters.domainInventory.domains[-1].Remove('owner') }; Reason = 'owner|parked' }
        @{ Case = 'external sender provenance missing'; Change = { param($fixture) Add-DomainInventoryEntry $fixture 'sender.external.example' -Accepted $false -Sending $true; $fixture.Parameters.domainInventory.domains[-1].Remove('senderSource') }; Reason = 'sender|source' }
        @{ Case = 'external owner attestation missing reference'; Change = { param($fixture) Add-DomainInventoryEntry $fixture 'parked.external.example' -Accepted $false -Parked $true; $fixture.Parameters.domainInventory.domains[-1].ownerAttestation = @{ suppliedAtUtc = [datetimeoffset]::UtcNow.AddMinutes(-5).ToString('o'); expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') } }; Reason = 'attestation|reference' }
        @{ Case = 'external owner attestation invalid timestamp'; Change = { param($fixture) Add-DomainInventoryEntry $fixture 'parked.external.example' -Accepted $false -Parked $true; $fixture.Parameters.domainInventory.domains[-1].ownerAttestation = @{ reference = 'fixture:owner-assertion'; suppliedAtUtc = 'yesterday'; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') } }; Reason = 'attestation|supplied|timestamp' }
        @{ Case = 'external owner attestation expired'; Change = { param($fixture) Add-DomainInventoryEntry $fixture 'parked.external.example' -Accepted $false -Parked $true; $fixture.Parameters.domainInventory.domains[-1].ownerAttestation = @{ reference = 'fixture:owner-assertion'; suppliedAtUtc = [datetimeoffset]::UtcNow.AddDays(-2).ToString('o'); expiresOn = [datetimeoffset]::UtcNow.AddDays(-1).ToString('o') } }; Reason = 'attestation|expir' }
        @{ Case = 'external owner attestation future timestamp'; Change = { param($fixture) Add-DomainInventoryEntry $fixture 'parked.external.example' -Accepted $false -Parked $true; $fixture.Parameters.domainInventory.domains[-1].ownerAttestation = @{ reference = 'fixture:owner-assertion'; suppliedAtUtc = [datetimeoffset]::UtcNow.AddDays(1).ToString('o'); expiresOn = [datetimeoffset]::UtcNow.AddDays(2).ToString('o') } }; Reason = 'attestation|supplied|future' }
        @{ Case = 'external owner attestation missing expiry'; Change = { param($fixture) Add-DomainInventoryEntry $fixture 'parked.external.example' -Accepted $false -Parked $true; $fixture.Parameters.domainInventory.domains[-1].ownerAttestation = @{ reference = 'fixture:owner-assertion'; suppliedAtUtc = [datetimeoffset]::UtcNow.AddMinutes(-5).ToString('o') } }; Reason = 'attestation|expir' }
    ) {
        # Arrange
        $fixture = New-DomainInventoryFixture
        $null = & $Change $fixture

        # Act
        $result = Invoke-DomainInventoryPublicFixture -Fixture $fixture

        # Assert
        $result.Check.Status | Should -BeIn @('Error', 'Fail')
        $result.Check.Reason | Should -Match $Reason
    }
}

Describe 'EXR-011-A01 raw accepted domain completeness' {
    It 'retains unusable raw observations as Error: <Case>' -ForEach @(
        @{ Case = 'collection error after partial output'; Change = { param($response) $response.Error = 'Synthetic domain collection denied' }; Reason = 'Synthetic domain collection denied' }
        @{ Case = 'collection warning after partial output'; Change = { param($response) $response.Warning = 'Synthetic result truncated' }; Reason = 'warning|truncated' }
        @{ Case = 'continuation envelope'; Change = { param($response) $response.Items[0].ContinuationToken = 'synthetic-next' }; Reason = 'page|envelope' }
        @{ Case = 'odata envelope'; Change = { param($response) $response.Items[0]['@odata.nextLink'] = 'https://invalid.example/next' }; Reason = 'page|envelope' }
        @{ Case = 'next page envelope'; Change = { param($response) $response.Items[0].NextPageToken = 'synthetic-next' }; Reason = 'page|envelope' }
        @{ Case = 'explicit incomplete envelope'; Change = { param($response) $response.Items[0].Complete = $false }; Reason = 'page|envelope|complete' }
        @{ Case = 'missing Name'; Change = { param($response) $response.Items[0].Remove('Name') }; Reason = 'Name|property' }
        @{ Case = 'missing DomainName'; Change = { param($response) $response.Items[0].Remove('DomainName') }; Reason = 'DomainName|property' }
        @{ Case = 'missing DomainType'; Change = { param($response) $response.Items[0].Remove('DomainType') }; Reason = 'DomainType|property' }
        @{ Case = 'empty DomainName'; Change = { param($response) $response.Items[0].DomainName = ' ' }; Reason = 'identity|DomainName' }
        @{ Case = 'duplicate normalized raw identity'; Change = { param($response) $duplicate = $response.Items[0].Clone(); $duplicate.DomainName = ' CONTOSO.EXAMPLE. '; $response.Items += $duplicate }; Reason = 'duplicate|identity|ambiguous' }
    ) {
        # Arrange
        $fixture = New-DomainInventoryFixture
        $response = $fixture.Raw['Get-AcceptedDomain']
        Add-DomainInventoryEntry $fixture 'sender.external.example' -Accepted $false -Sending $true
        Add-DomainInventoryEntry $fixture 'parked.external.example' -Accepted $false -Parked $true
        $response.Remove('ByIdentity')
        $response.Items = @($response.Items[0])
        $null = & $Change $response

        # Act
        $result = Invoke-DomainInventoryPublicFixture -Fixture $fixture

        # Assert
        $result.Check.Status | Should -BeExactly Error
        $observation = @($result.Evidence.Observation | Where-Object Command -EQ 'Get-AcceptedDomain')
        $observation.Count | Should -Be 1
        $observation[0].Complete | Should -BeFalse
        $observation[0].Error | Should -Match $Reason
        @($observation[0].Raw).Count | Should -Be $response.Items.Count
        $observation[0].StartedAtUtc | Should -Not -BeNullOrEmpty
        $observation[0].FinishedAtUtc | Should -Not -BeNullOrEmpty
        if ($Case -eq 'collection warning after partial output') { $observation[0].Warnings -join ' ' | Should -Match 'Synthetic result truncated' }
        $inventory = $result.Evidence.DomainInventory
        @($inventory.domains).Count | Should -Be 4
        $inventory.source.owner | Should -BeExactly $fixture.Parameters.domainInventory.source.owner
        $inventory.source.reference | Should -BeExactly $fixture.Parameters.domainInventory.source.reference
        $inventory.source.suppliedAtUtc | Should -BeExactly $fixture.Parameters.domainInventory.source.suppliedAtUtc
        $externalSender = @($inventory.domains | Where-Object domainName -EQ 'sender.external.example')
        $externalSender.Count | Should -Be 1
        $externalSender[0].accepted | Should -BeFalse
        $externalSender[0].sending | Should -BeTrue
        $externalSender[0].sendingSystem | Should -BeExactly External
        $externalSender[0].owner | Should -BeExactly 'Synthetic independent owner'
        $externalSender[0].ownerReadiness | Should -BeExactly Unverified
        $externalSender[0].senderSource.owner | Should -BeExactly 'Synthetic external sender owner'
        $externalSender[0].senderSource.reference | Should -BeExactly 'fixture:external-sender'
        $externalSender[0].senderSource.suppliedAtUtc | Should -BeExactly $fixture.Parameters.domainInventory.domains[2].senderSource.suppliedAtUtc
        $parked = @($inventory.domains | Where-Object domainName -EQ 'parked.external.example')
        $parked.Count | Should -Be 1
        $parked[0].accepted | Should -BeFalse
        $parked[0].parked | Should -BeTrue
        $parked[0].owner | Should -BeExactly 'Synthetic independent owner'
        $parked[0].ownerReadiness | Should -BeExactly Unverified
        @($observation[0].Raw | Where-Object DomainName -Like '*.external.example').Count | Should -Be 0
    }

    It 'does not substitute an Identity lookup for full unlimited domain collection' {
        # Arrange
        $fixture = New-DomainInventoryFixture

        # Act
        $result = Invoke-DomainInventoryPublicFixture -Fixture $fixture

        # Assert
        $calls = @($result.Calls | Where-Object { $_ -like 'Get-AcceptedDomain:*' })
        $calls.Count | Should -Be 1
        $arguments = ($calls[0] -split ':', 2)[1] | ConvertFrom-Json -AsHashtable
        $arguments.ContainsKey('Identity') | Should -BeFalse
        $arguments.ResultSize | Should -BeExactly 'Unlimited'
    }
}

Describe 'EXR-011-A01 public domain evidence provenance' {
    It 'does not omit <Class> from the evidence denominator' -ForEach @(
        @{ Class = 'external sending'; Name = 'sender.external.example'; Sending = $true; Parked = $false }
        @{ Class = 'external parked'; Name = 'parked.external.example'; Sending = $false; Parked = $true }
        @{ Class = 'accepted subdomain'; Name = 'child.contoso.example'; Sending = $false; Parked = $false }
    ) {
        # Arrange
        $fixture = New-DomainInventoryFixture
        $isSubdomain = $Class -eq 'accepted subdomain'
        Add-DomainInventoryEntry $fixture $Name -Accepted $isSubdomain -Sending $Sending -Parked $Parked -Parent $(if ($isSubdomain) { 'contoso.example' } else { $null }) -Observe:$isSubdomain

        # Act
        $result = Invoke-DomainInventoryPublicFixture -Fixture $fixture

        # Assert
        $entries = @($result.Evidence.DomainInventory.domains | Where-Object domainName -EQ $Name)
        $entries.Count | Should -Be 1
        $entries[0].owner | Should -BeExactly 'Synthetic independent owner'
        $result.Check.Status | Should -Not -BeExactly NotApplicable
        if (-not $isSubdomain) { $entries[0].ownerReadiness | Should -BeExactly Unverified }
        if ($Sending) { $entries[0].senderSource.reference | Should -BeExactly 'fixture:external-sender' }
    }

    It 'does not replace independent input source with Exchange observation provenance' {
        # Arrange
        $fixture = New-DomainInventoryFixture

        # Act
        $result = Invoke-DomainInventoryPublicFixture -Fixture $fixture

        # Assert
        $result.Evidence.DomainInventory.source.reference | Should -BeExactly 'fixture:inventory-approval'
        $result.Evidence.DomainInventory.source.owner | Should -BeExactly 'Synthetic inventory owner'
        $result.Evidence.DomainInventory.source.suppliedAtUtc | Should -BeExactly $fixture.Parameters.domainInventory.source.suppliedAtUtc
    }
}

Describe 'EXR-011-A01 executable domain contract mapping' {
    It 'ships a versioned schema that refuses missing completeness' {
        # Arrange
        $fixture = New-DomainInventoryFixture
        $fixture.Parameters.domainInventory.Remove('complete')
        $schemaPath = Join-Path $sampleRoot 'config/domain-inventory.schema.v1.json'
        $json = $fixture.Parameters.domainInventory | ConvertTo-Json -Depth 30
        $schemaExists = Test-Path $schemaPath

        # Act
        $valid = if ($schemaExists) { Test-Json -Json $json -SchemaFile $schemaPath -ErrorAction SilentlyContinue } else { $null }

        # Assert
        $schemaExists | Should -BeTrue
        $valid | Should -BeFalse
    }

    It 'does not ship an active sample without explicit domain inventory' {
        # Arrange
        $samplePath = Join-Path $sampleRoot 'config/parameters.exchange-only.sample.json'

        # Act
        $sample = Get-Content $samplePath -Raw | ConvertFrom-Json -AsHashtable

        # Assert
        $sample.domainInventory.schemaVersion | Should -Be 1
        $sample.domainInventory.tenantId | Should -BeExactly $sample.MICROSOFT_ENTRA_TENANT_GUID
        @($sample.domainInventory.domains.domainName) | Should -Contain $sample.INITIAL_ONMICROSOFT_DOMAIN
        $sample.domainInventory.source.reference | Should -Not -BeNullOrEmpty
    }

    It 'does not retain the primary-only recommendation mapping for EXO-001' {
        # Arrange
        $mappingPath = Join-Path $sampleRoot 'config/exchange-recommendations.v1.json'

        # Act
        $catalog = Get-Content $mappingPath -Raw | ConvertFrom-Json

        # Assert
        $mapping = @($catalog.Mappings | Where-Object ControlId -EQ 'EXO-001')
        $mapping.Count | Should -Be 1
        $mapping[0].SourceId | Should -BeExactly S01
        $mapping[0].Evaluator | Should -BeExactly 'Test-AcceptedDomainControl'
        $mapping[0].Evidence | Should -BeExactly 'exchangeOnline.acceptedDomain'
        ($mapping[0].Setting + ' ' + $mapping[0].Limit) | Should -Not -Match 'one domain only|configured domain in this all-cloud'
        ($mapping[0].Setting + ' ' + $mapping[0].Limit) | Should -Match 'inventory|denominator'
        $mapping[0].Runbook | Should -BeExactly 'docs/EXCHANGE-ONLY.md'
        $mapping[0].RunbookSection | Should -Match 'domain'
    }

    It 'does not leave the control catalogue without the supplied inventory and topology contract' {
        # Arrange
        $catalogPath = Join-Path $sampleRoot 'docs/CONTROL-CATALOG.md'

        # Act
        $catalog = Get-Content $catalogPath -Raw

        # Assert
        $catalog | Should -Match 'domainInventory'
        $catalog | Should -Match 'InternalRelay'
        $catalog | Should -Match 'EXCHANGE-ONLY.md'
    }

    It 'provides a parseable explicit inventory runbook example rather than implicit completeness' {
        # Arrange
        $guidePath = Join-Path $sampleRoot 'docs/EXCHANGE-ONLY.md'

        # Act
        $guide = Get-Content $guidePath -Raw

        # Assert
        $blocks = @([regex]::Matches($guide, '(?s)```json\s*(.*?)```') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -match '"domainInventory"' })
        $blocks.Count | Should -Be 1
        $example = ($blocks[0] | ConvertFrom-Json -AsHashtable).domainInventory
        $example.schemaVersion | Should -Be 1
        $example.tenantId | Should -Not -BeNullOrEmpty
        $example.complete | Should -BeOfType ([bool])
        $example.source.reference | Should -Not -BeNullOrEmpty
        @($example.domains | Where-Object { $_.sending }).Count | Should -BeGreaterThan 0
        @($example.domains | Where-Object { $_.parked -and -not $_.accepted }).Count | Should -BeGreaterThan 0
        @($example.domains | Where-Object { $_.domainType -eq 'InternalRelay' -and $_.topologyApproval.reference }).Count | Should -BeGreaterThan 0
        @($example.domains | Where-Object { $_.domainName -like '*.onmicrosoft.com' }).Count | Should -BeGreaterThan 0
        $guide | Should -Match 'Get-AcceptedDomain\s+-ResultSize\s+Unlimited'
        $guide | Should -Match 'Unverified'
    }
}

Describe 'EXR-011-A01 positive complete inventory and effective topology' {
    It 'passes the complete approved topology without requiring external parked or sending domains in Exchange' {
        # Arrange
        $fixture = New-CompleteDomainTopologyFixture

        # Act
        $result = Invoke-DomainInventoryPublicFixture -Fixture $fixture

        # Assert
        $result.Check.Status | Should -BeExactly Pass
        $result.Check.ControlId | Should -BeExactly 'EXO-001'
        $observations = @($result.Evidence.Observation | Where-Object Command -EQ 'Get-AcceptedDomain')
        $observations.Count | Should -Be 1
        $observations[0].Complete | Should -BeTrue
        $observations[0].Paging | Should -BeExactly ResultSizeUnlimited
        @($observations[0].Raw).Count | Should -Be 4
        @($observations[0].Raw | Where-Object DomainType -EQ 'InternalRelay').Count | Should -Be 1
        @($observations[0].Raw | Where-Object DomainName -Like '*.external.example').Count | Should -Be 0
    }
}

Describe 'EXR-011-A01 positive public domain evidence' {
    It 'retains the complete normalized denominator and independent provenance without certifying external owners' {
        # Arrange
        $fixture = New-CompleteDomainTopologyFixture
        $expectedNames = @($fixture.Parameters.domainInventory.domains.domainName | Sort-Object)

        # Act
        $result = Invoke-DomainInventoryPublicFixture -Fixture $fixture

        # Assert
        $inventory = $result.Evidence.DomainInventory
        @($inventory.domains).Count | Should -Be 6
        @($inventory.domains.domainName | Sort-Object) -join ',' | Should -BeExactly ($expectedNames -join ',')
        $inventory.schemaVersion | Should -Be 1
        $inventory.complete | Should -BeTrue
        $inventory.tenantId | Should -BeExactly $fixture.Parameters.MICROSOFT_ENTRA_TENANT_GUID
        $inventory.source.owner | Should -BeExactly $fixture.Parameters.domainInventory.source.owner
        $inventory.source.reference | Should -BeExactly $fixture.Parameters.domainInventory.source.reference
        $inventory.source.suppliedAtUtc | Should -BeExactly $fixture.Parameters.domainInventory.source.suppliedAtUtc
        $relay = @($inventory.domains | Where-Object domainName -EQ 'contoso.example')[0]
        $relay.domainType | Should -BeExactly InternalRelay
        $relay.topologyApproval.reference | Should -BeExactly 'fixture:split-routing'
        $child = @($inventory.domains | Where-Object domainName -EQ 'child.contoso.example')[0]
        $child.parentDomain | Should -BeExactly 'contoso.example'
        $child.sending | Should -BeTrue
        $externalSender = @($inventory.domains | Where-Object domainName -EQ 'sender.external.example')[0]
        $externalSender.accepted | Should -BeFalse
        $externalSender.sendingSystem | Should -BeExactly External
        $externalSender.senderSource.owner | Should -BeExactly 'Synthetic external sender owner'
        $externalSender.senderSource.reference | Should -BeExactly 'fixture:external-sender'
        $externalSender.senderSource.suppliedAtUtc | Should -BeExactly $fixture.Parameters.domainInventory.domains[4].senderSource.suppliedAtUtc
        $externalSender.ownerReadiness | Should -BeExactly Unverified
        $externalParked = @($inventory.domains | Where-Object domainName -EQ 'parked.external.example')[0]
        $externalParked.accepted | Should -BeFalse
        $externalParked.parked | Should -BeTrue
        $externalParked.owner | Should -BeExactly 'Synthetic independent owner'
        $externalParked.ownerReadiness | Should -BeExactly Unverified
        $result.Check.Status | Should -BeExactly Pass
        $result.Evidence.Source | Should -BeExactly ExchangeOnline
        $result.Evidence.Command | Should -BeExactly 'Get-AcceptedDomain'
        $raw = @($result.Evidence.Observation | Where-Object Command -EQ 'Get-AcceptedDomain')[0].Raw
        @($raw | Where-Object DomainName -CEQ ' CONTOSO.ONMICROSOFT.COM. ').Count | Should -Be 1
        @($result.Envelope.Check).Count | Should -Be 25
        @($result.Envelope.Evidence).Count | Should -Be 25
    }
}