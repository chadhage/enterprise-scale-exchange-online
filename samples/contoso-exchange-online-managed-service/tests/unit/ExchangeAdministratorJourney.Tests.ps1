BeforeAll {
    $script:sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:guidePath = Join-Path $script:sampleRoot 'docs/EXCHANGE-ADMINISTRATOR-JOURNEY.md'
    . (Join-Path $script:sampleRoot 'tests/helpers/ExchangeJourneyDoubles.ps1')
    function Invoke-JourneyExample {
        param([hashtable]$InputData, [string]$Through = 'inputs')
        if (-not (Test-Path $script:guidePath)) { throw 'JourneyGuideMissing' }
        $guide = Get-Content $script:guidePath -Raw
        $blocks = [regex]::Matches($guide, '(?s)<!-- journey:([a-z]+) -->\s*```powershell\s*(.*?)```')
        $expected = @('inputs','session','domain','mailboxes','groups','presets','hardening','preview','approve','apply','frozen','validation')
        if (($blocks | ForEach-Object { $_.Groups[1].Value }) -join ',' -cne ($expected -join ',')) { throw 'JourneyGuideOrder' }
        $code = [Collections.Generic.List[string]]::new()
        foreach ($block in $blocks) {
            if ($block.Groups[1].Value -eq 'presets') { $code.Add('Invoke-JourneyPortalInitialization') }
            if ($block.Groups[1].Value -eq 'frozen') { $code.Add('$global:journeyState.Collecting = $true') }
            $code.Add($block.Groups[2].Value)
            if ($block.Groups[1].Value -eq 'frozen') { $code.Add('$global:journeyState.Gate = $gate | ConvertFrom-Json; $global:journeyState.FrozenHash = $evidenceHash') }
            if ($block.Groups[1].Value -eq $Through) { break }
        }
        Push-Location $script:sampleRoot
        try { & ([scriptblock]::Create('param($journey)' + "`n" + ($code -join "`n"))) $InputData }
        catch {
            if ($_.Exception.Message -like 'JourneyCollectionRefused:*') {
                $evidence = Get-Content (Join-Path $InputData.ArtifactRoot 'evidence/exchange-online-evidence.json') -Raw | ConvertFrom-Json
                $evidence.Check | Where-Object Status -NotIn @('Pass','ApprovedException') | ForEach-Object { Write-Host "$($_.ControlId) $($_.Status): $($_.Reason)" }
            }
            throw
        }
        finally { Pop-Location }
    }
    function New-JourneyInput {
        $tenant = '11111111-2222-3333-4444-555555555555'
        $records = @{}
        foreach ($name in 'Tenant','Domain','Identity','License','Access','Dns','Signing','Change','Client') {
            $records[$name] = @{
                Owner = "$name owner"; Reference = "OFFLINE-$name"; TenantId = $tenant
                Approved = $true; ExpiresUtc = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
            }
        }
        @{
            TenantId = $tenant; Cloud = 'O365Default'; Domain = 'contoso.example'
            DomainType = 'Authoritative'; Operator = 'operator@contoso.example'
            Mailboxes = @('pilot@contoso.example'); OperationsMailbox = 'secops@contoso.example'
            PriorityGroup = 'priority-users@contoso.example'; PriorityMembers = @('pilot@contoso.example')
            GroupOwner = 'pilot@contoso.example'; Preset = 'Standard'
            ParameterPath = 'C:\ApprovedExchange\parameters.json'; ArtifactRoot = 'C:\ApprovedExchange\CHG008'
            ChangeId = 'CHG008'; AuthorityPath = 'C:\ApprovedExchange\authority.json'
            ApprovalIdentity = 'approver@contoso.example'; CertificateThumbprint = 'OFFLINE'
            ConfigurationHash = ('a' * 64); ConfigurationPath = 'C:\ApprovedExchange\configuration.json'; Handoffs = $records
            Validation = @()
        }
    }
}

Describe 'EXR-008 executable Exchange administrator journey' {
    BeforeEach {
        $script:journeyCalls = [Collections.Generic.List[string]]::new()
    }

    AfterEach { Clear-JourneyDoubles }

    It 'refuses missing required input <Field> before provisioning' -ForEach @(
        'TenantId','Cloud','Domain','DomainType','Operator','Mailboxes','OperationsMailbox',
        'PriorityGroup','PriorityMembers','GroupOwner','Preset','ParameterPath','ArtifactRoot',
        'ChangeId','AuthorityPath','ApprovalIdentity','CertificateThumbprint','ConfigurationHash','ConfigurationPath','Handoffs'
    | ForEach-Object { @{ Field = $_ } }) {
        # Arrange
        $inputData = New-JourneyInput
        $inputData.Remove($Field)
        # Act
        $invoke = { Invoke-JourneyExample -InputData $inputData }
        # Assert
        $invoke | Should -Throw "*JourneyInputRequired:$Field*"
        $script:journeyCalls.Count | Should -Be 0
    }

    It 'routes missing <Handoff> to <Owner> without provisioning' -ForEach @(
        @{ Handoff = 'Tenant'; Owner = 'RAID-D01' }
        @{ Handoff = 'Domain'; Owner = 'RAID-D02' }
        @{ Handoff = 'Identity'; Owner = 'RAID-D02' }
        @{ Handoff = 'License'; Owner = 'RAID-D02' }
        @{ Handoff = 'Access'; Owner = 'RAID-D03' }
        @{ Handoff = 'Dns'; Owner = 'RAID-D04' }
        @{ Handoff = 'Signing'; Owner = 'RAID-D05' }
        @{ Handoff = 'Change'; Owner = 'RAID-D05' }
        @{ Handoff = 'Client'; Owner = 'RAID-D02' }
    ) {
        # Arrange
        $inputData = New-JourneyInput
        $inputData.Handoffs.Remove($Handoff)
        # Act
        $invoke = { Invoke-JourneyExample -InputData $inputData }
        # Assert
        $invoke | Should -Throw "*JourneyHandoffRequired:$Handoff*$Owner*"
        $script:journeyCalls.Count | Should -Be 0
    }

    It 'refuses invalid owner handoff <Fault>' -ForEach @('Owner','Reference','TenantId','Approved','ExpiresUtc','Expired' | ForEach-Object { @{ Fault = $_ } }) {
        # Arrange
        $inputData = New-JourneyInput
        switch ($Fault) {
            TenantId { $inputData.Handoffs.Tenant.TenantId = 'another-tenant' }
            Approved { $inputData.Handoffs.Tenant.Approved = $false }
            Expired { $inputData.Handoffs.Tenant.ExpiresUtc = [datetimeoffset]::UtcNow.AddDays(-1).ToString('o') }
            default { $inputData.Handoffs.Tenant.Remove($Fault) }
        }
        # Act
        $invoke = { Invoke-JourneyExample -InputData $inputData }
        # Assert
        $invoke | Should -Throw '*JourneyHandoffInvalid:Tenant*RAID-D01*'
        $script:journeyCalls.Count | Should -Be 0
    }

    It 'refuses unsupported topology or unresolved input <Fault>' -ForEach @(
        @{ Fault = 'Cloud'; Value = 'Unknown'; Reason = 'JourneyCloudUnsupported' }
        @{ Fault = 'DomainType'; Value = 'ExternalRelay'; Reason = 'JourneyTopologyUnsupported' }
        @{ Fault = 'TenantId'; Value = 'not-a-guid'; Reason = 'JourneyTenantInvalid' }
        @{ Fault = 'Preset'; Value = 'Custom'; Reason = 'JourneyPresetUnsupported' }
        @{ Fault = 'OperationsMailbox'; Value = 'secops@other.example'; Reason = 'JourneyRecipientScope' }
        @{ Fault = 'PriorityMembers'; Value = @('unknown@contoso.example'); Reason = 'JourneyMembershipUnapproved' }
        @{ Fault = 'GroupOwner'; Value = 'unknown@contoso.example'; Reason = 'JourneyMembershipUnapproved' }
        @{ Fault = 'ApprovalIdentity'; Value = 'operator@contoso.example'; Reason = 'JourneyIndependentApproverRequired' }
    ) {
        # Arrange
        $inputData = New-JourneyInput
        $inputData[$Fault] = $Value
        # Act
        $invoke = { Invoke-JourneyExample -InputData $inputData }
        # Assert
        $invoke | Should -Throw "*$Reason*"
        $script:journeyCalls.Count | Should -Be 0
    }

    It 'stops <Fault> at <Through> with <Reason>' -ForEach @(
        @{ Fault = 'ModuleMissing'; Through = 'session'; Reason = 'JourneyModuleRequired' }
        @{ Fault = 'ModuleOld'; Through = 'session'; Reason = 'JourneyModuleRequired' }
        @{ Fault = 'RoleMissing'; Through = 'session'; Reason = 'JourneyPermissionRequired' }
        @{ Fault = 'RoleParameterMissing'; Through = 'session'; Reason = 'JourneyPermissionRequired:New-Mailbox.Shared' }
        @{ Fault = 'WrongTenant'; Through = 'session'; Reason = 'JourneySessionMismatch' }
        @{ Fault = 'MultipleSessions'; Through = 'session'; Reason = 'JourneySessionMismatch' }
        @{ Fault = 'MissingParameter'; Through = 'session'; Reason = 'JourneyParameterFileRequired' }
        @{ Fault = 'UnverifiedEntitlement'; Through = 'session'; Reason = 'ExchangeEntitlementUnverified' }
        @{ Fault = 'DomainMissing'; Through = 'domain'; Reason = 'JourneyAcceptedDomainMissing' }
        @{ Fault = 'DomainDuplicate'; Through = 'domain'; Reason = 'JourneyAcceptedDomainAmbiguous' }
        @{ Fault = 'DomainReadDenied'; Through = 'domain'; Reason = 'JourneyReadFailed:AcceptedDomain' }
        @{ Fault = 'DomainReadback'; Through = 'domain'; Reason = 'JourneyDomainReadback' }
        @{ Fault = 'MailboxMissing'; Through = 'mailboxes'; Reason = 'JourneyMailboxNotProvisioned' }
        @{ Fault = 'MailboxWrongType'; Through = 'mailboxes'; Reason = 'JourneyMailboxNotProvisioned' }
        @{ Fault = 'SharedCollision'; Through = 'mailboxes'; Reason = 'JourneyRecipientCollision' }
        @{ Fault = 'SharedReadback'; Through = 'mailboxes'; Reason = 'JourneySharedReadback' }
        @{ Fault = 'GroupCollision'; Through = 'groups'; Reason = 'JourneyRecipientCollision' }
        @{ Fault = 'GroupReadback'; Through = 'groups'; Reason = 'JourneyGroupReadback' }
        @{ Fault = 'ExtraMember'; Through = 'groups'; Reason = 'JourneyMembershipDrift' }
        @{ Fault = 'MembershipReadback'; Through = 'groups'; Reason = 'JourneyMembershipReadback' }
        @{ Fault = 'PresetMissing'; Through = 'presets'; Reason = 'JourneyPresetInitializationRequired' }
        @{ Fault = 'PresetDisabled'; Through = 'presets'; Reason = 'JourneyPresetInitializationRequired' }
        @{ Fault = 'PresetReadDenied'; Through = 'presets'; Reason = 'JourneyPresetReadFailed' }
        @{ Fault = 'ParameterMismatch'; Through = 'hardening'; Reason = 'JourneyParameterMismatch' }
        @{ Fault = 'ConfigurationMismatch'; Through = 'hardening'; Reason = 'JourneyConfigurationMismatch' }
        @{ Fault = 'DnsCutoverUnapproved'; Through = 'validation'; Reason = 'JourneyDnsCutoverRequired' }
        @{ Fault = 'ValidationMissing'; Through = 'validation'; Reason = 'JourneyValidationRequired' }
        @{ Fault = 'ClientFailed'; Through = 'validation'; Reason = 'JourneyValidationFailed' }
        @{ Fault = 'TraceMissing'; Through = 'validation'; Reason = 'JourneyMessageTraceMissing' }
    ) {
        # Arrange
        $inputData = New-JourneyInput
        Initialize-JourneyDoubles -InputData $inputData -Fault $Fault -Directory $TestDrive
        # Act
        $invoke = { Invoke-JourneyExample -InputData $inputData -Through $Through }
        # Assert
        $invoke | Should -Throw "*$Reason*"
        $global:journeyState.Forbidden.Count | Should -Be 0
        if ($Through -eq 'session' -or $Fault -in @('DomainMissing','DomainDuplicate','DomainReadDenied','ParameterMismatch','ConfigurationMismatch')) {
            $global:journeyState.Writes.Count | Should -Be 0
        }
    }

    It 'refuses internal-only traffic presented as <Kind> Internet mail flow' -ForEach @(
        @{ Kind = 'Inbound'; Field = 'Sender' }
        @{ Kind = 'Outbound'; Field = 'Recipient' }
    ) {
        # Arrange
        $inputData = New-JourneyInput
        Initialize-JourneyDoubles -InputData $inputData -Directory $TestDrive
        $record = $inputData.Validation | Where-Object Kind -EQ $Kind
        $record[$Field] = $inputData.OperationsMailbox
        # Act
        $invoke = { Invoke-JourneyExample -InputData $inputData -Through validation }
        # Assert
        $invoke | Should -Throw "*JourneyValidationFailed:$Kind*external endpoint*"
        $global:journeyState.Forbidden.Count | Should -Be 0
    }

    It 'does not omit the newly created shared mailbox from the hardening preview' {
        # Arrange
        $inputData = New-JourneyInput
        Initialize-JourneyDoubles -InputData $inputData -Directory $TestDrive
        # Act
        $null = Invoke-JourneyExample -InputData $inputData -Through preview
        # Assert
        $preview = Get-Content (Join-Path $inputData.ArtifactRoot 'preview-CHG008.json') -Raw | ConvertFrom-Json
        @($preview.Operation | Where-Object { $_.Command -eq 'Set-CASMailbox' -and ($_.Identity | ConvertFrom-Json).Identity -eq $inputData.OperationsMailbox }).Count | Should -Be 1
        @(Get-Mailbox -ResultSize Unlimited | Where-Object PrimarySmtpAddress -EQ $inputData.OperationsMailbox).Count | Should -Be 1
    }

    It 'does not leak installed command doubles into subsequent test containers' {
        # Arrange
        $inputData = New-JourneyInput
        Initialize-JourneyDoubles -InputData $inputData -Directory $TestDrive
        $installedNames = @($global:journeyState.Functions | Select-Object -Unique)
        # Act
        Clear-JourneyDoubles
        # Assert
        foreach ($name in $installedNames) {
            Microsoft.PowerShell.Management\Get-Item -LiteralPath "Function:\$name" -ErrorAction SilentlyContinue | Should -BeNullOrEmpty -Because "$name must not survive journey teardown"
        }
    }

    It 'does not retain test trust or signature verification after teardown' {
        # Arrange
        $inputData = New-JourneyInput
        Initialize-JourneyDoubles -InputData $inputData -Directory $TestDrive
        $original = & (Microsoft.PowerShell.Core\Get-Module ExchangeOnlineBaseline.Common) {
            @{
                Signature = (Microsoft.PowerShell.Management\Get-Item Function:\Test-BaselineDetachedCmsSignature).Definition
                Chain = (Microsoft.PowerShell.Management\Get-Item Function:\New-BaselineEvidenceCertificateChain).Definition
            }
        }
        $null = Invoke-JourneyExample -InputData $inputData -Through session
        # Act
        Clear-JourneyDoubles
        # Assert
        $restored = & (Microsoft.PowerShell.Core\Get-Module ExchangeOnlineBaseline.Common) {
            @{
                Signature = (Microsoft.PowerShell.Management\Get-Item Function:\Test-BaselineDetachedCmsSignature).Definition
                Chain = (Microsoft.PowerShell.Management\Get-Item Function:\New-BaselineEvidenceCertificateChain).Definition
            }
        }
        $restored.Signature | Should -BeExactly $original.Signature
        $restored.Chain | Should -BeExactly $original.Chain
    }

    It 'does not leave the ordered journey undiscoverable behind historical onboarding instructions' {
        # Arrange
        $readmePath = Join-Path $script:sampleRoot 'README.md'
        # Act
        $activeEntry = (Get-Content -LiteralPath $readmePath -Raw) -split '\*\*Historical reference only:', 2 | Select-Object -First 1
        # Assert
        $activeEntry | Should -Match '\]\(docs/EXCHANGE-ADMINISTRATOR-JOURNEY\.md\)'
    }

    It 'executes the ordered net-new journey over changed Exchange state and genuine immutable artifacts' {
        # Arrange
        $inputData = New-JourneyInput
        Initialize-JourneyDoubles -InputData $inputData -Directory $TestDrive
        # Act
        $result = Invoke-JourneyExample -InputData $inputData -Through validation
        # Assert
        $global:journeyState.Forbidden.Count | Should -Be 0
        $global:journeyState.Writes | Should -Contain 'Set-AcceptedDomain'
        $global:journeyState.Writes | Should -Contain 'New-Mailbox'
        $global:journeyState.Writes | Should -Contain 'New-DistributionGroup'
        $global:journeyState.Writes | Should -Contain 'Add-DistributionGroupMember'
        $global:adapterCalls.Command | Should -Contain 'Set-TransportConfig'
        $global:adapterCalls.Command | Should -Contain 'Set-OrganizationConfig'
        $global:adapterCalls.Command | Should -Contain 'Set-CASMailbox'
        $global:adapterCalls.Command | Should -Contain 'Set-EOPProtectionPolicyRule'
        $global:adapterState.TransportConfig[0].SmtpClientAuthenticationDisabled | Should -BeTrue
        $global:adapterState.OrganizationConfig[0].EwsEnabled | Should -BeFalse
        $global:adapterState.CASMailbox[0].PopEnabled | Should -BeFalse
        $global:journeyState.Members | Should -Be $inputData.PriorityMembers
        $global:journeyState.Calls.IndexOf('Connect-ExchangeOnline') | Should -BeLessThan $global:journeyState.Calls.IndexOf('Get-AcceptedDomain')
        $global:journeyState.Calls.IndexOf('Get-Mailbox') | Should -BeLessThan $global:journeyState.Calls.IndexOf('New-Mailbox')
        $global:journeyState.Calls.IndexOf('New-Mailbox') | Should -BeLessThan $global:journeyState.Calls.IndexOf('New-DistributionGroup')
        $global:journeyState.Calls.IndexOf('Add-DistributionGroupMember') | Should -BeLessThan $global:journeyState.Calls.IndexOf('PortalPresetInitialization')
        $preview = Get-Content (Join-Path $inputData.ArtifactRoot 'preview-CHG008.json') -Raw | ConvertFrom-Json
        @($preview.Operation).Count | Should -BeGreaterThan 7
        (Get-Content (Join-Path $inputData.ArtifactRoot 'postchange-CHG008.json') -Raw | ConvertFrom-Json).Status | Should -BeExactly Succeeded
        $frozen = Join-Path $inputData.ArtifactRoot 'evidence/frozen-exchange-evidence.json'
        (Get-FileHash $frozen).Hash | Should -BeExactly $global:journeyState.FrozenHash
        @($result | Where-Object { $_.PSObject.Properties['Status'] -and $_.Status -eq 'ExchangeJourneyValidated' }).Count | Should -Be 1
        $gate = $global:journeyState.Gate
        $gate.Admitted | Should -BeTrue
        $gate.ExternalReadiness.Status | Should -BeExactly Unverified
        $global:journeyState.Collections | Should -Be 1
    }
}