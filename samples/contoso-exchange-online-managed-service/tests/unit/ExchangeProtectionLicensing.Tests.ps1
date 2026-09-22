BeforeDiscovery {
    $handoffDefects = @('MissingHandoff','Unverified','StringVerification','MissingExpiry','InvalidExpiry','Expired','WrongTenant','WrongDomain','MissingOwner','MissingReference','MissingRecipients','MissingRecipient','DuplicateRecipient','WrongRecipient','MissingTenantDefender','MissingRecipientDefender','MissingRecipientExchange','SuiteOnlyTenant','SuiteOnlyRecipient','UnknownTenantPlan','UnknownRecipientPlan')
    $handoffCases = @(foreach ($scope in @('Custom','BuiltIn')) {
        foreach ($defect in $handoffDefects) {
            if ($scope -eq 'Custom' -and $defect -eq 'Expired') { continue }
            @{ Scope = $scope; Defect = $defect }
        }
    })
    $admissionCases = @(foreach ($scope in @('Custom','BuiltIn')) {
        foreach ($defect in $handoffDefects) { @{ Scope = $scope; Defect = $defect } }
    })
    $unsupportedPlanCases = @(foreach ($authority in @('Tenant','Recipient')) {
        foreach ($plan in @('EXCHANGE_S_STANDARD','SYNTHETIC_UNKNOWN_PLAN','SPE_E5')) { @{ Authority = $authority; Plan = $plan } }
    })
    $consumerCases = @(foreach ($control in @('MDO-003','MDO-009','MDO-006')) {
        foreach ($defect in @('Expired','WrongTenant','WrongDomain','MissingRecipientExchange')) { @{ Control = $control; Defect = $defect } }
        if ($control -ne 'MDO-006') { @{ Control = $control; Defect = 'MissingRecipientDefender' } }
    })
}
BeforeAll {
    . (Join-Path $PSScriptRoot '../helpers/ExchangeProtectionFixture.ps1')
    $root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:licensingModule = Import-Module (Join-Path $root 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -PassThru
    function New-EopProtectionFixture {
        $fixture = New-ProtectionFixture
        $fixture.Context.Entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE')
        foreach ($row in $fixture.Context.Entitlement.recipients) { $row.servicePlans = @('EXCHANGE_S_ENTERPRISE') }
        foreach ($row in $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix) { $row.defender = $false }
        $fixture
    }
    function New-LicensingScopeFixture {
        param([string]$Scope = 'Custom')
        $fixture = New-ProtectionFixture
        $address = if ($Scope -eq 'BuiltIn') { 'default@contoso.example' } else { 'custom@contoso.example' }
        $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix = @($fixture.Context.Configuration.controls['MDO-001'].recipientMatrix | Where-Object address -eq $address)
        $fixture.Raw['Get-Recipient'].Items = @($fixture.Raw['Get-Recipient'].Items | Where-Object PrimarySmtpAddress -eq $address)
        $fixture.Context.Entitlement.recipients = @($fixture.Context.Entitlement.recipients | Where-Object address -eq $address)
        $fixture.Context.Parameters.domainInventory.source.suppliedAtUtc = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o')
        $fixture.Context.Parameters.domainInventory.domains[0].senderSource.suppliedAtUtc = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o')
        $fixture.Context.Configuration = & $script:licensingModule {
            param($configuration, $parameters)
            Convert-BaselinePlaceholderNode $configuration $parameters
        } $fixture.Context.Configuration $fixture.Context.Parameters
        $fixture
    }
    function Write-LicensingFixtureInputs {
        param($Fixture)
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $directory
        $configurationPath = Join-Path $directory 'configuration.json'
        $parameterPath = Join-Path $directory 'parameters.json'
        $Fixture.Context.Configuration | ConvertTo-Json -Depth 60 | Set-Content $configurationPath
        $Fixture.Context.Parameters | ConvertTo-Json -Depth 60 | Set-Content $parameterPath
        @{ ConfigurationPath = $configurationPath; ParameterPath = $parameterPath; ForActionPlanning = $true }
    }
    function New-LicensingIndependentState {
        param($Fixture)
        $state = @{ Recipients = $Fixture.Raw['Get-Recipient'].Items; Presets = @{ EOP = @(); ATP = @() }; Families = @{}; Groups = @{}; BuiltIn = $Fixture.Raw['Get-ATPBuiltInProtectionRule'].Items[0] }
        foreach ($family in @('MalwareFilter','HostedContentFilter','HostedOutboundSpamFilter','AntiPhish','SafeLinks','SafeAttachment')) {
            $state.Families[$family] = @{ Policies = $Fixture.Raw["Get-${family}Policy"].Items; Rules = $Fixture.Raw["Get-${family}Rule"].Items }
        }
        $state
    }
    function Invoke-LicensingCollector {
        param($Fixture)
        & $script:licensingModule {
            param($context, $rawFixture)
            foreach ($command in $rawFixture.Keys) {
                $body = @'
                [CmdletBinding()]
                param($Identity, $ResultSize)
                $response = $rawFixture[$MyInvocation.MyCommand.Name]
                if ($response['Error']) { throw $response['Error'] }
                if ($response['Warning']) { Write-Warning $response['Warning'] }
                $items = $response['Items']
                if ($response['ByIdentity'] -and $Identity) { $items = $response['ByIdentity'][$Identity] }
                elseif ($Identity -and $MyInvocation.MyCommand.Name -ne 'Get-DistributionGroupMember') {
                    $items = @($items | Where-Object { $_['Identity'] -eq $Identity -or $_['Name'] -eq $Identity -or $_['PrimarySmtpAddress'] -eq $Identity })
                }
                foreach ($item in $items) { [pscustomobject]$item }
'@
                Set-Item "Function:$command" ([scriptblock]::Create($body))
            }
            $observations = [Collections.Generic.List[object]]::new()
            Get-StandardPresetEvidence -EopRuleCollection { throw 'UnexpectedLegacyCollector' } -AtpRuleCollection { throw 'UnexpectedLegacyCollector' } -ExchangeContext $context -Observation $observations
        } $Fixture.Context $Fixture.Raw
    }
    function Set-LicensingHandoffDefect {
        param($Fixture, [string]$Defect)
        $handoff = $Fixture.Context.Entitlement
        switch ($Defect) {
            MissingHandoff { $Fixture.Context.Entitlement = $null; $Fixture.Context.Parameters.Remove('entitlement') }
            Unverified { $handoff.verified = $false }
            StringVerification { $handoff.verified = 'true' }
            MissingExpiry { $handoff.Remove('expiresOn') }
            InvalidExpiry { $handoff.expiresOn = 'not-a-date' }
            Expired { $handoff.expiresOn = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o') }
            WrongTenant { $handoff.tenantId = '11111111-1111-1111-1111-111111111111' }
            WrongDomain { $handoff.recipientDomains = @('different.example') }
            MissingOwner { $handoff.owner = '' }
            MissingReference { $handoff.reference = '' }
            MissingRecipients { $handoff.Remove('recipients') }
            MissingRecipient { $handoff.recipients = @() }
            DuplicateRecipient { $handoff.recipients += $handoff.recipients[0].Clone() }
            WrongRecipient { $handoff.recipients[0].address = 'someone-else@contoso.example' }
            MissingTenantDefender { $handoff.servicePlans = @('EXCHANGE_S_ENTERPRISE') }
            MissingRecipientDefender { $handoff.recipients[0].servicePlans = @('EXCHANGE_S_ENTERPRISE') }
            MissingRecipientExchange { $handoff.recipients[0].servicePlans = @('ATP_ENTERPRISE') }
            SuiteOnlyTenant { $handoff.servicePlans = @('SPE_E5'); $Fixture.Context.Parameters.messagingTier = 'MDO_P2' }
            SuiteOnlyRecipient { $handoff.recipients[0].servicePlans = @('SPE_E5') }
            UnknownTenantPlan { $handoff.servicePlans = @('SYNTHETIC_UNKNOWN_PLAN') }
            UnknownRecipientPlan { $handoff.recipients[0].servicePlans = @('SYNTHETIC_UNKNOWN_PLAN') }
            default { throw "Unknown test defect: $Defect" }
        }
    }
    $script:licensingForbiddenCommands = @('Connect-MgGraph','Invoke-MgGraphRequest','Get-MgSubscribedSku','Get-MgUserLicenseDetail','Set-MgUserLicense','Connect-ExchangeOnline')
    & $script:licensingModule {
        param($commands)
        foreach ($command in $commands) {
            Set-Item "Function:script:$command" { throw 'OfflineLicensingBoundary: external calls are forbidden.' }
        }
    } $script:licensingForbiddenCommands
}
Describe 'EXR-010 capability-specific Exchange entitlement' {
    BeforeEach {
        foreach ($command in $script:licensingForbiddenCommands) {
            Mock -CommandName $command -ModuleName ExchangeOnlineBaseline.Common { throw 'OfflineLicensingBoundary: external calls are forbidden.' }
        }
    }
    AfterEach {
        foreach ($command in $script:licensingForbiddenCommands) {
            Should -Invoke -CommandName $command -ModuleName ExchangeOnlineBaseline.Common -Times 0 -Exactly
        }
    }
    It 'rejects an expired custom-policy entitlement handoff at public collection and evaluation' {
        # Arrange
        $fixture = New-ProtectionFixture
        $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix = @($fixture.Context.Configuration.controls['MDO-001'].recipientMatrix | Where-Object address -eq 'custom@contoso.example')
        $fixture.Raw['Get-Recipient'].Items = @($fixture.Raw['Get-Recipient'].Items | Where-Object PrimarySmtpAddress -eq 'custom@contoso.example')
        $fixture.Context.Entitlement.expiresOn = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o')

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-001

        # Assert
        $result.Result.Status | Should -BeExactly NotEntitled -Because $result.Result.Reason
        $result.Result.Reason | Should -Match 'Entitlement.*(Expired|Stale)|Expired.*Entitlement|EntitlementUnverified'
        $result.Evidence.Source | Should -BeExactly SuppliedExternalEntitlement
        $result.Evidence.FailureReason | Should -Match 'Entitlement'
    }
    It 'refuses <Scope> handoff defect <Defect> with a visible capability decision' -ForEach $handoffCases {
        # Arrange
        $fixture = New-LicensingScopeFixture $Scope
        Set-LicensingHandoffDefect $fixture $Defect

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-001

        # Assert
        $result.Result.Status | Should -BeExactly NotEntitled -Because $result.Result.Reason
        $result.Result.Reason | Should -Match 'NotEntitled|EntitlementUnverified|Entitlement.*(Missing|Expired|Stale|Mismatch|Unsupported)'
        $result.Evidence.Source | Should -BeExactly SuppliedExternalEntitlement
        $result.Evidence.Collected | Should -BeFalse
        $result.Evidence.FailureReason | Should -Match 'Entitl'
        @($result.Evidence.Observation | Where-Object Command -Match 'Graph|Mg').Count | Should -Be 0
    }
    It 'refuses action admission for <Scope> with <Defect>' -ForEach $admissionCases {
        # Arrange
        $fixture = New-LicensingScopeFixture $Scope
        Set-LicensingHandoffDefect $fixture $Defect
        $inputs = Write-LicensingFixtureInputs $fixture
        $caught = $null

        # Act
        try { $null = Get-BaselineExchangeContext @inputs } catch { $caught = $_ }

        # Assert
        $caught | Should -Not -BeNullOrEmpty -Because 'invalid evidence must not admit actionable Exchange configuration'
        $caught.Exception.Message | Should -Match 'NotEntitled|EntitlementUnverified|Entitlement.*(Missing|Expired|Stale|Mismatch|Unsupported)'
        $caught.Exception.Message | Should -Not -Match 'ParameterBinding|ExchangeSchemaInvalid|DomainInventory'
    }
    It 'refuses unsupported EOP-only <Authority> plan <Plan> explicitly' -ForEach $unsupportedPlanCases {
        # Arrange
        $fixture = New-EopProtectionFixture
        if ($Authority -eq 'Tenant') { $fixture.Context.Entitlement.servicePlans = @($Plan) }
        else { foreach ($recipient in $fixture.Context.Entitlement.recipients) { $recipient.servicePlans = @($Plan) } }

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-001

        # Assert
        $result.Result.Status | Should -BeExactly NotEntitled -Because $result.Result.Reason
        $result.Result.Reason | Should -Match 'NotEntitled|Unsupported.*Plan|Entitlement'
        $result.Evidence.FailureReason | Should -Match 'NotEntitled|Unsupported.*Plan|Entitlement'
    }
    It 'does not hide unlicensed <Scope> capability use behind defender false' -TestCases @(
        @{ Scope = 'Custom' }
        @{ Scope = 'BuiltIn' }
    ) {
        param($Scope)
        # Arrange
        $fixture = New-LicensingScopeFixture $Scope
        $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix[0].defender = $false
        $fixture.Context.Entitlement.recipients[0].servicePlans = @('EXCHANGE_S_ENTERPRISE')

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-001

        # Assert
        $result.Result.Status | Should -BeExactly NotEntitled -Because $result.Result.Reason
        $result.Result.Reason | Should -Match 'NotEntitled'
        $result.Evidence.FailureReason | Should -Match 'NotEntitled'
    }
    It 'rechecks <Scope> independent evidence against a now <Defect> handoff at the evaluator' -TestCases @(
        @{ Scope = 'Custom'; Defect = 'Expired' }
        @{ Scope = 'Custom'; Defect = 'WrongTenant' }
        @{ Scope = 'Custom'; Defect = 'MissingRecipientDefender' }
        @{ Scope = 'BuiltIn'; Defect = 'Expired' }
        @{ Scope = 'BuiltIn'; Defect = 'WrongTenant' }
        @{ Scope = 'BuiltIn'; Defect = 'MissingRecipientDefender' }
    ) {
        param($Scope, $Defect)
        # Arrange
        $fixture = New-LicensingScopeFixture $Scope
        $state = New-LicensingIndependentState $fixture
        $evidence = New-BaselineEvidence -ControlId MDO-001 -Source ExchangeOnline -Command ExchangeEmailProtectionMatrix -Value $state
        Set-LicensingHandoffDefect $fixture $Defect

        # Act
        $result = Test-StandardPresetControl -Evidence $evidence -DesiredState $fixture.Context.Configuration.controls['MDO-001'] -GroupResolver { throw 'UnexpectedGroupLookup' } -ExchangeContext $fixture.Context

        # Assert
        $result.Status | Should -BeExactly NotEntitled -Because $result.Reason
        $result.Reason | Should -Match 'NotEntitled|EntitlementUnverified|Entitlement.*(Expired|Stale|Mismatch)'
    }
    It 'never treats fresh licensing as complete raw evidence after <Defect>' -TestCases @(
        @{ Defect = 'Warning'; Reason = 'ExchangeRawWarning' }
        @{ Defect = 'Error'; Reason = 'SyntheticRecipientReadFailed' }
        @{ Defect = 'Paged'; Reason = 'ExchangeRawPageEnvelope' }
        @{ Defect = 'MissingAddress'; Reason = 'ExchangeRawPropertyMissing' }
    ) {
        param($Defect, $Reason)
        # Arrange
        $fixture = New-LicensingScopeFixture
        switch ($Defect) {
            Warning { $fixture.Raw['Get-Recipient'].Warning = 'Synthetic recipient result truncated' }
            Error { $fixture.Raw['Get-Recipient'].Error = 'SyntheticRecipientReadFailed' }
            Paged { $fixture.Raw['Get-Recipient'].Items[0].ContinuationToken = 'synthetic-next-page' }
            MissingAddress { $fixture.Raw['Get-Recipient'].Items[0].Remove('PrimarySmtpAddress') }
        }

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-001

        # Assert
        $result.Result.Status | Should -BeExactly Error
        $result.Evidence.Collected | Should -BeFalse
        $result.Evidence.FailureReason | Should -Match $Reason
        @($result.Evidence.Observation | Where-Object { $_.Command -eq 'Get-Recipient' -and -not $_.Complete }).Count | Should -Be 1
    }
    It 'refuses a fresh handoff whose actual recipient inventory has a different scope' {
        # Arrange
        $fixture = New-LicensingScopeFixture
        $fixture.Raw['Get-Recipient'].Items[0].PrimarySmtpAddress = 'unapproved@contoso.example'
        $fixture.Raw['Get-Recipient'].Items[0].Identity = 'unapproved@contoso.example'

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-001

        # Assert
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match 'EmailProtectionRecipientInventory'
        @($result.Evidence.Value.Matrix).Count | Should -Be 0
    }
    It 'refuses <Scope> collector admission with <Defect>' -TestCases @(
        @{ Scope = 'Custom'; Defect = 'Expired' }
        @{ Scope = 'Custom'; Defect = 'WrongTenant' }
        @{ Scope = 'Custom'; Defect = 'MissingRecipientDefender' }
        @{ Scope = 'BuiltIn'; Defect = 'Expired' }
        @{ Scope = 'BuiltIn'; Defect = 'WrongTenant' }
        @{ Scope = 'BuiltIn'; Defect = 'MissingRecipientDefender' }
    ) {
        param($Scope, $Defect)
        # Arrange
        $fixture = New-LicensingScopeFixture $Scope
        Set-LicensingHandoffDefect $fixture $Defect

        # Act
        $evidence = Invoke-LicensingCollector $fixture

        # Assert
        $evidence.Collected | Should -BeFalse -Because 'unbound entitlement cannot produce successful capability collection'
        $evidence.Source | Should -BeExactly SuppliedExternalEntitlement
        $evidence.FailureReason | Should -Match 'NotEntitled|EntitlementUnverified|Entitlement.*(Expired|Stale|Mismatch)'
    }
    It 'does not hide missing <Capability> entitlement behind declared suite <Suite>' -TestCases @(
        @{ Capability = 'PriorityAccountProtection'; Suite = 'MDO_P1' }
        @{ Capability = 'AutomatedInvestigation'; Suite = 'MDO_P1' }
        @{ Capability = 'PriorityAccountProtection'; Suite = 'MDO_P2' }
        @{ Capability = 'AutomatedInvestigation'; Suite = 'MDO_P2' }
    ) {
        param($Capability, $Suite)
        # Arrange
        $fixture = New-LicensingScopeFixture
        $fixture.Context.Parameters.messagingTier = $Suite
        $inputs = Write-LicensingFixtureInputs $fixture

        # Act
        $context = Get-BaselineExchangeContext @inputs

        # Assert
        $decision = @($context.DeploymentEntitlement.Capability | Where-Object Name -eq $Capability)
        $decision.Count | Should -Be 1 -Because 'absence of a decision is not an explicit P2 refusal'
        $decision[0].Entitled | Should -BeFalse
        $decision[0].Reason | Should -Match 'NotEntitled|not entitled|P2.*(unconfirmed|required|missing)'
        $context.DeploymentEntitlement.NotEntitled | Should -Contain $Capability
    }
    It 'does not require P2 to detect P1 impersonation drift' {
        # Arrange
        $fixture = New-LicensingScopeFixture
        $fixture.Raw['Get-AntiPhishRule'].Items[0].SentTo = @()
        $fixture.Raw['Get-AntiPhishRule'].Items[0].RecipientDomainIs = @('contoso.example')
        foreach ($policy in $fixture.Raw['Get-AntiPhishPolicy'].Items) { $policy.EnableTargetedUserProtection = $false }

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-009

        # Assert
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Not -Match 'NotEntitled|THREAT_INTELLIGENCE'
        $result.Result.Reason | Should -Match '^ExchangeAntiPhishCoverageDrift:'
    }
    It 'does not require P2 to detect P1 <Family> email setting drift' -TestCases @(
        @{ Family = 'SafeLinks'; Field = 'EnableSafeLinksForEmail' }
        @{ Family = 'SafeAttachment'; Field = 'Enable' }
    ) {
        param($Family, $Field)
        # Arrange
        $fixture = New-LicensingScopeFixture
        $policy = $fixture.Raw["Get-${Family}Policy"].Items | Where-Object Name -eq 'Custom email'
        $policy[$Field] = $false

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-001

        # Assert
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match "EmailProtectionSettingDrift.*$Family/$Field"
        $result.Result.Reason | Should -Not -Match 'NotEntitled|THREAT_INTELLIGENCE'
    }
    It 'does not suppress incomplete Exchange reporting evidence without AIR entitlement' {
        # Arrange
        $fixture = New-EopProtectionFixture
        $fixture.Context.Parameters.reportingEvidence.Remove('deliveries')

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-006

        # Assert
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match 'ReportingDeliveryIncomplete'
        $result.Result.Reason | Should -Not -Match 'NotEntitled|THREAT_INTELLIGENCE'
    }
    It 'does not publish an unbound licensing source or collapse impersonation reporting and tabletop into P2' {
        # Arrange
        $path = Join-Path $root 'config/exchange-recommendations.v1.json'

        # Act
        $catalog = Get-Content $path -Raw | ConvertFrom-Json -AsHashtable

        # Assert
        foreach ($control in @('MDO-001','MDO-003','MDO-006','MDO-009','OPS-002')) {
            $mapping = @($catalog.Mappings | Where-Object ControlId -eq $control)
            $mapping.Count | Should -Be 1
            $source = @($catalog.Sources | Where-Object Id -eq $mapping[0].SourceId)
            $source.Count | Should -Be 1
            $source[0].Url | Should -Match '^https://learn\.microsoft\.com/'
            $source[0].Sections | Should -Contain $mapping[0].Section
            $source[0].ReviewedOn | Should -Match '^\d{4}-\d{2}-\d{2}$'
        }
        ($catalog.Mappings | Where-Object ControlId -eq MDO-009).License | Should -Match 'P1/P2'
        ($catalog.Mappings | Where-Object ControlId -eq MDO-006).License | Should -Match 'EOP.*automated investigation.*P2.*separately'
        ($catalog.Mappings | Where-Object ControlId -eq OPS-002).License | Should -Match 'no P2 requirement'
        $document = Get-Content (Join-Path $root 'docs/LICENSING-GATE.md') -Raw
        $document | Should -Match 'EXCHANGE_S_ENTERPRISE'
        $document | Should -Match 'does not yet model every Exchange plan'
        $document | Should -Match 'P2 priority-account capabilities, AIR'
        $document | Should -Match 'supplied licensing-owner handoff'
        $document | Should -Match 'not assign licenses, query Graph'
    }
    It 'refuses <Control> capability consumer with <Defect>' -ForEach $consumerCases {
        # Arrange
        $fixture = New-LicensingScopeFixture
        $fixture.Raw['Get-AntiPhishRule'].Items[0].SentTo = @()
        $fixture.Raw['Get-AntiPhishRule'].Items[0].RecipientDomainIs = @('contoso.example')
        $fixture.Context.Entitlement.recipients = @($fixture.Raw['Get-Recipient'].Items | ForEach-Object { @{ address = $_.PrimarySmtpAddress; servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE') } })
        $fixture.Context.Entitlement.recipients += @{ address = 'secops@contoso.example'; servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE') }
        Set-LicensingHandoffDefect $fixture $Defect
        if ($Defect -eq 'MissingRecipientExchange') {
            foreach ($recipient in $fixture.Context.Entitlement.recipients) { $recipient.servicePlans = @('ATP_ENTERPRISE') }
        }
        if ($Defect -eq 'MissingRecipientDefender') {
            foreach ($recipient in $fixture.Context.Entitlement.recipients) { $recipient.servicePlans = @('EXCHANGE_S_ENTERPRISE') }
        }

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq $Control

        # Assert
        $result.Result.Status | Should -BeExactly NotEntitled -Because $result.Result.Reason
        $result.Result.Reason | Should -Match 'NotEntitled|EntitlementUnverified|Entitlement.*(Expired|Stale|Mismatch)'
        $result.Evidence.Source | Should -BeExactly SuppliedExternalEntitlement
        $result.Evidence.FailureReason | Should -Match 'Entitl'
    }
    It 'does not skip drift in the EOP Standard matrix without Defender' {
        # Arrange
        $fixture = New-EopProtectionFixture
        $fixture.Raw['Get-MalwareFilterPolicy'].Items[0].ZapEnabled = $false

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-001

        # Assert
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match EmailProtectionSettingDrift
    }
    It 'does not skip disabled EOP Strict scope without Defender' {
        # Arrange
        $fixture = New-EopProtectionFixture
        $fixture.Raw['Get-EOPProtectionPolicyRule'].ByIdentity['Strict Preset Security Policy'][0].State = 'Disabled'

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-002

        # Assert
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match StrictPresetDrift
    }
    It 'does not make a tabletop cadence contingent on Defender Plan 2' {
        # Arrange
        $fixture = New-EopProtectionFixture

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq OPS-002

        # Assert
        $result.Result.Status | Should -BeExactly Error
        $result.Result.Reason | Should -Not -Match 'NotEntitled|THREAT_INTELLIGENCE'
    }
    It 'evaluates EOP settings while preserving unavailable Defender as NotEntitled for <Scope>' -TestCases @(
        @{ Scope = 'EOP' }
        @{ Scope = 'Custom' }
        @{ Scope = 'BuiltIn' }
    ) {
        param($Scope)
        # Arrange
        $fixture = if ($Scope -eq 'EOP') { New-EopProtectionFixture } else { New-LicensingScopeFixture $Scope }

        # Act
        $results = Invoke-ProtectionRawRegistry $fixture $script:licensingModule

        # Assert
        $matrix = $results | Where-Object ControlId -eq MDO-001
        if ($Scope -eq 'EOP') {
            foreach ($control in @('MDO-001','MDO-002')) { ($results | Where-Object ControlId -eq $control).Result.Status | Should -BeExactly Pass }
            foreach ($control in @('MDO-003','MDO-009')) { ($results | Where-Object ControlId -eq $control).Result.Status | Should -BeExactly NotEntitled }
            @($matrix.Evidence.Value.Matrix).Count | Should -Be 20
            @($matrix.Evidence.Observation.Command | Where-Object { $_ -match 'ATP|SafeLinks|SafeAttachment' }).Count | Should -Be 0
            ($results | Where-Object ControlId -eq MDO-006).Result.Status | Should -BeExactly Pass
        }
        else {
            $matrix.Result.Status | Should -BeExactly Pass -Because $matrix.Result.Reason
            $matrix.Evidence.Collected | Should -BeTrue
            @($matrix.Evidence.Value.Matrix).Count | Should -Be 6
            foreach ($family in @('SafeLinks','SafeAttachment')) {
                $row = @($matrix.Evidence.Value.Matrix | Where-Object Family -eq $family)
                $row.Count | Should -Be 1
                $row[0].Policy | Should -BeExactly $(if ($Scope -eq 'Custom') { 'Custom email' } else { 'Built-In Protection Policy' })
            }
            @($matrix.Evidence.Observation | Where-Object { -not $_.Complete }).Count | Should -Be 0
            $matrix.Evidence.Observation.Command | Should -Contain Get-Recipient
            $matrix.Evidence.Observation.Command | Should -Contain Get-SafeLinksPolicy
            $matrix.Evidence.Observation.Command | Should -Contain Get-SafeAttachmentPolicy
        }
    }
    It 'collects one independently observed licensed custom-policy capability fixture' {
        # Arrange
        $fixture = New-LicensingScopeFixture

        # Act
        $evidence = Invoke-LicensingCollector $fixture

        # Assert
        $evidence.Collected | Should -BeTrue
        $evidence.FailureReason | Should -BeNullOrEmpty
        $evidence.Value.Assessment.Status | Should -BeExactly Pass
        @($evidence.Value.Matrix).Count | Should -Be 6
        @($evidence.Value.Recipients).Count | Should -Be 1
        $evidence.Value.Recipients[0].PrimarySmtpAddress | Should -BeExactly 'custom@contoso.example'
    }
    It 'evaluates one complete independently supplied licensed custom-policy observation' {
        # Arrange
        $fixture = New-LicensingScopeFixture
        $state = New-LicensingIndependentState $fixture
        $evidence = New-BaselineEvidence -ControlId MDO-001 -Source ExchangeOnline -Command ExchangeEmailProtectionMatrix -Value $state

        # Act
        $result = Test-StandardPresetControl -Evidence $evidence -DesiredState $fixture.Context.Configuration.controls['MDO-001'] -GroupResolver { throw 'UnexpectedGroupLookup' } -ExchangeContext $fixture.Context

        # Assert
        $result.Status | Should -BeExactly Pass
        $result.Reason | Should -Match '^EmailProtectionVerified:'
        $result.Reason | Should -Match 'external readiness remains unverified'
    }
    It 'admits one current bound <Scope> handoff with explicit capability outcomes' -TestCases @(
        @{ Scope = 'EOP' }
        @{ Scope = 'Custom' }
        @{ Scope = 'BuiltIn' }
    ) {
        param($Scope)
        # Arrange
        $fixture = New-LicensingScopeFixture $(if ($Scope -eq 'BuiltIn') { 'BuiltIn' } else { 'Custom' })
        if ($Scope -eq 'EOP') {
            $fixture.Context.Entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE')
            $fixture.Context.Entitlement.recipients[0].servicePlans = @('EXCHANGE_S_ENTERPRISE')
            $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix[0].defender = $false
        }
        $inputs = Write-LicensingFixtureInputs $fixture

        # Act
        $context = Get-BaselineExchangeContext @inputs

        # Assert
        $context.DeploymentProfile | Should -BeExactly ExchangeOnly
        $context.Entitlement.verified | Should -BeTrue
        $context.Entitlement.tenantId | Should -BeExactly $fixture.Context.Parameters.MICROSOFT_ENTRA_TENANT_GUID
        $context.Entitlement.recipients[0].address | Should -BeExactly $fixture.Context.Entitlement.recipients[0].address
        $context.DeploymentEntitlement.Source | Should -BeExactly SuppliedExternalEntitlement
        $context.DeploymentEntitlement.AtpPresets | Should -Be ($Scope -ne 'EOP')
        foreach ($capability in @('PriorityAccountProtection','AutomatedInvestigation')) {
            $decision = @($context.DeploymentEntitlement.Capability | Where-Object Name -eq $capability)
            $decision.Count | Should -Be 1
            $decision[0].Entitled | Should -BeFalse
            $context.DeploymentEntitlement.NotEntitled | Should -Contain $capability
        }
    }
}
AfterAll {
    & $script:licensingModule {
        param($commands)
        foreach ($command in $commands) { Remove-Item "Function:script:$command" -ErrorAction SilentlyContinue }
    } $script:licensingForbiddenCommands
}