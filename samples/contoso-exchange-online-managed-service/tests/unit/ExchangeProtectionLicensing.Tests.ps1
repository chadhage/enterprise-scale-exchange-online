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
    $capabilityAttestationCases = @(foreach ($capability in @('PriorityAccountProtection','AutomatedInvestigation')) {
        foreach ($defect in @('MissingAttestations','NullAttestations','ScalarAttestations','ObjectAttestations','EmptyAttestations','NullRecord','StringRecord','MissingCapability','UnknownCapability','DuplicateCapability','MissingEntitled','StringEntitled','NumericEntitled','NullEntitled','NotEntitled','MissingScope','EmptyScope','NullScope','ScalarScope','DuplicateRecipient','UnknownRecipient','MalformedRecipient')) {
            @{ Capability = $capability; Defect = $defect }
        }
    })
    $compoundCapabilityCases = @(foreach ($scope in @('Custom','BuiltIn')) {
        foreach ($capability in @('PriorityAccountProtection','AutomatedInvestigation')) {
            foreach ($defect in @('Unverified','StringVerification','MissingExpiry','InvalidExpiry','Expired','WrongTenant','WrongDomain','MissingOwner','MissingReference','MissingRecipients','MissingRecipient','DuplicateRecipient','WrongRecipient','MissingRecipientExchange','MissingRecipientDefender')) {
                @{ Scope = $scope; Capability = $capability; Defect = $defect }
            }
        }
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
    function Get-LicensingHandoffReasonPattern {
        param([string]$Defect, $Fixture)
        if ($Defect -in @('MissingHandoff','Unverified','StringVerification','MissingExpiry','InvalidExpiry','Expired','WrongTenant','WrongDomain','MissingOwner','MissingReference')) {
            $legacy = '^ExchangeEntitlementUnverified:'
        }
        elseif ($Defect -in @('SuiteOnlyTenant','UnknownTenantPlan','MissingTenantExchange')) {
            $legacy = "^ExchangeNotEntitled: 'EXCHANGE_S_ENTERPRISE' is not confirmed for this recipient scope\."
        }
        else {
            $address = [regex]::Escape($Fixture.Context.Configuration.controls['MDO-001'].recipientMatrix[0].address)
            $legacy = "^EmailProtectionNotEntitled: '$address' requires explicitly supplied feature service plans\."
        }
        if ($Defect -in @('Expired','WrongTenant','WrongDomain','MissingRecipientExchange','MissingRecipientDefender')) {
            return '(?s)(?=' + $legacy + ')(?=.*' + (Get-LicensingCategoryPattern $Defect) + ')'
        }
        $legacy
    }
    function Get-LicensingCategoryPattern {
        param([string]$Defect)
        $category = switch ($Defect) {
            { $_ -in @('Expired','MissingExpiry','InvalidExpiry') } { '(?:Expir(?:ed|y|ation)|Stale)'; break }
            WrongTenant { '(?:Tenant(?:Binding)?(?:Mismatch|Missing|Unbound|Invalid)|(?:Mismatch|Missing|Unbound|Invalid)Tenant)'; break }
            { $_ -in @('WrongDomain','MissingRecipients','MissingRecipient','WrongRecipient','MissingScope','EmptyScope','NullScope','UnknownRecipient') } { '(?:Scope(?:Mismatch|Missing|Empty|Invalid|Unbound)|(?:Mismatch|Missing|Empty|Invalid|Unbound)Scope|Recipient(?:Missing|Mismatch|Unknown)|(?:Missing|Mismatch|Unknown)Recipient)'; break }
            MissingRecipientExchange { '(?:Recipient(?:Exchange|Exo)(?:Entitlement)?(?:Missing|Unconfirmed|NotEntitled)|(?:Exchange|Exo)Recipient(?:Entitlement)?(?:Missing|Unconfirmed|NotEntitled))'; break }
            MissingRecipientDefender { '(?:Recipient(?:Defender|Atp)(?:Entitlement)?(?:Missing|Unconfirmed|NotEntitled)|(?:Defender|Atp)Recipient(?:Entitlement)?(?:Missing|Unconfirmed|NotEntitled))'; break }
            MissingTenantExchange { '(?:Tenant(?:Exchange|Exo)(?:Entitlement)?(?:Missing|Unconfirmed|NotEntitled)|(?:Exchange|Exo)Tenant(?:Entitlement)?(?:Missing|Unconfirmed|NotEntitled))'; break }
            MissingTenantDefender { '(?:Tenant(?:Defender|Atp)(?:Entitlement)?(?:Missing|Unconfirmed|NotEntitled)|(?:Defender|Atp)Tenant(?:Entitlement)?(?:Missing|Unconfirmed|NotEntitled))'; break }
            { $_ -in @('MissingAttestations','NullAttestations','EmptyAttestations','NotEntitled') } { '(?:Capability(?:Entitlement)?(?:Unconfirmed|Missing|NotEntitled)|(?:Unconfirmed|Missing|NotEntitled)Capability)'; break }
            Unverified { '(?:Unverified|Verification(?:Missing|Invalid|Failed))'; break }
            default { '(?:Malformed|Invalid(?:Type|Record|Attestation|Verification|Owner|Reference)|(?:Type|Record|Attestation|Verification|Owner|Reference)(?:Invalid|Missing)|Duplicate(?:Recipient|Capability))' }
        }
        '(?im)^(?!ExchangeEntitlementUnverified:|ExchangeNotEntitled:|EmailProtectionNotEntitled:)(?:(?:Category|Code)\s*[:=]\s*)?[A-Za-z0-9]*' + $category + '[A-Za-z0-9]*(?=:|\r?$)'
    }
    function Get-LicensingCategoryText {
        param($Node)
        foreach ($item in @($Node)) {
            if ($item -is [string]) { $item }
            elseif ($null -ne $item) {
                foreach ($name in @('Category','Code','Reason','Violation')) {
                    if ($item -is [Collections.IDictionary]) {
                        if ($item.Contains($name)) { Get-LicensingCategoryText $item[$name] }
                    }
                    elseif ($item.PSObject.Properties[$name]) { Get-LicensingCategoryText $item.PSObject.Properties[$name].Value }
                }
            }
        }
    }
    function Get-LicensingDecisionReason {
        param($Context, [string]$Capability)
        $memberValue = {
            param($Node, [string]$Name)
            if ($null -eq $Node) { return }
            if ($Node -is [Collections.IDictionary]) {
                if ($Node.Contains($Name)) { $Node[$Name] }
            }
            elseif ($Node.PSObject.Properties[$Name]) { $Node.PSObject.Properties[$Name].Value }
        }
        $projection = $Context.DeploymentEntitlement
        $decisions = @($projection.Capability | Where-Object { $_ -and $_.Name -ceq $Capability })
        if ($decisions.Count -ne 1) { return }
        foreach ($violation in @(& $memberValue $projection Violation)) {
            if ((& $memberValue $violation Capability) -ceq $Capability) {
                Get-LicensingCategoryText $violation
            }
        }
        foreach ($decision in $decisions) {
            Get-LicensingCategoryText (& $memberValue $decision Reason)
            foreach ($violation in @(& $memberValue $decision Violation)) {
                Get-LicensingCategoryText $violation
            }
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
        $result.Result.Reason | Should -Match (Get-LicensingCategoryPattern Expired)
        $result.Evidence.Source | Should -BeExactly SuppliedExternalEntitlement
        $result.Evidence.FailureReason | Should -Match (Get-LicensingCategoryPattern Expired)
    }
    It 'refuses <Scope> handoff defect <Defect> with a visible capability decision' -ForEach $handoffCases {
        # Arrange
        $fixture = New-LicensingScopeFixture $Scope
        Set-LicensingHandoffDefect $fixture $Defect
        $reasonPattern = Get-LicensingHandoffReasonPattern $Defect $fixture

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-001

        # Assert
        $result.Result.Status | Should -BeExactly NotEntitled -Because $result.Result.Reason
        $result.Result.Reason | Should -Match $reasonPattern
        $result.Evidence.Source | Should -BeExactly SuppliedExternalEntitlement
        $result.Evidence.Collected | Should -BeFalse
        $result.Evidence.FailureReason | Should -Match $reasonPattern
        @($result.Evidence.Observation | Where-Object Command -Match 'Graph|Mg').Count | Should -Be 0
    }
    It 'refuses action admission for <Scope> with <Defect>' -ForEach $admissionCases {
        # Arrange
        $fixture = New-LicensingScopeFixture $Scope
        Set-LicensingHandoffDefect $fixture $Defect
        $inputs = Write-LicensingFixtureInputs $fixture
        $reasonPattern = Get-LicensingHandoffReasonPattern $Defect $fixture
        $caught = $null

        # Act
        try { $null = Get-BaselineExchangeContext @inputs } catch { $caught = $_ }

        # Assert
        $caught | Should -Not -BeNullOrEmpty -Because 'invalid evidence must not admit actionable Exchange configuration'
        $caught.Exception.Message | Should -Match $reasonPattern
        $caught.Exception.Message | Should -Not -Match 'ParameterBinding|ExchangeSchemaInvalid|DomainInventory'
    }
    It 'refuses unsupported EOP-only <Authority> plan <Plan> explicitly' -ForEach $unsupportedPlanCases {
        # Arrange
        $fixture = New-EopProtectionFixture
        if ($Authority -eq 'Tenant') { $fixture.Context.Entitlement.servicePlans = @($Plan) }
        else { foreach ($recipient in $fixture.Context.Entitlement.recipients) { $recipient.servicePlans = @($Plan) } }
        $reasonPattern = if ($Authority -eq 'Tenant') {
            "^ExchangeNotEntitled: 'EXCHANGE_S_ENTERPRISE' is not confirmed for this recipient scope\."
        } else {
            "^EmailProtectionNotEntitled: 'user@contoso\.example' requires explicitly supplied feature service plans\."
        }

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-001

        # Assert
        $result.Result.Status | Should -BeExactly NotEntitled -Because $result.Result.Reason
        $result.Result.Reason | Should -Match $reasonPattern
        $result.Evidence.FailureReason | Should -Match $reasonPattern
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
        $recipientPattern = [regex]::Escape($fixture.Context.Configuration.controls['MDO-001'].recipientMatrix[0].address)

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-001

        # Assert
        $result.Result.Status | Should -BeExactly NotEntitled -Because $result.Result.Reason
        $result.Result.Reason | Should -Match "^EmailProtectionNotEntitled: '$recipientPattern'"
        $result.Evidence.FailureReason | Should -Match "^EmailProtectionNotEntitled: '$recipientPattern'"
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
        $reasonPattern = Get-LicensingHandoffReasonPattern $Defect $fixture

        # Act
        $result = Test-StandardPresetControl -Evidence $evidence -DesiredState $fixture.Context.Configuration.controls['MDO-001'] -GroupResolver { throw 'UnexpectedGroupLookup' } -ExchangeContext $fixture.Context

        # Assert
        $result.Status | Should -BeExactly NotEntitled -Because $result.Reason
        $result.Reason | Should -Match $reasonPattern
    }
    It 'g18 refuses tenant Exchange plan absence even when ATP is present at action admission' {
        # Arrange
        $fixture = New-LicensingScopeFixture
        $fixture.Context.Entitlement.servicePlans = @('ATP_ENTERPRISE')
        $inputs = Write-LicensingFixtureInputs $fixture
        $caught = $null

        # Act
        try { $null = Get-BaselineExchangeContext @inputs } catch { $caught = $_ }

        # Assert
        $caught | Should -Not -BeNullOrEmpty -Because 'ATP does not supply the tenant Exchange prerequisite'
        $caught.Exception.Message | Should -Match "^ExchangeNotEntitled: 'EXCHANGE_S_ENTERPRISE' is not confirmed for this recipient scope\."
    }
    It 'g18 refuses independent evaluation with <Defect> parent handoff' -TestCases @(
        @{ Defect = 'MissingHandoff' }
        @{ Defect = 'Unverified' }
    ) {
        param($Defect)
        # Arrange
        $fixture = New-LicensingScopeFixture
        $state = New-LicensingIndependentState $fixture
        $evidence = New-BaselineEvidence -ControlId MDO-001 -Source ExchangeOnline -Command ExchangeEmailProtectionMatrix -Value $state
        Set-LicensingHandoffDefect $fixture $Defect

        # Act
        $result = Test-StandardPresetControl -Evidence $evidence -DesiredState $fixture.Context.Configuration.controls['MDO-001'] -GroupResolver { throw 'UnexpectedGroupLookup' } -ExchangeContext $fixture.Context

        # Assert
        $result.Status | Should -BeExactly NotEntitled -Because 'previously collected policy state cannot replace a verified licensing handoff'
        $result.Reason | Should -Match '^ExchangeEntitlementUnverified:'
    }
    It 'g18 detects EOP-only spoof intelligence drift without Defender entitlement' {
        # Arrange
        $fixture = New-EopProtectionFixture
        foreach ($policy in $fixture.Raw['Get-AntiPhishPolicy'].Items) { $policy.EnableSpoofIntelligence = $false }

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-001

        # Assert
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match 'EmailProtectionSettingDrift.*AntiPhish/EnableSpoofIntelligence'
        @($result.Evidence.Observation.Command | Where-Object { $_ -match 'ATP|SafeLinks|SafeAttachment' }).Count | Should -Be 0
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
        $reasonPattern = Get-LicensingHandoffReasonPattern $Defect $fixture

        # Act
        $evidence = Invoke-LicensingCollector $fixture

        # Assert
        $evidence.Collected | Should -BeFalse -Because 'unbound entitlement cannot produce successful capability collection'
        $evidence.Source | Should -BeExactly SuppliedExternalEntitlement
        $evidence.FailureReason | Should -Match $reasonPattern
    }
    It 'g18 refuses <Capability> capability decision with <Defect> attestation' -ForEach $capabilityAttestationCases {
        # Arrange
        $fixture = New-LicensingScopeFixture
        $recipient = $fixture.Context.Entitlement.recipients[0].address
        $record = @{ capability = $Capability; entitled = $true; recipients = @($recipient) }
        $fixture.Context.Entitlement.capabilityAttestations = @($record)
        switch ($Defect) {
            MissingAttestations { $fixture.Context.Entitlement.Remove('capabilityAttestations') }
            NullAttestations { $fixture.Context.Entitlement.capabilityAttestations = $null }
            ScalarAttestations { $fixture.Context.Entitlement.capabilityAttestations = 'invalid' }
            ObjectAttestations { $fixture.Context.Entitlement.capabilityAttestations = $record }
            EmptyAttestations { $fixture.Context.Entitlement.capabilityAttestations = @() }
            NullRecord { $fixture.Context.Entitlement.capabilityAttestations = @($null) }
            StringRecord { $fixture.Context.Entitlement.capabilityAttestations = @('invalid') }
            MissingCapability { $record.Remove('capability') }
            UnknownCapability { $record.capability = 'UnknownCapability' }
            DuplicateCapability { $fixture.Context.Entitlement.capabilityAttestations += $record.Clone() }
            MissingEntitled { $record.Remove('entitled') }
            StringEntitled { $record.entitled = 'true' }
            NumericEntitled { $record.entitled = 1 }
            NullEntitled { $record.entitled = $null }
            NotEntitled { $record.entitled = $false }
            MissingScope { $record.Remove('recipients') }
            EmptyScope { $record.recipients = @() }
            NullScope { $record.recipients = $null }
            ScalarScope { $record.recipients = $recipient }
            DuplicateRecipient { $record.recipients = @($recipient, $recipient) }
            UnknownRecipient { $record.recipients = @('unknown@contoso.example') }
            MalformedRecipient { $record.recipients = @('not-an-address') }
        }
        $inputs = Write-LicensingFixtureInputs $fixture

        # Act
        $context = Get-BaselineExchangeContext @inputs

        # Assert
        $decision = @($context.DeploymentEntitlement.Capability | Where-Object Name -CEQ $Capability)
        $decision.Count | Should -Be 1 -Because "$Defect must produce a visible decision for $Capability, not omit it"
        $decision[0].Entitled | Should -BeOfType ([bool])
        $decision[0].Entitled | Should -BeFalse
        $reason = (Get-LicensingDecisionReason $context $Capability) -join "`n"
        $reason | Should -Not -BeNullOrEmpty -Because 'the refusal must remain visible through either ratified reason channel'
        $reason | Should -Match (Get-LicensingCategoryPattern $Defect) -Because "$Defect requires its specific category through Violation or capability Reason"
        $context.DeploymentEntitlement.NotEntitled | Should -Contain $Capability
    }
    It 'g20 refuses affirmative <Capability> for <Scope> with <Defect> prerequisite' -ForEach $compoundCapabilityCases {
        # Arrange
        $fixture = New-LicensingScopeFixture $Scope
        $recipient = $fixture.Context.Entitlement.recipients[0].address
        $fixture.Context.Entitlement.capabilityAttestations = @(
            @{ capability = $Capability; entitled = $true; recipients = @($recipient) }
        )
        Set-LicensingHandoffDefect $fixture $Defect
        $inputs = Write-LicensingFixtureInputs $fixture
        $context = $null
        $caught = $null

        # Act
        try { $context = Get-BaselineExchangeContext @inputs } catch { $caught = $_ }

        # Assert
        $caught | Should -Not -BeNullOrEmpty -Because 'mandatory parent and recipient P1 prerequisites must refuse action admission even with affirmative P2 evidence'
        $context | Should -BeNullOrEmpty
        $caught.Exception.Message | Should -Match (Get-LicensingCategoryPattern $Defect) -Because 'refusing the entire context must identify the actual invalid prerequisite'
        $caught.Exception.Message | Should -Match (Get-LicensingHandoffReasonPattern $Defect $fixture)
        $caught.Exception.Message | Should -Not -Match 'ParameterBinding|ExchangeSchemaInvalid|DomainInventory|OfflineLicensingBoundary'
    }
    It 'g22 refuses affirmative <Capability> without <Prerequisite> tenant entitlement' -TestCases @(
        @{ Capability = 'PriorityAccountProtection'; Prerequisite = 'Exchange'; Defect = 'MissingTenantExchange' }
        @{ Capability = 'AutomatedInvestigation'; Prerequisite = 'Exchange'; Defect = 'MissingTenantExchange' }
        @{ Capability = 'PriorityAccountProtection'; Prerequisite = 'Defender'; Defect = 'MissingTenantDefender' }
        @{ Capability = 'AutomatedInvestigation'; Prerequisite = 'Defender'; Defect = 'MissingTenantDefender' }
    ) {
        param($Capability, $Prerequisite, $Defect)
        # Arrange
        $fixture = New-LicensingScopeFixture
        $fixture.Context.Entitlement.servicePlans = if ($Prerequisite -eq 'Exchange') { @('ATP_ENTERPRISE') } else { @('EXCHANGE_S_ENTERPRISE') }
        $fixture.Context.Entitlement.capabilityAttestations = @(
            @{ capability = $Capability; entitled = $true; recipients = @('custom@contoso.example') }
        )
        $inputs = Write-LicensingFixtureInputs $fixture
        $context = $null
        $caught = $null

        # Act
        try { $context = Get-BaselineExchangeContext @inputs } catch { $caught = $_ }

        # Assert
        $caught | Should -Not -BeNullOrEmpty -Because 'P2 attestation cannot replace tenant Exchange or Defender entitlement'
        $context | Should -BeNullOrEmpty
        $caught.Exception.Message | Should -Match (Get-LicensingHandoffReasonPattern $Defect $fixture)
        $caught.Exception.Message | Should -Match (Get-LicensingCategoryPattern $Defect)
        $caught.Exception.Message | Should -Not -Match 'ParameterBinding|ExchangeSchemaInvalid|DomainInventory|OfflineLicensingBoundary'
    }
    It 'g22 does not extend exact <Capability> attestation to another licensed recipient' -TestCases @(
        @{ Capability = 'PriorityAccountProtection' }
        @{ Capability = 'AutomatedInvestigation' }
    ) {
        param($Capability)
        # Arrange
        $fixture = New-LicensingScopeFixture
        $fixture.Context.Entitlement.recipients += @{ address = 'attested@contoso.example'; servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE') }
        $fixture.Context.Entitlement.capabilityAttestations = @(
            @{ capability = $Capability; entitled = $true; recipients = @('attested@contoso.example') }
        )
        $inputs = Write-LicensingFixtureInputs $fixture

        # Act
        $context = Get-BaselineExchangeContext @inputs

        # Assert
        $decision = @($context.DeploymentEntitlement.Capability | Where-Object Name -CEQ $Capability)
        $decision.Count | Should -Be 1 -Because 'the requested custom recipient is licensed but outside the exact optional capability attestation'
        $decision[0].Entitled | Should -BeOfType ([bool])
        $decision[0].Entitled | Should -BeFalse
        $context.DeploymentEntitlement.NotEntitled | Should -Contain $Capability
        (Get-LicensingDecisionReason $context $Capability) -join "`n" | Should -Match (Get-LicensingCategoryPattern WrongDomain)
        $context.DeploymentEntitlement.AtpPresets | Should -BeTrue -Because 'unconfirmed optional P2 must not block the licensed P1 planner'
    }
    It 'g22 does not borrow <Source> categories for <Capability>' -TestCases @(
        @{ Capability = 'PriorityAccountProtection'; Peer = 'AutomatedInvestigation'; Source = 'UnboundGlobal' }
        @{ Capability = 'AutomatedInvestigation'; Peer = 'PriorityAccountProtection'; Source = 'UnboundGlobal' }
        @{ Capability = 'PriorityAccountProtection'; Peer = 'AutomatedInvestigation'; Source = 'PeerGlobal' }
        @{ Capability = 'AutomatedInvestigation'; Peer = 'PriorityAccountProtection'; Source = 'PeerGlobal' }
        @{ Capability = 'PriorityAccountProtection'; Peer = 'AutomatedInvestigation'; Source = 'MissingDecision' }
        @{ Capability = 'AutomatedInvestigation'; Peer = 'PriorityAccountProtection'; Source = 'MissingDecision' }
    ) {
        param($Capability, $Peer, $Source)
        # Arrange
        $context = @{ DeploymentEntitlement = @{
            Capability = @(
                @{ Name = $Capability; Entitled = $false; Reason = 'EmailProtectionNotEntitled: capability unconfirmed.' }
                @{ Name = $Peer; Entitled = $false; Reason = "EmailProtectionNotEntitled: peer only.`nCategory: RecipientExchangeMissing" }
            )
            Violation = @{ Category = 'RecipientExchangeMissing' }
        } }
        if ($Source -eq 'PeerGlobal') { $context.DeploymentEntitlement.Violation.Capability = $Peer }
        if ($Source -eq 'MissingDecision') {
            $context.DeploymentEntitlement.Capability = @($context.DeploymentEntitlement.Capability | Where-Object Name -NE $Capability)
            $context.DeploymentEntitlement.Violation.Capability = $Capability
        }

        # Act
        $reason = (Get-LicensingDecisionReason $context $Capability) -join "`n"

        # Assert
        $reason | Should -Not -Match (Get-LicensingCategoryPattern MissingRecipientExchange) -Because 'another capability or an absent decision cannot satisfy the requested capability category'
    }
    It 'g22 does not accept a legacy human prefix as the <Defect> category' -TestCases @(
        @{ Defect = 'Unverified' }, @{ Defect = 'Expired' }, @{ Defect = 'WrongTenant' }, @{ Defect = 'WrongDomain' }
        @{ Defect = 'StringVerification' }, @{ Defect = 'MissingRecipientExchange' }, @{ Defect = 'MissingRecipientDefender' }, @{ Defect = 'MissingAttestations' }
    ) {
        param($Defect)
        # Arrange
        $reason = "ExchangeEntitlementUnverified: supply a current tenant- and recipient-bound licensing owner handoff (RAID-D02).`nEmailProtectionNotEntitled: explicitly supplied feature service plans are required."

        # Act
        $matchesCategory = $reason -match (Get-LicensingCategoryPattern $Defect)

        # Assert
        $matchesCategory | Should -BeFalse -Because 'case-specific categories must be separately parseable, not inferred from a generic prefix or prose'
    }
    It 'g20 does not claim operational readiness from <Capability> entitlement alone' -TestCases @(
        @{ Capability = 'PriorityAccountProtection' }
        @{ Capability = 'AutomatedInvestigation' }
    ) {
        param($Capability)
        # Arrange
        $fixture = New-LicensingScopeFixture
        $fixture.Context.Parameters.Remove('reportingEvidence')
        $fixture.Context.Entitlement.capabilityAttestations = @(
            @{ capability = $Capability; entitled = $true; recipients = @('custom@contoso.example') }
        )
        $inputs = Write-LicensingFixtureInputs $fixture

        # Act
        $context = Get-BaselineExchangeContext @inputs

        # Assert
        $decision = @($context.DeploymentEntitlement.Capability | Where-Object Name -CEQ $Capability)
        $decision.Count | Should -Be 1
        $decision[0].Entitled | Should -BeOfType ([bool])
        $decision[0].Entitled | Should -BeTrue -Because 'missing operational evidence is not missing externally attested capability entitlement'
        $reason = (Get-LicensingDecisionReason $context $Capability) -join "`n"
        $reason | Should -Match '(?i)(?:operational|external) readiness (?:remains |is )?(?:unverified|unconfirmed|not (?:assessed|verified|confirmed))' -Because 'licensing does not verify AIR operation, audit configuration, permissions or priority-account tag setup'
        $reason | Should -Not -Match '(?i)(?:AIR|audit|permissions?|tags?|operational readiness) (?:is |are )?(?:ready|verified|configured|enabled|confirmed)\b'
        $context.DeploymentEntitlement | ConvertTo-Json -Depth 20 | Should -Not -Match '(?i)"[A-Za-z]*(?:Readiness|Ready|Audit|Permission|Tag)[A-Za-z]*"\s*:\s*(?:true|"(?:Pass|Ready|Verified|Configured|Enabled|Confirmed)")' -Because 'the entitlement projection must not promote unobserved operational prerequisites to ready'
        $context.DeploymentEntitlement.NotEntitled | Should -Not -Contain $Capability
    }
    It 'g20 does not let affirmed <Capability> hide incomplete reporting operation' -TestCases @(
        @{ Capability = 'PriorityAccountProtection' }
        @{ Capability = 'AutomatedInvestigation' }
    ) {
        param($Capability)
        # Arrange
        $fixture = New-LicensingScopeFixture
        $fixture.Context.Parameters.reportingEvidence.Remove('deliveries')
        $fixture.Context.Entitlement.capabilityAttestations = @(
            @{ capability = $Capability; entitled = $true; recipients = @('custom@contoso.example') }
        )

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-006

        # Assert
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match 'ReportingDeliveryIncomplete'
        $result.Result.Reason | Should -Not -Match 'NotEntitled|THREAT_INTELLIGENCE'
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
        (Get-LicensingDecisionReason $context $Capability) -join "`n" | Should -Match (Get-LicensingCategoryPattern MissingAttestations)
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
        $reasonPattern = Get-LicensingCategoryPattern $Defect

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq $Control

        # Assert
        $result.Result.Status | Should -BeExactly NotEntitled -Because $result.Result.Reason
        $result.Result.Reason | Should -Match $reasonPattern
        $result.Evidence.Source | Should -BeExactly SuppliedExternalEntitlement
        $result.Evidence.FailureReason | Should -Match $reasonPattern
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
    It 'g18 admits one scoped <Capability> attestation independently of suite labels and its peer capability' -TestCases @(
        @{ Capability = 'PriorityAccountProtection'; Peer = 'AutomatedInvestigation' }
        @{ Capability = 'AutomatedInvestigation'; Peer = 'PriorityAccountProtection' }
    ) {
        param($Capability, $Peer)
        # Arrange
        $fixture = New-LicensingScopeFixture
        $recipient = 'custom@contoso.example'
        $fixture.Context.Parameters.messagingTier = 'MDO_P1'
        $fixture.Context.Parameters.reportingEvidence.Remove('deliveries')
        $fixture.Context.Entitlement.capabilityAttestations = @(
            @{ capability = $Capability; entitled = $true; recipients = @($recipient) }
        )
        $inputs = Write-LicensingFixtureInputs $fixture

        # Act
        $context = Get-BaselineExchangeContext @inputs

        # Assert
        $context.DeploymentEntitlement.Source | Should -BeExactly SuppliedExternalEntitlement
        $context.DeploymentEntitlement.AtpPresets | Should -BeTrue
        $attested = @($context.DeploymentEntitlement.Capability | Where-Object Name -CEQ $Capability)
        $unattested = @($context.DeploymentEntitlement.Capability | Where-Object Name -CEQ $Peer)
        $attested.Count | Should -Be 1
        $unattested.Count | Should -Be 1
        $attested[0].Entitled | Should -BeOfType ([bool])
        $attested[0].Entitled | Should -BeTrue -Because 'a valid scoped attestation, not ATP or a suite label, admits this capability'
        $unattested[0].Entitled | Should -BeOfType ([bool])
        $unattested[0].Entitled | Should -BeFalse -Because 'attesting one capability cannot admit its peer'
        $context.DeploymentEntitlement.NotEntitled | Should -Not -Contain $Capability
        $context.DeploymentEntitlement.NotEntitled | Should -Contain $Peer
        $context.Entitlement.capabilityAttestations[0].recipients | Should -HaveCount 1
        $context.Entitlement.capabilityAttestations[0].recipients[0] | Should -BeExactly $recipient
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
        elseif ($Scope -eq 'BuiltIn') {
            $matrix.Result.Status | Should -BeExactly Fail -Because 'valid BuiltIn defaults do not satisfy the requested Standard Safe Links settings'
            $matrix.Result.Reason | Should -Match "^EmailProtectionSettingDrift: 'default@contoso\.example/SafeLinks/(EnableForInternalSenders|DisableURLRewrite|AllowClickThrough)' differs from 'Standard'"
            $matrix.Evidence.Collected | Should -BeTrue
            $builtIn = @($matrix.Evidence.Value.Families.SafeLinks.Policies | Where-Object Name -eq 'Built-In Protection Policy')
            $builtIn.Count | Should -Be 1
            $builtIn[0].EnableForInternalSenders | Should -BeFalse
            $builtIn[0].DisableURLRewrite | Should -BeTrue
            $builtIn[0].AllowClickThrough | Should -BeTrue
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
Describe 'EXR-010 g22 public approved-change entitlement admission' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../helpers/ApprovedAdapterDoubles.ps1')
        $script:licensingChangeCommand = Join-Path $root 'scripts/Invoke-ExchangeOnlineChange.ps1'
    }
    BeforeEach {
        Initialize-AdapterDoubles
        foreach ($command in $global:adapterCommands) {
            Mock -CommandName $command -ModuleName ExchangeOnlineBaseline.Common { throw 'OfflineLicensingAdapterBoundary: admission must precede adapter dispatch.' }
        }
        foreach ($command in $script:licensingForbiddenCommands) {
            Mock -CommandName $command -ModuleName ExchangeOnlineBaseline.Common { throw 'OfflineLicensingBoundary: external calls are forbidden.' }
        }
    }
    AfterEach {
        foreach ($command in $script:licensingForbiddenCommands) {
            Should -Invoke -CommandName $command -ModuleName ExchangeOnlineBaseline.Common -Times 0 -Exactly
        }
    }
    It 'g22 refuses public <Scope> preview with <Defect> before any adapter read or write' -TestCases @(
        @{ Scope = 'Custom'; AdapterScope = 'AtpPresets'; Defect = 'MissingRecipientExchange' }
        @{ Scope = 'BuiltIn'; AdapterScope = 'BuiltInProtection'; Defect = 'MissingRecipientExchange' }
        @{ Scope = 'Custom'; AdapterScope = 'AtpPresets'; Defect = 'MissingRecipientDefender' }
        @{ Scope = 'BuiltIn'; AdapterScope = 'BuiltInProtection'; Defect = 'MissingRecipientDefender' }
    ) {
        param($Scope, $AdapterScope, $Defect)
        # Arrange
        $fixture = New-LicensingScopeFixture $Scope
        Set-LicensingHandoffDefect $fixture $Defect
        $arguments = Write-LicensingFixtureInputs $fixture
        $arguments.Remove('ForActionPlanning')
        $arguments.ArtifactRoot = Split-Path $arguments.ParameterPath -Parent
        $arguments.ChangeId = 'LICENSING-G22'
        $arguments.RequestedBy = 'operator@example.test'
        $caught = $null

        # Act
        try { $null = & $script:licensingChangeCommand -Stage Preview @arguments -Scope $AdapterScope -Confirm:$false } catch { $caught = $_ }

        # Assert
        foreach ($command in @($global:adapterCommands | Where-Object { $_ -like 'Get-*' })) {
            Should -Invoke -CommandName $command -ModuleName ExchangeOnlineBaseline.Common -Times 0 -Exactly
        }
        foreach ($command in @($global:adapterCommands | Where-Object { $_ -notlike 'Get-*' })) {
            Should -Invoke -CommandName $command -ModuleName ExchangeOnlineBaseline.Common -Times 0 -Exactly
        }
        $global:adapterCalls.Count | Should -Be 0
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -Match (Get-LicensingHandoffReasonPattern $Defect $fixture)
        $caught.Exception.Message | Should -Not -Match 'OfflineLicensingAdapterBoundary|ParameterBinding|ExchangeSchemaInvalid|DomainInventory|OfflineLicensingBoundary'
        Test-Path (Join-Path $arguments.ArtifactRoot 'preview-LICENSING-G22.json') | Should -BeFalse
    }
    AfterAll {
        foreach ($name in @($global:adapterCommands) + @('Get-ConnectionInformation','Invoke-OfflineAdapterCommand')) { Remove-Item "Function:global:$name" -ErrorAction SilentlyContinue }
        Remove-Variable -Name adapterCalls,adapterCommands,adapterState,adapterWriteFault,adapterReadFault,adapterReadbackFault,adapterMissingCommand -Scope Global -ErrorAction SilentlyContinue
    }
}
AfterAll {
    & $script:licensingModule {
        param($commands)
        foreach ($command in $commands) { Remove-Item "Function:script:$command" -ErrorAction SilentlyContinue }
    } $script:licensingForbiddenCommands
}