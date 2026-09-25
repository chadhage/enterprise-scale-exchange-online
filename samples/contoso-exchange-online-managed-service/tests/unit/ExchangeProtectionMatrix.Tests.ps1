BeforeDiscovery {
    . (Join-Path $PSScriptRoot '../helpers/ExchangeProtectionFixture.ps1')
    $reference = Get-ProtectionReferenceValues
    $settingCases = @(foreach ($family in $reference.Keys) { foreach ($field in $reference[$family].Keys) { @{ Family = $family; Field = $field } } })
}
BeforeAll {
    . (Join-Path $PSScriptRoot '../helpers/ExchangeProtectionFixture.ps1')
    $root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:matrixModule = Import-Module (Join-Path $root 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -PassThru
    function New-A02MatrixFixture {
        param([string]$Address = 'custom@contoso.example')
        $fixture = New-ProtectionFixture
        $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix = @($fixture.Context.Configuration.controls['MDO-001'].recipientMatrix | Where-Object address -eq $Address)
        $fixture.Raw['Get-Recipient'].Items = @($fixture.Raw['Get-Recipient'].Items | Where-Object PrimarySmtpAddress -eq $Address)
        $fixture
    }
    function Set-A02Exception {
        param($Fixture, [string]$Setting = 'DisableURLRewrite', $Value = $true)
        $Fixture.Context.Configuration.controls['MDO-001'].settingExceptions = @(@{
            recipient = 'custom@contoso.example'; family = 'SafeLinks'; setting = $Setting; value = $Value
            approval = $Fixture.Context.Configuration.controls['MDO-001'].approval.Clone()
        })
        $Fixture.Raw['Get-SafeLinksPolicy'].Items[2][$Setting] = $Value
    }
}
Describe 'EXR-010 effective email setting matrix' {
    It 'A02 g20 excludes an unlicensed GuestMailUser without rejecting or losing real mailbox coverage' {
        # Arrange
        $fixture = New-A02MatrixFixture
        $guestAddress = 'guest@contoso.example'
        $fixture.Raw['Get-Recipient'].Items += @{ Identity = 'guest'; PrimarySmtpAddress = $guestAddress; RecipientTypeDetails = 'GuestMailUser' }
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -BeExactly Pass
        $result.Result.Reason | Should -Match '^EmailProtectionVerified:'
        @($result.Evidence.Value.Matrix).Count | Should -Be 6
        @($result.Evidence.Value.Matrix.Recipient | Select-Object -Unique) | Should -Be @('custom@contoso.example')
        @($result.Evidence.Value.Matrix.Recipient) | Should -Not -Contain $guestAddress
        @($result.Evidence.Value.Matrix.Family | Sort-Object) | Should -Be @('AntiPhish','HostedContentFilter','HostedOutboundSpamFilter','MalwareFilter','SafeAttachment','SafeLinks')
        @($fixture.Context.Entitlement.recipients.address) | Should -Not -Contain $guestAddress
        $observedGuest = @($result.Evidence.Observation | Where-Object Command -eq Get-Recipient | ForEach-Object Raw | Where-Object PrimarySmtpAddress -eq $guestAddress)
        $observedGuest.Count | Should -Be 1
        $observedGuest[0].RecipientTypeDetails | Should -BeExactly GuestMailUser
    }

    It 'A02 g20 comparator rejects <Case>' -ForEach @(
        @{ Case = 'one empty string versus zero elements'; ActualValues = @(''); ExpectedValues = @() }
        @{ Case = 'one newline-containing element versus two elements'; ActualValues = @("alpha`nbeta"); ExpectedValues = @('alpha','beta') }
    ) {
        # Arrange
        $actual = $ActualValues
        $expected = $ExpectedValues
        # Act
        $equal = & $script:matrixModule { param($actual, $expected) Test-BaselineEmailSettingEqual -Actual $actual -Expected $expected } $actual $expected
        # Assert
        $equal | Should -BeFalse
    }

    It 'A02 g20 rejects ordinary setting drift for <Case>' -ForEach @(
        @{ Case = 'one empty DoNotRewriteUrls element versus an empty target'; Family = 'SafeLinks'; Field = 'DoNotRewriteUrls'; Mutate = {
            param($fixture)
            $fixture.Raw['Get-SafeLinksPolicy'].Items[2].DoNotRewriteUrls = @('')
        } }
        @{ Case = 'one newline-containing domain versus two target domains'; Family = 'AntiPhish'; Field = 'TargetedDomainsToProtect'; Mutate = {
            param($fixture)
            $fixture.Context.Configuration.controls['MDO-009'].protectedDomains = @('alpha.contoso.example','beta.contoso.example')
            $fixture.Raw['Get-AntiPhishPolicy'].Items[2].TargetedDomainsToProtect = @("alpha.contoso.example`nbeta.contoso.example")
        } }
    ) {
        # Arrange
        $fixture = New-A02MatrixFixture
        & $Mutate $fixture
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match "^EmailProtectionSettingDrift: 'custom@contoso.example/$Family/$Field'"
    }

    It 'A02 g20 refuses ApprovedException for <Case>' -ForEach @(
        @{ Case = 'one empty string instead of the approved zero elements'; ApprovedValues = @(); ObservedValues = @('') }
        @{ Case = 'one newline-containing URL instead of the approved two elements'; ApprovedValues = @('https://alpha.example','https://beta.example'); ObservedValues = @("https://alpha.example`nhttps://beta.example") }
    ) {
        # Arrange
        $fixture = New-A02MatrixFixture
        Set-A02Exception $fixture 'DoNotRewriteUrls' $ApprovedValues
        $fixture.Raw['Get-SafeLinksPolicy'].Items[2].DoNotRewriteUrls = $ObservedValues
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match "^EmailProtectionSettingDrift: 'custom@contoso.example/SafeLinks/DoNotRewriteUrls'"
    }

    It 'A02 does not lose custom applicability when every inclusion condition is empty' {
        # Arrange
        $fixture = New-A02MatrixFixture
        foreach ($family in @('MalwareFilter','HostedContentFilter','AntiPhish','SafeLinks','SafeAttachment')) {
            $fixture.Raw["Get-${family}Rule"].Items[0].SentTo = @()
        }
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -Not -BeIn @('Fail','Error','ApprovedException')
        @($result.Evidence.Value.Matrix | Where-Object Family -ne HostedOutboundSpamFilter | ForEach-Object Policy | Select-Object -Unique) | Should -Be @('Custom email')
    }

    It 'A02 does not demand inapplicable <Field> on a custom outbound policy' -ForEach @(
        @{ Field = 'BccSuspiciousOutboundMail' }
        @{ Field = 'BccSuspiciousOutboundAdditionalRecipients' }
    ) {
        # Arrange
        $fixture = New-A02MatrixFixture 'strict@contoso.example'
        $fixture.Raw['Get-HostedOutboundSpamFilterPolicy'].Items[2].Remove($Field)
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -Not -BeIn @('Fail','Error','ApprovedException')
        $row = @($result.Evidence.Value.Matrix | Where-Object Family -eq HostedOutboundSpamFilter)
        $row.Count | Should -Be 1
        $row[0].Policy | Should -BeExactly 'Strict outbound'
        @($row[0].Settings.Setting) | Should -Not -Contain $Field
    }

    It 'A02 rejects explicit configured encrypted-attachment target drift in <Field> even when blocking is disabled' -ForEach @(
        @{ Field = 'ExcludedTypesFromBlockingEncryptedAttachments'; Value = @('pdf') }
        @{ Field = 'QuarantineTagForBlockingEncryptedAttachments'; Value = 'Unused quarantine tag' }
    ) {
        # Arrange
        $fixture = New-A02MatrixFixture
        $fixture.Raw['Get-SafeAttachmentPolicy'].Items[2][$Field] = $Value
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match "EmailProtectionSettingDrift: 'custom@contoso.example/SafeAttachment/$Field'"
    }

    It 'A02 refuses omitted rule scope <Field>' -ForEach @(
        @{ Field = 'SentTo' }; @{ Field = 'SentToMemberOf' }; @{ Field = 'RecipientDomainIs' }
        @{ Field = 'ExceptIfSentTo' }; @{ Field = 'ExceptIfSentToMemberOf' }; @{ Field = 'ExceptIfRecipientDomainIs' }
    ) {
        # Arrange
        $fixture = New-A02MatrixFixture
        $fixture.Raw['Get-SafeLinksRule'].Items[0].Remove($Field)
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -BeExactly Error
        $result.Result.Reason | Should -Match "ExchangeRawPropertyMissing.*$Field"
    }

    It 'A02 refuses omitted outbound scope <Field>' -ForEach @(
        @{ Field = 'From' }; @{ Field = 'FromMemberOf' }; @{ Field = 'SenderDomainIs' }
        @{ Field = 'ExceptIfFrom' }; @{ Field = 'ExceptIfFromMemberOf' }; @{ Field = 'ExceptIfSenderDomainIs' }
    ) {
        # Arrange
        $fixture = New-A02MatrixFixture
        $fixture.Raw['Get-HostedOutboundSpamFilterRule'].Items[0].Remove($Field)
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -BeExactly Error
        $result.Result.Reason | Should -Match "ExchangeRawPropertyMissing.*$Field"
    }

    It 'A02 rejects an incomplete source-control-effective-evidence mapping' {
        # Arrange
        $inventoryPath = Join-Path $root 'config/exchange-recommendations.v1.json'
        $commands = @('Get-Recipient','Get-EOPProtectionPolicyRule','Get-ATPProtectionPolicyRule','Get-ATPBuiltInProtectionRule','Get-DistributionGroup','Get-DistributionGroupMember')
        foreach ($family in @('MalwareFilter','HostedContentFilter','HostedOutboundSpamFilter','AntiPhish','SafeLinks','SafeAttachment')) { $commands += "Get-${family}Policy", "Get-${family}Rule" }
        # Act
        $inventory = Get-Content $inventoryPath -Raw | ConvertFrom-Json
        # Assert
        $mapping = @($inventory.Mappings | Where-Object ControlId -eq MDO-001)
        $mapping.Count | Should -Be 1
        $mapping[0].Evidence | Should -BeExactly 'defender.standardPreset'
        $mapping[0].Evaluator | Should -BeExactly 'Test-StandardPresetControl'
        $mapping[0].RunbookSection | Should -BeExactly 'R-MDO-001 Standard preset assignment'
        $mapping[0].SourceId | Should -BeExactly 'S10'
        foreach ($command in $commands) { $mapping[0].Commands | Should -Contain $command }
        foreach ($source in @(
            @{ Id = 'S10'; Url = 'https://learn.microsoft.com/defender-office-365/preset-security-policies' }
            @{ Id = 'S13'; Url = 'https://learn.microsoft.com/defender-office-365/quarantine-policies' }
            @{ Id = 'S14'; Url = 'https://learn.microsoft.com/defender-office-365/recommended-settings-for-eop-and-office365' }
        )) {
            $actual = @($inventory.Sources | Where-Object Id -eq $source.Id)
            $actual.Count | Should -Be 1
            $actual[0].Url | Should -BeExactly $source.Url
            $actual[0].ReviewedOn | Should -Match '^\d{4}-\d{2}-\d{2}$'
        }
        foreach ($control in @('MDO-002','MDO-003','MDO-008','MDO-009','EXO-004')) {
            @($inventory.Mappings | Where-Object ControlId -eq $control).Count | Should -Be 1
        }
    }

    It 'A02 does not select <WrongPolicy> for <Case>' -ForEach @(
        @{ Case = 'empty custom conditions apply to all recipients'; Family = 'SafeLinks'; EopStrict = $false; AtpStrict = $false; EmptyCustom = $true; WrongPolicy = 'Built-In Protection Policy'; ExpectedPolicy = 'Custom email' }
        @{ Case = 'lower numeric priority wins the whole policy'; Family = 'SafeLinks'; EopStrict = $false; AtpStrict = $false; EmptyCustom = $false; WrongPolicy = 'Custom email'; ExpectedPolicy = 'First custom' }
    ) {
        # Arrange
        $scope = @{ State = 'Enabled'; SentTo = @('custom@contoso.example'); SentToMemberOf = @(); RecipientDomainIs = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @(); ExceptIfRecipientDomainIs = @() }
        $eop = $scope.Clone(); $eop.Name = $(if ($EopStrict) { 'Strict Preset Security Policy' } else { 'Standard Preset Security Policy' })
        $atp = $scope.Clone(); $atp.Name = $(if ($AtpStrict) { 'Strict Preset Security Policy' } else { 'Standard Preset Security Policy' })
        if ($Family -eq 'SafeLinks') { $eop.State = 'Disabled'; $atp.State = 'Disabled' }
        $custom = $scope.Clone(); $custom.Name = 'Custom rule'; $custom.Priority = 5; $custom["${Family}Policy"] = 'Custom email'
        if ($EmptyCustom) { $custom.SentTo = @() }
        $rules = @($custom)
        if ($Case -eq 'lower numeric priority wins the whole policy') {
            $first = $custom.Clone(); $first.Name = 'First rule'; $first.Priority = 0; $first["${Family}Policy"] = 'First custom'
            $rules += $first
        }
        $state = @{
            Groups = @{}; Presets = @{ EOP = @($eop); ATP = @($atp) }
            BuiltIn = @{ Name = 'ATP Built-In Protection Rule'; State = 'Enabled'; ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @(); ExceptIfRecipientDomainIs = @() }
            Families = @{ $Family = @{ Rules = $rules; Policies = @(
                @{ Name = 'Custom email'; IsDefault = $false }
                @{ Name = 'First custom'; IsDefault = $false }
                @{ Name = 'Standard Preset Security Policy'; IsDefault = $false }
                @{ Name = 'Strict Preset Security Policy'; IsDefault = $false }
                @{ Name = 'Built-In Protection Policy'; IsDefault = $true }
            ) } }
        }
        # Act
        $policy = & $script:matrixModule { param($state, $family) Resolve-BaselineEmailPolicy $state $family 'custom@contoso.example' $true } $state $Family
        # Assert
        $policy.Name | Should -Not -BeExactly $WrongPolicy
        $policy.Name | Should -BeExactly $ExpectedPolicy
    }

    It 'A02 fails closed when matching EOP <EopLevel> and ATP <AtpLevel> anti-phishing preset levels differ' -ForEach @(
        @{ EopLevel = 'Strict'; AtpLevel = 'Standard' }
        @{ EopLevel = 'Standard'; AtpLevel = 'Strict' }
    ) {
        # Arrange
        $scope = @{ State = 'Enabled'; SentTo = @('custom@contoso.example'); SentToMemberOf = @(); RecipientDomainIs = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @(); ExceptIfRecipientDomainIs = @() }
        $eop = $scope.Clone(); $eop.Name = "$EopLevel Preset Security Policy"
        $atp = $scope.Clone(); $atp.Name = "$AtpLevel Preset Security Policy"
        $state = @{
            Groups = @{}; Presets = @{ EOP = @($eop); ATP = @($atp) }
            Families = @{ AntiPhish = @{ Rules = @(); Policies = @(
                @{ Name = 'Standard Preset Security Policy'; IsDefault = $false }
                @{ Name = 'Strict Preset Security Policy'; IsDefault = $false }
            ) } }
        }
        # Act
        $act = { & $script:matrixModule { param($state) Resolve-BaselineEmailPolicy $state 'AntiPhish' 'custom@contoso.example' $true } $state }
        # Assert
        $act | Should -Throw '*EmailProtectionPrecedenceAmbiguous*'
    }

    It 'A02 deterministically resolves matching same-level EOP and ATP anti-phishing presets' {
        # Arrange
        $scope = @{ Name = 'Standard Preset Security Policy'; State = 'Enabled'; SentTo = @('custom@contoso.example'); SentToMemberOf = @(); RecipientDomainIs = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @(); ExceptIfRecipientDomainIs = @() }
        $state = @{
            Groups = @{}; Presets = @{ EOP = @($scope.Clone()); ATP = @($scope.Clone()) }
            Families = @{ AntiPhish = @{ Rules = @(); Policies = @(
                @{ Name = 'Standard Preset Security Policy'; IsDefault = $false }
                @{ Name = 'Strict Preset Security Policy'; IsDefault = $false }
            ) } }
        }
        # Act
        $policy = & $script:matrixModule { param($state) Resolve-BaselineEmailPolicy $state 'AntiPhish' 'custom@contoso.example' $true } $state
        # Assert
        $policy.Name | Should -BeExactly 'Standard Preset Security Policy'
    }

    It 'A02 rejects a <Case> before accepting an effective policy' -ForEach @(
        @{ Case = 'string Boolean setting'; Family = 'SafeLinks'; Field = 'EnableSafeLinksForEmail'; Value = 'true' }
        @{ Case = 'string integer setting'; Family = 'HostedContentFilter'; Field = 'BulkThreshold'; Value = '6' }
        @{ Case = 'scalar array setting'; Family = 'AntiPhish'; Field = 'TargetedDomainsToProtect'; Value = 'contoso.example' }
    ) {
        # Arrange
        $fixture = New-A02MatrixFixture
        $fixture.Raw["Get-${Family}Policy"].Items[2][$Field] = $Value
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match "EmailProtectionSettingDrift: 'custom@contoso.example/$Family/$Field'"
    }

    It 'A02 rejects false <Case> precedence' -ForEach @(
        @{ Case = 'custom above Standard'; Address = 'user@contoso.example'; Expected = 'Custom email'; Mutate = { param($fixture) } }
        @{ Case = 'Standard above Strict'; Address = 'strict@contoso.example'; Expected = 'Standard Preset Security Policy'; Mutate = { param($fixture) foreach ($kind in @('EOP','ATP')) { $fixture.Raw["Get-${kind}ProtectionPolicyRule"].ByIdentity['Standard Preset Security Policy'][0].ExceptIfSentToMemberOf = @() } } }
        @{ Case = 'custom above Strict'; Address = 'strict@contoso.example'; Expected = 'Custom email'; Mutate = { param($fixture) } }
        @{ Case = 'default above custom'; Address = 'custom@contoso.example'; Expected = 'Default'; Mutate = { param($fixture) } }
        @{ Case = 'custom despite matching exclusion group'; Address = 'custom@contoso.example'; Expected = 'Custom email'; Mutate = { param($fixture) $fixture.Raw['Get-SafeLinksRule'].Items[0].ExceptIfSentToMemberOf = @('excluded@contoso.example'); $fixture.Raw['Get-DistributionGroup'].Items += @{ Identity = 'excluded@contoso.example'; PrimarySmtpAddress = 'excluded@contoso.example' }; $fixture.Raw['Get-DistributionGroupMember'].ByIdentity = @{ 'excluded@contoso.example' = @(@{ PrimarySmtpAddress = 'custom@contoso.example'; RecipientType = 'UserMailbox' }) } } }
        @{ Case = 'built-in despite direct exclusion'; Address = 'default@contoso.example'; Expected = 'Default'; Mutate = { param($fixture) $fixture.Raw['Get-ATPBuiltInProtectionRule'].Items[0].ExceptIfSentTo = @('default@contoso.example') } }
        @{ Case = 'built-in despite domain exclusion'; Address = 'default@contoso.example'; Expected = 'Default'; Mutate = { param($fixture) $fixture.Raw['Get-ATPBuiltInProtectionRule'].Items[0].ExceptIfRecipientDomainIs = @('contoso.example') } }
        @{ Case = 'built-in despite disabled state'; Address = 'default@contoso.example'; Expected = 'Default'; Mutate = { param($fixture) $fixture.Raw['Get-ATPBuiltInProtectionRule'].Items[0].State = 'Disabled' } }
    ) {
        # Arrange
        $fixture = New-A02MatrixFixture $Address
        $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix[0].expectedPolicy = $Expected
        & $Mutate $fixture
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match 'EmailProtectionPrecedence'
    }

    It 'A02 does not require Defender-only AntiPhish fields for an EOP-only custom recipient' {
        # Arrange
        $fixture = New-A02MatrixFixture
        $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix[0].defender = $false
        $fixture.Context.Entitlement.recipients[2].servicePlans = @('EXCHANGE_S_ENTERPRISE')
        $eopFields = @('EnableSpoofIntelligence','HonorDmarcPolicy','DmarcQuarantineAction','DmarcRejectAction','AuthenticationFailAction','SpoofQuarantineTag','EnableFirstContactSafetyTips','EnableUnauthenticatedSender','EnableViaTag')
        $policy = $fixture.Raw['Get-AntiPhishPolicy'].Items[2]
        foreach ($field in @($policy.Keys)) { if ($field -notin ($eopFields + @('Name','Identity','IsDefault'))) { $policy.Remove($field) } }
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -Not -BeIn @('Error','Fail','ApprovedException')
        $row = @($result.Evidence.Value.Matrix | Where-Object Family -eq AntiPhish)
        $row.Count | Should -Be 1
        @($row[0].Settings.Setting | Sort-Object) | Should -Be @($eopFields | Sort-Object)
        $row[0].Policy | Should -BeExactly 'Custom email'
    }

    It 'A02 refuses <Case>' -ForEach @(
        @{ Case = 'duplicate desired recipient'; Reason = 'EmailProtectionRecipientInventory'; Mutate = { param($fixture) $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix += $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix[0].Clone() } }
        @{ Case = 'undeclared observed mailbox'; Reason = 'EmailProtectionRecipientInventory'; Mutate = { param($fixture) $fixture.Raw['Get-Recipient'].Items += @{ Identity = 'extra'; PrimarySmtpAddress = 'extra@contoso.example'; RecipientTypeDetails = 'SharedMailbox' } } }
        @{ Case = 'duplicate observed SMTP under distinct identities'; Reason = 'EmailProtectionRecipientInventory'; Mutate = { param($fixture) $copy = $fixture.Raw['Get-Recipient'].Items[0].Clone(); $copy.Identity = 'duplicate'; $fixture.Raw['Get-Recipient'].Items += $copy } }
        @{ Case = 'unknown recipient class silently omitted'; Reason = 'EmailProtectionRecipientInventory|ExchangeRaw'; Mutate = { param($fixture) $fixture.Raw['Get-Recipient'].Items += @{ Identity = 'unknown'; PrimarySmtpAddress = 'unknown@contoso.example'; RecipientTypeDetails = 'UnknownMailbox' } } }
        @{ Case = 'unknown desired profile'; Reason = 'ExchangeSchemaInvalid'; Mutate = { param($fixture) $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix[0].level = 'Unknown' } }
        @{ Case = 'string recipient capability'; Reason = 'ExchangeSchemaInvalid'; Mutate = { param($fixture) $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix[0].defender = 'false' } }
        @{ Case = 'string custom rule priority'; Reason = 'EmailProtectionPriorityAmbiguous'; Mutate = { param($fixture) $fixture.Raw['Get-SafeLinksRule'].Items[0].Priority = '1' } }
        @{ Case = 'negative custom rule priority'; Reason = 'EmailProtectionPriorityAmbiguous'; Mutate = { param($fixture) $fixture.Raw['Get-SafeLinksRule'].Items[0].Priority = -1 } }
        @{ Case = 'unknown custom rule state'; Reason = 'EmailProtectionRuleState'; Mutate = { param($fixture) $fixture.Raw['Get-SafeLinksRule'].Items[0].State = 'Unknown' } }
        @{ Case = 'unsupported custom rule predicate'; Reason = 'EmailProtection.*Scope'; Mutate = { param($fixture) $fixture.Raw['Get-SafeLinksRule'].Items[0].RecipientAddressContainsWords = @('unmatched') } }
        @{ Case = 'unsupported custom rule exception'; Reason = 'EmailProtection.*Scope'; Mutate = { param($fixture) $fixture.Raw['Get-SafeLinksRule'].Items[0].ExceptIfRecipientAddressContainsWords = @('custom') } }
        @{ Case = 'null custom condition'; Reason = 'EmailProtection.*Scope|ExchangeRaw'; Mutate = { param($fixture) $fixture.Raw['Get-SafeLinksRule'].Items[0].SentTo = $null } }
        @{ Case = 'wildcard custom condition'; Reason = 'EmailProtection.*Scope|EmailProtectionPrecedence'; Mutate = { param($fixture) $fixture.Raw['Get-SafeLinksRule'].Items[0].SentTo = @('*') } }
        @{ Case = 'recipient-domain AND condition mismatch'; Reason = 'EmailProtectionPrecedence'; Mutate = { param($fixture) $fixture.Raw['Get-SafeLinksRule'].Items[0].RecipientDomainIs = @('other.example') } }
        @{ Case = 'direct recipient exclusion'; Reason = 'EmailProtectionPrecedence'; Mutate = { param($fixture) $fixture.Raw['Get-SafeLinksRule'].Items[0].ExceptIfSentTo = @('custom@contoso.example') } }
        @{ Case = 'domain exclusion'; Reason = 'EmailProtectionPrecedence'; Mutate = { param($fixture) $fixture.Raw['Get-SafeLinksRule'].Items[0].ExceptIfRecipientDomainIs = @('contoso.example') } }
        @{ Case = 'disabled custom rule'; Reason = 'EmailProtectionPrecedence'; Mutate = { param($fixture) $fixture.Raw['Get-SafeLinksRule'].Items[0].State = 'Disabled' } }
        @{ Case = 'lower-priority expected policy'; Reason = 'EmailProtectionPrecedence'; Mutate = {
            param($fixture)
            $firstPolicy = $fixture.Raw['Get-SafeLinksPolicy'].Items[2].Clone()
            $firstPolicy.Name = 'First custom'; $firstPolicy.Identity = 'First custom'; $firstPolicy.IsDefault = $false
            $fixture.Raw['Get-SafeLinksPolicy'].Items += $firstPolicy
            $fixture.Raw['Get-SafeLinksRule'].Items[0].Priority = 1
            $firstRule = $fixture.Raw['Get-SafeLinksRule'].Items[0].Clone()
            $firstRule.Name = 'First matching'; $firstRule.Identity = 'First matching'; $firstRule.Priority = 0; $firstRule.SafeLinksPolicy = 'First custom'
            $fixture.Raw['Get-SafeLinksRule'].Items += $firstRule
        } }
        @{ Case = 'recipient scope mistaken for outbound sender scope'; Reason = 'EmailProtectionSettingDrift'; Mutate = { param($fixture) $fixture.Raw['Get-HostedOutboundSpamFilterRule'].Items[0].SentTo = @('custom@contoso.example'); $fixture.Raw['Get-HostedOutboundSpamFilterPolicy'].Items[1].AutoForwardingMode = 'On' } }
        @{ Case = 'outbound sender exclusion'; Reason = 'EmailProtectionSettingDrift'; Mutate = { param($fixture) $fixture.Raw['Get-HostedOutboundSpamFilterRule'].Items[0].From = @('custom@contoso.example'); $fixture.Raw['Get-HostedOutboundSpamFilterRule'].Items[0].ExceptIfFrom = @('custom@contoso.example'); $fixture.Raw['Get-HostedOutboundSpamFilterPolicy'].Items[1].AutoForwardingMode = 'On' } }
        @{ Case = 'missing default policy'; Reason = 'EmailProtectionPolicyMissing'; Mutate = { param($fixture) $fixture.Raw['Get-HostedOutboundSpamFilterPolicy'].Items = @($fixture.Raw['Get-HostedOutboundSpamFilterPolicy'].Items | Where-Object Name -ne Default) } }
        @{ Case = 'ambiguous default policy'; Reason = 'EmailProtectionPolicyMissing'; Mutate = { param($fixture) $fixture.Raw['Get-HostedOutboundSpamFilterPolicy'].Items[0].IsDefault = $true } }
        @{ Case = 'string default marker'; Reason = 'EmailProtectionPolicyMissing|ExchangeRaw'; Mutate = { param($fixture) $fixture.Raw['Get-HostedOutboundSpamFilterPolicy'].Items[1].IsDefault = 'true' } }
        @{ Case = 'missing setting exception owner'; Reason = 'ExchangeSchemaInvalid'; Mutate = { param($fixture) Set-A02Exception $fixture; $fixture.Context.Configuration.controls['MDO-001'].settingExceptions[0].approval.Remove('owner') } }
        @{ Case = 'expired setting exception'; Reason = 'EmailProtectionException'; Mutate = { param($fixture) Set-A02Exception $fixture; $fixture.Context.Configuration.controls['MDO-001'].settingExceptions[0].approval.expiresOn = '2000-01-01T00:00:00Z' } }
        @{ Case = 'duplicate setting exception'; Reason = 'EmailProtectionException'; Mutate = { param($fixture) Set-A02Exception $fixture; $fixture.Context.Configuration.controls['MDO-001'].settingExceptions += $fixture.Context.Configuration.controls['MDO-001'].settingExceptions[0].Clone() } }
        @{ Case = 'tenant wildcard setting exception'; Reason = 'EmailProtectionException'; Mutate = { param($fixture) Set-A02Exception $fixture; $fixture.Context.Configuration.controls['MDO-001'].settingExceptions[0].recipient = '*' } }
        @{ Case = 'wrong recipient setting exception'; Reason = 'EmailProtectionException'; Mutate = { param($fixture) Set-A02Exception $fixture; $fixture.Context.Configuration.controls['MDO-001'].settingExceptions[0].recipient = 'other@contoso.example' } }
        @{ Case = 'unknown setting exception'; Reason = 'EmailProtectionException'; Mutate = { param($fixture) Set-A02Exception $fixture; $fixture.Context.Configuration.controls['MDO-001'].settingExceptions[0].setting = 'UnknownSetting' } }
        @{ Case = 'unknown family exception'; Reason = 'EmailProtectionException'; Mutate = { param($fixture) Set-A02Exception $fixture; $fixture.Context.Configuration.controls['MDO-001'].settingExceptions[0].family = 'TeamsProtection' } }
        @{ Case = 'broad exception value'; Reason = 'EmailProtectionException'; Mutate = { param($fixture) Set-A02Exception $fixture 'DoNotRewriteUrls' @('*') } }
        @{ Case = 'string exception for Boolean setting'; Reason = 'EmailProtectionException'; Mutate = { param($fixture) Set-A02Exception $fixture 'DisableURLRewrite' 'true' } }
        @{ Case = 'string exception for integer setting'; Reason = 'EmailProtectionException'; Mutate = { param($fixture) Set-A02Exception $fixture; $exception = $fixture.Context.Configuration.controls['MDO-001'].settingExceptions[0]; $exception.family = 'HostedContentFilter'; $exception.setting = 'BulkThreshold'; $exception.value = '6'; $fixture.Raw['Get-HostedContentFilterPolicy'].Items[2].BulkThreshold = '6'; $fixture.Raw['Get-SafeLinksPolicy'].Items[2].DisableURLRewrite = $false } }
        @{ Case = 'scalar exception for array setting'; Reason = 'EmailProtectionException'; Mutate = { param($fixture) Set-A02Exception $fixture 'DoNotRewriteUrls' 'https://approved.example' } }
        @{ Case = 'unused Defender exception on EOP-only recipient'; Reason = 'EmailProtectionException'; Mutate = { param($fixture) Set-A02Exception $fixture; $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix[0].defender = $false; $fixture.Context.Entitlement.recipients[2].servicePlans = @('EXCHANGE_S_ENTERPRISE') } }
    ) {
        # Arrange
        $fixture = New-A02MatrixFixture
        & $Mutate $fixture
        $caught = $null
        # Act
        try { $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001 }
        catch { $caught = $_.Exception.Message }
        # Assert
        if ($Reason -eq 'ExchangeSchemaInvalid') {
            $caught | Should -Match '^ExchangeSchemaInvalid:'
        } else {
            $caught | Should -BeNullOrEmpty
            if ($Case -eq 'lower-priority expected policy') {
                $rawRules = @($result.Evidence.Observation | Where-Object Command -eq Get-SafeLinksRule | ForEach-Object Raw | Sort-Object { $_.Priority })
                $rawRules.Count | Should -Be 2
                $rawRules[0].Priority | Should -BeOfType ([int])
                $rawRules[0].Priority | Should -Be 0
                $rawRules[0].SafeLinksPolicy | Should -BeExactly 'First custom'
                $rawRules[1].Priority | Should -BeOfType ([int])
                $rawRules[1].Priority | Should -Be 1
                $rawRules[1].SafeLinksPolicy | Should -BeExactly 'Custom email'
                $rawPolicies = @($result.Evidence.Observation | Where-Object Command -eq Get-SafeLinksPolicy | ForEach-Object Raw | Where-Object Name -in @('First custom','Custom email'))
                $rawPolicies.Count | Should -Be 2
                foreach ($policy in $rawPolicies) {
                    $policy.IsDefault | Should -BeExactly $false
                    foreach ($field in (Get-ProtectionReferenceValues).SafeLinks.Keys) { $policy.Keys | Should -Contain $field }
                }
                $result.Result.Reason | Should -BeExactly "EmailProtectionPrecedence: 'custom@contoso.example/SafeLinks' resolves to 'First custom', not 'Custom email'."
            }
            $result.Result.Status | Should -Not -BeIn @('Pass','ApprovedException')
            $result.Result.Reason | Should -Match $Reason
        }
    }

    It 'A02 refuses incomplete <Command> via <Failure>' -ForEach @(
        @{ Command = 'Get-Recipient'; Failure = 'Warning' }
        @{ Command = 'Get-Recipient'; Failure = 'Error' }
        @{ Command = 'Get-DistributionGroupMember'; Failure = 'Warning' }
        @{ Command = 'Get-DistributionGroupMember'; Failure = 'Error' }
        @{ Command = 'Get-EOPProtectionPolicyRule'; Failure = 'Warning' }
        @{ Command = 'Get-ATPProtectionPolicyRule'; Failure = 'Error' }
        @{ Command = 'Get-ATPBuiltInProtectionRule'; Failure = 'Warning' }
        @{ Command = 'Get-SafeLinksPolicy'; Failure = 'Warning' }
        @{ Command = 'Get-HostedOutboundSpamFilterRule'; Failure = 'Warning' }
    ) {
        # Arrange
        $fixture = New-A02MatrixFixture
        $fixture.Raw[$Command][$Failure] = 'A02 incomplete raw response'
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -BeExactly Error
        $result.Result.Reason | Should -Match 'A02 incomplete raw response'
    }

    It 'A02 refuses recursive membership <Case>' -ForEach @(
        @{ Case = 'self cycle' }
        @{ Case = 'nested cycle' }
        @{ Case = 'nested unresolved SMTP' }
        @{ Case = 'nested denied collection' }
        @{ Case = 'nested paged collection' }
    ) {
        # Arrange
        $fixture = New-A02MatrixFixture
        foreach ($kind in @('EOP','ATP')) {
            $fixture.Raw["Get-${kind}ProtectionPolicyRule"].ByIdentity['Strict Preset Security Policy'][0].SentToMemberOf = @('outer@contoso.example')
            $fixture.Raw["Get-${kind}ProtectionPolicyRule"].ByIdentity['Standard Preset Security Policy'][0].ExceptIfSentToMemberOf = @('outer@contoso.example')
        }
        $fixture.Raw['Get-DistributionGroup'] = @{ Items = @(
            @{ Identity = 'outer@contoso.example'; PrimarySmtpAddress = 'outer@contoso.example' }
            @{ Identity = 'inner@contoso.example'; PrimarySmtpAddress = 'inner@contoso.example' }
        ) }
        $fixture.Raw['Get-DistributionGroupMember'] = @{ ByIdentity = @{
            'outer@contoso.example' = @(@{ PrimarySmtpAddress = 'inner@contoso.example'; RecipientType = 'MailUniversalDistributionGroup' })
            'inner@contoso.example' = @(@{ PrimarySmtpAddress = 'outer@contoso.example'; RecipientType = 'MailUniversalDistributionGroup' })
        } }
        switch ($Case) {
            'self cycle' { $fixture.Raw['Get-DistributionGroupMember'].ByIdentity['outer@contoso.example'][0].PrimarySmtpAddress = 'outer@contoso.example' }
            'nested unresolved SMTP' { $fixture.Raw['Get-DistributionGroupMember'].ByIdentity['inner@contoso.example'][0].PrimarySmtpAddress = '' }
            'nested denied collection' { $fixture.Raw['Get-DistributionGroupMember'].Error = 'A02 nested access denied' }
            'nested paged collection' { $fixture.Raw['Get-DistributionGroupMember'].Warning = 'A02 nested more results available' }
        }
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -Not -BeIn @('Pass','ApprovedException')
        $result.Result.Reason | Should -Match 'EmailProtectionGroupUnresolved|A02 nested'
    }

    It 'A02 does not substitute Standard for genuine raw BuiltIn <Field>' -ForEach @(
        @{ Field = 'EnableForInternalSenders'; BuiltInValue = $false; StandardValue = $true }
        @{ Field = 'DisableURLRewrite'; BuiltInValue = $true; StandardValue = $false }
        @{ Field = 'AllowClickThrough'; BuiltInValue = $true; StandardValue = $false }
    ) {
        # Arrange
        $fixture = New-ProtectionFixture
        $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix = @($fixture.Context.Configuration.controls['MDO-001'].recipientMatrix | Where-Object address -eq 'default@contoso.example')
        $fixture.Raw['Get-Recipient'].Items = @($fixture.Raw['Get-Recipient'].Items | Where-Object PrimarySmtpAddress -eq 'default@contoso.example')
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $rawPolicies = @($result.Evidence.Observation | Where-Object Command -eq Get-SafeLinksPolicy | ForEach-Object Raw)
        $builtIn = @($rawPolicies | Where-Object Name -eq 'Built-In Protection Policy')
        $builtIn.Count | Should -Be 1
        $builtIn[0].Identity | Should -BeExactly 'Built-In Protection Policy'
        $builtIn[0].$Field | Should -BeOfType ([bool])
        $builtIn[0].$Field | Should -BeExactly $BuiltInValue
        $builtIn[0].$Field | Should -Not -Be $StandardValue
        $standard = @($rawPolicies | Where-Object Name -eq 'Standard Preset Security Policy')
        $standard.Count | Should -Be 1
        $standard[0].$Field | Should -BeOfType ([bool])
        $standard[0].$Field | Should -BeExactly $StandardValue
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match "EmailProtectionSettingDrift: 'default@contoso.example/SafeLinks/(EnableForInternalSenders|DisableURLRewrite|AllowClickThrough)'"
    }
    It 'rejects drift in <Family>/<Field>' -ForEach $settingCases {
        # Arrange
        $fixture = New-ProtectionFixture
        $target = @($fixture.Raw["Get-${Family}Policy"].Items | Where-Object Name -eq $(if ($Family -eq 'HostedOutboundSpamFilter') { 'Default' } else { 'Standard Preset Security Policy' }))[0]
        $target[$Field] = if ($target[$Field] -is [bool]) { -not $target[$Field] } else { 'DRIFT' }
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match 'EmailProtectionSettingDrift'
    }
    It 'rejects an omitted <Family>/<Field>' -ForEach $settingCases {
        # Arrange
        $fixture = New-ProtectionFixture
        $target = @($fixture.Raw["Get-${Family}Policy"].Items | Where-Object Name -eq $(if ($Family -eq 'HostedOutboundSpamFilter') { 'Default' } else { 'Standard Preset Security Policy' }))[0]
        $target.Remove($Field)
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -BeExactly Error
        $result.Result.Reason | Should -Match 'ExchangeRawPropertyMissing'
    }
    It 'rejects <Case>' -ForEach @(
        @{ Case = 'recipient hole'; Reason = 'EmailProtectionRecipientInventory'; Mutate = { param($fixture) $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix = @($fixture.Context.Configuration.controls['MDO-001'].recipientMatrix | Select-Object -Skip 1) } }
        @{ Case = 'wrong precedence'; Reason = 'EmailProtectionPrecedence'; Mutate = { param($fixture) $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix[0].expectedPolicy = 'Custom email' } }
        @{ Case = 'missing license'; Reason = 'EmailProtectionNotEntitled'; Mutate = { param($fixture) $fixture.Context.Entitlement.recipients[0].servicePlans = @('EXCHANGE_S_ENTERPRISE') } }
        @{ Case = 'suite name is not entitlement'; Reason = 'EmailProtectionNotEntitled'; Mutate = { param($fixture) $fixture.Context.Entitlement.recipients[0].servicePlans = @('Microsoft 365 E5') } }
        @{ Case = 'unresolved group'; Reason = 'EmailProtectionGroupUnresolved'; Mutate = { param($fixture) $fixture.Raw['Get-DistributionGroupMember'].Items = @(@{ Identity = 'unresolved'; PrimarySmtpAddress = ''; RecipientType = 'UserMailbox' }) } }
        @{ Case = 'recipient exception removes strict coverage'; Reason = 'EmailProtectionPrecedence'; Mutate = { param($fixture) $fixture.Raw['Get-ATPProtectionPolicyRule'].ByIdentity['Strict Preset Security Policy'][0].ExceptIfSentTo = @('strict@contoso.example') } }
        @{ Case = 'duplicate priority'; Reason = 'EmailProtectionPriorityAmbiguous'; Mutate = { param($fixture) $duplicate = $fixture.Raw['Get-SafeLinksRule'].Items[0].Clone(); $duplicate.Name = 'Other'; $fixture.Raw['Get-SafeLinksRule'].Items += $duplicate } }
        @{ Case = 'misbound policy'; Reason = 'EmailProtectionPolicyMissing'; Mutate = { param($fixture) $fixture.Raw['Get-SafeLinksRule'].Items[0].SafeLinksPolicy = 'Absent' } }
        @{ Case = 'unapproved setting exception'; Reason = 'EmailProtectionException'; Mutate = { param($fixture) $fixture.Context.Configuration.controls['MDO-001'].settingExceptions = @(@{ recipient = '*'; family = 'SafeLinks'; setting = 'AllowClickThrough'; value = $true; approval = $null }) } }
        @{ Case = 'expired approval'; Reason = 'ApprovalExpired'; Mutate = { param($fixture) $fixture.Context.Configuration.controls['MDO-001'].approval.expiresOn = '2000-01-01T00:00:00Z' } }
        @{ Case = 'uncollected recipients'; Reason = 'ExchangeRaw'; Mutate = { param($fixture) $fixture.Raw['Get-Recipient'].Items = @() } }
        @{ Case = 'truncated rules'; Reason = 'ExchangeRaw'; Mutate = { param($fixture) $fixture.Raw['Get-SafeLinksRule'].Warning = 'More results available' } }
        @{ Case = 'denied collection'; Reason = 'Access denied'; Mutate = { param($fixture) $fixture.Raw['Get-SafeAttachmentPolicy'].Error = 'Access denied' } }
    ) {
        # Arrange
        $fixture = New-ProtectionFixture
        & $Mutate $fixture
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -Not -Be Pass
        $result.Result.Reason | Should -Match $Reason
    }

    It 'A02 records one complete mixed public matrix with independent field and policy evidence' {
        # Arrange
        $fixture = New-ProtectionFixture
        $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix[3].expectedPolicy = 'Standard Preset Security Policy'
        $fixture.Context.Configuration.controls['MDO-001'].excludedSecOpsMailbox = @('custom@contoso.example','secops@contoso.example')
        foreach ($kind in @('EOP','ATP')) {
            $fixture.Raw["Get-${kind}ProtectionPolicyRule"].ByIdentity['Standard Preset Security Policy'][0].ExceptIfSentTo = @('custom@contoso.example','secops@contoso.example')
        }
        $priorityGroup = $fixture.Raw['Get-EOPProtectionPolicyRule'].ByIdentity['Strict Preset Security Policy'][0].SentToMemberOf[0]
        $fixture.Raw['Get-DistributionGroup'].Items += @{ Identity = 'nested@contoso.example'; PrimarySmtpAddress = 'nested@contoso.example' }
        $fixture.Raw['Get-DistributionGroupMember'] = @{ ByIdentity = @{
            $priorityGroup = @(@{ PrimarySmtpAddress = 'nested@contoso.example'; RecipientType = 'MailUniversalSecurityGroup' })
            'nested@contoso.example' = @(@{ PrimarySmtpAddress = 'strict@contoso.example'; RecipientType = 'UserMailbox' })
        } }
        $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix[4].defender = $false
        $fixture.Context.Entitlement.recipients[4].servicePlans = @('EXCHANGE_S_ENTERPRISE')
        $fixture.Raw['Get-ATPBuiltInProtectionRule'].Items[0].ExceptIfSentTo = @('secops@contoso.example')
        Set-A02Exception $fixture
        $expectedRecipients = @(
            @{ Address = 'user@contoso.example'; Policy = 'Standard Preset Security Policy'; Profile = 'Standard'; Defender = $true; Outbound = 'Default' }
            @{ Address = 'strict@contoso.example'; Policy = 'Strict Preset Security Policy'; Profile = 'Strict'; Defender = $true; Outbound = 'Strict outbound' }
            @{ Address = 'custom@contoso.example'; Policy = 'Custom email'; Profile = 'Standard'; Defender = $true; Outbound = 'Default' }
            @{ Address = 'default@contoso.example'; Policy = 'Standard Preset Security Policy'; Profile = 'Standard'; Defender = $true; Outbound = 'Default' }
            @{ Address = 'secops@contoso.example'; Policy = 'Default'; Profile = 'Standard'; Defender = $false; Outbound = 'Default' }
        )
        $eopFields = @('EnableSpoofIntelligence','HonorDmarcPolicy','DmarcQuarantineAction','DmarcRejectAction','AuthenticationFailAction','SpoofQuarantineTag','EnableFirstContactSafetyTips','EnableUnauthenticatedSender','EnableViaTag')
        $sections = @{
            MalwareFilter = 'Anti-malware policy settings'
            HostedContentFilter = 'Anti-spam policy settings / ASF settings in anti-spam policies'
            HostedOutboundSpamFilter = 'Outbound spam policy settings'
            AntiPhish = 'Anti-phishing policy settings for all cloud mailboxes / Impersonation settings / Phishing email thresholds'
            SafeAttachment = 'Safe Attachments policy settings'
            SafeLinks = 'Safe Links policy settings (Email and Click protection only)'
        }
        $localFields = @{
            MalwareFilter = @('EnableInternalSenderAdminNotifications','InternalSenderAdminAddress','EnableExternalSenderAdminNotifications','ExternalSenderAdminAddress','CustomNotifications','CustomFromName','CustomFromAddress','CustomInternalSubject','CustomInternalBody','CustomExternalSubject','CustomExternalBody')
            HostedContentFilter = @('EnableLanguageBlockList','LanguageBlockList','EnableRegionBlockList','RegionBlockList')
            HostedOutboundSpamFilter = @()
            AntiPhish = @('TargetedUsersToProtect','TargetedDomainsToProtect','ExcludedSenders','ExcludedDomains')
            SafeAttachment = @()
            SafeLinks = @('DoNotRewriteUrls','EnableOrganizationBranding','CustomNotificationText','UseTranslatedNotificationText')
        }
        $expected = @(foreach ($recipient in $expectedRecipients) {
            $values = Get-ProtectionReferenceValues $recipient.Profile
            foreach ($family in @('MalwareFilter','HostedContentFilter','HostedOutboundSpamFilter','AntiPhish','SafeAttachment','SafeLinks')) {
                if (-not $recipient.Defender -and $family -in @('SafeAttachment','SafeLinks')) { continue }
                $policyName = $recipient.Policy
                $fields = $values[$family].Clone()
                if ($family -eq 'HostedOutboundSpamFilter') {
                    $policyName = $recipient.Outbound
                    if ($policyName -ne 'Default') { $fields.Remove('BccSuspiciousOutboundMail'); $fields.Remove('BccSuspiciousOutboundAdditionalRecipients') }
                }
                if ($family -eq 'AntiPhish') {
                    if (-not $recipient.Defender) { foreach ($field in @($fields.Keys)) { if ($field -notin $eopFields) { $fields.Remove($field) } } }
                    else { $fields.TargetedUsersToProtect = @('secops@contoso.example') }
                }
                if ($recipient.Address -eq 'custom@contoso.example' -and $family -eq 'SafeLinks') { $fields.DisableURLRewrite = $true }
                @{ Recipient = $recipient.Address; Family = $family; Policy = $policyName; Level = $recipient.Profile; Fields = $fields }
            }
        })
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -BeExactly ApprovedException
        $result.Result.Reason | Should -Match '^EmailProtectionVerified:'
        $result.Evidence.ControlId | Should -BeExactly 'MDO-001'
        @($result.Evidence.Value.Matrix).Count | Should -Be 28
        foreach ($entry in $expected) {
            $rows = @($result.Evidence.Value.Matrix | Where-Object { $_.Recipient -eq $entry.Recipient -and $_.Family -eq $entry.Family })
            $rows.Count | Should -Be 1
            $rows[0].Policy | Should -BeExactly $entry.Policy
            $rows[0].Level | Should -BeExactly $entry.Level
            @($rows[0].Settings).Count | Should -Be $entry.Fields.Count
            @($rows[0].Settings.Setting | Sort-Object) | Should -Be @($entry.Fields.Keys | Sort-Object)
            foreach ($field in $entry.Fields.Keys) {
                $settings = @($rows[0].Settings | Where-Object Setting -eq $field)
                $settings.Count | Should -Be 1
                $actual = $settings[0]
                if ($entry.Fields[$field] -is [array]) {
                    ($actual.Actual -is [Collections.IList]) | Should -BeTrue -Because "$($entry.Recipient)/$($entry.Family)/$field Actual must preserve an array, not null or a scalar"
                    ($actual.Expected -is [Collections.IList]) | Should -BeTrue -Because "$($entry.Recipient)/$($entry.Family)/$field Expected must preserve an array, not null or a scalar"
                    @($actual.Actual).Count | Should -Be $entry.Fields[$field].Count
                    @($actual.Expected).Count | Should -Be $entry.Fields[$field].Count
                    foreach ($value in @($actual.Actual) + @($actual.Expected)) { $value | Should -BeOfType ([string]) }
                    @($actual.Actual | Sort-Object) | Should -Be @($entry.Fields[$field] | Sort-Object)
                    @($actual.Expected | Sort-Object) | Should -Be @($entry.Fields[$field] | Sort-Object)
                } else {
                    if ($entry.Fields[$field] -is [int] -or $entry.Fields[$field] -is [long]) {
                        ($actual.Actual -is [int] -or $actual.Actual -is [long]) | Should -BeTrue -Because "$field Actual must preserve an integer"
                        ($actual.Expected -is [int] -or $actual.Expected -is [long]) | Should -BeTrue -Because "$field Expected must preserve an integer"
                    } else {
                        $actual.Actual | Should -BeOfType ($entry.Fields[$field].GetType())
                        $actual.Expected | Should -BeOfType ($entry.Fields[$field].GetType())
                    }
                    $actual.Actual | Should -BeExactly $entry.Fields[$field]
                    $actual.Expected | Should -BeExactly $entry.Fields[$field]
                }
                $basis = if ($entry.Recipient -eq 'custom@contoso.example' -and $entry.Family -eq 'SafeLinks' -and $field -eq 'DisableURLRewrite') { 'ApprovedException' }
                    elseif ($field -in $localFields[$entry.Family]) { 'LocalPolicy' }
                    else { 'MicrosoftRecommendation' }
                $actual.Basis | Should -BeExactly $basis
                $actual.Source | Should -BeExactly 'https://learn.microsoft.com/defender-office-365/recommended-settings-for-eop-and-office365'
                $actual.Section | Should -BeExactly $sections[$entry.Family]
                $actual.ReviewedOn | Should -BeExactly '2026-09-21'
            }
        }
        $customLinks = @($result.Evidence.Value.Matrix | Where-Object { $_.Recipient -eq 'custom@contoso.example' -and $_.Family -eq 'SafeLinks' })[0]
        @($customLinks.Settings | Where-Object Setting -eq DisableURLRewrite)[0].Basis | Should -BeExactly ApprovedException
        @($customLinks.Settings | Where-Object Setting -eq DoNotRewriteUrls)[0].Basis | Should -BeExactly LocalPolicy
        @($customLinks.Settings | Where-Object Setting -eq EnableSafeLinksForEmail)[0].Basis | Should -BeExactly MicrosoftRecommendation
        @($result.Evidence.Observation | Where-Object Command -eq Get-Recipient).Arguments.ResultSize | Should -BeExactly Unlimited
        @($result.Evidence.Observation | Where-Object Command -eq Get-DistributionGroupMember | ForEach-Object { $_.Arguments.ResultSize } | Select-Object -Unique) | Should -Be @('Unlimited')
        @($result.Evidence.Observation.Command | Where-Object { $_ -match '^(Set|New|Remove|Enable|Disable)-|^[^-]+-(Mg|SPO|Teams)|Graph|AtpPolicyForO365|License' }).Count | Should -Be 0
    }

    It 'records a licensed effective matrix with a separately approved custom exception' {
        # Arrange
        $fixture = New-ProtectionFixture
        foreach ($recipient in $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix) {
            if ($recipient.expectedPolicy -eq 'Default') { $recipient.expectedPolicy = 'Standard Preset Security Policy' }
        }
        foreach ($kind in @('EOP','ATP')) {
            $fixture.Raw["Get-${kind}ProtectionPolicyRule"].ByIdentity['Standard Preset Security Policy'][0].ExceptIfSentTo = @('custom@contoso.example')
        }
        $fixture.Raw['Get-SafeLinksPolicy'].Items[2].DisableURLRewrite = $true
        $fixture.Context.Configuration.controls['MDO-001'].settingExceptions = @(@{
            recipient = 'custom@contoso.example'; family = 'SafeLinks'; setting = 'DisableURLRewrite'; value = $true
            approval = @{ reference = 'OFFLINE-EXCEPTION-010'; owner = 'security@contoso.example'; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') }
        })
        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:matrixModule | Where-Object ControlId -eq MDO-001
        # Assert
        $result.Result.Status | Should -BeExactly ApprovedException
        @($result.Evidence.Value.Matrix).Count | Should -Be 30
        @($result.Evidence.Value.Matrix | Where-Object { $_.Recipient -eq 'strict@contoso.example' -and $_.Family -ne 'HostedOutboundSpamFilter' } | ForEach-Object { $_['Policy'] } | Select-Object -Unique) | Should -Be @('Strict Preset Security Policy')
        @($result.Evidence.Observation | Where-Object Command -eq Get-Recipient).Arguments.ResultSize | Should -BeExactly Unlimited
        @($result.Evidence.Observation.Command | Where-Object { $_ -match '^[^-]+-(Mg|SPO|Teams)|Graph|AtpPolicyForO365|License' }).Count | Should -Be 0
    }
}