BeforeDiscovery {
    . (Join-Path $PSScriptRoot '../helpers/ExchangeProtectionFixture.ps1')
    $standard = Get-ProtectionReferenceValues Standard
    $strict = Get-ProtectionReferenceValues Strict
    $standard.AntiPhish.TargetedUsersToProtect = @()
    $standard.AntiPhish.TargetedDomainsToProtect = @()
    $strict.AntiPhish.TargetedUsersToProtect = @()
    $strict.AntiPhish.TargetedDomainsToProtect = @()
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
    $defenderFields = @('PhishThresholdLevel','EnableTargetedUserProtection','EnableOrganizationDomainsProtection','EnableTargetedDomainsProtection','TargetedUsersToProtect','TargetedDomainsToProtect','ExcludedSenders','ExcludedDomains','EnableMailboxIntelligence','EnableMailboxIntelligenceProtection','TargetedUserProtectionAction','TargetedDomainProtectionAction','TargetedUserQuarantineTag','TargetedDomainQuarantineTag','MailboxIntelligenceProtectionAction','MailboxIntelligenceQuarantineTag','EnableSimilarUsersSafetyTips','EnableSimilarDomainsSafetyTips','EnableUnusualCharactersSafetyTips')
    $catalogContract = @{
        Version = '1.0.0'
        ReviewedOn = '2026-09-21'
        Source = 'https://learn.microsoft.com/defender-office-365/recommended-settings-for-eop-and-office365'
        SourceCommit = '379db33154f4d944dbb33fce80576aff5296dfbf'
        FileTypesSource = 'https://learn.microsoft.com/defender-office-365/anti-malware-protection-about#common-attachments-filter-in-anti-malware-policies'
        FileTypesSourceCommit = 'a303cf1b405a37ff173ff70117802d92b98ccc05'
        FileTypesSourceSha256 = '95D86CFB11658B9058F3ADDD54300F33D0764F1FCE4B938A8FA67085792FFCC8'
        Excluded = @('EnableATPForSPOTeamsODB','EnableSafeDocs','AllowSafeDocsOpen','EnableSafeLinksForTeams','EnableSafeLinksForOffice','TeamsProtectionPolicy')
        Families = @{}
    }
    foreach ($family in $standard.Keys) {
        $overrides = @{}
        foreach ($field in $standard[$family].Keys) {
            if (($standard[$family][$field] | ConvertTo-Json -Compress) -cne ($strict[$family][$field] | ConvertTo-Json -Compress)) {
                $overrides[$field] = $strict[$family][$field]
            }
        }
        $catalogContract.Families[$family] = @{
            Section = $sections[$family]
            Plan = $(if ($family -in @('SafeLinks','SafeAttachment')) { 'Defender' } elseif ($family -eq 'AntiPhish') { 'ExchangeAndDefender' } else { 'Exchange' })
            Local = $localFields[$family]
            Standard = $standard[$family]
            Strict = $overrides
        }
    }
    $catalogContract.Families.AntiPhish.DefenderFields = $defenderFields
    $catalogContract.Families.SafeLinks.BuiltIn = @{ EnableForInternalSenders = $false; DisableURLRewrite = $true; AllowClickThrough = $true }
    $catalogContract.Families.SafeAttachment.BuiltIn = @{}
    $contractJson = $catalogContract | ConvertTo-Json -Depth 100
    $catalogNegatives = [Collections.Generic.List[object]]::new()
    $addNegative = {
        param([string]$Case, [string]$Field, [scriptblock]$Mutate)
        $candidate = $contractJson | ConvertFrom-Json -AsHashtable
        $null = & $Mutate $candidate
        $catalogNegatives.Add(@{ Case = $Case; Field = $Field; Json = ($candidate | ConvertTo-Json -Depth 100) })
    }
    foreach ($family in @($standard.Keys | Sort-Object)) {
        & $addNegative "missing family $family" $family { param($candidate) $candidate.Families.Remove($family) }
        foreach ($metadata in @('Section','Plan','Local','Standard','Strict')) {
            & $addNegative "missing $family/$metadata" $metadata { param($candidate) $candidate.Families[$family].Remove($metadata) }
        }
        & $addNegative "unbound section for $family" 'Section' { param($candidate) $candidate.Families[$family].Section = 'Microsoft Teams protection settings' }
        & $addNegative "wrong applicability for $family" 'Plan' { param($candidate) $candidate.Families[$family].Plan = $(if ($family -eq 'SafeLinks' -or $family -eq 'SafeAttachment') { 'Exchange' } else { 'Defender' }) }
        & $addNegative "unknown applicability for $family" 'Plan' { param($candidate) $candidate.Families[$family].Plan = 'Microsoft 365 E5' }
        & $addNegative "unsupported Local member for $family" 'InventedEmailSetting' { param($candidate) $candidate.Families[$family].Local += 'InventedEmailSetting' }
        & $addNegative "fabricated ApprovedException catalogue label for $family" 'Basis' { param($candidate) $candidate.Families[$family].Basis = 'ApprovedException' }
        & $addNegative "fabricated MicrosoftDefault catalogue label for $family" 'Basis' { param($candidate) $candidate.Families[$family].Basis = 'MicrosoftDefault' }
        foreach ($field in @($standard[$family].Keys | Sort-Object)) {
            & $addNegative "missing Standard $family/$field" $field { param($candidate) $candidate.Families[$family].Standard.Remove($field) }
            $expected = $standard[$family][$field]
            $wrongType = if ($expected -is [bool]) { 'true' } elseif ($expected -is [int]) { '6' } elseif ($expected -is [array]) { 'not-an-array' } else { $false }
            $profiles = @('Standard','Strict')
            if ($family -in @('SafeLinks','SafeAttachment')) { $profiles += 'BuiltIn' }
            foreach ($profileName in $profiles) {
                & $addNegative "wrong JSON type $family/$profileName/$field" $field { param($candidate) $candidate.Families[$family][$profileName][$field] = $wrongType }
                if ($expected -is [array]) {
                    & $addNegative "non-string array member $family/$profileName/$field" $field { param($candidate) $candidate.Families[$family][$profileName][$field] = @(17) }
                    & $addNegative "null array member $family/$profileName/$field" $field { param($candidate) $candidate.Families[$family][$profileName][$field] = @($null) }
                }
                if ($field -notin $localFields[$family]) {
                    $drift = if ($expected -is [bool]) { -not $expected } elseif ($expected -is [int]) { 2 } elseif ($expected -is [array]) { @('invented.example') } else { 'InventedAction' }
                    if ($profileName -eq 'BuiltIn' -and $catalogContract.Families[$family].BuiltIn.ContainsKey($field)) { $drift = -not $catalogContract.Families[$family].BuiltIn[$field] }
                    & $addNegative "unbound recommendation $family/$profileName/$field" $field { param($candidate) $candidate.Families[$family][$profileName][$field] = $drift }
                }
            }
            if ($field -in $localFields[$family]) {
                & $addNegative "local choice mislabeled MicrosoftRecommendation $family/$field" $field { param($candidate) $candidate.Families[$family].Local = @($candidate.Families[$family].Local | Where-Object { $_ -ne $field }) }
            } else {
                & $addNegative "Microsoft recommendation mislabeled LocalPolicy $family/$field" $field { param($candidate) $candidate.Families[$family].Local += $field }
            }
        }
        foreach ($field in $catalogContract.Families[$family].Strict.Keys) {
            & $addNegative "Strict silently inherits Standard $family/$field" $field { param($candidate) $candidate.Families[$family].Strict.Remove($field) }
        }
        foreach ($profileName in @('Standard','Strict')) {
            & $addNegative "unsupported field $family/$profileName" 'InventedEmailSetting' { param($candidate) $candidate.Families[$family][$profileName].InventedEmailSetting = $true }
        }
        if ($localFields[$family].Count) {
            & $addNegative "duplicate Local member $family" 'Local' { param($candidate) $candidate.Families[$family].Local += $candidate.Families[$family].Local[0] }
        }
    }
    foreach ($metadata in @('Version','ReviewedOn','Source','SourceCommit','FileTypesSource','FileTypesSourceCommit','FileTypesSourceSha256','Excluded','Families')) {
        & $addNegative "missing root $metadata" $metadata { param($candidate) $candidate.Remove($metadata) }
        & $addNegative "null root $metadata" $metadata { param($candidate) $candidate[$metadata] = $null }
    }
    foreach ($reviewDate in @('2000-01-01','not-a-date','9999-12-31','2026-02-30')) {
        & $addNegative "stale malformed or future review $reviewDate" 'ReviewedOn' { param($candidate) $candidate.ReviewedOn = $reviewDate }
    }
    foreach ($source in @('https://example.invalid/recommendations','https://learn.microsoft.com/defender-office-365/preset-security-policies')) {
        & $addNegative "unbound recommendation source $source" 'Source' { param($candidate) $candidate.Source = $source }
    }
    foreach ($commit in @('main','0000000000000000000000000000000000000000')) {
        & $addNegative "unbound source revision $commit" 'SourceCommit' { param($candidate) $candidate.SourceCommit = $commit }
    }
    & $addNegative 'unbound attachment-list source' 'FileTypesSource' { param($candidate) $candidate.FileTypesSource = $candidate.Source }
    foreach ($commit in @('main','0000000000000000000000000000000000000000')) {
        & $addNegative "unbound attachment-list FileTypesSourceCommit $commit" 'FileTypesSourceCommit' { param($candidate) $candidate.FileTypesSourceCommit = $commit }
    }
    foreach ($digest in @('not-a-sha256',('0' * 64))) {
        & $addNegative "unbound attachment-list FileTypesSourceSha256 $digest" 'FileTypesSourceSha256' { param($candidate) $candidate.FileTypesSourceSha256 = $digest }
    }
    & $addNegative 'unsupported catalogue version' 'Version' { param($candidate) $candidate.Version = '999.0.0' }
    & $addNegative 'unsupported collaboration family' 'TeamsProtectionPolicy' { param($candidate) $candidate.Families.TeamsProtectionPolicy = @{ Standard = @{ ZapEnabled = $true }; Strict = @{} } }
    & $addNegative 'ApprovedException is not a catalogue profile' 'ApprovedException' { param($candidate) $candidate.Families.SafeLinks.ApprovedException = @{ AllowClickThrough = $true } }
    foreach ($field in $catalogContract.Excluded) {
        foreach ($profileName in @('Standard','Strict','BuiltIn')) {
            & $addNegative "excluded workload field $profileName/$field" $field { param($candidate) $candidate.Families.SafeLinks[$profileName][$field] = $true }
        }
        & $addNegative "missing exclusion $field" $field { param($candidate) $candidate.Excluded = @($candidate.Excluded | Where-Object { $_ -ne $field }) }
    }
    & $addNegative 'duplicate exclusion' 'Excluded' { param($candidate) $candidate.Excluded += 'EnableSafeDocs' }
    & $addNegative 'missing mixed-plan field applicability' 'DefenderFields' { param($candidate) $candidate.Families.AntiPhish.Remove('DefenderFields') }
    & $addNegative 'duplicate mixed-plan field applicability' 'DefenderFields' { param($candidate) $candidate.Families.AntiPhish.DefenderFields += 'PhishThresholdLevel' }
    & $addNegative 'spoof field wrongly requires Defender' 'EnableSpoofIntelligence' { param($candidate) $candidate.Families.AntiPhish.DefenderFields += 'EnableSpoofIntelligence' }
    foreach ($field in $defenderFields) {
        & $addNegative "Defender-only field mislabeled Exchange $field" $field { param($candidate) $candidate.Families.AntiPhish.DefenderFields = @($candidate.Families.AntiPhish.DefenderFields | Where-Object { $_ -ne $field }) }
    }
    foreach ($family in @('SafeLinks','SafeAttachment')) {
        & $addNegative "missing explicit BuiltIn profile $family" 'BuiltIn' { param($candidate) $candidate.Families[$family].Remove('BuiltIn') }
        & $addNegative "null BuiltIn profile $family" 'BuiltIn' { param($candidate) $candidate.Families[$family].BuiltIn = $null }
        & $addNegative "unsupported BuiltIn field $family" 'InventedEmailSetting' { param($candidate) $candidate.Families[$family].BuiltIn.InventedEmailSetting = $true }
    }
    foreach ($field in $catalogContract.Families.SafeLinks.BuiltIn.Keys) {
        & $addNegative "BuiltIn silently inherits Standard SafeLinks/$field" $field { param($candidate) $candidate.Families.SafeLinks.BuiltIn.Remove($field) }
    }
    & $addNegative 'synthetic Standard defaults as BuiltIn SafeLinks' 'BuiltIn' { param($candidate) $candidate.Families.SafeLinks.BuiltIn = $candidate.Families.SafeLinks.Standard.Clone() }
    & $addNegative 'custom disabled SafeAttachment mistaken for BuiltIn' 'Enable' { param($candidate) $candidate.Families.SafeAttachment.BuiltIn.Enable = $false }
    & $addNegative 'invented BuiltIn profile for anti-spam' 'BuiltIn' { param($candidate) $candidate.Families.HostedContentFilter.BuiltIn = @{} }
    & $addNegative 'fractional spam threshold' 'BulkThreshold' { param($candidate) $candidate.Families.HostedContentFilter.Standard.BulkThreshold = 6.5 }
    & $addNegative 'null string setting' 'FileTypeAction' { param($candidate) $candidate.Families.MalwareFilter.Standard.FileTypeAction = $null }
    & $addNegative 'null list setting' 'FileTypes' { param($candidate) $candidate.Families.MalwareFilter.Standard.FileTypes = $null }
    & $addNegative 'null Boolean Strict override' 'ZapEnabled' { param($candidate) $candidate.Families.MalwareFilter.Strict.ZapEnabled = $null }
    foreach ($duplicate in @(
        @{ Case = 'duplicate root source'; Original = '"SourceCommit":'; Replacement = '"SourceCommit":"0000000000000000000000000000000000000000","SourceCommit":'; Field = 'SourceCommit' }
        @{ Case = 'duplicate Standard field'; Original = '"EnableFileFilter":'; Replacement = '"EnableFileFilter":false,"EnableFileFilter":'; Field = 'EnableFileFilter' }
        @{ Case = 'case-colliding Standard field'; Original = '"EnableFileFilter":'; Replacement = '"enablefilefilter":false,"EnableFileFilter":'; Field = 'EnableFileFilter' }
        @{ Case = 'duplicate Strict field'; Original = '"PhishThresholdLevel": 4'; Replacement = '"PhishThresholdLevel":3,"PhishThresholdLevel":4'; Field = 'PhishThresholdLevel' }
        @{ Case = 'duplicate BuiltIn field'; Original = '"DisableURLRewrite": true'; Replacement = '"DisableURLRewrite":false,"DisableURLRewrite":true'; Field = 'DisableURLRewrite' }
    )) {
        $catalogNegatives.Add(@{ Case = $duplicate.Case; Field = $duplicate.Field; Json = $contractJson.Replace($duplicate.Original, $duplicate.Replacement) })
    }
    $sourceEvidenceCases = @(
        @{
            Case = 'captured source provenance'
            Patterns = @(
                '(?im)^.*recommended-current\.md.*379db33154f4d944dbb33fce80576aff5296dfbf.*62C0BCA45F818F55D44E1914F7E83B739F67FAF633DD2DCE1A40A0E33E41CF5F.*$'
                '(?im)^.*recommended-pinned\.md.*379db33154f4d944dbb33fce80576aff5296dfbf.*527E7504482B0C8E47DF5030AFD5822B53C20D70223A7EC8DC60CD2123713D31.*$'
                '(?im)^.*file-types-current\.md.*a303cf1b405a37ff173ff70117802d92b98ccc05.*95D86CFB11658B9058F3ADDD54300F33D0764F1FCE4B938A8FA67085792FFCC8.*$'
                [regex]::Escape('https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365')
                [regex]::Escape('https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about')
                '2026-08-10'
                '2026-06-09'
                'common-attachments-filter-in-anti-malware-policies'
                '(?im)^.*captured.*(?:representation|rendered|markdown).*(?:digest|SHA-256).*$'
                '(?im)^.*(?:not|no).*(?:latest|future).*$'
                'FileTypesSourceCommit'
                'FileTypesSourceSha256'
            )
        }
        @{
            Case = 'field classification and capability mapping'
            Patterns = @(
                '(?im)^.*MicrosoftRecommendation.*LocalPolicy.*ApprovedException.*$'
                '(?im)^.*(?:classification|capability).*(?:not|distinct|separate).*(?:operational|mutation|support).*$'
                foreach ($family in @($catalogContract.Families.Keys | Sort-Object)) {
                    '(?im)^.*' + [regex]::Escape($family) + '.*' + [regex]::Escape($sections[$family]) + '.*' + [regex]::Escape($catalogContract.Families[$family].Plan) + '.*$'
                    foreach ($field in $standard[$family].Keys) {
                        $classification = if ($field -in $localFields[$family]) { 'LocalPolicy' } else { 'MicrosoftRecommendation' }
                        $capability = if ($family -in @('SafeLinks','SafeAttachment') -or ($family -eq 'AntiPhish' -and $field -in $defenderFields)) { 'Defender' } else { 'Exchange' }
                        '(?im)^.*' + [regex]::Escape($family) + '.*' + [regex]::Escape($field) + '.*' + $classification + '.*' + $capability + '.*$'
                    }
                }
            )
        }
        @{
            Case = 'conditional operational qualifications'
            Patterns = @(
                '(?im)^.*BccSuspiciousOutboundMail.*BccSuspiciousOutboundAdditionalRecipients.*default.policy.only.*$'
                '(?im)^.*(?:HostedOutboundSpamFilter|outbound spam).*(?:outside|not (?:part of|included in)).*preset.*$'
                '(?im)^.*EnableBlockingEncryptedAttachments.*Enable.*(?:\$true|true).*Action.*Block.*$'
                '(?im)^.*ExcludedTypesFromBlockingEncryptedAttachments.*QuarantineTagForBlockingEncryptedAttachments.*EnableBlockingEncryptedAttachments.*(?:\$true|true).*$'
                '(?im)^.*encrypted.*conditional.*(?:not|never).*universal.*$'
                '(?im)^.*(?:not|no).*(?:raw getter|getter shape).*(?:live compatibility|live support).*$'
            )
        }
        @{
            Case = 'encrypted attachment cmdlet uncertainty'
            Patterns = @(
                '(?im)^.*new-safeattachmentpolicy\.md.*eda2c42b9b7ab27352dc773176c89e6dee6df78e.*512966D5327D648C3F2C95975EEA7F19B253DD7182688826973045BE54BD950D.*$'
                '(?im)^.*set-safeattachmentpolicy\.md.*372c15f972287c9e0d2579f996636ed5ad6951e3.*4D7E29459193B2DBCEA5B060390BB981097013DA46503AA22C3B8F0E492F7030.*$'
                '(?im)^.*set-hostedoutboundspamfilterpolicy\.md.*589c47eee8c4444079d9edb1967f534a950deb08.*0929B3A4716E60AEDCEE24A70B5AF11111078289B8B19C6AA7E0E3504ADC9DE6.*$'
                [regex]::Escape('https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-safeattachmentpolicy?view=exchange-ps')
                [regex]::Escape('https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-safeattachmentpolicy?view=exchange-ps')
                [regex]::Escape('https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-hostedoutboundspamfilterpolicy?view=exchange-ps')
                '2017-09-25'
                'Safe Attachments policy settings'
                'Outbound spam policy settings'
                'Parameters'
                foreach ($field in @('EnableBlockingEncryptedAttachments','ExcludedTypesFromBlockingEncryptedAttachments','QuarantineTagForBlockingEncryptedAttachments')) {
                    '(?im)^.*' + $field + '.*recommendation.*(?:absent|not (?:listed|present)).*New-SafeAttachmentPolicy.*Set-SafeAttachmentPolicy.*(?:uncertain|unverified|unconfirmed).*$'
                }
                '(?im)^.*(?:not|no).*(?:supported mutation|mutation support).*$'
            )
        }
    )
    $localCustomizations = @{
        MalwareFilter = @{
            EnableInternalSenderAdminNotifications = $true
            InternalSenderAdminAddress = 'internal-alerts@contoso.example'
            EnableExternalSenderAdminNotifications = $true
            ExternalSenderAdminAddress = 'external-alerts@contoso.example'
            CustomNotifications = $true
            CustomFromName = 'Contoso Security'
            CustomFromAddress = 'security@contoso.example'
            CustomInternalSubject = 'Internal malware notification'
            CustomInternalBody = 'Contact Contoso Security about this internal message.'
            CustomExternalSubject = 'External malware notification'
            CustomExternalBody = 'Contact Contoso Security about this external message.'
        }
        HostedContentFilter = @{
            EnableLanguageBlockList = $true
            LanguageBlockList = @('FR')
            EnableRegionBlockList = $true
            RegionBlockList = @('FR')
        }
        AntiPhish = @{
            TargetedUsersToProtect = @('Security;security@contoso.example')
            TargetedDomainsToProtect = @('contoso.example')
            ExcludedSenders = @('trusted@partner.example')
            ExcludedDomains = @('partner.example')
        }
        SafeLinks = @{
            DoNotRewriteUrls = @('https://trusted.contoso.example/')
            EnableOrganizationBranding = $true
            CustomNotificationText = 'Contact Contoso Security before continuing.'
            UseTranslatedNotificationText = $true
        }
    }
    $customizedContract = $contractJson | ConvertFrom-Json -AsHashtable
    foreach ($family in $localCustomizations.Keys) {
        $profiles = @('Standard','Strict')
        if ($family -eq 'SafeLinks') { $profiles += 'BuiltIn' }
        foreach ($profileName in $profiles) {
            foreach ($field in $localCustomizations[$family].Keys) {
                $customizedContract.Families[$family][$profileName][$field] = $localCustomizations[$family][$field]
            }
        }
    }
    $admissionCases = @(
        @{ Variant = 'shipped artifact'; ExpectedCatalog = $catalogContract; ReferenceCatalog = $catalogContract; CandidateJson = $null; LocalChoices = $null }
        @{ Variant = 'all 23 nondefault local fields'; ExpectedCatalog = $customizedContract; ReferenceCatalog = $catalogContract; CandidateJson = ($customizedContract | ConvertTo-Json -Depth 100); LocalChoices = $localCustomizations }
    )
}

BeforeAll {
    $root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $root 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force
}

Describe 'EXR-010-A01 email setting catalogue types' {
    It 'rejects null instead of an integer for HostedContentFilter Standard BulkThreshold' {
        InModuleScope ExchangeOnlineBaseline.Common {
            # Arrange
            $catalogPath = Join-Path (Get-Module ExchangeOnlineBaseline.Common).ModuleBase '../config/exchange-email-settings.v1.json'
            $catalog = Get-Content -LiteralPath $catalogPath -Raw | ConvertFrom-Json -AsHashtable
            $catalog.Families.SafeLinks.BuiltIn = @{ EnableForInternalSenders = $false; DisableURLRewrite = $true; AllowClickThrough = $true }
            $catalog.Families.SafeAttachment.BuiltIn = @{}
            $catalog.Families.HostedContentFilter.Standard.BulkThreshold = $null
            $script:invalidEmailSettingCatalogJson = $catalog | ConvertTo-Json -Depth 100
            Mock Get-Content { $script:invalidEmailSettingCatalogJson } -ParameterFilter {
                $LiteralPath -match '[\\/]config[\\/]exchange-email-settings\.v1\.json$' -and $Raw
            }
            $rejection = $null

            # Act
            try { $null = Get-BaselineEmailSettingCatalog } catch { $rejection = $_ }

            # Assert
            $rejection | Should -Not -BeNullOrEmpty -Because 'BulkThreshold requires an integer, not null'
            $rejection.Exception.Message | Should -Match 'BulkThreshold'
        }
    }

    It 'rejects a string instead of a boolean for MalwareFilter Standard EnableFileFilter' {
        InModuleScope ExchangeOnlineBaseline.Common {
            # Arrange
            $catalogPath = Join-Path (Get-Module ExchangeOnlineBaseline.Common).ModuleBase '../config/exchange-email-settings.v1.json'
            $catalog = Get-Content -LiteralPath $catalogPath -Raw | ConvertFrom-Json -AsHashtable
            $catalog.Families.SafeLinks.BuiltIn = @{ EnableForInternalSenders = $false; DisableURLRewrite = $true; AllowClickThrough = $true }
            $catalog.Families.SafeAttachment.BuiltIn = @{}
            $catalog.Families.MalwareFilter.Standard.EnableFileFilter = 'true'
            $script:invalidEmailSettingCatalogJson = $catalog | ConvertTo-Json -Depth 100
            Mock Get-Content { $script:invalidEmailSettingCatalogJson } -ParameterFilter {
                $LiteralPath -match '[\\/]config[\\/]exchange-email-settings\.v1\.json$' -and $Raw
            }
            $rejection = $null

            # Act
            try {
                $null = Get-BaselineEmailSettingCatalog
            } catch {
                $rejection = $_
            }

            # Assert
            Should -Invoke Get-Content -Times 1 -Exactly -Scope It -ParameterFilter {
                $LiteralPath -match '[\\/]config[\\/]exchange-email-settings\.v1\.json$' -and $Raw
            }
            $rejection | Should -Not -BeNullOrEmpty -Because 'the catalogue loader must reject a JSON string for boolean EnableFileFilter'
            $rejection.Exception.Message | Should -Match 'EnableFileFilter'
            $rejection.Exception.Message | Should -Match '(?i)bool'
        }
    }
}

Describe 'EXR-010-A01 bounded catalogue admission' {
    It 'rejects <Case>' -ForEach @($catalogNegatives | Where-Object Field -NotIn @('FileTypesSourceCommit','FileTypesSourceSha256')) {
        InModuleScope ExchangeOnlineBaseline.Common -Parameters @{ Json = $Json; Field = $Field; Case = $Case } {
            param($Json, $Field, $Case)
            # Arrange
            $script:invalidEmailSettingCatalogJson = $Json
            Mock Get-Content { $script:invalidEmailSettingCatalogJson } -ParameterFilter {
                $LiteralPath -match '[\\/]config[\\/]exchange-email-settings\.v1\.json$' -and $Raw
            }
            $rejection = $null

            # Act
            try { $null = Get-BaselineEmailSettingCatalog } catch { $rejection = $_ }

            # Assert
            Should -Invoke Get-Content -Times 1 -Exactly -Scope It -ParameterFilter {
                $LiteralPath -match '[\\/]config[\\/]exchange-email-settings\.v1\.json$' -and $Raw
            }
            $rejection | Should -Not -BeNullOrEmpty -Because $Case
            $rejection.Exception.Message | Should -Match ([regex]::Escape($Field))
        }
    }

    It 'rejects attachment source binding <Case>' -ForEach @($catalogNegatives | Where-Object Field -In @('FileTypesSourceCommit','FileTypesSourceSha256')) {
        InModuleScope ExchangeOnlineBaseline.Common -Parameters @{ Json = $Json; Field = $Field; Case = $Case } {
            param($Json, $Field, $Case)
            # Arrange
            $script:invalidEmailSettingCatalogJson = $Json
            Mock Get-Content { $script:invalidEmailSettingCatalogJson } -ParameterFilter {
                $LiteralPath -match '[\\/]config[\\/]exchange-email-settings\.v1\.json$' -and $Raw
            }
            $rejection = $null

            # Act
            try { $null = Get-BaselineEmailSettingCatalog } catch { $rejection = $_ }

            # Assert
            Should -Invoke Get-Content -Times 1 -Exactly -Scope It -ParameterFilter {
                $LiteralPath -match '[\\/]config[\\/]exchange-email-settings\.v1\.json$' -and $Raw
            }
            $rejection | Should -Not -BeNullOrEmpty -Because $Case
            $rejection.Exception.Message | Should -Match ([regex]::Escape($Field))
        }
    }

    It 'maps one complete dated catalogue to all 247 applicable profile-field assertions: <Variant>' -ForEach $admissionCases {
        InModuleScope ExchangeOnlineBaseline.Common -Parameters @{ ExpectedCatalog = $ExpectedCatalog; ReferenceCatalog = $ReferenceCatalog; CandidateJson = $CandidateJson; LocalChoices = $LocalChoices } {
            param($ExpectedCatalog, $ReferenceCatalog, $CandidateJson, $LocalChoices)
            # Arrange
            $violations = [Collections.Generic.List[string]]::new()
            $mapped = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $validatedLocalChoices = 0
            if ($CandidateJson) {
                foreach ($family in $LocalChoices.Keys) {
                    if ((@($LocalChoices[$family].Keys | Sort-Object) -join '|') -cne (@($ReferenceCatalog.Families[$family].Local | Sort-Object) -join '|')) { throw "Incomplete independent local candidate for $family" }
                    foreach ($field in $LocalChoices[$family].Keys) {
                        $choice = $LocalChoices[$family][$field]
                        $valid = switch -Regex ($field) {
                            '^(EnableInternalSenderAdminNotifications|EnableExternalSenderAdminNotifications|CustomNotifications|EnableLanguageBlockList|EnableRegionBlockList|EnableOrganizationBranding|UseTranslatedNotificationText)$' { $choice -is [bool] -and $choice }
                            '^(InternalSenderAdminAddress|ExternalSenderAdminAddress|CustomFromAddress)$' { $choice -is [string] -and [Net.Mail.MailAddress]::new($choice).Address -ceq $choice }
                            '^(LanguageBlockList|RegionBlockList)$' { $choice -is [array] -and $choice.Count -eq 1 -and $choice[0] -ceq 'FR' }
                            '^TargetedUsersToProtect$' { $choice -is [array] -and $choice.Count -eq 1 -and $choice[0] -cmatch '^[A-Za-z ]+;[a-z]+@contoso\.example$' }
                            '^(TargetedDomainsToProtect|ExcludedDomains)$' { $choice -is [array] -and $choice.Count -eq 1 -and [uri]::CheckHostName($choice[0]) -eq [UriHostNameType]::Dns }
                            '^ExcludedSenders$' { $choice -is [array] -and $choice.Count -eq 1 -and [Net.Mail.MailAddress]::new($choice[0]).Address -ceq $choice[0] }
                            '^DoNotRewriteUrls$' { $choice -is [array] -and $choice.Count -eq 1 -and [uri]::IsWellFormedUriString($choice[0], [UriKind]::Absolute) -and ([uri]$choice[0]).Scheme -ceq 'https' }
                            default { $choice -is [string] -and -not [string]::IsNullOrWhiteSpace($choice) }
                        }
                        $unchanged = (ConvertTo-Json -InputObject $choice -Compress) -ceq (ConvertTo-Json -InputObject $ReferenceCatalog.Families[$family].Standard[$field] -Compress)
                        if (-not $valid -or $unchanged) { throw "Invalid or default independent local candidate $family/$field" }
                        $validatedLocalChoices++
                    }
                }
                if ($validatedLocalChoices -ne 23) { throw 'Independent candidate must customize all 23 local fields' }
                $script:validEmailSettingCatalogJson = $CandidateJson
                Mock Get-Content { $script:validEmailSettingCatalogJson } -ParameterFilter {
                    $LiteralPath -match '[\\/]config[\\/]exchange-email-settings\.v1\.json$' -and $Raw
                }
            }

            # Act
            $actual = Get-BaselineEmailSettingCatalog

            # Assert
            if ($CandidateJson) {
                $validatedLocalChoices | Should -Be 23
                Should -Invoke Get-Content -Times 1 -Exactly -Scope It -ParameterFilter {
                    $LiteralPath -match '[\\/]config[\\/]exchange-email-settings\.v1\.json$' -and $Raw
                }
            }
            foreach ($metadata in @('Version','Source','SourceCommit','FileTypesSource','FileTypesSourceCommit','FileTypesSourceSha256')) {
                if ($actual[$metadata] -cne $ExpectedCatalog[$metadata]) { $violations.Add("Unbound $metadata") }
            }
            $reviewed = [datetime]::MinValue
            if (-not [datetime]::TryParseExact([string]$actual.ReviewedOn, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$reviewed) -or
                $reviewed -lt [datetime]'2026-08-10' -or $reviewed -gt [datetime]::UtcNow.Date) { $violations.Add('ReviewedOn is malformed, predates the pinned source, or is in the future') }
            if ((@($actual.Excluded | Sort-Object) -join '|') -cne (@($ExpectedCatalog.Excluded | Sort-Object) -join '|')) { $violations.Add('Incomplete excluded workloads') }
            if ((@($actual.Families.Keys | Sort-Object) -join '|') -cne (@($ExpectedCatalog.Families.Keys | Sort-Object) -join '|')) { $violations.Add('Incomplete email families') }
            foreach ($family in $ExpectedCatalog.Families.Keys) {
                $expectedDefinition = $ExpectedCatalog.Families[$family]
                $definition = $actual.Families[$family]
                if (-not $definition) { $violations.Add("Missing $family"); continue }
                foreach ($metadata in @('Section','Plan')) {
                    if ($definition[$metadata] -cne $expectedDefinition[$metadata]) { $violations.Add("Unbound $family/$metadata") }
                }
                foreach ($metadata in @('Local','DefenderFields')) {
                    if ((@($definition[$metadata] | Sort-Object) -join '|') -cne (@($expectedDefinition[$metadata] | Sort-Object) -join '|')) { $violations.Add("Invalid $family/$metadata classification") }
                }
                if ((@($definition.Standard.Keys | Sort-Object) -join '|') -cne (@($expectedDefinition.Standard.Keys | Sort-Object) -join '|')) { $violations.Add("Incomplete $family/Standard fields") }
                $profiles = @('Standard','Strict')
                if ($family -in @('SafeLinks','SafeAttachment')) { $profiles += 'BuiltIn' }
                foreach ($profileName in $profiles) {
                    if (-not $definition.ContainsKey($profileName) -or $definition[$profileName] -isnot [System.Collections.IDictionary]) { $violations.Add("Missing explicit $family/$profileName profile"); continue }
                    $expectedValues = $expectedDefinition.Standard.Clone()
                    $actualValues = $definition.Standard.Clone()
                    if ($profileName -ne 'Standard') {
                        foreach ($field in $expectedDefinition[$profileName].Keys) { $expectedValues[$field] = $expectedDefinition[$profileName][$field] }
                        foreach ($field in $definition[$profileName].Keys) { $actualValues[$field] = $definition[$profileName][$field] }
                    }
                    if ((@($actualValues.Keys | Sort-Object) -join '|') -cne (@($expectedValues.Keys | Sort-Object) -join '|')) { $violations.Add("Unexpected $family/$profileName fields") }
                    foreach ($field in $expectedValues.Keys) {
                        $identity = "$family/$profileName/$field"
                        if (-not $mapped.Add($identity)) { $violations.Add("Duplicate assertion $identity") }
                        $expected = $expectedValues[$field]
                        $observed = $actualValues[$field]
                        $typed = if ($expected -is [bool]) { $observed -is [bool] } elseif ($expected -is [int] -or $expected -is [long]) { $observed -is [int] -or $observed -is [long] } elseif ($expected -is [array]) { $observed -is [array] -and @($observed | Where-Object { $_ -isnot [string] }).Count -eq 0 } else { $observed -is [string] }
                        if (-not $typed) { $violations.Add("Wrong JSON type $identity"); continue }
                        if ($CandidateJson -or $field -notin $expectedDefinition.Local) {
                            $valuesMatch = if ($expected -is [array]) { (@($observed | Sort-Object) -join '|') -ceq (@($expected | Sort-Object) -join '|') } else { (ConvertTo-Json -InputObject $observed -Compress) -ceq (ConvertTo-Json -InputObject $expected -Compress) }
                            if (-not $valuesMatch) { $violations.Add("Unbound or reset catalogue value $identity") }
                        }
                        if ($CandidateJson -and $field -in $expectedDefinition.Local) {
                            if ((ConvertTo-Json -InputObject $definition[$profileName][$field] -Compress) -cne (ConvertTo-Json -InputObject $expectedDefinition[$profileName][$field] -Compress)) { $violations.Add("LocalPolicy override not preserved $identity") }
                        }
                    }
                }
            }
            if ($mapped.Count -ne 247) { $violations.Add("Mapped $($mapped.Count) of 247 applicable profile-fields") }
            $violations.Count | Should -Be 0 -Because ($violations -join '; ')
        }
    }
}

Describe 'EXR-010-A01 durable source evidence' {
    It 'rejects absent or incomplete <Case>' -ForEach $sourceEvidenceCases {
        # Arrange
        $documentPath = Join-Path $root 'docs/EMAIL-SETTINGS-SOURCES.md'
        $violations = [Collections.Generic.List[string]]::new()

        # Act
        $document = Get-Content -LiteralPath $documentPath -Raw -ErrorAction SilentlyContinue

        # Assert
        if ([string]::IsNullOrWhiteSpace($document)) { $violations.Add('Missing durable source document') }
        foreach ($pattern in $Patterns) {
            if ("$document" -notmatch $pattern) { $violations.Add("Missing $Case evidence: $pattern") }
        }
        $reviewMatch = [regex]::Match("$document", '(?im)^ReviewedOn:\s*(\d{4}-\d{2}-\d{2})\s*$')
        $reviewed = [datetime]::MinValue
        if (-not $reviewMatch.Success -or -not [datetime]::TryParseExact($reviewMatch.Groups[1].Value, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$reviewed) -or
            $reviewed -lt [datetime]'2026-08-10' -or $reviewed -gt [datetime]::UtcNow.Date) { $violations.Add('Missing or invalid dated source review') }
        $violations.Count | Should -Be 0 -Because ($violations -join '; ')
    }
}