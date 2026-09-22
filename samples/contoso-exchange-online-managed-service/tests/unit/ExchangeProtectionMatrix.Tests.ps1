BeforeDiscovery {
    . (Join-Path $PSScriptRoot '../helpers/ExchangeProtectionFixture.ps1')
    $reference = Get-ProtectionReferenceValues
    $settingCases = @(foreach ($family in $reference.Keys) { foreach ($field in $reference[$family].Keys) { @{ Family = $family; Field = $field } } })
}
BeforeAll {
    . (Join-Path $PSScriptRoot '../helpers/ExchangeProtectionFixture.ps1')
    $root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:matrixModule = Import-Module (Join-Path $root 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -PassThru
}
Describe 'EXR-010 effective email setting matrix' {
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