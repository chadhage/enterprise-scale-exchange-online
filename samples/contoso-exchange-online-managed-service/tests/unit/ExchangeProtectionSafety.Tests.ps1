BeforeAll {
    . (Join-Path $PSScriptRoot '../helpers/ExchangeProtectionFixture.ps1')
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:safetyModule = Import-Module (Join-Path $sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -PassThru
    function Invoke-EmailSafetyCheck {
        param($Fixture)
        Invoke-ProtectionRawRegistry $Fixture $script:safetyModule | Where-Object ControlId -eq MDO-001
    }
}
Describe 'EXR-010 managed protection boundaries' {
    It 'rejects an approved individual preset setting exception' {
        $fixture = New-ProtectionFixture
        $fixture.Context.Configuration.controls['MDO-001'].settingExceptions = @(@{
            recipient = 'user@contoso.example'; family = 'SafeLinks'; setting = 'AllowClickThrough'; value = $false
            approval = $fixture.Context.Configuration.controls['MDO-001'].approval.Clone()
        })
        $result = Invoke-EmailSafetyCheck $fixture
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match 'EmailProtectionException'
    }
    It 'rejects an approved individual built-in setting exception' {
        $fixture = New-ProtectionFixture
        $fixture.Context.Configuration.controls['MDO-001'].settingExceptions = @(@{
            recipient = 'default@contoso.example'; family = 'SafeLinks'; setting = 'AllowClickThrough'; value = $false
            approval = $fixture.Context.Configuration.controls['MDO-001'].approval.Clone()
        })
        $result = Invoke-EmailSafetyCheck $fixture
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match 'EmailProtectionException'
    }
    It 'does not call actual built-in Safe Links a Standard configuration' {
        $fixture = New-ProtectionFixture
        $policy = $fixture.Raw['Get-SafeLinksPolicy'].Items | Where-Object Name -eq 'Built-In Protection Policy'
        $policy.EnableForInternalSenders = $false
        $policy.DisableURLRewrite = $true
        $policy.AllowClickThrough = $true
        $result = Invoke-EmailSafetyCheck $fixture
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match 'EmailProtectionSettingDrift'
    }
    It 'rejects Defender recipients when tenant capability is absent' {
        $fixture = New-ProtectionFixture
        $fixture.Context.Entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE')
        $result = Invoke-EmailSafetyCheck $fixture
        $result.Result.Status | Should -BeExactly NotEntitled
        $result.Result.Reason | Should -Match 'EmailProtectionNotEntitled'
    }
    It 'rejects an unlicensed recipient inside a Defender preset' {
        $fixture = New-ProtectionFixture
        $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix[0].defender = $false
        $fixture.Context.Entitlement.recipients[0].servicePlans = @('EXCHANGE_S_ENTERPRISE')
        $result = Invoke-EmailSafetyCheck $fixture
        $result.Result.Status | Should -BeExactly NotEntitled
        $result.Result.Reason | Should -Match 'EmailProtectionNotEntitled'
    }
    It 'does not substitute local limited permissions for managed preset recommendations' {
        $configuration = Get-Content (Join-Path $sampleRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
        $configuration.controls['MDO-008'].endUserAccessLevel | Should -BeExactly FullAccess
        @($configuration.controls['MDO-008'].categoryPermissions | Where-Object accessLevel -eq LimitedAccess).Count | Should -Be 0
    }
}