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
}
Describe 'EXR-010 capability-specific Exchange entitlement' {
    It 'does not skip drift in the EOP Standard matrix without Defender' {
        $fixture = New-EopProtectionFixture
        $fixture.Raw['Get-MalwareFilterPolicy'].Items[0].ZapEnabled = $false
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-001
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match EmailProtectionSettingDrift
    }
    It 'does not skip disabled EOP Strict scope without Defender' {
        $fixture = New-EopProtectionFixture
        $fixture.Raw['Get-EOPProtectionPolicyRule'].ByIdentity['Strict Preset Security Policy'][0].State = 'Disabled'
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq MDO-002
        $result.Result.Status | Should -BeExactly Fail
        $result.Result.Reason | Should -Match StrictPresetDrift
    }
    It 'does not make a tabletop cadence contingent on Defender Plan 2' {
        $fixture = New-EopProtectionFixture
        $result = Invoke-ProtectionRawRegistry $fixture $script:licensingModule | Where-Object ControlId -eq OPS-002
        $result.Result.Status | Should -BeExactly Error
        $result.Result.Reason | Should -Not -Match 'NotEntitled|THREAT_INTELLIGENCE'
    }
    It 'evaluates EOP settings while preserving unavailable Defender as NotEntitled' {
        $fixture = New-EopProtectionFixture
        $results = Invoke-ProtectionRawRegistry $fixture $script:licensingModule
        foreach ($control in @('MDO-001','MDO-002')) { ($results | Where-Object ControlId -eq $control).Result.Status | Should -BeExactly Pass }
        foreach ($control in @('MDO-003','MDO-009')) { ($results | Where-Object ControlId -eq $control).Result.Status | Should -BeExactly NotEntitled }
        $matrix = $results | Where-Object ControlId -eq MDO-001
        @($matrix.Evidence.Value.Matrix).Count | Should -Be 20
        @($matrix.Evidence.Observation.Command | Where-Object { $_ -match 'ATP|SafeLinks|SafeAttachment' }).Count | Should -Be 0
    }
}