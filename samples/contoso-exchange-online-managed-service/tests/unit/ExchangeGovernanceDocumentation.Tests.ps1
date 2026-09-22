BeforeAll {
    $script:sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:runbooks = Get-Content (Join-Path $script:sampleRoot 'docs/RUNBOOKS.md') -Raw
    $script:implementation = Get-Content (Join-Path $script:sampleRoot 'docs/IMPLEMENTATION-GUIDE.md') -Raw
    $script:governanceSection = [regex]::Match($script:runbooks, '(?s)### R-GOV-001.*?## Completion gate').Value
}
Describe 'EXR-009 active governance documentation contract' {
    It 'does not prescribe external tenant provisioning command <Command>' -ForEach @(
        'New-UnifiedAuditLogRetentionPolicy','New-DlpCompliancePolicy','New-DlpComplianceRule',
        'Set-DlpCompliancePolicy','New-RetentionCompliancePolicy','New-RetentionComplianceRule',
        'Get-LabelPolicy','Get-ComplianceCase'
    | ForEach-Object { @{ Command = $_ } }) {
        $script:governanceSection | Should -Not -Match ([regex]::Escape($Command))
    }
    It 'does not infer a legal hold from the priority group or seven years' {
        $script:governanceSection | Should -Not -Match '2555|KeepAndDelete|PriorityUsers@'
        $script:implementation | Should -Not -Match 'Enable litigation hold for priority users|Create an Exchange DLP policy in simulation'
    }
    It 'maps each retained governance control to the explicit contract and external handoff' {
        foreach ($control in @('GOV-003','GOV-004','GOV-005')) { $script:governanceSection | Should -Match $control }
        $script:governanceSection | Should -Match 'EXCHANGE-GOVERNANCE.md'
        $script:governanceSection | Should -Match 'RAID-I02/D03'
        $script:governanceSection | Should -Match 'Unverified'
    }
}