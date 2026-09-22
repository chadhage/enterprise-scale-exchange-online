BeforeAll {
    $root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:reportAdapterModule = Import-Module (Join-Path $root 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -PassThru
    function New-ReportAdapterContext {
        $configuration = Get-Content (Join-Path $root 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
        $configuration.controls['MDO-006'].reportingMailbox = 'secops@contoso.example'
        $configuration.controls['MDO-006'].approval = @{ reference = 'OFFLINE-010'; owner = 'security'; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') }
        @{ Configuration = $configuration; Parameters = @{ SECURITY_OPERATIONS_MAILBOX = 'secops@contoso.example' } }
    }
    function Get-ReportAdapterDefinitions {
        param($Context, [string]$Scope = 'ReportSubmission')
        & $script:reportAdapterModule { param($context,$scope) @(Get-ApprovedAdapterDefinitions $context @($scope) -DesiredOnly) } $Context $Scope
    }
}
Describe 'EXR-010 reporting approved mutation contract' {
    It 'rejects <Case> before planning writes' -ForEach @(
        @{ Case = 'missing approval'; Mutate = { param($context) $context.Configuration.controls['MDO-006'].approval = $null } }
        @{ Case = 'wildcard mailbox'; Mutate = { param($context) $context.Configuration.controls['MDO-006'].reportingMailbox = '*@contoso.example' } }
        @{ Case = 'inconsistent destination'; Mutate = { param($context) $context.Configuration.controls['MDO-006'].sendCopyToSecOpsMailbox = $false } }
    ) {
        $context = New-ReportAdapterContext
        & $Mutate $context
        { Get-ReportAdapterDefinitions $context } | Should -Throw
    }
    It 'does not omit the <_> reporting policy contract' -ForEach @('ReportNotJunkAddresses','ReportPhishAddresses','PreSubmitMessageEnabled','PostSubmitMessageEnabled') {
        $definitions = Get-ReportAdapterDefinitions (New-ReportAdapterContext)
        ($definitions | Where-Object Noun -eq ReportSubmissionPolicy).Desired.ContainsKey($_) | Should -BeTrue
    }
    It 'does not omit the reporting rule or its state operation' {
        $definitions = Get-ReportAdapterDefinitions (New-ReportAdapterContext)
        @($definitions | Where-Object { $_.Noun -eq 'ReportSubmissionRule' -and -not $_.Toggle }).Count | Should -Be 1
        @($definitions | Where-Object { $_.Noun -eq 'ReportSubmissionRule' -and $_.Toggle }).Count | Should -Be 1
    }
    It 'does not mutate rule Mode through the SecOps policy' {
        $definitions = Get-ReportAdapterDefinitions (New-ReportAdapterContext) SecOpsOverride
        @($definitions | Where-Object { $_.Noun -eq 'SecOpsOverridePolicy' -and $_.Desired.ContainsKey('Mode') }).Count | Should -Be 0
    }
    It 'plans exact email category destinations and a bound enabled reporting rule' {
        $definitions = Get-ReportAdapterDefinitions (New-ReportAdapterContext)
        $policy = $definitions | Where-Object Noun -eq ReportSubmissionPolicy
        foreach ($field in @('ReportJunkAddresses','ReportNotJunkAddresses','ReportPhishAddresses')) { $policy.Desired[$field] | Should -Be @('secops@contoso.example') }
        $rule = $definitions | Where-Object { $_.Noun -eq 'ReportSubmissionRule' -and -not $_.Toggle }
        $rule.Desired.SentTo | Should -Be @('secops@contoso.example')
        $rule.Guard.ReportSubmissionPolicy | Should -BeExactly DefaultReportSubmissionPolicy
        ($definitions | Where-Object Toggle).Desired.Enabled | Should -BeTrue
        @($definitions | ForEach-Object { $_.Desired.Keys } | Where-Object { $_ -match 'Teams|Chat' }).Count | Should -Be 0
    }
}