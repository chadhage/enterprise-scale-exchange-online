BeforeAll {
    $root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $docs = Join-Path $root docs
}
Describe 'EXR-010 Exchange-only email guidance' {
    It 'does not retain cross-workload setup in <Name>' -ForEach @(
        @{ Name = 'RUNBOOKS.md' }; @{ Name = 'IMPLEMENTATION-GUIDE.md' }; @{ Name = 'LICENSING-GATE.md' }
    ) {
        $text = Get-Content (Join-Path $docs $Name) -Raw
        $text | Should -Not -Match 'Set-AtpPolicyForO365|Set-SPOTenant|Enable Safe Documents|Enable Safe Attachments for SharePoint|Connect-MgGraph'
    }
    It 'does not label impersonation or tabletop cadence as intrinsically P2' {
        $text = Get-Content (Join-Path $docs 'CONTROL-CATALOG.md') -Raw
        $text | Should -Not -Match '\| MDO-009 \|[^\r\n]*MDO P2|\| OPS-002 \|[^\r\n]*MDO P2'
    }
    It 'does not omit <Term> from the supported email contract' -ForEach @('recipientMatrix','settingExceptions','ReportingEvidence','DLP','AddSentTo','rollback','ExternalReadiness','EXR-016','LocalPolicy') {
        $path = Join-Path $docs 'EXCHANGE-EMAIL-PROTECTION.md'
        Test-Path $path | Should -BeTrue
        Get-Content $path -Raw | Should -Match $_
    }
}