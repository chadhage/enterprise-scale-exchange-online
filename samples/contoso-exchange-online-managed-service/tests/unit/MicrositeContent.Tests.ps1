BeforeAll {
    $script:repositoryRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
    $script:indexPath = Join-Path $repositoryRoot 'microsite\index.html'
    $script:scriptPath = Join-Path $repositoryRoot 'microsite\script.js'
    $script:index = Get-Content -LiteralPath $indexPath -Raw
    $script:script = Get-Content -LiteralPath $scriptPath -Raw
    $script:content = $index + "`n" + $script
}

Describe 'Microsite supported content boundary' {
    It 'uses the active Exchange-only contract' {
        $script:index | Should -Match 'exchange-only\.v1\.json'
        $script:index | Should -Match 'exchange-only\.schema\.v1\.json'
        $script:index | Should -Match 'EXCHANGE-ADMINISTRATOR-JOURNEY\.md'
        $script:index | Should -Match 'parameters\.exchange-only\.sample\.json'
    }

    It 'does not expose quarantined scripts or schema names' {
        $script:content | Should -Not -Match 'Deploy-MDOBaseline\.ps1'
        $script:content | Should -Not -Match 'Validate-MDOConfiguration\.ps1'
        $script:content | Should -Not -Match 'mdo-config-schema\.json'
        $script:content | Should -Not -Match 'Run-Tests\.ps1'
        $script:content | Should -Not -Match '\bSPFx\b'
    }

    It 'does not include a legacy configuration generator' {
        $script:script | Should -Not -Match 'BASELINE_(STANDARD|STRICT)'
        $script:script | Should -Not -Match 'generateConfig'
        $script:script | Should -Not -Match 'downloadConfig'
        $script:content | Should -Not -Match 'deploymentMode'
        $script:index | Should -Not -Match '<form\b'
    }

    It 'does not describe preset security policies as detect-only' {
        $script:content | Should -Not -Match 'Audit Mode'
        $script:content | Should -Not -Match 'detect threats but don''t block'
        $script:content | Should -Not -Match 'switch to Enforce'
        $script:content | Should -Not -Match 'Safe Links detonation'
    }

    It 'does not publish unsafe serialized policy rollback instructions' {
        $script:content | Should -Not -Match 'Recreate policies from exported JSON'
        $script:content | Should -Not -Match 'Get-AntiPhishPolicy.+ConvertTo-Json'
    }

    It 'separates Strict protection from Plan 2 capabilities' {
        $script:index | Should -Match 'Assigning Strict does not enable them'
        $script:index | Should -Match 'AIR and other advanced investigation capabilities are separate Plan 2 features'
    }

    It 'states the customization and precedence boundary' {
        $script:index | Should -Match 'Virtually all individual settings.+Microsoft-managed'
        $script:index | Should -Match 'presets have higher precedence'
    }

    It 'does not claim sovereign-cloud support' {
        $script:index | Should -Match 'active journey is limited to Worldwide tenants'
        $script:index | Should -Match 'has not validated sovereign-cloud or hybrid'
    }

    It 'pins current runtime prerequisites and least-privilege guidance' {
        $script:index | Should -Match 'PowerShell 7\.6 or later'
        $script:index | Should -Match 'ExchangeOnlineManagement 3\.10\.0 or later'
        $script:index | Should -Match 'Organization Management or Security Administrator'
        $script:index | Should -Match 'Global Administrator is highly privileged'
    }

    It 'requires governed temporary allow entries' {
        $script:index | Should -Match 'Submit legitimate messages, URLs, or attachments to Microsoft first'
        $script:index | Should -Match 'prohibits permanent allow entries'
        $script:index | Should -Match 'owner, ticket, timestamps, expiry, and justification'
    }

    It 'does not make a blanket no-cost licensing claim' {
        $script:index | Should -Not -Match 'No additional costs'
        $script:index | Should -Match 'No general cost claim can be made'
        $script:index | Should -Match 'tenant service plans and recipient assignments'
    }

    It 'does not publish stale test-count or coverage claims' {
        $script:content | Should -Not -Match '150\+'
        $script:content | Should -Not -Match '80%\+'
    }
}
