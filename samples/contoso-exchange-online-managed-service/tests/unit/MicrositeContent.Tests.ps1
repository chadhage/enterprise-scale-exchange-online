BeforeAll {
    $script:repositoryRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
    $script:indexPath = Join-Path $repositoryRoot 'microsite\index.html'
    $script:scriptPath = Join-Path $repositoryRoot 'microsite\script.js'
    $script:pagesWorkflowPath = Join-Path $repositoryRoot '.github\workflows\deploy-pages.yml'
    $script:docsPath = Join-Path $repositoryRoot 'samples\contoso-exchange-online-managed-service\docs'
    $script:index = Get-Content -LiteralPath $indexPath -Raw
    $script:script = Get-Content -LiteralPath $scriptPath -Raw
    $script:pagesWorkflow = Get-Content -LiteralPath $pagesWorkflowPath -Raw
    $script:content = $index + "`n" + $script
}

Describe 'Microsite supported content boundary' {
    It 'uses the active Exchange-only contract' {
        $script:index | Should -Match 'exchange-only\.v1\.json'
        $script:index | Should -Match 'exchange-only\.schema\.v1\.json'
        $script:index | Should -Match 'EXCHANGE-ADMINISTRATOR-JOURNEY\.md'
        $script:index | Should -Match 'parameters\.exchange-only\.sample\.json'
    }

    It 'shows a gated wizard in the supported workflow order with script and usage-guide links' {
        $script:index | Should -Match 'Guided Exchange change wizard'
        $script:index | Should -Match 'Prerequisites fit.*begin Step 1'
        $script:index | Should -Match 'One versioned Exchange-only configuration'
        $script:index | Should -Match 'wizardIntro'
        $script:index | Should -Match 'changeWizard'
        $script:index | Should -Match 'Net-new Exchange administrator journey'
        $script:index | Should -Match 'data-wizard-complete'
        $script:index | Should -Match 'Invoke-ExchangeOnlineChange\.ps1'
        $script:index | Should -Match 'Deploy-ExchangeOnlineBaseline\.ps1'
        $script:index | Should -Match 'Test-ExchangeOnlineBaseline\.ps1'
        $script:index | Should -Match 'Preview command and review guidance'
        $script:index | Should -Not -Match 'former generator emitted a quarantined'
        $stepTitles = [regex]::Matches($script:index, '<h2 id="wizardTitle\d+"[^>]*>(?<title>[^<]+)</h2>') |
            ForEach-Object { $_.Groups['title'].Value }
        ($stepTitles -join '|') | Should -BeExactly 'Get the change kit and open PowerShell 7|Choose what this change will touch|Prepare your inputs|Sign in and run the readiness check|Create and inspect the immutable preview|Get a separate approval and validate it|Apply only the reviewed change|Collect evidence, assess outcome, and retain recovery artifacts'
        $script:index | Should -Match 'aria-valuemax="8"'
        $script:index.IndexOf('<h2>Runtime and access</h2>') | Should -BeLessThan $script:index.IndexOf('id="wizardBegin"')
        $script:index.IndexOf('<h2>Support boundary</h2>') | Should -BeLessThan $script:index.IndexOf('id="wizardBegin"')
        $script:index.IndexOf('id="wizardBegin"') | Should -BeLessThan $script:index.IndexOf('id="wizardMount"')
        $script:script | Should -Match 'completed\[currentStep\]'
        $script:script | Should -Match 'wizardProgressBar'
        $script:script | Should -Match 'mount\.append\(template\.content\.cloneNode\(true\)\)'
        $script:script | Should -Match 'beginButton\.addEventListener'
    }

    It 'walks the operator from download through a readiness gate with copyable commands' {
        $workflowPath = Join-Path $script:repositoryRoot '.github\workflows\release-kit.yml'
        $releaseWorkflow = Get-Content -LiteralPath $workflowPath -Raw
        $script:index | Should -Match 'releases/latest/download'''
        $script:index | Should -Match '/exchange-online-change-kit\.zip"'
        $script:index | Should -Match '/exchange-online-change-kit\.zip\.sha256"'
        $script:index | Should -Match 'Get-FileHash'
        $script:index | Should -Match 'Unblock-File'
        $script:index | Should -Match 'Test-ExchangeOnlineChangeReadiness\.ps1 -WorkstationOnly'
        $script:index | Should -Match 'READY FOR PREVIEW'
        $script:index | Should -Match 'class="terminal-sample"'
        $releaseWorkflow | Should -Match 'exchange-online-change-kit\.zip\.sha256'
        $releaseWorkflow | Should -Match 'gh release create'
        $script:script | Should -Match 'function addCopyButtons'
        $script:script | Should -Match 'navigator\.clipboard\.writeText\(code\.textContent\)'
        $script:script | Should -Match 'addCopyButtons\(content\)'
        $script:index.IndexOf('id="wizardTitle0"') | Should -BeLessThan $script:index.IndexOf('Test-ExchangeOnlineChangeReadiness.ps1 `')
        $script:index.IndexOf('Test-ExchangeOnlineChangeReadiness.ps1 `') | Should -BeLessThan $script:index.IndexOf('id="wizardTitle4"')
    }

    It 'builds Step 2 from choices instead of asking for an unexplained profile choice' {
        $script:index | Should -Not -Match 'Use one approved Exchange-only profile'
        $script:index | Should -Not -Match 'Nothing to choose'
        $script:index | Should -Match 'Which areas does your ticket approve\?'
        $script:index | Should -Match 'Who gets Standard and who gets Strict\?'
        $script:index | Should -Match 'Which extra settings does your ticket include\?'
        $script:index | Should -Match 'id="step3Checklist"'
        $script:index | Should -Match 'MAIL_ENABLED_PRIORITY_USERS_GROUP'
        $script:index | Should -Match 'Never set <code>verified</code> to <code>true</code> yourself'
        $script:index | Should -Not -Match "(?m)^\s+-Scope 'Transport'</code>"
        $script:index | Should -Match '-Scope <span data-scope-arg>'
        ([regex]::Matches($script:index, 'data-scope-arg')).Count | Should -BeGreaterOrEqual 2
    }

    It 'introduces the approver before Step 1 and hands off explicitly at Step 6' {
        $roles = $script:index.IndexOf('id="wizardRoles"')
        $roles | Should -BeGreaterThan 0
        $roles | Should -BeLessThan $script:index.IndexOf('id="wizardBegin"')
        $script:index | Should -Match 'Approval authority owner'
        $script:index | Should -Match '24 hours'
        $script:index | Should -Match 'Hand off to your approver'
        $script:index | Should -Match 'Set-Clipboard'
        $script:index | Should -Match '6a\. Approver \(not you\)'
        $script:index | Should -Match ([regex]::Escape(@'
'$(([string]$_.Value).Replace("'", "''"))'
'@.Trim()))
        $script:index | Should -Not -Match ([regex]::Escape(@'
= '$($_.Value)'
'@.Trim()))
        $script:index.IndexOf('Hand off to your approver') | Should -BeLessThan $script:index.IndexOf('id="wizardTitle5"')
    }

    It 'ends the walkthrough with a script that writes the Markdown evidence report' {
        $script:index | Should -Match 'New-ExchangeChangeEvidenceReport\.ps1 -ArtifactRoot \$change\.ArtifactRoot -ChangeId \$change\.ChangeId'
        $script:index | Should -Match 'evidence-report-&lt;ChangeId&gt;\.md'
        $script:index.IndexOf('id="wizardTitle7"') | Should -BeLessThan $script:index.IndexOf('New-ExchangeChangeEvidenceReport.ps1')
        Test-Path -LiteralPath (Join-Path $script:repositoryRoot 'samples\contoso-exchange-online-managed-service\scripts\New-ExchangeChangeEvidenceReport.ps1') | Should -BeTrue
    }

    It 'offers exactly the scopes and required workflowOptions the scripts accept' {
        $adapters = Get-Content -LiteralPath (Join-Path $script:repositoryRoot 'samples\contoso-exchange-online-managed-service\scripts\ExchangeOnlineBaseline.ApprovedAdapters.ps1') -Raw
        $supportedBlock = [regex]::Match($adapters, '(?s)function Assert-ApprovedAdapterScope.*?\$supported = @\((.*?)\)').Groups[1].Value
        $supported = @([regex]::Matches($supportedBlock, "'([A-Za-z]+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object)
        $offered = @([regex]::Matches($script:script, "\{ area: '[^']+', id: '([A-Za-z]+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object)
        $supported.Count | Should -Be 32
        $offered | Should -Be $supported

        $readiness = Get-Content -LiteralPath (Join-Path $script:repositoryRoot 'samples\contoso-exchange-online-managed-service\scripts\Test-ExchangeOnlineChangeReadiness.ps1') -Raw
        foreach ($pair in [regex]::Matches($readiness, "(\w+) = '(\w+)'(?=;|\s*$)", 'Multiline')) {
            $scope = $pair.Groups[1].Value
            $key = $pair.Groups[2].Value
            if ($scope -notin $supported) { continue }
            $script:script | Should -Match "id: '$($scope)'[^\r\n]*required: \['$($key)'\]"
            $script:script | Should -Match "\n    $($key): \{"
        }
    }

    It 'renders every repository guide inside the microsite and publishes the source documents' {
        $sourceDocuments = @(Get-ChildItem -LiteralPath $script:docsPath -Filter '*.md' | ForEach-Object Name | Sort-Object)
        $catalog = [regex]::Match($script:script, 'const documentCatalog = \[(?<files>[\s\S]*?)\];').Groups['files'].Value
        $publishedDocuments = @([regex]::Matches($catalog, "'(?<file>[^']+\.md)'") | ForEach-Object { $_.Groups['file'].Value } | Sort-Object)
        ($publishedDocuments -join '|') | Should -BeExactly ($sourceDocuments -join '|')
        $script:pagesWorkflow | Should -Match 'cp samples/contoso-exchange-online-managed-service/docs/\*\.md microsite/docs/'
        $script:script | Should -Match 'fetch\(`docs/\$'
        $script:script | Should -Match 'function renderMarkdown'
        $script:script | Should -Match 'content\.replaceChildren\(rendered\.content\)'
        $script:script | Should -Match 'link\.dataset\.document = sourceFile'
        $script:script | Should -Match 'route\.set\(''section'', section\)'
        $script:script | Should -Match ([regex]::Escape('<(?:https?:\/\/|mailto:)[^<>\s]+>'))
        $script:script | Should -Match ([regex]::Escape("token.startsWith('<')"))
        $script:index | Should -Not -Match 'github\.com/chadhage/enterprise-scale-exchange-online/blob/main/samples/contoso-exchange-online-managed-service/docs/'
    }

    It 'opens every external microsite link in a new page safely' {
        $externalLinks = [regex]::Matches($script:index, '<a\b(?=[^>]*\bhref="https?://)[^>]*>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $externalLinks.Count | Should -BeGreaterThan 0
        foreach ($link in $externalLinks) {
            $link.Value | Should -Match '\btarget="_blank"'
            $link.Value | Should -Match '\brel="noopener noreferrer"'
        }
    }

    It 'marks offsite links with a distinct icon and an accessible new-tab hint' {
        $styles = Get-Content -LiteralPath (Join-Path $script:repositoryRoot 'microsite\styles.css') -Raw
        $styles | Should -Match 'a\[target="_blank"\]::after'
        $styles | Should -Match '\.visually-hidden'
        $script:script | Should -Match '\(opens in a new tab\)'
        $script:script | Should -Match 'markExternalLinks\(document\)'
        $script:script | Should -Match 'markExternalLinks\(content\)'
    }

    It 'restores the current section and wizard step after a full page refresh' {
        $script:script | Should -Match 'sessionStorage\.setItem\(viewStateKey'
        $script:script | Should -Match 'saveViewState\(\{ section: sectionId \}\)'
        $script:script | Should -Match 'saveViewState\(\{ wizard:'
        $script:script | Should -Match 'currentStep > firstOpen'
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
