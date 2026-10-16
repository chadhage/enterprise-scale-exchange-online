[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Join-Path $PWD '.artifacts/bundle'
if (Test-Path -LiteralPath $root) { throw 'Artifact staging must start in an empty directory.' }
$site = Join-Path $root 'site'
$kit = Join-Path $PWD '.artifacts/package/exchange-online-change-kit'
$null = New-Item -ItemType Directory -Path $site, $kit -Force
foreach ($name in 'index.html', 'script.js', 'styles.css', '.nojekyll') {
    Copy-Item -LiteralPath (Join-Path 'microsite' $name) -Destination $site
}
$docs = Join-Path $site 'docs'
$null = New-Item -ItemType Directory -Path $docs
Copy-Item -Path 'samples/contoso-exchange-online-managed-service/docs/*.md' -Destination $docs
$plan = Get-Content '.artifacts/ci/plan.json' -Raw | ConvertFrom-Json
$version = @{ schema = 1; sourceCommit = $plan.commit; sourceTree = $plan.tree }
$version | ConvertTo-Json | Set-Content (Join-Path $site 'version.json') -Encoding utf8
foreach ($name in 'config', 'docs', 'scripts', 'README.md') {
    Copy-Item -LiteralPath (Join-Path 'samples/contoso-exchange-online-managed-service' $name) -Destination $kit -Recurse
}
$version | ConvertTo-Json | Set-Content (Join-Path $kit 'version.json') -Encoding utf8
$zip = Join-Path $root 'exchange-online-change-kit.zip'
Compress-Archive -LiteralPath $kit -DestinationPath $zip
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$($hash)  exchange-online-change-kit.zip" | Set-Content "$($zip).sha256" -Encoding ascii

$extracted = Join-Path $PWD '.artifacts/extracted'
Expand-Archive -LiteralPath $zip -DestinationPath $extracted
$extractedKit = Join-Path $extracted 'exchange-online-change-kit'
$manifest = Join-Path $extractedKit 'scripts/ExchangeOnlineBaseline.Common.psd1'
$null = Test-ModuleManifest -Path $manifest -ErrorAction Stop
Import-Module $manifest -Force -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $extractedKit 'scripts/ExchangeOnlineBaseline.Connection.psm1') -Force -ErrorAction Stop
if (@((Get-ExchangeScopeReadCommand).Keys).Count -ne 32) { throw 'Extracted kit scope contract is incomplete.' }
$configuration = Join-Path $extractedKit 'config/exchange-only.v1.json'
$schema = Join-Path $extractedKit 'config/exchange-only.schema.v1.json'
if (-not (Get-Content $configuration -Raw | Test-Json -SchemaFile $schema -ErrorAction Stop)) {
    throw 'Packaged configuration does not satisfy its schema.'
}
$required = @(
    'scripts/Invoke-ExchangeOnlineChange.ps1', 'scripts/Deploy-ExchangeOnlineBaseline.ps1',
    'scripts/Test-ExchangeOnlineBaseline.ps1', 'scripts/Test-ExchangeOnlineChangeReadiness.ps1',
    'scripts/New-ExchangeChangeEvidenceReport.ps1', 'scripts/ExchangeOnlineBaseline.ApprovedAdapters.ps1',
    'config/exchange-only.manifest.v1.json', 'docs/EXCHANGE-ADMINISTRATOR-JOURNEY.md'
)
foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $extractedKit $path) -PathType Leaf)) {
        throw "Extracted kit is missing $($path)."
    }
}
