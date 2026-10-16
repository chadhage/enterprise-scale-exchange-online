[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$tools = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'tools.psd1')
Import-Module PSScriptAnalyzer -RequiredVersion $tools.PSScriptAnalyzer -ErrorAction Stop
$paths = @(git ls-files -- '*.ps1' '*.psm1' '*.psd1')
if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate tracked PowerShell files.' }
$paths = @($paths | Where-Object { $_ -notlike 'deprecated/*' })
$diagnostics = @(
    foreach ($path in $paths) {
        $tokens = $null
        $parseErrors = $null
        $null = [Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $PWD $path), [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors.Count) { throw "PowerShell parse failure: $($path): $($parseErrors.Message -join '; ')" }
        try { Invoke-ScriptAnalyzer -Path $path }
        catch { throw "Source analysis failed for $($path): $($_.Exception.Message)" }
    }
)
$null = New-Item -ItemType Directory -Path '.artifacts' -Force
$diagnostics | Select-Object ScriptPath, Line, RuleName, Severity, Message |
    ConvertTo-Json -Depth 4 | Set-Content '.artifacts/analyzer.json' -Encoding utf8
if (@($diagnostics | Where-Object Severity -EQ Error).Count) {
    throw 'PSScriptAnalyzer reported errors. See analyzer.json.'
}
git diff HEAD --check
if ($LASTEXITCODE -ne 0) { throw 'Whitespace validation failed.' }
