[CmdletBinding()]
param(
    [string]$PlanPath = '.artifacts/ci/plan.json',
    [ValidateRange(0, 31)][int]$Shard = 0,
    [ValidateRange(1, 32)][int]$ShardCount = 1,
    [string]$OutputRoot = '.artifacts/results',
    [string]$TestFile,
    [string]$ResultPath
)

$ErrorActionPreference = 'Stop'
$tools = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'tools.psd1')

if ($TestFile) {
    if ([string]::IsNullOrWhiteSpace($ResultPath)) { throw 'ResultPath is required for a test-container child.' }
    Import-Module Pester -RequiredVersion $tools.Pester -ErrorAction Stop
    $started = [datetimeoffset]::UtcNow
    $config = New-PesterConfiguration
    $config.Run.Path = $TestFile
    $config.Run.PassThru = $true
    $config.Output.Verbosity = 'Normal'
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = [IO.Path]::ChangeExtension($ResultPath, '.xml')
    $config.TestResult.OutputFormat = 'NUnitXml'
    # Instrument this contract once in its existing shard, not in another test run.
    if ([IO.Path]::GetFileName($TestFile) -eq 'ExchangeOnlineConnection.Tests.ps1') {
        $config.CodeCoverage.Enabled = $true
        $config.CodeCoverage.Path = 'samples/contoso-exchange-online-managed-service/scripts/ExchangeOnlineBaseline.Connection.psm1'
        $config.CodeCoverage.OutputPath = [IO.Path]::ChangeExtension($ResultPath, '.coverage.xml')
    }
    $result = Invoke-Pester -Configuration $config
    $complete = $result.TotalCount -gt 0 -and $result.PassedCount -eq $result.TotalCount -and
        $result.FailedCount -eq 0 -and $result.FailedContainersCount -eq 0 -and
        $result.SkippedCount -eq 0 -and $result.NotRunCount -eq 0
    [ordered]@{
        file = $TestFile.Replace('\', '/')
        inputHash = (Get-FileHash -LiteralPath $TestFile -Algorithm SHA256).Hash.ToLowerInvariant()
        total = $result.TotalCount
        passed = $result.PassedCount
        failed = $result.FailedCount
        failedContainers = $result.FailedContainersCount
        skipped = $result.SkippedCount
        notRun = $result.NotRunCount
        complete = $complete
        startedAt = $started.ToString('o')
        durationSeconds = ([datetimeoffset]::UtcNow - $started).TotalSeconds
        powershell = $PSVersionTable.PSVersion.ToString()
        pester = (Get-Module Pester).Version.ToString()
        tests = @($result.Tests | ForEach-Object {
            @{ name = $_.ExpandedPath -join '.'; result = [string]$_.Result }
        })
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ResultPath -Encoding utf8
    if (-not $complete) { exit 1 }
    exit 0
}

if ($Shard -ge $ShardCount) { throw 'Shard must be smaller than ShardCount.' }
$plan = Get-Content -LiteralPath $PlanPath -Raw | ConvertFrom-Json
$files = @($plan.tests)
if (-not $files.Count) { throw 'Test selection is empty.' }
$null = New-Item -ItemType Directory -Path $OutputRoot -Force
$reports = [Collections.Generic.List[object]]::new()
$failed = $false
for ($index = $Shard; $index -lt $files.Count; $index += $ShardCount) {
    $file = [string]$files[$index]
    $path = Join-Path $OutputRoot "test-$($index).json"
    $log = Join-Path $OutputRoot "test-$($index).log"
    if ((Test-Path -LiteralPath $path) -or (Test-Path -LiteralPath $log)) {
        throw "Existing container output refused: $($file). Use a fresh output directory."
    }
    & (Join-Path $PSHOME 'pwsh') -NoProfile -NonInteractive -File $PSCommandPath `
        -TestFile $file -ResultPath $path *> $log
    $childExit = $LASTEXITCODE
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Write-Warning "Test container produced no result: $($file); exit $($childExit). See $($log)."
        $failed = $true
        $reports.Add(@{ file = $file; complete = $false; invocationExit = $childExit })
        continue
    }
    $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable
    $report.invocationExit = $childExit
    $reports.Add($report)
    Write-Information "$($file): $($report.passed)/$($report.total); exit $($childExit)" -InformationAction Continue
    if ($childExit -ne 0 -or -not $report.complete) { $failed = $true }
}
@{ shard = $Shard; shardCount = $ShardCount; reports = @($reports) } |
    ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath (Join-Path $OutputRoot "summary-$($Shard).json") -Encoding utf8
if ($failed) { throw 'Offline verification failed. See the per-container logs and results.' }
