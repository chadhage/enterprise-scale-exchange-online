#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Master test runner for MDO Baseline Configuration solution

.DESCRIPTION
    Orchestrates running all test levels with reporting

.PARAMETER TestLevel
    Specific test level to run: Unit, Integration, E2E, Acceptance, or All

.PARAMETER GenerateReport
    Generate HTML test report

.PARAMETER WithCodeCoverage
    Include code coverage analysis

.EXAMPLE
    .\Run-Tests.ps1 -TestLevel All
    .\Run-Tests.ps1 -TestLevel Unit -WithCodeCoverage
    .\Run-Tests.ps1 -TestLevel Integration -GenerateReport
#>

param(
    [ValidateSet("Unit", "Integration", "E2E", "Acceptance", "All")]
    [string]$TestLevel = "All",
    
    [switch]$GenerateReport,
    [switch]$WithCodeCoverage
)

$ErrorActionPreference = "Stop"

# Set up paths
$projectRoot = Split-Path -Parent $PSScriptRoot
$testsPath = Join-Path $projectRoot "tests"
$reportsPath = Join-Path $projectRoot "test-reports"

# Ensure report directory exists
if (-not (Test-Path $reportsPath)) {
    New-Item -ItemType Directory -Path $reportsPath | Out-Null
}

# Verify Pester is installed
try {
    Import-Module Pester -ErrorAction Stop
    Write-Host "✓ Pester module loaded" -ForegroundColor Green
} catch {
    Write-Host "✗ Pester not found. Installing..." -ForegroundColor Yellow
    Install-Module Pester -Force -SkipPublisherCheck -Scope CurrentUser
    Import-Module Pester
}

# Build test configuration
$pesterConfig = @{
    Run = @{
        Path = $testsPath
        Exit = $true
    }
    Output = @{
        Verbosity = "Detailed"
    }
}

# Add code coverage if requested
if ($WithCodeCoverage) {
    $pesterConfig.CodeCoverage = @{
        Enabled = $true
        Path = Join-Path $projectRoot "scripts"
        OutputFormat = "JaCoCo"
        OutputPath = Join-Path $reportsPath "coverage-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
    }
    Write-Host "Code coverage enabled" -ForegroundColor Cyan
}

# Adjust path based on test level
switch ($TestLevel) {
    "Unit" {
        $pesterConfig.Run.Path = Join-Path $testsPath "unit"
        Write-Host "Running Unit Tests..." -ForegroundColor Cyan
    }
    "Integration" {
        $pesterConfig.Run.Path = Join-Path $testsPath "integration"
        Write-Host "Running Integration Tests..." -ForegroundColor Cyan
    }
    "E2E" {
        $pesterConfig.Run.Path = Join-Path $testsPath "e2e"
        Write-Host "Running End-to-End Tests..." -ForegroundColor Cyan
    }
    "Acceptance" {
        Write-Host "Running Acceptance Checklist..." -ForegroundColor Cyan
        Write-Host "Please review: $testsPath\acceptance\ACCEPTANCE_CHECKLIST.md" -ForegroundColor Yellow
        return
    }
    default {
        Write-Host "Running Full Test Suite..." -ForegroundColor Cyan
    }
}

# Add test result output path if report requested
if ($GenerateReport) {
    $reportPath = Join-Path $reportsPath "test-results-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
    $pesterConfig.TestResult = @{
        OutputFormat = "NUnitXml"
        OutputPath = $reportPath
    }
    Write-Host "Test report will be saved to: $reportPath" -ForegroundColor Cyan
}

# Run tests
Write-Host "`n" + ("=" * 60) -ForegroundColor Gray
try {
    $results = Invoke-Pester -Configuration $pesterConfig -PassThru
    
    # Display summary
    Write-Host "`n" + ("=" * 60) -ForegroundColor Gray
    Write-Host "TEST SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Gray
    Write-Host "Total Tests:    $($results.Tests.Count)"
    Write-Host "Passed:         $($results.PassedCount) ✓" -ForegroundColor Green
    Write-Host "Failed:         $($results.FailedCount)" -ForegroundColor $(if ($results.FailedCount -gt 0) { "Red" } else { "Green" })
    Write-Host "Skipped:        $($results.SkippedCount)" -ForegroundColor Yellow
    Write-Host ("=" * 60) -ForegroundColor Gray
    
    if ($results.FailedCount -gt 0) {
        Write-Host "`n❌ Some tests failed!" -ForegroundColor Red
        exit 1
    } else {
        Write-Host "`n✓ All tests passed!" -ForegroundColor Green
        exit 0
    }
} catch {
    Write-Host "`n❌ Test execution failed: $_" -ForegroundColor Red
    exit 2
}
