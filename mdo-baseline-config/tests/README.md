# MDO Baseline Configuration - Testing Guide

Complete guide for running, writing, and maintaining tests for the MDO baseline configuration solution.

## Quick Start

### Run All Tests
```powershell
# From project root
cd .\mdo-baseline-config
Invoke-Pester -Path ".\tests" -Output Detailed
```

### Run Specific Test Level
```powershell
# Unit tests
Invoke-Pester -Path ".\tests\unit" -Output Detailed

# Integration tests
Invoke-Pester -Path ".\tests\integration" -Output Detailed

# E2E tests
Invoke-Pester -Path ".\tests\e2e" -Output Detailed

# Acceptance tests
Invoke-Pester -Path ".\tests\acceptance" -Output Detailed
```

### Run Single Test File
```powershell
Invoke-Pester -Path ".\tests\unit\Deploy-MDOBaseline.Tests.ps1" -Output Detailed
```

## Test Structure

```
tests/
├── TEST_STRATEGY.md                          # Overall testing strategy
├── README.md                                 # This file
├── unit/                                     # Unit tests (Pester)
│   ├── Deploy-MDOBaseline.Tests.ps1          # Deployment function tests
│   ├── Validate-MDOConfiguration.Tests.ps1   # Validation function tests
│   └── *.Tests.ps1                           # Other unit tests
├── integration/                              # Integration tests (Pester)
│   ├── config-to-deployment.Tests.ps1        # Configuration pipeline
│   └── *.Tests.ps1                           # Component interaction tests
├── e2e/                                      # End-to-end tests (Pester)
│   ├── complete-deployment-flow.Tests.ps1    # Full workflow tests
│   └── *.Tests.ps1                           # Scenario-based tests
├── acceptance/                               # Acceptance tests & checklists
│   └── ACCEPTANCE_CHECKLIST.md              # Business requirement validation
└── fixtures/                                 # Test data
    ├── valid-config.json                     # Valid test configuration
    └── *.json                                # Test data files
```

## Prerequisites

### Install Pester 5.3+
```powershell
# Install Pester (might need -SkipPublisherCheck on some systems)
Install-Module Pester -Force -SkipPublisherCheck

# Verify installation
Get-Module Pester -ListAvailable
```

### Verify PowerShell Version
```powershell
# Must be PowerShell 7.0 or higher
$PSVersionTable.PSVersion

# Should output version 7.x or higher
```

## Writing Tests

### Unit Test Template

```powershell
BeforeAll {
    # Set up paths and import functions
    $script:scriptsPath = Join-Path $PSScriptRoot "..\..\scripts"
    . (Join-Path $script:scriptsPath "MyScript.ps1")
}

Describe "Function Name Unit Tests" {
    
    Context "Scenario Description" {
        It "Should do something specific" {
            # Arrange - Set up test data
            $input = "test value"
            $expected = "expected result"
            
            # Act - Execute the function
            $result = MyFunction $input
            
            # Assert - Verify the result
            $result | Should -Be $expected
        }
    }
}
```

### Integration Test Template

```powershell
Describe "Component Integration Tests" {
    
    Context "Multi-component workflow" {
        It "Should process through complete pipeline" {
            # Arrange - Set up multiple components
            $component1 = Initialize-Component1
            $component2 = Initialize-Component2
            
            # Act - Execute integrated workflow
            $intermediate = $component1 | Process-Component1
            $result = $intermediate | Process-Component2
            
            # Assert - Verify end-to-end result
            $result.Success | Should -Be $true
        }
    }
}
```

### E2E Test Template

```powershell
Describe "End-to-End Workflow Tests" {
    
    Context "Complete user scenario" {
        It "Should complete entire workflow" {
            # Full workflow from start to finish
            # Including all prerequisites and cleanup
            
            $success = Complete-Workflow
            $success | Should -Be $true
        }
    }
}
```

## Test Naming Conventions

### Unit Test Names
```powershell
# Format: Should_Action_WhenCondition
It "Should replace placeholder when template contains value" { }
It "Should validate GUID when format is correct" { }
It "Should throw error when file not found" { }
```

### Integration Test Names
```powershell
# Format: Should_IntegrateComponents_WhenCondition
It "Should process config through entire pipeline when all components available" { }
It "Should coordinate policies when recipient targeting applied" { }
```

### E2E Test Names
```powershell
# Format: Should_CompleteWorkflow_WhenScenario
It "Should complete deployment from config generation to policy creation" { }
It "Should handle three-phase rollout when organizations are phased" { }
```

## Assertions

Common Pester assertions:

```powershell
# Equality
$result | Should -Be $expected
$result | Should -Not -Be $notExpected

# Null/Empty
$result | Should -BeNullOrEmpty
$result | Should -Not -BeNullOrEmpty

# Type
$result | Should -BeOfType [string]
$result | Should -BeOfType [System.Collections.Hashtable]

# Comparison
$number | Should -BeGreaterThan 5
$number | Should -BeLessThan 10
$date | Should -BeBefore $endDate

# Collections
$array | Should -Contain "value"
$array | Should -HaveCount 5

# String matching
$string | Should -Match "pattern"
$string | Should -Not -Match "pattern"

# Exceptions
{ BadFunction } | Should -Throw
{ BadFunction } | Should -Throw -ExceptionType [System.ArgumentException]
```

## Test Fixtures

### Using Test Data Files

```powershell
BeforeAll {
    $script:fixturePath = Join-Path $PSScriptRoot "..\fixtures"
}

Context "With test data" {
    It "Should load fixture data" {
        $config = Get-Content (Join-Path $script:fixturePath "valid-config.json") | ConvertFrom-Json
        $config | Should -Not -BeNullOrEmpty
    }
}
```

### Creating Fixtures

Create JSON fixture files for reusable test data:

**fixtures/valid-config.json**
```json
{
  "organizationSettings": {
    "tenantId": "12345678-1234-1234-1234-123456789012",
    "tenantName": "Test Organization",
    "domain": "test.com"
  },
  "protectionLevel": "Standard"
}
```

## Mocking

### Mock External Commands

```powershell
Context "With mocked Exchange cmdlets" {
    BeforeEach {
        Mock Get-AntiPhishPolicy { return @{ Name = "Test Policy" } }
    }
    
    It "Should call Get-AntiPhishPolicy" {
        Get-AntiPhishPolicy
        
        Should -Invoke Get-AntiPhishPolicy -Times 1
    }
}
```

### Mock File Operations

```powershell
Context "With mocked file system" {
    BeforeEach {
        Mock Test-Path { return $true }
        Mock Get-Content { return '{"test": true}' }
    }
    
    It "Should handle file operations" {
        $result = Get-Content "C:\test.json"
        $result | Should -Match "test"
    }
}
```

## Code Coverage

### Generate Coverage Report

```powershell
# Run tests with code coverage
$config = @{
    Run = @{
        Path = "./tests"
        Exit = $true
    }
    CodeCoverage = @{
        Enabled = $true
        Path = "./scripts"
        OutputFormat = "JaCoCo"
        OutputPath = "./coverage.xml"
    }
}
Invoke-Pester -Configuration $config
```

### Coverage Goals

- **Unit Tests**: 80%+ coverage
- **Integration Tests**: 85%+ coverage
- **E2E Tests**: 100% critical path coverage

## Continuous Integration

### GitHub Actions Example

```yaml
name: Test Suite

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Pester
        shell: pwsh
        run: Install-Module Pester -Force -SkipPublisherCheck
      - name: Run Unit Tests
        shell: pwsh
        run: |
          $config = @{ Run = @{ Path = "./tests/unit" } }
          Invoke-Pester -Configuration $config

  integration-tests:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Pester
        shell: pwsh
        run: Install-Module Pester -Force -SkipPublisherCheck
      - name: Run Integration Tests
        shell: pwsh
        run: |
          $config = @{ Run = @{ Path = "./tests/integration" } }
          Invoke-Pester -Configuration $config

  e2e-tests:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Pester
        shell: pwsh
        run: Install-Module Pester -Force -SkipPublisherCheck
      - name: Run E2E Tests
        shell: pwsh
        run: |
          $config = @{ Run = @{ Path = "./tests/e2e" } }
          Invoke-Pester -Configuration $config
```

## Test Maintenance

### Best Practices

1. **Keep Tests DRY**
   - Use helper functions for common test setup
   - Share fixtures across related tests
   - Avoid duplicated test logic

2. **Test Independence**
   - Each test should run independently
   - No test should depend on another test
   - Use BeforeEach/AfterEach for setup/cleanup

3. **Descriptive Names**
   - Test names should explain what is being tested
   - Use "Should_Action_WhenCondition" pattern
   - Avoid unclear abbreviations

4. **Focused Assertions**
   - One logical assertion per test (can be multiple lines)
   - Test one thing per test method
   - Clear failure messages

5. **Performance**
   - Keep unit tests fast (< 100ms each)
   - Mock external dependencies
   - Use integration tests for slow operations

### Reviewing Test Results

```powershell
# Run with detailed output
$config = @{ Run = @{ Path = "./tests" }; Output = @{ Verbosity = "Detailed" } }
Invoke-Pester -Configuration $config

# Generate HTML report
$config = @{
    Run = @{ Path = "./tests" }
    TestResult = @{
        OutputFormat = "NUnitXml"
        OutputPath = "./test-results.xml"
    }
}
Invoke-Pester -Configuration $config
```

## Troubleshooting Tests

### Issue: Tests Cannot Find Script Files

**Solution**: Verify paths in BeforeAll block
```powershell
BeforeAll {
    $script:scriptsPath = Join-Path (Split-Path -Parent $PSScriptRoot) "scripts"
    Write-Host "Scripts path: $script:scriptsPath"
    Test-Path $script:scriptsPath | Should -Be $true
}
```

### Issue: Mock Not Being Used

**Solution**: Ensure mock is declared before function call
```powershell
BeforeEach {
    Mock Get-Command { } # Mock before use
}

It "Should use mocked command" {
    Get-Command # Uses mock
    Should -Invoke Get-Command
}
```

### Issue: Tests Pass Locally but Fail in CI

**Solution**: 
- Check file paths (use relative paths)
- Verify module dependencies
- Check PowerShell version in CI environment
- Review environment variables

## Advanced Testing

### Parameterized Tests

```powershell
It "Should validate email <email>" -ForEach @(
    @{ email = "test@example.com"; valid = $true },
    @{ email = "invalid-email"; valid = $false }
) {
    Validate-Email $email | Should -Be $valid
}
```

### Testing with Different Data

```powershell
$testCases = @(
    @{ input = "Standard"; expected = "Standard Protection" },
    @{ input = "Strict"; expected = "Strict Protection" }
)

It "Should process <input>" -ForEach $testCases {
    $result = Get-ProtectionLevel $input
    $result | Should -Be $expected
}
```

## Test Execution Workflow

### Pre-Commit Testing
```powershell
# Run quick unit tests before committing
Invoke-Pester -Path "./tests/unit" -Output Quick
```

### Pre-Push Testing
```powershell
# Run all tests before pushing
Invoke-Pester -Path "./tests" -Output Detailed
```

### Full Test Suite (CI/CD)
```powershell
# Complete test run in pipeline
$config = @{
    Run = @{ Path = "./tests"; Exit = $true }
    CodeCoverage = @{ Enabled = $true; Path = "./scripts" }
}
Invoke-Pester -Configuration $config
```

## Test Metrics

### Success Criteria
- ✅ All unit tests pass (green)
- ✅ Code coverage > 80%
- ✅ No skipped tests
- ✅ All integration tests pass
- ✅ All E2E tests pass

### Reporting

```powershell
# Generate comprehensive test report
$testResults = Invoke-Pester -Path "./tests" -PassThru

Write-Host "Total Tests: $($testResults.Tests.Count)"
Write-Host "Passed: $($testResults.PassedCount)"
Write-Host "Failed: $($testResults.FailedCount)"
Write-Host "Skipped: $($testResults.SkippedCount)"
```

---

**Version**: 1.0.0  
**Last Updated**: January 2026
