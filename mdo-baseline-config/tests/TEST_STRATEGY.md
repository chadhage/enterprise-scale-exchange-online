# MDO Baseline Configuration - Testing Strategy & Framework

Comprehensive testing strategy covering unit, feature, integration, end-to-end, and acceptance testing.

## Testing Pyramid

```
                      ▲
                     /│\
                    / │ \         Acceptance Tests (2-3 tests)
                   /  │  \       Business outcomes validation
                  /   │   \
                 /────┼────\    E2E Tests (5-10 tests)
                /     │     \   Complete workflows
               /      │      \
              /───────┼───────\  Integration Tests (20-30 tests)
             /        │        \ Component interactions
            /         │         \
           /──────────┼──────────\ Feature Tests (15-20 tests)
          /           │           \ Feature-level validation
         /            │            \
        /─────────────┼─────────────\ Unit Tests (50-80 tests)
       /              │              \ Individual functions
      /______________│______________\
```

## Test Structure

```
tests/
├── unit/                              # Unit tests (Pester)
│   ├── Deploy-MDOBaseline.Tests.ps1
│   ├── Generate-ConfigFromTemplate.Tests.ps1
│   ├── Validate-MDOConfiguration.Tests.ps1
│   └── helpers.Tests.ps1
│
├── features/                          # Feature tests
│   ├── configuration-generation.feature
│   ├── policy-deployment.feature
│   └── validation.feature
│
├── integration/                       # Integration tests (PowerShell)
│   ├── config-to-deployment.Tests.ps1
│   ├── policy-interactions.Tests.ps1
│   └── allow-block-list.Tests.ps1
│
├── e2e/                              # End-to-end tests
│   ├── complete-deployment-flow.Tests.ps1
│   ├── dry-run-to-enforcement.Tests.ps1
│   └── phased-rollout.Tests.ps1
│
├── acceptance/                        # Acceptance tests & checklists
│   ├── business-requirements.Tests.ps1
│   └── ACCEPTANCE_CHECKLIST.md
│
├── fixtures/                          # Test data
│   ├── valid-config.json
│   ├── invalid-config.json
│   ├── standard-config.json
│   └── strict-config.json
│
└── README.md                         # Testing guide
```

## 1. Unit Tests

### Purpose
Test individual functions in isolation with mocked dependencies.

### Tools
- **Pester 5.3+** - PowerShell unit testing framework
- **Mock objects** - Simulate Exchange Online cmdlets

### Coverage Areas

#### Deploy-MDOBaseline.ps1
- `Test-Prerequisites` - Validates PowerShell version, modules
- `Connect-ExchangeOnline` - Connection logic with mocks
- `Resolve-ConfigParameters` - Parameter replacement ({{}} tokens)
- Individual Deploy-* functions - Policy creation logic
- `Write-Log` - Logging functionality
- Error handling paths

#### Generate-ConfigFromTemplate.ps1
- Template loading
- Parameter substitution (all placeholder types)
- JSON parsing and validation
- Output file writing
- Error scenarios (missing file, invalid path)

#### Validate-MDOConfiguration.ps1
- Configuration loading
- Schema validation (each field type)
- GUID format validation
- Email validation
- Required field checks
- Warning detection logic

### Example Unit Test Structure
```powershell
Describe "Resolve-ConfigParameters" {
    Context "Standard placeholder replacement" {
        It "Should replace {{TENANT_ID}} with provided value" {
            # Arrange
            $config = @{ "tenantId" = "{{TENANT_ID}}" }
            $expectedId = "12345678-1234-1234-1234-123456789012"
            
            # Act
            $result = Resolve-ConfigParameters -Config $config -TenantId $expectedId
            
            # Assert
            $result.tenantId | Should -Be $expectedId
        }
    }
}
```

## 2. Feature Tests

### Purpose
Test complete features work end-to-end, validating business requirements.

### Format
Gherkin BDD syntax using PowerShell Specflow or Pester

### Features

#### Configuration Generation
```gherkin
Feature: Configuration Generation
  As an administrator
  I want to generate organization-specific configurations
  So that I can deploy MDO baselines quickly

  Scenario: Generate config from standard template
    Given a standard baseline template
    When I provide organization parameters
    Then a valid configuration file should be generated
    And all placeholders should be replaced
    And the configuration should validate against schema
```

#### Policy Deployment
```gherkin
Feature: Policy Deployment
  As a security team
  I want to deploy policies to Exchange Online
  So that my organization is protected

  Scenario: Deploy anti-phishing policy in audit mode
    Given a valid configuration
    When I deploy in Audit mode
    Then the policy should be created
    And no emails should be blocked
    And detection should be logged
```

#### Configuration Validation
```gherkin
Feature: Configuration Validation
  As an administrator
  I want to validate configurations
  So that I ensure deployment will succeed

  Scenario: Validate standard baseline
    Given a standard baseline configuration
    When I run validation
    Then validation should pass
    And no warnings should be present
```

## 3. Integration Tests

### Purpose
Test multiple components working together, validating interactions.

### Test Categories

#### Configuration to Deployment Flow
- Load config → Validate → Resolve parameters → Create policies
- Verify each step output feeds correctly to next step

#### Policy Interaction Tests
- Multiple policies don't conflict
- Policy priority is respected
- Recipient targeting works across policies
- Allow/Block list applies correctly

#### Component Integration
- Configuration file → PowerShell parsing → Exchange Online API
- Verify data transformation at each step
- Ensure no information loss

### Example Integration Test
```powershell
Describe "Configuration to Deployment Integration" {
    Context "Full pipeline with standard baseline" {
        It "Should successfully process config from generation to deployment readiness" {
            # Generate config
            $config = .\Generate-ConfigFromTemplate.ps1 -TemplateFile $standardTemplate -OutputFile $testOutput
            
            # Validate config
            $validation = .\Validate-MDOConfiguration.ps1 -ConfigPath $testOutput
            $validation.Failed.Count | Should -Be 0
            
            # Verify no unreplaced placeholders
            (Get-Content $testOutput -Raw) -match "\{\{" | Should -BeNullOrEmpty
        }
    }
}
```

## 4. End-to-End Tests

### Purpose
Test complete workflows from start to finish in realistic scenarios.

### Test Scenarios

#### Scenario 1: Complete Deployment Flow
1. Generate configuration from template
2. Validate configuration
3. Execute dry-run
4. Verify dry-run output
5. Execute full deployment
6. Verify policies created in Exchange Online
7. Verify recipient targeting
8. Verify Allow/Block lists applied

#### Scenario 2: Dry-Run to Enforcement
1. Deploy in Audit mode
2. Verify detection without enforcement
3. Switch to Enforce mode
4. Deploy same configuration
5. Verify policies updated with enforcement

#### Scenario 3: Phased Rollout
1. Deploy Phase 1 (10% pilot group)
2. Verify only pilot group targeted
3. Deploy Phase 2 (50% staged group)
4. Verify staged group targeted
5. Deploy Phase 3 (organization-wide)
6. Verify all users targeted

### Prerequisites for E2E Tests
- Test Microsoft 365 tenant (optional)
- Mock Exchange Online (recommended for automated tests)
- Test configuration files
- Test recipient groups

## 5. Acceptance Tests

### Purpose
Validate business requirements and customer expectations.

### Test Categories

#### Configuration Requirements
- ✓ All MDO policies supported
- ✓ Both Standard and Strict levels available
- ✓ Zero hardcoding (all parameterized)
- ✓ Multi-cloud support (Cloud, GCC, GCC-High, DoD)

#### Deployment Requirements
- ✓ Dry-run capability (preview without changes)
- ✓ Audit and Enforce modes
- ✓ Phased rollout support (3 phases)
- ✓ Rollback procedures documented

#### Documentation Requirements
- ✓ README covers overview and quick start
- ✓ DEPLOYMENT.md provides step-by-step procedures
- ✓ CUSTOMIZATION.md explains tailoring options
- ✓ TROUBLESHOOTING.md covers common issues

#### Interface Requirements
- ✓ Microsite loads without errors
- ✓ Configuration can be generated from web form
- ✓ Configuration can be downloaded as JSON
- ✓ All sections accessible and functional

### Acceptance Test Checklist
See `tests/acceptance/ACCEPTANCE_CHECKLIST.md`

## Running Tests

### Prerequisites
```powershell
# Install Pester for unit/integration/e2e tests
Install-Module Pester -Force -SkipPublisherCheck

# Verify installation
$PSVersionTable.PSVersion  # Should be 7.0+
Get-Module Pester -ListAvailable
```

### Run All Tests
```powershell
# Run all Pester tests
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

### Run Specific Test Level
```powershell
# Unit tests only
Invoke-Pester -Path "./tests/unit" -Output Detailed

# Integration tests only
Invoke-Pester -Path "./tests/integration" -Output Detailed

# E2E tests only
Invoke-Pester -Path "./tests/e2e" -Output Detailed
```

### Run Single Test File
```powershell
Invoke-Pester -Path "./tests/unit/Deploy-MDOBaseline.Tests.ps1" -Output Detailed
```

## Test Coverage Goals

| Level | Target | Rationale |
|-------|--------|-----------|
| Unit Tests | 80%+ | Core logic must be reliable |
| Feature Tests | 95%+ | All features must work |
| Integration Tests | 85%+ | Component interactions critical |
| E2E Tests | 100% | All workflows must work |
| Acceptance Tests | 100% | Business requirements essential |

## CI/CD Integration

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
        run: Invoke-Pester -Path "./tests/unit" -Output Detailed

  integration-tests:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Integration Tests
        shell: pwsh
        run: Invoke-Pester -Path "./tests/integration" -Output Detailed

  e2e-tests:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run E2E Tests
        shell: pwsh
        run: Invoke-Pester -Path "./tests/e2e" -Output Detailed
```

## Test Data Management

### Fixtures Directory
Located in `tests/fixtures/`, contains:

**valid-config.json**
- Complete, valid configuration
- All required fields
- Proper formatting
- Passes schema validation

**invalid-config.json**
- Missing required fields
- Malformed JSON
- Invalid values
- Fails schema validation

**standard-config.json**
- Standard protection baseline
- Parameterized placeholders
- All 7 policies defined

**strict-config.json**
- Strict protection baseline
- Advanced features enabled
- More aggressive settings

## Quality Metrics

### Code Coverage
- Unit tests: 80%+ coverage of production code
- Integration tests: Critical path coverage
- E2E tests: All user workflows

### Test Quality
- Each test: Single responsibility (one assertion focus)
- Descriptive names: `Should_ReplaceAllPlaceholders_WhenParametersProvided`
- Proper arrange-act-assert pattern
- Mock external dependencies

### Build Quality
- All tests must pass before merge
- Code coverage must not decrease
- No test skips in main branch
- Failed tests must be investigated

## Troubleshooting Tests

### Issue: Pester Module Not Found
```powershell
Install-Module Pester -Force -SkipPublisherCheck -Scope CurrentUser
```

### Issue: Tests Fail Due to Missing Mock Data
- Check fixture files exist in `tests/fixtures/`
- Verify fixture file paths in test files
- Run tests from project root directory

### Issue: Exchange Online Tests Need Real Connection
- Use `-SkipOnline` parameter for offline testing
- Mock Exchange cmdlets with Pester's `Mock`
- Create separate test suite for online testing

## Next Steps

1. ✅ Create test directory structure
2. ✅ Write unit test files (Pester)
3. ✅ Write feature tests (Gherkin/Pester)
4. ✅ Write integration tests
5. ✅ Write E2E test scenarios
6. ✅ Create acceptance test checklist
7. ✅ Configure CI/CD pipeline
8. ✅ Document test execution procedures

---

**Version**: 1.0.0  
**Last Updated**: January 2026
