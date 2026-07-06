# MDO Baseline Configuration Testing - Quick Reference

## Installation

```powershell
# Install Pester (if not already installed)
Install-Module Pester -Force -SkipPublisherCheck

# Verify PowerShell version
$PSVersionTable.PSVersion  # Must be 7.0+
```

## Running Tests

### Run All Tests
```powershell
cd .\mdo-baseline-config
Invoke-Pester -Path ".\tests" -Output Detailed
```

### By Test Level
```powershell
# Unit tests
Invoke-Pester -Path ".\tests\unit" -Output Detailed

# Integration tests
Invoke-Pester -Path ".\tests\integration" -Output Detailed

# E2E tests
Invoke-Pester -Path ".\tests\e2e" -Output Detailed
```

### Using Run-Tests.ps1 Script
```powershell
# Run all tests
.\tests\Run-Tests.ps1 -TestLevel All

# Run specific level
.\tests\Run-Tests.ps1 -TestLevel Unit

# With code coverage
.\tests\Run-Tests.ps1 -TestLevel All -WithCodeCoverage

# With HTML report
.\tests\Run-Tests.ps1 -TestLevel All -GenerateReport
```

## Test Files

### Unit Tests (50+ tests)
- **Deploy-MDOBaseline.Tests.ps1**
  - Parameter validation
  - Configuration parsing
  - Deployment modes
  - Logging functions

- **Validate-MDOConfiguration.Tests.ps1**
  - GUID validation
  - Email validation
  - Protection level validation
  - Threshold validation

### Integration Tests (20+ tests)
- **config-to-deployment.Tests.ps1**
  - Configuration generation
  - Parameter substitution
  - Policy coordination
  - Recipient targeting

### E2E Tests (5+ tests)
- **complete-deployment-flow.Tests.ps1**
  - Full deployment workflow
  - Dry-run to enforcement
  - Three-phase rollout
  - Phased transitions

### Acceptance Tests
- **ACCEPTANCE_CHECKLIST.md**
  - Configuration requirements
  - Deployment capabilities
  - Documentation completeness
  - Interface functionality
  - Testing requirements

## Test Fixtures

Located in `tests/fixtures/`:
- `valid-config.json` - Valid configuration file
- `invalid-config.json` - Invalid configuration for error testing

## Key Testing Areas

### Unit Test Focus
- Function parameter validation
- Configuration JSON parsing
- Placeholder substitution
- Error handling paths
- Logging functionality

### Integration Test Focus
- Configuration pipeline
- Multiple component interaction
- Allow/Block list processing
- Authentication settings
- Policy priorities

### E2E Test Focus
- Complete deployment workflows
- Phased rollout scenarios
- Dry-run to enforcement transitions
- Configuration consistency
- Rollback procedures

### Acceptance Test Focus
- All MDO policies supported
- Both protection levels available
- Zero hardcoding principle
- Multi-cloud support
- Complete documentation
- Professional interface

## Success Criteria

✅ **All unit tests pass**  
✅ **All integration tests pass**  
✅ **All E2E tests pass**  
✅ **Code coverage > 80%**  
✅ **No skipped tests**  
✅ **Acceptance checklist complete**

## Troubleshooting

### Pester Not Found
```powershell
Install-Module Pester -Force -SkipPublisherCheck -Scope CurrentUser
```

### Tests Fail Due to Missing Functions
- Verify scripts are in correct paths
- Check BeforeAll blocks in test files
- Ensure dot-sourcing of scripts

### Cannot Find Fixture Files
- Run tests from project root
- Verify fixture paths in test files
- Check fixtures directory exists

## CI/CD Integration

Tests run automatically on:
- ✅ Pull requests
- ✅ Commits to main branch
- ✅ Scheduled daily runs

See `.github/workflows/tests.yml` for CI/CD configuration

## Test Metrics

**Coverage Target**: 80%+  
**Pass Rate Target**: 100%  
**Test Execution Time**: < 5 minutes  
**Acceptance Sign-Off**: Required before release

## Resources

- [Pester Documentation](https://pester.dev/)
- [PowerShell Testing Best Practices](https://learn.microsoft.com/powershell/)
- [TEST_STRATEGY.md](./TEST_STRATEGY.md) - Detailed testing strategy
- [README.md](./README.md) - Complete testing guide

---

**Quick Help**: `Invoke-Pester -Path ".\tests" -Output Detailed`
