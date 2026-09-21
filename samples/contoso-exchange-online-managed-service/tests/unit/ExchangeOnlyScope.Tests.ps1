BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force
}

Describe 'EXR-001 Exchange-only manifest boundary' {
    It 'rejects unknown profiles rather than falling back to history' {
        # Arrange
        $profile = 'Undeclared'
        # Act
        $invoke = { Get-BaselineControlRegistry -Profile $profile }
        # Assert
        $invoke | Should -Throw '*UnknownExecutionProfile*'
    }

    It 'does not dispatch excluded controls by default' {
        # Arrange
        $excluded = @('EXO-003','EXO-011','MDO-004','MDO-005','PP-001','PP-002','PP-003','PP-004','ABN-001','ABN-002','MON-001','MON-002','GOV-001','GOV-002','GOV-006','GOV-007')
        # Act
        $registry = Get-BaselineControlRegistry
        # Assert
        @($registry | Where-Object ControlId -In $excluded).Count | Should -Be 0
    }

    It 'rejects a cross-workload mutation in the Exchange configuration' {
        # Arrange
        $configuration = @{ metadata = @{ deploymentProfile = 'ExchangeOnly'; version = '1.0.0' }; desiredState = @{ defenderForOffice365 = @{ safeDocuments = @{ enabled = $true } } } }
        # Act
        $invoke = { Assert-BaselineExchangeScope -Configuration $configuration }
        # Assert
        $invoke | Should -Throw '*ExchangeScopeViolation*'
    }

    It 'refuses a missing manifest control instead of reducing the denominator' {
        # Arrange
        $configuration = @{ metadata = @{ deploymentProfile = 'ExchangeOnly'; version = '1.0.0' }; controls = @{} }
        # Act
        $invoke = { Assert-BaselineExchangeScope -Configuration $configuration }
        # Assert
        $invoke | Should -Throw '*ExchangeControlMissing*'
    }

    It 'does not infer entitlement from a declared messaging tier' {
        # Arrange
        $configurationPath = Join-Path $sampleRoot 'config/exchange-only.v1.json'
        $parameterPath = Join-Path $sampleRoot 'config/parameters.exchange-only.sample.json'
        # Act
        $invoke = { Get-BaselineExchangeContext -ConfigurationPath $configurationPath -ParameterPath $parameterPath }
        # Assert
        $invoke | Should -Throw '*ExchangeEntitlementUnverified*'
    }

    It 'refuses historical configuration at the default public boundary before connecting' {
        # Arrange
        $command = Join-Path $sampleRoot 'scripts/Test-ExchangeOnlineBaseline.ps1'
        $configuration = Join-Path $sampleRoot 'config/exchange-online-secure-baseline.microsoft-native.json'
        $parameters = Join-Path $sampleRoot 'tests/fixtures/com007/parameters.native.complete.json'
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $command -ParameterPath $parameters -ConfigurationPath $configuration -SkipConnection 2>&1 | Out-String
        # Assert
        $output | Should -Match 'HistoricalProfileRequiresOptIn'
    }

    It 'refuses historical configuration at the deployment boundary before connecting' {
        # Arrange
        $command = Join-Path $sampleRoot 'scripts/Deploy-ExchangeOnlineBaseline.ps1'
        $configuration = Join-Path $sampleRoot 'config/exchange-online-secure-baseline.microsoft-native.json'
        $parameters = Join-Path $sampleRoot 'tests/fixtures/com007/parameters.native.complete.json'
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $command -ParameterPath $parameters -ConfigurationPath $configuration -SkipConnection 2>&1 | Out-String
        # Assert
        $output | Should -Match 'HistoricalProfileRequiresOptIn'
    }

    It 'accepts the shipped complete Exchange-only manifest and explicit historical registry' {
        # Arrange
        $configuration = Get-Content (Join-Path $sampleRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
        # Act
        $manifest = Assert-BaselineExchangeScope -Configuration $configuration
        # Assert
        $manifest.Profile | Should -BeExactly 'ExchangeOnly'
        $manifest.Version | Should -BeExactly '1.0.0'
        @($manifest.ControlId).Count | Should -Be 25
        $registry = Get-BaselineControlRegistry
        @($registry.ControlId) | Should -Be @($manifest.ControlId)
        $historical = Get-BaselineControlRegistry -Profile Historical
        @($historical.ControlId).Count | Should -Be 43
        $manifest.ExternalReadiness.Status | Should -BeExactly 'Unverified'
    }
}