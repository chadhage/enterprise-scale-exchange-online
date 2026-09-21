BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $command = Join-Path $sampleRoot 'scripts/Test-ExchangeOnlineBaseline.ps1'
    $harness = Join-Path $sampleRoot 'tests/helpers/ExchangeOnlyPublicHarness.ps1'
    $parameters = Get-Content (Join-Path $sampleRoot 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
    $parameters.entitlement.verified = $true
    $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
    $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE','THREAT_INTELLIGENCE')
    $parameterPath = Join-Path $TestDrive 'parameters.json'
    $parameters | ConvertTo-Json -Depth 20 | Set-Content $parameterPath
}

Describe 'EXR-001 default public Exchange dispatch' {
    It 'refuses schema-invalid resolved parameters before any connection, collection or evidence' {
        # Arrange
        $invalidParameters = $parameters.Clone()
        $invalidParameters.EXTERNAL_POSTMASTER_SMTP_ADDRESS = ''
        $invalidParameterPath = Join-Path $TestDrive 'invalid-resolved-parameters.json'
        $invalidParameters | ConvertTo-Json -Depth 20 | Set-Content $invalidParameterPath
        $calls = Join-Path $TestDrive 'invalid-resolved.calls'
        $outputPath = Join-Path $TestDrive 'invalid-resolved-output'
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $invalidParameterPath $outputPath $calls 2>&1 | Out-String
        # Assert
        $LASTEXITCODE | Should -Not -Be 0
        $output | Should -Match 'ExchangeSchemaInvalid'
        Test-Path $calls | Should -BeFalse
        Test-Path $outputPath | Should -BeFalse
    }

    It 'refuses malformed scoped input before any connection or collector' {
        # Arrange
        $configuration = Get-Content (Join-Path $sampleRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
        $configuration.controls['EXO-002'].smtpClientAuthenticationDisabled = 'false'
        $configurationPath = Join-Path $TestDrive 'invalid.json'
        $configuration | ConvertTo-Json -Depth 30 | Set-Content $configurationPath
        $calls = Join-Path $TestDrive 'invalid.calls'
        $outputPath = Join-Path $TestDrive 'invalid-output'
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $calls -ConfigurationPath $configurationPath 2>&1 | Out-String
        # Assert
        $output | Should -Match 'ExchangeSchemaInvalid'
        Test-Path $calls | Should -BeFalse
        Test-Path (Join-Path $outputPath 'exchange-online-evidence.json') | Should -BeFalse
    }

    It 'never connects to or collects an excluded service in an entitled default run' {
        # Arrange
        $outputPath = Join-Path $TestDrive 'no-excluded'
        $calls = Join-Path $TestDrive 'no-excluded.calls'
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $calls 2>&1 | Out-String
        # Assert
        Test-Path $calls | Should -BeTrue
        Get-Content $calls -Raw | Should -Not -Match 'EXCLUDED:'
        Test-Path (Join-Path $outputPath 'exchange-online-evidence.json') | Should -BeTrue -Because $output
    }

    It 'does not turn inaccessible Exchange collections into Pass or omit them' {
        # Arrange
        $outputPath = Join-Path $TestDrive 'inaccessible'
        $calls = Join-Path $TestDrive 'inaccessible.calls'
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $calls 2>&1 | Out-String
        # Assert
        $LASTEXITCODE | Should -Not -Be 0
        $path = Join-Path $outputPath 'exchange-online-evidence.json'
        Test-Path $path | Should -BeTrue -Because $output
        $envelope = Get-Content $path -Raw | ConvertFrom-Json
        @($envelope.Check).Count | Should -Be 25
        @($envelope.Check | Where-Object Status -EQ Pass).Count | Should -Be 0
        @($envelope.Check | Where-Object Status -EQ Error).Count | Should -Be 25
    }

    It 'completes the entire scoped registry through the actual default public command' {
        # Arrange
        $manifest = Get-Content (Join-Path $sampleRoot 'config/exchange-only.manifest.v1.json') -Raw | ConvertFrom-Json
        $outputPath = Join-Path $TestDrive 'complete'
        $calls = Join-Path $TestDrive 'complete.calls'
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $parameterPath $outputPath $calls -RawExchange 2>&1 | Out-String
        # Assert
        $path = Join-Path $outputPath 'exchange-online-evidence.json'
        Test-Path $path | Should -BeTrue -Because $output
        $envelope = Get-Content $path -Raw | ConvertFrom-Json
        @($envelope.Check.ControlId) | Should -Be @($manifest.ControlId)
        @($envelope.Evidence.ControlId) | Should -Be @($manifest.ControlId)
        $envelope.DeploymentProfile | Should -BeExactly 'ExchangeOnly'
        $envelope.ProfileVersion | Should -BeExactly '1.0.0'
        $envelope.ManifestHash | Should -Match '^[a-f0-9]{64}$'
        $envelope.ExternalReadiness.Status | Should -BeExactly 'Unverified'
        @($envelope.ExternalCheck.ControlId).Count | Should -Be 3
        @($envelope.Exclusion.ControlId).Count | Should -Be 15
        $envelope.Exclusion.Count | Should -Be $manifest.Exclusion.Count
        ($envelope.Check | Where-Object ControlId -EQ 'EXO-001').Status | Should -BeExactly 'Pass'
        ($envelope.Evidence | Where-Object ControlId -EQ 'EXO-001').Value.DomainType | Should -BeExactly 'Authoritative'
        foreach ($controlId in @('MON-003','OPS-001','OPS-002')) {
            $result = $envelope.Check | Where-Object ControlId -EQ $controlId
            $result.Status | Should -BeExactly 'Error'
            $result.Reason | Should -Match 'ExchangeOperationalEvidenceRequired'
        }
        $observed = Get-Content $calls
        $observed | Should -Contain 'Get-RoleGroup'
        $observed | Should -Contain 'Get-RetentionPolicy'
        $observed | Should -Contain 'Get-DkimSigningConfig'
        $observed | Should -Contain 'Get-AntiPhishPolicy'
        @($observed | Where-Object { $_ -like 'EXCLUDED:*' }).Count | Should -Be 0
    }
}