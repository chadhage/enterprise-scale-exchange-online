BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $command = Join-Path $sampleRoot 'scripts/Deploy-ExchangeOnlineBaseline.ps1'
    $parameters = Get-Content (Join-Path $sampleRoot 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
    $parameters.entitlement.verified = $true
    $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
    $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE')
    $parameterPath = Join-Path $TestDrive 'parameters.json'
    $parameters | ConvertTo-Json -Depth 20 | Set-Content $parameterPath
}

Describe 'EXR-001 Exchange-only deployment boundary' {
    It 'refuses actionable preview for conflicting primary InternalRelay without <MissingField>' -TestCases @(
        @{ MissingField = 'source' }
        @{ MissingField = 'topologyApproval' }
    ) {
        param($MissingField)

        # Arrange
        $conflictingParameters = $parameters | ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable -DateKind String
        $primary = @($conflictingParameters.domainInventory.domains | Where-Object domainName -EQ $conflictingParameters.PRIMARY_SMTP_DOMAIN)[0]
        $primary.domainType = 'InternalRelay'
        $primary.topologyApproval = @{ owner = 'Synthetic routing owner'; reference = 'fixture:split-routing'; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') }
        $conflictingParameters.domainInventory.source.suppliedAtUtc = [datetimeoffset]::UtcNow.AddMinutes(-5).ToString('o')
        if ($MissingField -eq 'source') { $conflictingParameters.domainInventory.Remove('source') }
        else { $primary.Remove('topologyApproval') }
        $conflictPath = Join-Path $TestDrive "conflicting-topology-without-$MissingField.json"
        $conflictingParameters | ConvertTo-Json -Depth 30 | Set-Content $conflictPath
        $configurationPath = Join-Path $sampleRoot 'config/exchange-only.v1.json'
        $harness = Join-Path $sampleRoot 'tests/helpers/ExchangeOnlyPublicHarness.ps1'
        $calls = Join-Path $TestDrive "conflicting-topology-without-$MissingField.calls"
        $outputPath = Join-Path $TestDrive "conflicting-topology-without-$MissingField-output"

        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $conflictPath $outputPath $calls -ConfigurationPath $configurationPath -Deployment 2>&1 | Out-String
        $exitCode = $LASTEXITCODE

        # Assert
        Test-Path $calls | Should -BeFalse
        $output | Should -Not -Match 'ParameterBinding|parameter cannot be found|ExchangeSchemaInvalid'
        ($output -match '"Status"\s*:\s*"Planned"') | Should -BeFalse -Because "conflicting inventory without $MissingField must be refused before actionable preview (observed exit $exitCode)"
        $exitCode | Should -Not -Be 0 -Because 'invalid inventory must not bypass the topology conflict refusal'
        $output | Should -Match 'DomainInventory'
        $output | Should -Not -Match 'ExchangeOnlyPlan'
        Test-Path $outputPath | Should -BeFalse
    }

    It 'refuses actionable preview when approved primary InternalRelay conflicts with configured Authoritative' {
        # Arrange
        $conflictingParameters = $parameters | ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable -DateKind String
        $primary = @($conflictingParameters.domainInventory.domains | Where-Object domainName -EQ $conflictingParameters.PRIMARY_SMTP_DOMAIN)[0]
        $primary.domainType = 'InternalRelay'
        $primary.topologyApproval = @{ owner = 'Synthetic routing owner'; reference = 'fixture:split-routing'; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') }
        $conflictingParameters.domainInventory.source.suppliedAtUtc = [datetimeoffset]::UtcNow.AddMinutes(-5).ToString('o')
        $conflictPath = Join-Path $TestDrive 'conflicting-topology.json'
        $conflictingParameters | ConvertTo-Json -Depth 30 | Set-Content $conflictPath
        $configurationPath = Join-Path $sampleRoot 'config/exchange-only.v1.json'
        $harness = Join-Path $sampleRoot 'tests/helpers/ExchangeOnlyPublicHarness.ps1'
        $calls = Join-Path $TestDrive 'conflicting-topology.calls'
        $outputPath = Join-Path $TestDrive 'conflicting-topology-output'

        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $conflictPath $outputPath $calls -ConfigurationPath $configurationPath -Deployment 2>&1 | Out-String
        $exitCode = $LASTEXITCODE

        # Assert
        Test-Path $calls | Should -BeFalse
        $output | Should -Not -Match 'ParameterBinding|parameter cannot be found|ExchangeSchemaInvalid'
        ($output -match '"Status"\s*:\s*"Planned"') | Should -BeFalse -Because 'a conflicting inventory must not yield an actionable public preview'
        $exitCode | Should -Not -Be 0 -Because 'contradictory approved and configured topology must be refused before planning'
        $output | Should -Match 'DomainInventory.*(conflict|topology)|topology.*(conflict|configur)'
        $output | Should -Not -Match '"Status"\s*:\s*"Planned"'
        Test-Path $outputPath | Should -BeFalse
    }

    It 'refuses schema-invalid resolved parameters before any connection, collection or plan' {
        # Arrange
        $invalidParameters = $parameters.Clone()
        $invalidParameters.EXTERNAL_POSTMASTER_SMTP_ADDRESS = ''
        $invalidParameterPath = Join-Path $TestDrive 'invalid-resolved-parameters.json'
        $invalidParameters | ConvertTo-Json -Depth 20 | Set-Content $invalidParameterPath
        $harness = Join-Path $sampleRoot 'tests/helpers/ExchangeOnlyPublicHarness.ps1'
        $calls = Join-Path $TestDrive 'invalid-resolved.calls'
        $outputPath = Join-Path $TestDrive 'invalid-resolved-output'
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $invalidParameterPath $outputPath $calls -Deployment 2>&1 | Out-String
        # Assert
        $output | Should -Match 'ExchangeSchemaInvalid'
        $LASTEXITCODE | Should -Not -Be 0
        Test-Path $calls | Should -BeFalse
        $output | Should -Not -Match 'ExchangeOnlyPlan'
        Test-Path $outputPath | Should -BeFalse
    }

    It 'never connects or requests excluded mutation commands in default audit mode' {
        # Arrange
        $configurationPath = Join-Path $sampleRoot 'config/exchange-only.v1.json'
        # Act
        $output = & pwsh -NoProfile -NonInteractive -CommandWithArgs '& $args[0] -ParameterPath $args[1] -ConfigurationPath $args[2] -SkipConnection | ConvertTo-Json -Depth 30' $command $parameterPath $configurationPath 2>&1 | Out-String
        # Assert
        $output | Should -Match 'ExchangeOnlyPlan'
        $output | Should -Not -Match 'Set-AtpPolicyForO365|pp-inbound|pp-outbound|Connect-MgGraph|Purview'
    }

    It 'returns a bound Exchange-only mutation plan from the default public deployer' {
        # Arrange
        $manifest = Get-Content (Join-Path $sampleRoot 'config/exchange-only.manifest.v1.json') -Raw | ConvertFrom-Json
        # Act
        $output = & pwsh -NoProfile -NonInteractive -CommandWithArgs '& $args[0] -ParameterPath $args[1] -SkipConnection | ConvertTo-Json -Depth 30' $command $parameterPath 2>&1 | Out-String
        # Assert
        $LASTEXITCODE | Should -Be 0 -Because $output
        $plan = $output | ConvertFrom-Json
        $plan.Kind | Should -BeExactly 'ExchangeOnlyPlan'
        $plan.DeploymentProfile | Should -BeExactly 'ExchangeOnly'
        $plan.ConfigurationHash | Should -Match '^[a-f0-9]{64}$'
        @($plan.ControlId) | Should -Be @($manifest.ControlId)
        @($plan.Operation.Command) | Should -Contain 'Set-TransportConfig'
        @($plan.Operation.Command) | Should -Contain 'Set-ATPProtectionPolicyRule'
        @($plan.Operation.Command) | Should -Not -Contain 'Set-AtpPolicyForO365'
        $plan.Status | Should -BeExactly 'Planned'
        $plan.ExternalReadiness.Status | Should -BeExactly 'Unverified'
    }
}