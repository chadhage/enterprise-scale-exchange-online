#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:SchemaPath = Join-Path $script:SampleRoot 'config\exchange-online-secure-baseline.schema.json'
    $script:GatewayPath = Join-Path $script:SampleRoot 'config\exchange-online-secure-baseline.json'
    $script:NativePath = Join-Path $script:SampleRoot 'config\exchange-online-secure-baseline.microsoft-native.json'
    Import-Module (Join-Path $script:SampleRoot 'scripts\ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking
}

Describe 'PP-006 shipped profile parity' {
    It 'rejects a Gateway profile with no trusted ARC sealer' {
        # Arrange
        $configuration = Get-Content $script:GatewayPath -Raw | ConvertFrom-Json
        $configuration.desiredState.emailAuthentication.PSObject.Properties.Remove('trustedArcSealers')
        # Act
        $valid = $configuration | ConvertTo-Json -Depth 30 | Test-Json -SchemaFile $script:SchemaPath -ErrorAction SilentlyContinue
        # Assert
        $valid | Should -BeFalse
    }

    It 'rejects a Native profile with a trusted ARC sealer' {
        # Arrange
        $configuration = Get-Content $script:NativePath -Raw | ConvertFrom-Json
        $configuration.desiredState.emailAuthentication.trustedArcSealers = @('not-native.example')
        # Act
        $valid = $configuration | ConvertTo-Json -Depth 30 | Test-Json -SchemaFile $script:SchemaPath -ErrorAction SilentlyContinue
        # Assert
        $valid | Should -BeFalse
    }

    It 'declares exact PP applicability without overlap or omission' {
        # Arrange
        $registry = @(Get-BaselineControlRegistry -Profile Historical)[0]
        $pp = @($registry | Where-Object ControlId -Like 'PP-*')
        # Act
        $fold = @($pp | ForEach-Object { '{0}:{1}' -f $_.ControlId, (@($_.ApplicableProfile) -join '+') })
        # Assert
        $fold | Should -Be @('PP-001:Gateway', 'PP-002:Gateway', 'PP-003:Gateway', 'PP-004:Gateway', 'PP-005:Native')
    }

    It 'ships one schema-valid exact PP contract for each profile' {
        # Arrange
        $gateway = Get-Content $script:GatewayPath -Raw
        $native = Get-Content $script:NativePath -Raw
        # Act
        $result = @(
            $gateway | Test-Json -SchemaFile $script:SchemaPath
            $native | Test-Json -SchemaFile $script:SchemaPath
        )
        # Assert
        $result | Should -Be @($true, $true)
        @((($gateway | ConvertFrom-Json).desiredState.emailAuthentication.trustedArcSealers)).Count | Should -BeGreaterThan 0
        @((($native | ConvertFrom-Json).desiredState.emailAuthentication.trustedArcSealers)).Count | Should -Be 0
    }
}