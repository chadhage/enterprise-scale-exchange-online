BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force
}

Describe 'EXR-001 typed Exchange configuration boundary' {
    It 'rejects malformed setting <Case>' -ForEach @(
        @{ Case = 'string boolean'; Control = 'EXO-002'; Key = 'smtpClientAuthenticationDisabled'; Value = 'false' }
        @{ Case = 'scalar list'; Control = 'EXO-007'; Key = 'allowList'; Value = 'someone@example.test' }
        @{ Case = 'object list item'; Control = 'EXO-010'; Key = 'approvedMembers'; Value = @(@{ name = 'unexpected' }) }
        @{ Case = 'null boolean'; Control = 'MDO-001'; Key = 'enabled'; Value = $null }
        @{ Case = 'invalid domain type'; Control = 'EXO-001'; Key = 'domainType'; Value = 'Undeclared' }
        @{ Case = 'negative key size'; Control = 'AUTH-001'; Key = 'keySize'; Value = -1 }
    ) {
        # Arrange
        $configuration = Get-Content (Join-Path $sampleRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
        $configuration.controls[$Control][$Key] = $Value
        # Act
        $invoke = { Assert-BaselineExchangeScope -Configuration $configuration }
        # Assert
        $invoke | Should -Throw '*ExchangeSchemaInvalid*'
    }

    It 'rejects omission of retained operational control <_>' -ForEach @('MON-003','OPS-001','OPS-002') {
        # Arrange
        $configuration = Get-Content (Join-Path $sampleRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
        $configuration.controls.Remove($_)
        # Act
        $invoke = { Assert-BaselineExchangeScope -Configuration $configuration }
        # Assert
        $invoke | Should -Throw '*ExchangeControlMissing*'
    }

    It 'accepts exactly the complete typed 25-control Exchange configuration' {
        # Arrange
        $configuration = Get-Content (Join-Path $sampleRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
        # Act
        $manifest = Assert-BaselineExchangeScope -Configuration $configuration
        # Assert
        @($manifest.ControlId).Count | Should -Be 25
        @($manifest.ControlId) | Should -Contain 'MON-003'
        @($manifest.ControlId) | Should -Contain 'OPS-001'
        @($manifest.ControlId) | Should -Contain 'OPS-002'
        Test-Path (Join-Path $sampleRoot 'config/exchange-only.schema.v1.json') | Should -BeTrue
    }
}