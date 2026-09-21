BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force
}
Describe 'EXR-001 scoped deployment operation admission' {
    It 'refuses <Case> before invoking a pre-read or mutator' -ForEach @(
        @{ Case = 'cross-workload mutator'; Command = 'Set-AtpPolicyForO365'; Read = { Get-TransportConfig } }
        @{ Case = 'cross-workload reader'; Command = 'Set-TransportConfig'; Read = { Get-AtpPolicyForO365 } }
        @{ Case = 'directory enumeration'; Command = 'Set-TransportConfig'; Read = { Get-Recipient } }
        @{ Case = 'dynamic reader'; Command = 'Set-TransportConfig'; Read = { & $unknownCommand } }
        @{ Case = 'Purview reader'; Command = 'Set-TransportConfig'; Read = { Get-RetentionCompliancePolicy } }
    ) {
        # Arrange
        $operation = @{ OperationId = 'exo-transport-config'; Command = $Command; Read = $Read }
        # Act
        $invoke = { Assert-BaselineExchangeMutationPlan -Operation @($operation) }
        # Assert
        $invoke | Should -Throw '*ExchangeMutationScopeViolation*'
    }
    It 'admits a declared Exchange mutation without executing its reader' {
        # Arrange
        $operation = @{ OperationId = 'exo-transport-config'; Command = 'Set-TransportConfig'; Read = { Get-TransportConfig } }
        # Act
        $accepted = Assert-BaselineExchangeMutationPlan -Operation @($operation)
        # Assert
        $accepted | Should -BeTrue
    }
}