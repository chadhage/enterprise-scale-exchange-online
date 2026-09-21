BeforeDiscovery {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force
}

BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force
}

Describe 'EXR-001 registry admission before collection' {
    InModuleScope ExchangeOnlineBaseline.Common {
        BeforeAll {
            $originalRegistry = Get-BaselineControlRegistry
            $configuration = Get-Content (Join-Path (Get-Module ExchangeOnlineBaseline.Common).ModuleBase '../config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
            $context = @{ Configuration = $configuration; Manifest = Get-BaselineExchangeManifest; Parameters = @{ PRIMARY_SMTP_DOMAIN = 'example.test' }; Entitlement = @{ servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE','THREAT_INTELLIGENCE') } }
        }
        BeforeEach {
            $script:guardRegistry = @($originalRegistry | ConvertTo-Json -Depth 30 | ConvertFrom-Json)
            Mock Get-BaselineControlRegistry { ,$script:guardRegistry }
            Mock Get-AcceptedDomainEvidence { throw 'CollectorMustNotRun' }
        }
        It 'refuses <Case> before the first collector' -ForEach @(
            @{ Case = 'missing control' }
            @{ Case = 'unknown applicability' }
            @{ Case = 'mixed blank applicability' }
            @{ Case = 'false exclusion' }
            @{ Case = 'substituted external collector' }
            @{ Case = 'duplicate control' }
        ) {
            # Arrange
            switch ($Case) {
                'missing control' { $script:guardRegistry = @($script:guardRegistry | Where-Object ControlId -NE 'GOV-005') }
                'unknown applicability' { $script:guardRegistry[-1].ApplicableProfile = @('Undeclared') }
                'mixed blank applicability' { $script:guardRegistry[-1].ApplicableProfile = @('Native','') }
                'false exclusion' { $script:guardRegistry[-1].ApplicableProfile = @('Gateway') }
                'substituted external collector' { $script:guardRegistry[-1].Collector = 'Get-DataLossPreventionEvidence' }
                'duplicate control' { $script:guardRegistry += $script:guardRegistry[-1] }
            }
            # Act
            $invoke = { Invoke-BaselineExchangeRegistry -Context $context }
            # Assert
            $invoke | Should -Throw '*ExchangeRegistryInvalid*'
            Should -Invoke Get-AcceptedDomainEvidence -Times 0 -Exactly
        }
        It 'runs exactly one result for every admitted Exchange control' {
            # Arrange
            $expected = 25
            # Act
            $execution = @(Invoke-BaselineExchangeRegistry -Context $context)
            # Assert
            $execution.Count | Should -Be $expected
            @($execution.ControlId | Select-Object -Unique).Count | Should -Be $expected
            Should -Invoke Get-AcceptedDomainEvidence -Times 1 -Exactly
        }
    }
}