#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:BaselinePath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'
    $script:ParameterPath = Join-Path $script:SampleRoot 'tests' 'fixtures' 'com003' 'parameters.gateway.complete.json'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function Get-FreshResolution {
        [CmdletBinding()]
        param()

        return Resolve-BaselineConfiguration -ConfigurationPath $script:BaselinePath -ParameterPath $script:ParameterPath -DeploymentProfile 'ThirdPartyGateway'
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'COM-004-A3 immutable resolved configuration' {

    Context 'Negative: the returned configuration must reject every mutation' {

        It 'rejects assignment to a top-level member' {
            # Arrange
            $configuration = (Get-BaselineConfigurationHash -Resolution (Get-FreshResolution)).Configuration

            # Act
            $act = { $configuration.metadata = 'replaced' }

            # Assert
            $act | Should -Throw
        }

        It 'rejects assignment to a nested member' {
            # Arrange
            $configuration = (Get-BaselineConfigurationHash -Resolution (Get-FreshResolution)).Configuration

            # Act
            $act = { $configuration.metadata.version = '99.0.0' }

            # Assert
            $act | Should -Throw
        }

        It 'rejects assignment to a member nested below the desired state' {
            # Arrange
            $configuration = (Get-BaselineConfigurationHash -Resolution (Get-FreshResolution)).Configuration

            # Act
            $act = { $configuration.desiredState.mailFlow.gateway.declared = $false }

            # Assert
            $act | Should -Throw
        }

        It 'rejects replacement of a nested collection member' {
            # Arrange
            $configuration = (Get-BaselineConfigurationHash -Resolution (Get-FreshResolution)).Configuration

            # Act
            $act = { $configuration.administratorInputs.proofpointSmartHosts = @('attacker.example') }

            # Assert
            $act | Should -Throw
        }

        It 'rejects assignment to a nested collection element' {
            # Arrange
            $configuration = (Get-BaselineConfigurationHash -Resolution (Get-FreshResolution)).Configuration

            # Act
            $act = { $configuration.administratorInputs.proofpointSmartHosts[0] = 'attacker.example' }

            # Assert
            $act | Should -Throw
        }

        It 'does not hand back the mutable configuration instance carried by the resolution' {
            # Arrange
            $resolution = (Get-FreshResolution)

            # Act
            $configuration = (Get-BaselineConfigurationHash -Resolution $resolution).Configuration

            # Assert
            [object]::ReferenceEquals($configuration, $resolution.Configuration) | Should -BeFalse
        }
    }

    Context 'Positive: freezing preserves the resolved document exactly' {

        It 'serializes to exactly the canonical text of the resolution it was built from' {
            # Arrange
            $expected = ConvertTo-CanonicalJson -InputObject (Get-FreshResolution).Configuration

            # Act
            $configuration = (Get-BaselineConfigurationHash -Resolution (Get-FreshResolution)).Configuration

            # Assert
            (ConvertTo-CanonicalJson -InputObject $configuration) | Should -BeExactly $expected
        }
    }
}

