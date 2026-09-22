#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:BaselinePath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'
    $script:ParameterPath = Join-Path $script:SampleRoot 'tests' 'fixtures' 'com003' 'parameters.gateway.complete.json'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:Resolution = Resolve-BaselineConfiguration -ConfigurationPath $script:BaselinePath -ParameterPath $script:ParameterPath -DeploymentProfile 'ThirdPartyGateway'

    function ConvertTo-ReversedMemberOrder {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Node
        )

        if ($Node -is [System.Management.Automation.PSCustomObject]) {
            $reversed = [ordered]@{}
            foreach ($property in @($Node.PSObject.Properties | Sort-Object -Property Name -Descending)) {
                $reversed[$property.Name] = ConvertTo-ReversedMemberOrder -Node $property.Value
            }

            return [pscustomobject]$reversed
        }

        if ($Node -isnot [string] -and $Node -is [System.Collections.IList]) {
            return , @(foreach ($item in $Node) { ConvertTo-ReversedMemberOrder -Node $item })
        }

        return $Node
    }

    function New-ResolutionFrom {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Configuration,

            [string[]]$SuppliedParameterName = @('PRIMARY_SMTP_DOMAIN')
        )

        return [pscustomobject]@{
            Configuration           = $Configuration
            DeploymentProfile       = 'ThirdPartyGateway'
            SuppliedParameterName   = $SuppliedParameterName
            DeclaredPlaceholderName = @('PRIMARY_SMTP_DOMAIN')
        }
    }

    function Get-Sha256HexOfText {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Text
        )

        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
        return [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'COM-004-A2 stable canonical configuration hash' {

    Context 'Negative: hashing must refuse a resolution it does not recognize' {

        It 'fails with ResolutionNotRecognized when the input is not a resolution' {
            # Arrange
            $notAResolution = 'exchange-online-secure-baseline.json'

            # Act
            $act = { Get-BaselineConfigurationHash -Resolution $notAResolution }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ResolutionNotRecognized*'
        }

        It 'fails with ResolutionNotRecognized when the resolution carries no configuration' {
            # Arrange
            $withoutConfiguration = [pscustomobject]@{ DeploymentProfile = 'ThirdPartyGateway' }

            # Act
            $act = { Get-BaselineConfigurationHash -Resolution $withoutConfiguration }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ResolutionNotRecognized*'
        }

        It 'fails with ResolutionNotRecognized when the resolved configuration is null' {
            # Arrange
            $nullConfiguration = New-ResolutionFrom -Configuration $null

            # Act
            $act = { Get-BaselineConfigurationHash -Resolution $nullConfiguration }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ResolutionNotRecognized*'
        }
    }

    Context 'Negative: the hash must not vary, mislabel itself, or collide' {

        It 'does not report an algorithm other than SHA-256' {
            # Arrange
            $resolution = $script:Resolution

            # Act
            $result = Get-BaselineConfigurationHash -Resolution $resolution

            # Assert
            $result.Algorithm | Should -BeExactly 'SHA256'
        }

        It 'does not return a hash that differs from the SHA-256 of the canonical text' {
            # Arrange
            $expected = Get-Sha256HexOfText -Text (ConvertTo-CanonicalJson -InputObject $script:Resolution.Configuration)

            # Act
            $result = Get-BaselineConfigurationHash -Resolution $script:Resolution

            # Assert
            $result.Hash | Should -BeExactly $expected
        }

        It 'does not return a hash outside the 64 character lower-case hexadecimal form' {
            # Arrange
            $resolution = $script:Resolution

            # Act
            $result = Get-BaselineConfigurationHash -Resolution $resolution

            # Assert
            $result.Hash | Should -MatchExactly '^[0-9a-f]{64}$'
        }

        It 'does not return a different hash when the same resolution is hashed again' {
            # Arrange
            $first = (Get-BaselineConfigurationHash -Resolution $script:Resolution).Hash

            # Act
            $second = (Get-BaselineConfigurationHash -Resolution $script:Resolution).Hash

            # Assert
            $second | Should -BeExactly $first
        }

        It 'does not return the same hash for configurations whose values differ' {
            # Arrange
            $baseline = (Get-BaselineConfigurationHash -Resolution $script:Resolution).Hash
            $altered = $script:Resolution.Configuration | ConvertTo-Json -Depth 64 | ConvertFrom-Json
            $altered.metadata.version = '99.0.0'

            # Act
            $alteredHash = (Get-BaselineConfigurationHash -Resolution (New-ResolutionFrom -Configuration $altered)).Hash

            # Assert
            $alteredHash | Should -Not -BeExactly $baseline
        }

        It 'does not change the hash when a value outside the configuration changes' {
            # Arrange
            $baseline = (Get-BaselineConfigurationHash -Resolution (New-ResolutionFrom -Configuration $script:Resolution.Configuration)).Hash
            $differentEnvelope = New-ResolutionFrom -Configuration $script:Resolution.Configuration -SuppliedParameterName @('PRIMARY_SMTP_DOMAIN', 'CENTRAL_SIEM_PLATFORM')

            # Act
            $envelopeHash = (Get-BaselineConfigurationHash -Resolution $differentEnvelope).Hash

            # Assert
            $envelopeHash | Should -BeExactly $baseline
        }
    }

    Context 'Positive: a member-order permutation hashes identically' {

        It 'produces one identical SHA-256 hash for a shipped resolution and its member-order permutation' {
            # Arrange
            $permuted = New-ResolutionFrom -Configuration (ConvertTo-ReversedMemberOrder -Node $script:Resolution.Configuration)
            $expected = (Get-BaselineConfigurationHash -Resolution $script:Resolution).Hash

            # Act
            $actual = (Get-BaselineConfigurationHash -Resolution $permuted).Hash

            # Assert
            $actual | Should -BeExactly $expected
        }
    }
}
