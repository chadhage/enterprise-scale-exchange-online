#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'

    # The two shipped profiles. Deployment and evidence must reach the same desired state and the
    # same identity for each of them, so the context is asserted over both.
    $script:ShippedProfile = @(
        [pscustomobject]@{
            Name              = 'MicrosoftNative'
            ConfigurationPath = (Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.microsoft-native.json')
            ParameterPath     = (Join-Path $script:SampleRoot 'tests' 'fixtures' 'com007' 'parameters.native.complete.json')
        }
        [pscustomobject]@{
            Name              = 'ThirdPartyGateway'
            ConfigurationPath = (Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json')
            ParameterPath     = (Join-Path $script:SampleRoot 'tests' 'fixtures' 'com003' 'parameters.gateway.complete.json')
        }
    )

    $script:NativeProfile = $script:ShippedProfile | Where-Object { $_.Name -eq 'MicrosoftNative' }
    $script:GatewayProfile = $script:ShippedProfile | Where-Object { $_.Name -eq 'ThirdPartyGateway' }

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-MutatedJsonFile {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$SourcePath,

            [Parameter(Mandatory)]
            [string]$Directory,

            [Parameter(Mandatory)]
            [scriptblock]$Mutate
        )

        $document = Get-Content -LiteralPath $SourcePath -Raw | ConvertFrom-Json -AsHashtable
        & $Mutate $document

        $path = Join-Path $Directory ('Mutated-{0}.json' -f [guid]::NewGuid().ToString('N'))
        $document | ConvertTo-Json -Depth 64 | Set-Content -LiteralPath $path -Encoding utf8
        return $path
    }

    function Get-UnresolvedBaselineHash {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ConfigurationPath
        )

        $document = Get-Content -LiteralPath $ConfigurationPath -Raw | ConvertFrom-Json
        return (Get-BaselineConfigurationHash -Resolution ([pscustomobject]@{ Configuration = $document })).Hash
    }

    function Get-CanonicalTextHash {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$CanonicalJson
        )

        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($CanonicalJson)
        return [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'COM-007-A2 deterministic shared baseline context' {

    Context 'Negative: the context must refuse an unusable input' {

        It 'fails with ConfigurationFileNotFound when the configuration file does not exist' {
            # Arrange
            $absentConfiguration = Join-Path $TestDrive 'absent-baseline.json'

            # Act
            $act = { Get-BaselineContext -ConfigurationPath $absentConfiguration -ParameterPath $script:GatewayProfile.ParameterPath -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ConfigurationFileNotFound*'
        }

        It 'fails with ParameterFileNotFound when the parameter file does not exist' {
            # Arrange
            $absentParameter = Join-Path $TestDrive 'absent-parameters.json'

            # Act
            $act = { Get-BaselineContext -ConfigurationPath $script:GatewayProfile.ConfigurationPath -ParameterPath $absentParameter -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ParameterFileNotFound*'
        }

        It 'fails with SchemaFileNotFound when the schema file does not exist' {
            # Arrange
            $absentSchema = Join-Path $TestDrive 'absent-schema.json'

            # Act
            $act = { Get-BaselineContext -ConfigurationPath $script:GatewayProfile.ConfigurationPath -ParameterPath $script:GatewayProfile.ParameterPath -SchemaPath $absentSchema }

            # Assert
            $act | Should -Throw -ExpectedMessage 'SchemaFileNotFound*'
        }
    }

    Context 'Negative: the context must refuse an unresolved administrator input' {

        It 'fails with RecursivePlaceholderValue when the parameter file still carries an administrator placeholder' {
            # Arrange
            $parameterPath = New-MutatedJsonFile -SourcePath $script:GatewayProfile.ParameterPath -Directory $TestDrive -Mutate {
                param($document)
                $document['SECURITY_OPERATIONS_MAILBOX'] = '__ADMIN_REQUIRED:SECURITY_OPERATIONS_MAILBOX__'
            }

            # Act
            $act = { Get-BaselineContext -ConfigurationPath $script:GatewayProfile.ConfigurationPath -ParameterPath $parameterPath -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'RecursivePlaceholderValue*'
        }

        It 'fails with UnresolvedPlaceholder when the parameter file omits a declared administrator input' {
            # Arrange
            $parameterPath = New-MutatedJsonFile -SourcePath $script:GatewayProfile.ParameterPath -Directory $TestDrive -Mutate {
                param($document)
                $null = $document.Remove('SECURITY_OPERATIONS_MAILBOX')
            }

            # Act
            $act = { Get-BaselineContext -ConfigurationPath $script:GatewayProfile.ConfigurationPath -ParameterPath $parameterPath -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'UnresolvedPlaceholder*'
        }

        It 'names the placeholder that was left unresolved' {
            # Arrange
            $parameterPath = New-MutatedJsonFile -SourcePath $script:GatewayProfile.ParameterPath -Directory $TestDrive -Mutate {
                param($document)
                $null = $document.Remove('SECURITY_OPERATIONS_MAILBOX')
            }

            # Act
            $act = { Get-BaselineContext -ConfigurationPath $script:GatewayProfile.ConfigurationPath -ParameterPath $parameterPath -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage '*__ADMIN_REQUIRED:SECURITY_OPERATIONS_MAILBOX__*'
        }
    }

    Context 'Negative: the context must refuse an input the baseline does not declare' {

        It 'fails with UnknownParameterKey when the parameter file supplies an undeclared key' {
            # Arrange
            $parameterPath = New-MutatedJsonFile -SourcePath $script:GatewayProfile.ParameterPath -Directory $TestDrive -Mutate {
                param($document)
                $document['NOT_A_DECLARED_INPUT'] = 'unexpected'
            }

            # Act
            $act = { Get-BaselineContext -ConfigurationPath $script:GatewayProfile.ConfigurationPath -ParameterPath $parameterPath -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'UnknownParameterKey*'
        }

        It 'fails with DeploymentProfileMismatch when the document declares another profile than the one requested' {
            # Arrange
            $requestedProfile = 'MicrosoftNative'

            # Act
            $act = { Get-BaselineContext -ConfigurationPath $script:GatewayProfile.ConfigurationPath -ParameterPath $script:GatewayProfile.ParameterPath -SchemaPath $script:SchemaPath -DeploymentProfile $requestedProfile }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DeploymentProfileMismatch*'
        }

        It 'fails when the resolved desired state violates a cross-member rule the schema cannot express' {
            # Arrange
            $configurationPath = New-MutatedJsonFile -SourcePath $script:NativeProfile.ConfigurationPath -Directory $TestDrive -Mutate {
                param($document)
                $document['desiredState']['mailFlow']['enhancedFiltering']['enabled'] = $true
            }

            # Act
            $act = { Get-BaselineContext -ConfigurationPath $configurationPath -ParameterPath $script:NativeProfile.ParameterPath -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage '*Enhanced Filtering is enabled but no mail gateway is declared*'
        }
    }

    Context 'Negative: the context must not report a hash that fails to identify the resolved document' {

        It 'does not return the hash of the unresolved baseline document' {
            # Arrange
            $unresolvedHash = Get-UnresolvedBaselineHash -ConfigurationPath $script:GatewayProfile.ConfigurationPath

            # Act
            $context = Get-BaselineContext -ConfigurationPath $script:GatewayProfile.ConfigurationPath -ParameterPath $script:GatewayProfile.ParameterPath -SchemaPath $script:SchemaPath

            # Assert
            $context.Hash | Should -Not -Be $unresolvedHash -Because 'the identity must cover the resolved administrator inputs, not the placeholders'
        }

        It 'does not return one hash for two different administrator inputs' {
            # Arrange
            $alteredParameterPath = New-MutatedJsonFile -SourcePath $script:GatewayProfile.ParameterPath -Directory $TestDrive -Mutate {
                param($document)
                $document['SECURITY_OPERATIONS_MAILBOX'] = 'another.secops@contoso.example'
            }
            $baseline = Get-BaselineContext -ConfigurationPath $script:GatewayProfile.ConfigurationPath -ParameterPath $script:GatewayProfile.ParameterPath -SchemaPath $script:SchemaPath

            # Act
            $altered = Get-BaselineContext -ConfigurationPath $script:GatewayProfile.ConfigurationPath -ParameterPath $alteredParameterPath -SchemaPath $script:SchemaPath

            # Assert
            $altered.Hash | Should -Not -Be $baseline.Hash -Because 'a different administrator input is a different desired state'
        }

        It 'does not return one hash for two different deployment profiles' {
            # Arrange
            $native = Get-BaselineContext -ConfigurationPath $script:NativeProfile.ConfigurationPath -ParameterPath $script:NativeProfile.ParameterPath -SchemaPath $script:SchemaPath

            # Act
            $gateway = Get-BaselineContext -ConfigurationPath $script:GatewayProfile.ConfigurationPath -ParameterPath $script:GatewayProfile.ParameterPath -SchemaPath $script:SchemaPath

            # Assert
            $gateway.Hash | Should -Not -Be $native.Hash -Because 'two profiles are two different desired states'
        }
    }

    Context 'Positive: one shared context is deterministic for every shipped profile' {

        It 'builds two independent contexts per shipped profile that carry identical canonical text and one identical SHA-256 hash of that text' {
            # Arrange
            $expected = @($script:ShippedProfile | ForEach-Object { '{0}=deterministic' -f $_.Name }) -join ';'

            # Act
            $observed = @(
                foreach ($profile in $script:ShippedProfile) {
                    $first = Get-BaselineContext -ConfigurationPath $profile.ConfigurationPath -ParameterPath $profile.ParameterPath -SchemaPath $script:SchemaPath -DeploymentProfile $profile.Name
                    $second = Get-BaselineContext -ConfigurationPath $profile.ConfigurationPath -ParameterPath $profile.ParameterPath -SchemaPath $script:SchemaPath -DeploymentProfile $profile.Name

                    $deterministic =
                        $first.CanonicalJson -ceq $second.CanonicalJson -and
                        $first.Hash -ceq $second.Hash -and
                        $first.Algorithm -ceq 'SHA256' -and
                        $first.Hash -ceq (Get-CanonicalTextHash -CanonicalJson $first.CanonicalJson)

                    '{0}={1}' -f $profile.Name, $(if ($deterministic) { 'deterministic' } else { 'divergent' })
                }
            ) -join ';'

            # Assert
            $observed | Should -Be $expected
        }
    }
}
