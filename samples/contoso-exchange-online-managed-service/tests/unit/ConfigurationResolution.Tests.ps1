#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:FixtureRoot = Join-Path $script:SampleRoot 'tests' 'fixtures' 'com002'
    $script:TemplatePath = Join-Path $script:FixtureRoot 'baseline.gateway.template.json'
    $script:ParameterPath = Join-Path $script:FixtureRoot 'parameters.complete.json'
    $script:ResolvedPath = Join-Path $script:FixtureRoot 'baseline.gateway.resolved.json'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-JsonFile {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Directory,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$Text
        )

        $path = Join-Path $Directory ('Fixture-{0}.json' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $path -Value $Text -Encoding utf8
        return $path
    }

    function ConvertTo-ComparableJson {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$InputObject
        )

        return ($InputObject | ConvertTo-Json -Depth 32 -Compress)
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'COM-002-A profile and placeholder resolution' {

    Context 'Negative: resolution must refuse unsafe or unusable input' {

        It 'fails with ConfigurationFileNotFound when the configuration file is absent' {
            # Arrange
            $absentConfiguration = Join-Path $TestDrive 'absent-baseline.json'

            # Act
            $act = { Resolve-BaselineConfiguration -ConfigurationPath $absentConfiguration -ParameterPath $script:ParameterPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ConfigurationFileNotFound*'
        }

        It 'fails with ParameterFileNotFound when the parameter file is absent' {
            # Arrange
            $absentParameters = Join-Path $TestDrive 'absent-parameters.json'

            # Act
            $act = { Resolve-BaselineConfiguration -ConfigurationPath $script:TemplatePath -ParameterPath $absentParameters }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ParameterFileNotFound*'
        }

        It 'fails with ConfigurationJsonInvalid when the configuration is malformed JSON' {
            # Arrange
            $malformedConfiguration = New-JsonFile -Directory $TestDrive -Text '{ "metadata": '

            # Act
            $act = { Resolve-BaselineConfiguration -ConfigurationPath $malformedConfiguration -ParameterPath $script:ParameterPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ConfigurationJsonInvalid*'
        }

        It 'fails with ParameterJsonInvalid when the parameter file is malformed JSON' {
            # Arrange
            $malformedParameters = New-JsonFile -Directory $TestDrive -Text '{ "PRIMARY_SMTP_DOMAIN": '

            # Act
            $act = { Resolve-BaselineConfiguration -ConfigurationPath $script:TemplatePath -ParameterPath $malformedParameters }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ParameterJsonInvalid*'
        }

        It 'fails with ParameterDocumentNotObject when the parameter document is not an object' {
            # Arrange
            $arrayParameters = New-JsonFile -Directory $TestDrive -Text '[ "PRIMARY_SMTP_DOMAIN", "contoso.example" ]'

            # Act
            $act = { Resolve-BaselineConfiguration -ConfigurationPath $script:TemplatePath -ParameterPath $arrayParameters }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ParameterDocumentNotObject*'
        }

        It 'fails with UnsupportedParameterValueType when a value is a number' {
            # Arrange
            $numericParameters = New-JsonFile -Directory $TestDrive -Text '{ "PRIMARY_SMTP_DOMAIN": 42 }'

            # Act
            $act = { Resolve-BaselineConfiguration -ConfigurationPath $script:TemplatePath -ParameterPath $numericParameters }

            # Assert
            $act | Should -Throw -ExpectedMessage 'UnsupportedParameterValueType*'
        }

        It 'fails with UnsupportedParameterValueType when a value is an object' {
            # Arrange
            $objectParameters = New-JsonFile -Directory $TestDrive -Text '{ "PRIMARY_SMTP_DOMAIN": { "value": "contoso.example" } }'

            # Act
            $act = { Resolve-BaselineConfiguration -ConfigurationPath $script:TemplatePath -ParameterPath $objectParameters }

            # Assert
            $act | Should -Throw -ExpectedMessage 'UnsupportedParameterValueType*'
        }

        It 'fails with UnsupportedParameterValueType when an array contains a non-string element' {
            # Arrange
            $mixedArrayParameters = New-JsonFile -Directory $TestDrive -Text '{ "CURRENT_PROOFPOINT_PUBLIC_IP_OR_CIDR": [ "198.51.100.0/24", 25 ] }'

            # Act
            $act = { Resolve-BaselineConfiguration -ConfigurationPath $script:TemplatePath -ParameterPath $mixedArrayParameters }

            # Assert
            $act | Should -Throw -ExpectedMessage 'UnsupportedParameterValueType*'
        }

        It 'fails with RecursivePlaceholderValue when a supplied value contains a placeholder' {
            # Arrange
            $recursiveParameters = New-JsonFile -Directory $TestDrive -Text '{ "PRIMARY_SMTP_DOMAIN": "__ADMIN_REQUIRED:LEGAL_ORGANIZATION_NAME__" }'

            # Act
            $act = { Resolve-BaselineConfiguration -ConfigurationPath $script:TemplatePath -ParameterPath $recursiveParameters }

            # Assert
            $act | Should -Throw -ExpectedMessage 'RecursivePlaceholderValue*'
        }

        It 'fails with ArrayValueForScalarPlaceholder when an array is supplied for a scalar placeholder' {
            # Arrange
            $arrayForScalar = New-JsonFile -Directory $TestDrive -Text '{ "PRIMARY_SMTP_DOMAIN": [ "contoso.example" ] }'

            # Act
            $act = { Resolve-BaselineConfiguration -ConfigurationPath $script:TemplatePath -ParameterPath $arrayForScalar }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ArrayValueForScalarPlaceholder*'
        }

        It 'fails with EmptyArrayValueForArrayPlaceholder when an empty array is supplied for an array placeholder' {
            # Arrange
            $emptyArrayParameters = New-JsonFile -Directory $TestDrive -Text '{ "CURRENT_PROOFPOINT_PUBLIC_IP_OR_CIDR": [] }'

            # Act
            $act = { Resolve-BaselineConfiguration -ConfigurationPath $script:TemplatePath -ParameterPath $emptyArrayParameters }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EmptyArrayValueForArrayPlaceholder*'
        }

        It 'fails with MixedArrayPlaceholder when a placeholder shares an array with literal entries' {
            # Arrange
            $mixedTemplate = New-JsonFile -Directory $TestDrive -Text '{ "metadata": { "deploymentProfile": "ThirdPartyGateway" }, "smartHosts": [ "literal.pphosted.example", "__ADMIN_REQUIRED:PROOFPOINT_OUTBOUND_SMART_HOST_FQDN__" ] }'

            # Act
            $act = { Resolve-BaselineConfiguration -ConfigurationPath $mixedTemplate -ParameterPath $script:ParameterPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MixedArrayPlaceholder*'
        }

        It 'fails with DeploymentProfileMismatch when the document declares another profile' {
            # Arrange
            $requestedProfile = 'MicrosoftNative'

            # Act
            $act = { Resolve-BaselineConfiguration -ConfigurationPath $script:TemplatePath -ParameterPath $script:ParameterPath -DeploymentProfile $requestedProfile }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DeploymentProfileMismatch*'
        }

        It 'fails with DeploymentProfileNotDeclared when the document declares no profile' {
            # Arrange
            $profilelessTemplate = New-JsonFile -Directory $TestDrive -Text '{ "metadata": { "name": "no profile" } }'

            # Act
            $act = { Resolve-BaselineConfiguration -ConfigurationPath $profilelessTemplate -ParameterPath $script:ParameterPath -DeploymentProfile 'ThirdPartyGateway' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DeploymentProfileNotDeclared*'
        }
    }

    Context 'Positive: the selected profile resolves to the expected document' {

        It 'replaces every scalar and array placeholder with the supplied value exactly' {
            # Arrange
            $expected = ConvertTo-ComparableJson -InputObject (Get-Content -LiteralPath $script:ResolvedPath -Raw | ConvertFrom-Json)

            # Act
            $resolution = Resolve-BaselineConfiguration -ConfigurationPath $script:TemplatePath -ParameterPath $script:ParameterPath -DeploymentProfile 'ThirdPartyGateway'

            # Assert
            (ConvertTo-ComparableJson -InputObject $resolution.Configuration) | Should -BeExactly $expected
        }
    }
}
