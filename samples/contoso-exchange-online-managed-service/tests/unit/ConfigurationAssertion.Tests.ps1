#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:BaselinePath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
    $script:ParameterPath = Join-Path $script:SampleRoot 'tests' 'fixtures' 'com003' 'parameters.gateway.complete.json'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # Validation must be offline. These global stubs stand in for the Exchange Online and Microsoft
    # Graph commands the module would otherwise resolve, and record any invocation.
    $global:BaselineTenantCommandInvocation = [System.Collections.Generic.List[string]]::new()
    $script:TenantCommandName = @(
        'Connect-ExchangeOnline'
        'Get-OrganizationConfig'
        'Get-AcceptedDomain'
        'Get-TransportConfig'
        'Get-RemoteDomain'
        'Connect-MgGraph'
        'Get-MgSubscribedSku'
        'Get-MgUser'
    )

    foreach ($name in $script:TenantCommandName) {
        Set-Item -Path "function:global:$name" -Value ([scriptblock]::Create("`$global:BaselineTenantCommandInvocation.Add('$name')"))
    }

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

    function New-RawJsonFile {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Directory,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$Text
        )

        $path = Join-Path $Directory ('Raw-{0}.json' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $path -Value $Text -Encoding utf8
        return $path
    }
}

AfterAll {
    foreach ($name in $script:TenantCommandName) {
        Remove-Item -Path "function:global:$name" -Force -ErrorAction SilentlyContinue
    }

    Remove-Variable -Name 'BaselineTenantCommandInvocation' -Scope Global -Force -ErrorAction SilentlyContinue
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'COM-003-A rejection of invalid resolved configuration' {

    Context 'Negative: assertion must refuse an unrecognized resolution' {

        It 'fails with ResolutionNotRecognized when the resolution carries no configuration' {
            # Arrange
            $resolution = [pscustomobject]@{
                DeploymentProfile       = 'ThirdPartyGateway'
                SuppliedParameterName   = @()
                DeclaredPlaceholderName = @()
            }

            # Act
            $act = { Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ResolutionNotRecognized*'
        }

        It 'fails with ResolutionNotRecognized when the resolution carries no placeholder inventory' {
            # Arrange
            $resolution = [pscustomobject]@{
                Configuration         = [pscustomobject]@{ metadata = [pscustomobject]@{ name = 'incomplete' } }
                DeploymentProfile     = 'ThirdPartyGateway'
                SuppliedParameterName = @()
            }

            # Act
            $act = { Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ResolutionNotRecognized*'
        }
    }

    Context 'Negative: assertion must refuse an unusable schema' {

        It 'fails with SchemaFileNotFound when the selected schema does not exist' {
            # Arrange
            $absentSchema = Join-Path $TestDrive 'absent-schema.json'
            $resolution = Resolve-BaselineConfiguration -ConfigurationPath $script:BaselinePath -ParameterPath $script:ParameterPath -DeploymentProfile 'ThirdPartyGateway'

            # Act
            $act = { Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $absentSchema }

            # Assert
            $act | Should -Throw -ExpectedMessage 'SchemaFileNotFound*'
        }

        It 'fails with SchemaJsonInvalid when the selected schema is malformed JSON' {
            # Arrange
            $malformedSchema = New-RawJsonFile -Directory $TestDrive -Text '{ "type": '
            $resolution = Resolve-BaselineConfiguration -ConfigurationPath $script:BaselinePath -ParameterPath $script:ParameterPath -DeploymentProfile 'ThirdPartyGateway'

            # Act
            $act = { Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $malformedSchema }

            # Assert
            $act | Should -Throw -ExpectedMessage 'SchemaJsonInvalid*'
        }

        It 'fails with SchemaNotValid when the selected schema is JSON but not a usable schema' {
            # Arrange
            $unusableSchema = New-RawJsonFile -Directory $TestDrive -Text '{ "type": "definitely-not-a-json-type" }'
            $resolution = Resolve-BaselineConfiguration -ConfigurationPath $script:BaselinePath -ParameterPath $script:ParameterPath -DeploymentProfile 'ThirdPartyGateway'

            # Act
            $act = { Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $unusableSchema }

            # Assert
            $act | Should -Throw -ExpectedMessage 'SchemaNotValid*'
        }
    }

    Context 'Negative: assertion must refuse unknown parameter keys and unresolved tokens' {

        It 'fails with UnknownParameterKey when a supplied key matches no declared placeholder' {
            # Arrange
            $extraParameters = New-MutatedJsonFile -SourcePath $script:ParameterPath -Directory $TestDrive -Mutate {
                param($Document)
                $Document['UNDECLARED_PARAMETER_KEY'] = 'unused.example'
            }
            $resolution = Resolve-BaselineConfiguration -ConfigurationPath $script:BaselinePath -ParameterPath $extraParameters -DeploymentProfile 'ThirdPartyGateway'

            # Act
            $act = { Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'UnknownParameterKey*'
        }

        It 'fails with UnresolvedPlaceholder when a scalar placeholder has no supplied value' {
            # Arrange
            $incompleteParameters = New-MutatedJsonFile -SourcePath $script:ParameterPath -Directory $TestDrive -Mutate {
                param($Document)
                $Document.Remove('PRIMARY_SMTP_DOMAIN')
            }
            $resolution = Resolve-BaselineConfiguration -ConfigurationPath $script:BaselinePath -ParameterPath $incompleteParameters -DeploymentProfile 'ThirdPartyGateway'

            # Act
            $act = { Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'UnresolvedPlaceholder*'
        }

        It 'fails with UnresolvedPlaceholder when an array placeholder has no supplied value' {
            # Arrange
            $incompleteParameters = New-MutatedJsonFile -SourcePath $script:ParameterPath -Directory $TestDrive -Mutate {
                param($Document)
                $Document.Remove('PROOFPOINT_OUTBOUND_SMART_HOST_FQDN')
            }
            $resolution = Resolve-BaselineConfiguration -ConfigurationPath $script:BaselinePath -ParameterPath $incompleteParameters -DeploymentProfile 'ThirdPartyGateway'

            # Act
            $act = { Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'UnresolvedPlaceholder*'
        }
    }

    Context 'Negative: assertion must refuse a document the selected schema rejects' {

        It 'fails with SchemaValidationFailed when a required section is absent' {
            # Arrange
            $withoutDeployment = New-MutatedJsonFile -SourcePath $script:BaselinePath -Directory $TestDrive -Mutate {
                param($Document)
                $Document.Remove('deployment')
            }
            $resolution = Resolve-BaselineConfiguration -ConfigurationPath $withoutDeployment -ParameterPath $script:ParameterPath -DeploymentProfile 'ThirdPartyGateway'

            # Act
            $act = { Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'SchemaValidationFailed*'
        }

        It 'fails with SchemaValidationFailed when a constant control value is weakened' {
            # Arrange
            $weakenedSmtpAuth = New-MutatedJsonFile -SourcePath $script:BaselinePath -Directory $TestDrive -Mutate {
                param($Document)
                $Document['desiredState']['exchangeOnline']['smtpClientAuthenticationDisabled'] = $false
            }
            $resolution = Resolve-BaselineConfiguration -ConfigurationPath $weakenedSmtpAuth -ParameterPath $script:ParameterPath -DeploymentProfile 'ThirdPartyGateway'

            # Act
            $act = { Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'SchemaValidationFailed*'
        }

        It 'fails with SchemaValidationFailed when an unknown top-level section is present' {
            # Arrange
            $withUnknownSection = New-MutatedJsonFile -SourcePath $script:BaselinePath -Directory $TestDrive -Mutate {
                param($Document)
                $Document['unknownSection'] = @{ smuggled = $true }
            }
            $resolution = Resolve-BaselineConfiguration -ConfigurationPath $withUnknownSection -ParameterPath $script:ParameterPath -DeploymentProfile 'ThirdPartyGateway'

            # Act
            $act = { Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'SchemaValidationFailed*'
        }

        It 'fails with SchemaValidationFailed when audit retention falls below the mandated boundary' {
            # Arrange
            $shortRetention = New-MutatedJsonFile -SourcePath $script:BaselinePath -Directory $TestDrive -Mutate {
                param($Document)
                $Document['desiredState']['purviewGovernance']['auditRetentionDays'] = 179
            }
            $resolution = Resolve-BaselineConfiguration -ConfigurationPath $shortRetention -ParameterPath $script:ParameterPath -DeploymentProfile 'ThirdPartyGateway'

            # Act
            $act = { Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage 'SchemaValidationFailed*'
        }
    }

    Context 'Positive: a complete resolution validates offline against the selected schema' {

        It 'validates a shipped baseline without invoking any Exchange Online or Microsoft Graph command' {
            # Arrange
            $global:BaselineTenantCommandInvocation.Clear()
            $resolution = Resolve-BaselineConfiguration -ConfigurationPath $script:BaselinePath -ParameterPath $script:ParameterPath -DeploymentProfile 'ThirdPartyGateway'

            # Act
            $assertion = Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $script:SchemaPath

            # Assert
            ('Valid={0};TenantCommands={1}' -f $assertion.Valid, $global:BaselineTenantCommandInvocation.Count) | Should -BeExactly 'Valid=True;TenantCommands=0'
        }
    }
}
