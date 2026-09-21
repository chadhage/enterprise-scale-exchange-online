#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'configuration-analyzer-evidence.schema.json'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop
    $script:CommonModule = Get-Module -Name 'ExchangeOnlineBaseline.Common'

    function New-ConfigurationAnalyzerDocument {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{},
            [string[]]$Omit = @()
        )

        $document = [ordered]@{
            SchemaVersion  = '1.0.0'
            GeneratedAtUtc = '2026-09-19T12:34:56Z'
            ControlResults = @(
                [ordered]@{ ControlId = 'EXO-004'; Result = 'Pass' }
                [ordered]@{ ControlId = 'MDO-001'; Result = 'Fail' }
                [ordered]@{ ControlId = 'PP-005'; Result = 'NotApplicable' }
            )
        }

        foreach ($name in $Omit) { $document.Remove($name) }
        foreach ($name in $Override.Keys) { $document[$name] = $Override[$name] }

        return [pscustomobject]$document
    }

    function Invoke-ConfigurationAnalyzerSchemaCheck {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [object]$Document
        )

        return & $script:CommonModule {
            param($Candidate, $ContractPath)
            Test-BaselineConfigurationAnalyzerDocument -Document $Candidate -SchemaPath $ContractPath
        } $Document $script:SchemaPath
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EVD-009 sanitized Configuration Analyzer payload contract' {
    Context 'missing partial and malformed documents are refused' {
        It 'refuses a missing document' {
            # Arrange
            $document = $null

            # Act
            $act = { Invoke-ConfigurationAnalyzerSchemaCheck -Document $document }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ConfigurationAnalyzerDocumentNotProvided*'
        }

        It 'refuses a document that is not an object' {
            # Arrange
            $document = 'all controls passed'

            # Act
            $act = { Invoke-ConfigurationAnalyzerSchemaCheck -Document $document }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ConfigurationAnalyzerDocumentNotAnObject*'
        }

        It 'schema-refuses a partial document omitting <_>' -ForEach @(
            'SchemaVersion'
            'GeneratedAtUtc'
            'ControlResults'
        ) {
            # Arrange
            $document = New-ConfigurationAnalyzerDocument -Omit @($_)

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse -Because "a Configuration Analyzer payload without $_ is partial evidence"
            $result.Violation | Should -Not -BeNullOrEmpty
        }

        It 'schema-refuses a malformed control-result collection' {
            # Arrange
            $document = New-ConfigurationAnalyzerDocument -Override @{ ControlResults = 'EXO-004 passed' }

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse
        }

        It 'schema-refuses an empty control-result collection' {
            # Arrange
            $document = New-ConfigurationAnalyzerDocument -Override @{ ControlResults = @() }

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse
        }
    }

    Context 'undeclared and unsanitized members are refused' {
        It 'schema-refuses an unknown top-level member' {
            # Arrange
            $document = New-ConfigurationAnalyzerDocument -Override @{ TrustAnalyzer = $true }

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse
        }

        It 'schema-refuses an unknown control-result member' {
            # Arrange
            $document = New-ConfigurationAnalyzerDocument -Override @{
                ControlResults = @([ordered]@{ ControlId = 'EXO-004'; Result = 'Pass'; Confidence = 100 })
            }

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse
        }

        It 'schema-refuses a planted tenant identifier' {
            # Arrange
            $document = New-ConfigurationAnalyzerDocument -Override @{
                TenantId = '00000000-1111-2222-3333-444444444444'
            }

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse -Because 'tenant binding belongs to the signed outer evidence envelope, not the sanitized Analyzer payload'
        }

        It 'schema-refuses a planted user identifier' {
            # Arrange
            $document = New-ConfigurationAnalyzerDocument -Override @{
                ControlResults = @([ordered]@{ ControlId = 'EXO-004'; Result = 'Pass'; UserPrincipalName = 'admin@contoso.example' })
            }

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse
        }

        It 'schema-refuses a planted access token' {
            # Arrange
            $document = New-ConfigurationAnalyzerDocument -Override @{
                AccessToken = 'eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJleGFtcGxlIn0.signature'
            }

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse
        }
    }

    Context 'version and control-result vocabularies are exact' {
        It 'schema-refuses an unsupported payload version' {
            # Arrange
            $document = New-ConfigurationAnalyzerDocument -Override @{ SchemaVersion = '2.0.0' }

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse
        }

        It 'schema-refuses a malformed generation time' {
            # Arrange
            $document = New-ConfigurationAnalyzerDocument -Override @{ GeneratedAtUtc = 'today' }

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse
        }

        It 'schema-refuses a control result missing <_>' -ForEach @('ControlId', 'Result') {
            # Arrange
            $controlResult = [ordered]@{ ControlId = 'EXO-004'; Result = 'Pass' }
            $controlResult.Remove($_)
            $document = New-ConfigurationAnalyzerDocument -Override @{ ControlResults = @($controlResult) }

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse -Because "an Analyzer result without $_ cannot be correlated"
        }

        It 'schema-refuses a malformed control identifier' {
            # Arrange
            $document = New-ConfigurationAnalyzerDocument -Override @{
                ControlResults = @([ordered]@{ ControlId = 'exo-four'; Result = 'Pass' })
            }

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse
        }

        It 'schema-refuses an unsupported control result' {
            # Arrange
            $document = New-ConfigurationAnalyzerDocument -Override @{
                ControlResults = @([ordered]@{ ControlId = 'EXO-004'; Result = 'Warning' })
            }

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse
        }

        It 'refuses duplicate results for one control' {
            # Arrange
            $document = New-ConfigurationAnalyzerDocument -Override @{
                ControlResults = @(
                    [ordered]@{ ControlId = 'EXO-004'; Result = 'Pass' }
                    [ordered]@{ ControlId = 'EXO-004'; Result = 'Fail' }
                )
            }

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse -Because 'one control cannot carry contradictory Analyzer results'
            $result.Violation | Should -BeLike '*ConfigurationAnalyzerControlResultNotUnique*'
        }
    }

    Context 'one complete sanitized Configuration Analyzer payload' {
        It 'admits the complete payload' {
            # Arrange
            $document = New-ConfigurationAnalyzerDocument

            # Act
            $result = Invoke-ConfigurationAnalyzerSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeTrue -Because "the complete sanitized payload should conform, but the contract reported '$($result.Violation -join '; ')'"
        }
    }
}