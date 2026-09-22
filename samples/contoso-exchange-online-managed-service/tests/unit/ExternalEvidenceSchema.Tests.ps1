#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'external-evidence.schema.json'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop
    $script:CommonModule = Get-Module -Name 'ExchangeOnlineBaseline.Common'

    function New-ExternalEvidenceDocument {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{},
            [string[]]$Omit = @()
        )

        $document = [ordered]@{
            SchemaVersion     = '1.0.0'
            EvidenceId        = '11111111-2222-4333-8444-555555555555'
            TenantId          = '00000000-1111-2222-3333-444444444444'
            DeploymentProfile = 'MicrosoftNative'
            ConfigurationHash = 'a3f1c9d2b4e6708192a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f809'
            ControlId         = 'EXO-004'
            Collector         = [ordered]@{
                Identity = 'Contoso.Exchange.ForwardingAudit'
                Version  = '2.1.0'
            }
            GeneratedAtUtc    = '2026-09-19T12:34:56Z'
            PayloadHash       = 'b4f2d0e3c5a7819203b4c5d6e7f8091a23b4c5d6e7f8091a23b4c5d6e7f8091a'
            Payload           = [ordered]@{
                MailboxesInspected = 42
                ForwardingFindings = @()
            }
            Signature         = [ordered]@{
                Model     = 'DetachedCms'
                MediaType = 'application/pkcs7-signature'
                Value     = 'MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExDzANBglghkgBZQMEAgEFADA='
            }
        }

        foreach ($name in $Omit) { $document.Remove($name) }
        foreach ($name in $Override.Keys) { $document[$name] = $Override[$name] }

        return [pscustomobject]$document
    }

    function Invoke-ExternalEvidenceSchemaCheck {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [object]$Document,

            [AllowNull()]
            [AllowEmptyString()]
            [string]$SchemaPath = $script:SchemaPath
        )

        return & $script:CommonModule {
            param($Candidate, $ContractPath)
            Test-ExternalEvidenceDocument -Document $Candidate -SchemaPath $ContractPath
        } $Document $SchemaPath
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EVD-008 external-evidence document and schema contract' {
    BeforeAll {
        $script:FixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('external-evidence-schema-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:FixtureRoot -Force | Out-Null
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:FixtureRoot) {
            Remove-Item -LiteralPath $script:FixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'the schema seam fails closed' {
        It 'refuses a missing document' {
            # Arrange
            $document = $null

            # Act
            $act = { Invoke-ExternalEvidenceSchemaCheck -Document $document }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ExternalEvidenceDocumentNotProvided*'
        }

        It 'refuses a document that is not an object' {
            # Arrange
            $document = 'signed evidence is attached'

            # Act
            $act = { Invoke-ExternalEvidenceSchemaCheck -Document $document }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ExternalEvidenceDocumentNotAnObject*'
        }

        It 'refuses a missing schema path' {
            # Arrange
            $document = New-ExternalEvidenceDocument

            # Act
            $act = { Invoke-ExternalEvidenceSchemaCheck -Document $document -SchemaPath '' }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ExternalEvidenceSchemaPathRequired*'
        }

        It 'refuses a schema path that names no file' {
            # Arrange
            $missingSchema = Join-Path $script:FixtureRoot 'absent.schema.json'

            # Act
            $act = { Invoke-ExternalEvidenceSchemaCheck -Document (New-ExternalEvidenceDocument) -SchemaPath $missingSchema }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ExternalEvidenceSchemaNotFound*'
        }

        It 'refuses a schema file that is malformed JSON' {
            # Arrange
            $malformedSchema = Join-Path $script:FixtureRoot 'malformed.schema.json'
            Set-Content -LiteralPath $malformedSchema -Value '{ "type": "object", ' -Encoding utf8

            # Act
            $act = { Invoke-ExternalEvidenceSchemaCheck -Document (New-ExternalEvidenceDocument) -SchemaPath $malformedSchema }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ExternalEvidenceSchemaJsonInvalid*'
        }

        It 'refuses JSON that is not a usable schema' {
            # Arrange
            $unusableSchema = Join-Path $script:FixtureRoot 'unusable.schema.json'
            Set-Content -LiteralPath $unusableSchema -Value '{ "type": 42 }' -Encoding utf8

            # Act
            $act = { Invoke-ExternalEvidenceSchemaCheck -Document (New-ExternalEvidenceDocument) -SchemaPath $unusableSchema }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ExternalEvidenceSchemaNotUsable*'
        }
    }

    Context 'every top-level contract member is required' {
        It 'schema-refuses a document omitting <_>' -ForEach @(
            'SchemaVersion'
            'EvidenceId'
            'TenantId'
            'DeploymentProfile'
            'ConfigurationHash'
            'ControlId'
            'Collector'
            'GeneratedAtUtc'
            'PayloadHash'
            'Payload'
            'Signature'
        ) {
            # Arrange
            $document = New-ExternalEvidenceDocument -Omit @($_)

            # Act
            $result = Invoke-ExternalEvidenceSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse -Because "external evidence without $_ is partial evidence"
            $result.Violation | Should -Not -BeNullOrEmpty
        }

        It 'schema-refuses a collector missing <_>' -ForEach @('Identity', 'Version') {
            # Arrange
            $collector = [ordered]@{ Identity = 'Contoso.Exchange.ForwardingAudit'; Version = '2.1.0' }
            $collector.Remove($_)
            $document = New-ExternalEvidenceDocument -Override @{ Collector = $collector }

            # Act
            $result = Invoke-ExternalEvidenceSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse -Because "collector metadata without $_ cannot identify the producing implementation"
        }

        It 'schema-refuses detached-signature metadata missing <_>' -ForEach @('Model', 'MediaType', 'Value') {
            # Arrange
            $signature = [ordered]@{
                Model     = 'DetachedCms'
                MediaType = 'application/pkcs7-signature'
                Value     = 'MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExDzANBglghkgBZQMEAgEFADA='
            }
            $signature.Remove($_)
            $document = New-ExternalEvidenceDocument -Override @{ Signature = $signature }

            # Act
            $result = Invoke-ExternalEvidenceSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse -Because "signature metadata without $_ cannot describe the detached signature to verify"
        }
    }

    Context 'identifiers hashes times and vocabularies have exact shapes' {
        It 'schema-refuses <Name>' -ForEach @(
            @{ Name = 'an unsupported schema version'; Override = @{ SchemaVersion = '2.0.0' } }
            @{ Name = 'a malformed evidence ID'; Override = @{ EvidenceId = 'evidence-september' } }
            @{ Name = 'a non-RFC-4122 evidence ID'; Override = @{ EvidenceId = '11111111-2222-6333-8444-555555555555' } }
            @{ Name = 'a malformed tenant ID'; Override = @{ TenantId = 'contoso.example' } }
            @{ Name = 'an unknown deployment profile'; Override = @{ DeploymentProfile = 'EveryTenant' } }
            @{ Name = 'a malformed configuration hash'; Override = @{ ConfigurationHash = 'the september baseline' } }
            @{ Name = 'an uppercase configuration hash'; Override = @{ ConfigurationHash = ('A' * 64) } }
            @{ Name = 'a malformed control ID'; Override = @{ ControlId = 'the forwarding control' } }
            @{ Name = 'a lowercase control ID'; Override = @{ ControlId = 'exo-004' } }
            @{ Name = 'a malformed generation time'; Override = @{ GeneratedAtUtc = 'last Friday' } }
            @{ Name = 'a generation time with a non-UTC offset'; Override = @{ GeneratedAtUtc = '2026-09-19T14:34:56+02:00' } }
            @{ Name = 'a malformed payload hash'; Override = @{ PayloadHash = 'sha256:payload' } }
            @{ Name = 'an uppercase payload hash'; Override = @{ PayloadHash = ('B' * 64) } }
        ) {
            # Arrange
            $document = New-ExternalEvidenceDocument -Override $Override

            # Act
            $result = Invoke-ExternalEvidenceSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse -Because "$Name cannot be bound or compared deterministically"
        }

        It 'schema-refuses <Name> collector metadata' -ForEach @(
            @{ Name = 'blank'; Collector = [ordered]@{ Identity = '   '; Version = '2.1.0' } }
            @{ Name = 'malformed-version'; Collector = [ordered]@{ Identity = 'Contoso.Exchange.ForwardingAudit'; Version = 'current' } }
        ) {
            # Arrange
            $document = New-ExternalEvidenceDocument -Override @{ Collector = $Collector }

            # Act
            $result = Invoke-ExternalEvidenceSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse -Because "$Name collector metadata cannot identify one versioned collector"
        }
    }

    Context 'payload and detached signature shapes are constrained' {
        It 'schema-refuses a scalar payload' {
            # Arrange
            $document = New-ExternalEvidenceDocument -Override @{ Payload = 'everything passed' }

            # Act
            $result = Invoke-ExternalEvidenceSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse -Because 'a payload must be structured evidence rather than an unsupported verdict string'
        }

        It 'schema-refuses an empty payload object' {
            # Arrange
            $document = New-ExternalEvidenceDocument -Override @{ Payload = [ordered]@{} }

            # Act
            $result = Invoke-ExternalEvidenceSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse -Because 'an empty object carries no external observation'
        }

        It 'schema-refuses <Name> signature metadata' -ForEach @(
            @{ Name = 'another signature model'; Signature = [ordered]@{ Model = 'EnterpriseCertificate'; MediaType = 'application/pkcs7-signature'; Value = 'MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExDzANBglghkgBZQMEAgEFADA=' } }
            @{ Name = 'another media type'; Signature = [ordered]@{ Model = 'DetachedCms'; MediaType = 'text/plain'; Value = 'MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExDzANBglghkgBZQMEAgEFADA=' } }
            @{ Name = 'a blank detached value'; Signature = [ordered]@{ Model = 'DetachedCms'; MediaType = 'application/pkcs7-signature'; Value = '   ' } }
        ) {
            # Arrange
            $document = New-ExternalEvidenceDocument -Override @{ Signature = $Signature }

            # Act
            $result = Invoke-ExternalEvidenceSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse -Because "$Name does not describe the selected detached CMS artifact"
        }
    }

    Context 'members the contract never declared are refused' {
        It 'schema-refuses an unknown top-level member' {
            # Arrange
            $document = New-ExternalEvidenceDocument -Override @{ TrustMe = $true }

            # Act
            $result = Invoke-ExternalEvidenceSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse
        }

        It 'schema-refuses an unknown collector member' {
            # Arrange
            $document = New-ExternalEvidenceDocument -Override @{
                Collector = [ordered]@{ Identity = 'Contoso.Exchange.ForwardingAudit'; Version = '2.1.0'; Trusted = $true }
            }

            # Act
            $result = Invoke-ExternalEvidenceSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse
        }

        It 'schema-refuses an unknown signature member' {
            # Arrange
            $document = New-ExternalEvidenceDocument -Override @{
                Signature = [ordered]@{
                    Model = 'DetachedCms'; MediaType = 'application/pkcs7-signature'; Value = 'MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExDzANBglghkgBZQMEAgEFADA='; Verified = $true
                }
            }

            # Act
            $result = Invoke-ExternalEvidenceSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeFalse
        }
    }

    Context 'the schema verdict is immutable' {
        It 'refuses assignment to the conformance result' {
            # Arrange
            $result = Invoke-ExternalEvidenceSchemaCheck -Document (New-ExternalEvidenceDocument)

            # Act
            $act = { $result.Conforms = $false }

            # Assert
            $act | Should -Throw
        }
    }

    Context 'one complete external-evidence document' {
        It 'admits the complete document' {
            # Arrange
            $document = New-ExternalEvidenceDocument

            # Act
            $result = Invoke-ExternalEvidenceSchemaCheck -Document $document

            # Assert
            $result.Conforms | Should -BeTrue -Because "a complete external-evidence document should conform, but the schema reported '$($result.Violation -join '; ')'"
        }
    }
}
