#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:TenantId = '00000000-1111-2222-3333-444444444444'
    $script:ConfigurationHash = 'a3f1c9d2b4e6708192a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f809'
    $script:AsOf = [datetimeoffset]::new(2026, 9, 19, 12, 0, 0, [timespan]::Zero)

    function New-ConfigurationAnalyzerFixture {
        param([hashtable]$Override = @{})

        $document = [ordered]@{
            SchemaVersion     = '1.0.0'
            EvidenceId        = '11111111-2222-4333-8444-555555555555'
            TenantId          = $script:TenantId
            DeploymentProfile = 'MicrosoftNative'
            ConfigurationHash = $script:ConfigurationHash
            ControlId         = 'EXO-001'
            Collector         = [ordered]@{
                Identity = 'Microsoft Configuration Analyzer'
                Version  = '1.0.0'
            }
            GeneratedAtUtc    = $script:AsOf.AddMinutes(-5).UtcDateTime.ToString('o')
            PayloadHash       = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            Payload           = [ordered]@{
                SchemaVersion  = '1.0.0'
                GeneratedAtUtc = $script:AsOf.AddMinutes(-5).UtcDateTime.ToString('o')
                ControlResults = @([ordered]@{ ControlId = 'EXO-001'; Result = 'Pass' })
            }
            Signature         = [ordered]@{
                Model     = 'DetachedCms'
                MediaType = 'application/pkcs7-signature'
                Value     = 'synthetic-signature'
            }
        }

        foreach ($name in $Override.Keys) { $document[$name] = $Override[$name] }
        if (-not $Override.ContainsKey('PayloadHash')) {
            $document.PayloadHash = Get-BaselineExternalEvidencePayloadHash -Payload $document.Payload
        }
        return [pscustomobject]$document
    }

    function New-ConfigurationAnalyzerRegistry {
        return @([pscustomobject]@{
                ControlId = 'EXO-001'
                Collector = 'Get-AcceptedDomainEvidence'
                Evaluator = 'Test-AcceptedDomainControl'
            })
    }

    function New-AnalyzerSourceContract {
        return [pscustomobject]@{
            Identity = 'Microsoft Configuration Analyzer'
            Version  = '1.0.0'
        }
    }

    function New-SatisfiedResult {
        return [pscustomobject]@{ Satisfied = $true; Reason = @() }
    }

    function New-RefusedResult {
        param([Parameter(Mandatory)][string]$Reason)
        return [pscustomobject]@{ Satisfied = $false; Reason = @($Reason) }
    }

    function New-AdmittedImportResult {
        param([Parameter(Mandatory)][object]$Evidence)
        return [pscustomobject]@{
            Satisfied = $true
            Admitted  = @([pscustomobject]@{ EvidenceId = $Evidence.EvidenceId; ControlId = $Evidence.ControlId; Evidence = $Evidence })
            Refused   = @()
        }
    }

    function New-RefusedImportResult {
        param([Parameter(Mandatory)][object]$Evidence, [Parameter(Mandatory)][string]$Reason)
        return [pscustomobject]@{
            Satisfied = $false
            Admitted  = @()
            Refused   = @([pscustomobject]@{ EvidenceId = $Evidence.EvidenceId; ControlId = $Evidence.ControlId; Reason = @($Reason) })
        }
    }

    function Invoke-ConfigurationAnalyzerImport {
        param(
            [AllowNull()][AllowEmptyCollection()][object[]]$Evidence,
            [scriptblock]$DocumentValidator = { param($Document) New-SatisfiedResult },
            [scriptblock]$ExternalEvidenceImporter = { param($Argument) New-AdmittedImportResult -Evidence $Argument.Evidence[0] },
            [scriptblock]$SourceContractProvider = { New-AnalyzerSourceContract },
            [scriptblock]$CorrelationValidator = { param($AnalyzerEvidence, $AuthoritativeEvidence, $Registry, $SourceContract) New-SatisfiedResult },
            [scriptblock]$ExternalDocumentValidator,
            [scriptblock]$SignatureValidator,
            [scriptblock]$SignerValidator
        )

        $argument = @{
            Evidence                 = $Evidence
            TenantId                 = $script:TenantId
            DeploymentProfile        = 'MicrosoftNative'
            ConfigurationHash        = $script:ConfigurationHash
            Registry                 = (New-ConfigurationAnalyzerRegistry)
            AuthoritativeEvidence    = @([pscustomobject]@{ ControlId = 'EXO-001'; Status = 'Pass'; Evidence = [pscustomobject]@{ Collected = $true } })
            MaximumAge               = [timespan]::FromHours(24)
            AsOf                     = $script:AsOf
            DocumentValidator        = $DocumentValidator
            ExternalEvidenceImporter = $ExternalEvidenceImporter
            SourceContractProvider   = $SourceContractProvider
            CorrelationValidator     = $CorrelationValidator
        }
        if ($PSBoundParameters.ContainsKey('ExternalDocumentValidator')) { $argument.ExternalDocumentValidator = $ExternalDocumentValidator }
        if ($PSBoundParameters.ContainsKey('SignatureValidator')) { $argument.SignatureValidator = $SignatureValidator }
        if ($PSBoundParameters.ContainsKey('SignerValidator')) { $argument.SignerValidator = $SignerValidator }

        return Import-BaselineConfigurationAnalyzerEvidence @argument
    }

    function Get-AnalyzerRefusalReason {
        param([Parameter(Mandatory)][object]$Decision)
        return @($Decision.Refused | ForEach-Object { @($_.Reason) })
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EVD-009 Configuration Analyzer ingestion orchestration' {
    Context 'Negative: evidence presence and payload contract' {
        It 'refuses an absent Configuration Analyzer export for its named reason' {
            # Arrange
            $evidence = @()

            # Act
            $act = { Invoke-ConfigurationAnalyzerImport -Evidence $evidence }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ConfigurationAnalyzerEvidenceRequired*'
        }

        It 'refuses a malformed Analyzer payload with the payload seam reason' {
            # Arrange
            $evidence = New-ConfigurationAnalyzerFixture
            $validator = { param($Document) New-RefusedResult -Reason 'ConfigurationAnalyzerSchemaViolation: results is required.' }

            # Act
            $decision = Invoke-ConfigurationAnalyzerImport -Evidence $evidence -DocumentValidator $validator

            # Assert
            Get-AnalyzerRefusalReason -Decision $decision | Should -Contain 'ConfigurationAnalyzerSchemaViolation: results is required.'
        }
    }

    Context 'Negative: EVD-008 admission refusals are preserved exactly' {
        It 'refuses stale Analyzer evidence for its named reason' {
            # Arrange
            $evidence = New-ConfigurationAnalyzerFixture
            $reason = 'ExternalEvidenceStale: Analyzer evidence is outside the maximum age.'
            $importer = { param($Argument) [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ Reason = @($reason) }) } }.GetNewClosure()

            # Act
            $decision = Invoke-ConfigurationAnalyzerImport -Evidence $evidence -ExternalEvidenceImporter $importer

            # Assert
            Get-AnalyzerRefusalReason -Decision $decision | Should -Contain $reason
        }

        It 'refuses unsigned Analyzer evidence for its named reason' {
            # Arrange
            $evidence = New-ConfigurationAnalyzerFixture
            $reason = 'ExternalEvidenceUnsigned: detached CMS signature is required.'
            $importer = { param($Argument) [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ Reason = @($reason) }) } }.GetNewClosure()

            # Act
            $decision = Invoke-ConfigurationAnalyzerImport -Evidence $evidence -ExternalEvidenceImporter $importer

            # Assert
            Get-AnalyzerRefusalReason -Decision $decision | Should -Contain $reason
        }

        It 'refuses Analyzer evidence raised for another tenant' {
            # Arrange
            $evidence = New-ConfigurationAnalyzerFixture
            $reason = 'ExternalEvidenceTenantMismatch: Analyzer tenant does not match the run tenant.'
            $importer = { param($Argument) [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ Reason = @($reason) }) } }.GetNewClosure()

            # Act
            $decision = Invoke-ConfigurationAnalyzerImport -Evidence $evidence -ExternalEvidenceImporter $importer

            # Assert
            Get-AnalyzerRefusalReason -Decision $decision | Should -Contain $reason
        }

        It 'refuses Analyzer evidence raised for another deployment profile' {
            # Arrange
            $evidence = New-ConfigurationAnalyzerFixture
            $reason = 'ExternalEvidenceProfileMismatch: Analyzer profile does not match the run profile.'
            $importer = { param($Argument) [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ Reason = @($reason) }) } }.GetNewClosure()

            # Act
            $decision = Invoke-ConfigurationAnalyzerImport -Evidence $evidence -ExternalEvidenceImporter $importer

            # Assert
            Get-AnalyzerRefusalReason -Decision $decision | Should -Contain $reason
        }

        It 'refuses Analyzer evidence raised for another configuration hash' {
            # Arrange
            $evidence = New-ConfigurationAnalyzerFixture
            $reason = 'ExternalEvidenceConfigurationHashMismatch: Analyzer hash does not match the run hash.'
            $importer = { param($Argument) [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ Reason = @($reason) }) } }.GetNewClosure()

            # Act
            $decision = Invoke-ConfigurationAnalyzerImport -Evidence $evidence -ExternalEvidenceImporter $importer

            # Assert
            Get-AnalyzerRefusalReason -Decision $decision | Should -Contain $reason
        }

        It 'refuses Analyzer evidence naming a control outside the registry' {
            # Arrange
            $evidence = New-ConfigurationAnalyzerFixture
            $reason = "ExternalEvidenceUnknownControl: 'EXO-999' is not present in the current control registry."
            $importer = { param($Argument) [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ Reason = @($reason) }) } }.GetNewClosure()

            # Act
            $decision = Invoke-ConfigurationAnalyzerImport -Evidence $evidence -ExternalEvidenceImporter $importer

            # Assert
            Get-AnalyzerRefusalReason -Decision $decision | Should -Contain $reason
        }
    }

    Context 'Negative: source and correlation contracts' {
        It 'refuses an Analyzer source version that differs from the registered source contract' {
            # Arrange
            $collector = [ordered]@{ Identity = 'Microsoft Configuration Analyzer'; Version = '0.9.0' }
            $evidence = New-ConfigurationAnalyzerFixture -Override @{ Collector = $collector }

            # Act
            $decision = Invoke-ConfigurationAnalyzerImport -Evidence $evidence

            # Assert
            Get-AnalyzerRefusalReason -Decision $decision | Should -Contain "ConfigurationAnalyzerSourceVersionMismatch: evidence version '0.9.0' does not match registered version '1.0.0'."
        }

        It 'preserves a refused correlation with its exact reason' {
            # Arrange
            $evidence = New-ConfigurationAnalyzerFixture
            $reason = "ConfigurationAnalyzerContradiction: control 'EXO-001' contradicts authoritative evidence."
            $correlator = { param($AnalyzerEvidence, $AuthoritativeEvidence, $Registry, $SourceContract) [pscustomobject]@{ Satisfied = $false; Reason = @($reason) } }.GetNewClosure()

            # Act
            $decision = Invoke-ConfigurationAnalyzerImport -Evidence $evidence -CorrelationValidator $correlator

            # Assert
            Get-AnalyzerRefusalReason -Decision $decision | Should -Contain $reason
        }
    }

    Context 'Positive: one signed sanitized export is admitted and correlated' {
        It 'admits the export through EVD-008 and correlates it without replacing authoritative evidence' {
            # Arrange
            $evidence = New-ConfigurationAnalyzerFixture
            $state = [ordered]@{ CorrelationCalls = 0; AuthoritativeCollector = '' }
            $correlator = {
                param($AnalyzerEvidence, $AuthoritativeEvidence, $Registry, $SourceContract)
                $state.CorrelationCalls++
                $state.AuthoritativeCollector = [string]$Registry[0].Collector
                return [pscustomobject]@{ Satisfied = $true; Reason = @(); CorrelatedControl = @('EXO-001') }
            }.GetNewClosure()
            $externalDocumentValidator = { param($Document) [pscustomobject]@{ Satisfied = $true; Reason = @() } }
            $signatureValidator = { param($Document, $CanonicalBytes) [pscustomobject]@{ Verified = $true; Reason = @() } }
            $signerValidator = { param($Document, $SignatureResult) [pscustomobject]@{ Authorized = $true; Reason = @() } }

            # Act
            $decision = Invoke-ConfigurationAnalyzerImport `
                -Evidence $evidence `
                -ExternalEvidenceImporter $null `
                -CorrelationValidator $correlator `
                -ExternalDocumentValidator $externalDocumentValidator `
                -SignatureValidator $signatureValidator `
                -SignerValidator $signerValidator

            # Assert
            $decision.Satisfied | Should -BeTrue -Because ($decision | ConvertTo-Json -Depth 10 -Compress)
            @($decision.Admitted).Count | Should -Be 1
            @($decision.Refused).Count | Should -Be 0
            $state.CorrelationCalls | Should -Be 1
            $state.AuthoritativeCollector | Should -BeExactly 'Get-AcceptedDomainEvidence'
            @($decision.Correlation.CorrelatedControl) | Should -Be @('EXO-001')
        }
    }
}