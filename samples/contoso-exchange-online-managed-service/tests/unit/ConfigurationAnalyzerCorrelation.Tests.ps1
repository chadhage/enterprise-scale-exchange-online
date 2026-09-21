#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:CatalogPath = Join-Path $script:SampleRoot 'docs' 'CONTROL-CATALOG.md'
    $script:CommonModule = Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -PassThru -ErrorAction Stop

    function New-AnalyzerSourceMetadata {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{},
            [string[]]$Omit = @()
        )

        $metadata = [ordered]@{
            Identity                      = 'MicrosoftConfigurationAnalyzer'
            Version                       = '1.0.0'
            EvidenceRole                  = 'Supplemental'
            AuthoritativeEvidenceRequired = $true
            ControlScope                  = 'ApplicableKnownControls'
        }
        foreach ($name in $Omit) { $metadata.Remove($name) }
        foreach ($name in $Override.Keys) { $metadata[$name] = $Override[$name] }
        return [pscustomobject]$metadata
    }

    function New-ControlDefinitionFixture {
        [CmdletBinding()]
        param(
            [object]$SourceMetadata = (New-AnalyzerSourceMetadata),
            [switch]$WithoutSourceMetadata
        )

        [object[]]$definition = @(
            [ordered]@{ ControlId = 'EXO-001'; ApplicableProfile = @('Native', 'Gateway') }
            [ordered]@{ ControlId = 'PP-001'; ApplicableProfile = @('Gateway') }
        )
        if (-not $WithoutSourceMetadata) {
            Add-Member -InputObject $definition -MemberType NoteProperty -Name 'ConfigurationAnalyzerSource' -Value $SourceMetadata
        }
        return , $definition
    }

    function Write-AnalyzerCatalogFixture {
        [CmdletBinding()]
        param(
            [string]$Identity = 'MicrosoftConfigurationAnalyzer',
            [string]$Version = '1.0.0',
            [string]$EvidenceRole = 'Supplemental',
            [string]$ControlScope = 'ApplicableKnownControls',
            [string]$AuthoritativeEvidence = 'Required',
            [switch]$OmitDeclaration
        )

        $path = Join-Path $TestDrive 'CONTROL-CATALOG.md'
        $content = @('# Control Catalog', '', '## Versioned Evidence Sources', '', '| Identity | Version | Evidence role | Control scope | Authoritative control evidence |', '| --- | --- | --- | --- | --- |')
        if (-not $OmitDeclaration) {
            $content += "| $Identity | $Version | $EvidenceRole | $ControlScope | $AuthoritativeEvidence |"
        }
        Set-Content -LiteralPath $path -Value $content -Encoding utf8NoBOM
        return $path
    }

    function Invoke-AnalyzerSourceContract {
        [CmdletBinding()]
        param(
            [string]$CatalogPath,
            [object[]]$ControlDefinition
        )

        return & $script:CommonModule {
            param($Path, $Definition)
            Get-BaselineConfigurationAnalyzerSourceContract -CatalogPath $Path -ControlDefinition $Definition
        } $CatalogPath $ControlDefinition
    }

    function New-RegistryEntry {
        [CmdletBinding()]
        param(
            [string]$ControlId = 'EXO-001',
            [string[]]$ApplicableProfile = @('Native', 'Gateway')
        )

        return [pscustomobject]@{
            ControlId         = $ControlId
            ApplicableProfile = $ApplicableProfile
        }
    }

    function New-AnalyzerResult {
        [CmdletBinding()]
        param(
            [string]$ControlId = 'EXO-001',
            [string]$Status = 'Pass',
            [switch]$CarryEvidence
        )

        $result = [ordered]@{ ControlId = $ControlId; Status = $Status }
        if ($CarryEvidence) { $result.Evidence = [pscustomobject]@{ Claimed = 'authoritative' } }
        return [pscustomobject]$result
    }

    function New-AuthoritativeResult {
        [CmdletBinding()]
        param(
            [string]$ControlId = 'EXO-001',
            [string]$Status = 'Pass',
            [switch]$WithoutEvidence
        )

        $result = [ordered]@{ ControlId = $ControlId; Status = $Status }
        if (-not $WithoutEvidence) {
            $result.Evidence = [pscustomobject]@{ Source = 'Get-AcceptedDomainEvidence'; Collected = $true }
        }
        return [pscustomobject]$result
    }

    function Invoke-AnalyzerCorrelation {
        [CmdletBinding()]
        param(
            [object[]]$AnalyzerResult,
            [object[]]$AuthoritativeResult,
            [object[]]$Registry,
            [string]$DeploymentProfile = 'Native'
        )

        return & $script:CommonModule {
            param($Analyzer, $Authoritative, $ControlRegistry, $Profile)
            Test-BaselineConfigurationAnalyzerCorrelation -AnalyzerResult $Analyzer -AuthoritativeResult $Authoritative -Registry $ControlRegistry -DeploymentProfile $Profile
        } $AnalyzerResult $AuthoritativeResult $Registry $DeploymentProfile
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EVD-009 Configuration Analyzer source contract' {
    Context 'Negative: source metadata and catalog declarations are mandatory' {
        It 'refuses a source contract with no catalog path' {
            # Arrange
            $definition = New-ControlDefinitionFixture

            # Act
            $act = { Invoke-AnalyzerSourceContract -CatalogPath '' -ControlDefinition $definition }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ConfigurationAnalyzerCatalogPathRequired*'
        }

        It 'refuses a source contract whose catalog does not exist' {
            # Arrange
            $definition = New-ControlDefinitionFixture
            $missingCatalog = Join-Path $TestDrive 'missing-catalog.md'

            # Act
            $act = { Invoke-AnalyzerSourceContract -CatalogPath $missingCatalog -ControlDefinition $definition }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ConfigurationAnalyzerCatalogNotFound*'
        }

        It 'refuses a control definition carrying no Configuration Analyzer source metadata' {
            # Arrange
            $catalog = Write-AnalyzerCatalogFixture
            $definition = New-ControlDefinitionFixture -WithoutSourceMetadata

            # Act
            $act = { Invoke-AnalyzerSourceContract -CatalogPath $catalog -ControlDefinition $definition }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ConfigurationAnalyzerSourceMetadataRequired*'
        }

        It 'refuses source metadata carrying no identity' {
            # Arrange
            $catalog = Write-AnalyzerCatalogFixture
            $definition = New-ControlDefinitionFixture -SourceMetadata (New-AnalyzerSourceMetadata -Omit @('Identity'))

            # Act
            $act = { Invoke-AnalyzerSourceContract -CatalogPath $catalog -ControlDefinition $definition }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ConfigurationAnalyzerSourceIdentityRequired*'
        }

        It 'refuses source metadata carrying no version' {
            # Arrange
            $catalog = Write-AnalyzerCatalogFixture
            $definition = New-ControlDefinitionFixture -SourceMetadata (New-AnalyzerSourceMetadata -Omit @('Version'))

            # Act
            $act = { Invoke-AnalyzerSourceContract -CatalogPath $catalog -ControlDefinition $definition }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ConfigurationAnalyzerSourceVersionRequired*'
        }

        It 'refuses a catalog carrying no Microsoft Configuration Analyzer declaration' {
            # Arrange
            $catalog = Write-AnalyzerCatalogFixture -OmitDeclaration
            $definition = New-ControlDefinitionFixture

            # Act
            $result = Invoke-AnalyzerSourceContract -CatalogPath $catalog -ControlDefinition $definition

            # Assert
            $result.Reason | Should -Contain 'ConfigurationAnalyzerCatalogSourceMissing'
        }
    }

    Context 'Negative: catalog and registry source identity and version cannot drift' {
        It 'refuses a catalog source identity that differs from the registry definition' {
            # Arrange
            $catalog = Write-AnalyzerCatalogFixture -Identity 'Microsoft Secure Score'
            $definition = New-ControlDefinitionFixture

            # Act
            $result = Invoke-AnalyzerSourceContract -CatalogPath $catalog -ControlDefinition $definition

            # Assert
            $result.Reason | Should -Contain "ConfigurationAnalyzerSourceIdentityMismatch: catalog 'Microsoft Secure Score' does not match registry 'MicrosoftConfigurationAnalyzer'."
        }

        It 'refuses a catalog source version that differs from the registry definition' {
            # Arrange
            $catalog = Write-AnalyzerCatalogFixture -Version '2.0.0'
            $definition = New-ControlDefinitionFixture

            # Act
            $result = Invoke-AnalyzerSourceContract -CatalogPath $catalog -ControlDefinition $definition

            # Assert
            $result.Reason | Should -Contain "ConfigurationAnalyzerSourceVersionMismatch: catalog '2.0.0' does not match registry '1.0.0'."
        }

        It 'refuses a catalog that treats Analyzer output as authoritative evidence' {
            # Arrange
            $catalog = Write-AnalyzerCatalogFixture -EvidenceRole 'Authoritative' -AuthoritativeEvidence 'Optional'
            $definition = New-ControlDefinitionFixture

            # Act
            $result = Invoke-AnalyzerSourceContract -CatalogPath $catalog -ControlDefinition $definition

            # Assert
            $result.Reason | Should -Contain 'ConfigurationAnalyzerEvidenceRoleMismatch: Microsoft Configuration Analyzer must remain Supplemental and require authoritative control evidence.'
        }

        It 'refuses registry metadata that permits Analyzer output to replace authoritative evidence' {
            # Arrange
            $catalog = Write-AnalyzerCatalogFixture
            $metadata = New-AnalyzerSourceMetadata -Override @{ AuthoritativeEvidenceRequired = $false }
            $definition = New-ControlDefinitionFixture -SourceMetadata $metadata

            # Act
            $result = Invoke-AnalyzerSourceContract -CatalogPath $catalog -ControlDefinition $definition

            # Assert
            $result.Reason | Should -Contain 'ConfigurationAnalyzerAuthoritativeEvidenceRequired: registry metadata must require separate authoritative control evidence.'
        }

        It 'refuses a source scope other than applicable known controls' {
            # Arrange
            $catalog = Write-AnalyzerCatalogFixture -ControlScope 'AnyReportedControl'
            $definition = New-ControlDefinitionFixture

            # Act
            $result = Invoke-AnalyzerSourceContract -CatalogPath $catalog -ControlDefinition $definition

            # Assert
            $result.Reason | Should -Contain "ConfigurationAnalyzerControlScopeMismatch: catalog 'AnyReportedControl' does not match registry 'ApplicableKnownControls'."
        }

        It 'returns a source contract that cannot be rewritten by a caller' {
            # Arrange
            $catalog = Write-AnalyzerCatalogFixture
            $definition = New-ControlDefinitionFixture

            # Act
            $result = Invoke-AnalyzerSourceContract -CatalogPath $catalog -ControlDefinition $definition

            # Assert
            { $result.Version = '9.9.9' } | Should -Throw
        }
    }

    Context 'Positive: the shipped catalog and registry publish one matching supplemental source' {
        It 'publishes Microsoft Configuration Analyzer at one matching version without authoritative standing' {
            # Arrange
            $definition = & $script:CommonModule { return , $script:BaselineControlDefinition }

            # Act
            $result = Invoke-AnalyzerSourceContract -CatalogPath $script:CatalogPath -ControlDefinition $definition

            # Assert
            ('Satisfied={0};Identity={1};Version={2};Role={3};AuthorityRequired={4};Scope={5}' -f $result.Satisfied, $result.Identity, $result.Version, $result.EvidenceRole, $result.AuthoritativeEvidenceRequired, $result.ControlScope) |
                Should -BeExactly 'Satisfied=True;Identity=MicrosoftConfigurationAnalyzer;Version=1.0.0;Role=Supplemental;AuthorityRequired=True;Scope=ApplicableKnownControls'
        }
    }
}

Describe 'EVD-009 Configuration Analyzer correlation' {
    Context 'Negative: correlation requires complete declared inputs' {
        It 'refuses an empty Analyzer result set' {
            # Arrange
            $authoritative = @(New-AuthoritativeResult)
            $registry = @(New-RegistryEntry)

            # Act
            $act = { Invoke-AnalyzerCorrelation -AnalyzerResult @() -AuthoritativeResult $authoritative -Registry $registry }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ConfigurationAnalyzerResultRequired*'
        }

        It 'refuses an empty authoritative result set' {
            # Arrange
            $analyzer = @(New-AnalyzerResult)
            $registry = @(New-RegistryEntry)

            # Act
            $act = { Invoke-AnalyzerCorrelation -AnalyzerResult $analyzer -AuthoritativeResult @() -Registry $registry }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ConfigurationAnalyzerAuthoritativeResultRequired*'
        }

        It 'refuses an empty control registry' {
            # Arrange
            $analyzer = @(New-AnalyzerResult)
            $authoritative = @(New-AuthoritativeResult)

            # Act
            $act = { Invoke-AnalyzerCorrelation -AnalyzerResult $analyzer -AuthoritativeResult $authoritative -Registry @() }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ConfigurationAnalyzerRegistryRequired*'
        }

        It 'refuses duplicate Analyzer results for one control by name' {
            # Arrange
            $analyzer = @(New-AnalyzerResult; New-AnalyzerResult)
            $authoritative = @(New-AuthoritativeResult)
            $registry = @(New-RegistryEntry)

            # Act
            $result = Invoke-AnalyzerCorrelation -AnalyzerResult $analyzer -AuthoritativeResult $authoritative -Registry $registry

            # Assert
            $result.Reason | Should -Contain "ConfigurationAnalyzerControlDuplicated: Analyzer reported 'EXO-001' more than once."
        }
    }

    Context 'Negative: only applicable known controls can correlate' {
        It 'refuses an Analyzer result naming an unknown control' {
            # Arrange
            $analyzer = @(New-AnalyzerResult -ControlId 'EXO-999')
            $authoritative = @(New-AuthoritativeResult)
            $registry = @(New-RegistryEntry)

            # Act
            $result = Invoke-AnalyzerCorrelation -AnalyzerResult $analyzer -AuthoritativeResult $authoritative -Registry $registry

            # Assert
            $result.Reason | Should -Contain "ConfigurationAnalyzerUnknownControl: 'EXO-999' is not present in the current control registry."
        }

        It 'refuses an Analyzer result for a control outside the selected profile' {
            # Arrange
            $analyzer = @(New-AnalyzerResult -ControlId 'PP-001')
            $authoritative = @(New-AuthoritativeResult -ControlId 'PP-001')
            $registry = @(New-RegistryEntry -ControlId 'PP-001' -ApplicableProfile @('Gateway'))

            # Act
            $result = Invoke-AnalyzerCorrelation -AnalyzerResult $analyzer -AuthoritativeResult $authoritative -Registry $registry -DeploymentProfile 'Native'

            # Assert
            $result.Reason | Should -Contain "ConfigurationAnalyzerControlNotApplicable: 'PP-001' does not apply to profile 'Native'."
        }

        It 'refuses an Analyzer status outside its declared Pass and Fail vocabulary' {
            # Arrange
            $analyzer = @(New-AnalyzerResult -Status 'Unknown')
            $authoritative = @(New-AuthoritativeResult)
            $registry = @(New-RegistryEntry)

            # Act
            $result = Invoke-AnalyzerCorrelation -AnalyzerResult $analyzer -AuthoritativeResult $authoritative -Registry $registry

            # Assert
            $result.Reason | Should -Contain "ConfigurationAnalyzerStatusInvalid: 'EXO-001' reported 'Unknown'; expected Pass or Fail."
        }
    }

    Context 'Negative: Analyzer output is supplemental and contradictions fail closed' {
        It 'refuses to manufacture an authoritative result for an Analyzer-only control' {
            # Arrange
            $analyzer = @(New-AnalyzerResult -CarryEvidence)
            $authoritative = @(New-AuthoritativeResult -ControlId 'EXO-002')
            $registry = @(New-RegistryEntry; New-RegistryEntry -ControlId 'EXO-002')

            # Act
            $result = Invoke-AnalyzerCorrelation -AnalyzerResult $analyzer -AuthoritativeResult $authoritative -Registry $registry

            # Assert
            $result.Reason | Should -Contain "ConfigurationAnalyzerAuthoritativeResultMissing: 'EXO-001' has Analyzer output but no authoritative control result."
        }

        It 'refuses to use Analyzer-carried evidence in place of authoritative evidence' {
            # Arrange
            $analyzer = @(New-AnalyzerResult -CarryEvidence)
            $authoritative = @(New-AuthoritativeResult -WithoutEvidence)
            $registry = @(New-RegistryEntry)

            # Act
            $result = Invoke-AnalyzerCorrelation -AnalyzerResult $analyzer -AuthoritativeResult $authoritative -Registry $registry

            # Assert
            $result.Reason | Should -Contain "ConfigurationAnalyzerAuthoritativeEvidenceMissing: 'EXO-001' has no authoritative control evidence."
        }

        It 'fails a contradictory Analyzer result by control name' {
            # Arrange
            $analyzer = @(New-AnalyzerResult -Status 'Pass')
            $authoritative = @(New-AuthoritativeResult -Status 'Fail')
            $registry = @(New-RegistryEntry)

            # Act
            $result = Invoke-AnalyzerCorrelation -AnalyzerResult $analyzer -AuthoritativeResult $authoritative -Registry $registry

            # Assert
            $result.Reason | Should -Contain "ConfigurationAnalyzerContradiction: 'EXO-001' Analyzer status 'Pass' contradicts authoritative status 'Fail'."
        }

        It 'returns a correlation decision that cannot be rewritten by a caller' {
            # Arrange
            $analyzer = @(New-AnalyzerResult -Status 'Pass')
            $authoritative = @(New-AuthoritativeResult -Status 'Fail')
            $registry = @(New-RegistryEntry)

            # Act
            $result = Invoke-AnalyzerCorrelation -AnalyzerResult $analyzer -AuthoritativeResult $authoritative -Registry $registry

            # Assert
            { $result.Satisfied = $true } | Should -Throw
        }
    }

    Context 'Positive: one consistent applicable result correlates without replacing evidence' {
        It 'correlates the Analyzer status to the existing authoritative result and preserves its evidence' {
            # Arrange
            $analyzer = @(New-AnalyzerResult -Status 'Pass' -CarryEvidence)
            $authoritative = @(New-AuthoritativeResult -Status 'Pass')
            $registry = @(New-RegistryEntry)

            # Act
            $result = Invoke-AnalyzerCorrelation -AnalyzerResult $analyzer -AuthoritativeResult $authoritative -Registry $registry

            # Assert
            $correlation = @($result.Correlated)[0]
            ('Satisfied={0};Control={1};Analyzer={2};Authoritative={3};EvidenceSource={4};Role={5}' -f $result.Satisfied, $correlation.ControlId, $correlation.AnalyzerStatus, $correlation.AuthoritativeStatus, $correlation.AuthoritativeEvidence.Source, $correlation.AnalyzerEvidenceRole) |
                Should -BeExactly 'Satisfied=True;Control=EXO-001;Analyzer=Pass;Authoritative=Pass;EvidenceSource=Get-AcceptedDomainEvidence;Role=Supplemental'
        }
    }
}