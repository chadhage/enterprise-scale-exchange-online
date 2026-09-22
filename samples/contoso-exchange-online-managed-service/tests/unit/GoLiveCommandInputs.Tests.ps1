#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:EvidenceScriptPath = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'
    $script:RiskAcceptanceSchemaPath = Join-Path $script:SampleRoot 'config' 'risk-acceptance.schema.json'
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:TenantId = 'f1a3b5c7-0000-4000-8000-0123456789ab'
    $script:ConfigurationHash = 'a3f1c9d2b4e6708192a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f809'

    function Get-GoLiveInputMaterializationBlock {
        $source = Get-Content -LiteralPath $script:EvidenceScriptPath -Raw
        $startToken = '# GATE-006 INPUT MATERIALIZATION START'
        $endToken = '# GATE-006 INPUT MATERIALIZATION END'
        $start = $source.IndexOf($startToken, [System.StringComparison]::Ordinal)
        $end = $source.IndexOf($endToken, [System.StringComparison]::Ordinal)

        if ($start -lt 0 -or $end -le $start) {
            return [scriptblock]::Create('$null = Connect-ExchangeOnline; Import-Module ExchangeOnlineManagement; $goLiveInput = [pscustomobject]@{}')
        }

        $bodyStart = $start + $startToken.Length
        return [scriptblock]::Create($source.Substring($bodyStart, $end - $bodyStart))
    }

    $script:MaterializationBlock = Get-GoLiveInputMaterializationBlock

    function New-RiskAcceptanceDocument {
        param(
            [string]$ConfigurationHash = $script:ConfigurationHash,
            [switch]$SchemaInvalid,
            [switch]$Unsigned
        )

        $document = [ordered]@{
            SchemaVersion      = '1.0.0'
            ControlId          = 'EXO-001'
            TenantId           = $script:TenantId
            ConfigurationHash  = $ConfigurationHash
            Owner              = 'risk-owner@contoso.example'
            Justification      = 'A bounded operational exception remains under active review.'
            CompensatingControl = @('Daily review of the affected control')
            ExternalReference  = 'RISK-2026-0042'
            ApprovalIdentity   = 'approver@contoso.example'
            ApprovalAuthority  = 'ExchangeOnlineChangeApproval'
            ApprovalTimeUtc    = '2026-09-19T10:00:00Z'
            EffectiveTimeUtc   = '2026-09-19T10:00:00Z'
            ExpiryTimeUtc      = '2026-09-26T10:00:00Z'
            Signature          = [ordered]@{ Model = 'DetachedCms'; Value = 'AQIDBA==' }
        }

        if ($SchemaInvalid) { $document.Remove('ControlId') }
        if ($Unsigned) { $document.Signature.Value = '' }
        return [pscustomobject]$document
    }

    function Write-RiskAcceptanceDocument {
        param(
            [object]$Document = (New-RiskAcceptanceDocument),
            [string]$Text
        )

        $path = Join-Path $TestDrive ('risk-acceptance-{0}.json' -f [guid]::NewGuid().ToString('N'))
        if ($PSBoundParameters.ContainsKey('Text')) {
            Set-Content -LiteralPath $path -Value $Text -Encoding utf8
        }
        else {
            $Document | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding utf8
        }
        return $path
    }

    function New-GoLiveContext {
        param([bool]$EntitlementDetermined = $true)

        return [pscustomobject]@{
            Hash              = $script:ConfigurationHash
            Algorithm         = 'SHA256'
            DeploymentProfile = 'MicrosoftNative'
            Entitlement       = [pscustomobject]@{
                Source       = 'SanitizedOfflineFixture'
                Determined   = $EntitlementDetermined
                NotEntitled  = @()
                Missing      = @()
            }
        }
    }

    function Invoke-GoLiveInputMaterialization {
        param(
            [AllowNull()][AllowEmptyString()][string]$RiskAcceptancePath = (Write-RiskAcceptanceDocument),
            [AllowNull()][AllowEmptyString()][string]$ExpectedConfigurationHash = $script:ConfigurationHash,
            [timespan]$MaximumEvidenceAge = ([timespan]::FromDays(7)),
            [object]$Context = (New-GoLiveContext),
            [object]$Envelope = ([pscustomobject]@{ TenantId = $script:TenantId; ConfigurationHash = "sha256:$($script:ConfigurationHash)" }),
            [scriptblock]$CmsVerificationScript = {
                param([byte[]]$ContentBytes, [byte[]]$SignatureBytes)
                [pscustomobject]@{ SignatureValid = $true; ContentMatched = $true; ChainTrusted = $true; RevocationStatus = 'Good' }
            }
        )

        $GoLive = $true
        $configuration = [pscustomobject]@{
            metadata = [pscustomobject]@{ configurationOwner = 'operator@contoso.example' }
            administratorInputs = [pscustomobject]@{ tenantId = $script:TenantId }
        }
        $riskAcceptanceSchemaPath = $script:RiskAcceptanceSchemaPath
        $goLiveCatalogPath = Join-Path $script:SampleRoot 'docs' 'CONTROL-CATALOG.md'
        $goLiveCmsVerificationScript = $CmsVerificationScript
        $goLiveInput = $null

        . $script:MaterializationBlock
        return $goLiveInput
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GATE-006 go-live command input materialization' {
    Context 'Negative: risk acceptance input is required, readable, parseable, and schema-valid' {
        It 'refuses an absent risk acceptance path' {
            # Arrange
            $path = Join-Path $TestDrive 'absent-risk-acceptance.json'

            # Act
            $act = { Invoke-GoLiveInputMaterialization -RiskAcceptancePath $path }

            # Assert
            $act | Should -Throw -ExpectedMessage '*GoLiveRiskAcceptanceNotFound*'
        }

        It 'refuses an unreadable risk acceptance path' {
            # Arrange
            $path = Join-Path $TestDrive 'risk-acceptance-directory'
            $null = New-Item -ItemType Directory -Path $path

            # Act
            $act = { Invoke-GoLiveInputMaterialization -RiskAcceptancePath $path }

            # Assert
            $act | Should -Throw -ExpectedMessage '*GoLiveRiskAcceptanceUnreadable*'
        }

        It 'refuses malformed risk acceptance JSON' {
            # Arrange
            $path = Write-RiskAcceptanceDocument -Text '{ not-json'

            # Act
            $act = { Invoke-GoLiveInputMaterialization -RiskAcceptancePath $path }

            # Assert
            $act | Should -Throw -ExpectedMessage '*GoLiveRiskAcceptanceMalformed*'
        }

        It 'refuses a risk acceptance rejected by the published schema' {
            # Arrange
            $path = Write-RiskAcceptanceDocument -Document (New-RiskAcceptanceDocument -SchemaInvalid)

            # Act
            $act = { Invoke-GoLiveInputMaterialization -RiskAcceptancePath $path }

            # Assert
            $act | Should -Throw -ExpectedMessage '*GoLiveRiskAcceptanceSchemaInvalid*'
        }
    }

    Context 'Negative: hash, age, and entitlement bindings fail closed' {
        It 'refuses an absent expected configuration hash' {
            # Arrange
            $missing = ''

            # Act
            $act = { Invoke-GoLiveInputMaterialization -ExpectedConfigurationHash $missing }

            # Assert
            $act | Should -Throw -ExpectedMessage '*GoLiveExpectedConfigurationHashRequired*'
        }

        It 'refuses an expected configuration hash that differs from the resolved context' {
            # Arrange
            $otherHash = ('b' * 64)

            # Act
            $act = { Invoke-GoLiveInputMaterialization -ExpectedConfigurationHash $otherHash }

            # Assert
            $act | Should -Throw -ExpectedMessage '*GoLiveExpectedConfigurationHashMismatch*'
        }

        It 'refuses a zero maximum evidence age' {
            # Arrange
            $age = [timespan]::Zero

            # Act
            $act = { Invoke-GoLiveInputMaterialization -MaximumEvidenceAge $age }

            # Assert
            $act | Should -Throw -ExpectedMessage '*GoLiveMaximumEvidenceAgeNotPositive*'
        }

        It 'refuses a negative maximum evidence age' {
            # Arrange
            $age = [timespan]::FromMinutes(-1)

            # Act
            $act = { Invoke-GoLiveInputMaterialization -MaximumEvidenceAge $age }

            # Assert
            $act | Should -Throw -ExpectedMessage '*GoLiveMaximumEvidenceAgeNotPositive*'
        }

        It 'refuses unresolved target entitlement' {
            # Arrange
            $context = New-GoLiveContext -EntitlementDetermined $false

            # Act
            $act = { Invoke-GoLiveInputMaterialization -Context $context }

            # Assert
            $act | Should -Throw -ExpectedMessage '*GoLiveTargetEntitlementUnresolved*'
        }
    }

    Context 'Negative: detached CMS evidence must be present, bound, and verified' {
        It 'refuses unsigned evidence' {
            # Arrange
            $path = Write-RiskAcceptanceDocument -Document (New-RiskAcceptanceDocument -Unsigned)

            # Act
            $act = { Invoke-GoLiveInputMaterialization -RiskAcceptancePath $path }

            # Assert
            $act | Should -Throw -ExpectedMessage '*GoLiveEvidenceUnsigned*'
        }

        It 'refuses a detached CMS signature bound to other bytes' {
            # Arrange
            $verifier = { [pscustomobject]@{ SignatureValid = $true; ContentMatched = $false } }

            # Act
            $act = { Invoke-GoLiveInputMaterialization -CmsVerificationScript $verifier }

            # Assert
            $act | Should -Throw -ExpectedMessage '*GoLiveEvidenceTampered*'
        }

        It 'refuses detached CMS evidence that cannot be verified' {
            # Arrange
            $verifier = { throw 'offline trust chain unavailable' }

            # Act
            $act = { Invoke-GoLiveInputMaterialization -CmsVerificationScript $verifier }

            # Assert
            $act | Should -Throw -ExpectedMessage '*GoLiveEvidenceUnverified*'
        }
    }

    Context 'Negative: materialization remains offline and module-free' {
        It 'contains no tenant-access command' {
            # Arrange
            $ast = $script:MaterializationBlock.Ast
            $tenantCommand = @('Connect-ExchangeOnline', 'Connect-MgGraph', 'Invoke-MgGraphRequest', 'Get-Recipient', 'Get-DistributionGroupMember')

            # Act
            $attempt = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -in $tenantCommand }, $true))

            # Assert
            $attempt | Should -BeNullOrEmpty
        }

        It 'contains no live-module import or installation command' {
            # Arrange
            $ast = $script:MaterializationBlock.Ast
            $moduleCommand = @('Import-Module', 'Install-Module', 'Install-PSResource')

            # Act
            $attempt = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -in $moduleCommand }, $true))

            # Assert
            $attempt | Should -BeNullOrEmpty
        }
    }

    Context 'Positive: one sanitized go-live input set is complete' {
        It 'materializes the validated artifacts and resolved bindings exactly once' {
            # Arrange
            $context = New-GoLiveContext
            $script:CmsVerificationCount = 0
            $verifier = {
                param([byte[]]$ContentBytes, [byte[]]$SignatureBytes)
                $script:CmsVerificationCount++
                [pscustomobject]@{
                    SignatureValid  = $true
                    ContentMatched  = $true
                    ChainTrusted    = $true
                    RevocationStatus = 'Good'
                }
            }

            # Act
            $inputSet = Invoke-GoLiveInputMaterialization -Context $context -CmsVerificationScript $verifier

            # Assert
            $script:CmsVerificationCount | Should -Be 1
            @($inputSet.RiskAcceptance).Count | Should -Be 1
            $inputSet.ExpectedConfigurationHash | Should -BeExactly $script:ConfigurationHash
            $inputSet.MaximumEvidenceAge | Should -Be ([timespan]::FromDays(7))
            $inputSet.TargetEntitlement | Should -Be $context.Entitlement
            $inputSet.Signature.Verified | Should -BeTrue
            $inputSet.Signature.ContentHash | Should -Not -BeNullOrEmpty
            $inputSet.RequestedBy | Should -BeExactly 'operator@contoso.example'
        }
    }
}
