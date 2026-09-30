#requires -Version 7.0

BeforeAll {
    $script:sampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:modulePath = Join-Path $script:sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psm1'
    $script:manifestPath = Join-Path $script:sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1'
    $script:moduleSource = Get-Content -LiteralPath $script:modulePath -Raw
    $script:moduleAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:modulePath,
        [ref]$null,
        [ref]$null
    )
    $script:manifest = Import-PowerShellDataFile -LiteralPath $script:manifestPath
    $script:commonModule = Import-Module $script:manifestPath -Force -DisableNameChecking -PassThru

    . (Join-Path $script:sampleRoot 'tests/helpers/ExchangeProtectionFixture.ps1')
}

Describe 'EXR-010-A12-L01-F02 bounded compatibility negatives' {
    Context 'public registry command definition and exports' {
        It 'requires the registry command to exist in the module definition' {
            # Arrange
            $commandName = 'Invoke-BaselineExchangeRegistry'

            # Act
            $definition = @($script:moduleAst.FindAll({
                        param($node)
                        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                        $node.Name -ceq $commandName
                    }, $true))

            # Assert
            $definition.Count | Should -Be 1
        }

        It 'requires the registry command in the module export declaration' {
            # Arrange
            $commandName = 'Invoke-BaselineExchangeRegistry'
            $exportDeclaration = ($script:moduleSource -split 'Export-ModuleMember -Function @\(', 2)[-1]

            # Act
            $declared = $exportDeclaration -match "'$([regex]::Escape($commandName))'"

            # Assert
            $declared | Should -BeTrue
        }

        It 'requires the registry command in the manifest export declaration' {
            # Arrange
            $commandName = 'Invoke-BaselineExchangeRegistry'

            # Act
            $declared = @($script:manifest.FunctionsToExport) -ccontains $commandName

            # Assert
            $declared | Should -BeTrue
        }
    }

    Context 'complete public compatibility surface definitions and dual exports' {
        It 'requires <CommandName> on the <Surface> surface' -ForEach @(
            foreach ($commandName in @(
                    'Get-BaselineExchangeManifest'
                    'Get-BaselineExchangeContext'
                    'Invoke-BaselineExchangeGoLive'
                )) {
                foreach ($surface in @('Definition', 'ModuleExport', 'ManifestExport')) {
                    @{ CommandName = $commandName; Surface = $surface }
                }
            }
        ) {
            # Arrange
            $exportDeclaration = ($script:moduleSource -split 'Export-ModuleMember -Function @\(', 2)[-1]

            # Act
            $count = switch ($Surface) {
                'Definition' {
                    @($script:moduleAst.FindAll({
                                param($node)
                                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                                $node.Name -ceq $CommandName
                            }, $true)).Count
                }
                'ModuleExport' {
                    @([regex]::Matches($exportDeclaration, "'$([regex]::Escape($CommandName))'")).Count
                }
                'ManifestExport' {
                    @($script:manifest.FunctionsToExport | Where-Object { $_ -ceq $CommandName }).Count
                }
            }

            # Assert
            $count | Should -Be 1
        }
    }

    Context 'compatibility helpers remain private implementation seams' {
        It 'defines <CommandName> exactly once without exporting it' -ForEach @(
            @(
                'Assert-BaselineExchangeScope'
                'Get-BaselineExchangeCapabilityDecision'
                'ConvertTo-BaselineDomainInventory'
                'Invoke-BaselineExchangeRawCollection'
                'Read-BaselineExchangeOperationalArtifact'
                'Test-BaselineExchangeEvidenceSignature'
                'New-BaselineEvidenceCertificateChain'
            ) | ForEach-Object { @{ CommandName = $_ } }
        ) {
            # Arrange
            $exportDeclaration = ($script:moduleSource -split 'Export-ModuleMember -Function @\(', 2)[-1]

            # Act
            $actual = [pscustomobject]@{
                DefinitionCount = @($script:moduleAst.FindAll({
                            param($node)
                            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                            $node.Name -ceq $CommandName
                        }, $true)).Count
                ModuleExportCount = @([regex]::Matches($exportDeclaration, "'$([regex]::Escape($CommandName))'")).Count
                ManifestExportCount = @($script:manifest.FunctionsToExport | Where-Object { $_ -ceq $CommandName }).Count
            }

            # Assert
            $actual.DefinitionCount | Should -Be 1
            $actual.ModuleExportCount | Should -Be 0
            $actual.ManifestExportCount | Should -Be 0
        }
    }

    Context 'closed Exchange-only scope is admitted before collection' {
        BeforeAll {
            $script:exchangeControlId = @(
                'EXO-001', 'EXO-002', 'EXO-004', 'EXO-005', 'EXO-006', 'EXO-007', 'EXO-008', 'EXO-009', 'EXO-010', 'EXO-012'
                'MDO-001', 'MDO-002', 'MDO-003', 'MDO-006', 'MDO-007', 'MDO-008', 'MDO-009'
                'PP-005', 'AUTH-001', 'MON-003', 'OPS-001', 'OPS-002', 'GOV-003', 'GOV-004', 'GOV-005'
            )
            $script:scopeFixture = New-ProtectionFixture
        }

        It 'projects exactly the ordered 25-control Exchange-only manifest' {
            # Arrange
            $expected = $script:exchangeControlId

            # Act
            $manifest = Get-BaselineExchangeManifest

            # Assert
            @($manifest.ControlId).Count | Should -Be 25
            @($manifest.ControlId) | Should -Be $expected
        }

        It 'refuses <Case> scope before the first collector' -ForEach @(
            @{ Case = 'reduced'; ExpectedError = '*ExchangeControlMissing*' }
            @{ Case = 'expanded'; ExpectedError = '*ExchangeScopeViolation*' }
            @{ Case = 'excluded'; ExpectedError = '*ExchangeScopeViolation*' }
        ) {
            # Arrange
            $context = $script:scopeFixture.Context | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
            switch ($Case) {
                'reduced' {
                    $context.Configuration.controls.Remove('GOV-005')
                }
                'expanded' {
                    $context.Configuration.controls['EXO-003'] = @{ enabled = $true }
                }
                'excluded' {
                    $context.Configuration.controls.Remove('PP-005')
                    $context.Configuration.controls['PP-001'] = @{ enabled = $true }
                }
            }
            Mock Get-AcceptedDomainEvidence -ModuleName ExchangeOnlineBaseline.Common {
                throw 'CollectorMustNotRun'
            }

            # Act
            $invoke = { Invoke-BaselineExchangeRegistry -Context $context }

            # Assert
            $invoke | Should -Throw $ExpectedError
            Should -Invoke Get-AcceptedDomainEvidence -ModuleName ExchangeOnlineBaseline.Common -Times 0 -Exactly
        }
    }

    Context 'registry dispatch enforces real collector and evaluator contracts' {
        BeforeEach {
            $script:dispatchFixture = New-ProtectionFixture
        }

        It 'injects mandatory offline seams so real collectors do not produce an Error-only run' {
            # Arrange
            $fixture = $script:dispatchFixture

            # Act
            $execution = @(Invoke-ProtectionRawRegistry -Fixture $fixture -Module $script:commonModule)

            # Assert
            $execution.Count | Should -Be 25
            @($execution.Result | Where-Object Status -ne 'Error').Count | Should -BeGreaterThan 0
            @($execution.Result | Where-Object Status -eq 'Error').Count | Should -BeLessThan 25
        }

        It 'refuses an evaluator result with <Case> status as explicit Error evidence' -ForEach @(
            @{ Case = 'missing'; ReturnedStatus = $null }
            @{ Case = 'arbitrary'; ReturnedStatus = 'Arbitrary' }
        ) {
            # Arrange
            $fixture = $script:dispatchFixture
            $script:returnedEvaluatorStatus = $ReturnedStatus
            Mock Get-AcceptedDomainEvidence -ModuleName ExchangeOnlineBaseline.Common {
                New-BaselineEvidence -ControlId 'EXO-001' -Source 'OfflineFixture' -Command 'Get-AcceptedDomain' -Value @{}
            }
            Mock Test-AcceptedDomainControl -ModuleName ExchangeOnlineBaseline.Common {
                [pscustomobject]@{
                    ControlId = 'EXO-001'
                    Status = $script:returnedEvaluatorStatus
                    Reason = 'synthetic evaluator result'
                }
            }

            # Act
            $result = @(Invoke-ProtectionRawRegistry -Fixture $fixture -Module $script:commonModule |
                    Where-Object ControlId -CEQ 'EXO-001')[0]

            # Assert
            $result.Result.Status | Should -Be 'Error'
            $result.Result.Reason | Should -BeLike '*ExchangeEvaluatorContractInvalid*'
            $result.Evidence.Collected | Should -BeFalse
            $result.Evidence.FailureReason | Should -BeLike '*ExchangeEvaluatorContractInvalid*'
        }

        It 'records a collector exception as matching explicit Error evidence' {
            # Arrange
            $fixture = $script:dispatchFixture
            Mock Get-AcceptedDomainEvidence -ModuleName ExchangeOnlineBaseline.Common {
                throw 'SyntheticCollectorFailure'
            }

            # Act
            $result = @(Invoke-ProtectionRawRegistry -Fixture $fixture -Module $script:commonModule |
                    Where-Object ControlId -CEQ 'EXO-001')[0]

            # Assert
            $result.Result.Status | Should -Be 'Error'
            $result.Result.Reason | Should -BeLike '*SyntheticCollectorFailure*'
            $result.Evidence.ControlId | Should -Be 'EXO-001'
            $result.Evidence.Collected | Should -BeFalse
            $result.Evidence.FailureReason | Should -BeLike '*SyntheticCollectorFailure*'
        }
    }

    Context 'registry admission refuses invalid retained Exchange registries' {
        BeforeAll {
            $script:originalRegistry = & $script:commonModule { Get-BaselineControlRegistry }
            $configuration = Get-Content (Join-Path $script:sampleRoot 'config/exchange-only.v1.json') -Raw |
                ConvertFrom-Json -AsHashtable
            $parameters = Get-Content (Join-Path $script:sampleRoot 'config/parameters.exchange-only.sample.json') -Raw |
                ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.entitlement.verified = $true
            $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
            $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE', 'ATP_ENTERPRISE', 'THREAT_INTELLIGENCE')
            $script:registryContext = @{
                Configuration = $configuration
                Parameters = $parameters
                Entitlement = $parameters.entitlement
            }
        }

        BeforeEach {
            $script:candidateRegistry = @($script:originalRegistry | ConvertTo-Json -Depth 30 | ConvertFrom-Json)
        }

        It 'refuses a <Case> retained registry before collection' -ForEach @(
            @{ Case = 'duplicate' }
            @{ Case = 'incomplete' }
            @{ Case = 'mismatched' }
        ) {
            # Arrange
            switch ($Case) {
                'duplicate' {
                    $script:candidateRegistry += $script:candidateRegistry[-1]
                }
                'incomplete' {
                    $script:candidateRegistry = @($script:candidateRegistry | Select-Object -SkipLast 1)
                }
                'mismatched' {
                    @($script:candidateRegistry | Where-Object ControlId -CEQ 'MDO-001')[0].Collector = 'Get-DataLossPreventionEvidence'
                }
            }
            Mock Get-BaselineControlRegistry -ModuleName ExchangeOnlineBaseline.Common {
                ,$script:candidateRegistry
            }

            # Act
            $invoke = { Invoke-BaselineExchangeRegistry -Context $script:registryContext }

            # Assert
            $invoke | Should -Throw '*ExchangeRegistryInvalid*'
        }
    }

    Context 'private certificate-chain seam remains hardened' {
        It 'requires one module-private certificate-chain seam definition' {
            # Arrange
            $commandName = 'New-BaselineEvidenceCertificateChain'

            # Act
            $definition = @($script:moduleAst.FindAll({
                        param($node)
                        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                        $node.Name -ceq $commandName
                    }, $true))

            # Assert
            $definition.Count | Should -Be 1
        }

        It 'disables certificate downloads on the private chain' {
            # Arrange
            $module = $script:commonModule

            # Act
            $downloadsDisabled = & $module {
                $chain = New-BaselineEvidenceCertificateChain
                try { $chain.ChainPolicy.DisableCertificateDownloads }
                finally { $chain.Dispose() }
            }

            # Assert
            $downloadsDisabled | Should -BeTrue
        }

        It 'uses offline revocation on the private chain' {
            # Arrange
            $module = $script:commonModule
            $commandName = 'Test-BaselineEvidenceCertificateChain'
            $exportDeclaration = ($script:moduleSource -split 'Export-ModuleMember -Function @\(', 2)[-1]

            # Act
            $actual = [pscustomobject]@{
                RevocationMode = & $module {
                    $chain = New-BaselineEvidenceCertificateChain
                    try { $chain.ChainPolicy.RevocationMode }
                    finally { $chain.Dispose() }
                }
                DefinitionCount = @($script:moduleAst.FindAll({
                            param($node)
                            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                            $node.Name -ceq $commandName
                        }, $true)).Count
                ModuleExportCount = @([regex]::Matches(
                        $exportDeclaration,
                        "'$([regex]::Escape($commandName))'"
                    )).Count
                ManifestExportCount = @(
                    $script:manifest.FunctionsToExport |
                        Where-Object { $_ -ceq $commandName }
                ).Count
            }

            # Assert
            $actual.RevocationMode |
                Should -Be ([System.Security.Cryptography.X509Certificates.X509RevocationMode]::Offline)
            $actual.DefinitionCount | Should -Be 1
            $actual.ModuleExportCount | Should -Be 0
            $actual.ManifestExportCount | Should -Be 0
        }
    }

    Context 'compatibility does not bypass signer refusal decisions' {
        It 'retains unsigned and unauthorized refusal shapes through the private chain path' {
            # Arrange
            $module = $script:commonModule
            $bytes = [Text.Encoding]::UTF8.GetBytes('offline refusal fixture')

            # Act
            $actual = & $module {
                param($canonicalBytes)
                $chain = New-BaselineEvidenceCertificateChain
                try {
                    $signature = Test-BaselineDetachedCmsSignature -CanonicalBytes $canonicalBytes -Signature $null -VerificationScript {
                        throw 'Unsigned input must not reach verification.'
                    }
                    $signer = Test-BaselineExternalEvidenceSigner -SignatureVerification $signature `
                        -DeclaredSignerIdentity 'offline@example.invalid' -DeclaredAuthority 'ExchangeChangeApprover' `
                        -AuthorizedSigner @() -DecisionTimeUtc ([datetimeoffset]'2026-09-30T00:00:00Z')
                    [pscustomobject]@{
                        SignatureVerified = $signature.Verified
                        SignatureReason = $signature.Reason
                        SignerAuthorized = $signer.Authorized
                        SignerReason = $signer.Reason
                        RevocationMode = $chain.ChainPolicy.RevocationMode
                    }
                }
                finally {
                    $chain.Dispose()
                }
            } $bytes

            # Assert
            $actual | Should -Not -BeNullOrEmpty
            $actual.SignatureVerified | Should -BeFalse
            $actual.SignatureReason | Should -Be 'ExternalEvidenceUnsigned'
            $actual.SignerAuthorized | Should -BeFalse
            $actual.SignerReason | Should -Be 'ExternalEvidenceSignatureUnverified'
            $actual.RevocationMode | Should -Be ([System.Security.Cryptography.X509Certificates.X509RevocationMode]::Offline)
        }
    }

    Context 'detached CMS fails closed through the hardened private chain' {
        BeforeAll {
            $script:cmsKey = [Security.Cryptography.RSA]::Create(2048)
            $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=Offline Untrusted Signer',
                $script:cmsKey,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $script:cmsCertificate = $request.CreateSelfSigned(
                [datetimeoffset]::UtcNow.AddMinutes(-5),
                [datetimeoffset]::UtcNow.AddHours(1)
            )
            $script:cmsBytes = [Text.Encoding]::UTF8.GetBytes('offline hardened-chain fixture')
            $cms = [Security.Cryptography.Pkcs.SignedCms]::new(
                [Security.Cryptography.Pkcs.ContentInfo]::new($script:cmsBytes),
                $true
            )
            $signer = [Security.Cryptography.Pkcs.CmsSigner]::new($script:cmsCertificate)
            $null = $signer.SignedAttributes.Add(
                [Security.Cryptography.Pkcs.Pkcs9SigningTime]::new([datetime]::UtcNow.AddMinutes(-1))
            )
            $cms.ComputeSignature($signer)
            $script:cmsSignature = $cms.Encode()
            $script:cmsSecondKey = [Security.Cryptography.RSA]::Create(2048)
            $secondRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=Offline Second Signer',
                $script:cmsSecondKey,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $script:cmsSecondCertificate = $secondRequest.CreateSelfSigned(
                [datetimeoffset]::UtcNow.AddMinutes(-5),
                [datetimeoffset]::UtcNow.AddHours(1)
            )
            $multipleCms = [Security.Cryptography.Pkcs.SignedCms]::new(
                [Security.Cryptography.Pkcs.ContentInfo]::new($script:cmsBytes),
                $true
            )
            $multipleCms.ComputeSignature(
                [Security.Cryptography.Pkcs.CmsSigner]::new($script:cmsCertificate)
            )
            $multipleCms.ComputeSignature(
                [Security.Cryptography.Pkcs.CmsSigner]::new($script:cmsSecondCertificate)
            )
            $script:cmsMultipleSignature = $multipleCms.Encode()
            $missingTimeCms = [Security.Cryptography.Pkcs.SignedCms]::new(
                [Security.Cryptography.Pkcs.ContentInfo]::new($script:cmsBytes),
                $true
            )
            $missingTimeCms.ComputeSignature(
                [Security.Cryptography.Pkcs.CmsSigner]::new($script:cmsCertificate)
            )
            $script:cmsMissingTimeSignature = $missingTimeCms.Encode()
            $script:cmsAuthorizedSigner = @(@{
                    Identity = 'offline-reviewer'
                    Authority = 'ExchangeOnlineChangeApproval'
                    Thumbprint = $script:cmsCertificate.Thumbprint
                })
        }

        AfterAll {
            $script:cmsSecondCertificate.Dispose()
            $script:cmsSecondKey.Dispose()
            $script:cmsCertificate.Dispose()
            $script:cmsKey.Dispose()
        }

        It 'refuses <Case> CMS before invoking chain evidence' -ForEach @(
            @{ Case = 'malformed'; SignatureKind = 'Malformed' }
            @{ Case = 'multiple signer'; SignatureKind = 'Multiple' }
            @{ Case = 'missing signing time'; SignatureKind = 'MissingTime' }
        ) {
            # Arrange
            $signatureBytes = switch ($SignatureKind) {
                'Malformed' { [byte[]](1, 2, 3) }
                'Multiple' { $script:cmsMultipleSignature }
                'MissingTime' { $script:cmsMissingTimeSignature }
            }
            Mock Test-BaselineEvidenceCertificateChain -ModuleName ExchangeOnlineBaseline.Common {
                throw 'ChainEvidenceMustNotRun'
            }

            # Act
            $invoke = {
                & $script:commonModule {
                    param($bytes, $signatureBytes, $authorizedSigner)
                    Test-BaselineExchangeEvidenceSignature -Bytes $bytes -SignatureBytes $signatureBytes `
                        -SignerIdentity 'offline-reviewer' -AuthorizedSigner $authorizedSigner
                } $script:cmsBytes $signatureBytes $script:cmsAuthorizedSigner
            }

            # Assert
            $invoke | Should -Throw '*ExchangeSignatureUnverified*'
            Should -Invoke Test-BaselineEvidenceCertificateChain `
                -ModuleName ExchangeOnlineBaseline.Common -Times 0 -Exactly
        }
    }

    Context 'retained configuration schema is refused before collection' {
        BeforeEach {
            $script:schemaContext = (New-ProtectionFixture).Context |
                ConvertTo-Json -Depth 100 |
                ConvertFrom-Json -AsHashtable
            Mock Get-AcceptedDomainEvidence -ModuleName ExchangeOnlineBaseline.Common {
                throw 'CollectorMustNotRun'
            }
        }

        It 'refuses a <Case> retained setting before the first collector' -ForEach @(
            @{ Case = 'missing'; ExpectedError = '*ExchangeControlMissing*' }
            @{ Case = 'unsupported'; ExpectedError = '*ExchangeScopeViolation*' }
            @{ Case = 'malformed'; ExpectedError = '*ExchangeSchemaInvalid*' }
        ) {
            # Arrange
            switch ($Case) {
                'missing' {
                    $script:schemaContext.Configuration.controls['EXO-001'].Remove('domainType')
                }
                'unsupported' {
                    $script:schemaContext.Configuration.controls['EXO-001']['unretainedSetting'] = $true
                }
                'malformed' {
                    $script:schemaContext.Configuration.controls['EXO-001']['domainType'] = 'Arbitrary'
                }
            }

            # Act
            $invoke = { Invoke-BaselineExchangeRegistry -Context $script:schemaContext }

            # Assert
            $invoke | Should -Throw $ExpectedError
            Should -Invoke Get-AcceptedDomainEvidence -ModuleName ExchangeOnlineBaseline.Common -Times 0 -Exactly
        }
    }

    Context 'authoritative retained projection is isolated from broad registry drift' {
        BeforeEach {
            $script:projectionFixture = New-ProtectionFixture
            $script:projectionRegistry = @(
                (& $script:commonModule { Get-BaselineControlRegistry }) |
                    ConvertTo-Json -Depth 30 |
                    ConvertFrom-Json
            )
        }

        It 'ignores drift in a broad-registry control excluded from the 25-control manifest' {
            # Arrange
            @($script:projectionRegistry | Where-Object ControlId -CEQ 'EXO-003')[0].Collector =
                'Get-DataLossPreventionEvidence'
            Mock Get-BaselineControlRegistry -ModuleName ExchangeOnlineBaseline.Common {
                ,$script:projectionRegistry
            }

            # Act
            $execution = @(Invoke-ProtectionRawRegistry -Fixture $script:projectionFixture -Module $script:commonModule)

            # Assert
            $execution.Count | Should -Be 25
            @($execution.ControlId) | Should -Be $script:exchangeControlId
        }

        It 'refuses <Case> retained-registry drift before collection' -ForEach @(
            @{ Case = 'member mismatch' }
            @{ Case = 'order mismatch' }
        ) {
            # Arrange
            if ($Case -eq 'member mismatch') {
                @($script:projectionRegistry | Where-Object ControlId -CEQ 'MDO-001')[0].Collector =
                    'Get-DataLossPreventionEvidence'
            }
            else {
                $first = [array]::IndexOf([object[]]$script:projectionRegistry, @($script:projectionRegistry | Where-Object ControlId -CEQ 'EXO-001')[0])
                $second = [array]::IndexOf([object[]]$script:projectionRegistry, @($script:projectionRegistry | Where-Object ControlId -CEQ 'EXO-002')[0])
                $temporary = $script:projectionRegistry[$first]
                $script:projectionRegistry[$first] = $script:projectionRegistry[$second]
                $script:projectionRegistry[$second] = $temporary
            }
            Mock Get-BaselineControlRegistry -ModuleName ExchangeOnlineBaseline.Common {
                ,$script:projectionRegistry
            }

            # Act
            $invoke = { Invoke-BaselineExchangeRegistry -Context $script:projectionFixture.Context }

            # Assert
            $invoke | Should -Throw '*ExchangeRegistryInvalid*'
        }
    }

    Context 'operational artifacts fail closed before use' {
        BeforeEach {
            $script:artifactContext = (New-ProtectionFixture).Context
            $script:artifactContext.Manifest = Get-BaselineExchangeManifest
            if ([string]::IsNullOrWhiteSpace([string]$script:artifactContext.Hash)) {
                $script:artifactContext.Hash = 'a' * 64
            }
            $script:artifactDirectory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory -Path $script:artifactDirectory
            $script:artifactPath = Join-Path $script:artifactDirectory 'MON-003.json'
            $script:artifactDocument = [ordered]@{
                ControlId = 'MON-003'
                TenantId = $script:artifactContext.Parameters.MICROSOFT_ENTRA_TENANT_GUID
                DeploymentProfile = 'ExchangeOnly'
                ConfigurationHash = $script:artifactContext.Hash
                ManifestHash = $script:artifactContext.Manifest.Hash
                GeneratedAtUtc = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o')
                Payload = @{ Complete = $true }
                Signature = @{ Model = 'DetachedCms'; Value = [Convert]::ToBase64String([byte[]](1, 2, 3)) }
            }
            $script:artifactContext.Parameters.operationalEvidence = @{
                'MON-003' = @{
                    path = $script:artifactPath
                    signerIdentity = 'offline-artifact-reviewer'
                    authorizedSigner = @(@{
                            Identity = 'offline-artifact-reviewer'
                            Authority = 'ExchangeOnlineChangeApproval'
                            Thumbprint = '00'
                        })
                }
            }
        }

        It 'refuses a <Case> operational artifact' -ForEach @(
            @{ Case = 'unsigned'; ExpectedError = '*Unsigned*' }
            @{ Case = 'stale'; ExpectedError = '*Stale*' }
            @{ Case = 'future'; ExpectedError = '*Future*' }
            @{ Case = 'wrong tenant'; ExpectedError = '*Tenant*' }
            @{ Case = 'wrong configuration'; ExpectedError = '*Configuration*' }
            @{ Case = 'wrong manifest'; ExpectedError = '*Manifest*' }
            @{ Case = 'wrong control'; ExpectedError = '*Control*' }
            @{ Case = 'unauthorized signer'; ExpectedError = '*Unauthorized*' }
            @{ Case = 'untrusted chain'; ExpectedError = '*Untrusted*' }
            @{ Case = 'revoked chain'; ExpectedError = '*Revoked*' }
            @{ Case = 'inconclusive revocation'; ExpectedError = '*Revocation*' }
        ) {
            # Arrange
            switch ($Case) {
                'unsigned' { $script:artifactDocument.Remove('Signature') }
                'stale' { $script:artifactDocument.GeneratedAtUtc = [datetimeoffset]::UtcNow.AddDays(-30).ToString('o') }
                'future' { $script:artifactDocument.GeneratedAtUtc = [datetimeoffset]::UtcNow.AddHours(1).ToString('o') }
                'wrong tenant' { $script:artifactDocument.TenantId = [guid]::NewGuid().ToString('D') }
                'wrong configuration' { $script:artifactDocument.ConfigurationHash = 'b' * 64 }
                'wrong manifest' { $script:artifactDocument.ManifestHash = 'c' * 64 }
                'wrong control' { $script:artifactDocument.ControlId = 'OPS-001' }
                'unauthorized signer' {
                    $script:artifactContext.Parameters.operationalEvidence['MON-003'].authorizedSigner = @()
                }
                { $_ -in @('untrusted chain', 'revoked chain', 'inconclusive revocation') } {
                    $script:artifactContext.Parameters.operationalEvidence['MON-003'].chainState = 'Trusted'
                    $legacyKey = [Security.Cryptography.RSA]::Create(2048)
                    try {
                        $legacyRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                            'CN=Legacy Operational Artifact Signer',
                            $legacyKey,
                            [Security.Cryptography.HashAlgorithmName]::SHA256,
                            [Security.Cryptography.RSASignaturePadding]::Pkcs1
                        )
                        $legacyCertificate = $legacyRequest.CreateSelfSigned(
                            [datetimeoffset]::UtcNow.AddMinutes(-5),
                            [datetimeoffset]::UtcNow.AddHours(1)
                        )
                        try {
                            $script:artifactDocument.Remove('Signature')
                            $legacyBytes = [Text.Encoding]::UTF8.GetBytes(
                                (ConvertTo-CanonicalJson -InputObject $script:artifactDocument)
                            )
                            $legacyCms = [Security.Cryptography.Pkcs.SignedCms]::new(
                                [Security.Cryptography.Pkcs.ContentInfo]::new($legacyBytes),
                                $true
                            )
                            $legacySigner = [Security.Cryptography.Pkcs.CmsSigner]::new($legacyCertificate)
                            $null = $legacySigner.SignedAttributes.Add(
                                [Security.Cryptography.Pkcs.Pkcs9SigningTime]::new(
                                    [datetime]::UtcNow.AddMinutes(-1)
                                )
                            )
                            $legacyCms.ComputeSignature($legacySigner)
                            $script:artifactDocument.Signature = @{
                                Model = 'DetachedCms'
                                Value = [Convert]::ToBase64String($legacyCms.Encode())
                            }
                            $script:artifactContext.Parameters.operationalEvidence['MON-003'].authorizedSigner[0].Thumbprint =
                                $legacyCertificate.Thumbprint
                            $script:artifactContext.Parameters.operationalEvidence['MON-003'].authorizedSigner[0].Subject =
                                $legacyCertificate.Subject
                            $script:legacyArtifactChainEvidence = [ordered]@{
                                Thumbprint = $legacyCertificate.Thumbprint
                                LeafThumbprint = $legacyCertificate.Thumbprint
                                RootThumbprint = $legacyCertificate.Thumbprint
                                DecisionTimeUtc = [datetimeoffset]::UtcNow
                                ChainTrusted = $Case -cne 'untrusted chain'
                                RevocationStatus = switch ($Case) {
                                    'untrusted chain' { 'Good' }
                                    'revoked chain' { 'Revoked' }
                                    'inconclusive revocation' { 'Unknown' }
                                }
                            }
                        }
                        finally {
                            $legacyCertificate.Dispose()
                        }
                    }
                    finally {
                        $legacyKey.Dispose()
                    }
                    Mock Test-BaselineEvidenceCertificateChain -ModuleName ExchangeOnlineBaseline.Common {
                        $script:legacyArtifactChainEvidence
                    }
                }
            }
            $script:artifactDocument | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $script:artifactPath

            # Act
            $invoke = {
                & $script:commonModule {
                    param($context)
                    Read-BaselineExchangeOperationalArtifact -ControlId 'MON-003' -Context $context
                } $script:artifactContext
            }

            # Assert
            $invoke | Should -Throw $ExpectedError
            if ($Case -in @('untrusted chain', 'revoked chain', 'inconclusive revocation')) {
                Should -Invoke Test-BaselineEvidenceCertificateChain `
                    -ModuleName ExchangeOnlineBaseline.Common -Times 1 -Exactly
            }
        }
    }

    Context 'every retained control receives its mandatory command-specific seams' {
        It 'does not degrade <ControlId> to Error because a mandatory seam is missing' -ForEach @(
            @(
                'EXO-001', 'EXO-002', 'EXO-004', 'EXO-005', 'EXO-006', 'EXO-007', 'EXO-008', 'EXO-009', 'EXO-010', 'EXO-012'
                'MDO-001', 'MDO-002', 'MDO-003', 'MDO-006', 'MDO-007', 'MDO-008', 'MDO-009'
                'PP-005', 'AUTH-001', 'MON-003', 'OPS-001', 'OPS-002', 'GOV-003', 'GOV-004', 'GOV-005'
            ) | ForEach-Object { @{ ControlId = $_ } }
        ) {
            # Arrange
            $fixture = New-ProtectionFixture

            # Act
            $result = @(Invoke-ProtectionRawRegistry -Fixture $fixture -Module $script:commonModule |
                    Where-Object ControlId -CEQ $ControlId)[0]

            # Assert
            $result.Result.Status | Should -Not -Be 'Error'
            $result.Result.Reason | Should -Not -BeLike '*missing mandatory parameter*'
        }
    }

    Context 'operational verification cannot be bypassed by caller-supplied state' {
        BeforeAll {
            $script:verificationRootKey = [Security.Cryptography.RSA]::Create(2048)
            $rootRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=Offline Verification Root',
                $script:verificationRootKey,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $rootRequest.CertificateExtensions.Add(
                [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
            )
            $script:verificationRoot = $rootRequest.CreateSelfSigned(
                [datetimeoffset]::UtcNow.AddDays(-1),
                [datetimeoffset]::UtcNow.AddDays(1)
            )
            $script:verificationLeafKey = [Security.Cryptography.RSA]::Create(2048)
            $leafRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=Offline Artifact Signer',
                $script:verificationLeafKey,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $leafRequest.CertificateExtensions.Add(
                [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true)
            )
            $issuedLeaf = $leafRequest.Create(
                $script:verificationRoot,
                [datetimeoffset]::UtcNow.AddHours(-1),
                [datetimeoffset]::UtcNow.AddHours(1),
                [byte[]](1, 2, 3, 4, 5, 6, 7, 8)
            )
            $script:verificationLeaf =
                [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey(
                    $issuedLeaf,
                    $script:verificationLeafKey
                )
            $issuedLeaf.Dispose()
            $global:PublicSurfaceVerificationRoot = $script:verificationRoot
        }

        AfterAll {
            $script:verificationLeaf.Dispose()
            $script:verificationLeafKey.Dispose()
            $script:verificationRoot.Dispose()
            $script:verificationRootKey.Dispose()
        }

        BeforeEach {
            $script:verificationContext = (New-ProtectionFixture).Context
            $script:verificationDirectory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory -Path $script:verificationDirectory
            $script:verificationPath = Join-Path $script:verificationDirectory 'MON-003.json'
            $unsigned = [ordered]@{
                ControlId = 'MON-003'
                TenantId = $script:verificationContext.Parameters.MICROSOFT_ENTRA_TENANT_GUID
                DeploymentProfile = 'ExchangeOnly'
                ConfigurationHash = $script:verificationContext.Hash
                ManifestHash = $script:verificationContext.Manifest.Hash
                GeneratedAtUtc = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o')
                Payload = @{ Complete = $true }
            }
            $signedBytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson -InputObject $unsigned))
            $cms = [Security.Cryptography.Pkcs.SignedCms]::new(
                [Security.Cryptography.Pkcs.ContentInfo]::new($signedBytes),
                $true
            )
            $signer = [Security.Cryptography.Pkcs.CmsSigner]::new($script:verificationLeaf)
            $null = $signer.SignedAttributes.Add(
                [Security.Cryptography.Pkcs.Pkcs9SigningTime]::new([datetime]::UtcNow.AddMinutes(-1))
            )
            $cms.ComputeSignature($signer)
            $script:verificationDocument = $unsigned
            $script:verificationDocument.Signature = @{
                Model = 'DetachedCms'
                Value = [Convert]::ToBase64String($cms.Encode())
            }
            $script:verificationDocument | ConvertTo-Json -Depth 30 |
                Set-Content -LiteralPath $script:verificationPath
            $script:verificationContext.Parameters.operationalEvidence['MON-003'] = @{
                path = $script:verificationPath
                signerIdentity = 'offline-artifact-reviewer'
                authorizedSigner = @(@{
                        Identity = 'offline-artifact-reviewer'
                        Authority = 'ExchangeOnlineChangeApproval'
                        Thumbprint = $script:verificationLeaf.Thumbprint
                        Subject = $script:verificationLeaf.Subject
                    })
            }
        }

        It 'refuses inline verifiedDocument even when caller labels it explicitly verified' {
            # Arrange
            $reference = $script:verificationContext.Parameters.operationalEvidence['MON-003']
            $reference.Remove('path')
            $reference.verificationSeam = 'ExplicitOfflineTestVerification'
            $reference.verifiedDocument = $script:verificationDocument
            Mock Test-BaselineEvidenceCertificateChain -ModuleName ExchangeOnlineBaseline.Common {
                throw 'ChainEvidenceMustNotRun'
            }

            # Act
            $invoke = {
                & $script:commonModule {
                    param($context)
                    Read-BaselineExchangeOperationalArtifact -ControlId 'MON-003' -Context $context
                } $script:verificationContext
            }

            # Assert
            $invoke | Should -Throw '*ArtifactMissing*'
            Should -Invoke Test-BaselineEvidenceCertificateChain `
                -ModuleName ExchangeOnlineBaseline.Common -Times 0 -Exactly
        }

        It 'invokes real cryptographic verification and then bound Good chain evidence once' {
            # Arrange
            $script:goodVerificationEvidence = [ordered]@{
                Thumbprint = $script:verificationLeaf.Thumbprint
                LeafThumbprint = $script:verificationLeaf.Thumbprint
                RootThumbprint = $script:verificationRoot.Thumbprint
                DecisionTimeUtc = [datetimeoffset]::UtcNow
                ChainTrusted = $true
                RevocationStatus = 'Good'
            }
            Mock Test-BaselineEvidenceCertificateChain -ModuleName ExchangeOnlineBaseline.Common {
                $script:goodVerificationEvidence
            }

            # Act
            $actual = & {
                & $script:commonModule {
                    param($context)
                    Read-BaselineExchangeOperationalArtifact -ControlId 'MON-003' -Context $context
                } $script:verificationContext
            }

            # Assert
            $actual.SignatureVerified | Should -BeTrue
            $actual.SignerThumbprint | Should -Be $script:verificationLeaf.Thumbprint
            Should -Invoke Test-BaselineEvidenceCertificateChain `
                -ModuleName ExchangeOnlineBaseline.Common -Times 1 -Exactly
        }

        It 'fails closed for a <Case> verification result rather than trusting caller chainState' -ForEach @(
            @{ Case = 'untrusted'; Failure = 'ExternalEvidenceSignerChainUntrusted' }
            @{ Case = 'revoked'; Failure = 'ExternalEvidenceSignerRevoked' }
            @{ Case = 'inconclusive'; Failure = 'ExternalEvidenceSignerRevocationInconclusive' }
        ) {
            # Arrange
            $script:verificationContext.Parameters.operationalEvidence['MON-003'].chainState = 'Trusted'
            $script:verificationChainEvidence = [ordered]@{
                Thumbprint = $script:verificationLeaf.Thumbprint
                LeafThumbprint = $script:verificationLeaf.Thumbprint
                RootThumbprint = $script:verificationRoot.Thumbprint
                DecisionTimeUtc = [datetimeoffset]::UtcNow
                ChainTrusted = $Case -cne 'untrusted'
                RevocationStatus = switch ($Case) {
                    'untrusted' { 'Good' }
                    'revoked' { 'Revoked' }
                    'inconclusive' { 'Unknown' }
                }
            }
            Mock Test-BaselineEvidenceCertificateChain -ModuleName ExchangeOnlineBaseline.Common {
                $script:verificationChainEvidence
            }

            # Act
            $invoke = {
                & $script:commonModule {
                    param($context)
                    Read-BaselineExchangeOperationalArtifact -ControlId 'MON-003' -Context $context
                } $script:verificationContext
            }

            # Assert
            $invoke | Should -Throw "*$Failure*"
            Should -Invoke Test-BaselineEvidenceCertificateChain `
                -ModuleName ExchangeOnlineBaseline.Common -Times 1 -Exactly
        }

        It 'refuses an empty authorized-signer list before invoking chain evidence' {
            # Arrange
            $script:verificationContext.Parameters.operationalEvidence['MON-003'].authorizedSigner = @()
            Mock Test-BaselineEvidenceCertificateChain -ModuleName ExchangeOnlineBaseline.Common {
                throw 'ChainEvidenceMustNotRun'
            }

            # Act
            $invoke = {
                & $script:commonModule {
                    param($context)
                    Read-BaselineExchangeOperationalArtifact -ControlId 'MON-003' -Context $context
                } $script:verificationContext
            }

            # Assert
            $invoke | Should -Throw '*Unauthorized*'
            Should -Invoke Test-BaselineEvidenceCertificateChain `
                -ModuleName ExchangeOnlineBaseline.Common -Times 0 -Exactly
        }
    }

    Context 'go-live binds the complete Exchange disposition and evidence record contract' {
        BeforeEach {
            $script:goLiveFixture = New-ProtectionFixture
            $script:goLiveContext = $script:goLiveFixture.Context
            $script:goLiveManifest = Get-BaselineExchangeManifest
            $script:goLiveContext.Manifest = $script:goLiveManifest
            $script:goLiveDirectory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory -Path $script:goLiveDirectory
            $script:goLiveEvidencePath = Join-Path $script:goLiveDirectory 'evidence.json'
            $script:goLiveSignaturePath = Join-Path $script:goLiveDirectory 'evidence.p7s'
            $script:goLiveAuthorityPath = Join-Path $script:goLiveDirectory 'authorized-signers.json'
            $script:goLiveKey = [Security.Cryptography.RSA]::Create(2048)
            $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=Offline Go-Live Binding Signer',
                $script:goLiveKey,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $script:goLiveCertificate = $request.CreateSelfSigned(
                [datetimeoffset]::UtcNow.AddMinutes(-5),
                [datetimeoffset]::UtcNow.AddHours(1)
            )
            $global:PublicSurfaceGoLiveThumbprint = $script:goLiveCertificate.Thumbprint
            @(@{
                    Identity = 'offline-golive-reviewer'
                    Authority = 'ExchangeOnlineChangeApproval'
                    Thumbprint = $script:goLiveCertificate.Thumbprint
                    Subject = $script:goLiveCertificate.Subject
                }) | ConvertTo-Json -AsArray -Depth 10 |
                Set-Content -LiteralPath $script:goLiveAuthorityPath
            $collectedAt = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o')
            $script:goLiveEnvelope = [ordered]@{
                TenantId = $script:goLiveContext.Parameters.MICROSOFT_ENTRA_TENANT_GUID
                DeploymentProfile = 'ExchangeOnly'
                ConfigurationHash = $script:goLiveContext.Hash
                CollectedAtUtc = $collectedAt
                Entitlement = $script:goLiveContext.Entitlement
                Check = @(
                    foreach ($controlId in $script:goLiveManifest.ControlId) {
                        [ordered]@{ ControlId = $controlId; Status = 'Pass'; Reason = 'Offline conformance.' }
                    }
                )
                Evidence = @(
                    foreach ($controlId in $script:goLiveManifest.ControlId) {
                        [ordered]@{
                            ControlId = $controlId
                            Collected = $true
                            CollectedAtUtc = $collectedAt
                            Value = [ordered]@{ Source = 'IndependentOfflineObservation' }
                        }
                    }
                )
                ManifestHash = $script:goLiveManifest.Hash
                Exclusion = $script:goLiveManifest.Exclusion
                ExternalCheck = $script:goLiveManifest.ExternalCheck
                ExternalReadiness = $script:goLiveManifest.ExternalReadiness
            }
            Mock Test-BaselineEvidenceCertificateChain -ModuleName ExchangeOnlineBaseline.Common {
                param($Certificate, $CertificateCollection, $DecisionTimeUtc)
                [ordered]@{
                    Thumbprint = $Certificate.Thumbprint
                    LeafThumbprint = $Certificate.Thumbprint
                    RootThumbprint = $Certificate.Thumbprint
                    DecisionTimeUtc = [datetimeoffset]$DecisionTimeUtc
                    ChainTrusted = $true
                    RevocationStatus = 'Good'
                }
            }
        }

        AfterEach {
            Remove-Variable -Name PublicSurfaceGoLiveThumbprint -Scope Global -ErrorAction SilentlyContinue
            if ($null -ne $script:goLiveCertificate) { $script:goLiveCertificate.Dispose() }
            if ($null -ne $script:goLiveKey) { $script:goLiveKey.Dispose() }
        }

        It 'refuses a correctly signed ExchangeOnly envelope with <Case>' -ForEach @(
            @{ Case = 'missing ManifestHash'; ExpectedReason = 'ExchangeManifestMismatch' }
            @{ Case = 'mismatched ManifestHash'; ExpectedReason = 'ExchangeManifestMismatch' }
            @{ Case = 'mismatched Exclusion'; ExpectedReason = 'ExchangeDispositionMismatch' }
            @{ Case = 'mismatched ExternalCheck'; ExpectedReason = 'ExchangeDispositionMismatch' }
            @{ Case = 'mismatched ExternalReadiness'; ExpectedReason = 'ExchangeDispositionMismatch' }
            @{ Case = 'changed Entitlement'; ExpectedReason = 'ExchangeEntitlementChanged' }
            @{ Case = 'an uncollected evidence record'; ExpectedReason = 'ExchangeEvidenceUncollected' }
            @{ Case = 'a missing evidence Value'; ExpectedReason = 'ExchangeEvidenceValueMissing' }
            @{ Case = 'a null evidence Value'; ExpectedReason = 'ExchangeEvidenceValueMissing' }
            @{ Case = 'an unreadable evidence record time'; ExpectedReason = 'ExchangeEvidenceRecordTimeUnreadable' }
            @{ Case = 'a future evidence record time'; ExpectedReason = 'ExchangeEvidenceRecordFromFuture' }
            @{ Case = 'a stale evidence record time'; ExpectedReason = 'ExchangeEvidenceRecordStale' }
        ) {
            # Arrange
            switch ($Case) {
                'missing ManifestHash' { $script:goLiveEnvelope.Remove('ManifestHash') }
                'mismatched ManifestHash' { $script:goLiveEnvelope.ManifestHash = 'f' * 64 }
                'mismatched Exclusion' { $script:goLiveEnvelope.Exclusion = @('PP-999') }
                'mismatched ExternalCheck' {
                    $script:goLiveEnvelope.ExternalCheck = [ordered]@{ Status = 'Verified'; Reference = 'caller' }
                }
                'mismatched ExternalReadiness' {
                    $script:goLiveEnvelope.ExternalReadiness = [ordered]@{ Status = 'Verified'; Reference = 'caller'; Meaning = 'caller' }
                }
                'changed Entitlement' {
                    $script:goLiveEnvelope.Entitlement = $script:goLiveContext.Entitlement |
                        ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable -DateKind String
                    $script:goLiveEnvelope.Entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE')
                }
                'an uncollected evidence record' { $script:goLiveEnvelope.Evidence[0].Collected = $false }
                'a missing evidence Value' { $script:goLiveEnvelope.Evidence[0].Remove('Value') }
                'a null evidence Value' { $script:goLiveEnvelope.Evidence[0].Value = $null }
                'an unreadable evidence record time' { $script:goLiveEnvelope.Evidence[0].CollectedAtUtc = 'not-a-time' }
                'a future evidence record time' {
                    $script:goLiveEnvelope.Evidence[0].CollectedAtUtc = [datetimeoffset]::UtcNow.AddHours(1).ToString('o')
                }
                'a stale evidence record time' {
                    $script:goLiveEnvelope.Evidence[0].CollectedAtUtc = [datetimeoffset]::UtcNow.AddHours(-2).ToString('o')
                }
            }
            $script:goLiveEnvelope | ConvertTo-Json -Depth 100 |
                Set-Content -LiteralPath $script:goLiveEvidencePath
            $evidenceHash = (Get-FileHash -LiteralPath $script:goLiveEvidencePath -Algorithm SHA256).Hash

            # Act
            $actual = Invoke-BaselineExchangeGoLive -Context $script:goLiveContext `
                -EvidencePath $script:goLiveEvidencePath -SignaturePath $script:goLiveSignaturePath `
                -MaximumEvidenceAge ([timespan]::FromHours(1)) -SignerIdentity 'offline-golive-reviewer' `
                -AuthorizedSignerPath $script:goLiveAuthorityPath -ExpectedEvidenceHash $evidenceHash `
                -ExpectedConfigurationHash $script:goLiveContext.Hash -SignEvidence `
                -SigningCertificate $script:goLiveCertificate

            # Assert
            $actual.Decision.Admitted | Should -BeFalse
            @($actual.Decision.Finding) -join '; ' | Should -Match $ExpectedReason
        }
    }

    Describe 'EXR-010-A12-L01-F02 bounded compatibility positive' {
        AfterEach {
            if ($null -ne $script:positiveCertificate) { $script:positiveCertificate.Dispose() }
            if ($null -ne $script:positiveKey) { $script:positiveKey.Dispose() }
        }

        It 'resolves and exercises the complete offline compatibility surface without weakening refusal shapes' {
            # Arrange
            $module = $script:commonModule
            $fixture = New-ProtectionFixture
            $script:positiveKey = [Security.Cryptography.RSA]::Create(2048)
            $positiveRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=Offline Positive Signer',
                $script:positiveKey,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $script:positiveCertificate = $positiveRequest.CreateSelfSigned(
                [datetimeoffset]::UtcNow.AddMinutes(-5),
                [datetimeoffset]::UtcNow.AddHours(1)
            )
            $global:PublicSurfacePositiveThumbprint = $script:positiveCertificate.Thumbprint
            $directory = Join-Path $TestDrive 'positive'
            $null = New-Item -ItemType Directory -Path $directory
            $configurationPath = Join-Path $directory 'configuration.json'
            $parameterPath = Join-Path $directory 'parameters.json'
            $evidencePath = Join-Path $directory 'evidence.json'
            $signaturePath = Join-Path $directory 'evidence.p7s'
            $authorizedSignerPath = Join-Path $directory 'authorized-signers.json'
            $fixture.Context.Configuration | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $configurationPath
            $fixture.Context.Parameters | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $parameterPath
            @{ Check = @(); Evidence = @() } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $evidencePath
            @(@{
                    Identity = 'offline-positive-reviewer'
                    Authority = 'ExchangeOnlineChangeApproval'
                    Thumbprint = $script:positiveCertificate.Thumbprint
                    Subject = $script:positiveCertificate.Subject
                }) | ConvertTo-Json -Depth 10 -AsArray | Set-Content -LiteralPath $authorizedSignerPath
            $evidenceHash = (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash
            Mock Test-BaselineEvidenceCertificateChain -ModuleName ExchangeOnlineBaseline.Common {
                param($Certificate, $CertificateCollection, $DecisionTimeUtc)
                $additional = @($CertificateCollection | Where-Object {
                        $_.Thumbprint -ine $Certificate.Thumbprint
                    })
                $root = if ($additional.Count -gt 0) { $additional[-1] } else { $Certificate }
                [ordered]@{
                    Thumbprint = $Certificate.Thumbprint
                    LeafThumbprint = $Certificate.Thumbprint
                    RootThumbprint = $root.Thumbprint
                    DecisionTimeUtc = if ($null -ne $DecisionTimeUtc) {
                        [datetimeoffset]$DecisionTimeUtc
                    }
                    else {
                        [datetimeoffset]::UtcNow
                    }
                    ChainTrusted = $true
                    RevocationStatus = 'Good'
                }
            }
            Mock Get-BaselineEvidenceContentHash -ModuleName ExchangeOnlineBaseline.Common {
                @{ Hash = ('a' * 64) }
            }
            Mock Test-BaselineGoLive -ModuleName ExchangeOnlineBaseline.Common {
                [ordered]@{
                    Admitted = $true
                    Reason = 'OfflineSignedEvidenceAdmitted'
                    Result = [ordered]@{ ControlId = 'GATE-003'; Status = 'Pass' }
                    ExternalReadiness = (Get-BaselineExchangeManifest).ExternalReadiness
                }
            }
            Mock Get-BaselineRunOutcome -ModuleName ExchangeOnlineBaseline.Common {
                [pscustomobject]@{ Success = $true; ExitCode = 0 }
            }

            # Act
            $actual = & {
                $publicCommands = @(Get-Command -Module ExchangeOnlineBaseline.Common -Name @(
                            'Get-BaselineExchangeManifest'
                            'Get-BaselineExchangeContext'
                            'Invoke-BaselineExchangeRegistry'
                            'Invoke-BaselineExchangeGoLive'
                        ) -ErrorAction SilentlyContinue)
                $manifest = Get-BaselineExchangeManifest
                $fixture.Context = Get-BaselineExchangeContext -ConfigurationPath $configurationPath -ParameterPath $parameterPath
                $execution = @(Invoke-ProtectionRawRegistry -Fixture $fixture -Module $module)
                $mdo001 = @($execution | Where-Object ControlId -CEQ 'MDO-001')[0]
                $mdo006 = @($execution | Where-Object ControlId -CEQ 'MDO-006')[0]
                $goLive = Invoke-BaselineExchangeGoLive -Context $fixture.Context -EvidencePath $evidencePath `
                    -SignaturePath $signaturePath -MaximumEvidenceAge ([timespan]::FromHours(1)) `
                    -SignerIdentity 'offline-positive-reviewer' -AuthorizedSignerPath $authorizedSignerPath `
                    -ExpectedEvidenceHash $evidenceHash -ExpectedConfigurationHash $fixture.Context.Hash `
                    -SignEvidence -SigningCertificate $script:positiveCertificate
                [pscustomobject]@{
                    PublicCommandCount = $publicCommands.Count
                    ManifestControlId = @($manifest.ControlId)
                    ResultCount = $execution.Count
                    UniqueControlCount = @($execution.ControlId | Select-Object -Unique).Count
                    ErrorCount = @($execution.Result | Where-Object Status -EQ 'Error').Count
                    Mdo001Status = $mdo001.Result.Status
                    Mdo006Status = $mdo006.Result.Status
                    GoLive = $goLive
                    SignatureCreated = Test-Path -LiteralPath $signaturePath
                }
            }

            # Assert
            $actual.PublicCommandCount | Should -Be 4
            $actual.ManifestControlId | Should -Be $script:exchangeControlId
            $actual.ResultCount | Should -Be 25
            $actual.UniqueControlCount | Should -Be 25
            @($actual.GoLive.Outcome) | Should -HaveCount 1
            $actual.Mdo001Status | Should -Be 'Pass'
            $actual.Mdo006Status | Should -Be 'Pass'
            $actual.ErrorCount | Should -Be 0
            $actual.GoLive.Decision.Admitted | Should -BeTrue
            $actual.GoLive.Decision.Result.ControlId | Should -BeExactly 'GATE-003'
            $actual.GoLive.Decision.Result.Status | Should -BeExactly 'Pass'
            $actual.GoLive.Decision.ExternalReadiness.Status | Should -BeExactly 'Unverified'
            $actual.GoLive.Decision.Stage | Should -Be 'Sign'
            $actual.GoLive.Outcome.Success | Should -BeTrue
            $actual.SignatureCreated | Should -BeTrue
        }
    }
}
