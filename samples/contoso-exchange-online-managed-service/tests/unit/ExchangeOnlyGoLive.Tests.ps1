BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force
    $manifest = Get-BaselineExchangeManifest
    $catalog = Join-Path $sampleRoot 'config/exchange-only.manifest.v1.json'
    $gateKey = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Scoped gate offline test', $gateKey, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $gateCertificate = $request.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(1))
    Mock -ModuleName ExchangeOnlineBaseline.Common New-BaselineEvidenceCertificateChain {
        $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.TrustMode = [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
        $null = $chain.ChainPolicy.CustomTrustStore.Add($gateCertificate)
        $chain
    }
    function Set-ScopedGateSignature {
        param($Case)
        $bytes = [Text.Encoding]::UTF8.GetBytes(($Case.Envelope | ConvertTo-Json -Depth 100))
        $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($bytes), $true)
        $signer = [Security.Cryptography.Pkcs.CmsSigner]::new($gateCertificate)
        $null = $signer.SignedAttributes.Add([Security.Cryptography.Pkcs.Pkcs9SigningTime]::new([datetime]::UtcNow))
        $cms.ComputeSignature($signer)
        $Case.Signature = @{
            Model = 'DetachedCms'; Value = [Convert]::ToBase64String($cms.Encode())
            ContentHash = (Get-BaselineEvidenceContentHash -Envelope $Case.Envelope).Hash
            EvidenceBytes = $bytes; SignerIdentity = 'offline-approver'
            AuthorizedSigner = @(@{ Identity = 'offline-approver'; Subject = $gateCertificate.Subject; Thumbprint = $gateCertificate.Thumbprint; Authority = 'ExchangeOnlineChangeApproval' })
        }
    }
    function New-ScopedGateCase {
        $envelope = [ordered]@{
            TenantId = 'offline-tenant'; DeploymentProfile = 'ExchangeOnly'; ProfileVersion = '1.0.0'
            ConfigurationHash = 'a' * 64; CollectedAtUtc = [datetimeoffset]::UtcNow.ToString('o')
            Check = @($manifest.ControlId | ForEach-Object { [pscustomobject]@{ ControlId = $_; Status = 'Pass' } })
            Evidence = @($manifest.ControlId | ForEach-Object { New-BaselineEvidence -ControlId $_ -Source ExchangeOnline -Command OfflineGateFixture -Value @{ observed = $true } })
            ManifestHash = $manifest.Hash; Exclusion = $manifest.Exclusion; ExternalCheck = $manifest.ExternalCheck; ExternalReadiness = $manifest.ExternalReadiness
            Entitlement = @{ verified = $true; tenantId = 'offline-tenant'; servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE','THREAT_INTELLIGENCE'); expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') }
        }
        $case = @{ Envelope = $envelope; CatalogPath = $catalog; ExpectedTenantId = 'offline-tenant'; ExpectedDeploymentProfile = 'ExchangeOnly'; ExpectedConfigurationHash = 'a' * 64; MaximumEvidenceAge = [timespan]::FromHours(1); ExpectedEntitlement = $envelope.Entitlement }
        Set-ScopedGateSignature -Case $case
        $case
    }
}

AfterAll {
    $gateCertificate.Dispose()
    $gateKey.Dispose()
}

Describe 'EXR-001 scoped go-live denominator' {
    It 'refuses a caller-reduced catalog that omits a retained control' {
        # Arrange
        $case = New-ScopedGateCase
        $case.CatalogPath = Join-Path $TestDrive 'reduced.json'
        @{ ControlId = @('EXO-001') } | ConvertTo-Json | Set-Content $case.CatalogPath
        $case.Envelope.Check = @($case.Envelope.Check | Where-Object ControlId -NE 'OPS-001')
        Set-ScopedGateSignature -Case $case
        # Act
        $decision = Test-BaselineGoLive @case
        # Assert
        $decision.Admitted | Should -BeFalse
        $decision.Finding -join ' ' | Should -Match 'OPS-001'
    }

    It 'rejects a changed manifest with the same profile version' {
        # Arrange
        $case = New-ScopedGateCase
        $case.Envelope.ManifestHash = 'b' * 64
        Set-ScopedGateSignature -Case $case
        # Act
        $decision = Test-BaselineGoLive @case
        # Assert
        $decision.Admitted | Should -BeFalse
        $decision.Finding -join ' ' | Should -Match 'ExchangeManifestMismatch'
    }

    It 'rejects fabricated external readiness and omitted dispositions' {
        # Arrange
        $case = New-ScopedGateCase
        $case.Envelope.ExternalReadiness = @{ Status = 'Pass' }
        $case.Envelope.Exclusion = @()
        Set-ScopedGateSignature -Case $case
        # Act
        $decision = Test-BaselineGoLive @case
        # Assert
        $decision.Admitted | Should -BeFalse
        $decision.Finding -join ' ' | Should -Match 'ExchangeDispositionMismatch'
    }

    It 'rejects missing scoped evidence even when all checks say Pass' {
        # Arrange
        $case = New-ScopedGateCase
        $case.Envelope.Evidence = @($case.Envelope.Evidence | Where-Object ControlId -NE 'EXO-010')
        Set-ScopedGateSignature -Case $case
        # Act
        $decision = Test-BaselineGoLive @case
        # Assert
        $decision.Admitted | Should -BeFalse
        $decision.Finding -join ' ' | Should -Match 'EvidenceControlMissing.*EXO-010'
    }

    It 'rejects excluded controls presented as Pass' {
        # Arrange
        $case = New-ScopedGateCase
        $case.Envelope.Check += [pscustomobject]@{ ControlId = 'GOV-002'; Status = 'Pass' }
        Set-ScopedGateSignature -Case $case
        # Act
        $decision = Test-BaselineGoLive @case
        # Assert
        $decision.Admitted | Should -BeFalse
        $decision.Finding -join ' ' | Should -Match 'CatalogControlUnknown.*GOV-002'
    }

    It 'rejects an unversioned scope declaration' {
        # Arrange
        $case = New-ScopedGateCase
        $case.Envelope.ProfileVersion = '0.0.0'
        Set-ScopedGateSignature -Case $case
        # Act
        $decision = Test-BaselineGoLive @case
        # Assert
        $decision.Admitted | Should -BeFalse
        $decision.Finding -join ' ' | Should -Match 'ExchangeProfileVersionMismatch'
    }

    It 'rejects signatures with no verified authority' {
        # Arrange
        $case = New-ScopedGateCase
        $case.Signature.AuthorizedSigner[0].Authority = 'NotAnApprover'
        # Act
        $decision = Test-BaselineGoLive @case
        # Assert
        $decision.Admitted | Should -BeFalse
        $decision.Finding -join ' ' | Should -Match 'ExchangeSignatureUnverified'
    }

    It 'rejects forged verified flags even when actual evidence bytes and hashes are supplied' {
        # Arrange
        $case = New-ScopedGateCase
        $case.Signature.Value = [Convert]::ToBase64String([byte[]]@(1,2,3))
        $case.Signature.Verified = $true
        # Act
        $decision = Test-BaselineGoLive @case
        # Assert
        $decision.Admitted | Should -BeFalse
        $decision.Finding -join ' ' | Should -Match ExchangeSignatureUnverified
    }

    It 'rejects a different evaluated envelope despite genuine signed bytes and an updated content hash' {
        # Arrange
        $case = New-ScopedGateCase
        $case.Envelope.Evidence[0] = New-BaselineEvidence -ControlId $manifest.ControlId[0] -Source ExchangeOnline -Command ChangedObservation -Value @{ changed = $true }
        $case.Signature.ContentHash = (Get-BaselineEvidenceContentHash -Envelope $case.Envelope).Hash
        # Act
        $decision = Test-BaselineGoLive @case
        # Assert
        $decision.Admitted | Should -BeFalse
        $decision.Finding -join ' ' | Should -Match 'ExchangeSignatureUnverified.*differs from the signed bytes'
    }

    It 'refuses forged verification and ID-only evidence for profile <Profile>' -ForEach @(
        @{ Profile = 'ExchangeOnly' }
        @{ Profile = 'exchangeonly' }
        @{ Profile = 'EXCHANGEONLY' }
    ) {
        $case = New-ScopedGateCase
        $case.ExpectedDeploymentProfile = $Profile
        $case.Envelope.Evidence = @($manifest.ControlId | ForEach-Object { @{ ControlId = $_ } })
        $case.Signature = @{ Model = 'DetachedCms'; Value = 'bogus'; Verified = $true; ContentHash = (Get-BaselineEvidenceContentHash -Envelope $case.Envelope).Hash }
        $decision = Test-BaselineGoLive @case
        $decision.Admitted | Should -BeFalse
        $decision.Finding -join ' ' | Should -Match 'ExchangeSignatureUnverified'
        $decision.Finding -join ' ' | Should -Match 'ExchangeEvidenceUncollected'
    }

    It 'admits the complete scoped gate fixture for <Profile> without certifying external readiness' -ForEach @(
        @{ Profile = 'ExchangeOnly' }
        @{ Profile = 'exchangeonly' }
        @{ Profile = 'EXCHANGEONLY' }
    ) {
        # Arrange
        $case = New-ScopedGateCase
        $case.ExpectedDeploymentProfile = $Profile
        # Act
        $decision = Test-BaselineGoLive @case
        # Assert
        $decision.Admitted | Should -BeTrue -Because ($decision.Finding -join '; ')
        $decision.ExternalReadiness.Status | Should -BeExactly 'Unverified'
        $decision.Finding.Count | Should -Be 0
    }
}