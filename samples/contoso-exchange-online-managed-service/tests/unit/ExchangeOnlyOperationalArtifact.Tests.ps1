BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $operationalModule = Import-Module (Join-Path $sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force -PassThru
    $key = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Offline operational owner', $key, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $certificate = $request.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(1))
    $rootPath = Join-Path $TestDrive 'operational-root.cer'
    [IO.File]::WriteAllBytes($rootPath, $certificate.RawData)
    function Save-OperationalFixture {
        $document.Remove('Signature')
        $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson -InputObject $document))
        $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($bytes), $true)
        $signer = [Security.Cryptography.Pkcs.CmsSigner]::new($certificate)
        $null = $signer.SignedAttributes.Add([Security.Cryptography.Pkcs.Pkcs9SigningTime]::new([datetime]::UtcNow))
        $cms.ComputeSignature($signer)
        $document.Signature = @{ Model = 'DetachedCms'; Value = [Convert]::ToBase64String($cms.Encode()) }
        $document | ConvertTo-Json -Depth 20 | Set-Content $artifactPath
    }
}
AfterAll {
    $certificate.Dispose()
    $key.Dispose()
}
Describe 'EXR-001 local operational evidence admission' {
    BeforeEach {
        $document = @{ ControlId = 'MON-003'; TenantId = 'offline'; DeploymentProfile = 'ExchangeOnly'; ConfigurationHash = 'a' * 64; ManifestHash = (Get-BaselineExchangeManifest).Hash; GeneratedAtUtc = [datetimeoffset]::UtcNow.ToString('o'); Payload = @{ Complete = $true } }
        $artifactPath = Join-Path $TestDrive 'operation.json'
        $context = @{
            Hash = 'a' * 64
            Manifest = Get-BaselineExchangeManifest
            Configuration = @{ controls = @{ 'MON-003' = @{ maximumEvidenceAgeHours = 48 }; 'OPS-002' = @{ maximumEvidenceAgeDays = 90 } } }
            Parameters = @{
                MICROSOFT_ENTRA_TENANT_GUID = 'offline'
                operationalEvidence = @{
                    'MON-003' = @{
                        path = $artifactPath
                        signerIdentity = 'offline-owner'
                        authorizedSigner = @(@{ Identity = 'offline-owner'; Subject = $certificate.Subject; Thumbprint = $certificate.Thumbprint; Authority = 'ExchangeOnlineChangeApproval' })
                        trustedRoot = @{ path = $rootPath; sha256 = (Get-FileHash $rootPath).Hash }
                    }
                }
            }
        }
    }
    It 'refuses <Case> without inventing operational Pass' -ForEach @(
        @{ Case = 'missing reference'; Reason = 'ExchangeOperationalArtifactMissing' }
        @{ Case = 'wrong tenant'; Reason = 'ExchangeOperationalArtifactTenantMismatch' }
        @{ Case = 'wrong control'; Reason = 'ExchangeOperationalArtifactControlMismatch' }
        @{ Case = 'historical profile'; Reason = 'ExchangeOperationalArtifactProfileMismatch' }
        @{ Case = 'wrong configuration'; Reason = 'ExchangeOperationalArtifactConfigurationMismatch' }
        @{ Case = 'wrong manifest'; Reason = 'ExchangeOperationalArtifactManifestMismatch' }
        @{ Case = 'stale artifact'; Reason = 'ExchangeOperationalArtifactStale' }
        @{ Case = 'signature refused'; Reason = 'ExchangeSignatureUnverified' }
        @{ Case = 'unauthorized signer'; Reason = 'ExternalEvidenceSignerUnauthorized' }
        @{ Case = 'configured age exceeded'; Reason = 'ExchangeOperationalArtifactStale' }
        @{ Case = 'invalid configured age'; Reason = 'ExchangeOperationalArtifactAgeInvalid' }
    ) {
        switch ($Case) {
            'missing reference' { $context.Parameters.operationalEvidence.Clear() }
            'wrong tenant' { $document.TenantId = 'another' }
            'wrong control' { $document.ControlId = 'OPS-001' }
            'historical profile' { $document.DeploymentProfile = 'Native' }
            'wrong configuration' { $document.ConfigurationHash = 'b' * 64 }
            'wrong manifest' { $document.ManifestHash = 'b' * 64 }
            'stale artifact' { $document.GeneratedAtUtc = [datetimeoffset]::UtcNow.AddDays(-10).ToString('o') }
            'unauthorized signer' { $context.Parameters.operationalEvidence['MON-003'].authorizedSigner[0].Thumbprint = '0' * 40 }
            'configured age exceeded' {
                $context.Configuration.controls['MON-003'].maximumEvidenceAgeHours = 1
                $document.GeneratedAtUtc = [datetimeoffset]::UtcNow.AddHours(-2).ToString('o')
            }
            'invalid configured age' { $context.Configuration.controls['MON-003'].maximumEvidenceAgeHours = 0 }
        }
        Save-OperationalFixture
        if ($Case -eq 'signature refused') {
            $document.Payload.Complete = $false
            $document | ConvertTo-Json -Depth 20 | Set-Content $artifactPath
        }
        { & $operationalModule { param($Context) Read-BaselineExchangeOperationalArtifact -ControlId MON-003 -Context $Context } $context } |
            Should -Throw "*$Reason*"
    }
    It 'returns the bound document and payload only after real CMS and pinned-root admission' {
        Save-OperationalFixture
        $result = & $operationalModule { param($Context) Read-BaselineExchangeOperationalArtifact -ControlId MON-003 -Context $Context } $context
        $result.Payload.Complete | Should -BeTrue
        $result.SignatureVerified | Should -BeTrue
        $result.SignerThumbprint | Should -BeExactly $certificate.Thumbprint
    }
    It 'uses the configured day-based age for incident exercise evidence' {
        $document.ControlId = 'OPS-002'
        $document.GeneratedAtUtc = [datetimeoffset]::UtcNow.AddDays(-5).ToString('o')
        $context.Parameters.operationalEvidence['OPS-002'] = $context.Parameters.operationalEvidence['MON-003']
        Save-OperationalFixture
        $result = & $operationalModule { param($Context) Read-BaselineExchangeOperationalArtifact -ControlId OPS-002 -Context $Context } $context
        $result.Payload.Complete | Should -BeTrue
        $result.SignatureVerified | Should -BeTrue
    }
}
