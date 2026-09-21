BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force
}
Describe 'EXR-001 local operational evidence admission' {
    BeforeEach {
        $document = @{ ControlId = 'MON-003'; TenantId = 'offline'; DeploymentProfile = 'ExchangeOnly'; ConfigurationHash = 'a' * 64; ManifestHash = (Get-BaselineExchangeManifest).Hash; GeneratedAtUtc = [datetimeoffset]::UtcNow.ToString('o'); Payload = @{ Complete = $true }; Signature = @{ Model = 'DetachedCms'; Value = 'AA==' } }
        $artifactPath = Join-Path $TestDrive 'operation.json'
        $context = @{ Hash = 'a' * 64; Manifest = Get-BaselineExchangeManifest; Configuration = @{ controls = @{ 'MON-003' = @{ maximumEvidenceAgeHours = 48 } } }; Parameters = @{ MICROSOFT_ENTRA_TENANT_GUID = 'offline'; operationalEvidence = @{ 'MON-003' = @{ path = $artifactPath; signerIdentity = 'offline-owner'; authorizedSigner = @(@{ Identity = 'offline-owner'; Subject = 'CN=Offline'; Authority = 'ExchangeOnlineChangeApproval' }) } } } }
        Mock Test-BaselineDetachedCmsSignature -ModuleName ExchangeOnlineBaseline.Common { @{ Verified = $true } }
        Mock Test-BaselineExternalEvidenceSigner -ModuleName ExchangeOnlineBaseline.Common { @{ Authorized = $true } }
    }
    It 'refuses <Case> without inventing operational Pass' -ForEach @(
        @{ Case = 'missing reference'; Reason = 'ExchangeOperationalEvidenceRequired' }
        @{ Case = 'wrong tenant'; Reason = 'ExchangeOperationalBindingMismatch' }
        @{ Case = 'wrong control'; Reason = 'ExchangeOperationalBindingMismatch' }
        @{ Case = 'historical profile'; Reason = 'ExchangeOperationalBindingMismatch' }
        @{ Case = 'wrong configuration'; Reason = 'ExchangeOperationalBindingMismatch' }
        @{ Case = 'wrong manifest'; Reason = 'ExchangeOperationalBindingMismatch' }
        @{ Case = 'stale artifact'; Reason = 'ExchangeOperationalEvidenceStale' }
        @{ Case = 'signature refused'; Reason = 'ExchangeOperationalSignatureRefused' }
        @{ Case = 'unauthorized signer'; Reason = 'ExchangeOperationalSignerRefused' }
    ) {
        # Arrange
        switch ($Case) {
            'missing reference' { $context.Parameters.operationalEvidence.Clear() }
            'wrong tenant' { $document.TenantId = 'another' }
            'wrong control' { $document.ControlId = 'OPS-001' }
            'historical profile' { $document.DeploymentProfile = 'MicrosoftNative' }
            'wrong configuration' { $document.ConfigurationHash = 'b' * 64 }
            'wrong manifest' { $document.ManifestHash = 'b' * 64 }
            'stale artifact' { $document.GeneratedAtUtc = [datetimeoffset]::UtcNow.AddDays(-10).ToString('o') }
            'signature refused' { Mock Test-BaselineDetachedCmsSignature -ModuleName ExchangeOnlineBaseline.Common { @{ Verified = $false } } }
            'unauthorized signer' { Mock Test-BaselineExternalEvidenceSigner -ModuleName ExchangeOnlineBaseline.Common { @{ Authorized = $false } } }
        }
        $document | ConvertTo-Json -Depth 20 | Set-Content $artifactPath
        # Act
        $invoke = { Read-BaselineExchangeOperationalArtifact -ControlId MON-003 -Context $context }
        # Assert
        $invoke | Should -Throw "*$Reason*"
    }
    It 'returns only a bound payload after signature and signer admission' {
        # Arrange
        $document | ConvertTo-Json -Depth 20 | Set-Content $artifactPath
        # Act
        $payload = Read-BaselineExchangeOperationalArtifact -ControlId MON-003 -Context $context
        # Assert
        $payload.Complete | Should -BeTrue
        $payload.SignatureVerified | Should -BeTrue
        Should -Invoke Test-BaselineDetachedCmsSignature -ModuleName ExchangeOnlineBaseline.Common -Times 1 -Exactly
        Should -Invoke Test-BaselineExternalEvidenceSigner -ModuleName ExchangeOnlineBaseline.Common -Times 1 -Exactly
    }
}