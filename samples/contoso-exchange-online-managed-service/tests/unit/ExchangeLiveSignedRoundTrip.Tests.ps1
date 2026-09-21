BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $command = Join-Path $sampleRoot 'scripts/Test-ExchangeOnlineBaseline.ps1'
    $harness = Join-Path $sampleRoot 'tests/helpers/ExchangeLiveRawHarness.ps1'
    . (Join-Path $sampleRoot 'tests/helpers/ExchangeGovernanceRawFixture.ps1')
    Import-Module (Join-Path $sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force
    $parameters = Get-Content (Join-Path $sampleRoot 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
    $parameters.entitlement.verified = $true
    $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
    $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE','THREAT_INTELLIGENCE')
    $governanceFixture = New-ExchangeGovernanceRawFixture $parameters
    $parameters.governanceEvidence = @{ recipientFlows = $governanceFixture.RecipientFlows }
    $governanceConfigurationPath = Join-Path $TestDrive 'governance.configuration.json'
    $governanceFixture.Configuration | ConvertTo-Json -Depth 50 | Set-Content $governanceConfigurationPath
    $parameterPath = Join-Path $TestDrive 'binding.parameters.json'
    $parameters | ConvertTo-Json -Depth 40 | Set-Content $parameterPath
    $context = Get-BaselineExchangeContext -ConfigurationPath $governanceConfigurationPath -ParameterPath $parameterPath
    $key = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=EXR005 Offline $([guid]::NewGuid())", $key, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
    $certificate = $request.CreateSelfSigned([datetimeoffset]::UtcNow.AddMinutes(-5), [datetimeoffset]::UtcNow.AddHours(1))
    $rootPath = Join-Path $TestDrive 'offline-root.cer'
    $rootBytes = $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    [IO.File]::WriteAllBytes($rootPath, $rootBytes)
    $rootHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($rootBytes))

    function Write-ExchangeLiveSignedArtifact {
        param($Document, $Path)
        $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson -InputObject $Document))
        $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($bytes), $true)
        $signer = [Security.Cryptography.Pkcs.CmsSigner]::new($certificate)
        $cms.ComputeSignature($signer)
        $Document.Signature = @{ Model = 'DetachedCms'; Value = [Convert]::ToBase64String($cms.Encode()) }
        $Document | ConvertTo-Json -Depth 40 | Set-Content $Path
    }
}

AfterAll {
    if ($certificate) { $certificate.Dispose() }
    if ($key) { $key.Dispose() }
}

Describe 'EXR-005 default public signed operational roundtrip' {
    It 'disables certificate downloads before local operational chain verification' {
        $definition = & (Get-Module ExchangeOnlineBaseline.Common) {
            (Get-Command Read-BaselineExchangeOperationalArtifact).Definition
        }
        $definition | Should -Match '(?s)RevocationMode\s*=\s*\[System.Security.Cryptography.X509Certificates.X509RevocationMode\]::Offline.*DisableCertificateDownloads\s*=\s*\$true.*\$chain\.Build\('
    }

    It 'evaluates all 25 controls from raw Exchange and real signed local artifacts: <Case>' -ForEach @(
        @{ Case = 'valid'; Expected = 'Pass' }
        @{ Case = 'tampered'; Expected = 'Error' }
        @{ Case = 'wrong binding'; Expected = 'Error' }
        @{ Case = 'stale'; Expected = 'Error' }
        @{ Case = 'unauthorized signer'; Expected = 'Error' }
        @{ Case = 'wrong root pin'; Expected = 'Error' }
        @{ Case = 'untrusted signer'; Expected = 'Error' }
        @{ Case = 'missing phase'; Expected = 'Fail' }
    ) {
        $localParameters = $parameters | ConvertTo-Json -Depth 40 | ConvertFrom-Json -AsHashtable
        $localParameters.operationalEvidence = @{}
        $generated = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o')
        $changeId = 'EXR005-OFFLINE-CHANGE'
        $payloads = @{
            'MON-003' = @{ Complete = $true; Refused = @(); ScheduledCollection = $true; CollectionFrequencyHours = 24; RetentionDays = 90; GeneratedAtUtc = $generated; DriftDetected = $false; Findings = @() }
            'OPS-001' = @{ Complete = $true; Refused = @(); ChangeId = $changeId; GeneratedAtUtc = $generated }
            'OPS-002' = @{ ExerciseId = 'EXR005-OFFLINE-EXERCISE'; CompletedAtUtc = $generated; ExerciseTypes = @('ExchangeIncidentResponse'); Owners = @($parameters.SECURITY_OPERATIONS_MAILBOX); Actions = @(@{ ActionId = 'OFFLINE-ACTION-1'; Owner = $parameters.SECURITY_OPERATIONS_MAILBOX; TrackingReference = 'local:EXR005-OFFLINE-ACTION-1' }) }
        }
        foreach ($phase in @('Preview','Pilot','Approval','Rollback','PostChange')) { $payloads['OPS-001'][$phase] = @{ Completed = $true; ChangeId = $changeId } }
        foreach ($controlId in $payloads.Keys) {
            $path = Join-Path $TestDrive "$Case-$controlId.json"
            $document = @{ ControlId = $controlId; TenantId = $parameters.MICROSOFT_ENTRA_TENANT_GUID; DeploymentProfile = 'ExchangeOnly'; ConfigurationHash = $context.Hash; ManifestHash = $context.Manifest.Hash; GeneratedAtUtc = $generated; Payload = $payloads[$controlId] }
            if ($controlId -eq 'OPS-001') {
                switch ($Case) {
                    'wrong binding' { $document.ConfigurationHash = '0' * 64 }
                    'stale' { $document.GeneratedAtUtc = [datetimeoffset]::UtcNow.AddDays(-10).ToString('o') }
                    'missing phase' { $document.Payload.Remove('Approval') }
                }
            }
            Write-ExchangeLiveSignedArtifact -Document $document -Path $path
            if ($Case -eq 'tampered' -and $controlId -eq 'OPS-001') {
                $document.Payload.ChangeId = 'tampered-after-signing'
                $document | ConvertTo-Json -Depth 40 | Set-Content $path
            }
            $localParameters.operationalEvidence[$controlId] = @{ path = $path; signerIdentity = 'offline-owner'; trustedRoot = @{ path = $rootPath; sha256 = $rootHash }; authorizedSigner = @(@{ Identity = 'offline-owner'; Subject = $certificate.Subject; Authority = 'ExchangeOnlineChangeApproval' }) }
        }
        if ($Case -eq 'unauthorized signer') { $localParameters.operationalEvidence['OPS-001'].authorizedSigner[0].Subject = 'CN=Other' }
        if ($Case -eq 'wrong root pin') { $localParameters.operationalEvidence['OPS-001'].trustedRoot.sha256 = '0' * 64 }
        if ($Case -eq 'untrusted signer') { $localParameters.operationalEvidence['OPS-001'].Remove('trustedRoot') }
        $localPath = Join-Path $TestDrive "$Case.parameters.json"
        $localParameters | ConvertTo-Json -Depth 40 | Set-Content $localPath
        $raw = (New-ExchangeGovernanceRawFixture $localParameters).Raw
        $rawPath = Join-Path $TestDrive "$Case.raw.json"
        $raw | ConvertTo-Json -Depth 40 | Set-Content $rawPath
        $outputPath = Join-Path $TestDrive "$Case-output"
        $callPath = Join-Path $TestDrive "$Case.calls"
        $output = & pwsh -NoProfile -NonInteractive -File $harness $command $localPath $outputPath $rawPath $callPath $governanceConfigurationPath 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        $envelope = Get-Content (Join-Path $outputPath 'exchange-online-evidence.json') -Raw | ConvertFrom-Json
        @($envelope.Check).Count | Should -Be 25
        @($envelope.Check.ControlId | Sort-Object -Unique).Count | Should -Be 25
        $changed = $envelope.Check | Where-Object ControlId -EQ 'OPS-001'
        $changed.Status | Should -BeExactly $Expected -Because ($changed.Reason + $output)
        $other = @($envelope.Check | Where-Object { $_.ControlId -ne 'OPS-001' -and $_.Status -ne 'Pass' })
        $other.Count | Should -Be 0 -Because (($other | ConvertTo-Json -Depth 10) + $output)
        if ($Case -eq 'valid') {
            $exitCode | Should -Be 0 -Because $output
            @($envelope.Check | Where-Object Status -EQ Pass).Count | Should -Be 25
            @($envelope.Evidence | Where-Object Failed).Count | Should -Be 0
            foreach ($controlId in @('MON-003','OPS-001')) { ($envelope.Evidence | Where-Object ControlId -EQ $controlId).Value.SignatureVerified | Should -BeTrue }
        }
        else { $exitCode | Should -Not -Be 0 }
        $calls = Get-Content $callPath
        @($calls | Where-Object { $_ -eq 'Connect-ExchangeOnline' }).Count | Should -Be 1
        $calls -join ' ' | Should -Not -Match 'EXCLUDED:|Connect-MgGraph|Connect-IPPSSession'
        $envelope.ExternalReadiness.Status | Should -BeExactly Unverified
    }
}