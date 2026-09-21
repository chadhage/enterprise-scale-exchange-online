BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force -DisableNameChecking
    . (Join-Path $sampleRoot 'tests/helpers/ExchangeGovernanceRawFixture.ps1')
    $parameters = Get-Content (Join-Path $sampleRoot 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
    $parameters.entitlement.verified = $true
    $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
    $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE','THREAT_INTELLIGENCE')
    $governanceFixture = New-ExchangeGovernanceRawFixture $parameters
    $parameters.governanceEvidence = @{ recipientFlows = $governanceFixture.RecipientFlows }
    $parameterPath = Join-Path $TestDrive 'parameters.json'
    $parameters | ConvertTo-Json -Depth 40 | Set-Content $parameterPath
    $configuration = $governanceFixture.Configuration
    $configuration.controls['EXO-009'].ewsEnabled = $true
    $configuration.controls['EXO-009'].ewsAllowList = @('OfflineArchiver/1.0')
    $configuration.controls['EXO-009'].ewsAllowedAppIds = @('11111111-2222-3333-4444-555555555555')
    $configuration.controls['EXO-009'].ewsException = @{ owner = 'Offline owner'; approval = 'OFFLINE-006'; expiresAt = [datetimeoffset]::UtcNow.AddDays(1).ToString('o'); cloud = 'Worldwide'; rollback = 'DisableEws'; clientImpact = 'Offline fixture only' }
    $configurationPath = Join-Path $TestDrive 'configuration.json'
    $configuration | ConvertTo-Json -Depth 60 | Set-Content $configurationPath
    $context = Get-BaselineExchangeContext -ConfigurationPath $configurationPath -ParameterPath $parameterPath
    $operationalKey = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=EXR006 operational fixture', $operationalKey, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $operationalCertificate = $request.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(1))
    $rootPath = Join-Path $TestDrive 'operational-root.cer'
    [IO.File]::WriteAllBytes($rootPath, $operationalCertificate.RawData)
    $generated = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o')
    $payloads = @{
        'MON-003' = @{ Complete = $true; Refused = @(); GeneratedAtUtc = $generated; ScheduledCollection = $true; CollectionFrequencyHours = 1; RetentionDays = 3650; DriftDetected = $false; Findings = @() }
        'OPS-001' = @{ Complete = $true; Refused = @(); ChangeId = 'OFFLINE-006'; GeneratedAtUtc = $generated }
        'OPS-002' = @{ ExerciseId = 'OFFLINE-006'; CompletedAtUtc = $generated; ExerciseTypes = @($context.Configuration.controls['OPS-002'].exerciseTypes); Owners = @($context.Configuration.controls['OPS-002'].owners); Actions = @(@{ ActionId = 'OFFLINE-A1'; Owner = $parameters.SECURITY_OPERATIONS_MAILBOX; Status = 'Closed'; TrackingReference = 'OFFLINE-006' }) }
    }
    foreach ($phase in @('Preview','Pilot','Approval','Rollback','PostChange')) { $payloads['OPS-001'][$phase] = @{ Completed = $true; ChangeId = 'OFFLINE-006' } }
    $parameters.operationalEvidence = @{}
    foreach ($controlId in $payloads.Keys) {
        $document = @{ ControlId = $controlId; TenantId = $parameters.MICROSOFT_ENTRA_TENANT_GUID; DeploymentProfile = 'ExchangeOnly'; ConfigurationHash = $context.Hash; ManifestHash = $context.Manifest.Hash; GeneratedAtUtc = $generated; Payload = $payloads[$controlId] }
        $content = [Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson -InputObject $document))
        $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($content), $true)
        $cms.ComputeSignature([Security.Cryptography.Pkcs.CmsSigner]::new($operationalCertificate))
        $document.Signature = @{ Model = 'DetachedCms'; Value = [Convert]::ToBase64String($cms.Encode()) }
        $artifactPath = Join-Path $TestDrive "$controlId.json"
        $document | ConvertTo-Json -Depth 50 | Set-Content $artifactPath
        $parameters.operationalEvidence[$controlId] = @{ path = $artifactPath; signerIdentity = 'offline-owner'; authorizedSigner = @(@{ Identity = 'offline-owner'; Subject = $operationalCertificate.Subject; Authority = 'ExchangeOnlineChangeApproval' }); trustedRoot = @{ path = $rootPath; sha256 = (Get-FileHash $rootPath).Hash } }
    }
    $operationalCertificate.Dispose()
    $operationalKey.Dispose()
    $parameters | ConvertTo-Json -Depth 60 | Set-Content $parameterPath
    $raw = $governanceFixture.Raw
    $raw['Get-OrganizationConfig'].Items[0].EwsEnabled = $true
    $raw['Get-OrganizationConfig'].Items[0].EwsAllowList = @('OfflineArchiver/1.0')
    $raw['Get-OrganizationConfig'].Items[0].EwsAllowedAppIDs = @('11111111-2222-3333-4444-555555555555')
    $rawPath = Join-Path $TestDrive 'raw.json'
    $raw | ConvertTo-Json -Depth 60 | Set-Content $rawPath
    $collectedPath = Join-Path $TestDrive 'collected'
    $collectCalls = Join-Path $TestDrive 'collect.calls'
    $collectOutput = & pwsh -NoProfile -NonInteractive -File (Join-Path $sampleRoot 'tests/helpers/ExchangeLiveRawHarness.ps1') (Join-Path $sampleRoot 'scripts/Test-ExchangeOnlineBaseline.ps1') $parameterPath $collectedPath $rawPath $collectCalls $configurationPath 2>&1 | Out-String
    $frozenPath = Join-Path $collectedPath 'exchange-online-evidence.json'
    $original = Get-Content -LiteralPath $frozenPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
    if ($LASTEXITCODE -ne 0) { throw "Collection fixture failed: $collectOutput $($original.Check | Where-Object Status -NotIn @('Pass','ApprovedException') | ConvertTo-Json -Depth 10 -Compress)" }
    function New-SigningCase {
        param([string]$Name)
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $directory
        $envelope = $original | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable -DateKind String
        switch ($Name) {
            'stale evidence' { $envelope.CollectedAtUtc = [datetimeoffset]::UtcNow.AddHours(-2).ToString('o') }
            'future evidence' { $envelope.CollectedAtUtc = [datetimeoffset]::UtcNow.AddHours(2).ToString('o') }
            'invalid timestamp' { $envelope.CollectedAtUtc = 'not-a-time' }
            'wrong tenant' { $envelope.TenantId = 'other-tenant' }
            'wrong configuration' { $envelope.ConfigurationHash = 'b' * 64 }
            'wrong manifest' { $envelope.ManifestHash = 'b' * 64 }
            'wrong profile' { $envelope.DeploymentProfile = 'Native' }
            'missing check' { $envelope.Check = @($envelope.Check | Where-Object ControlId -NE 'EXO-001') }
            'missing evidence' { $envelope.Evidence = @($envelope.Evidence | Where-Object ControlId -NE 'EXO-001') }
            'uncollected evidence' { $envelope.Evidence[0].Collected = $false }
            'missing evidence value' { $envelope.Evidence[0].Value = $null }
            'missing payload property' { $envelope.Evidence[0].Remove('Value') }
            'missing collection flag' { $envelope.Evidence[0].Remove('Collected') }
            'stale record' { $envelope.Evidence[0].CollectedAtUtc = [datetimeoffset]::UtcNow.AddHours(-2).ToString('o') }
            'future record' { $envelope.Evidence[0].CollectedAtUtc = [datetimeoffset]::UtcNow.AddHours(2).ToString('o') }
            'invalid record time' { $envelope.Evidence[0].CollectedAtUtc = 'not-a-time' }
            'missing record time' { $envelope.Evidence[0].Remove('CollectedAtUtc') }
            'duplicate evidence' { $envelope.Evidence += $envelope.Evidence[0] }
            'unknown evidence' { $envelope.Evidence[0].ControlId = 'GOV-002' }
            'unknown status' { $envelope.Check[0].Status = 'LooksFine' }
            'NotEntitled' { $envelope.Check[0].Status = 'NotEntitled' }
            'collection error' { $envelope.Check[0].Status = 'Error' }
            'failed control' { $envelope.Check[0].Status = 'Fail' }
            'fabricated readiness' { $envelope.ExternalReadiness.Status = 'Pass' }
            'empty checks' { $envelope.Check = @() }
        }
        $evidencePath = Join-Path $directory 'frozen.json'
        $envelope | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $evidencePath -Encoding utf8
        if ($Name -eq 'signed immutable run') { Copy-Item -LiteralPath $frozenPath -Destination $evidencePath -Force }
        $caseParameterPath = $parameterPath
        if ($Name -eq 'changed entitlement') {
            $changedParameters = $parameters | ConvertTo-Json -Depth 60 | ConvertFrom-Json -AsHashtable
            $changedParameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE')
            $caseParameterPath = Join-Path $directory 'parameters.json'
            $changedParameters | ConvertTo-Json -Depth 60 | Set-Content $caseParameterPath
        }
        $case = @{
            Case = $Name; EvidencePath = $evidencePath; SignaturePath = Join-Path $directory 'frozen.p7s'
            ParameterPath = $caseParameterPath; ConfigurationPath = $configurationPath; CallPath = Join-Path $directory 'calls.txt'
            ExpectedEvidenceHash = (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash
            ExpectedConfigurationHash = $context.Hash
        }
        $casePath = Join-Path $directory 'case.json'
        $case | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $casePath
        @{ Path = $casePath; Data = $case }
    }
}

Describe 'EXR-006 public frozen evidence refusals' {
    It 'refuses <Name> with exit <Code> and <Reason>' -ForEach @(
        @{ Name = 'tampered bytes'; Code = 14; Reason = 'EvidenceHashMismatch' }
        @{ Name = 'tampered bytes updated hash'; Code = 14; Reason = 'SignatureUnverified' }
        @{ Name = 'missing signing time'; Code = 14; Reason = 'SignatureUnverified' }
        @{ Name = 'future signing time'; Code = 14; Reason = 'SignatureUnverified' }
        @{ Name = 'wrong subject'; Code = 14; Reason = 'SignerUnauthorized' }
        @{ Name = 'malformed signature'; Code = 14; Reason = 'SignatureUnverified' }
        @{ Name = 'missing signature file'; Code = 14; Reason = 'SignatureUnverified' }
        @{ Name = 'multiple signers'; Code = 14; Reason = 'SignatureUnverified' }
        @{ Name = 'untrusted signer'; Code = 14; Reason = 'ChainUntrusted' }
        @{ Name = 'unauthorized signer'; Code = 14; Reason = 'SignerUnauthorized' }
        @{ Name = 'wrong authority'; Code = 14; Reason = 'SignerUnauthorized' }
        @{ Name = 'wrong certificate pin'; Code = 14; Reason = 'SignerUnauthorized' }
        @{ Name = 'duplicate authority'; Code = 14; Reason = 'SignerUnauthorized' }
        @{ Name = 'expired certificate'; Code = 14; Reason = 'ChainUntrusted|CertificateExpired' }
        @{ Name = 'future certificate'; Code = 14; Reason = 'ChainUntrusted|CertificateNotYetValid' }
        @{ Name = 'stale evidence'; Code = 13; Reason = 'GoLiveEvidenceStale' }
        @{ Name = 'future evidence'; Code = 13; Reason = 'GoLiveEvidenceFromFuture' }
        @{ Name = 'invalid timestamp'; Code = 13; Reason = 'GoLiveCollectionTimeUnreadable' }
        @{ Name = 'wrong tenant'; Code = 13; Reason = 'GoLiveTenantMismatch' }
        @{ Name = 'wrong configuration'; Code = 13; Reason = 'GoLiveConfigurationHashMismatch' }
        @{ Name = 'wrong manifest'; Code = 13; Reason = 'ExchangeManifestMismatch' }
        @{ Name = 'wrong profile'; Code = 13; Reason = 'GoLiveProfileMismatch' }
        @{ Name = 'missing check'; Code = 13; Reason = 'CatalogControlMissing' }
        @{ Name = 'missing evidence'; Code = 13; Reason = 'EvidenceControlMissing' }
        @{ Name = 'uncollected evidence'; Code = 13; Reason = 'ExchangeEvidenceUncollected' }
        @{ Name = 'missing evidence value'; Code = 13; Reason = 'ExchangeEvidenceValueMissing' }
        @{ Name = 'missing payload property'; Code = 13; Reason = 'ExchangeEvidenceValueMissing' }
        @{ Name = 'missing collection flag'; Code = 13; Reason = 'ExchangeEvidenceUncollected' }
        @{ Name = 'stale record'; Code = 13; Reason = 'ExchangeEvidenceRecordStale' }
        @{ Name = 'future record'; Code = 13; Reason = 'ExchangeEvidenceRecordFromFuture' }
        @{ Name = 'invalid record time'; Code = 13; Reason = 'ExchangeEvidenceRecordTimeUnreadable' }
        @{ Name = 'missing record time'; Code = 13; Reason = 'ExchangeEvidenceRecordTimeUnreadable' }
        @{ Name = 'changed entitlement'; Code = 13; Reason = 'ExchangeEntitlementChanged' }
        @{ Name = 'malformed evidence'; Code = 12; Reason = 'EvidenceUnreadable' }
        @{ Name = 'null evidence'; Code = 12; Reason = 'EvidenceUnreadable' }
        @{ Name = 'array evidence'; Code = 12; Reason = 'EvidenceUnreadable' }
        @{ Name = 'scalar evidence'; Code = 12; Reason = 'EvidenceUnreadable' }
        @{ Name = 'malformed authority'; Code = 14; Reason = 'SignerUnauthorized' }
        @{ Name = 'empty authority'; Code = 14; Reason = 'ExternalEvidenceSignerUnauthorized' }
        @{ Name = 'null authority'; Code = 14; Reason = 'ExternalEvidenceSignerUnauthorized' }
        @{ Name = 'scalar authority'; Code = 14; Reason = 'ExternalEvidenceSignerUnauthorized' }
        @{ Name = 'object authority'; Code = 14; Reason = 'ExternalEvidenceSignerUnauthorized' }
        @{ Name = 'null authority entry'; Code = 14; Reason = 'ExternalEvidenceSignerUnauthorized' }
        @{ Name = 'scalar authority entry'; Code = 14; Reason = 'ExternalEvidenceSignerUnauthorized' }
        @{ Name = 'mixed authority entries'; Code = 14; Reason = 'ExternalEvidenceSignerUnauthorized' }
        @{ Name = 'unsupported risk acceptance'; Code = 10; Reason = 'ExchangeGoLiveInputsRequired' }
        @{ Name = 'duplicate evidence'; Code = 13; Reason = 'EvidenceControlDuplicated' }
        @{ Name = 'unknown evidence'; Code = 13; Reason = 'EvidenceControlUnknown' }
        @{ Name = 'unknown status'; Code = 13; Reason = 'UnknownControlStatus' }
        @{ Name = 'NotEntitled'; Code = 13; Reason = 'ControlNotPassed' }
        @{ Name = 'collection error'; Code = 12; Reason = 'ControlNotPassed' }
        @{ Name = 'failed control'; Code = 13; Reason = 'ControlNotPassed' }
        @{ Name = 'fabricated readiness'; Code = 13; Reason = 'ExchangeDispositionMismatch' }
        @{ Name = 'empty checks'; Code = 12; Reason = 'GoLiveCheckRequired' }
        @{ Name = 'missing authority'; Code = 10; Reason = 'ExchangeGoLiveInputsRequired' }
        @{ Name = 'missing hash'; Code = 10; Reason = 'ExchangeGoLiveInputsRequired' }
        @{ Name = 'zero age'; Code = 10; Reason = 'MaximumEvidenceAgeNotPositive' }
        @{ Name = 'wrong expected hash'; Code = 14; Reason = 'EvidenceHashMismatch' }
        @{ Name = 'wrong expected configuration'; Code = 10; Reason = 'ExpectedConfigurationHashMismatch' }
        @{ Name = 'missing evidence file'; Code = 12; Reason = 'EvidenceUnreadable' }
        @{ Name = 'sign without private key'; Code = 14; Reason = 'SigningCertificateRequired' }
        @{ Name = 'sign hash mismatch'; Code = 14; Reason = 'EvidenceHashMismatch' }
        @{ Name = 'sign overwrite'; Code = 14; Reason = 'SignatureAlreadyExists' }
    ) {
        # Arrange
        $case = New-SigningCase -Name $Name
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File (Join-Path $sampleRoot 'tests/helpers/ExchangeEvidenceSigningHarness.ps1') $sampleRoot $case.Path 2>&1 | Out-String
        $actualExit = $LASTEXITCODE
        # Assert
        $actualExit | Should -Be $Code -Because $output
        $output | Should -Match $Reason
        Test-Path -LiteralPath $case.Data.CallPath | Should -BeFalse
    }

    It 'refuses caller-forged verified flags at the exported scoped decision API' {
        # Arrange
        $signature = @{ Model = 'DetachedCms'; Value = 'offline-gate-fixture'; Verified = $true; ContentHash = (Get-BaselineEvidenceContentHash -Envelope $original).Hash }
        # Act
        $decision = Test-BaselineGoLive -Envelope $original -CatalogPath 'ignored' -ExpectedTenantId $original.TenantId -ExpectedDeploymentProfile ExchangeOnly -ExpectedConfigurationHash $context.Hash -MaximumEvidenceAge ([timespan]::FromHours(1)) -Signature $signature
        # Assert
        $decision.Admitted | Should -BeFalse
        $decision.Finding -join ' ' | Should -Match ExchangeSignatureUnverified
    }

    It 'does not report an approved deviation as a fully passing Exchange gate' {
        # Arrange
        $case = New-SigningCase -Name 'retained approved deviation'
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File (Join-Path $sampleRoot 'tests/helpers/ExchangeEvidenceSigningHarness.ps1') $sampleRoot $case.Path 2>&1 | Out-String
        # Assert
        ($output | ConvertFrom-Json).Result.Status | Should -BeExactly ApprovedException -Because $output
    }

    It 'signs and verifies one immutable public collection without certifying external readiness or promoting deviations' {
        # Arrange
        $case = New-SigningCase -Name 'signed immutable run'
        (Get-Item -LiteralPath $case.Data.EvidencePath).IsReadOnly = $true
        $before = (Get-FileHash -LiteralPath $case.Data.EvidencePath).Hash
        # Act
        $output = & pwsh -NoProfile -NonInteractive -File (Join-Path $sampleRoot 'tests/helpers/ExchangeEvidenceSigningHarness.ps1') $sampleRoot $case.Path 2>&1 | Out-String
        $actualExit = $LASTEXITCODE
        # Assert
        $actualExit | Should -Be 0 -Because $output
        $decision = $output | ConvertFrom-Json
        $decision.Admitted | Should -BeTrue
        $decision.Result.Status | Should -BeExactly ApprovedException
        $decision.ExternalReadiness.Status | Should -BeExactly Unverified
        $decision.EvidenceHash | Should -Be $before
        (Get-FileHash -LiteralPath $case.Data.EvidencePath).Hash | Should -Be $before
        (Get-FileHash -LiteralPath $frozenPath).Hash | Should -Be $before
        Test-Path -LiteralPath $case.Data.CallPath | Should -BeFalse
        (Get-Content $collectCalls -Raw) | Should -Not -Match 'EXCLUDED|Graph|IPPSSession|DlpCompliance|Get-Label'
        @($original.Check | Where-Object Status -EQ ApprovedException).Count | Should -BeGreaterThan 0
        @($decision.Exception | Where-Object Status -EQ ApprovedException).Count | Should -BeGreaterThan 0
    }
}

Describe 'EXR-006 documented public workflow' {
    It 'provides parsable PowerShell for all five ordered workflow stages' {
        # Arrange
        $path = Join-Path $sampleRoot 'docs/EXCHANGE-GO-LIVE.md'
        $text = Get-Content $path -Raw
        # Act
        $blocks = [regex]::Matches($text, '(?s)```powershell\r?\n(.*?)```')
        $errors = @(foreach ($block in $blocks) {
            $tokens = $null
            $parseErrors = $null
            $null = [Management.Automation.Language.Parser]::ParseInput($block.Groups[1].Value, [ref]$tokens, [ref]$parseErrors)
            $parseErrors
        })
        # Assert
        $blocks.Count | Should -Be 5
        $errors.Count | Should -Be 0
        $text | Should -Match '## 1\. Resolve.*(?s:.*)## 2\. Collect.*(?s:.*)## 3\. Freeze.*(?s:.*)## 4\. Sign.*(?s:.*)## 5\. Verify'
    }

    It 'does not leave scoped signing inputs or distinct exits undocumented' {
        # Arrange
        $path = Join-Path $sampleRoot 'docs/EXCHANGE-GO-LIVE.md'
        # Act
        $text = if (Test-Path $path) { Get-Content $path -Raw } else { '' }
        # Assert
        foreach ($required in @('-SignEvidence','-GoLive','ExpectedEvidenceHash','ExpectedConfigurationHash','AuthorizedSignerPath','EvidenceSignerIdentity','SigningCertificate','Copy-Item','Get-FileHash','ApprovedException','ExternalReadiness','10','11','12','13','14','15')) {
            $text | Should -Match ([regex]::Escape($required))
        }
    }

    It 'does not retain the incomplete subject-only scoped go-live prescription' {
        # Arrange
        $path = Join-Path $sampleRoot 'docs/EXCHANGE-ONLY.md'
        # Act
        $text = Get-Content $path -Raw
        # Assert
        $text | Should -Not -Match 'Go-live uses `-GoLive -EvidencePath -EvidenceSignaturePath -EvidenceSignerSubject -MaximumEvidenceAge`'
        $text | Should -Match 'EXCHANGE-GO-LIVE.md'
    }
}