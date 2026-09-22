#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:FixtureRoot = Join-Path $script:SampleRoot 'tests' 'fixtures' 'tst006'
    $script:FixturePath = Join-Path $script:FixtureRoot 'compliant-microsoft-native.json'
    $script:SchemaPath = Join-Path $script:FixtureRoot 'compliant-offline-fixture.schema.json'
    $script:CatalogPath = Join-Path $script:SampleRoot 'docs' 'CONTROL-CATALOG.md'
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:ModulePath -Force -DisableNameChecking -ErrorAction Stop

    function Copy-Tst006Node {
        param([Parameter(Mandatory)][object]$Node)
        return ($Node | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30)
    }

    function New-Tst006ContractFixture {
        $tenantId = '00000000-0000-4000-8000-000000000006'
        $profile = 'MicrosoftNative'
        $configurationHash = 'sha256:' + ('6' * 64)
        $collectedAtUtc = '2026-09-19T12:00:00Z'
        $registry = @(Get-BaselineControlRegistry -Profile Historical)[0]

        $fixture = [pscustomobject][ordered]@{
            SchemaVersion = '1.0.0'
            FixtureId = 'tst006-microsoft-native-v1'
            Sanitized = $true
            Offline = [pscustomobject][ordered]@{
                TenantConnectionAllowed = $false
                NetworkAllowed = $false
                CredentialsRequired = $false
                ApplyAllowed = $false
            }
            Binding = [pscustomobject][ordered]@{
                TenantId = $tenantId
                OrganizationName = 'tst006.invalid'
                DeploymentProfile = $profile
                ConfigurationHash = $configurationHash
                CollectedAtUtc = $collectedAtUtc
            }
            Entitlement = [pscustomobject][ordered]@{
                Determined = $true
                FullyEntitled = $true
                EnabledServicePlan = @('EXCHANGE_S_ENTERPRISE', 'ATP_ENTERPRISE', 'SAFEDOCS', 'M365_ADVANCED_AUDITING', 'E3_COMPLIANCE')
            }
            Controls = @($registry | ForEach-Object {
                    $applicable = 'Native' -cin @($_.ApplicableProfile)
                    [pscustomobject][ordered]@{
                        ControlId = $_.ControlId
                        ApplicableProfile = @($_.ApplicableProfile)
                        Applicability = [pscustomobject][ordered]@{
                            Determined = $true
                            Applicable = $applicable
                            Reason = if ($applicable) { 'IncludedByMicrosoftNativeProfile' } else { 'ExcludedFromMicrosoftNativeProfile' }
                        }
                        Entitlement = [pscustomobject][ordered]@{
                            Determined = $true
                            Entitled = $true
                            Prerequisite = @($_.Prerequisite)
                        }
                        Collector = $_.Collector
                        Evaluator = $_.Evaluator
                        Evidence = [pscustomobject][ordered]@{
                            ControlId = $_.ControlId
                            TenantId = $tenantId
                            DeploymentProfile = $profile
                            ConfigurationHash = $configurationHash
                            CollectedAtUtc = $collectedAtUtc
                            Collected = $true
                            Source = 'SyntheticOffline'
                            Command = $_.Collector
                            Value = [pscustomobject]@{ Compliant = $true }
                        }
                        Result = [pscustomobject][ordered]@{
                            ControlId = $_.ControlId
                            Status = if ($applicable) { 'Pass' } else { 'NotApplicable' }
                            EvidenceControlId = $_.ControlId
                        }
                    }
                })
            Signature = [pscustomobject][ordered]@{
                Model = 'DetachedCms'
                MediaType = 'application/pkcs7-signature'
                Canonicalization = 'TST006-Canonical-JSON-SHA256-v1'
                PayloadHash = ''
                Value = ''
                Certificate = ''
                SignerSubject = 'CN=TST-006 Offline Fixture'
            }
        }

        Set-Tst006Signature -Fixture $fixture
        return $fixture
    }

    function Get-Tst006CanonicalBytes {
        param([Parameter(Mandatory)][object]$Fixture)

        $payload = [ordered]@{}
        foreach ($name in @('SchemaVersion', 'FixtureId', 'Sanitized', 'Offline', 'Binding', 'Entitlement', 'Controls')) {
            if ($Fixture.PSObject.Properties.Name -ccontains $name) { $payload[$name] = $Fixture.$name }
        }
        $canonical = ConvertTo-CanonicalJson -InputObject $payload
        return [System.Text.Encoding]::UTF8.GetBytes($canonical)
    }

    function Set-Tst006Signature {
        param([Parameter(Mandatory)][object]$Fixture)

        $bytes = Get-Tst006CanonicalBytes -Fixture $Fixture
        $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        try {
            $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=TST-006 Offline Fixture',
                $rsa,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $certificate = $request.CreateSelfSigned(
                [datetimeoffset]::Parse('2026-09-18T00:00:00Z'),
                [datetimeoffset]::Parse('2036-09-19T00:00:00Z'))
            $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new(
                [System.Security.Cryptography.Pkcs.ContentInfo]::new($bytes), $true)
            $cms.ComputeSignature([System.Security.Cryptography.Pkcs.CmsSigner]::new($certificate))
            $Fixture.Signature.PayloadHash = 'sha256:' + [Convert]::ToHexString($hash).ToLowerInvariant()
            $Fixture.Signature.Value = [Convert]::ToBase64String($cms.Encode())
            $Fixture.Signature.Certificate = [Convert]::ToBase64String($certificate.Export(
                    [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        }
        finally {
            $rsa.Dispose()
        }
    }

    function Test-Tst006FixtureContract {
        param([Parameter(Mandatory)][object]$Fixture)

        $violation = [System.Collections.Generic.List[string]]::new()
        $requiredTopLevel = @('SchemaVersion', 'FixtureId', 'Sanitized', 'Offline', 'Binding', 'Entitlement', 'Controls', 'Signature')
        $schemaValid = $false
        try {
            $schemaValid = Test-Json -Json ($Fixture | ConvertTo-Json -Depth 30) -SchemaFile $script:SchemaPath -ErrorAction Stop
        }
        catch {
            $schemaValid = $false
        }
        if (-not $schemaValid -or
            @($requiredTopLevel | Where-Object { $Fixture.PSObject.Properties.Name -cnotcontains $_ }).Count -gt 0 -or
            [string]$Fixture.SchemaVersion -cne '1.0.0') {
            $violation.Add('FixtureSchemaViolation')
        }

        if ($Fixture.Sanitized -ne $true) { $violation.Add('FixtureNotSanitized') }
        if ($null -eq $Fixture.Offline -or
            $Fixture.Offline.TenantConnectionAllowed -ne $false -or
            $Fixture.Offline.NetworkAllowed -ne $false -or
            $Fixture.Offline.CredentialsRequired -ne $false -or
            $Fixture.Offline.ApplyAllowed -ne $false) {
            $violation.Add('OfflineBoundaryViolation')
        }

        $sanitizedText = @($Fixture.Binding, $Fixture.Entitlement, $Fixture.Controls) | ConvertTo-Json -Depth 30 -Compress
        if ($sanitizedText -match '(?i)contoso\.(?:com|net|org)|onmicrosoft\.com|client.?secret|password|credential|bearer\s+|eyJ[A-Za-z0-9_-]{10,}\.') {
            $violation.Add('SensitiveMaterialDetected')
        }

        if ([string]$Fixture.Binding.DeploymentProfile -cne 'MicrosoftNative') { $violation.Add('ProfileBindingInvalid') }
        if ([string]$Fixture.Binding.TenantId -cne '00000000-0000-4000-8000-000000000006') { $violation.Add('TenantBindingInvalid') }
        if ([string]$Fixture.Binding.ConfigurationHash -cnotmatch '^sha256:[0-9a-f]{64}$') { $violation.Add('ConfigurationHashInvalid') }
        if ([string]$Fixture.Binding.CollectedAtUtc -cnotmatch '^2026-09-19T12:00:00Z$') { $violation.Add('CollectionTimeInvalid') }

        $registry = @(Get-BaselineControlRegistry -Profile Historical)[0]
        $expectedId = @($registry | ForEach-Object ControlId)
        $actualId = @($Fixture.Controls | ForEach-Object ControlId)
        foreach ($id in $expectedId | Where-Object { $_ -cnotin $actualId }) { $violation.Add("CatalogControlMissing:$id") }
        foreach ($id in $actualId | Where-Object { $_ -cnotin $expectedId } | Select-Object -Unique) { $violation.Add("CatalogControlUnknown:$id") }
        foreach ($group in @($actualId | Group-Object -CaseSensitive | Where-Object Count -GT 1)) {
            $violation.Add("CatalogControlDuplicated:$($group.Name)")
        }

        foreach ($row in @($Fixture.Controls | Where-Object { $_.ControlId -cin $expectedId })) {
            $definition = @($registry | Where-Object ControlId -CEQ $row.ControlId)[0]
            $applicable = 'Native' -cin @($definition.ApplicableProfile)
            if ($row.Applicability.Determined -ne $true) { $violation.Add("ApplicabilityUnresolved:$($row.ControlId)") }
            if ($row.Applicability.Applicable -ne $applicable) { $violation.Add("ApplicabilityMismatch:$($row.ControlId)") }
            if ($row.Entitlement.Determined -ne $true -or ($applicable -and $row.Entitlement.Entitled -ne $true)) {
                $violation.Add("ApplicableControlNotEntitled:$($row.ControlId)")
            }

            $evidenceBinding = @(
                [string]$row.Evidence.ControlId -ceq [string]$row.ControlId
                [string]$row.Evidence.TenantId -ceq [string]$Fixture.Binding.TenantId
                [string]$row.Evidence.DeploymentProfile -ceq [string]$Fixture.Binding.DeploymentProfile
                [string]$row.Evidence.ConfigurationHash -ceq [string]$Fixture.Binding.ConfigurationHash
                [string]$row.Evidence.CollectedAtUtc -ceq [string]$Fixture.Binding.CollectedAtUtc
                $row.Evidence.Collected -eq $true
            )
            if ($false -cin $evidenceBinding) { $violation.Add("EvidenceBindingMismatch:$($row.ControlId)") }
            if ([string]$row.Collector -cne [string]$definition.Collector -or
                [string]$row.Evaluator -cne [string]$definition.Evaluator -or
                [string]$row.Evidence.Command -cne [string]$definition.Collector) {
                $violation.Add("CollectorBindingMismatch:$($row.ControlId)")
            }

            $expectedStatus = if ($applicable) { 'Pass' } else { 'NotApplicable' }
            if ([string]$row.Result.ControlId -cne [string]$row.ControlId -or
                [string]$row.Result.EvidenceControlId -cne [string]$row.ControlId -or
                [string]$row.Result.Status -cne $expectedStatus) {
                $violation.Add("ResultStatusInvalid:$($row.ControlId)")
            }
        }

        if ([string]$Fixture.Signature.Model -cne 'DetachedCms' -or
            [string]$Fixture.Signature.MediaType -cne 'application/pkcs7-signature' -or
            [string]$Fixture.Signature.Canonicalization -cne 'TST006-Canonical-JSON-SHA256-v1' -or
            [string]::IsNullOrWhiteSpace([string]$Fixture.Signature.Value) -or
            [string]::IsNullOrWhiteSpace([string]$Fixture.Signature.Certificate)) {
            $violation.Add('DetachedCmsInputMissing')
        }
        else {
            try {
                $bytes = Get-Tst006CanonicalBytes -Fixture $Fixture
                $hash = 'sha256:' + [Convert]::ToHexString(
                    [System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
                if ([string]$Fixture.Signature.PayloadHash -cne $hash) { throw 'Payload hash mismatch.' }
                $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                    [Convert]::FromBase64String([string]$Fixture.Signature.Certificate))
                try {
                    if ([string]$certificate.Subject -cne [string]$Fixture.Signature.SignerSubject) { throw 'Signer subject mismatch.' }
                    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new(
                        [System.Security.Cryptography.Pkcs.ContentInfo]::new($bytes), $true)
                    $cms.Decode([Convert]::FromBase64String([string]$Fixture.Signature.Value))
                    $certificates = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
                    [void]$certificates.Add($certificate)
                    $cms.CheckSignature($certificates, $true)
                }
                finally {
                    $certificate.Dispose()
                }
            }
            catch {
                $violation.Add('DetachedCmsSignatureInvalid')
            }
        }

        return [pscustomobject]@{
            Valid = ($violation.Count -eq 0)
            SchemaValid = $schemaValid
            Violations = @($violation)
        }
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'TST-006 complete sanitized compliant offline fixture' {
    Context 'Negative: the fixture is closed, sanitized and offline-only' {
        It 'refuses a fixture that does not conform to its published schema' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            $fixture.PSObject.Properties.Remove('SchemaVersion')

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'FixtureSchemaViolation'
        }

        It 'refuses a fixture that is not explicitly sanitized' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            $fixture.Sanitized = $false

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'FixtureNotSanitized'
        }

        It 'refuses a fixture that permits tenant, network, credential or apply activity' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            $fixture.Offline.NetworkAllowed = $true

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'OfflineBoundaryViolation'
        }

        It 'refuses planted credential or production-domain material' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            $fixture.Binding.OrganizationName = 'admin@contoso.com; clientSecret=not-safe'

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'SensitiveMaterialDetected'
        }
    }

    Context 'Negative: one deterministic run binding governs the fixture' {
        It 'refuses a profile other than the shipped Microsoft-native profile' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            $fixture.Binding.DeploymentProfile = 'ThirdPartyGateway'

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'ProfileBindingInvalid'
        }

        It 'refuses a tenant identifier other than the declared synthetic tenant' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            $fixture.Binding.TenantId = '11111111-1111-4111-8111-111111111111'

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'TenantBindingInvalid'
        }

        It 'refuses a malformed canonical configuration hash' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            $fixture.Binding.ConfigurationHash = 'sha256:not-a-digest'

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'ConfigurationHashInvalid'
        }

        It 'refuses a collection instant that is not the fixed round-trip UTC instant' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            $fixture.Binding.CollectedAtUtc = 'tomorrow'

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'CollectionTimeInvalid'
        }
    }

    Context 'Negative: the complete shipped catalog is resolved exactly once' {
        It 'refuses a missing catalog control' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            $fixture.Controls = @($fixture.Controls | Where-Object ControlId -CNE 'GOV-007')

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'CatalogControlMissing:GOV-007'
        }

        It 'refuses a duplicated catalog control' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            $fixture.Controls = @($fixture.Controls) + @(Copy-Tst006Node $fixture.Controls[0])

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'CatalogControlDuplicated:EXO-001'
        }

        It 'refuses a control outside the shipped catalog' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            $unknown = Copy-Tst006Node $fixture.Controls[0]
            $unknown.ControlId = 'EXO-999'
            $fixture.Controls = @($fixture.Controls) + @($unknown)

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'CatalogControlUnknown:EXO-999'
        }

        It 'refuses a control whose applicability was not resolved' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            $fixture.Controls[0].Applicability.Determined = $false

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'ApplicabilityUnresolved:EXO-001'
        }

        It 'refuses a profile-excluded control projected as applicable' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            ($fixture.Controls | Where-Object ControlId -CEQ 'PP-001').Applicability.Applicable = $true

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'ApplicabilityMismatch:PP-001'
        }

        It 'refuses an applicable control without a resolved positive entitlement' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            ($fixture.Controls | Where-Object ControlId -CEQ 'MDO-005').Entitlement.Entitled = $false

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'ApplicableControlNotEntitled:MDO-005'
        }
    }

    Context 'Negative: evidence, result and signature are internally bound' {
        It 'refuses evidence bound to another tenant, profile, hash or collection time' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            ($fixture.Controls | Where-Object ControlId -CEQ 'AUTH-001').Evidence.TenantId = '11111111-1111-4111-8111-111111111111'

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'EvidenceBindingMismatch:AUTH-001'
        }

        It 'refuses evidence not attributed to the registered collector' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            ($fixture.Controls | Where-Object ControlId -CEQ 'MON-001').Evidence.Command = 'Get-SomethingElse'

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'CollectorBindingMismatch:MON-001'
        }

        It 'refuses a result status inconsistent with resolved applicability' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            ($fixture.Controls | Where-Object ControlId -CEQ 'EXO-001').Result.Status = 'NotApplicable'

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'ResultStatusInvalid:EXO-001'
        }

        It 'refuses absent detached-CMS verification inputs' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            $fixture.Signature.Value = ''

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'DetachedCmsInputMissing'
        }

        It 'refuses a detached signature that does not verify the canonical payload hash' {
            # Arrange
            $fixture = New-Tst006ContractFixture
            $fixture.Signature.PayloadHash = 'sha256:' + ('b' * 64)

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Violations | Should -Contain 'DetachedCmsSignatureInvalid'
        }
    }

    Context 'Positive: one complete signed Microsoft-native fixture' {
        It 'is schema-valid, sanitized, fully resolved and bound across the complete shipped catalog' {
            # Arrange
            $fixture = Get-Content -LiteralPath $script:FixturePath -Raw |
                ConvertFrom-Json -Depth 30 -DateKind String

            # Act
            $actual = Test-Tst006FixtureContract -Fixture $fixture

            # Assert
            $actual.Valid | Should -BeTrue -Because (@($actual.Violations) -join '; ')
            $actual.SchemaValid | Should -BeTrue
            @($fixture.Controls).Count | Should -Be 43
            @($fixture.Controls | Where-Object { $_.Result.Status -ceq 'Pass' }).Count | Should -Be 37
            @($fixture.Controls | Where-Object { $_.Result.Status -ceq 'NotApplicable' }).Count | Should -Be 6
            @($fixture.Controls | Where-Object { $_.Evidence.ControlId -cne $_.ControlId }).Count | Should -Be 0
            @($fixture.Controls | Where-Object { $_.Result.EvidenceControlId -cne $_.ControlId }).Count | Should -Be 0
        }
    }
}