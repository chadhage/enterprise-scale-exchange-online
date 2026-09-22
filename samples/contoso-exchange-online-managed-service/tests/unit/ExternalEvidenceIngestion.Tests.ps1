#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:TenantId = '00000000-1111-2222-3333-444444444444'
    $script:ConfigurationHash = 'a3f1c9d2b4e6708192a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f809'
    $script:AsOf = [datetime]::new(2026, 9, 19, 12, 0, 0, [System.DateTimeKind]::Utc)

    function Get-FixturePayloadHash {
        param([Parameter(Mandatory)][object]$Payload)

        $canonical = ConvertTo-CanonicalJson -InputObject $Payload
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($canonical)
        return [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    }

    function New-ExternalEvidenceFixture {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{},
            [string[]]$Omit = @()
        )

        $payload = [ordered]@{
            domainType = 'Authoritative'
            identity   = 'contoso.example'
        }
        $member = [ordered]@{
            SchemaVersion     = '1.0.0'
            EvidenceId        = '11111111-2222-4333-8444-555555555555'
            TenantId          = $script:TenantId
            DeploymentProfile = 'MicrosoftNative'
            ConfigurationHash = $script:ConfigurationHash
            ControlId         = 'EXO-001'
            Collector         = [ordered]@{ Identity = 'Get-AcceptedDomainEvidence'; Version = '1.0.0' }
            GeneratedAtUtc    = $script:AsOf.AddMinutes(-5).ToString('o')
            PayloadHash       = Get-FixturePayloadHash -Payload $payload
            Payload           = $payload
            Signature         = [ordered]@{
                Model     = 'DetachedCms'
                MediaType = 'application/pkcs7-signature'
                Value     = 'MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExDzANBglghkgBZQMEAgEFADA='
            }
        }

        foreach ($name in $Omit) { $member.Remove($name) }
        foreach ($name in $Override.Keys) { $member[$name] = $Override[$name] }
        return [pscustomobject]$member
    }

    function New-RegistryFixture {
        return @(
            [pscustomobject]@{
                ControlId = 'EXO-001'
                Collector = 'Get-AcceptedDomainEvidence'
            }
        )
    }

    function New-AcceptedSeamResult {
        return [pscustomobject]@{ Satisfied = $true; Reason = @() }
    }

    function New-RefusedSeamResult {
        param([Parameter(Mandatory)][string]$Reason)
        return [pscustomobject]@{ Satisfied = $false; Reason = @($Reason) }
    }

    function Invoke-ExternalEvidenceImport {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Evidence,
            [object[]]$Registry = (New-RegistryFixture),
            [string[]]$ReplayEvidenceId = @(),
            [object[]]$AdmittedEvidence = @(),
            [scriptblock]$DocumentValidator = { param($Document) New-AcceptedSeamResult },
            [scriptblock]$SignatureValidator = { param($Document, $CanonicalBytes) New-AcceptedSeamResult },
            [scriptblock]$SignerValidator = { param($Document, $SignatureResult) New-AcceptedSeamResult },
            [scriptblock]$CmsVerificationScript,
            [object[]]$AuthorizedSigner = @(),
            [string]$DeclaredSignerIdentity = ''
        )

        $argument = @{
            Evidence               = $Evidence
            TenantId               = $script:TenantId
            DeploymentProfile      = 'MicrosoftNative'
            ConfigurationHash      = $script:ConfigurationHash
            Registry               = $Registry
            MaximumAge             = [timespan]::FromHours(24)
            AsOf                   = $script:AsOf
            ReplayEvidenceId       = $ReplayEvidenceId
            AdmittedEvidence       = $AdmittedEvidence
            DocumentValidator      = $DocumentValidator
            SignatureValidator     = $SignatureValidator
            SignerValidator        = $SignerValidator
            AuthorizedSigner       = $AuthorizedSigner
            DeclaredSignerIdentity = $DeclaredSignerIdentity
        }
        if ($PSBoundParameters.ContainsKey('CmsVerificationScript')) {
            $argument.CmsVerificationScript = $CmsVerificationScript
        }

        return Import-BaselineExternalEvidence @argument
    }

    function Get-RefusalReason {
        param([Parameter(Mandatory)][object]$Decision)
        return @($Decision.Refused | ForEach-Object { @($_.Reason) })
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EVD-008 external evidence payload integrity' {
    Context 'Negative: no payload can be sealed' {
        It 'refuses a missing payload for its named reason' {
            # Arrange
            $payload = $null

            # Act
            $result = { Get-BaselineExternalEvidencePayloadHash -Payload $payload }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ExternalEvidencePayloadRequired*'
        }
    }

    Context 'Positive: one canonical payload has one stable identity' {
        It 'returns the lowercase SHA-256 hash of the canonical payload bytes' {
            # Arrange
            $payload = [ordered]@{ zeta = @('second', 'first'); alpha = [ordered]@{ enabled = $true } }
            $expected = Get-FixturePayloadHash -Payload $payload

            # Act
            $actual = Get-BaselineExternalEvidencePayloadHash -Payload $payload

            # Assert
            $actual | Should -BeExactly $expected
        }
    }
}

Describe 'EVD-008 external evidence ingestion' {
    Context 'Negative: missing and partial documents' {
        It 'refuses a missing evidence collection for its named reason' {
            # Arrange
            $evidence = @()

            # Act
            $result = { Invoke-ExternalEvidenceImport -Evidence $evidence }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ExternalEvidenceRequired*'
        }

        It 'refuses an incomplete document with the schema seam reason' {
            # Arrange
            $evidence = New-ExternalEvidenceFixture -Omit @('Payload')
            $validator = { param($Document) New-RefusedSeamResult -Reason 'ExternalEvidenceMemberRequired: payload' }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence -DocumentValidator $validator

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain 'ExternalEvidenceMemberRequired: payload'
        }

        It 'refuses an unsigned document with the detached-CMS seam reason' {
            # Arrange
            $evidence = New-ExternalEvidenceFixture -Omit @('Signature')
            $validator = { param($Document, $CanonicalBytes) New-RefusedSeamResult -Reason 'ExternalEvidenceUnsigned: detached CMS signature is required.' }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence -SignatureValidator $validator

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain 'ExternalEvidenceUnsigned: detached CMS signature is required.'
        }
    }

    Context 'Negative: run and registry binding' {
        It 'refuses evidence raised for another tenant' {
            # Arrange
            $evidence = New-ExternalEvidenceFixture -Override @{ tenantId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain "ExternalEvidenceTenantMismatch: evidence tenant 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' does not match run tenant '$($script:TenantId)'."
        }

        It 'refuses evidence raised for another deployment profile' {
            # Arrange
            $evidence = New-ExternalEvidenceFixture -Override @{ deploymentProfile = 'ThirdPartyGateway' }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain "ExternalEvidenceProfileMismatch: evidence profile 'ThirdPartyGateway' does not match run profile 'MicrosoftNative'."
        }

        It 'refuses evidence raised for another configuration hash' {
            # Arrange
            $otherHash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            $evidence = New-ExternalEvidenceFixture -Override @{ configurationHash = $otherHash }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain "ExternalEvidenceConfigurationHashMismatch: evidence hash '$otherHash' does not match run hash '$($script:ConfigurationHash)'."
        }

        It 'refuses evidence naming a control outside the current registry' {
            # Arrange
            $evidence = New-ExternalEvidenceFixture -Override @{ controlId = 'EXO-999' }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain "ExternalEvidenceUnknownControl: 'EXO-999' is not present in the current control registry."
        }

        It 'refuses evidence naming a collector other than the registered collector' {
            # Arrange
            $evidence = New-ExternalEvidenceFixture -Override @{ Collector = [ordered]@{ Identity = 'Get-OtherEvidence'; Version = '1.0.0' } }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain "ExternalEvidenceCollectorMismatch: control 'EXO-001' requires 'Get-AcceptedDomainEvidence', not 'Get-OtherEvidence'."
        }
    }

    Context 'Negative: time and payload integrity' {
        It 'refuses stale evidence at the exclusive maximum-age boundary' {
            # Arrange
            $generated = $script:AsOf.AddHours(-24).ToString('o')
            $evidence = New-ExternalEvidenceFixture -Override @{ generatedAtUtc = $generated }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain "ExternalEvidenceStale: evidence generated at '$generated' is not newer than the 1.00:00:00 maximum age at '$($script:AsOf.ToString('o'))'."
        }

        It 'refuses a generation time that cannot be parsed' {
            # Arrange
            $evidence = New-ExternalEvidenceFixture -Override @{ generatedAtUtc = 'not-a-time' }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain "ExternalEvidenceGenerationTimeInvalid: 'not-a-time' is not a round-trip UTC timestamp."
        }

        It 'refuses a document generated in the future' {
            # Arrange
            $generated = $script:AsOf.AddSeconds(1).ToString('o')
            $evidence = New-ExternalEvidenceFixture -Override @{ generatedAtUtc = $generated }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain "ExternalEvidenceFromFuture: evidence generated at '$generated' is later than '$($script:AsOf.ToString('o'))'."
        }

        It 'refuses a payload changed after its hash was declared' {
            # Arrange
            $evidence = New-ExternalEvidenceFixture
            $evidence.payload.identity = 'tampered.example'

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain 'ExternalEvidencePayloadHashMismatch: declared payload hash does not match the canonical payload bytes.'
        }
    }

    Context 'Negative: uniqueness and replay prevention' {
        It 'refuses two documents carrying one evidence identifier' {
            # Arrange
            $first = New-ExternalEvidenceFixture
            $second = New-ExternalEvidenceFixture -Override @{ ControlId = 'EXO-002'; Collector = [ordered]@{ Identity = 'Get-SmtpAuthenticationEvidence'; Version = '1.0.0' } }
            $registry = @(
                New-RegistryFixture
                [pscustomobject]@{ ControlId = 'EXO-002'; Collector = 'Get-SmtpAuthenticationEvidence' }
            )

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence @($first, $second) -Registry $registry

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain "ExternalEvidenceIdDuplicated: evidence ID '$($first.evidenceId)' occurs more than once in this import."
        }

        It 'refuses two documents claiming one control in one import' {
            # Arrange
            $first = New-ExternalEvidenceFixture
            $second = New-ExternalEvidenceFixture -Override @{ evidenceId = '99999999-2222-4333-8444-555555555555' }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence @($first, $second)

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain "ExternalEvidenceControlDuplicated: control 'EXO-001' occurs more than once in this import."
        }

        It 'refuses an evidence identifier already recorded by the replay store' {
            # Arrange
            $evidence = New-ExternalEvidenceFixture

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence -ReplayEvidenceId @($evidence.evidenceId)

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain "ExternalEvidenceReplayed: evidence ID '$($evidence.evidenceId)' was already consumed."
        }

        It 'refuses a control already admitted for this run' {
            # Arrange
            $evidence = New-ExternalEvidenceFixture
            $admitted = [pscustomobject]@{ EvidenceId = '77777777-2222-4333-8444-555555555555'; ControlId = 'EXO-001' }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence -AdmittedEvidence @($admitted)

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain "ExternalEvidenceControlAlreadyAdmitted: control 'EXO-001' already has external evidence in this run."
        }
    }

    Context 'Negative: specialist seam refusals and aggregation' {
        It 'carries a detached-CMS refusal without replacing its named reason' {
            # Arrange
            $evidence = New-ExternalEvidenceFixture
            $validator = { param($Document, $CanonicalBytes) New-RefusedSeamResult -Reason 'ExternalEvidenceSignatureTampered: detached CMS does not verify over the canonical document bytes.' }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence -SignatureValidator $validator

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain 'ExternalEvidenceSignatureTampered: detached CMS does not verify over the canonical document bytes.'
        }

        It 'carries a signer-authority refusal without replacing its named reason' {
            # Arrange
            $evidence = New-ExternalEvidenceFixture
            $validator = { param($Document, $SignatureResult) New-RefusedSeamResult -Reason 'ExternalEvidenceSignerUnauthorized: signer lacks the declared external-evidence authority.' }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence -SignerValidator $validator

            # Assert
            Get-RefusalReason -Decision $decision | Should -Contain 'ExternalEvidenceSignerUnauthorized: signer lacks the declared external-evidence authority.'
        }

        It 'aggregates every independent binding refusal on one document' {
            # Arrange
            $payload = [ordered]@{ changed = $true }
            $evidence = New-ExternalEvidenceFixture -Override @{
                tenantId          = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
                deploymentProfile = 'ThirdPartyGateway'
                configurationHash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
                generatedAtUtc    = $script:AsOf.AddHours(-25).ToString('o')
                payload            = $payload
            }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence

            # Assert
            $reason = Get-RefusalReason -Decision $decision
            @($reason | Where-Object { $_ -like 'ExternalEvidenceTenantMismatch:*' }).Count | Should -Be 1
            @($reason | Where-Object { $_ -like 'ExternalEvidenceProfileMismatch:*' }).Count | Should -Be 1
            @($reason | Where-Object { $_ -like 'ExternalEvidenceConfigurationHashMismatch:*' }).Count | Should -Be 1
            @($reason | Where-Object { $_ -like 'ExternalEvidenceStale:*' }).Count | Should -Be 1
            @($reason | Where-Object { $_ -like 'ExternalEvidencePayloadHashMismatch:*' }).Count | Should -Be 1
        }
    }

    Context 'Positive: one complete signed document is admitted' {
        It 'admits one fresh, unique, intact and correctly bound document as an immutable record' {
            # Arrange
            $script:CmsVerificationCall = 0
            $evidence = New-ExternalEvidenceFixture
            $cmsVerifier = {
                param([byte[]]$CanonicalBytes, [byte[]]$SignatureBytes)
                $script:CmsVerificationCall++
                [pscustomobject]@{
                    ContentMatched          = $CanonicalBytes.Count -gt 0
                    SignatureValid          = $SignatureBytes.Count -gt 0
                    SignerSubject           = 'CN=Contoso Evidence Approver'
                    SigningTimeUtc          = [datetimeoffset]'2026-09-19T11:59:00Z'
                    CertificateNotBeforeUtc = [datetimeoffset]'2026-01-01T00:00:00Z'
                    CertificateNotAfterUtc  = [datetimeoffset]'2027-01-01T00:00:00Z'
                    ChainTrusted            = $true
                    RevocationStatus        = 'Good'
                }
            }
            $authorizedSigner = [pscustomobject]@{
                Identity  = 'evidence-approver@contoso.example'
                Subject   = 'CN=Contoso Evidence Approver'
                Authority = 'ExchangeOnlineChangeApproval'
            }

            # Act
            $decision = Invoke-ExternalEvidenceImport -Evidence $evidence `
                -DocumentValidator $null `
                -SignatureValidator $null `
                -SignerValidator $null `
                -CmsVerificationScript $cmsVerifier `
                -AuthorizedSigner @($authorizedSigner) `
                -DeclaredSignerIdentity $authorizedSigner.Identity

            # Assert
            ('satisfied={0};admitted={1};refused={2};cms={3}' -f
                $decision.Satisfied,
                @($decision.Admitted).Count,
                @($decision.Refused).Count,
                $script:CmsVerificationCall) | Should -BeExactly 'satisfied=True;admitted=1;refused=0;cms=1'
            { $decision.Admitted[0].Evidence.payload.identity = 'changed.example' } | Should -Throw
        }
    }
}