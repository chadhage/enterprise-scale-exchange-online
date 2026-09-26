#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:CommonModule = Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -PassThru

    function Invoke-DetachedCmsSignatureTest {
        param(
            [byte[]]$CanonicalBytes,
            [AllowNull()][object]$Signature,
            [scriptblock]$VerificationScript,
            [AllowNull()][object]$VerificationContext
        )

        & $script:CommonModule {
            param($Bytes, $DetachedSignature, $Verifier, $Context)
            Test-BaselineDetachedCmsSignature -CanonicalBytes $Bytes -Signature $DetachedSignature -VerificationScript $Verifier -VerificationContext $Context
        } $CanonicalBytes $Signature $VerificationScript $VerificationContext
    }

    function Invoke-ExternalEvidenceSignerTest {
        param(
            [object]$SignatureVerification,
            [string]$DeclaredSignerIdentity = 'evidence-approver@contoso.example',
            [string]$DeclaredAuthority = 'ExchangeOnlineChangeApproval',
            [object[]]$AuthorizedSigner,
            [datetimeoffset]$DecisionTimeUtc = [datetimeoffset]'2026-09-19T12:00:00Z'
        )

        & $script:CommonModule {
            param($Verification, $Identity, $Authority, $Authorized, $DecisionTime)
            Test-BaselineExternalEvidenceSigner -SignatureVerification $Verification -DeclaredSignerIdentity $Identity -DeclaredAuthority $Authority -AuthorizedSigner $Authorized -DecisionTimeUtc $DecisionTime
        } $SignatureVerification $DeclaredSignerIdentity $DeclaredAuthority $AuthorizedSigner $DecisionTimeUtc
    }

    function New-SignatureMetadata {
        param([string]$Value = 'AQIDBA==')

        [pscustomobject]@{
            Model = 'DetachedCms'
            Value = $Value
        }
    }

    function New-VerifiedSignature {
        param(
            [bool]$ChainTrusted = $true,
            [string]$RevocationStatus = 'Good',
            [datetimeoffset]$NotBeforeUtc = [datetimeoffset]'2026-01-01T00:00:00Z',
            [datetimeoffset]$NotAfterUtc = [datetimeoffset]'2027-01-01T00:00:00Z',
            [datetimeoffset]$SigningTimeUtc = [datetimeoffset]'2026-09-19T11:59:00Z'
        )

        [pscustomobject]@{
            Verified           = $true
            Reason             = 'DetachedCmsSignatureValid'
            SignerSubject      = 'CN=Contoso Evidence Approver'
            SigningTimeUtc     = $SigningTimeUtc
            CertificateNotBeforeUtc = $NotBeforeUtc
            CertificateNotAfterUtc  = $NotAfterUtc
            ChainTrusted       = $ChainTrusted
            RevocationStatus   = $RevocationStatus
        }
    }

    function New-AuthorizedSigner {
        param(
            [string]$Identity = 'evidence-approver@contoso.example',
            [string]$Subject = 'CN=Contoso Evidence Approver',
            [string]$Authority = 'ExchangeOnlineChangeApproval'
        )

        [pscustomobject]@{
            Identity  = $Identity
            Subject   = $Subject
            Authority = $Authority
        }
    }
}

Describe 'EVD-008 detached CMS verification' {
    Context 'Negative: detached signature refusal' {
        It 'refuses unsigned external evidence by name' {
            # Arrange
            $canonicalBytes = [System.Text.Encoding]::UTF8.GetBytes('{"controlId":"EXO-001"}')

            # Act
            $result = Invoke-DetachedCmsSignatureTest -CanonicalBytes $canonicalBytes -Signature $null -VerificationScript { throw 'must not run' }

            # Assert
            $result.Verified | Should -BeFalse
            $result.Reason | Should -BeExactly 'ExternalEvidenceUnsigned'
        }

        It 'refuses malformed detached CMS by name' {
            # Arrange
            $canonicalBytes = [System.Text.Encoding]::UTF8.GetBytes('{"controlId":"EXO-001"}')
            $signature = New-SignatureMetadata -Value 'not base64!'

            # Act
            $result = Invoke-DetachedCmsSignatureTest -CanonicalBytes $canonicalBytes -Signature $signature -VerificationScript { throw 'must not run' }

            # Assert
            $result.Verified | Should -BeFalse
            $result.Reason | Should -BeExactly 'ExternalEvidenceSignatureMalformed'
        }

        It 'refuses a valid detached signature bound to different content by name' {
            # Arrange
            $canonicalBytes = [System.Text.Encoding]::UTF8.GetBytes('{"controlId":"EXO-001"}')
            $signature = New-SignatureMetadata
            $verificationScript = {
                param([byte[]]$ContentBytes, [byte[]]$SignatureBytes)
                [pscustomobject]@{
                    SignatureValid = $true
                    ContentMatched = $false
                }
            }

            # Act
            $result = Invoke-DetachedCmsSignatureTest -CanonicalBytes $canonicalBytes -Signature $signature -VerificationScript $verificationScript

            # Assert
            $result.Verified | Should -BeFalse
            $result.Reason | Should -BeExactly 'ExternalEvidenceWrongContent'
        }
    }

    Context 'Positive: exact canonical bytes are signed' {
        It 'admits one detached CMS signature over the exact canonical bytes' {
            # Arrange
            $canonicalBytes = [System.Text.Encoding]::UTF8.GetBytes('{"controlId":"EXO-001"}')
            $signature = New-SignatureMetadata
            $verificationScript = {
                param([byte[]]$ContentBytes, [byte[]]$SignatureBytes)
                [pscustomobject]@{
                    SignatureValid          = $true
                    ContentMatched          = [System.Text.Encoding]::UTF8.GetString($ContentBytes) -ceq '{"controlId":"EXO-001"}'
                    SignerSubject           = 'CN=Contoso Evidence Approver'
                    SigningTimeUtc          = [datetimeoffset]'2026-09-19T11:59:00Z'
                    CertificateNotBeforeUtc = [datetimeoffset]'2026-01-01T00:00:00Z'
                    CertificateNotAfterUtc  = [datetimeoffset]'2027-01-01T00:00:00Z'
                    ChainTrusted            = $true
                    RevocationStatus        = 'Good'
                }
            }

            # Act
            $result = Invoke-DetachedCmsSignatureTest -CanonicalBytes $canonicalBytes -Signature $signature -VerificationScript $verificationScript

            # Assert
            $result.Verified | Should -BeTrue
            $result.Reason | Should -BeExactly 'DetachedCmsSignatureValid'
            $result.SignerSubject | Should -BeExactly 'CN=Contoso Evidence Approver'
        }

        It 'passes optional verification context to the Common-bound verifier' {
            # Arrange
            $canonicalBytes = [System.Text.Encoding]::UTF8.GetBytes('{"controlId":"EXO-001"}')
            $signature = New-SignatureMetadata
            $sentinel = [datetimeoffset]'2026-09-19T11:58:37Z'
            $verificationScript = {
                param([byte[]]$ContentBytes, [byte[]]$SignatureBytes, $VerificationContext)
                [pscustomobject]@{
                    SignatureValid = $true
                    ContentMatched = $true
                    SigningTimeUtc = $VerificationContext
                }
            }

            # Act
            $result = Invoke-DetachedCmsSignatureTest -CanonicalBytes $canonicalBytes -Signature $signature -VerificationScript $verificationScript -VerificationContext $sentinel

            # Assert
            $result.Verified | Should -BeTrue
            $result.SigningTimeUtc | Should -Be $sentinel
        }
    }
}

Describe 'EVD-008 external-evidence signer authority' {
    Context 'Negative: signer authority, trust, revocation, and time refusal' {
        It 'refuses an untrusted certificate chain by name' {
            # Arrange
            $verification = New-VerifiedSignature -ChainTrusted $false
            $authorizedSigner = @(New-AuthorizedSigner)

            # Act
            $result = Invoke-ExternalEvidenceSignerTest -SignatureVerification $verification -AuthorizedSigner $authorizedSigner

            # Assert
            $result.Authorized | Should -BeFalse
            $result.Reason | Should -BeExactly 'ExternalEvidenceSignerChainUntrusted'
        }

        It 'refuses a signer outside the declared authority by name' {
            # Arrange
            $verification = New-VerifiedSignature
            $authorizedSigner = @(New-AuthorizedSigner -Identity 'other-approver@contoso.example')

            # Act
            $result = Invoke-ExternalEvidenceSignerTest -SignatureVerification $verification -AuthorizedSigner $authorizedSigner

            # Assert
            $result.Authorized | Should -BeFalse
            $result.Reason | Should -BeExactly 'ExternalEvidenceSignerUnauthorized'
        }

        It 'refuses an expired signer certificate by name' {
            # Arrange
            $verification = New-VerifiedSignature -NotAfterUtc ([datetimeoffset]'2026-09-19T11:00:00Z') -SigningTimeUtc ([datetimeoffset]'2026-09-19T10:00:00Z')
            $authorizedSigner = @(New-AuthorizedSigner)

            # Act
            $result = Invoke-ExternalEvidenceSignerTest -SignatureVerification $verification -AuthorizedSigner $authorizedSigner

            # Assert
            $result.Authorized | Should -BeFalse
            $result.Reason | Should -BeExactly 'ExternalEvidenceSignerCertificateExpired'
        }

        It 'refuses a signing time before the certificate validity window by name' {
            # Arrange
            $verification = New-VerifiedSignature -NotBeforeUtc ([datetimeoffset]'2026-09-19T11:00:00Z') -SigningTimeUtc ([datetimeoffset]'2026-09-19T10:00:00Z')
            $authorizedSigner = @(New-AuthorizedSigner)

            # Act
            $result = Invoke-ExternalEvidenceSignerTest -SignatureVerification $verification -AuthorizedSigner $authorizedSigner

            # Assert
            $result.Authorized | Should -BeFalse
            $result.Reason | Should -BeExactly 'ExternalEvidenceSigningTimeInvalid'
        }

        It 'refuses a revoked signer certificate by name' {
            # Arrange
            $verification = New-VerifiedSignature -RevocationStatus 'Revoked'
            $authorizedSigner = @(New-AuthorizedSigner)

            # Act
            $result = Invoke-ExternalEvidenceSignerTest -SignatureVerification $verification -AuthorizedSigner $authorizedSigner

            # Assert
            $result.Authorized | Should -BeFalse
            $result.Reason | Should -BeExactly 'ExternalEvidenceSignerRevoked'
        }

        It 'fails closed when revocation is inconclusive by name' {
            # Arrange
            $verification = New-VerifiedSignature -RevocationStatus 'Unknown'
            $authorizedSigner = @(New-AuthorizedSigner)

            # Act
            $result = Invoke-ExternalEvidenceSignerTest -SignatureVerification $verification -AuthorizedSigner $authorizedSigner

            # Assert
            $result.Authorized | Should -BeFalse
            $result.Reason | Should -BeExactly 'ExternalEvidenceSignerRevocationInconclusive'
        }
    }

    Context 'Positive: the signer is authorized and trustworthy' {
        It 'admits one authorized signer with a trusted current certificate and good revocation status' {
            # Arrange
            $verification = New-VerifiedSignature
            $authorizedSigner = @(New-AuthorizedSigner)

            # Act
            $result = Invoke-ExternalEvidenceSignerTest -SignatureVerification $verification -AuthorizedSigner $authorizedSigner

            # Assert
            $result.Authorized | Should -BeTrue
            $result.Reason | Should -BeExactly 'ExternalEvidenceSignerAuthorized'
            $result.Identity | Should -BeExactly 'evidence-approver@contoso.example'
        }
    }
}
