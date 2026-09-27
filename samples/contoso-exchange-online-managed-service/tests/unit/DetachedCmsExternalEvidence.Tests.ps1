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

Describe 'A12-F01 direct contract fixture' {
    Context 'Verification-context handoff and signer certificate boundaries' {
        It 'A12-F01 direct contract 01 preserves the explicit same-instant verification context' {
            # Arrange
            $canonicalBytes = [System.Text.Encoding]::UTF8.GetBytes('{"controlId":"EXO-010-A12"}')
            $signature = New-SignatureMetadata
            $approvalInstant = [datetimeoffset]'2026-09-26T22:36:08.6886336Z'
            $verificationScript = {
                param([byte[]]$ContentBytes, [byte[]]$SignatureBytes, $VerificationContext)
                [pscustomobject]@{
                    SignatureValid = $true
                    ContentMatched = $true
                    SigningTimeUtc = $VerificationContext
                }
            }

            # Act
            $result = Invoke-DetachedCmsSignatureTest -CanonicalBytes $canonicalBytes -Signature $signature -VerificationScript $verificationScript -VerificationContext $approvalInstant

            # Assert
            $result.Verified | Should -BeTrue
            $result.SigningTimeUtc | Should -BeOfType ([datetimeoffset])
            ([datetimeoffset]$result.SigningTimeUtc).UtcTicks | Should -Be $approvalInstant.UtcTicks
        }

        It 'A12-F01 direct contract 02 accepts a decision later than the preserved signing instant' {
            # Arrange
            $approvalInstant = [datetimeoffset]'2026-09-26T22:36:08.6886336Z'
            $decisionInstant = $approvalInstant.AddMinutes(1)
            $verification = New-VerifiedSignature -NotBeforeUtc $approvalInstant.AddDays(-1) -NotAfterUtc $approvalInstant.AddDays(1) -SigningTimeUtc $approvalInstant
            $authorizedSigner = @(New-AuthorizedSigner)

            # Act
            $result = Invoke-ExternalEvidenceSignerTest -SignatureVerification $verification -AuthorizedSigner $authorizedSigner -DecisionTimeUtc $decisionInstant

            # Assert
            $decisionInstant | Should -BeGreaterThan $approvalInstant
            $result.Authorized | Should -BeTrue
            $result.Reason | Should -BeExactly 'ExternalEvidenceSignerAuthorized'
        }

        It 'A12-F01 direct contract 03 refuses a missing explicit verification context' {
            # Arrange
            $canonicalBytes = [System.Text.Encoding]::UTF8.GetBytes('{"controlId":"EXO-010-A12"}')
            $signature = New-SignatureMetadata
            $verificationScript = {
                param([byte[]]$ContentBytes, [byte[]]$SignatureBytes, $VerificationContext)
                if ($null -eq $VerificationContext) {
                    throw 'Verification context is required.'
                }
            }

            # Act
            $result = Invoke-DetachedCmsSignatureTest -CanonicalBytes $canonicalBytes -Signature $signature -VerificationScript $verificationScript -VerificationContext $null

            # Assert
            $result.Verified | Should -BeFalse
            $result.Reason | Should -BeExactly 'ExternalEvidenceSignatureVerificationFailed'
        }

        It 'A12-F01 direct contract 04 refuses signing before the certificate lower bound' {
            # Arrange
            $notBefore = [datetimeoffset]'2026-09-26T22:35:00Z'
            $verification = New-VerifiedSignature -NotBeforeUtc $notBefore -NotAfterUtc $notBefore.AddDays(1) -SigningTimeUtc $notBefore.AddTicks(-1)
            $authorizedSigner = @(New-AuthorizedSigner)

            # Act
            $result = Invoke-ExternalEvidenceSignerTest -SignatureVerification $verification -AuthorizedSigner $authorizedSigner -DecisionTimeUtc $notBefore.AddMinutes(1)

            # Assert
            $result.Authorized | Should -BeFalse
            $result.Reason | Should -BeExactly 'ExternalEvidenceSigningTimeInvalid'
        }

        It 'A12-F01 direct contract 05 refuses signing after the certificate upper bound' {
            # Arrange
            $notAfter = [datetimeoffset]'2026-09-27T22:35:00Z'
            $verification = New-VerifiedSignature -NotBeforeUtc $notAfter.AddDays(-1) -NotAfterUtc $notAfter -SigningTimeUtc $notAfter.AddSeconds(1)
            $authorizedSigner = @(New-AuthorizedSigner)

            # Act
            $result = Invoke-ExternalEvidenceSignerTest -SignatureVerification $verification -AuthorizedSigner $authorizedSigner -DecisionTimeUtc $notAfter.AddMinutes(-1)

            # Assert
            $result.Authorized | Should -BeFalse
            $result.Reason | Should -BeExactly 'ExternalEvidenceSigningTimeInvalid'
        }

        It 'A12-F01 direct contract 06 admits the valid detached handoff and signer path' {
            # Arrange
            $canonicalBytes = [System.Text.Encoding]::UTF8.GetBytes('{"controlId":"EXO-010-A12"}')
            $signature = New-SignatureMetadata
            $approvalInstant = [datetimeoffset]'2026-09-26T22:36:08.6886336Z'
            $verificationScript = {
                param([byte[]]$ContentBytes, [byte[]]$SignatureBytes, $VerificationContext)
                [pscustomobject]@{
                    SignatureValid          = $true
                    ContentMatched          = [System.Text.Encoding]::UTF8.GetString($ContentBytes) -ceq '{"controlId":"EXO-010-A12"}'
                    SignerSubject           = 'CN=Contoso Evidence Approver'
                    SigningTimeUtc          = $VerificationContext
                    CertificateNotBeforeUtc = ([datetimeoffset]$VerificationContext).AddDays(-1)
                    CertificateNotAfterUtc  = ([datetimeoffset]$VerificationContext).AddDays(1)
                    ChainTrusted            = $true
                    RevocationStatus        = 'Good'
                }
            }
            $authorizedSigner = @(New-AuthorizedSigner)

            # Act
            $verification = Invoke-DetachedCmsSignatureTest -CanonicalBytes $canonicalBytes -Signature $signature -VerificationScript $verificationScript -VerificationContext $approvalInstant
            $result = Invoke-ExternalEvidenceSignerTest -SignatureVerification $verification -AuthorizedSigner $authorizedSigner -DecisionTimeUtc $approvalInstant.AddMinutes(1)

            # Assert
            $verification.Verified | Should -BeTrue
            $verification.SigningTimeUtc | Should -Be $approvalInstant
            $result.Authorized | Should -BeTrue
            $result.Reason | Should -BeExactly 'ExternalEvidenceSignerAuthorized'
        }
    }
}
