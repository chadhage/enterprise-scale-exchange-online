# Frozen Exchange Evidence Gate

EXR-006 supplies an Exchange-only collect, freeze, sign and verify workflow. Run the commands below in PowerShell 7.5 or later from `samples/contoso-exchange-online-managed-service`. This is not an apply command or tenant-wide launch certification. Never sign a freshly recollected replacement for the file the reviewer inspected.

## External Prerequisites

- A change-controlled parameter file with the current tenant- and recipient-bound licensing handoff from RAID-D02, plus the three required signed local operational artifacts described in [EXCHANGE-ONLY.md](EXCHANGE-ONLY.md).
- An approved Exchange configuration and independently retained resolved configuration SHA256 digest. The tenant is taken from the approved parameter file, not from the evidence being admitted.
- RAID-D05 supplies the authorized signer identity, public authority metadata, signing certificate/private-key access, trusted enterprise certificate chain and usable cached revocation evidence. This tool provisions none of these. Do not put keys, passwords or tenant credentials in the repository.
- Authority metadata and the retained evidence/configuration hashes must come through the independently approved change channel and be protected from modification by the evidence producer. An attacker who can replace the authority file and approved inputs controls the approval policy.

The authority file is a JSON array with exactly one matching authorized entry. It is public metadata, not a private key:

```json
[
  {
    "Identity": "approved-change-authority-identity",
    "Subject": "CN=Externally provisioned Exchange approver",
    "Authority": "ExchangeOnlineChangeApproval",
    "Thumbprint": "EXTERNALLY_APPROVED_CERTIFICATE_THUMBPRINT"
  }
]
```

Use the certificate's actual `Thumbprint` (case-insensitive), exact subject and externally approved identity. A subject string alone does not authorize a signer. `-EvidenceSignerSubject` remains an optional additional subject constraint, never a replacement for `-EvidenceSignerIdentity` and `-AuthorizedSignerPath`.

## 1. Resolve The Approved Inputs

These paths and metadata values are examples to replace with externally approved local inputs. The shipped sample licensing handoff is deliberately unverified and cannot complete this procedure.

```powershell
$ErrorActionPreference = 'Stop'
$parameterPath = 'C:\ApprovedExchange\parameters.json'
$configurationPath = 'C:\ApprovedExchange\exchange-only.json'
$authorizedSignerPath = 'C:\ApprovedExchange\authorized-signers.json'
$signerIdentity = 'approved-change-authority-identity'
Import-Module ./scripts/ExchangeOnlineBaseline.Common.psd1 -Force -DisableNameChecking
$context = Get-BaselineExchangeContext -ParameterPath $parameterPath -ConfigurationPath $configurationPath
$configurationHash = $context.Hash
$context.Parameters.MICROSOFT_ENTRA_TENANT_GUID
$configurationHash
```

Compare the printed tenant and configuration hash with the approved change record before continuing. The configuration digest is over resolved canonical configuration, not the raw configuration file. Retain it independently; do not derive expected bindings from the incoming evidence file during verification.

## 2. Collect Once

```powershell
$runDirectory = Join-Path 'C:\ExchangeEvidence' ([guid]::NewGuid().ToString('N'))
./scripts/Test-ExchangeOnlineBaseline.ps1 -ParameterPath $parameterPath `
    -ConfigurationPath $configurationPath -OutputPath $runDirectory
if ($LASTEXITCODE -ne 0) { throw "Collection refused with exit $LASTEXITCODE; inspect the evidence and resolve the findings." }
```

Collection connects only to Exchange Online. `-SkipConnection` is for an already established Exchange session or an offline harness; it does not synthesize evidence. All 25 retained controls are required, including MON-003, OPS-001 and OPS-002. Do not turn a licensing gap, missing operational artifact, Error or unknown status into Pass. A collection exit 0 is not a signed go-live decision.

## 3. Freeze And Review Exact Bytes

```powershell
$evidencePath = Join-Path $runDirectory 'frozen-exchange-evidence.json'
if (Test-Path -LiteralPath $evidencePath) { throw 'Use a new frozen artifact path.' }
Copy-Item -LiteralPath (Join-Path $runDirectory 'exchange-online-evidence.json') -Destination $evidencePath
$evidenceHash = (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash
(Get-Item -LiteralPath $evidencePath).IsReadOnly = $true
$evidenceHash
```

Record this exact-file SHA256 in the independently approved change record alongside tenant, configuration hash, manifest version and review. Read-only is an accidental-write guard, not a security boundary. Protect the approved artifacts and metadata with your normal access controls. Do not reformat JSON, change newlines/encoding, refresh a timestamp or run the collector over the frozen file. Even whitespace changes invalidate its CMS signature.

## 4. Sign The Reviewed File

The authorized signer uses an existing certificate from their approved signing environment. The example locates an existing Windows certificate; it does not create or install one. A non-Windows signing environment can supply an existing `X509Certificate2` with private-key access using its approved mechanism.

```powershell
$certificateThumbprint = 'EXTERNALLY_APPROVED_CERTIFICATE_THUMBPRINT'
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$certificateThumbprint"
$signaturePath = Join-Path $runDirectory 'frozen-exchange-evidence.p7s'
$gateInputs = @{
    ParameterPath = $parameterPath
    ConfigurationPath = $configurationPath
    EvidencePath = $evidencePath
    EvidenceSignaturePath = $signaturePath
    EvidenceSignerIdentity = $signerIdentity
    AuthorizedSignerPath = $authorizedSignerPath
    ExpectedEvidenceHash = $evidenceHash
    ExpectedConfigurationHash = $configurationHash
    MaximumEvidenceAge = [timespan]::FromHours(24)
}
./scripts/Test-ExchangeOnlineBaseline.ps1 @gateInputs -SignEvidence -SigningCertificate $certificate
if ($LASTEXITCODE -ne 0) { throw "Signing refused with exit $LASTEXITCODE." }
```

Signing uses SHA256 detached CMS over the file bytes, adds an authenticated CMS signing time, then runs genuine signature, certificate trust, authority and gate checks before creating the signature. It never overwrites a signature file or writes back to the evidence. Use a new artifact pair for a new review. Signing failures or unresolved gate results do not publish an admitted signature. This signing time is signer-asserted, not a trusted timestamp service or long-term archival signature.

## 5. Verify Without Recollection

The verifier obtains the same frozen file, detached signature, approved parameter/configuration files, authority metadata and independently retained hashes. On a separate host, reconstruct `$gateInputs` using those approved paths and hashes; never substitute hashes learned only from untrusted incoming artifacts. No private key or Exchange connection is needed:

```powershell
./scripts/Test-ExchangeOnlineBaseline.ps1 @gateInputs -GoLive
if ($LASTEXITCODE -ne 0) { throw "Exchange gate refused with exit $LASTEXITCODE." }
```

`-GoLive` and `-SignEvidence` are mutually exclusive. Both are read-only with respect to Exchange and perform no global tenant collectors. The verifier reads one byte snapshot, checks its raw SHA256 and genuine detached CMS signature, then measures that same content. It does not regenerate an envelope or replace its collection timestamp. It enforces current tenant/configuration/manifest/profile binding, positive maximum age, nonfuture collection time, complete and unique in-scope evidence/check coverage, known statuses, and the unchanged exclusions/external-readiness dispositions. Null/missing observations fail; completed empty TABL/connector inventories remain explicit empty arrays.

Every evidence record must carry a boolean `Collected = true`, a present nonnull `Value`, and a parseable collection timestamp within the same maximum age and not in the future. Re-signing malformed records does not make them admissible. The frozen entitlement handoff must exactly match the current approved handoff, including its service plans; removing ATP entitlement with an unchanged configuration still refuses. Any handoff change requires a new collection, review and signature. This compares externally supplied licensing evidence, not a fresh tenant or directory license query.

The exported `Test-BaselineGoLive` decision API also performs genuine CMS, offline chain and signer authorization checks for `ExchangeOnly`. Its `Signature` input must include the exact `EvidenceBytes`, base64 CMS `Value`, `Model = DetachedCms`, `ContentHash`, approved `SignerIdentity` and `AuthorizedSigner` metadata (with optional `SignerSubject`). The parsed envelope must match those signed bytes. Supply `ExpectedEntitlement` from the current approved context alongside the expected tenant, profile and configuration hash. Caller-provided `Verified` flags are not authority. Prefer the public script workflow above, which also checks the independently retained exact-file hash. Explicit historical-profile decision tests retain their older contract; they are not proof of scoped cryptographic admission.

Exactly one CMS signer must match the authorized identity, `ExchangeOnlineChangeApproval` role, subject and certificate pin. Certificate validity, signed signing time, platform chain trust and offline revocation validation must succeed. Certificate downloads are disabled; missing intermediates, unavailable cached revocation evidence and untrusted chains fail closed. The production frozen verifier has no custom-root or trust-bypass option. The test harness isolates trust without changing certificate stores. Separate operational-artifact `trustedRoot` inputs do not change frozen-evidence trust.

## Results And Exits

| Exit | Meaning | Action |
| --- | --- | --- |
| 0 | Completed scoped collection, or admitted sign/verify stage | Read the stage and result; collection alone is not approval. |
| 10 | Invalid configuration, missing required gate inputs, nonpositive age or expected configuration digest mismatch | Correct approved inputs. |
| 11 | Exchange connection failure during collection | Restore authorized Exchange connectivity. |
| 12 | Collection Error, unreadable evidence or no checks | Repair collection/artifact availability and collect a new run. |
| 13 | Compliance or evidence binding/age/coverage/status refusal | Resolve the findings; a trusted signature cannot excuse them. |
| 14 | Missing/invalid signature, evidence digest mismatch, untrusted/unauthorized signer, missing signing key or existing signature destination | Obtain valid independent authority/trust and a reviewed immutable artifact. |
| 15 | Unexpected internal failure | Investigate the tool defect; do not treat it as conformance. |

These are script runtime outcomes; PowerShell invocation/parser/mandatory-parameter binding errors remain host errors. Collection Error takes precedence over compliance findings after valid signature admission. Signature/hash failures are approval failures before evidence verdicts are trusted.

`NotEntitled`, `Manual`, `Unverified`, `Fail`, missing records and unknown statuses cannot silently pass. `Error` remains a collection failure. The Exchange script explicitly rejects a separate `-RiskAcceptancePath` with exit 10; the scoped decision API likewise refuses a nonempty `RiskAcceptance` input. Neither silently ignores acceptance inputs or turns unresolved states into exceptions. An already evaluated bounded EWS deviation remains `ApprovedException` in its control result, the gate's `Exception` list, and the overall admitted `Result.Status`; it is never relabeled Pass. Its upstream external approval authenticity remains a limitation of the EWS exception contract.

`ExternalReadiness.Status` remains `Unverified`, including after exit 0. Explicit manifest exclusions are not measured Pass controls. RAID-A01/R02/D05 and other external dependencies remain external obligations. This workflow cannot certify tenant-wide security, DNS/identity/Purview readiness or safe service launch. Offline tests are not live Microsoft compatibility proof.

## Verification And Sources

Offline regression: `Invoke-Pester -Path ./tests/unit/ExchangeEvidenceSigning.Tests.ps1 -Output Detailed`. The harness uses ephemeral real certificates, genuine CMS and an isolated custom trust store, plus recorded raw Exchange observations and signed local operational artifacts. No certificate store is modified, private key is persisted, tenant is accessed or Exchange mutation is performed.

The frozen round trip invokes the actual public script for both signing and verification, asserts unchanged read-only evidence bytes and no collection calls, and preserves `ApprovedException` and unverified external readiness. Malformed record fixtures are signed again before admission to isolate semantic refusals from signature tampering. JSON nulls, arrays and scalars are unreadable evidence (exit 12); malformed CMS and authority files are approval failures (exit 14). The companion `ExchangeOnlyGoLive.Tests.ps1` uses real CMS for direct API admission and explicitly tests forged flags and substitution of the evaluated envelope.

Microsoft API references consulted for this implementation:

- [SignedCms.CheckSignature](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.signedcms.checksignature): signature-only checking is not certificate trust or authorization. The workflow performs separate chain and authority checks, following the existing approved-change implementation.
- [X509ChainPolicy.RevocationMode](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509chainpolicy.revocationmode): explicit offline revocation policy.
- [X509ChainPolicy.DisableCertificateDownloads](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509chainpolicy.disablecertificatedownloads): disable certificate issuer downloads during chain construction.