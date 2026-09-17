# Exchange Online Baseline Design

This document publishes the Phase 0 design contracts for the Contoso Exchange Online managed
service. Each contract is owned by `scripts/ExchangeOnlineBaseline.Common.psm1` and is asserted
by an executable test under `tests/unit/`. The document is the approval record: a contract is in
force only when it appears as `Approved` in [Contract Approval](#contract-approval).

| Decision | Card | Module contract | Assertion |
| --- | --- | --- | --- |
| Result and go-live semantics | DES-001 | `Get-BaselineResultContract` | `tests/unit/ResultContract.Tests.ps1` |
| Canonical comparisons | DES-002 | `Get-CanonicalComparisonContract` | `tests/unit/CanonicalComparisonContract.Tests.ps1` |
| Applicability and entitlement authority | DES-003 | `Get-ApplicabilityAuthorityContract` | `tests/unit/ApplicabilityAuthorityContract.Tests.ps1` |
| Artifact versions | DES-004 | `Get-ArtifactVersionContract` | `tests/unit/ArtifactVersionContract.Tests.ps1` |
| Approval signature model | DES-005 | `Get-ApprovalSignatureContract` | `tests/unit/ApprovalSignatureContract.Tests.ps1` |

## Result And Go-Live Semantics

DES-001 fixes the vocabulary every control evaluation may use, so the go-live gate can fail
closed on anything it does not recognise.

- Normalized statuses: `Pass`, `Fail`, `ApprovedException`, `NotApplicable`, `Error`. A control
  result must normalize to exactly one of these.
- Non-normalized statuses: `Manual`, `NotEntitled`, `Unverified`. These record why evaluation
  could not conclude and can never stand in for a normalized result.
- Go-live success statuses: `Pass`, `ApprovedException`, `NotApplicable`. Any other status, and
  any missing or unknown status, blocks go-live.

`Manual`, `NotEntitled`, and `Unverified` are deliberately excluded from the success set. An
unproven control is treated as an unmet control.

## Canonical Comparisons

DES-002 fixes how desired state is normalized before it is compared to tenant state, so that
formatting differences never read as drift and drift never reads as agreement.

Collection equality is normalized set equality: two collections match when their normalized
members are the same set. No canonical kind is order sensitive or case sensitive.

| Canonical kind | Normalization rules |
| --- | --- |
| `SmtpAddress` | Trim, remove `smtp:` prefix, lower invariant, drop empty entries, drop duplicates |
| `Domain` | Trim, remove trailing dot, lower invariant, drop empty entries, drop duplicates |
| `Group` | Trim, resolve to primary SMTP address, lower invariant, drop empty entries, drop duplicates |
| `IpAddress` | Trim, expand CIDR, normalize IPv6, drop empty entries, drop duplicates |
| `Identity` | Trim, resolve to immutable identifier, lower invariant, drop empty entries, drop duplicates |

## Applicability And Entitlement Authority

DES-003 fixes which inputs decide whether a control applies, and which source wins when the
tenant contradicts the configuration.

- Applicability inputs: `DeploymentProfile`, `ActualServicePlan`, `CatalogControlPriority`. No
  other input participates in the applicability decision.
- Authority: runtime Graph service-plan results are authoritative at precedence 1. Declared
  licensing metadata in the baseline is planning information only, at precedence 2, and is never
  authoritative.
- Conflict resolution: `RuntimeGraphWins`. Where the baseline claims entitlement the tenant does
  not grant, the tenant decides, and the control is reported as not entitled rather than passed.

## Artifact Versions

DES-004 decouples artifact evolution from the baseline release. The baseline carries its own
version, and every artifact contract carries an independent semantic schema version sourced from
its own schema rather than from the baseline.

Baseline version: `1.0.0`.

| Artifact contract | Schema version | Version source |
| --- | --- | --- |
| Configuration | 1.0.0 | ArtifactSchema |
| Evidence | 1.0.0 | ArtifactSchema |
| Preview | 1.0.0 | ArtifactSchema |
| Approval | 1.0.0 | ArtifactSchema |
| Rollback | 1.0.0 | ArtifactSchema |
| Exception | 1.0.0 | ArtifactSchema |

A consumer must compare an artifact against its own schema version. Reading a baseline version to
infer an artifact schema version is a contract violation.

## Approval Signature Model

DES-005 selects **detached CMS** as the single approval signature model. Enterprise certificate
and approved external-ticket evidence remain in the approved set as recognised models, but only
one model governs verification, and detached CMS is it. Detached CMS binds the signature to the
exact approved artifact bytes without mutating the artifact, and it verifies offline against the
enterprise trust chain.

| Rule category | Requirement |
| --- | --- |
| Authority | The signer certificate subject must map to a named approver holding the Exchange Online change-approval role, and the approver must not be the operator requesting the change. |
| Verification | The detached CMS signature must verify against the canonical SHA-256 hash of the approved artifact and chain to the enterprise root, with the full chain validated offline. |
| Expiry | An approval is honoured only while the signing time is within the artifact validity window and the signer certificate is unexpired; an approval older than the declared maximum evidence age is rejected. |
| Revocation | Signer revocation status must be checked against the enterprise CRL or OCSP responder, and an unavailable or inconclusive revocation answer fails closed. |

## Contract Approval

Every versioned artifact contract below is approved at the stated schema version.

| Contract | Schema Version | Status |
| --- | --- | --- |
| Configuration | 1.0.0 | Approved |
| Evidence | 1.0.0 | Approved |
| Preview | 1.0.0 | Approved |
| Approval | 1.0.0 | Approved |
| Rollback | 1.0.0 | Approved |
| Exception | 1.0.0 | Approved |

Changing any contract requires a new schema version for that contract and a new row state here
before the change may be relied on by deployment or evidence.
