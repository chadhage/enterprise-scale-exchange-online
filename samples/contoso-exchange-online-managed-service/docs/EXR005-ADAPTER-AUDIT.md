# EXR-005 Retained Adapter Audit

This audit covers the default ExchangeOnly evidence path, not deployment or live acceptance. The versioned [manifest](../config/exchange-only.manifest.v1.json) retains exactly 25 controls: 22 raw Exchange adapters and 3 signed local operational-artifact adapters. The implementation is [ExchangeOnlineBaseline.Common.psm1](../scripts/ExchangeOnlineBaseline.Common.psm1), principally `Invoke-BaselineExchangeRegistry`, `Invoke-BaselineExchangeRawCollection`, `Get-BaselineExchangeBoundaryEvidence`, and `Read-BaselineExchangeOperationalArtifact`.

## Shared Collection Contract

Every attempted raw call records command, bound arguments, start/end UTC, raw objects (including output before failure), warnings, error and completeness. Required fields, selected Boolean/nullable-Boolean types, cardinality and configured identity uniqueness are checked before evaluation. Errors, any warning, unsupported page envelopes, missing fields and absent/duplicate configured identities refuse collection. Failed collection cannot become Pass. There is no retry that discards partial evidence and no synthetic `Complete` input accepted as raw Exchange output.

`U` below means explicit `ResultSize = Unlimited`; `I` means an identity lookup with one required result; `S` means exactly one result; `C` means cmdlet-managed enumeration without a custom paging loop. These are invocation contracts, not independent service-side completeness attestations. Empty collections are allowed only where noted. `U` does not prove that a service or SDK honored the request. In particular, silent truncation without a warning or continuation marker cannot be detected by this wrapper. Unknown properties alone do not constitute a complete type schema: downstream evaluators retain their own validation responsibilities.

## All 25 Adapters

| Control | Raw source and collection contract | Normalization and decision | Limits and refusal boundary |
| --- | --- | --- | --- |
| EXO-001 | `Get-AcceptedDomain -Identity <primary-domain>` (I); Name, DomainName, DomainType | Compare the returned accepted domain and authoritative type with the configured domain | One configured domain, not all tenant domains; no DNS publication proof |
| EXO-002 | `Get-TransportConfig` (S); `Get-CASMailbox` (U, nonempty, unique Identity) | Tenant SMTP AUTH setting plus nullable mailbox overrides | Requires raw nullable Booleans; mailbox effective-setting evaluation is not a sign-in test |
| EXO-004 | `Get-HostedOutboundSpamFilterPolicy` (C, nonempty); `Get-Mailbox` (U, nonempty); `Get-InboxRule -Mailbox <identity> -IncludeHidden` (U per mailbox, empty allowed) | Outbound policy, mailbox forwarding and enabled forwarding/redirect rule targets | Every enumerated mailbox is queried; partial/error/page-envelope output refuses; no end-to-end mail-flow proof |
| EXO-005 | `Get-TransportConfig` (S), ExternalPostmasterAddress | Compare approved postmaster address | Address configuration only, not delivery or mailbox availability |
| EXO-006 | `Get-OrganizationConfig` (S), AuditDisabled; `Get-MailboxAuditBypassAssociation` (U, empty allowed) | Audit enabled and no enabled bypass | Each returned bypass needs unique Identity and Boolean AuditBypassEnabled; no Purview audit ingestion check |
| EXO-007 | `Get-ExternalInOutlook` (S), Enabled and AllowList | Compare external tagging and normalized allow list | Does not test rendering in an Outlook client |
| EXO-008 | `Get-RemoteDomain` (U, nonempty, unique Identity) | Domain-specific forwarding, reply, OOF, delivery-report and NDR settings | 1,001-record regression places drift at record 1,001; no silent fallback to the default result cap |
| EXO-009 | `Get-OrganizationConfig -RetrieveEwsOperationAccessPolicy` (S); `Get-CASMailboxPlan` and `Get-CASMailbox` (U, nonempty) | EWS organization/mailbox overrides and allow lists; POP/IMAP mailbox and plan settings | Exchange settings only; no Entra application inventory or protocol traffic test |
| EXO-010 | `Get-RoleGroup` (U, nonempty); `Get-RoleGroupMember -Identity <group>` (U per group, empty allowed); `Get-ManagementRoleAssignment` (C, nonempty) | Compare approved group names and members; prefer PrimarySmtpAddress, otherwise preserve Identity with IdentitySource and Raw | 1,001-group cap regression and non-mail-principal identity test; partner-linked groups are hidden by the cmdlet default (ShowPartnerLinked is not requested); assignments are required observations, not a full effective-permissions evaluator; no PIM/access review/Graph or recursive directory expansion |
| EXO-012 | `Get-RoleAssignmentPolicy` and `Get-ManagementRoleAssignment` (C, nonempty, unique Identity) | Default assignment-policy binding and prohibited end-user add-in roles | Assignment-based evaluation, not a mailbox add-in installation inventory |
| MDO-001 | Standard `Get-EOPProtectionPolicyRule` and `Get-ATPProtectionPolicyRule` (I); `Get-DistributionGroup` (I) for group resolution | Enabled Standard preset, domain scope and exceptions; group identities resolved to SMTP | Presets must already exist; no provisioning or directory membership expansion |
| MDO-002 | Strict `Get-EOPProtectionPolicyRule` and `Get-ATPProtectionPolicyRule` (I); `Get-DistributionGroup` (I) | Enabled Strict preset and approved priority recipient scope | Scope configuration only; no effective protection message test |
| MDO-003 | `Get-ATPBuiltInProtectionRule` (S); `Get-DistributionGroup` (I) when needed | Enabled built-in protection and exclusions | One rule expected; cannot certify non-Exchange workloads |
| MDO-006 | `Get-ReportSubmissionPolicy`, `Get-ReportSubmissionRule`, `Get-SecOpsOverridePolicy` (S each); `Get-ExoSecOpsOverrideRule -Policy <policy-identity>` (S) | Enabled report rule bound to policy; exact destination; Junk/NotJunk/Phish copy settings; enforced SecOps rule | Missing/disabled/misbound/misrouted rules refuse despite compliant policy objects; no client button, portal or report-delivery test |
| MDO-007 | `Get-TenantAllowBlockListItems` (C), eight Sender/Url/FileHash/IP by Allow/Block calls; empty allowed | Raw Identity/Value/ExpirationDate; FileHash maps to File, bare Sender domain maps to Domain; exact identity/type/value/action join to supplied governance entries | No invented owner/ticket/justification/creation date; populated inventory needs one matching register entry; missing/ambiguous binding is Error, incomplete governance is Fail; register is supplied metadata, not an independently authenticated ticket system |
| MDO-008 | `Get-QuarantinePolicy` global (S) and ordinary policies (C, nonempty); `Get-HostedContentFilterPolicy`, `Get-MalwareFilterPolicy`, `Get-AntiPhishPolicy` (C, nonempty) | Global notification settings, permission values and policy quarantine tags | Policy references only; no quarantined-message release/delivery test or full rule-precedence simulation |
| MDO-009 | `Get-AntiPhishPolicy` (C, nonempty); `Get-AntiPhishRule` (C, empty collection allowed but rule binding required for applicable custom policy) | Targeted protection, protected identities/domains, exclusions and enabled rule bound to policy with approved recipient scope | Wrong/missing/disabled/misbound rules cannot pass; no user-tag portal or full effective policy precedence proof |
| PP-005 | `Get-InboundConnector` (C, empty allowed), Identity/Name/ConnectorType/Enabled | Detect prohibited enabled partner inbound connectors in native routing | Exchange connector objects only; no external gateway or actual transport-route verification |
| AUTH-001 | `Get-DkimSigningConfig -Identity <primary-domain>` (I) | Returned Name must match domain; optional Domain must agree; enabled, Valid, key sizes and nonempty CNAME values | Wrong returned domain fails; CNAME values are not DNS resolution or delivered-message signature verification |
| MON-003 | Local signed artifact, tenant/profile/configuration/manifest/control binding and maximum age | Scheduled collection, cadence, retention, timestamp, drift and findings | No scheduler or SIEM contact; missing/untrusted/stale artifact is Error; signed claims do not independently prove historical execution |
| OPS-001 | Local signed artifact with the same binding/trust checks | ChangeId and completed/bound Preview, Pilot, Approval, Rollback and PostChange phases | Missing phase fails; no real Apply or rollback is run by evidence collection |
| OPS-002 | Local signed artifact with binding/trust checks; supplied THREAT_INTELLIGENCE entitlement | Exercise ID, timestamp, types, owners and tracked actions | No incident simulation or ticket-system contact; signer/entitlement authority is external |
| GOV-003 | `Get-RetentionPolicy -Identity <policy-name>` (I); `Get-Mailbox` (U, nonempty, unique Identity) | Exact Exchange MRM policy name and mailbox assignments | Missing/duplicate mailbox identity refuses; not Purview retention, retention-tag action/duration validation or proof of processing |
| GOV-004 | `Get-Mailbox` (U, nonempty, unique Identity), PrimarySmtpAddress and Boolean LitigationHoldEnabled | Required custodians present and expected hold state across enumerated mailboxes | No inactive/soft-deleted mailbox inventory or independent legal/retention-content attestation |
| GOV-005 | `Get-IRMConfiguration` (S); `Test-IRMConfiguration -Sender <secops> -Recipient <secops>` (S), Results | Compare licensing/decryption settings; parse exactly one OVERALL RESULT: PASS/FAIL; explicit failed subtest cannot pass | No fabricated Success/IsValid field; failed/ambiguous/missing summary refuses; localized or changed report format is unsupported and fails closed; offline test does not perform RMS calls |

## Eight Review Themes

The retained reviewer-case tests support the following eight-theme mapping. The original review message is not included in this audit; this mapping does not claim an independent replay of an unavailable review transcript.

| Theme | Implementation and negative evidence | Remaining limit |
| --- | --- | --- |
| 1. Reporting and SecOps rule binding | MDO-006 rejects disabled/missing/misbound rules and incorrect report routing, including NotJunk/Phish | Live rule shape, UI and delivery remain unverified |
| 2. Audit bypass raw shape | EXO-006 rejects absent/null/string Boolean and absent identity | Service inventory completeness is not externally attested |
| 3. IRM functional raw result | GOV-005 consumes Results; failed, ambiguous and fabricated-result cases refuse | English report format and live RMS compatibility only assumed by fixtures |
| 4. MRM mailbox identity | GOV-003 refuses missing and duplicate mailbox Identity | MRM processing and tag semantics outside this adapter |
| 5. DKIM returned-domain binding | AUTH-001 rejects a different returned domain | DNS and delivered-message verification external |
| 6. Impersonation rule scope | MDO-009 rejects absent/disabled/misbound/wrong-domain rules | Full effective policy precedence not proved |
| 7. RBAC non-mail principal | EXO-010 preserves Identity when SMTP is unavailable and compares the approved member | No directory/PIM expansion or full assignment privilege evaluation |
| 8. TABL governance provenance | MDO-007 admits one exact raw-to-register binding; missing/wrong/duplicate binding and missing owner refuse | Supplied register is not cryptographically authenticated or independently retrieved |

Additional checks cover the RemoteDomain and RoleGroup default-cap regression (all 1,001 objects observed and final noncompliant object detected), malformed output from 34 cmdlet/control combinations, warning-only truncation, access denial and throttling after partial output, forwarding inventory, and the real signed-local roundtrip.

## Local Signature Verification

Detached CMS verification covers canonical JSON excluding Signature. One signer, content integrity, binding, age, certificate validity, chain trust and declared signer authority must pass. `RevocationMode = Offline` and `DisableCertificateDownloads = true` are both set before chain building; unavailable trust/revocation information fails closed. The optional `trustedRoot` reference supplies a local certificate `path` and SHA256 `sha256` pin, using CustomRootTrust without changing a machine/user certificate store. Pin and authorized signer metadata must be approved independently, not selected by the evidence author.

The signed regression generates an ephemeral in-memory RSA key and a temporary self-signed public certificate, creates real detached CMS signatures, and runs the default public command against raw Exchange stubs. It exercises valid, tampered, wrong-binding, stale, unauthorized-signer, wrong-root-pin, untrusted-signer and missing-phase cases. A separate source guard requires both offline policy settings before Build. That guard is not a network-capture or malicious-AIA integration test. No production credential, tenant connection, store installation or real Apply is involved. The separate frozen-evidence go-live verifier is not covered by this operational-artifact download guard.

## Reproducible Offline Checks

Run from the repository root with PowerShell 7.5+ and Pester 5. The fixture harness shadows Exchange connection/collection commands and rejects enumerated excluded-service calls. It does not constitute a general OS network sandbox.

```powershell
Invoke-Pester -Path 'samples/contoso-exchange-online-managed-service/tests/unit/ExchangeLiveSignedRoundTrip.Tests.ps1' -FullNameFilter '*disables certificate downloads*' -Output Detailed -PassThru
Invoke-Pester -Path 'samples/contoso-exchange-online-managed-service/tests/unit/ExchangeLiveAdapters.Tests.ps1' -Output Detailed -PassThru
Invoke-Pester -Path 'samples/contoso-exchange-online-managed-service/tests/unit/ExchangeLiveContract.Tests.ps1' -Output Detailed -PassThru
Invoke-Pester -Path 'samples/contoso-exchange-online-managed-service/tests/unit/ExchangeLiveSignedRoundTrip.Tests.ps1' -Output Detailed -PassThru
Invoke-Pester -Path 'samples/contoso-exchange-online-managed-service/tests' -Output None -PassThru
```

Focused evidence resides in [ExchangeLiveAdapters.Tests.ps1](../tests/unit/ExchangeLiveAdapters.Tests.ps1), [ExchangeLiveContract.Tests.ps1](../tests/unit/ExchangeLiveContract.Tests.ps1), and [ExchangeLiveSignedRoundTrip.Tests.ps1](../tests/unit/ExchangeLiveSignedRoundTrip.Tests.ps1). Raw fixtures and recording stubs reside in [ExchangeLiveRawFixture.ps1](../tests/helpers/ExchangeLiveRawFixture.ps1) and [ExchangeLiveRawHarness.ps1](../tests/helpers/ExchangeLiveRawHarness.ps1). Pester artifacts are temporary, not production acceptance packages. The signed success case requires 25 unique results, all Pass, exit 0, no failed evidence, and ExternalReadiness Unverified. Negative cases require a non-Pass target and nonzero exit while leaving the other 24 controls passing.

## Verified Offline Acceptance

Verified on 2026-09-20 using PowerShell 7.6.6 and Pester 5.7.1. Counts below are observed executions, not planned checks.

| Check | Total | Passed | Failed | Skipped | NotRun | Failed containers |
| --- | --- | --- | --- | --- | --- | --- |
| Certificate-download guard before production fix | 9 | 0 | 1 | 0 | 8 | 0 |
| Signed local roundtrip after fix | 9 | 9 | 0 | 0 | 0 | 0 |
| Raw forwarding adapters | 5 | 5 | 0 | 0 | 0 | 0 |
| Raw collection contract | 68 | 68 | 0 | 0 | 0 | 0 |
| Quarantine focused regression after repair | 64 | 64 | 0 | 0 | 0 | 0 |
| Final complete offline suite | 3542 | 3542 | 0 | 0 | 0 | 0 |

The first completed full run found two quarantine negative-case regressions (3540 passed, 2 failed). Scoped AntiPhishPolicy shape detection dereferenced null evidence before the existing evidence guard. Making that early inspection null-safe restored the missing-evidence exception and uncollected-evidence Error result without changing quarantine policy semantics. The 64-test [QuarantinePolicy.Tests.ps1](../tests/unit/QuarantinePolicy.Tests.ps1) slice passed before rerunning the full suite to the final counts above.

Audit reconciliation found 25 rows, 25 unique manifest IDs, zero manifest differences, 34 documented raw commands matching all 34 fixture commands, and zero broken local links. The signed valid case proves 25/25 scoped Pass results with ExternalReadiness still Unverified. Existing unrelated analyzer warnings are not a clean-lint claim.

## Remaining Acceptance Gaps

- Live ExchangeOnlineManagement version, permissions, returned object types and property serialization have not been validated against a tenant. Offline raw fixtures are not Microsoft compatibility certification.
- Unlimited arguments and cmdlet-managed enumeration do not detect unannounced service truncation. The cap emulator specifically proves RemoteDomain and RoleGroup behavior, not every SDK paging implementation.
- The per-adapter limits above remain limits, not claims of completed adjacent controls or external readiness. Signing authority, licensing handoff and supplied governance truth are external dependencies.
- The original eight-review transcript is not reproduced here; exact wording/order closure cannot be certified from the retained tests alone.
- Certificate download prevention has a structural guard plus real CMS success/refusal tests, not an observed-network/AIA test. Frozen-evidence go-live verification is a separate path.
- No real tenant, credential, Apply, transport test, RMS service call, incident exercise, DNS query or production signing authority was used. ExternalReadiness remains Unverified even when all 25 scoped controls pass offline.

## Checked Platform References

- [Get-RemoteDomain](https://learn.microsoft.com/powershell/module/exchangepowershell/get-remotedomain?view=exchange-ps): cloud ResultSize defaults to 1,000 and supports Unlimited.
- [Get-RoleGroup](https://learn.microsoft.com/powershell/module/exchangepowershell/get-rolegroup?view=exchange-ps): ResultSize and ShowPartnerLinked contracts; partner-linked groups are not shown by default.
- [X509ChainPolicy.DisableCertificateDownloads](https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.x509chainpolicy.disablecertificatedownloads?view=net-10.0): true disables AIA issuer-certificate retrieval; default is false.