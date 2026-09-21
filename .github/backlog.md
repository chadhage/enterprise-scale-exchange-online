# Exchange Online Remediation Backlog

Updated: 2026-09-21 (EXR-007 Done; EXR-008 sole In Progress; 26 total: To Do 18, In Progress 1, Done 7). Status, completion evidence and unique force rank are owned by [Kanban](kanban.md); the ordered entries below use the same sequence. Offline completion does not establish live acceptance or external readiness. User authorization is dated 2026-09-20; the EXR-007 source review and observed verification are dated 2026-09-21 in the supplied artifacts, not backdated to the authorization.

## Acceptance Boundary

Target: an administrator can follow a tested, ordered guide to configure and verify Exchange Online against a dated, explicitly enumerated set of applicable Microsoft recommendations. Report approved exceptions separately from conformance. Do not claim universal Microsoft certification or 100% tenant security.

Tenant-level dependencies are excluded and tracked in [RAID](RAID.md), including Purview tenant policy creation, identity and licensing, consent, PKI, DNS publishing, SIEM, and environment provisioning. Exchange-side consumers, clearly labeled prerequisite checks, and mailbox-level configuration are in scope. They must neither provision those services nor convert an unverified dependency into an Exchange Pass. Workload scope is determined by the resource changed, not by which PowerShell module exposes a command.

Each card inherits the board's test-first, ownership, WIP, evidence, and no-live-action-without-authorization rules. Dependencies below are delivery dependencies, not tenant provisioning tasks. Each acceptance clause requires an executable check; documentation checks must exercise the documented examples, not merely search for keywords.

## Force-Ranked Work

### EXR-001

Rank 1 - Enforce the Exchange-only execution boundary.

- Dependencies: none. Owner: Coworker swarm, root coordinated. Workstream: Scope. Updated: 2026-09-20. Status: Done; verification in Kanban.
- Finding: the native profile and complete-catalog gate require other workloads and tenant governance.
- Acceptance: define a versioned Exchange-only profile/control manifest and migrate sample configuration, registry dispatch, deployment, evidence, and go-live to it. Keep Exchange/EOP/Defender email controls for Exchange recipients; exclude Safe Documents, SPO/ODB/Teams settings, tenant-wide Purview, SIEM, Entra provisioning, and vendor/gateway setup from this journey. Existing historical profiles may remain isolated, but cannot be the default or an undocumented fallback. Retain explicit scope exclusions and external-readiness references, never fabricated Pass results. Do not require global directory scans, tenant admin consent, or externally owned collection to establish Exchange-only conformance.
- Verification: profile/schema/dispatch tests refuse out-of-scope mutations and accidental historical defaults, assert zero excluded-service calls, and prove one complete Exchange-only registry run. Preserve historical regressions separately with documented scope.
- RAID: RAID-I01, RAID-A01, RAID-D02, RAID-D03.

### EXR-002

Rank 2 - Correct remote-domain OOF hardening.

- Dependencies: EXR-001 (Done). Owner: Coworker swarm, root coordinated. Workstream: Security correctness. Updated: 2026-09-20. Status: Done; user-accepted completion evidence below.
- Finding: R-EXO-008 and the baseline interpret InternalLegacy as preventing internal OOF disclosure.
- Acceptance: use current Microsoft remote-domain semantics to define the approved default (None when blocking external OOF; External only for an explicitly approved external-reply policy). Remove the reversed InternalLegacy explanation from all active config/catalog/runbooks/evaluators. Account for specific remote-domain overrides, and preserve intended forwarding/NDR choices without claiming universal Microsoft defaults.
- Verification: negative tests detect InternalLegacy and conflicting effective overrides for the selected policy; positive proves correct effective values and matching deployment/readback/runbook semantics. Include Microsoft source and review date.
- Completion (2026-09-20): None is the default local blocking policy; External requires a nonblank approval reference. Legacy/invalid policy and conflicting effective specific-domain overrides are rejected before writes. Complete identifiable remote-domain evidence includes wildcard default coverage; forwarding/NDR choices are preserved. This is local policy, not a universal Microsoft default or live-compatibility certification.
- Evidence (explicitly accepted by user, 2026-09-20): units 36/36 (31 negatives + 5 positive units); focused 123/123; full `Invoke-Pester -Path samples/contoso-exchange-online-managed-service/tests -PassThru -Output None` 3,169/3,169, zero failures/skips/not-run/failed containers; `git diff --check` passed. Board stewardship inspected [OOF policy/readback tests](../samples/contoso-exchange-online-managed-service/tests/unit/RemoteDomainOofPolicy.Tests.ps1) and [OOF deployment admission tests](../samples/contoso-exchange-online-managed-service/tests/unit/RemoteDomainOofDeployment.Tests.ps1); these execution results were supplied, not rerun during the board update.
- Microsoft references (reviewed 2026-09-20 per accepted evidence): [Set-RemoteDomain](https://learn.microsoft.com/powershell/module/exchangepowershell/set-remotedomain?view=exchange-ps) and [Remote domains in Exchange Online](https://learn.microsoft.com/exchange/mail-flow-best-practices/remote-domains/remote-domains).

### EXR-003

Rank 3 - Correct EWS exception enforcement.

- Dependencies: EXR-001 (Done). Owner: Coworker swarm (implementation + read-only review); root coordinates. Workstream: Security correctness. Updated: 2026-09-20. Status: Done; user-supplied completion evidence below.
- Finding: R-EXO-009 enables EWS and populates EwsAllowList without enforcing that list.
- Acceptance: retain the approved disabled default; for supported exceptions explicitly configure and verify EwsApplicationAccessPolicy and the exact allow list, with mailbox override/effective-state checks. Validate current Microsoft EWS retirement behavior before offering an exception, distinguish application identity controls from user-agent filtering, and document owner/expiry/rollback and client impact. Do not add tenant app-registration work.
- Verification: missing enforcement mode, surplus entries, contradictory overrides, expired exceptions, and unsupported retirement-era combinations fail for named reasons; one approved supported exception passes readback.
- RAID: RAID-R03, RAID-D03.
- Start (2026-09-20): selected next in force rank after EXR-002 completion; EXR-001 delivery dependency is satisfied. RAID-R03 remains open and RAID-D03 unconfirmed; implementation and read-only review do not authorize tenant operations or establish external readiness. Obtain applicable external approvals before any live exception use.
- Completion (2026-09-20): all acceptance criteria verified per user-supplied evidence. The default remains disabled. Approved exceptions enforce `EwsApplicationAccessPolicy = EnforceAllowList` with exact UserAgent allow-list matching; AppIDs are validated separately from user-agent filtering, with `RetrieveEwsOperationAccessPolicy` raw collection. Owner, approval, expiry, retirement, and cloud validation reject unsupported exceptions; mailbox override/effective-state checks verify effective enforcement. The real registry preserves `ApprovedException` instead of converting it to Pass. Top-level admission runs before mutations. Documentation covers rollback and client impacts; no tenant app-registration work is included.
- Evidence (supplied by user, 2026-09-20): focused `Invoke-Pester -Path samples/contoso-exchange-online-managed-service/tests/unit/EwsException.Tests.ps1 -PassThru -Output None` 75/75; full `Invoke-Pester -Path samples/contoso-exchange-online-managed-service/tests -PassThru -Output None` 3,244/3,244, zero failed/skipped/not-run; `git diff --check` passed. Results were supplied, not rerun during board stewardship. Offline verification does not establish live compatibility, external readiness, or approval for tenant operations; RAID-R03/D03 remain open/unconfirmed.

### EXR-004

Rank 4 - Deliver the usable approval and apply workflow.

- Dependencies: EXR-001 (Done). Owner: fallback Coworker swarm (implementation + read-only review); root coordinates. Workstream: Change safety. Updated: 2026-09-20. Status: Done; user-supplied completion evidence below.
- Finding: the documented -Apply invocation omits required preview, approval, artifact root, and change identity.
- Acceptance: supply a supported operator path to generate the immutable Exchange preview, obtain approval using externally supplied signing capability, validate it, apply with every required argument, record pre/post state, and execute scoped rollback. Document working directory, explicit profile paths, file formats, and actionable failure recovery. A console WhatIf transcript is not substituted for the approved artifact. Missing enterprise signing prerequisites stop clearly without provisioning PKI or weakening the gate.
- Verification: run documented preview/approval/apply/rollback commands against offline Exchange boundaries; prove refusal of missing/mismatched/expired approval and one complete artifact round trip. Verify byte binding and matching ChangeId.
- RAID: RAID-D05.
- Start (2026-09-20): selected next in force rank after EXR-003 completion; EXR-001 delivery dependency is satisfied. Named Coworker registration failed despite a valid file, so root coordinates fallback workers under the same Exchange-only scope, one-card WIP limit, maximum four coworkers, ownership/review, serialized board stewardship, and no-tenant-operation constraints. This is a local worker-registration/tooling issue, not an external tenant issue. RAID-D05 remains an external prerequisite, not a provisioning assignment or permission to weaken approval gates. Board counts at start: To Do 14, In Progress 1, Done 3.
- Completion (2026-09-20): supported operator workflow across 19 scopes and 22 families covers immutable preview, CMS approval, approval validation, apply, pre/post state recording, and typed scoped rollback. Actual documented commands were exercised against offline Exchange boundaries. TABL rollback retry consumes validated, bound, ordered attempts, preserves receipts, and retains drift safeguards. Protected local artifact/index trust requirements are documented; this does not establish live compatibility or verify enterprise PKI.
- Evidence (supplied by user, 2026-09-20): focused 216/216; full `Invoke-Pester -Path samples/contoso-exchange-online-managed-service/tests -PassThru -Output None` 3,460/3,460, zero failed/skipped/not-run/failed containers. Supplied execution results were not rerun during board stewardship. RAID-D05 remains an external prerequisite; no tenant operation, PKI provisioning, or external-readiness certification is implied. At this completion, EXR-005 started as the sole In Progress card; its subsequent completion is recorded below.

### EXR-005

Rank 5 - Repair Exchange live collector contracts.

- Dependencies: EXR-001 (Done). Owner: fallback Coworker swarm (implementation + read-only review); root coordinates. Workstream: Evidence. Updated: 2026-09-20. Status: Done; user-supplied completion evidence below.
- Finding: the raw DLP output probe exposes a collector/evaluator contract mismatch; fabricated complete fixtures cannot validate live adapters.
- Acceptance: audit every retained Exchange live adapter against actual documented cmdlet response shapes and required properties. Normalize completeness, paging, errors, identity, and timestamps at explicit boundaries; preserve raw observations for diagnosis. Remove the out-of-scope DLP/Purview live path from the Exchange command instead of repairing tenant Purview here; retain its defect in RAID-I02 for the external owner. No hidden test-only variable injection may be required for ordinary operator execution.
- Verification: default public-command paths use realistic raw Exchange objects, including missing properties, empty success, throttling, paging, and access denial; no mock returns already-evaluated success or invented Complete wrappers at the live boundary. One retained-control raw collection round trip passes.
- RAID: RAID-I02, RAID-D02.
- Start (2026-09-20): selected next in force rank after EXR-004 completion; EXR-001 delivery dependency is satisfied. Root coordinates the fallback Coworker swarm under the existing Exchange-only scope, one-card WIP limit, maximum four coworkers, implementation/read-only review ownership, serialized board stewardship, and no-tenant-operation constraints. Live collector contract work does not authorize live tenant access or establish external readiness; RAID-I02/D02 remain external obligations. Board counts at start: To Do 13, In Progress 1, Done 4.
- Completion (2026-09-20): [EXR005 adapter audit](../samples/contoso-exchange-online-managed-service/docs/EXR005-ADAPTER-AUDIT.md) reconciles all 25 retained controls and 34 raw commands. Cap 1001 preserves final drift. The actual signed raw synthetic public-command run produces 25 Pass, exit 0, and `ExternalReadinessUnverified`; synthetic Exchange conformance is not external-readiness certification.
- Evidence (supplied by user, 2026-09-20): full `Invoke-Pester -Path samples/contoso-exchange-online-managed-service/tests -PassThru -Output None` 3,542/3,542, zero failures/skips/not-run/failed containers; raw collection 68/68, forwarding 5/5, signed 9/9, quarantine 64/64. Supplied execution results were not rerun during board stewardship. Live compatibility remains unproven; silent service-side truncation without a completeness signal remains a limitation, not a completeness guarantee. RAID-I02/D02 remain external obligations; no tenant access or operations are authorized. At this completion, EXR-006 started as the sole In Progress card; its subsequent completion is recorded below.

### EXR-006

Rank 6 - Repair scoped go-live and evidence signing.

- Dependencies: EXR-004, EXR-005 (both Done). Owner: fallback Coworker swarm (implementation + read-only review); root coordinates. Workstream: Go-live. Updated: 2026-09-20. Status: Done; user-supplied completion evidence below.
- Finding: completion instructions omit -GoLive inputs and contradict unresolved-status exits.
- Acceptance: provide a reproducible collect/freeze/sign/verify flow over the exact Exchange evidence bytes; do not require a signature over a freshly regenerated timestamped envelope. Document and enforce hash/age/tenant/signer binding and distinct error exits. In-scope missing or unentitled evidence cannot silently pass; approved deviations remain ApprovedException. Out-of-scope controls are explicitly excluded from the manifest, while unresolved tenant dependencies are reported separately as unverified external readiness, not as a tenant-wide go-live certification.
- Verification: end-to-end public-command negatives for tampering, age, binding, authority, missing records, unknown status, and NotEntitled; one signed immutable Exchange run succeeds without global tenant collectors. Prove external readiness is not inferred from Exchange exit 0.
- RAID: RAID-A01, RAID-R02, RAID-D05.
- Start (2026-09-20): selected next in force rank after EXR-005 completion; EXR-004 and EXR-005 delivery dependencies are satisfied. Root coordinates the fallback Coworker swarm under the existing Exchange-only scope, one-card WIP limit, maximum four coworkers, implementation/read-only review ownership, serialized board stewardship, and no-tenant-operation constraints. EXR-005 synthetic signed-run evidence does not complete this card's broader go-live/signing acceptance or verify external readiness. RAID-A01/R02/D05 remain external assumptions, risks, and prerequisites; no PKI provisioning or tenant operations are authorized. Board counts at start: To Do 12, In Progress 1, Done 5.
- Completion (2026-09-20): reproducible collect/freeze/sign/verify workflow signs and verifies the exact frozen Exchange evidence bytes with CMS and an authorized externally supplied signer, without regenerating a timestamped envelope. Tenant, configuration, hash, time, current-entitlement, and manifest binding plus record semantics are enforced. The case bypass is fixed; empty authority is refused with exit 14. The workflow requires no global collection and is documented. `RiskAcceptancePath` is explicitly refused, not silently ignored; approved deviations remain `ApprovedException`, distinct from Pass. External readiness remains unverified and is not inferred from Exchange exit 0.
- Evidence (supplied by user, 2026-09-20): full `Invoke-Pester -Path samples/contoso-exchange-online-managed-service/tests -PassThru -Output None` 3,618/3,618, zero failed/skipped/not-run/failed containers; focused 84/84; shared exit 114/114; unchanged exit 15/15. Supplied execution results were not rerun during board stewardship. Offline completion does not establish live compatibility or enterprise signing readiness; RAID-A01/R02/D05 remain external assumptions, risks, and prerequisites. No PKI provisioning or tenant operations are authorized. EXR-007 is now the sole In Progress card.

### EXR-007

Rank 7 - Establish dated Microsoft recommendation coverage.

- Dependencies: EXR-001 (Done). Owner: fallback Coworker swarm (implementation + read-only review); root coordinates. Workstream: Traceability. Updated: 2026-09-21. Status: Done; inventory and planning admission complete, not gap implementation or release approval.
- Finding: the repository's catalog is not a demonstrated denominator for 100% Microsoft alignment.
- Acceptance: publish an enumerated Exchange recommendation inventory mapping source URL/section, review date, applicability, license prerequisite, desired setting, command, evaluator, evidence, and runbook. Distinguish Microsoft recommendations from local hardening/business choices. Explicitly assess sharing/delegation, protocols, mailbox access, domains, protection, auditing, and Exchange governance; every uncovered applicable recommendation receives an independently ranked child card before release. Tenant recommendations map to RAID, not new tenant implementation cards. Define stale-reference review cadence.
- Verification: executable traceability checks reject missing/duplicate/stale/dangling mappings and unsupported universal-compliance claims; approved exclusions carry reasons and external ownership. A positive covers the declared Exchange manifest, not all Microsoft 365.
- RAID: RAID-R02, RAID-R03.

- Start (2026-09-20): selected next in force rank after EXR-006 completion; EXR-001 delivery dependency is satisfied. Root coordinates the fallback Coworker swarm under the existing Exchange-only scope, one-card WIP limit, maximum four coworkers, implementation/read-only review ownership, serialized board stewardship, and no-tenant-operation constraints. Recommendation coverage work does not establish live acceptance or external readiness; RAID-R02/R03 remain open. Board counts at start: To Do 11, In Progress 1, Done 6.
- Completion (2026-09-21): inspected the [EXR-007 report](../samples/contoso-exchange-online-managed-service/docs/EXR007-RECOMMENDATION-INVENTORY.md) and [inventory](../samples/contoso-exchange-online-managed-service/config/exchange-recommendations.v1.json). All 15 proposals now have explicit delivery ownership below: eight independently ranked children and seven explicit acceptance merges into existing EXR-009/010/011. No applicable gap is left as a future proposal or marked implemented by this admission. The inventory's `Proposed` statuses and relative proposal ranks remain the unmodified writer snapshot; this backlog and Kanban record authoritative delivery disposition and global rank. The report's statement that root admission remains outstanding is superseded by this planning record only.
- Evidence (report observed 2026-09-21 and supplied by user): full offline suite 3,669/3,669, zero failed/skipped/not-run/failed containers; focused 51/51 (50 negatives, one positive), zero failed/skipped/not-run/failed containers. This is the prior 3,618 plus 51, with no removed/reclassified tests. Report records passing `git diff --check`. Inventory: 30 sources, 25 manifest mappings, 15 applicable assessments/proposals, 18 external/excluded IDs in five groups. Results were inspected and recorded, not rerun during stewardship; source URLs were not re-fetched here. Validator success is `DeclaredExchangeManifest`, external readiness Unverified, release readiness false, not universal compliance or live compatibility. No independent product execution review is claimed by this planning pass.
- Cadence: source owner re-fetches/reviews at least every 90 days (current due 2026-12-20), before release and on source/scope/license changes. EWS requires review before October 2026 and before every exception decision. Malformed/future/stale dates and changed source semantics are not cured by merely refreshing timestamps. Source review date is 2026-09-21, not a Microsoft publication date.

#### Proposal Admission Ledger

Each source ID and assessment ID below resolves to the exact URL, section, review date, applicability, license and current Gap/Partial status in the linked inventory. Merged means delivery acceptance is owned by an existing To Do card, not that the gap is fixed. Children cover surfaces absent from existing exact acceptance; existing governance, threat-policy and domain surfaces are refined in place to avoid duplicate implementation cards.

| Proposal | Assessment / sources | Delivery disposition | Reason and acceptance owner |
| --- | --- | --- | --- |
| EXR007-C01 | A14 / S26, S08 | Admitted: [EXR-007-A01](#exr-007-a01), rank 12, To Do | New consumer/migration readiness reconciliation; EXR-003 enforcement remains Done and is not duplicated or reopened. |
| EXR007-C02 | A09 / S27, S06, S15 | Admitted: [EXR-007-A02](#exr-007-a02), rank 13, To Do | Non-TABL lists, SCL rules, connector trust and redundant tagging are additional collection/enforcement surfaces, not satisfied by EXR-010's broad-bypass wording. |
| EXR007-C03 | A05 / S25 | Admitted: [EXR-007-A03](#exr-007-a03), rank 14, To Do | Application resource scopes and additive Entra grants differ from EXR-009 administrator/end-user RBAC. |
| EXR007-C04 | A01 / S28, S22 | Admitted: [EXR-007-A04](#exr-007-a04), rank 15, To Do | New sharing-policy bindings and calendar publication; education guidance is contextual, not a universal enterprise rule. |
| EXR007-C05 | A03 / S24 | Admitted: [EXR-007-A05](#exr-007-a05), rank 16, To Do | Recipient permissions are not role-group membership or EXR-008 mailbox creation. |
| EXR007-C06 | A02 / S23 | Admitted: [EXR-007-A06](#exr-007-a06), rank 17, To Do | Organization-relationship disclosure is not remote-domain OOF enforcement. |
| EXR007-C07 | A10 / S05 | Admitted: [EXR-007-A07](#exr-007-a07), rank 18, To Do | Per-mailbox action sets are additional evidence beyond EXR-009's organization auditing/bypass checks. |
| EXR007-C08 | A06 / S09 | Merged: [EXR-009](#exr-009), rank 9, To Do | Effective administrator/end-user rights, scopes, membership and assignment-policy checks refine the existing Exchange RBAC acceptance. Application RBAC belongs only to A03. |
| EXR007-C09 | A07 / S16, S29, S01 | Merged: [EXR-011](#exr-011), rank 11, To Do | Complete sending/accepted/initial-domain coverage, selectors, MX provenance and external DNS evidence already belong to this exact domain-authentication scope. |
| EXR007-C10 | A08 / S14, S10, S13 | Merged: [EXR-010](#exr-010), rank 10, To Do | Expand existing effective protection, precedence, recipient scope and entitlement acceptance into individual setting assertions. |
| EXR007-C11 | A04 / S30, S08 | Admitted: [EXR-007-A08](#exr-007-a08), rank 19, To Do | ActiveSync/MAPI/OWA and client dependencies are absent from EXO-009's EWS/POP/IMAP scope. |
| EXR007-C12 | A11 / S19 | Merged: [EXR-009](#exr-009), rank 9, To Do | Tag semantics, assignment, holds and processing make the existing Exchange MRM acceptance executable. |
| EXR007-C13 | A12 / S20 | Merged: [EXR-009](#exr-009), rank 9, To Do | Duration, capacity, mailbox classes and entitlement refine the existing legally approved mailbox hold/custodian scope. |
| EXR007-C14 | A13 / S21 | Merged: [EXR-009](#exr-009), rank 9, To Do | Approved Exchange encryption rules and recipient behavior complete existing IRM functional verification, not tenant RMS provisioning. |
| EXR007-C15 | A15 / S11 | Merged: [EXR-010](#exr-010), rank 10, To Do | Mailbox prerequisites, routing and delivery complete the existing reporting mailbox/Advanced Delivery contract. |

- Reviewer-extra disposition: SMTP AUTH true/false/null mailbox overrides are already implemented under EXO-002/S02, not a sixteenth gap. Inspected [Test-SmtpAuthenticationControl](../samples/contoso-exchange-online-managed-service/scripts/ExchangeOnlineBaseline.Common.psm1#L10236), the Exchange raw collector with `Get-CASMailbox -ResultSize Unlimited`, and [SMTP authentication tests](../samples/contoso-exchange-online-managed-service/tests/unit/SmtpAuthentication.Tests.ps1#L397): organization enabled and explicit mailbox false fail; true disables and null inherits; missing properties error. This is static corroboration of existing acceptance, not a newly executed test or external sign-in/Conditional Access assurance.
- Sequencing: preserve EXR-008 through EXR-018 relative order. Insert eight children at ranks 12-19 before EXR-012, not after EXR-016: every child adds a documented Exchange readback, decision or operation contract needed by EXR-012/013 and the subsequent offline/live harness. Children depend on completed parent/boundary contracts, not on one another or downstream documentation, avoiding blocker cycles. EXR-012 waits for all eight; EXR-013/014/015/016/017/018 inherit the dependency transitively.
- Child delivery contract: each child implements its declared Exchange surface through actual public collection/evaluation/evidence and, where configuration is needed, the approved preview/apply/readback/rollback path. Bind sources, applicability, current entitlement and local-policy choices; reconcile inventory/control mappings and document exact commands/outputs in that implementation, without falsely enlarging the original 25-control evidence denominator. Author negative-first executable checks and a positive per behavioral unit using raw synthetic observations, complete paging/error/identity handling and named refusal reasons. Supplied external attestations remain separate from Exchange Pass. EXR-012 integrates these procedures, EXR-013 executes them, EXR-016 authors opt-in checks and EXR-017 owns separately authorized live execution. No product/configuration changes or tests are performed by this planning admission.

### EXR-008

Rank 8 - Author the net-new Exchange administrator journey.

- Dependencies: EXR-004, EXR-007 (both Done). Owner: one root-coordinated Coworker. Workstream: Onboarding. Updated: 2026-09-21. Status: Done (offline authoring and walkthrough).
- Finding: foundational Exchange setup is implied rather than an executable ordered procedure.
- Acceptance: begin from independently provisioned tenant, verified domain, approved identities/licenses/roles, and owner attestations. Provide exact Exchange portal/PowerShell steps for accepted-domain type, checking provisioned mailboxes, creating Exchange shared/operations mailboxes and mail-enabled priority groups, approved membership, preset initialization, hardening, preview/apply, and Exchange mail-flow/client validation. Provide parameter provenance/examples and stop conditions. Identity creation, license assignment, domain verification, and DNS publishing are linked handoffs, not embedded implementation instructions. Do not move MX before the DNS owner's readiness approval.
- Verification: a sanitized walkthrough checks ordering, all required inputs, role/module prerequisites, representative Exchange recipients and outcomes; missing tenant inputs produce a named prerequisite response without provisioning them.
- RAID: RAID-D01, RAID-D02, RAID-D03, RAID-D04.

- Start (2026-09-21): lowest eligible rank 8 after EXR-007 admission, under the user's 2026-09-20 authorization for remaining cards. Root assigns workers only to this card; maximum four, one-card WIP, serialized stewardship. Author and test the offline administrator journey and named prerequisite stop responses using sanitized supplied inputs. Unconfirmed external dependencies prevent live operations, not offline authoring; no tenant provisioning or live action is authorized. Board counts: 26 total, To Do 18, In Progress 1, Done 7.

### EXR-009

Rank 9 - Reconcile Exchange governance settings.

- Dependencies: EXR-005, EXR-007 (both Done). Owner: one Coworker instance, followed by direct root integration and verification. Workstream: Governance. Updated: 2026-09-21. Status: Done. No subsequent card started.
- Finding: governance examples disagree with desired state and present local legal choices as universal defaults.
- Acceptance: align Exchange mailbox auditing/bypass checks, Exchange RBAC, mailbox hold/custodian scope, mailbox retention interfaces and IRM settings with externally approved records/legal policy. Distinguish Exchange MRM from Purview retention; do not compare them as the same policy. No automatic seven-year KeepAndDelete or VIP litigation-hold assumption. Tenant DLP, Purview labels/eDiscovery/global audit-retention provisioning and the conflicting DLP sample are removed from the Exchange walkthrough and assigned to RAID-I02/D03. Document observable Exchange-side verification and externally owned outcomes separately.
- Verification: matching configured names/values across retained commands, missing custodian membership, unauthorized hold, retention-type confusion, audit bypass, and failed IRM functional checks; positive proves approved Exchange-only state without Purview collector calls.
- EXR007-C08 / A06 / S09 acceptance merge: evaluate the effective administrator/end-user assignment graph, direct/delegating assignments, management scopes, nested/partner-linked membership, nondefault mailbox assignment policies and prohibited add-in-role bypass. Reject excess rights, unresolved external provenance, incomplete/paged collection and hidden default result caps. One approved least-privilege graph and mailbox policy passes independent raw readback and scoped rollback. No Entra/PIM provisioning; application RBAC is EXR-007-A03, mailbox action coverage EXR-007-A07.
- EXR007-C12 / A11 / S19 acceptance merge: resolve MRM policy tag links, actions, ages, enabled state, mailbox assignment, retention holds and processing evidence. Reject wrong or missing semantics, blocked processing, MRM/Purview confusion and unsupported archive entitlement; no assumed seven-year deletion. One externally approved lifecycle policy passes tag/assignment/processing checks and rollback, with preservation policy separately unverified.
- EXR007-C13 / A12 / S20 acceptance merge: bind custodians, hold duration and owner to legal approval; verify per-mailbox entitlement, inactive/soft-deleted applicability and Recoverable Items capacity. Reject unauthorized duration/custodians, missing entitlement, omitted mailbox classes or capacity risk. One approved hold inventory proves scope, duration and capacity without Purview cases, tenant retention or VIP-equals-hold assumptions.
- EXR007-C14 / A13 / S21 acceptance merge: map approved business-message classes and recipients to Exchange encryption-rule scope, readback, IRM functional results and authorized recipient/decryption behavior. Reject scope gaps, failed IRM, missing recipient/entitlement evidence and unapproved transport/journal decryption. One approved Exchange rule/message-class contract passes offline recipient-flow checks and scoped rollback; retain actual recipient-delivery acceptance for EXR-016/017. RMS activation, keys and tenant labels remain external under RAID-D02/D03/A03.
- Integration verification: exercise these merged clauses through actual collection/evaluation/evidence and approved change paths using raw synthetic observations; update source/control/evidence/runbook mappings during implementation. Negative-first named failures and positive behavioral units are required, not prose-only acceptance. EXR-012/013 consume the resulting contracts; no new product acceptance is asserted by this merge.
- RAID: RAID-A03, RAID-D03, RAID-I02.

Completion evidence (2026-09-21, offline only):

- Implemented raw Exchange governance collection/evaluation for effective direct/delegating RBAC, read/write/custom/exclusive scopes, nested effective users, provenance, nondefault mailbox policies and add-in bypass; MRM tag links/types/actions/ages/enabled state, assignment, processing and archive entitlement; all three hold mailbox classes with legal duration/owner/entitlement and Recoverable Items headroom; encryption rule predicates/exceptions, class/recipient/template, IRM results, decryption approval and current independently supplied recipient observations. Evidence cannot select its own authorization; desired state controls the decision.
- Added signed existing-object `GovernanceMailboxPolicy`, `GovernanceMrm` and `GovernanceEncryption` scopes, with typed before/after state, immutable prerequisites, tamper refusal, missing-read refusal, exact restoration, administrator-drift refusal and repeated rollback no-op. These do not grant RBAC roles, create archives/tags/rules, clear processing holds, activate RMS, or release legal holds. MRM rollback is configuration recovery, not recovery of processed/deleted data. Other graph changes require separately reviewed Exchange changes and revalidation.
- Public raw integration and the frozen administrator journey consume explicit governance configuration and supplied synthetic recipient evidence. The pilot and shared mailbox have explicit policy/MRM bindings; the shared mailbox remains unheld. EXO-006 audit/bypass and EXO-012 controls remain exercised without Purview calls. External readiness stays Unverified.
- Replaced active tenant audit-retention/DLP/labels/eDiscovery provisioning, seven-year preservation defaults and priority-user hold inference with RAID-I02/D03 handoffs. Added [Exchange governance contract](../samples/contoso-exchange-online-managed-service/docs/EXCHANGE-GOVERNANCE.md), updated S09/S19/S20/S21 command/evidence/limit mappings, retained control catalog, runbooks, implementation guide, approved change scopes and journey inputs.
- Root verification: fresh `pwsh -NoProfile -NonInteractive` running `Invoke-Pester -Path ./samples/contoso-exchange-online-managed-service/tests -PassThru -Output None`: **3,856 passed / 3,856 total**, zero failed/skipped/not-run/failed containers. Semantic/raw/journey slice **157/157**, signed governance adapters **20/20**, governance documentation **10/10**, source inventory **51/51**. Tests ran after the final evidence-authority repair; not supplied user acceptance or live proof. Exactly one Coworker instance was invoked; remaining integration was performed directly by root, with no additional delegation.
- Live service serialization, actual recipient delivery, legal/identity/entitlement authority and enterprise PKI remain external or EXR-016/017 acceptance. EXR-009 completion is not whole-product best-practice coverage or release authorization.

### EXR-010

Rank 10 - Align Exchange email-protection guidance.

- Dependencies: EXR-005, EXR-007 (both Done). Owner: one Coworker instance, root coordinated. Workstream: Email protection. Updated: 2026-09-21. Status: In Progress; sole active card.
- Finding: preset guidance, licensing explanations, and cross-workload protection are mixed.
- Acceptance: document and verify EOP and externally licensed Defender email presets, precedence, recipient/group scope, impersonation targets, reporting mailbox, Advanced Delivery, quarantine behavior, and narrow allow/block exceptions for Exchange. Use Microsoft-supported preset modification surfaces. Remove Safe Documents and SPO/ODB/Teams setup from active guidance, not merely relabel their licensing. Consume supplied entitlement inputs without assigning licenses or assuming a suite label proves entitlement.
- Verification: scope/precedence, unsupported preset mutation, unlicensed capability, broad bypass and recipient exclusion negatives; one licensed Exchange-recipient workflow; zero non-Exchange workload writes.
- EXR007-C10 / A08 / S14, S10, S13 acceptance merge: enumerate every applicable Standard/Strict email table setting, including anti-malware file filters/ZAP, spam/BCL/actions, outbound limits, spoof/DMARC, impersonation/safety tips, Safe Links email and Safe Attachments email. Reject setting drift, scope holes, incorrect Strict/Standard/custom/default precedence, unsupported individual preset mutation and feature/recipient entitlement mismatch. One licensed effective recipient matrix proves each applicable setting and approved exception; settings without a Microsoft recommendation are labeled local. Distinguish Defender P1/P2 impersonation from P2 priority-account capabilities and do not attribute a P2 mandate to tabletop frequency. No Safe Documents/SPO/ODB/Teams writes. Non-TABL bypass implementation belongs to EXR-007-A02, not a duplicate here.
- EXR007-C15 / A15 / S11 acceptance merge: verify reporting mailbox prerequisites, Junk/NotJunk/Phish destinations, rule/policy bindings, feedback, SecOps exceptions and narrowly scoped Advanced Delivery. Reject missing mailbox prerequisites, wrong routing, absent delivery evidence and broad exceptions. One approved path passes the offline mailbox/rule/delivery contract; EXR-016/017 separately author/execute authorized actual report-delivery acceptance. Keep AIR entitlement separate and Teams excluded; do not treat rule readback alone as delivery proof.
- Integration verification: real public collection/evaluation/evidence and approved change paths must exercise these setting and reporting contracts over raw synthetic inputs, with exact source/control/runbook mappings updated during implementation. Use named negative failures and positive behavioral units; EXR-012/013 integrate and execute the documented contracts. This merge does not claim the gaps fixed.
- RAID: RAID-D02, RAID-I04.

### EXR-011

Rank 11 - Correct domain authentication and DNS handoffs.

- Dependencies: EXR-007, EXR-008. Owner: unassigned. Workstream: Domain protection. Updated: 2026-09-21. Status: To Do.
- Finding: primary-domain examples omit complete domain applicability and incorrectly explain DMARC inheritance and MX provenance.
- Acceptance: enumerate Exchange sending/accepted/initial domains and distinguish externally owned parked-domain inventory. Configure Exchange DKIM and retrieve exact selectors. Define DNS-owner input/output handoffs for MX, Autodiscover, SPF/DMARC, MTA-STS/TLS-RPT and reporting; correct parent/subdomain DMARC inheritance and do not claim Get-AcceptedDomain provides the tenant's MX target. Explain staging, propagation, alignment, and Exchange send/receive verification. No DNS/HTTPS/reporting-service provisioning is added to the board or deployer.
- Verification: domain classification and selector fidelity tests plus read-only/synthetic handoff checks; missing or stale external confirmation is a prerequisite issue, not a fabricated DNS pass. Include initial onmicrosoft domain and parked-domain owner handoff.
- EXR007-C09 / A07 / S16, S29, S01 acceptance merge: reject omitted accepted/sending/initial domains, wrong selector/key/signing state, invented MX provenance and stale DNS-owner attestations; classify subdomain and parked-domain responsibility without false NotApplicable. One complete approved Exchange domain denominator binds exact DKIM selectors/signing state and received-message authentication/alignment proof to independent SPF/DMARC/cutover evidence. Use synthetic message/header and owner records offline, with actual send/receive proof in EXR-016/017. Preserve approved domain-type topology and DMARC inheritance semantics, no DNS writes. Exercise the actual domain collection/evaluator and handoff contract with named negative and positive cases, updating source/control/evidence/runbook mappings in implementation; existing exact domain acceptance is not duplicated into a child.
- RAID: RAID-D04.

### EXR-007-A01

Rank 12 - Reconcile EWS consumer and migration readiness.

- Dependencies: EXR-007, EXR-003. Owner: unassigned. Workstream: Protocol readiness. Updated: 2026-09-21. Status: To Do.
- Provenance: EXR007-C01, assessment A14, sources S26/S08 reviewed 2026-09-21; see the EXR-007 admission ledger and child delivery contract. This is new dependency evidence, not a reproduced EXR-003 enforcement regression.
- Acceptance: consume a complete supplied EWS usage/consumer inventory; reconcile each consumer, approved exception, mailbox readback, cloud, migration owner/date and expiry to current cloud-specific retirement notices. Retain the disabled default and EXR-003 enforcement. Review before October 2026 and before each exception; application migration, registration and consent remain external.
- Verification: reject missing consumers/owners/migration dates, stale or cloud-mismatched attestations, unmatched exceptions and expiry beyond supported retirement boundaries. One complete approved consumer/exception inventory matches independent Exchange readback; report external migration readiness separately, never infer it from local enforcement. Test documented input and refusal contracts offline.
- RAID: RAID-R03, RAID-D02, RAID-D03; application owners supply usage and migration attestations.

### EXR-007-A02

Rank 13 - Enforce non-TABL filtering bypass boundaries.

- Dependencies: EXR-007, EXR-004, EXR-005. Owner: unassigned. Workstream: Email protection. Updated: 2026-09-21. Status: To Do.
- Provenance: EXR007-C02, A09, S27/S06/S15 reviewed 2026-09-21; child delivery contract applies. EXR-010 retains preset/TABL/protection acceptance; this child owns additional bypass surfaces.
- Acceptance: inventory transport SCL rules, connection-filter IP allows, anti-spam sender/domain allows, mailbox Safe Senders, inbound/outbound connector trust and redundant external subject-prefix rules. Bind each exception to authenticated narrow conditions, owner, approval and expiry, with complete paging/error handling and independent raw evidence.
- Verification: reject sender-domain-only unauthenticated SCL bypass, broad/shared IP ranges, unowned/expired allows, undeclared connector trust, incomplete lists and duplicate external-tag rules. One narrow authenticated approved exception passes raw rule/connector/mailbox-list collection, approved apply/readback and scoped rollback. No vendor/gateway provisioning; external routing ownership stays a handoff.
- RAID: RAID-D01, RAID-D02, RAID-D04.

### EXR-007-A03

Rank 14 - Bound Exchange application mailbox access.

- Dependencies: EXR-007, EXR-004, EXR-005. Owner: unassigned. Workstream: Authorization. Updated: 2026-09-21. Status: To Do.
- Provenance: EXR007-C03, A05, S25 reviewed 2026-09-21; child delivery contract applies. EXR-009 administrator/end-user rights and EWS user-agent filters do not prove application resource scope.
- Acceptance: enumerate Exchange application roles, service-principal references, assignments and management/resource scopes; consume independently supplied current additive-Entra-grant and consent evidence. Verify allowed and denied mailbox authorization and report propagation limits. Limit changes to Exchange assignments/scopes with approved readback/rollback; never register apps or mutate Graph consent.
- Verification: reject missing app/scope evidence, overprivileged or unscoped assignments, unintended mailbox authorization, absent/stale additive-grant attestations and incomplete inventories. One approved scoped application passes both allowed- and denied-mailbox tests and rollback with an external handoff; local authorization tests alone cannot certify absence of tenant-wide Entra access.
- RAID: RAID-D02, RAID-D03.

### EXR-007-A04

Rank 15 - Bound sharing policies and calendar publication.

- Dependencies: EXR-007, EXR-004, EXR-005. Owner: unassigned. Workstream: Sharing. Updated: 2026-09-21. Status: To Do.
- Provenance: EXR007-C04, A01, S28/S22 reviewed 2026-09-21; child delivery contract applies. Education no-all-domain guidance requires a declared enterprise applicability decision.
- Acceptance: inventory sharing policies, default/explicit mailbox bindings and calendar publication state. Configure only approved partner, anonymous/wildcard and detail scopes; default to neither universal education restrictions nor unreviewed existing sharing. Preserve independent partner readiness.
- Verification: reject unapproved wildcard/anonymous sharing, excess detail, missing mailbox bindings and incomplete calendar publication evidence. One approved partner-only policy and mailbox/calendar state round-trips approved set/readback/rollback without external-tenant changes.
- RAID: RAID-D02, RAID-D03 for external partner/identity and disclosure approval handoffs.

### EXR-007-A05

Rank 16 - Verify recipient delegation independently.

- Dependencies: EXR-007, EXR-004, EXR-005. Owner: unassigned. Workstream: Recipient permissions. Updated: 2026-09-21. Status: To Do.
- Provenance: EXR007-C05, A03, S24 reviewed 2026-09-21; child delivery contract applies. EXR-008 creation/membership and EXR-009 role groups do not inventory mailbox delegation.
- Acceptance: enumerate FullAccess, SendAs and SendOnBehalf independently for applicable user/shared mailboxes and recipients. Distinguish inherited/system entries and nested principals from explicit approved delegates; consume external identity/ownership evidence without a global directory provisioning workflow.
- Verification: reject any unauthorized access/send grant, missing shared mailbox, incomplete collection or unresolved nested-principal ownership. One least-privilege approved delegation set passes independent permission readback and scoped rollback, proving mailbox access is not silently treated as send permission.
- RAID: RAID-D02, RAID-D03.

### EXR-007-A06

Rank 17 - Bound organization-relationship disclosure.

- Dependencies: EXR-007, EXR-004, EXR-005. Owner: unassigned. Workstream: Sharing. Updated: 2026-09-21. Status: To Do.
- Provenance: EXR007-C06, A02, S23 reviewed 2026-09-21; child delivery contract applies. EXR-002 remote-domain OOF correctness does not cover organization relationships.
- Acceptance: inventory enabled/disabled organization relationships, partner domains, free/busy detail and access scopes against independent disclosure approval. Configure and verify only local Exchange relationship values, retaining partner-side attestations as external readiness.
- Verification: reject unknown partner domains, excessive free/busy detail, overbroad access scope and incomplete relationship evidence. One approved local relationship passes independent domain/detail/scope readback and rollback; an absent partner attestation stays Unverified rather than becoming a local or end-to-end Pass.
- RAID: RAID-D03 for partner organization/security-owner approval and readiness.

### EXR-007-A07

Rank 18 - Verify per-mailbox audit action coverage.

- Dependencies: EXR-007, EXR-004, EXR-005. Owner: unassigned. Workstream: Auditing. Updated: 2026-09-21. Status: To Do.
- Provenance: EXR007-C07, A10, S05 reviewed 2026-09-21; child delivery contract applies. EXR-009 retains organization auditing/bypass reconciliation; no duplicate ownership of those fixes.
- Acceptance: collect DefaultAuditSet, AuditAdmin, AuditDelegate and AuditOwner across supported mailbox types and compare managed defaults or independently approved customization. Consume organization/bypass state, per-event entitlement and scope without treating those alone as action coverage. Approved changes use readback/rollback; global audit ingestion and retention remain external.
- Verification: reject missing default/action evidence, unauthorized customization, bypass, omitted supported mailbox classes, incomplete collection and unsupported premium-event entitlement. One approved Admin/Delegate/Owner action policy passes independent raw mailbox readback and rollback with tenant ingestion explicitly Unverified.
- RAID: RAID-D02, RAID-D03; no tenant Purview/audit-retention provisioning.

### EXR-007-A08

Rank 19 - Verify mailbox client access applicability.

- Dependencies: EXR-007, EXR-004, EXR-005. Owner: unassigned. Workstream: Client access. Updated: 2026-09-21. Status: To Do.
- Provenance: EXR007-C11, A04, S30/S08 reviewed 2026-09-21; child delivery contract applies. Extend ActiveSync/MAPI/OWA applicability, not EXR-003 EWS or EXO-002 SMTP override work.
- Acceptance: define approved client/protocol values by mailbox class, CAS mailbox/plan, mobile-device mailbox policy and OWA mailbox policy. Check new Outlook's OWA dependency and other client impacts. Resolve the contradictory MAPI disable example with S08 true-enables semantics, not copied prose; do not blanket-disable clients without approval.
- Verification: reject unapproved ActiveSync/MAPI/OWA enablement, missing mailbox/plan/policy evidence, incomplete collection and disabling OWA without dependency assessment. One approved mailbox-class client policy passes set/readback/rollback and explicit offline client-impact contracts; authorized real client behavior is exercised under EXR-017. No device management or Conditional Access provisioning.
- RAID: RAID-D02, RAID-D03 for supplied identity/device policy and client-owner readiness.

### EXR-012

Rank 20 - Reconcile all Exchange operator documentation.

- Dependencies: EXR-006, EXR-008, EXR-009, EXR-010, EXR-011, EXR-007-A01, EXR-007-A02, EXR-007-A03, EXR-007-A04, EXR-007-A05, EXR-007-A06, EXR-007-A07, EXR-007-A08. Owner: unassigned. Workstream: Documentation. Updated: 2026-09-21.
- Acceptance: reconcile README, solution summary, implementation guide, runbooks, license-prerequisite guidance, control catalog, sample inputs, and evidence-viewer wording with the Exchange profile. Publish exact set/verify/expected-output steps, complete approval and go-live examples, current status/exit meanings, and recovery instructions. Every non-Exchange dependency points to RAID. Explain which values are Microsoft recommendations, administrator input, or approved business policy; remove universal 100% and accepted-exception-equals-Pass claims.
- Verification: sanitized examples resolve every input and link; operator outputs match actual status/exit contracts; no active procedure configures excluded services. Do not mark this Done on keyword checks alone; EXR-013 provides full executable walkthrough regression.
- RAID: RAID-R02, RAID-I03, RAID-I04.

### EXR-013

Rank 21 - Execute documented command contracts.

- Dependencies: EXR-012. Owner: unassigned. Workstream: Verification. Updated: 2026-09-21.
- Acceptance: parse and exercise every executable command block in the active Exchange journey using documented inputs, working directory, artifacts, and cmdlet signatures. Do not silently inject missing prerequisites or substitute a hand-built desired-state result. Label non-executable illustrations explicitly.
- Verification: missing approval arguments, wrong default profile, stale cmdlet/parameter, runbook/config name mismatch, stale exit semantics, and hidden prerequisite cases fail for their exact reasons; the sanitized documented Exchange workflow passes end to end.

### EXR-014

Rank 22 - Prove Exchange-only offline workflow.

- Dependencies: EXR-002, EXR-003, EXR-013. Owner: unassigned. Workstream: Verification. Updated: 2026-09-21.
- Acceptance: adapt retained TST-006 assets to the new manifest and exercise shipped commands through actual adapters over synthetic raw Exchange observations. Assert one result/evidence record per in-scope control and correct tenant/profile/hash/time binding. Negative cases assert named reasons, not just nonzero exits. No live contact, credentials or service mutations. Synthetic success is labeled offline evidence only.
- Verification: focused fixture/public-command/reconciliation suites and full offline regression pass. Reference baseline evidence is 3,072 passing tests from the assessment, not a requirement to retain out-of-scope feature tests in the Exchange release denominator. Every removal/reclassification must be accounted for.
- RAID: RAID-R01.

### EXR-015

Rank 23 - Enforce scoped coverage and regression guards.

- Dependencies: EXR-014. Owner: unassigned. Workstream: Test quality. Updated: 2026-09-21.
- Acceptance: repository maintainer approves the branch-capable tool/version, numeric threshold, Exchange code scope, and justified exclusions; implement the corresponding local/CI guard. Establish a reviewed Exchange-only discovery baseline, preserving legacy tests separately where needed rather than silently deleting or inflating assertions.
- Verification: below-threshold branches, line-only reports, discovery loss, and attempted external-service contact fail; one conforming report passes. A coverage percentage is not evidence of Microsoft semantic correctness or live compatibility.

### EXR-016

Rank 24 - Author opt-in Exchange live acceptance harness.

- Dependencies: EXR-014. Owner: unassigned. Workstream: Live validation. Updated: 2026-09-21.
- Acceptance: implement an explicitly opt-in Exchange-only harness using an externally supplied isolated environment. Cover documented preview/apply, idempotency, raw collection, signed go-live, drift, partial failure/rollback, mail-flow/client checks, and artifact sanitization. Never provision a tenant, identities/licenses, DNS, Purview, SIEM, vendor gateway or signing infrastructure. Teardown restores only the Exchange objects this test created or changed.
- Verification: offline CI explicitly skips live execution; opt-in without named external prerequisites fails clearly. Test no production target, no accidental live call, raw response compatibility, and secret/identifier sanitization with synthetic fixtures. No live execution occurs while authoring this card.
- RAID: RAID-D01 through RAID-D05.

### EXR-017

Rank 25 - Verify the documented Exchange service journey.

- Dependencies: EXR-016. External eligibility: RAID-D01 through RAID-D05 independently confirmed as applicable. Owner: Exchange service owner; not started. Workstream: Live validation. Updated: 2026-09-21.
- Acceptance: with explicit authorization, an Exchange administrator follows the published instructions in the supplied disposable environment without undocumented repair. Produce two consecutive sanitized Exchange runs proving approved apply, no-op second apply, effective security settings, mail flow, evidence/go-live, and scoped rollback. No tenant provisioning is a deliverable. Record any missing external prerequisite in RAID and do not claim success.
- Verification: execute the EXR-016 opt-in command and checklist, retain raw-output adapter proof and sanitized run artifacts, and have an independent reviewer attest the walkthrough. Offline fixtures alone cannot close this card.
- RAID: RAID-R01, RAID-D01 through RAID-D05.

### EXR-018

Rank 26 - Enforce the Exchange release acceptance gate.

- Dependencies: EXR-015, EXR-017. Owner: unassigned. Workstream: Release. Updated: 2026-09-21.
- Acceptance: release requires dated complete Exchange traceability, correct settings, all documented command tests, scoped regression/coverage, default live adapter compatibility, immutable approval/evidence verification, rollback/idempotency, and independent live walkthrough evidence. Report Exchange conformance, approved deviations, and external readiness separately; no tenant-wide 100% claim. Any newly identified applicable gap is force-ranked before this card can close.
- Verification: machine-checkable release manifest refuses each missing prerequisite and accepts one complete Exchange release packet with links to test and live evidence; RAID owners acknowledge unresolved external risks without converting them into passed Exchange controls.
- EXR-007 admission gate: require implementation evidence for all eight admitted children and all seven merged proposal clauses, resolved through this 15-row ledger into current source/control/evidence/runbook mappings. Reject omitted proposals, a mere Proposed/scheduled disposition offered as completion, stale review dates, missing per-setting coverage and absent authorized live evidence. Dependencies through EXR-012/013/014/016/017 already enforce all child completion; no reverse dependency from a child to documentation or release is introduced. The original 30-source/25-control/18-external inventory and 3,669-test result remain dated baseline evidence, not a promise that later scope/discovery counts stay unchanged.

## Prior Active Card Disposition

The [original board](kanban-history-2026-09-19.md) remains verbatim. These are retirements/replacements, not completion claims. Audit: 22 actual To Do plus 3 In Progress equals 25 active cards; the old header overcounted To Do by one. Some cards contained useful work but mandated the wrong scope or deferred operator correctness behind unrelated work; replacement retains useful intent without asserting those cards alone caused the code defects.

| Previous ID | Previous state | Disposition and reason |
| --- | --- | --- |
| ENV-001 | In Progress | Removed to RAID-D01/D02/D04; tenant, licensing, and DNS provisioning are external. |
| TST-005D | In Progress | Replaced by EXR-015; no current approval work is presumed active; approve Exchange coverage only. |
| TST-006 | In Progress | Replaced by EXR-014; preserve the existing fixture/tests but remove complete-M365-catalog success as acceptance. |
| EVD-010 | To Do | Replaced by EXR-007; source-first Exchange inventory instead of parity against an overbroad catalog. |
| TST-005 | To Do | Consolidated into EXR-015; scoped coverage requirement. |
| TST-005E | To Do | Consolidated into EXR-015; approval and enforcement stay one measurable card. |
| TST-007 | To Do | Replaced by EXR-013/014; exact failure reasons and documented Exchange commands. |
| TST-008 | To Do | Replaced by EXR-014/015; review discovery scope instead of retaining an arbitrary old 2,082-test floor. |
| INT-001A | To Do | Tenant identity/license definitions removed to RAID-D02; Exchange recipient work retained in EXR-008/016. |
| INT-001E | To Do | Removed to RAID-D02; external administrator supplies licensed identities. |
| INT-002A | To Do | Gateway/DNS setup removed to RAID-D01/D04; Exchange-only isolation guard retained in EXR-016. |
| INT-002E | To Do | Environment isolation assurance transferred to RAID-D01; no vendor-gateway workflow. |
| INT-003A | To Do | Replaced by EXR-016; keep Exchange apply/idempotency/drift, remove license mutation/SAFEDOCS scenarios. |
| INT-003E | To Do | Replaced by EXR-017 for Exchange execution only; external entitlement prerequisites in RAID-D02. |
| INT-004A | To Do | Replaced by EXR-016; retain Exchange safety/failure scenarios, remove native-to-vendor transition and Graph provisioning. |
| INT-004E | To Do | Replaced by EXR-017; validate Exchange failures and rollback only. |
| INT-005A | To Do | Consolidated into EXR-016; retain evidence sanitization. |
| INT-005E | To Do | Consolidated into EXR-017; two sanitized Exchange runs, not full-tenant proof. |
| INT-006A | To Do | Replaced by EXR-016; tenant/Purview/DNS/PKI setup obligations transferred to RAID-D01 through RAID-D05. |
| INT-006E | To Do | Replaced by EXR-017; consume external prerequisites, no provisioning-to-full-M365 acceptance. |
| REL-001 | To Do | Replaced by EXR-004/008/012; operator correctness and Exchange scope first. |
| REL-002 | To Do | Replaced by EXR-006/012; tenant consent, PKI, DNS, PIM and Purview ownership moved to RAID. |
| REL-005 | To Do | Replaced by EXR-013; test actual Exchange operator command contracts. |
| REL-003 | To Do | Replaced by EXR-018; Exchange release gate and reviewed regression denominator. |
| REL-004 | To Do | Replaced by EXR-007/017/018; remove full-tenant entitlement/Analyzer/Purview evidence as Exchange completion prerequisites. |

## Assessment Finding Coverage

| Assessment finding | Delivery or external disposition |
| --- | --- |
| 1. Reversed OOF semantics | EXR-002 |
| 2. Apply/go-live commands and status drift | EXR-004, EXR-006, EXR-012, EXR-013 |
| 3. Raw DLP collector mismatch | Remove Exchange coupling in EXR-001/005; external defect RAID-I02, not an Exchange Purview repair card. |
| 4. EWS allow-list enforcement missing | EXR-003 |
| 5. Native profile is not Exchange-only | EXR-001, EXR-010; tenant/workload ownership RAID-A01/D03 |
| 6. Net-new onboarding detail missing | EXR-008, EXR-011; external setup RAID-D01/D02/D04 |
| 7. Governance instructions and desired state diverge | EXR-009/012; legal decisions RAID-A03, tenant DLP repair RAID-I02/D03 |
| 8. Safe Documents licensing and DMARC explanation | EXR-010/011/012; external Safe Documents ownership RAID-I04 |
| 9. No complete denominator or live proof | EXR-007, EXR-013 through EXR-018; RAID-R01/R02/R03 |
