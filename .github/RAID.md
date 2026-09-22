# Exchange Online Service RAID Register

Updated: 2026-09-21 (remaining-parent child routing recorded; no external status or owner changed or confirmed). Owner: Exchange service owner (coordination only). Related: [Kanban](kanban.md), [backlog](backlog.md), [historical board](kanban-history-2026-09-19.md).

Purpose: record tenant-level assumptions, risks, issues and dependencies without turning them into Exchange implementation cards. Proposed owner roles below are routing responsibilities, not claims that a named person has accepted work. No external assumption is confirmed by this planning update. No credentials or tenant identifiers belong here.

## Scope Decision

Exchange configuration and mailbox-level operations are delivery scope. M365 tenant provisioning, identity/license assignment, Entra security/PIM/consent, DNS/HTTPS infrastructure, global Purview, SIEM, enterprise PKI and other workloads are not. EOP and licensed Defender protection of Exchange email are in scope; Safe Documents and protection of SPO/ODB/Teams are not. Third-party gateway/vendor onboarding is not part of the net-new native Exchange journey.

RAID is not a substitute for configuration evidence or a signed risk acceptance. Track external readiness separately from Exchange conformance. An unconfirmed dependency must be visible and may prevent safe service launch, but must not silently become an Exchange Pass or spawn an in-scope tenant provisioning card.

## Assumptions

| ID | Assumption | Proposed owner | Status | Validation or exit condition | Affected cards |
| --- | --- | --- | --- | --- | --- |
| RAID-A01 | An Exchange-only compliance boundary is approved; excluded tenant controls are separately governed. | Service owner and security architect | Scope directed by user; external assurance unconfirmed | Publish ownership and externally attested readiness; never label Exchange exit 0 as tenant security certification. | EXR-001, EXR-006, EXR-018 |
| RAID-A02 | The platform team supplies supported cloud environment, verified domains, usable identities, approved licenses and Exchange access before the Exchange procedure starts. | M365 platform owner | Unconfirmed | D01/D02 inputs are complete, current and independently approved. | EXR-008, EXR-016, EXR-017 |
| RAID-A03 | Records/legal owners decide retention periods, deletion, custodians, holds, encryption recipients, regional constraints and regulated data classes. | Records management and legal | Unconfirmed | Approved policy schedule identifies values and recipients; no universal seven-year deletion or hold-all-VIPs assumption. | EXR-009, EXR-012 |
| RAID-A04 | The DNS/security operations teams own external domain authentication records, MTA-STS hosting and aggregate/TLS-report monitoring. | DNS owner and security operations | Unconfirmed | D04 handoff includes initial onmicrosoft and parked-domain responsibility as applicable. | EXR-011, EXR-017 |

## Risks

| ID | Risk and impact | Proposed owner | Rating / status | Mitigation and closure evidence | Affected cards |
| --- | --- | --- | --- | --- | --- |
| RAID-R01 | 3,072 green offline tests may be mistaken for live Microsoft compatibility; realistic cmdlet output and actual operator workflow can still fail. | Engineering lead and Exchange service owner | High / open | Test retained raw adapters and documented commands; require authorized independent live Exchange walkthrough evidence, not only fixtures. | EXR-005, EXR-013, EXR-014, EXR-017 |
| RAID-R02 | An approved deviation or reduced scope may be marketed as 100% Microsoft/tenant security compliance. | Service owner and risk authority | High / open | Dated source inventory, explicit exclusions, separate ApprovedException and external-readiness reporting; release review rejects universal claims. | EXR-006, EXR-007, EXR-018 |
| RAID-R03 | Microsoft settings, licensing and EWS retirement behavior change after review, causing security or availability regressions. | Exchange service owner | High / open | Dated Microsoft references, quarterly and pre-release review, EWS compatibility checks and controlled rollback. | EXR-003, EXR-007, EXR-010 |
| RAID-R04 | Existing completed cross-workload code/tests or old agent heuristics reintroduce excluded tasks or override the force rank. | Repository maintainer | Medium / open | Active board scope/rank takes precedence for this program; preserve history separately and assert zero excluded-service calls. Do not infer new-scope acceptance from historical Done entries. | EXR-001, EXR-015, EXR-018 |

## Issues

| ID | Observed issue | Proposed owner | Status | Required resolution and closure evidence | Affected cards |
| --- | --- | --- | --- | --- | --- |
| RAID-I01 | Current product native configuration still enables other workloads and collects tenant-wide governance; board rescoping alone does not fix runtime behavior. | Exchange engineering lead for isolation; platform owners for excluded services | Open, reproduced by source review | EXR-001 isolates the Exchange profile; external owners retain responsibility for excluded services. Verify no excluded mutations or mandatory collectors on the Exchange path. | EXR-001, EXR-005 |
| RAID-I02 | Tenant Purview DLP default collector supplies raw objects while its evaluator requires Complete/Refused/Items; offline probe returned GOV-002 Error. Runbook policy Exchange-Regulated-Data/credit-card-only also disagrees with target Regulated data protection/credit-card-plus-SSN. | Purview platform owner | Open; outside Exchange delivery | External owner must repair/validate its collector adapter and policy/runbook contract in its own workstream. EXR-001/005/009 remove this mandatory tenant-Purview path from Exchange; exclusion does not close the external defect. | EXR-001, EXR-005, EXR-009 |
| RAID-I03 | Actual external environment availability, named dependency owners, permissions and sign-offs have not been evidenced in this review. Historical ENV-001 In Progress is not proof of readiness. | M365 program owner | Open / awaiting external evidence | Assign named owners and provide D01-D05 readiness records before authorized live acceptance; no credentials in this register. | EXR-008, EXR-012, EXR-017 |
| RAID-I04 | R-MDO-005 incorrectly treats Safe Documents as MDO P2 while separate licensing guidance recognizes SAFEDOCS. Safe Documents is outside the Exchange service boundary. | Endpoint/M365 protection owner | Open; outside Exchange delivery | External owner corrects its Safe Documents licensing/runbook using Microsoft service-plan guidance. EXR-010/012 remove this prescription from the active Exchange journey; do not implement endpoint licensing here. | EXR-010, EXR-012 |

## External Dependencies

These are acceptance handoffs, not authorizations or Exchange backlog tasks. At implementation start and before live validation, review status with the external owner. Record approved evidence reference, reviewer and date before marking Confirmed; overdue/unavailable items remain visible issues, not silently accepted assumptions.

| ID | External deliverable | Proposed accountable owner | Status | Evidence required / when needed | Exchange consumer |
| --- | --- | --- | --- | --- | --- |
| RAID-D01 | Disposable isolated M365 environment and explicit permission to test; no production identities or mail flow. | M365 tenant administrator | Unconfirmed | Environment approval, isolation attestation, authorized test window and ownership of eventual tenant teardown; required before EXR-017. No environment creation by the Exchange harness. | EXR-008, EXR-016, EXR-017 |
| RAID-D02 | Verified domains, pre-created identities, assigned supported service plans, mailbox provisioning entitlement, approved operator access and any required platform authentication/consent. | M365 licensing and identity administrators | Unconfirmed | Sanitized current entitlement/access handoff with recipient scope, expiry/review date and missing-license handling; required before live Exchange operations. License purchase/assignment and app consent remain external. | EXR-001, EXR-005, EXR-008, EXR-010, EXR-017 |
| RAID-D03 | Tenant Conditional Access, phishing-resistant MFA, emergency access/PIM, tenant Purview DLP/retention/labels/eDiscovery/global audit, legal policy and SIEM readiness where organizationally required. | Identity security, Purview/records, and security operations owners | Unconfirmed | Separately approved security/governance design and owner attestations; record which dependencies actually apply. Exchange consumes approved mailbox-level values, not implementation responsibility. Excluded-workload health is not proved by Exchange tests. | EXR-001, EXR-003, EXR-009, EXR-017, EXR-018 |
| RAID-D04 | Domain ownership/verification, MX and Autodiscover publishing, SPF/DMARC/DKIM CNAME publishing, MTA-STS HTTPS/TLS-RPT, report monitoring and DNS rollback approval. | DNS and domain owners | Unconfirmed | Exact Microsoft-provided MX/selector values, authorized sender inventory, DNS-owner publication/propagation proof and approved cutover/rollback window; required before Exchange mail-flow/DKIM acceptance. DNS authority changes and hosting are external. | EXR-008, EXR-011, EXR-017 |
| RAID-D05 | Trusted enterprise signing identities/certificates, approver authority, trust chain/revocation availability and change-management approval channel. | Enterprise PKI and change authority | Unconfirmed | Approved public trust/role metadata and accessible signing process; no private key in repo; needed before signed apply/go-live validation. Exchange tooling consumes the capability but does not provision enterprise PKI. | EXR-004, EXR-006, EXR-016, EXR-017 |

## Review And Escalation

### Remaining-Parent Child Routing

The twelve newly decomposed parents are scope references only, not active cards or external obligations. Their original register rows, owners and statuses remain unchanged; [backlog allocations](backlog.md#remaining-board-decomposition-review) identify executable child acceptance. None of this confirms readiness, grants permission or repairs the 13 known product regressions.

- [EXR-011](backlog.md#exr-011): D04 routes denominator/ownership to A01, supplied exact selectors to A02, DNS/MX/Autodiscover/SPF/DMARC/MTA-STS/TLS-RPT publication/reporting/cutover proof to A03 and bound message evidence to A04. No DNS/HTTPS writes or external-service certification.
- [EXR-007-A02](backlog.md#exr-007-a02): D01/D02/D04 retain external identity/routing ownership for T01 transport rules, T02 organization allows, T03 Safe Senders and T04 connector trust; no vendor setup. [EXR-007-A03](backlog.md#exr-007-a03): D02/D03 additive grants/consent evidence feeds T01 authorization and T02 Exchange-only assignment/scope lifecycle, with no app registration/consent mutation.
- [EXR-007-A04](backlog.md#exr-007-a04): D02/D03 disclosure and partner attestations feed T01 sharing/bindings and T02 calendar publication; partner readiness stays Unverified. [EXR-007-A05](backlog.md#exr-007-a05): D02/D03 identity/ownership evidence feeds separate T01 FullAccess, T02 SendAs and T03 SendOnBehalf outcomes, no directory provisioning. [EXR-007-A08](backlog.md#exr-007-a08): D02/D03 client/device approvals feed T01 mailbox/plan flags, T02 mobile policy and T03 OWA policy, not MDM or Conditional Access work.
- [EXR-012](backlog.md#exr-012) A01-A04 consume I03/I04/R02 and existing licensing/signing handoffs for entry inputs, runbooks, recovery and status wording. [EXR-013](backlog.md#exr-013) A01/A02 inventory then execute those documented contracts offline; [EXR-014](backlog.md#exr-014) A01/A02 reconcile raw fixtures then whole-service evidence under R01. Neither creates new external deliverables or duplicate email regression repairs.
- [EXR-015](backlog.md#exr-015) routes repository-maintainer coverage approval to A01, enforcement to A02 and discovery/isolation to A03 under R01/R04; real maintainer approval is not assumed. [EXR-016](backlog.md#exr-016) routes D01-D05 consumption to offline A01 opt-in/target/artifact safety, A02 change/recovery/owned-object ledger and A03 delivery/client probes. No live call or external provisioning while authoring.
- [EXR-017](backlog.md#exr-017): applicable D01-D05 must be independently confirmed with explicit live permission before A01's first walkthrough and A02's consecutive repeat/recovery; A03 requires actual independent review of both retained sanitized packets and raw-proof references. Code/docs changes invalidate the pair and restart A01 evidence. External owners retain tenant/infrastructure teardown; Exchange teardown touches only ledger-owned Exchange objects. No fabricated approval or offline stand-in closes live acceptance.

### EXR-010 Child Routing

EXR-010 is now a non-executable parent; its twelve [child contracts](backlog.md#acceptance-allocation) replace the former delivery card without creating new tenant obligations. Existing references to EXR-010 in this register denote that parent scope, not another active card. All external statuses and accountable roles above remain unchanged and unconfirmed.

- RAID-D02 supplies applicable recipient/capability inputs to A01-A10; A03 owns the Exchange entitlement decision contract, not license assignment or Graph consent.
- RAID-D03 supplies the reporting mailbox's DLP-owner handoff to A09/A10; neither child provisions Purview or treats unverified external state as Pass. Pre-write prerequisites are distinct from post-change delivery receipts.
- RAID-I04 routes excluded Safe Documents/collaboration guidance through A11; exclusion does not repair or certify the external workload. AIR capability remains separate from the Exchange reporting contract.
- RAID-D05 remains the existing signing prerequisite for reversible changes and A12 evidence integration. Synthetic offline signing is not enterprise PKI readiness. Actual report delivery and live compatibility remain EXR-016/017 under D01-D05, not child authoring work.

### EXR-007 External Handoffs

These refine existing external dependencies using the inventory's 2026-09-21 source review; they add no tenant implementation cards and do not change external status. User authorization dated 2026-09-20 covers Exchange delivery, not app migration, consent changes or partner-tenant operations. Named independent approvals are still required before live use; offline acceptance may exercise sanitized supplied handoffs without asserting readiness.

| Existing reference | External deliverable / accountable role | Status and verification condition | Exchange consumer |
| --- | --- | --- | --- |
| RAID-D02, RAID-D03, RAID-R03 | Application owners supply EWS consumer/usage inventory and migration owner/date; identity owners attest cloud and consent prerequisites. | Unconfirmed; current complete inventory must reconcile approved exceptions and the cloud-specific retirement notice, before October 2026 and each exception decision. Application migration is external. | EXR-007-A01 |
| RAID-D02, RAID-D03 | Identity/application owners attest additive Entra application grants, consent, app identifiers and principal provenance. | Unconfirmed; dated recipient/resource scope and grants evidence, including independent tenant-wide grants; local Exchange authorization tests alone cannot establish absence of those grants. No consent/registration changes by Exchange delivery. | EXR-007-A03, EXR-007-A05, EXR-009 |
| RAID-D03 | Partner organization administrators and security/data owners supply approved partner domains, disclosure/detail scope and remote-side readiness. | Unconfirmed; dated independently approved sharing/relationship handoff; local Exchange readback does not certify partner behavior. Remote-tenant configuration remains the partner's responsibility. | EXR-007-A04, EXR-007-A06 |
| RAID-D02, RAID-D03 | Licensing/audit owners supply supported mailbox/event entitlement and separately attest global audit ingestion/retention. | Unconfirmed; dated per-mailbox/event applicability and entitlement; no inference of ingestion from local action configuration. | EXR-007-A07 |
| RAID-D02, RAID-D03 | Client/device and identity owners supply approved client dependencies and external device/Conditional Access posture. | Unconfirmed; mailbox-class/client matrix identifies new Outlook/OWA dependencies and external policy owners; no device-management provisioning here. | EXR-007-A08 |
| RAID-A03, RAID-D02, RAID-D03 | Records/legal and RMS owners authorize lifecycle/hold/encryption scope, duration, decryption choices, entitlement and externally activated RMS. | Unconfirmed; signed policy schedule and readiness evidence before live mailbox changes; no tenant labels, keys, RMS activation or Purview cases in Exchange delivery. | EXR-009 |

The existing D01/D02/D03/D04/I04 routes also retain all 18 external/excluded control IDs in the inventory's five groups; the DLP defect remains RAID-I02, enterprise signing RAID-D05. EXR-011 consumes DNS-owner proof and EXR-010 consumes supplied protection/reporting entitlement; neither provisions the external services.

- Review open entries at each scope change, before external-dependent live work, and at release. The Exchange service owner routes unresolved prerequisites to accountable external roles.
- Escalate unresolved high risks and prerequisites to the service owner before launch. A separate authorized risk decision must state impact, compensating controls, owner and expiry; this document does not grant one.
- Close an assumption/dependency only with dated independent evidence. Close an issue only when its owner proves remediation; removing it from Exchange scope is not closure.
- 2026-09-19: Created from acceptance findings and the user's Exchange-only scope decision. All external readiness remains unconfirmed; no tenant configuration or live operation was performed.
- 2026-09-21: Recorded EXR-007 external handoff refinements only, with source-review dates distinct from the user's 2026-09-20 authorization. No external record confirmed or historical issue closed; no application migration, tenant provisioning or partner operation authorized.
