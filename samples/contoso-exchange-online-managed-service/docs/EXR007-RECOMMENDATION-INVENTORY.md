# EXR-007 Dated Recommendation Inventory

Review date: 2026-09-21. Owner: Exchange service owner. Delivery: sole writer, EXR-007 only. Supplied pre-change baseline: 3,618 offline tests. This document is a root handoff, not a board transition or release approval.

## Denominator And Evidence

The normative [inventory](../config/exchange-recommendations.v1.json) contains 30 specifically fetched Microsoft sources, 25 mappings to the declared ExchangeOnly 1.0.0 manifest, 15 applicable gap assessments and 15 independently ranked child proposals. Every retained mapping joins a source URL/section/review date to applicability, license prerequisites, desired setting, collection command, actual registry evaluator/evidence path, current runbook heading and explicit limit. A source review date is the date of this review, not Microsoft's publication date. Source findings are concise paraphrases, not copied manuals.

`MicrosoftRecommendation` identifies explicit recommended behavior; recipient selection and additional local restrictions still require approval. `MicrosoftCapabilityLocalPolicy` identifies a supported Microsoft capability whose desired values depend on topology, business needs or legal authority. `LocalChoice` explicitly avoids attributing repository values to Microsoft. Examples of local choices include remote-domain reply/NDR blocking, POP/IMAP/EWS disabled defaults, add-in acquisition restrictions, postmaster address, TABL 30/90-day governance, daily signed evidence, CMS change phases and quarterly exercises. Mandatory transport/journal decryption and hold selection also require external policy approval.

This is an enumerated, dated source assessment, not proof that the manifest exhausts the Microsoft recommendation universe. All seven requested areas were assessed: sharing/delegation, protocols, mailbox access, domains, protection, auditing and Exchange governance. The 15 gap records are Applicable, with Gap or Partial coverage; none is hidden as NotApplicable. Their missing evaluator/evidence/runbook fields explicitly say Unimplemented. C10 must expand the threat-policy tables into individual setting assertions before protection coverage can be claimed complete.

Commands in mappings are collection/readback command names, not ready-to-run mutations. Desired values come from the declared profile and source assessment. Current runbook headings are traceability targets, not endorsements that every example is correct; EXR-012/013 still own documentation reconciliation and executable walkthroughs. Historical evidence keys such as `purview.retentionPolicy` and `dns.dkim` are preserved because the live Exchange registry uses them; they do not authorize Purview or DNS collection. The [adapter audit](EXR005-ADAPTER-AUDIT.md) records collection and semantic limits.

## Source Findings

Microsoft Learn search and specific page fetch tools were used, including source pages for [SMTP AUTH](https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission), [recommended threat settings](https://learn.microsoft.com/defender-office-365/recommended-settings-for-eop-and-office365), [sharing policy bindings](https://learn.microsoft.com/exchange/sharing/sharing-policies/apply-a-sharing-policy), [recipient delegation](https://learn.microsoft.com/exchange/recipients-in-exchange-online/manage-permissions-for-recipients), [application RBAC](https://learn.microsoft.com/exchange/permissions-exo/application-rbac), [mailbox auditing](https://learn.microsoft.com/purview/audit-mailboxes), and [EWS retirement](https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/deprecation-of-ews-exchange-online). All 30 URLs, exact reviewed sections and findings are retained in the inventory; no documentation-unavailable claim is made.

- EWS documentation now describes phased disablement starting October 2026 and full disablement April 2027, with an explicit call to inventory consumers and migrate. C01 is a source-review/dependency follow-up, not a claim that a completed EXR-003 enforcement regression was reproduced.
- The email-app article's MAPI example says disable in prose but uses `MAPIEnabled $true`. The Set-CASMailbox parameter reference says true enables it. C11 must test intended behavior, not copy the contradictory example.
- The education baseline's no-all-domain sharing recommendation is contextual. C04 requires a declared enterprise decision using the generic sharing-policy mechanics, not an unsupported universal restriction.
- Accepted-domain Authoritative settings depend on topology. The single primary-domain checks do not cover every sending/initial domain. Exact DKIM selectors, SPF/DMARC and delivered-message authentication remain separate observations.
- Impersonation protection is available with Defender P1/P2; the repository's MDO-009 P2 gate and priority-account naming require C10/EXR-010 reconciliation. Tabletop frequency itself does not require a P2 license. Legacy E3 MRM gating is not a universal MRM licensing claim.
- IRM configuration and its self-test do not prove business-message encryption coverage. LitigationHoldEnabled does not prove legal approval, duration or Recoverable Items capacity. MRM policy name equality does not prove tag semantics or processing.

## Ranked Child Proposals

These ranks are relative within the proposed child set, not edits to the authoritative board's global force rank. Each full proposal includes owner, related existing card and at least two executable acceptance clauses in the inventory. Root must assign globally independent ranks and add every applicable gap to the board before release. Existing-card references indicate overlap to coordinate, not permission to silently absorb or drop the gap. No child implementation was started.

| Rank / Proposal | Gap and provenance | Required negative and positive acceptance |
| --- | --- | --- |
| 1 / EXR007-C01 | EWS consumer/migration readiness; new source follow-up to EXR-003 | Refuse stale/cloud-mismatched usage/expiry evidence; reconcile one complete approved consumer and exception inventory with external migration owners. |
| 2 / EXR007-C02 | Non-TABL bypasses; newly explicit surfaces under EXR-010 | Refuse sender-only SCL bypass, broad IP/anti-spam/Safe Sender allowances and connector trust; prove one narrow authenticated exception with expiry/readback/rollback. |
| 3 / EXR007-C03 | Exchange app mailbox access; new | Refuse unscoped or overprivileged app access and missing additive-Entra-grant evidence; prove allowed and denied mailbox authorization without tenant consent changes. |
| 4 / EXR007-C04 | Sharing policy/calendar publication; new | Refuse unapproved wildcard/anonymous/detail scope and missing mailbox binding; prove approved partner sharing and rollback. |
| 5 / EXR007-C05 | Recipient delegation; new | Refuse excess FullAccess/SendAs/SendOnBehalf and incomplete inventory; prove one independent approved delegation set with readback/rollback. |
| 6 / EXR007-C06 | Organization relationships; new | Refuse unknown partner/excess free-busy detail/access; prove approved local relationship, keeping partner readiness unverified. |
| 7 / EXR007-C07 | Mailbox audit actions; newly explicit EXR-009 surface | Refuse missing/unauthorized DefaultAuditSet/action lists and unsupported entitlement; prove approved Admin/Delegate/Owner coverage. |
| 8 / EXR007-C08 | Effective RBAC; known adapter/EXR-009 limit | Refuse direct/delegating/scope/nested/partner-linked excess and nondefault-policy bypass; prove approved effective Exchange rights. |
| 9 / EXR007-C09 | All sending/initial domains; known EXR-011 limit | Refuse omitted domains/wrong selectors/stale DNS attestation; prove complete Exchange domain denominator plus independent external handoff. |
| 10 / EXR007-C10 | Effective threat setting and recipient matrix; known EXR-010 limit | Enumerate email table settings and reject setting/scope/precedence/license errors or preset mutation; prove one licensed effective recipient matrix. |
| 11 / EXR007-C11 | ActiveSync/MAPI/OWA applicability; new | Refuse unapproved mailbox-class access and broken client dependencies; prove approved settings and client-impact checks. |
| 12 / EXR007-C12 | MRM tag semantics/processing; known EXR-009 limit | Refuse wrong action/age/tag links and MRM/Purview confusion; prove approved lifecycle semantics and processing evidence. |
| 13 / EXR007-C13 | Hold duration/capacity; known EXR-009 limit | Refuse unauthorized/unentitled holds and missing capacity/mailbox classes; prove legally approved scope/duration/capacity. |
| 14 / EXR007-C14 | Encryption rule/recipient behavior; known functional limit | Refuse scope gaps, failed IRM and unapproved decryption; prove approved Exchange message class/recipient flow without RMS provisioning. |
| 15 / EXR007-C15 | Reporting mailbox functional contract; known EXR-010 limit | Refuse mailbox/routing/Advanced Delivery failures; prove Exchange reporting path and separately authorized live delivery. |

## External Ownership

All 18 manifest-excluded or externally checked control IDs are reconciled in five exclusion groups, each with reason, exact existing RAID reference, external owner role and Unverified status. This records the user-directed scope boundary, not a fabricated external approval. Identity/licensing/consent route to RAID-D02/D03; non-Exchange protection to RAID-I04; native-topology vendor/gateway dependencies to RAID-D01; global Purview/SIEM/legal policy to RAID-D03; DNS/HTTPS/reporting to RAID-D04. Existing DLP defect RAID-I02 remains open. Enterprise signing remains RAID-D05, and legal authority RAID-A03/D03. Exchange-side sharing, application scopes and mailbox operations are not excluded merely because their owners consume external input.

No board/backlog/RAID/history changes were made by this writer. Existing dirty work was preserved. No credentials, tenant connection, Apply, commit or child-card implementation occurred. An early read-only execution-helper invocation was a deviation from the requested no-spawn constraint; it did no implementation, and subsequent work used direct tools only. No independent review is claimed.

## Review Cadence

The Exchange service owner must re-fetch and semantically review every source at least every 90 days, before release, on a Microsoft change notice, and whenever scope, licensing or desired values change. The current general review is due 2026-12-20; a document older than 90 days fails validation. Future or malformed dates fail. Do not refresh timestamps without reading the sources and recording changed sections, affected tests and gap decisions.

EWS additionally requires a pre-October-2026 review and review before every exception decision; do not wait for the quarterly deadline. Verify cloud-specific timeline and service behavior. Broken/moved links or contradicting guidance block source acceptance until resolved; keep earlier findings visible in normal version history. The validator is offline: it validates declared official URLs and reviewed section bindings, not current HTTP availability or source semantics. Future source re-fetch is a reviewer responsibility.

## Reproduce Offline

Run from the repository root in PowerShell 7 with Pester 5. No Exchange connection is made. The date is injected for reproducible historical checks; omit it for current freshness evaluation.

```powershell
$trace = & ./samples/contoso-exchange-online-managed-service/scripts/Test-ExchangeRecommendationInventory.ps1 -AsOfUtc ([datetime]'2026-09-21T12:00:00Z')
$trace | ConvertTo-Json
if (-not $trace.Valid) { throw ($trace.Codes -join ', ') }
Invoke-Pester -Path ./samples/contoso-exchange-online-managed-service/tests/unit/ExchangeRecommendationInventory.Tests.ps1 -PassThru -Output None
Invoke-Pester -Path ./samples/contoso-exchange-online-managed-service/tests -PassThru -Output None
```

The [validator](../scripts/Test-ExchangeRecommendationInventory.ps1) refuses missing/duplicate manifest mappings, stale/future/invalid review dates, unofficial URLs, duplicate source URLs/IDs, dangling sections/commands/evaluators/evidence/runbook headings, unsupported inventory claims, hidden applicability, missing assessment areas, invented gap coverage, untracked/orphaned proposals, duplicate ranks, absent child acceptance and missing/duplicate/rebound exclusions without reasons or external owners. Registry bindings are read from the actual ExchangeOnly registry. Command-name presence is checked against local implementation; this is not live cmdlet parameter validation. Universal-claim detection is confined to this structured inventory, not an assertion that all existing documentation has been reconciled.

The positive result is `Valid=true`, `Scope=DeclaredExchangeManifest`, `ManifestCount=25`, `MappedCount=25`, `ProposedGapCount=15`, `ExternalReadiness=Unverified`, `ReleaseReady=false`. Validation success means traceability is coherent, not that applicable gaps are implemented or a tenant is ready. Proposed-gap admission and final release gating remain root/EXR-018 responsibilities; this validator deliberately cannot authorize release.

## Observed Verification

All 42 initial negatives were observed red before the single positive was authored. The positive then failed as intended before inventory implementation. Eight additional boundary negatives were subsequently observed red before their fixes. Final focused result: 51/51 (50 negatives, exactly one positive), zero failed/skipped/not-run/failed containers. Fetched-page heading comparisons found four old titles; all references were corrected and the comparison reran with zero mismatches. The nine short source pages were inspected directly in tool output; the remaining 21 fetched pages had automated exact-heading comparisons.

Full offline suite observed on 2026-09-21: **3,669 total, 3,669 passed, zero failed/skipped/not-run/failed containers**, exactly the supplied 3,618 baseline plus 51 EXR-007 tests. The full command above was executed directly after focused verification. `git diff --check` passed, with only an existing LF/CRLF informational warning on SmtpAuthentication.Tests.ps1. No existing tests were removed or reclassified. Board admission and independent review are still required before root can accept release readiness; live compatibility and external readiness remain unproven.