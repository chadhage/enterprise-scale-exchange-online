# Exchange Email Protection

Scope: retained ExchangeOnly controls MDO-001/002/003/006/007/008/009 and OPS-002. Source review: 2026-09-21. This contract does not configure Safe Documents, SharePoint, OneDrive, Teams, licensing, Graph consent or global Purview. ExternalReadiness remains Unverified.

## Operator Contract

The active procedure evaluates the 25-control ExchangeOnly profile. The 43-control Historical profile remains available only for explicit regression and reference use; it is not the active deployment default.

| Profile | Control denominator | Collaboration treatment |
| --- | ---: | --- |
| Historical | 43 | MDO-004 and MDO-005 remain opt-in reference controls for historical regression only. |
| ExchangeOnly | 25 | Excludes MDO-004 and MDO-005 as not applicable to the active Exchange deployment. |

Catalogue values retain their declared provenance: `MicrosoftRecommendation` is a sourced Microsoft value, `LocalPolicy` is an approved local choice, and `ApprovedException` is a separately authorized deviation. Never relabel a local value or exception as a Microsoft recommendation.

### Inputs

Supply the versioned ExchangeOnly configuration and complete raw collection, the exact tenant and recipient matrix, and a current tenant- and recipient-bound entitlement handoff from the licensing owner. The handoff must name its owner and approval reference, cover every evaluated recipient, list exact enabled service plans, and have a future expiry. Also supply current approval, setting exceptions, domain inventory, reporting evidence, and the independently owned DLP or other external handoffs required by the selected retained controls. Missing, stale, malformed, unresolved, or scope-mismatched input stops the procedure; the Exchange operator does not query Graph, grant consent, assign licenses, or configure excluded collaboration workloads to repair it.

### Set

Initialize Microsoft-managed Standard and Strict preset objects in the Defender portal, then use the signed Exchange approved-change workflow to preview only supported existing-object scope, state, and named setting changes. Bind the preview to the exact collected before-state and current approval before using `-Apply`. Apply only retained Exchange controls for entitled recipients. Do not recreate preset backing policies, add MDO-004 or MDO-005 to ExchangeOnly, or substitute a local value for a `MicrosoftRecommendation`.

### Verify

Recollect the complete raw Exchange evidence after the approved change and evaluate it against the same configuration, recipient matrix, entitlement handoff, profile, and catalogue version used for preview. Confirm exact effective-recipient precedence, policy/rule bindings, quarantine permissions, report routing, independent Junk/NotJunk/Phish observations, and every expected/observed catalogue value. Preserve external handoffs as independently owned evidence with readiness `Unverified`; an Exchange readback does not certify licensing, DLP, Safe Documents, SharePoint, OneDrive, or Teams.

### Expected Output

The ExchangeOnly evaluation reports 25 of 25 retained controls with no missing or unknown controls and keeps `Pass`, `NotEntitled`, `ApprovedException`, `Fail`, and `Error` distinct. Historical regression evidence and the public result retain the complete denominator and exit contract:

| Artifact | Profile | Controls | Exit |
| --- | --- | ---: | ---: |
| TST-006 evidence | Historical | 43/43 | n/a |
| TST-006 result | Historical | 43/43 | 0 |

The Historical result preserves MDO-004 and MDO-005 as opt-in references. It does not make them ExchangeOnly defaults or certify those external workloads.

### Recovery

On input, preview, apply, collection, or verification failure, stop and retain all artifacts. Use the signed workflow rollback to restore the captured Exchange before-state, recollect the same full matrix, and record the failed step and owner. Route entitlement, DLP, identity, consent, or excluded-workload gaps back to the named external owner; do not broaden Exchange scope or perform collaboration writes as recovery.

## Effective Settings

1. Obtain a current tenant- and recipient-bound entitlement handoff from the licensing owner. EOP Standard/Strict checks run independently of Defender. Safe Links, Safe Attachments and targeted impersonation require supplied Defender P1/P2 capability; suite labels are not evidence. Tabletop cadence has no Defender P2 requirement.
2. Initialize Standard and Strict in the Defender preset-policy wizard. Assign Strict to the exact approved priority group and Standard to the remaining approved recipients. Review both EOP and, when licensed, Defender scopes. Configure supported preset impersonation targets in that wizard, not by editing individual preset values.
3. Approve MDO-001 `recipientMatrix`: one exact SMTP address per observed mailbox, its expected preset and whether Defender email protection applies. Supply exact current recipient entitlement rows. Confirm nested group membership and exclusions; missing, duplicate, stale, cyclic or unresolvable scope evidence fails closed.
4. The evaluator resolves Strict, then Standard, then custom rule priority, then default or built-in protection for each family. Outbound spam is not part of presets and requires a separately effective outbound policy. A custom rule cannot supersede an applicable preset.
5. Review every entry in [the versioned settings catalogue](../config/exchange-email-settings.v1.json). It enumerates anti-malware, inbound/outbound spam, spoof/DMARC/impersonation, Safe Links email and Safe Attachments email settings. Evidence records effective policy, source and each expected/observed value. Missing fields and typed value drift fail. `LocalPolicy` identifies choices without a Microsoft recommendation; do not advertise them as Microsoft defaults.
6. Use approved, owner-bound, expiring `settingExceptions` only for an effective non-preset policy and an exact recipient/family/setting. ApprovedException remains distinct from Pass. Exceptions cannot authorize unsupported Microsoft-managed preset mutation. Reconcile unused or misbound exceptions before approval.
7. Inspect effective quarantine tags and permissions as well as notification cadence. Standard/Strict non-high-risk categories use their documented full-access policies, not a universal limited-access default. High-confidence phishing and malware remain admin-only. A local limited-access custom policy requires explicit scope and precedence approval.

The signed change workflow supports preset scope/state and named existing-object adapters; it does not manufacture preset backing policies or provide arbitrary setting writes. When a catalogue setting lacks a supported adapter, stop and obtain a separately reviewed Exchange change, then recollect the full matrix. Preview, current approval, exact before/after readback and rollback are mandatory for automated changes. Rollback restores captured configuration, not messages already delivered or processed.

## Reporting

1. Approve exactly one Exchange Online user or shared mailbox in MDO-006. Distribution groups, external recipients and forwarded mailboxes are refused. Keep `SECURITY_OPERATIONS_MAILBOX` consistent with that address.
2. In Defender Settings > Email & collaboration > User reported settings, initialize the single policy and rule. Select the built-in Outlook report button, Microsoft and the reporting mailbox. The existing-object adapter requires `DefaultReportSubmissionPolicy` and its bound reporting rule; it will not silently create replacements.
3. Approve pre-submit and post-submit feedback settings. These booleans are local experience choices. The `ReportSubmission` scope sets all Junk, NotJunk and Phish switches and address lists, enables Microsoft reporting, updates the bound rule destination and enables the rule. A policy address alone is not a rule binding.
4. Under Advanced delivery > SecOps mailbox, initialize the SecOps policy/rule for that exact mailbox. The `SecOpsOverride` scope requires the existing enforcing rule and updates addresses using the supported `AddSentTo`/`RemoveSentTo` delta API. No domain, group or wildcard exception is accepted. Third-party phishing simulation and other non-TABL bypass inventories are separate EXR-007-A02 work, not implicitly authorized here.
5. Obtain current DLP-owner evidence for that exact mailbox: excluded where needed or explicitly not applicable. The Exchange workflow does not alter Purview DLP. Keep this handoff separate from Exchange configuration conformance.
6. Supply `reportingEvidence` in parameters; the frozen evidence payload carries `ReportingEvidence`. Bind the mailbox, current approval and DLP approval. Include one independent observation for each category `Junk`, `NotJunk`, `Phish`: messageId, microsoftSubmissionId, feedbackMessageId, reporter, recipient, originalMessagePreserved and receivedAt. The evaluator rejects missing/duplicate identifiers, wrong recipients, altered originals, future timestamps and observations older than 30 days.
7. Recollect policy, rule, exact mailbox and SecOps readback after the approved change. A readback pass is not proof that a report was delivered. Offline fixtures prove only contract behavior; authorized actual delivery and feedback acceptance are authored/executed under EXR-016/017. AIR is a separately entitled P2 feature, not a prerequisite for the basic reporting contract.

## Allow/Block Exceptions

MDO-007 requires investigated exact entries, owner and expiry. Do not use permanent broad allows or broad SecOps exclusions as an onboarding shortcut. Use Microsoft submissions to investigate false positives and repair authentication at the sender. Broader bypass inventory and third-party simulation governance remain the separately ranked EXR-007-A02 card.

## Sources And Evidence

| Source | Controls | Evidence and procedure |
| --- | --- | --- |
| S14: [Recommended email settings](https://learn.microsoft.com/defender-office-365/recommended-settings-for-eop-and-office365) | MDO-001/002/008/009, EXO-004 | Versioned setting catalogue, raw effective-recipient matrix and quarantine readback; R-MDO-001/002/008/009 |
| S10/S13: [Preset policies](https://learn.microsoft.com/defender-office-365/preset-security-policies) | MDO-001/002/003 | EOP/ATP rules, recursive membership, all applicable policy families and recipient entitlements; R-MDO-001/002/003 |
| S11: [Custom reporting mailbox](https://learn.microsoft.com/defender-office-365/submissions-user-reported-messages-custom-mailbox) | MDO-006 | Mailbox, reporting policy/rule, three delivery observations and feedback; R-MDO-006 |
| [Advanced delivery](https://learn.microsoft.com/defender-office-365/advanced-delivery-policy-configure) | MDO-006 | Exact SecOps mailbox, enforcing rule, supported policy delta and external DLP evidence |

Tests exercise raw collection, evaluation, frozen evidence and signed apply/rollback with synthetic inputs. They do not certify live service serialization, actual delivery, externally supplied entitlement authority or tenant-wide readiness.