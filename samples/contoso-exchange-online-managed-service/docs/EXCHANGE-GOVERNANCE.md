# Approved Exchange Governance

This contract implements EXR-009 for ExchangeOnly. It does not authorize legal policy, tenant identity changes, Purview policy provisioning, RMS activation, or service launch. External readiness remains Unverified. Review date: 2026-09-21.

## Inputs and Ownership

Create an approved copy of `config/exchange-only.v1.json` and supply its path as `ConfigurationPath` to the journey, change workflow and evidence collector. The shipped `approval: null` and empty inventories deliberately fail governance evaluation. Do not substitute a fabricated ticket, inferred suite entitlement, generic retention period, or priority-user membership.

Each governance control requires `approval` with `reference`, `owner` and future `expiresOn`. These are configuration bindings to independently administered approvals, not cryptographic proof by themselves. Protect the configuration and obtain the existing CMS change approval over its resolved hash. Legal/records and identity owners approve the actual population and semantics; RAID-D02/D03 provide identity and licensing evidence, RAID-D05 provides signing authority. Approvers must validate the underlying records before signing.

| Control | Required contract | Exchange observation | External outcome |
| --- | --- | --- | --- |
| EXO-006 | Organization auditing enabled, no unauthorized bypass | `Get-OrganizationConfig`, complete `Get-MailboxAuditBypassAssociation` | Tenant audit retention/ingestion is RAID-I02/D03; mailbox action sets remain EXR-007-A07 |
| EXO-010 | Exact `approvedRoleGroups`, `approvedMembers`, `assignments`, `scopes`, `effectiveUsers`, `mailboxPolicies` | Groups/members, ordinary and effective role assignments, management scopes, all role-assignment policies and mailbox bindings | Entra/PIM, linked-partner provenance and application RBAC are not inferred from Exchange |
| GOV-003 | `policyType: ExchangeMRM`, `policyName`, `tags`, `maximumProcessingAgeDays`, `mailboxEntitlement` | Policy tag links, resolved tag type/action/age/enabled state, mailbox assignment/processing flags/archive state, organization ELC flag, MRM diagnostics | Purview preservation remains Unverified |
| GOV-004 | `enabled`, exact `custodians`/`holds`, `minimumRecoverableItemsFreeBytes` | Active/inactive/soft-deleted mailboxes, hold duration/owner, Recoverable Items quota and statistics | Legal case authorization, preservation outcomes and entitlement authority remain external |
| GOV-005 | IRM values, `decryptionApproval`, `messageClasses` and current independent recipient observations | IRM, complete transport-rule predicates/exceptions, approved sender/recipient functional test and supplied flow records | RMS activation, keys, labels and actual delivery acceptance remain external |

### RBAC

Each assignment approves Identity, Role, RoleAssignee, RoleAssigneeType, Delegating, Enabled, RecipientReadScope, RecipientWriteScope, ConfigReadScope, ConfigWriteScope, CustomRecipientWriteScope, CustomConfigWriteScope, ExclusiveRecipientWriteScope and ExclusiveConfigWriteScope. Each scope approves Identity, RecipientRoot, RecipientRestrictionFilter, ServerRestrictionFilter and Exclusive. Effective rows require nonempty method/chain provenance and exact approved assignment/user pairs. Nested effective users not present in the approval fail. Partner-linked groups fail unresolved rather than certifying external membership.

`mailboxPolicies` contains mailbox/policy pairs for the complete observed population, including nondefault policies. Prohibited My Custom Apps, My Marketplace Apps and My ReadWriteMailboxApps assignments fail even when listed in the approval. `GovernanceMailboxPolicy` changes existing mailbox bindings only; it neither grants roles nor creates/removes groups. An unapproved graph requires a separate explicitly reviewed Exchange RBAC change and fresh evidence. Application mailbox access is EXR-007-A03.

### MRM

Each tag contains `name`, `type`, `action`, numeric `ageDays` and Boolean `enabled`. Each mailbox entitlement contains `identity` and Boolean `archive`; enabled MoveToArchive tags require active archives and independently supplied entitlement. Every observed mailbox must have the approved policy, no retention hold, no ELC processing block and a successful `ELCLastSuccessTimestamp` within the approved positive age limit. Missing, ambiguous, stale or future diagnostics fail.

`GovernanceMrm` changes existing tag action/age/enabled state, policy tag links and explicitly listed mailbox assignments. Tag types are immutable prerequisites; new tags, archives and processing-block removal require separate approval. Verify every consumer before modifying a shared tag. Rollback restores settings only: it cannot undo deletions or archive moves already performed by MRM. Records-owner approval must accept that operational risk. MRM is not preservation, and neither a matching name nor a Purview distribution status proves MRM behavior.

### Holds

Each `holds` row contains `mailbox`, `durationDays`, `owner`, `mailboxClass` (Active/Inactive/SoftDeleted) and Boolean `entitled`. Custodians must resolve exactly once across the three classes. The owner and duration must match the legal approval, and a mailbox outside the approved inventory must not be on litigation hold. Recoverable Items free capacity must exceed the approved threshold; unknown sizes fail. Duplicate inactive/soft-deleted rows for the same Exchange GUID are deduplicated, not double-counted.

Hold creation, alteration or release is not an automatic baseline action. The legal owner authorizes a separate Exchange procedure and its recovery decision. Never remove a legal hold merely to restore a baseline snapshot. Tenant case management is RAID-I02/D03, not an Exchange-only procedure.

### Encryption

Each `messageClasses` row contains `name`, `rule`, `header`, `recipients`, `template`, `sender` and Boolean `entitled`. This version supports an enabled enforced Exchange rule with exactly the HeaderContains and SentTo predicates, no exceptions, the approved class value and the approved rights template. Additional conditions are not silently ignored. Protection-removal rules and earlier enabled stopping rules fail conservatively. Classification-header integrity is an externally approved design prerequisite, not proof that arbitrary senders classify messages correctly.

`decryptionApproval` explicitly binds `transport` and Boolean `journal` to the configured transport and journal decryption values. No decryption setting is a universal legal recommendation. `GovernanceEncryption` changes existing rule settings and Exchange IRM only; it does not initialize RMS or create rules. Disabled rules, unsupported predicates and other rule conflicts must be separately resolved and reverified.

Parameters supply `governanceEvidence.recipientFlows`. Each record has `Class`, `Recipient`, Boolean `Protected`, `AuthorizedDecryption`, `UnauthorizedRejected`, an independently traceable `EvidenceReference`, and `ObservedAtUtc` no older than 24 hours and not in the future. Exactly one record is required per approved class/recipient, alongside a successful `Test-IRMConfiguration` for the approved sender and recipient. Boolean assertions without an independently verifiable source are not production acceptance. Offline tests use explicitly synthetic records; authorized live delivery testing is EXR-016/017.

## Change and Evidence Sequence

1. Resolve and independently approve the complete governance configuration and entitlement records. Validate legal, records, identity and recipient population before any preview.
2. Connect to the authorized Exchange tenant using the existing journey. Use the [approved change workflow](APPROVED-CHANGE.md) with the approved configuration path and only the needed scopes: `GovernanceMailboxPolicy`, `GovernanceMrm`, `GovernanceEncryption`.
3. Review exact targets, typed before/after values, tag consumers, irreversible processing risk and recovery decisions. Obtain independent CMS approval. A changed configuration or parameter file invalidates the preview.
4. Validate and apply the signed operations. Missing commands/properties, unauthorized settings and drift stop processing. Configuration-only rollback restores captured values and refuses later administrator drift; it is not data recovery or release of legal obligations.
5. Run the public collector and [frozen evidence gate](EXCHANGE-GO-LIVE.md) using the same configuration path and bindings. Collection errors, warning/truncation signals and incomplete raw records do not become Pass. Passing a scoped change is not passing the complete baseline.

Evidence paths remain `exchangeOnline.roleAssignment`, `purview.retentionPolicy`, `purview.litigationHold` and `purview.irmConfiguration` for compatibility. The historical `purview` key does not imply a Purview collector: these retained records are collected from Exchange. ExternalReady is never inferred from them.

## Verification and Sources

Negative-first semantic tests are in `tests/unit/ExchangeGovernance.Tests.ps1`; raw public collection tests in `ExchangeGovernanceRaw.Tests.ps1`; signed public apply/rollback tests in `ExchangeGovernanceAdapters.Tests.ps1`; documentation exclusions in `ExchangeGovernanceDocumentation.Tests.ps1`. The administrator journey also runs with a pilot and a separately unheld shared mailbox. All verification here is offline; Exchange service serialization and actual message delivery still require EXR-016/017.

Microsoft source mappings are S09 (Exchange permissions), S19 (MRM tags/policies), S20 (litigation hold) and S21 (Message Encryption) in [the dated source inventory](../config/exchange-recommendations.v1.json). Policy populations, legal durations, capacity thresholds, approval expiry and processing-age limits are local decisions, not universal Microsoft defaults.