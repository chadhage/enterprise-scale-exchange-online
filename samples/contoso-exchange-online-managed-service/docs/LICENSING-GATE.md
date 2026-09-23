# Licensing And Capability Gate

The supported ExchangeOnly workflow consumes a supplied licensing-owner handoff. It does not assign licenses, query Graph, create app registrations, grant consent or infer entitlement from suite names. Tenant licensing administration is external RAID-D02/I04 work. Historical Native/Gateway tier declarations are not authority for ExchangeOnly.

## Required Inputs

Supply `entitlement` in the parameter document with the exact tenant, covered Exchange recipient scope, enabled service-plan names and a current expiry. MDO-001 also requires current per-recipient plan rows matching the approved `recipientMatrix`. The workflow cannot establish the independent truth of a supplied handoff; its owner and approval must be accepted outside this Exchange configuration assessment.

The current versioned workflow requires the explicit Exchange service plan `EXCHANGE_S_ENTERPRISE`. It does not yet model every Exchange plan or shared-mailbox licensing alternative. Do not substitute a suite name, invent a service-plan assignment or claim unsupported recipient licensing is verified. Stop for an approved capability-model update when the supplied plans differ.

## Optional Capability Attestations

The handoff may include `entitlement.capabilityAttestations`. Each entry names exactly `PriorityAccountProtection` or `AutomatedInvestigation`, a Boolean `entitled`, and a nonempty array of unique valid recipient addresses:

```text
"capabilityAttestations": [
  {
    "capability": "PriorityAccountProtection",
    "entitled": true,
    "recipients": ["priority@contoso.example"]
  },
  {
    "capability": "AutomatedInvestigation",
    "entitled": true,
    "recipients": ["priority@contoso.example"]
  }
]
```

This is a member of the existing entitlement object, not an independent handoff. Both capabilities inherit the parent's matching valid tenant ID, Boolean `verified: true`, nonempty `owner` and `reference`, covered recipient domain and future `expiresOn`. The parent and every affected recipient still require `EXCHANGE_S_ENTERPRISE`; Defender capability use also requires tenant and recipient `ATP_ENTERPRISE`. An affirmative attestation never replaces these prerequisites. All attested addresses must match exactly one recipient-license row, and the requested recipient matrix must be contained in the attested scope. An attestation for one licensed recipient does not authorize another licensed recipient outside that scope. Duplicate capability records and malformed Boolean or scope values do not grant entitlement.

Trust remains externally accepted through the licensing owner under RAID-D02. The workflow checks the supplied contract, not issuer cryptography or the independent truth of license assignments. There is no new P2 service-plan identifier: `ATP_ENTERPRISE`, suite labels, impersonation settings, reporting evidence and tabletop cadence cannot affirm either optional P2 capability.

Collection, independent evaluation and action admission use the same typed capability decision rules. `DeploymentEntitlement.Capability` contains named Boolean decisions with recipient scope and a `Reason`; `NotEntitled` lists unconfirmed capabilities. Reasons retain human-readable refusal prefixes and include a separate `Category:` line for expiry, tenant binding, scope, malformed evidence, missing tenant/recipient Exchange or Defender entitlement, and unconfirmed capability. Categories belong to the named decision, not to an unrelated capability.

Missing or invalid optional P2 evidence yields a false decision without blocking otherwise valid EOP/P1 planning. Invalid mandatory parent or recipient prerequisites refuse `-ForActionPlanning` and public approved-change preview before adapter reads, writes or a preview artifact. EOP requires Exchange entitlement, not Defender. Actual setting drift remains `Fail`, including BuiltIn settings that do not meet Standard requirements; entitlement does not make those settings conformant.

Capability entitlement is separate from operational readiness. Even a true P2 decision leaves operational readiness unverified: AIR operation, audit configuration, permissions, priority-account tags and reporting delivery require their own observations. Missing operational evidence cannot be converted into Pass by a licensing attestation.

## Capability Boundaries

| Capability | Supplied entitlement | Result without capability |
| --- | --- | --- |
| Standard and Strict EOP policies | Supported Exchange entitlement | Exchange validation cannot proceed without its required handoff |
| Safe Links and Safe Attachments email, built-in Defender protection | `ATP_ENTERPRISE` for the tenant and affected recipients | Defender controls remain NotEntitled; EOP evaluation still runs |
| Targeted user/domain impersonation | Defender P1/P2 email capability, represented by `ATP_ENTERPRISE` | MDO-009 remains NotEntitled; spoof/EOP settings are still evaluated |
| P2 priority-account capabilities, AIR | Separately confirmed scoped `PriorityAccountProtection` / `AutomatedInvestigation` attestations | Typed false decisions when unconfirmed; not inferred from P1 or operational evidence |
| OPS-002 Exchange tabletop | Supported Exchange entitlement | Tabletop cadence has no P2 mandate; missing exercise evidence is not a licensing skip |
| MRM/archive, hold and encryption | Exact per-mailbox or feature evidence in the governance contract | Missing capability evidence fails the applicable governance check |

Safe Documents and SharePoint/OneDrive/Teams are excluded workloads, not unlicensed retained Exchange controls. They are not part of this setup or release claim.

Attack Simulation Training entitlement is not modeled by these two optional capability names.

## Results

- `Pass`: the applicable retained check met its contract using current supplied inputs and observations.
- `Fail`: observed state contradicts an applicable requirement.
- `Error`: evidence is incomplete, malformed or unavailable; this is not a pass.
- `NotEntitled`: a required capability is not confirmed. This remains a visible non-passing retained result, not whole-baseline compliance.
- `ApprovedException`: a current exact exception is accepted separately from Pass.
- External readiness remains `Unverified`; Exchange conformance does not certify licensing authority, identity, DLP or other external dependencies.

Do not change a desired-state tier merely to hide a missing capability or failed cmdlet. Reconcile the handoff with the licensing owner and rerun the same checks.

## Before Changes

1. Confirm tenant, recipient scope, plan status and expiry with the licensing owner.
2. Approve the recipient matrix and identify recipients requiring Defender email protection.
3. Initialize EOP presets in the Defender portal. Initialize Defender presets only for externally confirmed licensed recipients. Never manually recreate Microsoft-managed preset backing policies.
4. Preview supported Exchange changes, obtain the configured signed approval, apply and recollect exact raw evidence.
5. Stop on unconfirmed entitlement. Record the gap and owner rather than presenting an EOP-only tenant as a fully passing Defender baseline.

See [Exchange email protection](EXCHANGE-EMAIL-PROTECTION.md) for settings, precedence, report routing and independent delivery evidence, and [Exchange governance](EXCHANGE-GOVERNANCE.md) for per-mailbox legal/archive/encryption inputs. Source: [Microsoft preset policies](https://learn.microsoft.com/defender-office-365/preset-security-policies), reviewed 2026-09-21.
