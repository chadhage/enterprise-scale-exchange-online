# Licensing and Capability Gate

Exchange action planning and evidence evaluation consume a supplied licensing-owner handoff. The
handoff must be current, tenant-bound, domain-bound, and recipient-bound, and must explicitly name
`EXCHANGE_S_ENTERPRISE` for Exchange Online plus `ATP_ENTERPRISE` wherever Defender email
capabilities are requested. The offline gate does not assign licenses, query Graph, or connect to
Exchange Online to repair missing evidence. This supplied licensing-owner handoff
does not authorize the Exchange workflow to query Graph or grant consent.

The current projection is deliberately narrow and does not yet model every Exchange plan or infer
entitlement from suite labels such as `SPE_E5`. P2 priority-account capabilities, AIR, and similar
optional features require separate, exact recipient-scoped capability attestations. Those
attestations establish licensing only; operational readiness remains independently evidenced.

Every control in the [control catalog](CONTROL-CATALOG.md) carries a **Tier** for planning.
The labels below are historical planning metadata, never proof of entitlement.
The default ExchangeOnly commands require the supplied handoff and recipient service plans.
Historical Native/Gateway commands require an explicit configuration and `-AllowHistoricalProfile`.

```json
"licensing": {
  "messagingTier": "MDO_P2",
  "complianceTier": "E5Compliance"
}
```

| Field | Allowed values |
| --- | --- |
| `messagingTier` | `EOP`, `MDO_P1`, `MDO_P2` |
| `complianceTier` | `None`, `E3`, `E5Compliance` |

## How the gate behaves

| Outcome | Meaning | Fails the run? |
| --- | --- | --- |
| `Applied` / `Planned` | The control was configured, or would be under `-WhatIf` | — |
| `Pass` / `Fail` | Evidence collection confirmed or contradicted the required state | `Fail` exits non-zero |
| `NotEntitled` | The required capability is not confirmed for the exact recipient scope | Refuses scoped go-live |
| `NotApplicable` | The control belongs to the other deployment profile | No |
| `Manual` | The retained control lacks independently admitted evidence | Refuses go-live |

`NotEntitled` is not a claim that a tenant violated a licensed setting, but it is not a
successful retained-control verdict. The gate cannot certify missing entitlement.
External workloads remain excluded rather than being configured to repair a licensing gap.

## Microsoft Graph Permissions

**Historical collector reference only.** Opt-in historical adapters can read directory
licensing evidence using the four read-only scopes below. These scopes are not requested
by the active ExchangeOnly gate, which consumes the supplied licensing-owner handoff.

| Permission | Type | Read by | Least privilege |
| --- | --- | --- | --- |
| `Organization.Read.All` | Application | `Get-BaselineTenantServicePlan` reading `subscribedSkus` | The tenant subscription inventory is the only entitlement authority, and this is the narrowest scope that returns it. |
| `User.Read.All` | Application | `Get-BaselineTargetPopulation` classifying recipients | Classification needs the account and licence state of every recipient; `User.Read` covers only the signed-in account. |
| `GroupMember.Read.All` | Application | `Get-BaselineTargetPopulation` resolving the Strict priority group | Strict scope is a group membership, not a domain, and this reads membership without reading group content. |
| `LicenseAssignment.Read.All` | Application | `Get-BaselineTargetEntitlement` reading `assignedPlans` | A per-user licence gap is invisible in the tenant inventory; the `.ReadWrite.All` variant would let the tooling change assignments it only needs to read. |

Nothing in the licensing gate writes to the directory. If a reviewer sees a write scope on the app registration, the app registration has drifted from this document and the surplus grant should be removed rather than documented.

## Consent

All four scopes are admin-consent-only. A Global Administrator or Privileged Role Administrator grants tenant-wide administrator consent once, on the app registration the tooling authenticates as; a user consenting for themselves cannot grant them, and a run that assumes user consent fails on the first read.

Historical opt-in: a separate identity owner records the consent grant and its approved
application, read-only scopes, approver and review date. This is an external handoff, not
an Exchange setup step. The active workflow does not grant consent or request directory access.

## Identify your tier

The licensing owner supplies tenant and recipient service-plan evidence. Suite labels in
the historical mapping below are planning hints only and do not replace that evidence.

| If `SkuPartNumber` includes | Set `messagingTier` to |
| --- | --- |
| Only `EXCHANGESTANDARD`, `EXCHANGEENTERPRISE`, `O365_BUSINESS_*`, `SPE_E3`, `ENTERPRISEPACK` | `EOP` |
| `ATP_ENTERPRISE` (Defender for Office 365 Plan 1), `SPB` | `MDO_P1` |
| `THREAT_INTELLIGENCE` (Defender for Office 365 Plan 2), `SPE_E5`, `M365_E5_SUITE_COMPONENTS`, `Microsoft_Defender_Suite` | `MDO_P2` |

| If `SkuPartNumber` includes | Set `complianceTier` to |
| --- | --- |
| No Microsoft 365 suite licence | `None` |
| `SPE_E3`, `ENTERPRISEPACK`, `M365_E3` | `E3` |
| `SPE_E5`, `INFORMATION_PROTECTION_COMPLIANCE`, `M365_E5_COMPLIANCE` | `E5Compliance` |

If the tenant is mixed — some users on E3, some on E5 — declare the **lowest** tier that covers the population the preset policies target, and scope the higher-tier controls to a licensed group with a documented exception.

## Control availability by messaging tier

| Control | `EOP` | `MDO_P1` | `MDO_P2` |
| --- | :---: | :---: | :---: |
| EXO-001 … EXO-012 Exchange hardening | Yes | Yes | Yes |
| MDO-001 Standard preset (EOP policies) | Yes | Yes | Yes |
| MDO-002 Strict preset (EOP policies) | Yes | Yes | Yes |
| MDO-001/002 Safe Links and Safe Attachments preset policies | No | Yes | Yes |
| MDO-003 Built-in protection | No | Yes | Yes |
| MDO-004 Safe Attachments for SharePoint, OneDrive, Teams | No | Yes | Yes |
| MDO-005 Safe Documents | No | No | Only with `SAFEDOCS` |
| MDO-006 User submissions | Yes | Yes | Yes |
| MDO-007 Tenant Allow/Block List | Yes | Yes | Yes |
| MDO-008 Quarantine policies and notifications | Yes | Yes | Yes |
| MDO-009 Priority account protection | No | No | Yes |
| AUTH-001 … AUTH-003 email authentication | Yes | Yes | Yes |
| PP-001 … PP-005 gateway controls | Yes | Yes | Yes |
| Threat Explorer, Automated Investigation and Response, Attack Simulation Training | No | No | Yes |
| OPS-002 Incident exercise via Attack Simulation Training | No | No | Yes |

At `EOP` the Standard and Strict presets still exist and still apply anti-spam, anti-malware, and anti-phishing. Only the Safe Links and Safe Attachments halves of the preset are withheld, which is why the tooling assigns the `EOP*ProtectionPolicyRule` pair unconditionally and the `ATP*ProtectionPolicyRule` pair only when `messagingTier` is `MDO_P1` or higher.

**Safe Documents is the exception to the tier table.** It is not granted by Defender for Office 365 Plan 2. It is granted by the `SAFEDOCS` service plan, which ships in Microsoft 365 E5 and Microsoft 365 E5 Security — a tenant can hold Plan 2 as a standalone add-on and hold no `SAFEDOCS` at all. `MDO_P2` in the row above therefore means *not blocked by tier*, not *entitled*. The tooling never infers Safe Documents from the declared tier or from a Defender plan bundle: it requires an enabled `SAFEDOCS` assignment on the tenant and on every target, matched on the service plan identifier, and treats a `SAFEDOCS` plan that is disabled, suspended, or pending as absent. Declare it explicitly under `safeDocuments.requiredServicePlan`, which is fixed to `SAFEDOCS`.

## Control availability by compliance tier

| Control | `None` | `E3` | `E5Compliance` |
| --- | :---: | :---: | :---: |
| MON-002 Unified audit log (standard retention) | Yes | Yes | Yes |
| GOV-001 Audit retention policy beyond standard retention | No | No | Yes |
| GOV-002 Exchange DLP policy | No | Yes | Yes |
| GOV-003 Mailbox retention policy | No | Yes | Yes |
| GOV-004 Litigation hold | No | Yes | Yes |
| GOV-005 Information Rights Management / Office 365 Message Encryption | No | Yes | Yes |
| GOV-006 Sensitivity labels with automatic labelling | No | No | Yes |
| GOV-007 eDiscovery (Premium) readiness | No | No | Yes |
| Insider risk management, communication compliance, information barriers | No | No | Yes |

## Minimum viable baselines

**Exchange Online Protection only.** Do every `EXO-*`, `AUTH-*`, `MON-*`, and `OPS-001` control, assign the Standard and Strict presets, and configure quarantine policies. Record the absence of Safe Links, Safe Attachments, and Built-in protection as an accepted risk with a review date. This is a defensible baseline; it is not the recommended one.

**Defender for Office 365 Plan 1.** Everything above, plus `MDO-003` and `MDO-004`. The largest remaining gap is post-breach investigation: no Threat Explorer, no automated investigation. Compensate with SIEM detections built on the `EmailEvents` and `EmailPostDeliveryEvents` tables.

**Defender for Office 365 Plan 2 with E5 Compliance.** Every control is entitled with one caveat: Safe Documents still depends on an enabled `SAFEDOCS` service plan rather than on Plan 2, so confirm it in the tenant inventory before you count `MDO-005` as covered. This is the configuration the sample baselines default to.

## Verify before you deploy

```powershell
# Confirm the Defender preset policies exist for the tier you declared.
Get-EOPProtectionPolicyRule | Select-Object Name, State
Get-ATPProtectionPolicyRule | Select-Object Name, State   # empty or error at EOP tier
```

If `Get-ATPProtectionPolicyRule` returns nothing on a tenant you declared as `MDO_P1` or `MDO_P2`, the presets have not been initialized. Open the Defender portal preset page once and complete the wizard, then rerun. Microsoft does not support recreating the backing policies by hand.

Confirm the Safe Documents service plan separately, because no Defender cmdlet will tell you the tenant lacks it:

```powershell
Get-MgSubscribedSku |
    Select-Object -ExpandProperty ServicePlans |
    Where-Object { $_.ServicePlanName -eq 'SAFEDOCS' -and $_.ProvisioningStatus -eq 'Success' }
```

No enabled row means no Safe Documents, whatever the declared tier says.
