# Solution Summary

Every claim below maps to a control ID in the [control catalog](samples/contoso-exchange-online-managed-service/docs/CONTROL-CATALOG.md), a runbook in [RUNBOOKS.md](samples/contoso-exchange-online-managed-service/docs/RUNBOOKS.md), and a field in the evidence JSON produced by `Test-ExchangeOnlineBaseline.ps1`. A claim without all three is not made.

## What This Repository Is

An evidence-oriented baseline for onboarding a net-new business entity to Exchange Online, Exchange Online Protection, and Microsoft Defender for Office 365, in two deployment profiles:

| Profile | Mail path | Configuration |
| --- | --- | --- |
| **Microsoft-native** | Internet → EOP → Exchange Online | `config/exchange-online-secure-baseline.microsoft-native.json` |
| **Third-party gateway** | Internet → gateway → EOP → Exchange Online | `config/exchange-online-secure-baseline.json` |

Protection comes from Microsoft's **preset security policies** (Standard for the organization, Strict for priority users). The repository does not transcribe individual preset values into local configuration; those values are Microsoft-managed and change as threats evolve. Freezing a local copy is recorded as `BAD-010`.

## Supported Solution

`samples/contoso-exchange-online-managed-service/`

| Path | Purpose |
| --- | --- |
| `config/exchange-online-secure-baseline.json` | Third-party gateway desired state |
| `config/exchange-online-secure-baseline.microsoft-native.json` | Microsoft-native desired state |
| `config/exchange-online-secure-baseline.schema.json` | Schema, including the gateway conditional |
| `config/parameters.sample.json` | Administrator input contract (gateway profile) |
| `config/parameters.microsoft-native.sample.json` | Administrator input contract (native profile) |
| `scripts/Deploy-ExchangeOnlineBaseline.ps1` | WhatIf-by-default, idempotent deployment |
| `scripts/Test-ExchangeOnlineBaseline.ps1` | Live control tests and JSON evidence export |
| `tests/SecureBaseline.Tests.ps1` | Static Pester guardrails |
| `docs/IMPLEMENTATION-GUIDE.md` | End-to-end setup and operating guide |
| `docs/RUNBOOKS.md` | Per-control portal path, cmdlet, value, verification, expected output |
| `docs/CONTROL-CATALOG.md` | MUST / SHOULD / AVOID control matrix |
| `docs/LICENSING-GATE.md` | Which controls each licence tier entitles |
| `dashboard/index.html` | Local evidence viewer |

## Quarantined

`deprecated/mdo-baseline-config-custom-policies/` is not a supported deployment path. It built custom EOP/MDO policies from transcribed values, never created the matching policy rules, and called cmdlets with parameters that do not exist. `Deploy-MDOBaseline.ps1` refuses to run. See [deprecated/README.md](deprecated/README.md) for the recorded defects and migration steps.

## Control Coverage

**Status key** — `Automated`: applied by `Deploy-ExchangeOnlineBaseline.ps1`. `Verified`: checked by `Test-ExchangeOnlineBaseline.ps1` against live tenant state. `Manual`: owned by DNS, Entra, Purview, SharePoint, or the SIEM, with a runbook and a verification command, but not applied from the Exchange Online session.

### Exchange Online hardening

| Control | Status | Applied by | Evidence field |
| --- | --- | --- | --- |
| EXO-001 Accepted domain authoritative | Verified | Manual (portal) | `evidence.acceptedDomain` |
| EXO-002 SMTP AUTH disabled | Automated + Verified | `Set-TransportConfig` | `evidence.transport` |
| EXO-003 Legacy auth blocked | Manual | Conditional Access | Entra policy export |
| EXO-004 Auto external forwarding off | Automated + Verified | `Set-HostedOutboundSpamFilterPolicy` | `evidence.outboundSpam` |
| EXO-005 External postmaster | Automated + Verified | `Set-TransportConfig` | `evidence.transport` |
| EXO-006 Mailbox auditing on | Automated + Verified | `Set-OrganizationConfig` | `evidence.organization` |
| EXO-007 External sender tagging | Automated + Verified | `Set-ExternalInOutlook` | `evidence.externalInOutlook` |
| EXO-008 Default remote domain hardened | Automated + Verified | `Set-RemoteDomain` | `evidence.remoteDomain` |
| EXO-009 Legacy protocols restricted | Automated + Verified | `Set-OrganizationConfig`, `Set-CASMailboxPlan` | `evidence.organization`, `evidence.casMailboxPlans` |
| EXO-010 RBAC hygiene | Manual | PIM and role groups | `evidence.roleGroups` |
| EXO-011 MTA-STS and TLS-RPT | Manual | DNS and HTTPS policy host | DNS query in runbook |
| EXO-012 Outlook add-in acquisition | Manual | `Remove-ManagementRoleAssignment` | Role assignment export |

### Defender for Office 365

| Control | Status | Applied by | Evidence field |
| --- | --- | --- | --- |
| MDO-001 Standard preset assigned | Automated + Verified | `Set-EOPProtectionPolicyRule`, `Set-ATPProtectionPolicyRule` | `evidence.standardEop`, `evidence.standardAtp` |
| MDO-002 Strict preset assigned | Automated + Verified | Same, scoped to priority users | `evidence.strictEop`, `evidence.strictAtp` |
| MDO-003 Built-in protection unexcluded | Automated + Verified | `Set-ATPBuiltInProtectionRule` | `evidence.builtInProtection` |
| MDO-004 Safe Attachments for SPO/ODB/Teams | Automated + Verified | `Set-AtpPolicyForO365` | `evidence.atpGlobal` |
| MDO-005 Safe Documents, no bypass | Automated + Verified | `Set-AtpPolicyForO365` | `evidence.atpGlobal` |
| MDO-006 User submissions | Manual | `Set-ReportSubmissionPolicy` | Defender portal export |
| MDO-007 Tenant Allow/Block List hygiene | Manual | `New-TenantAllowBlockListItems` | TABL export |
| MDO-008 Quarantine notification cadence | Automated + Verified | `Set-QuarantinePolicy` | `evidence.quarantineGlobal` |
| MDO-009 Priority account protection | Manual | Portal user tags | Portal export |

### Mail gateway

| Control | Status | Applied by | Evidence field |
| --- | --- | --- | --- |
| PP-001 Gateway inbound connector constrained | Automated + Verified | `New-`/`Set-InboundConnector` | `evidence.inboundConnector` |
| PP-002 Enhanced Filtering enabled | Automated + Verified | `Set-InboundConnector` | `evidence.inboundConnector` |
| PP-003 Gateway outbound connector | Automated + Verified | `New-`/`Set-OutboundConnector` | `evidence.outboundConnector` |
| PP-004 Trusted ARC sealer | Manual | `Set-ArcConfig` | Authentication-Results header |
| PP-005 No undeclared Partner inbound (native profile) | Verified | — | `evidence.partnerInboundConnectors` |

### Email authentication

| Control | Status | Applied by | Evidence field |
| --- | --- | --- | --- |
| AUTH-001 DKIM enabled and valid | Partly automated + Verified | `New-`/`Set-DkimSigningConfig`; CNAMEs published manually in DNS | `evidence.dkim` |
| AUTH-002 SPF single record, `-all` | Manual | Authoritative DNS | `Resolve-DnsName` in runbook |
| AUTH-003 DMARC `p=reject` | Manual | Authoritative DNS | `Resolve-DnsName` in runbook |

DKIM key creation and enablement are automated; the CNAME records are not, because DNS is outside the Exchange Online boundary. SPF and DMARC are DNS records with no Exchange Online cmdlet at all.

### Governance and monitoring

| Control | Status | Tier | Evidence |
| --- | --- | --- | --- |
| MON-001 Central telemetry | Manual | EOP | SIEM connector health plus synthetic alert |
| MON-002 Unified audit log | Manual | EOP | `Search-UnifiedAuditLog` result |
| MON-003 Drift evidence | Automated | EOP | Timestamped evidence JSON, 180-day retention |
| OPS-001 Change safety | Automated | EOP | WhatIf output attached to change record |
| OPS-002 Incident exercise | Manual | MDO P2 | Attack simulation report |
| GOV-001 Audit retention policy | Manual | E5 Compliance | `Get-UnifiedAuditLogRetentionPolicy` |
| GOV-002 Exchange DLP policy | Manual | E3 | `Get-DlpCompliancePolicy` |
| GOV-003 Mailbox retention policy | Manual | E3 | `Get-RetentionCompliancePolicy` |
| GOV-004 Litigation hold | Manual | E3 | `Get-Mailbox` filtered on `LitigationHoldEnabled` |
| GOV-005 Information Rights Management | Manual | E3 | `Get-IRMConfiguration`, `Test-IRMConfiguration` |
| GOV-006 Sensitivity labels | Manual | E5 Compliance | `Get-Label`, `Get-LabelPolicy` |
| GOV-007 eDiscovery readiness | Manual | E5 Compliance | `Get-RoleGroupMember`, `Get-ComplianceCase` |

Purview controls run in a Security & Compliance PowerShell session (`Connect-IPPSSession`), not the Exchange Online session, which is why they are reported `Manual` rather than automated.

## Licensing Gate

Declare the tenant's entitlement once:

```json
"licensing": { "messagingTier": "MDO_P2", "complianceTier": "E5Compliance" }
```

Controls above the declared tier report `NotEntitled` and do not fail the run. At `EOP`, the tooling assigns the EOP half of the presets and skips the Safe Links and Safe Attachments half. See [LICENSING-GATE.md](samples/contoso-exchange-online-managed-service/docs/LICENSING-GATE.md) for the full matrix and the SKU lookup.

## Deployment Model

| Stage | Command | Outcome |
| --- | --- | --- |
| Static validation | `Invoke-Pester ./tests/SecureBaseline.Tests.ps1` | Configuration guardrails |
| Preview | `./scripts/Deploy-ExchangeOnlineBaseline.ps1 -ParameterPath <file>` | Every supported cmdlet invoked with `-WhatIf` |
| Apply | Same command with `-Apply` | Changes made under an approved change record |
| Evidence | `./scripts/Test-ExchangeOnlineBaseline.ps1 -ParameterPath <file>` | JSON evidence, non-zero exit on any `Fail` |

`Assert-Configuration` fails closed before any tenant call on: SCL `-1` bypass rules, SMTP AUTH enabled, automatic external forwarding not `Off`, Enhanced Filtering enabled with no gateway declared, gateway connectors declared with no gateway, a declared gateway with no Enhanced Filtering skip list, and Abnormal configured as an SMTP hop.

## Security Boundary

The deployment script configures supported Exchange Online controls only. It does not automate DNS, licensing, Conditional Access, Privileged Identity Management, SIEM ingestion, SharePoint tenant settings, Microsoft Purview, gateway vendor administration, or OAuth consent. Those cross-system steps have separate owners, approvals, and evidence, and each has a runbook with a verification command.

## Not Covered

Recorded so the gap is explicit rather than implied:

- Mobile device management and Intune app protection for Outlook.
- Insider risk management, communication compliance, and information barriers.
- Public folder migration and hybrid Exchange coexistence.
- Backup and third-party archiving beyond native retention and litigation hold.
- Microsoft Teams, SharePoint, and OneDrive governance other than Safe Attachments (`MDO-004`).

## Review Cadence

Microsoft-managed preset values evolve. Review the [authoritative references](samples/contoso-exchange-online-managed-service/docs/RUNBOOKS.md#authoritative-references) at least quarterly and update the `reviewedOn` date in the baseline configuration. Do not copy individual preset values into custom policies.

---

**Version**: 2.0.0
**Last reviewed**: 2026-09-16

The templates and information in this repository are provided as examples, "as is, where is" without warranty of any kind. This is not an official Microsoft product and does not replace or represent any official Microsoft product or service.
