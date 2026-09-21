# Control Catalog

`MUST` controls are onboarding gates. `SHOULD` controls require a documented risk acceptance when omitted. `AVOID` entries are known weakening patterns.

**Columns**

- **Profile** — `Both`, `Native` (Microsoft-native only), or `Gateway` (third-party SMTP gateway only).
- **Tier** — the minimum licence that entitles the control. Controls above the declared tier are reported `NotEntitled`, not `Fail`. See [LICENSING-GATE.md](LICENSING-GATE.md).
- **Runbook** — the step-level procedure in [RUNBOOKS.md](RUNBOOKS.md).

## Versioned Evidence Sources

Microsoft Configuration Analyzer is a supplemental correlation source. Its signed, sanitized results can corroborate or contradict a known applicable control, but cannot create or replace that control's authoritative evidence.

| Identity | Version | Evidence role | Control scope | Authoritative control evidence |
| --- | --- | --- | --- | --- |
| MicrosoftConfigurationAnalyzer | 1.0.0 | Supplemental | ApplicableKnownControls | Required |

## Exchange Online Service Hardening

| ID | Priority | Profile | Tier | Setting or practice | Required state | Evidence | Runbook |
| --- | --- | --- | --- | --- | --- | --- | --- |
| EXO-001 | MUST | Both | EOP | Accepted domain | `Authoritative` for cloud-only recipients | `Get-AcceptedDomain` | [R-EXO-001](RUNBOOKS.md#r-exo-001-accepted-domain-type) |
| EXO-002 | MUST | Both | EOP | SMTP AUTH | Disabled tenant-wide | `Get-TransportConfig` | [R-EXO-002](RUNBOOKS.md#r-exo-002-disable-smtp-auth-tenant-wide) |
| EXO-003 | MUST | Both | EOP | Legacy authentication | Blocked by Conditional Access | Entra policy export and sign-in test | [R-EXO-003](RUNBOOKS.md#r-exo-003-block-legacy-authentication) |
| EXO-004 | MUST | Both | EOP | Automatic external forwarding | `Off` | `Get-HostedOutboundSpamFilterPolicy` | [R-EXO-004](RUNBOOKS.md#r-exo-004-disable-automatic-external-forwarding) |
| EXO-005 | SHOULD | Both | EOP | External postmaster | Monitored business address | `Get-TransportConfig` | [R-EXO-005](RUNBOOKS.md#r-exo-005-external-postmaster-address) |
| EXO-006 | MUST | Both | EOP | Mailbox auditing | On by default; no audit bypass associations | `Get-OrganizationConfig`, `Get-MailboxAuditBypassAssociation` | [R-EXO-006](RUNBOOKS.md#r-exo-006-mailbox-auditing) |
| EXO-007 | MUST | Both | EOP | External sender identification | Enabled; allow list empty or ticketed | `Get-ExternalInOutlook` | [R-EXO-007](RUNBOOKS.md#r-exo-007-external-sender-identification) |
| EXO-008 | MUST | Both | EOP | Default and effective specific remote domains | Local block-external-OOF policy: `None`; `External` only with explicit external-reply approval. Forwarding, client-rule replies and reports retain approved business choices, sample off. Not universal Microsoft defaults. Microsoft semantics reviewed 2026-09-20. | `Get-RemoteDomain` | [R-EXO-008](RUNBOOKS.md#r-exo-008-default-remote-domain) |
| EXO-009 | MUST | Both | EOP | Legacy protocol surface | EWS disabled by local default; supported temporary exceptions require enforced exact user-agent and AppID lists, effective mailbox checks, owner and expiry; POP/IMAP off for new and existing mailboxes | `Get-OrganizationConfig`, `Get-CASMailboxPlan`, `Get-CASMailbox` | [R-EXO-009](RUNBOOKS.md#r-exo-009-legacy-protocol-restriction) |
| EXO-010 | MUST | ExchangeOnly | Supplied Exchange entitlement | Exchange RBAC hygiene | Approved effective admin/end-user graph, scopes and mailbox policy bindings; external provenance unresolved fails | Role groups/members, direct/effective assignments, management scopes, mailbox policies | [Contract](EXCHANGE-GOVERNANCE.md#rbac) |
| EXO-011 | SHOULD | Both | EOP | MTA-STS and TLS-RPT | `mode: enforce` policy published; TLS reports delivered to a monitored address | DNS query plus HTTPS policy fetch | [R-EXO-011](RUNBOOKS.md#r-exo-011-mta-sts-and-tls-rpt) |
| EXO-012 | SHOULD | Both | EOP | Outlook add-in acquisition | User-installed add-ins disabled in the default role assignment policy | `Get-RoleAssignmentPolicy`, `Get-ManagementRoleAssignment` | [R-EXO-012](RUNBOOKS.md#r-exo-012-outlook-add-in-acquisition) |

## Microsoft Defender for Office 365

| ID | Priority | Profile | Tier | Setting or practice | Required state | Evidence | Runbook |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MDO-001 | MUST | Both | EOP | Standard preset | Enabled for all normal recipients | EOP and ATP policy-rule exports | [R-MDO-001](RUNBOOKS.md#r-mdo-001-standard-preset-assignment) |
| MDO-002 | MUST | Both | EOP | Strict preset | Enabled for priority users | Group membership plus policy-rule exports | [R-MDO-002](RUNBOOKS.md#r-mdo-002-strict-preset-assignment) |
| MDO-003 | MUST | Both | MDO P1 | Built-in protection | Enabled; no broad exclusions | `Get-ATPBuiltInProtectionRule` | [R-MDO-003](RUNBOOKS.md#r-mdo-003-built-in-protection) |
| MDO-004 | MUST | Both | MDO P1 | Safe Attachments for SPO/ODB/Teams | Enabled | `Get-AtpPolicyForO365` | [R-MDO-004](RUNBOOKS.md#r-mdo-004-safe-attachments-for-sharepoint-onedrive-and-teams) |
| MDO-005 | SHOULD | Both | MDO P2 | Safe Documents | Enabled when licensed; no click-through | `Get-AtpPolicyForO365` | [R-MDO-005](RUNBOOKS.md#r-mdo-005-safe-documents) |
| MDO-006 | MUST | Both | EOP | User submissions | Microsoft reporting enabled; SecOps receives copy | Defender portal export and functional test | [R-MDO-006](RUNBOOKS.md#r-mdo-006-user-submissions) |
| MDO-007 | MUST | Both | EOP | Tenant allow/block entries | Investigated, scoped, owner and expiry | TABL export plus ticket | [R-MDO-007](RUNBOOKS.md#r-mdo-007-tenant-allowblock-list) |
| MDO-008 | MUST | Both | EOP | Quarantine policies | End users get limited access; malware and high-confidence phish are admin-only; notifications daily | `Get-QuarantinePolicy` | [R-MDO-008](RUNBOOKS.md#r-mdo-008-quarantine-policies-and-notifications) |
| MDO-009 | SHOULD | Both | MDO P2 | Priority account protection | Priority accounts tagged; premium mitigations applied | Defender portal user-tag export | [R-MDO-009](RUNBOOKS.md#r-mdo-009-priority-account-protection) |

## Mail Gateway (third-party SMTP gateway profile only)

Every control below is `NotApplicable` in the Microsoft-native profile. `Assert-Configuration` rejects a configuration that enables Enhanced Filtering without declaring a gateway, and rejects gateway connectors when no gateway is declared.

| ID | Priority | Profile | Tier | Setting or practice | Required state | Evidence | Runbook |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PP-001 | MUST | Gateway | EOP | Gateway inbound connector | Partner, enabled, TLS, constrained sources | `Get-InboundConnector` | [R-PP-001](RUNBOOKS.md#r-pp-001-gateway-inbound-connector) |
| PP-002 | MUST | Gateway | EOP | Enhanced Filtering | Enabled with every non-Microsoft public hop | Connector export and message headers | [R-PP-002](RUNBOOKS.md#r-pp-002-enhanced-filtering-for-connectors) |
| PP-003 | MUST | Gateway | EOP | Gateway outbound connector | Partner smart hosts with domain validation | `Get-OutboundConnector` and validation test | [R-PP-003](RUNBOOKS.md#r-pp-003-gateway-outbound-connector) |
| PP-004 | SHOULD | Gateway | EOP | Trusted ARC sealer | Verified gateway domain when supported | ARC configuration and Authentication-Results headers | [R-PP-004](RUNBOOKS.md#r-pp-004-trusted-arc-sealer) |
| PP-005 | MUST | Native | EOP | No undeclared Partner inbound connector | Zero enabled Partner inbound connectors | `Get-InboundConnector` | [R-PP-005](RUNBOOKS.md#r-pp-005-no-undeclared-partner-inbound-connector) |

## Email Authentication

| ID | Priority | Profile | Tier | Setting or practice | Required state | Evidence | Runbook |
| --- | --- | --- | --- | --- | --- | --- | --- |
| AUTH-001 | MUST | Both | EOP | DKIM | Enabled, valid, 2048-bit for sending domains | `Get-DkimSigningConfig` and DNS query | [R-AUTH-001](RUNBOOKS.md#r-auth-001-dkim) |
| AUTH-002 | MUST | Both | EOP | SPF | One approved record; `-all` target state | Authoritative DNS query | [R-AUTH-002](RUNBOOKS.md#r-auth-002-spf) |
| AUTH-003 | MUST | Both | EOP | DMARC | `p=reject; pct=100; sp=reject` target state | Authoritative DNS query and aggregate reports | [R-AUTH-003](RUNBOOKS.md#r-auth-003-dmarc) |

## Third-Party Post-Delivery Integration

| ID | Priority | Profile | Tier | Setting or practice | Required state | Evidence | Runbook |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ABN-001 | MUST | Gateway | EOP | Abnormal integration | Microsoft API post-delivery mode | Enterprise app, vendor health, test case | [R-ABN-001](RUNBOOKS.md#r-abn-001-abnormal-security-integration-mode) |
| ABN-002 | MUST | Gateway | EOP | Abnormal permissions | Least privilege; reviewed every 90 days | Consent export and access-review record | [R-ABN-002](RUNBOOKS.md#r-abn-002-abnormal-security-permissions) |

## Monitoring and Operations

| ID | Priority | Profile | Tier | Setting or practice | Required state | Evidence | Runbook |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MON-001 | MUST | Both | EOP | Central telemetry | All declared sources present in SIEM | Connector health and synthetic alert | [R-MON-001](RUNBOOKS.md#r-mon-001-central-telemetry) |
| MON-002 | MUST | Both | EOP | Unified audit | Enabled and retained | Purview audit search/export | [R-MON-002](RUNBOOKS.md#r-mon-002-unified-audit-log) |
| MON-003 | MUST | Both | EOP | Drift evidence | Scheduled collection; minimum 180-day retention | Timestamped evidence JSON | [R-MON-003](RUNBOOKS.md#r-mon-003-drift-evidence) |
| OPS-001 | MUST | Both | EOP | Change safety | WhatIf, pilot, approval, rollback, validation | Change record | [R-OPS-001](RUNBOOKS.md#r-ops-001-change-safety) |
| OPS-002 | SHOULD | Both | MDO P2 | Incident exercise | Quarterly phish/remediation tabletop or simulation | Exercise record and actions | [R-OPS-002](RUNBOOKS.md#r-ops-002-incident-exercise) |

## Exchange Governance and External Handoffs

| ID | Priority | Profile | Tier | Setting or practice | Required state | Evidence | Runbook |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GOV-001 | MUST | Both | E5 Compliance | Audit retention | Retention policy covering the regulatory period | `Get-UnifiedAuditLogRetentionPolicy` | [R-GOV-001](RUNBOOKS.md#r-gov-001-audit-retention-policy) |
| GOV-002 | MUST | Both | E3 | Exchange DLP | At least one enforced policy covering the regulated data classes | `Get-DlpCompliancePolicy`, `Get-DlpComplianceRule` | [R-GOV-002](RUNBOOKS.md#r-gov-002-exchange-dlp-policy) |
| GOV-003 | MUST | ExchangeOnly | Per-mailbox MRM/archive entitlement | Exchange MRM | Approved tags, assignment and successful processing; preservation separately Unverified | Policy/tag/mailbox/ELC/diagnostic readback | [Contract](EXCHANGE-GOVERNANCE.md#mrm) |
| GOV-004 | MUST | ExchangeOnly | Per-mailbox hold entitlement | Litigation hold | Legal custodian/duration/owner/class and capacity; no automatic priority-user holds | All mailbox classes and Recoverable Items statistics | [Contract](EXCHANGE-GOVERNANCE.md#holds) |
| GOV-005 | SHOULD | ExchangeOnly | Supplied Message Encryption/RMS entitlement | Exchange encryption | Approved business classes, rule scope, recipient flow and explicit decryption authorization | IRM, transport rules, functional and independent recipient observations | [Contract](EXCHANGE-GOVERNANCE.md#encryption) |
| GOV-006 | SHOULD | Both | E5 Compliance | Sensitivity labels | Published to messaging users with an encryption label | `Get-Label`, `Get-LabelPolicy` | [R-GOV-006](RUNBOOKS.md#r-gov-006-sensitivity-labels) |
| GOV-007 | SHOULD | Both | E5 Compliance | eDiscovery readiness | Named case owners; role group membership reviewed | `Get-ComplianceCase`, `Get-RoleGroupMember` | [R-GOV-007](RUNBOOKS.md#r-gov-007-ediscovery-readiness) |

## Practices to Avoid

GOV-001/002/006/007 above are external handoff references only under RAID-I02/D03, excluded from the ExchangeOnly manifest. They are not provisioning tasks or Exchange conformance claims.

| ID | AVOID | Why |
| --- | --- | --- |
| BAD-001 | SCL `-1` rules for gateway traffic | Bypasses Microsoft spam/phish evaluation and degrades signals |
| BAD-002 | Adding gateway IPs to connection-filter allow lists | Over-trusts all traffic from a shared gateway |
| BAD-003 | Trusting MX records as the only ingress control | Senders can deliver directly to the tenant endpoint |
| BAD-004 | Broad permanent sender/domain allows | Creates durable impersonation and malware paths |
| BAD-005 | Disabling Built-in, Safe Links, or Safe Attachments because a gateway scans first | Removes defense in depth and post-delivery capabilities |
| BAD-006 | Routing Abnormal through SMTP | Adds loops and bypass risk to an API-oriented integration |
| BAD-007 | Guessing gateway IPs, TLS names, ARC domains, or DKIM CNAMEs | Vendor and Microsoft values are tenant/service specific and change |
| BAD-008 | Global Administrator for routine operations | Violates least privilege and expands credential impact |
| BAD-009 | Enabling SMTP AUTH globally for one application | Exposes every mailbox to an unnecessary legacy protocol |
| BAD-010 | Freezing custom copies of preset-policy values | Misses Microsoft-managed threat-setting updates |
| BAD-011 | Enabling Enhanced Filtering with no gateway declared | Skip lists without a real upstream hop discard genuine connecting IPs |
| BAD-012 | Creating a custom EOP/MDO policy without its matching rule | The policy has no recipient scope and silently protects nobody |
| BAD-013 | Blocking common business file types in the anti-malware common attachment filter | Quarantines routine mail and drives users to unmanaged channels |
| BAD-014 | Granting end users full quarantine release rights for malware or high-confidence phish | Lets users restore confirmed-malicious mail |
