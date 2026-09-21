# Exchange Online with Defender: Implementation Guide

**Active entrypoint:** [Exchange-only execution](EXCHANGE-ONLY.md).

**Approved scoped changes:** follow [Approved Exchange Change](APPROVED-CHANGE.md) for executable preview/approval/validation/apply/readback/rollback commands and external signing prerequisites. A console WhatIf transcript is not an approved artifact.

**Historical reference only:** all procedures below describe the former cross-workload journey, not the default Exchange-only profile. They require explicit historical opt-in and are not instructions to provision excluded services. EXR-012 owns the comprehensive rewrite.

Authoritative-source review date: **2026-09-16**.

This guide is the ordered narrative. [RUNBOOKS.md](RUNBOOKS.md) carries the setting-level detail for every control: portal path, exact cmdlet and value, verification command, and expected output. Work through this guide and open the linked runbook at each step.

## 0. Choose a Profile and Confirm Entitlement

**Profile.** If a third-party SMTP gateway fronts your mail, use `config/exchange-online-secure-baseline.json` and complete section 3. If not, use `config/exchange-online-secure-baseline.microsoft-native.json` and skip section 3 entirely.

The two are not interchangeable. `Assert-Configuration` fails closed if Enhanced Filtering is enabled without a declared gateway, or if gateway connectors are declared without one. Enhanced Filtering exists to recover the true originating IP from behind a non-Microsoft hop; with no such hop, its skip list discards genuine connecting IPs.

**Entitlement.** Read [LICENSING-GATE.md](LICENSING-GATE.md), identify your SKUs, and set `licensing.messagingTier` and `licensing.complianceTier` in the baseline. Controls above the declared tier report `NotEntitled` rather than failing. Declaring a tier you do not hold surfaces as a cmdlet error the first time the tooling touches the capability.

## 1. Decide and Record the Service Boundary

Confirm licensing for Exchange Online, Defender for Office 365, Microsoft Purview Audit, and Defender XDR. Name accountable owners for messaging, DNS, the gateway vendor if any, identity, SIEM, and incident response. Record data residency, retention, recovery, legal hold, and delegated-administration requirements before provisioning users.

Use least-privileged, just-in-time roles. Exchange Administrator and Security Administrator are preferred for their respective tasks; reserve Global Administrator for emergency or otherwise impossible operations. Use separate administrator and daily-use identities with phishing-resistant MFA and Conditional Access. See [R-EXO-010](RUNBOOKS.md#r-exo-010-exchange-rbac-hygiene).

## 2. Prepare the Domain and Identities

1. Add and verify the custom domain in Microsoft 365.
2. Keep the accepted domain `Authoritative` when every valid recipient is in Exchange Online. Use `InternalRelay` only for a documented split-domain design. See [R-EXO-001](RUNBOOKS.md#r-exo-001-accepted-domain-type).
3. Create the mail-enabled priority-users group and SecOps mailbox from the parameter file.
4. License pilot users and verify mailbox provisioning.
5. Block legacy authentication with Conditional Access and disable SMTP AUTH tenant-wide. Grant exceptions only to named service mailboxes using OAuth where no modern alternative exists; record an owner and expiry. See [R-EXO-002](RUNBOOKS.md#r-exo-002-disable-smtp-auth-tenant-wide) and [R-EXO-003](RUNBOOKS.md#r-exo-003-block-legacy-authentication).

## 3. Establish Gateway Mail Flow (gateway profile only)

Skip this section entirely in the Microsoft-native profile, and complete [R-PP-005](RUNBOOKS.md#r-pp-005-no-undeclared-partner-inbound-connector) instead to confirm no leftover Partner inbound connector accepts mail for your domains.

The intended paths are:

```text
Inbound:  Internet -> Gateway -> EOP/MDO -> Exchange Online
Outbound: Exchange Online -> Gateway -> Internet
```

1. Obtain the current public sending ranges, smart hosts, TLS certificate name, SPF record, MX target, and ARC support directly from the contracted vendor's documentation or support channel.
2. Create a Partner inbound connector constrained by all current public source IPs and require TLS. See [R-PP-001](RUNBOOKS.md#r-pp-001-gateway-inbound-connector).
3. Enable Enhanced Filtering for Connectors on that connector. Include every non-Microsoft public hop. Pilot with test recipients first if this is an existing production flow; then apply to the whole organization. See [R-PP-002](RUNBOOKS.md#r-pp-002-enhanced-filtering-for-connectors).
4. Disable transport rules that set SCL to `-1`. Do not add vendor ranges to the connection-filter IP allow list. Both patterns suppress Microsoft protection signals.
5. Create a Partner outbound connector to the approved smart hosts with domain-validated TLS. See [R-PP-003](RUNBOOKS.md#r-pp-003-gateway-outbound-connector).
6. Change MX only after connector validation and rollback tests. Prevent direct internet delivery to the tenant's `*.mail.protection.outlook.com` target using the constrained Partner connector design; MX alone is not a security boundary.
7. If the gateway modifies messages and supports ARC sealing, configure its verified ARC sealing domain as a trusted ARC sealer. Never guess this domain. See [R-PP-004](RUNBOOKS.md#r-pp-004-trusted-arc-sealer).

Validate with messages from external SPF-pass, SPF-fail, DKIM-pass, and DMARC-fail sources. Confirm the `X-MS-Exchange-ExternalOriginalInternetSender` and `X-MS-Exchange-SkipListedInternetSender` headers and review the Threat protection status report.

## 4. Enable Microsoft Protection

1. In `https://security.microsoft.com/presetSecurityPolicies`, initialize Standard and Strict preset policies. Microsoft does not recommend manually recreating the backing policies and rules.
2. Assign Standard to the accepted domain, excluding priority users and the SecOps mailbox. See [R-MDO-001](RUNBOOKS.md#r-mdo-001-standard-preset-assignment).
3. Assign Strict to the mail-enabled priority-users group. Strict has higher precedence than Standard. See [R-MDO-002](RUNBOOKS.md#r-mdo-002-strict-preset-assignment).
4. Keep Built-in protection enabled with no broad exceptions. It remains fallback Safe Links and Safe Attachments coverage. See [R-MDO-003](RUNBOOKS.md#r-mdo-003-built-in-protection).
5. Enable Safe Attachments for SharePoint, OneDrive, and Teams. Block infected-file download in SharePoint administration. See [R-MDO-004](RUNBOOKS.md#r-mdo-004-safe-attachments-for-sharepoint-onedrive-and-teams).
6. Enable Safe Documents when licensed and keep user bypass disabled. See [R-MDO-005](RUNBOOKS.md#r-mdo-005-safe-documents).
7. Deploy the Microsoft Report Message/Report Phishing experience. Send reports to Microsoft and a copy to SecOps. See [R-MDO-006](RUNBOOKS.md#r-mdo-006-user-submissions).
8. Configure the global quarantine notification cadence. Leave the preset-assigned quarantine policies alone: they already place malware and high-confidence phish under admin-only access. See [R-MDO-008](RUNBOOKS.md#r-mdo-008-quarantine-policies-and-notifications).
9. Use Tenant Allow/Block List submissions for temporary, investigated exceptions. Avoid permanent sender/domain allows and security-policy bypass rules. See [R-MDO-007](RUNBOOKS.md#r-mdo-007-tenant-allowblock-list).

Preset values are Microsoft-managed and can change as threats evolve. Use the current [recommended settings tables](https://learn.microsoft.com/defender-office-365/recommended-settings-for-eop-and-office365) as the authority, not a frozen transcription.

## 5. Harden the Exchange Online Service

Threat policies protect message content. These controls reduce the service's own attack surface and are independent of licence tier.

1. Turn off automatic external forwarding, then sweep existing mailbox forwarding separately. See [R-EXO-004](RUNBOOKS.md#r-exo-004-disable-automatic-external-forwarding).
2. Set a monitored external postmaster address. See [R-EXO-005](RUNBOOKS.md#r-exo-005-external-postmaster-address).
3. Confirm default mailbox auditing is on and remove every audit bypass association. See [R-EXO-006](RUNBOOKS.md#r-exo-006-mailbox-auditing).
4. Enable external sender identification and keep the allow list empty. See [R-EXO-007](RUNBOOKS.md#r-exo-007-external-sender-identification).
5. Apply the approved local remote-domain policy: the sample blocks external OOF with `AllowedOOFType None`; `External` requires an explicitly approved external-reply policy reference. Verify Default and every specific domain override. Forwarding, client-rule replies and NDR settings are independent business choices, not universal Microsoft defaults. See [R-EXO-008](RUNBOOKS.md#r-exo-008-default-remote-domain) for dated Microsoft semantics and override stop conditions.
6. Restrict the legacy protocol surface: EWS disabled by local default, POP and IMAP off for new and existing mailboxes. A temporary EWS exception requires current retirement support, enforced exact user-agent and application-ID lists, effective mailbox readback, owner, approval, expiry, client impact and disabled rollback. Exceptions are reported separately from disabled-default conformance; no post-April-2027 enablement is offered. See [R-EXO-009](RUNBOOKS.md#r-exo-009-legacy-protocol-restriction), Microsoft sources reviewed 2026-09-20.
7. Remove user add-in acquisition from the default role assignment policy and deploy approved add-ins centrally. See [R-EXO-012](RUNBOOKS.md#r-exo-012-outlook-add-in-acquisition).
8. Publish MTA-STS in `enforce` mode and a TLS-RPT reporting address. See [R-EXO-011](RUNBOOKS.md#r-exo-011-mta-sts-and-tls-rpt).

## 6. Configure Email Authentication

1. Configure DKIM in Exchange Online with 2048-bit keys while disabled.
2. Retrieve `Selector1CNAME` and `Selector2CNAME` using `Get-DkimSigningConfig`. Since May 2025, new domains can use a dynamic partition in the CNAME target; do not construct targets manually.
3. Publish both exact CNAME records, wait for DNS propagation, and enable DKIM only when status becomes `Valid`. See [R-AUTH-001](RUNBOOKS.md#r-auth-001-dkim).
4. Publish one SPF TXT record using the value approved for your actual outbound path. End with `-all` after all legitimate senders are represented; never publish multiple SPF records. See [R-AUTH-002](RUNBOOKS.md#r-auth-002-spf).
5. Stage DMARC monitoring during domain discovery, then reach `p=reject; pct=100; sp=reject`. The baseline represents the target state. Review aggregate reports throughout rollout. See [R-AUTH-003](RUNBOOKS.md#r-auth-003-dmarc).
6. Test every sanctioned bulk sender and SaaS system for aligned DKIM or SPF before enforcement.

## 7. Onboard Post-Delivery Vendors (gateway profile only)

Treat Abnormal as downstream, API-based post-delivery processing, not an SMTP hop.

1. Use the vendor's current Microsoft 365 onboarding workflow and a separately approved enterprise application.
2. Review requested delegated/application permissions, publisher verification, data handling, and remediation scope. Grant only what the contracted features require. See [R-ABN-002](RUNBOOKS.md#r-abn-002-abnormal-security-permissions).
3. Do not create an Exchange connector, journaling route, SCL bypass, or transport exception for Abnormal unless a separately reviewed vendor feature explicitly requires it. See [R-ABN-001](RUNBOOKS.md#r-abn-001-abnormal-security-integration-mode).
4. Restrict consent administration, monitor service-principal sign-ins, and perform access reviews every 90 days.
5. Forward Abnormal cases, health events, and remediation telemetry to the central SIEM. Test detection, message removal, restoration, and audit attribution.

## 8. Establish Governance

Use the [Exchange governance contract](EXCHANGE-GOVERNANCE.md), with independently approved identity, records, legal and per-mailbox licensing inputs. A suite name or planning tier is not entitlement evidence.

1. Verify Exchange organization auditing and bypass state (EXO-006), the complete Exchange RBAC graph (EXO-010), and prohibited end-user add-in grants (EXO-012).
2. Resolve the approved Exchange MRM policy, linked tag semantics, mailbox assignment and successful processing. MRM is not Purview retention or preservation.
3. Verify the named legal custodian inventory, hold duration/owner, mailbox class, entitlement and Recoverable Items capacity. Do not infer legal scope from priority-user groups.
4. Apply only explicitly approved existing-object scopes through signed preview and rollback; verify Exchange IRM and approved encryption rules against independent recipient-flow evidence.
5. Obtain tenant audit retention, DLP, labels, eDiscovery and preservation evidence from external owners under RAID-I02/D03. This walkthrough does not provision them.

Missing entitlement or approval blocks the affected Exchange control. External readiness remains Unverified even when the Exchange checks pass.

## 9. Centralize Monitoring

Send Defender XDR incidents and alerts, Office 365 unified audit records, Exchange admin activity, Entra logs, Purview DLP events, and any vendor telemetry to the designated SIEM. Use supported Microsoft connectors/APIs rather than legacy Exchange reporting cmdlets, many of which no longer return useful data. See [R-MON-001](RUNBOOKS.md#r-mon-001-central-telemetry).

Daily operations must review service health, high-severity incidents, connector failures, outbound spam, restricted users, campaigns, submissions, and vendor integration health. Weekly operations must review message-flow anomalies, spoof detections, override usage, false positives, and control drift. Quarterly governance must review privileged access, app consent, connectors, transport rules, accepted domains, DKIM age/status, retention, and vendor source ranges.

Run `Test-ExchangeOnlineBaseline.ps1` after every approved change and on a schedule. Retain its JSON evidence with the change record for at least 180 days or the organization's longer regulatory period. See [R-MON-003](RUNBOOKS.md#r-mon-003-drift-evidence).

## 10. Rollout and Recovery

1. Pilot with representative users for at least five business days.
2. Establish measurable exit criteria: no unexplained delivery failures, expected authentication results, working submissions, visible SIEM events, and successful incident-response exercises.
3. Expand by business cohort. Do not weaken controls globally to address one sender; repair sender authentication or use narrow, expiring exceptions.
4. Keep previous DNS values, connector settings, assignments, and test messages in the rollback record.
5. For an outage, prefer reverting the most recent scoped change. Never introduce an unauthenticated open relay or broad SCL bypass as a recovery step.

See [R-OPS-001](RUNBOOKS.md#r-ops-001-change-safety) for the change procedure and [R-OPS-002](RUNBOOKS.md#r-ops-002-incident-exercise) for the exercise cadence.

## Go-Live Gate

The active Exchange procedure is [collect, freeze, sign and verify](EXCHANGE-GO-LIVE.md). A collection-only exit `0` is not a go-live decision: use the documented `-SignEvidence` and `-GoLive` invocations with all required hash, age and signer inputs. In-scope `Manual`, `NotEntitled`, missing and unknown evidence cannot be accepted as Pass. Approved deviations remain `ApprovedException`; external readiness remains Unverified even after the signed Exchange gate exits `0`. External owners must independently establish service-launch readiness.

## Authoritative References

See [RUNBOOKS.md](RUNBOOKS.md#authoritative-references).
