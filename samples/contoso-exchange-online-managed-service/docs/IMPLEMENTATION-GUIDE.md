# Exchange Online with Defender: Implementation Guide

Authoritative-source review date: **2026-09-14**.

## 1. Decide and Record the Service Boundary

Confirm licensing for Exchange Online, Defender for Office 365 Plan 2, Microsoft Purview Audit, Defender XDR, and Safe Documents. Name accountable owners for messaging, DNS, Proofpoint, Abnormal, identity, SIEM, and incident response. Record data residency, retention, recovery, legal hold, and delegated-administration requirements before provisioning users.

Use least-privileged, just-in-time roles. Exchange Administrator and Security Administrator are preferred for their respective tasks; reserve Global Administrator for emergency or otherwise impossible operations. Use separate administrator and daily-use identities with phishing-resistant MFA and Conditional Access.

## 2. Prepare the Domain and Identities

1. Add and verify the custom domain in Microsoft 365.
2. Keep the accepted domain `Authoritative` when every valid recipient is in Exchange Online. Use `InternalRelay` only for a documented split-domain design.
3. Create the mail-enabled priority-users group and SecOps mailbox from the parameter file.
4. License pilot users and verify mailbox provisioning.
5. Block legacy authentication with Conditional Access and disable SMTP AUTH tenant-wide. Grant exceptions only to named service mailboxes using OAuth where no modern alternative exists; record an owner and expiry.

## 3. Establish Proofpoint Mail Flow

The intended paths are:

```text
Inbound:  Internet -> Proofpoint -> EOP/MDO -> Exchange Online
Outbound: Exchange Online -> Proofpoint -> Internet
```

1. Obtain the current Proofpoint public sending ranges, smart hosts, TLS certificate name, SPF record, MX target, and ARC support directly from the contracted Proofpoint service documentation or support channel.
2. Create a Partner inbound connector constrained by all current public Proofpoint source IPs and require TLS.
3. Enable Enhanced Filtering for Connectors on that connector. Include every non-Microsoft public hop. Pilot with test recipients first if this is an existing production flow; then apply to the whole organization.
4. Disable transport rules that set SCL to `-1`. Do not add Proofpoint ranges to the connection-filter IP allow list. Both patterns suppress Microsoft protection signals.
5. Create a Partner outbound connector to the approved Proofpoint smart hosts with domain-validated TLS.
6. Change MX only after connector validation and rollback tests. Prevent direct internet delivery to the tenant's `*.mail.protection.outlook.com` target using the constrained Partner connector design; MX alone is not a security boundary.
7. If Proofpoint modifies messages and supports ARC sealing, configure its verified ARC sealing domain as a trusted ARC sealer. Never guess this domain.

Validate with messages from external SPF-pass, SPF-fail, DKIM-pass, and DMARC-fail sources. Confirm the `X-MS-Exchange-ExternalOriginalInternetSender` and `X-MS-Exchange-SkipListedInternetSender` headers and review the Threat protection status report.

## 4. Enable Microsoft Protection

1. In `https://security.microsoft.com/presetSecurityPolicies`, initialize Standard and Strict preset policies. Microsoft does not recommend manually recreating the backing policies and rules.
2. Assign Standard to the accepted domain, excluding priority users and the SecOps mailbox.
3. Assign Strict to the mail-enabled priority-users group. Strict has higher precedence than Standard.
4. Keep Built-in protection enabled with no broad exceptions. It remains fallback Safe Links and Safe Attachments coverage.
5. Enable Safe Attachments for SharePoint, OneDrive, and Teams. Block infected-file download in SharePoint administration.
6. Enable Safe Documents when licensed and keep user bypass disabled.
7. Deploy the Microsoft Report Message/Report Phishing experience. Send reports to Microsoft and a copy to SecOps.
8. Use Tenant Allow/Block List submissions for temporary, investigated exceptions. Avoid permanent sender/domain allows and security-policy bypass rules.

Preset values are Microsoft-managed and can change as threats evolve. Use the current [recommended settings tables](https://learn.microsoft.com/defender-office-365/recommended-settings-for-eop-and-office365) as the authority, not a frozen transcription.

## 5. Configure Email Authentication

1. Configure DKIM in Exchange Online with 2048-bit keys while disabled.
2. Retrieve `Selector1CNAME` and `Selector2CNAME` using `Get-DkimSigningConfig`. Since May 2025, new domains can use a dynamic partition in the CNAME target; do not construct targets manually.
3. Publish both exact CNAME records, wait for DNS propagation, and enable DKIM only when status becomes `Valid`.
4. Publish one SPF TXT record using the value approved for the actual Proofpoint outbound path. End with `-all` after all legitimate senders are represented; never publish multiple SPF records.
5. Stage DMARC monitoring during domain discovery, then reach `p=reject; pct=100; sp=reject`. The baseline represents the target state. Review aggregate reports throughout rollout.
6. Test every sanctioned bulk sender and SaaS system for aligned DKIM or SPF before enforcement.

## 6. Onboard Abnormal Security

Treat Abnormal as downstream, API-based post-delivery processing, not an SMTP hop.

1. Use the vendor's current Microsoft 365 onboarding workflow and a separately approved enterprise application.
2. Review requested delegated/application permissions, publisher verification, data handling, and remediation scope. Grant only the contracted features require.
3. Do not create an Exchange connector, journaling route, SCL bypass, or transport exception for Abnormal unless a separately reviewed vendor feature explicitly requires it.
4. Restrict consent administration, monitor service-principal sign-ins, and perform access reviews every 90 days.
5. Forward Abnormal cases, health events, and remediation telemetry to the central SIEM. Test detection, message removal, restoration, and audit attribution.

## 7. Centralize Monitoring

Send Defender XDR incidents and alerts, Office 365 unified audit records, Exchange admin activity, Entra logs, Proofpoint telemetry, and Abnormal cases to the designated SIEM. Use supported Microsoft connectors/APIs rather than legacy Exchange reporting cmdlets, many of which no longer return useful data.

Daily operations must review service health, high-severity incidents, connector failures, outbound spam, restricted users, campaigns, submissions, and vendor integration health. Weekly operations must review message-flow anomalies, spoof detections, override usage, false positives, and control drift. Quarterly governance must review privileged access, app consent, connectors, transport rules, accepted domains, DKIM age/status, retention, and vendor source ranges.

Run `Test-ExchangeOnlineBaseline.ps1` after every approved change and on a schedule. Retain its JSON evidence with the change record for at least 180 days or the organization's longer regulatory period.

## 8. Rollout and Recovery

1. Pilot with representative users for at least five business days.
2. Establish measurable exit criteria: no unexplained delivery failures, expected authentication results, working submissions, visible SIEM events, and successful incident-response exercises.
3. Expand by business cohort. Do not weaken controls globally to address one sender; repair sender authentication or use narrow, expiring exceptions.
4. Keep previous DNS values, connector settings, assignments, and test messages in the rollback record.
5. For an outage, prefer reverting the most recent scoped change. Never introduce an unauthenticated open relay or broad SCL bypass as a recovery step.

## Authoritative References

- [Recommended EOP and Defender for Office 365 settings](https://learn.microsoft.com/defender-office-365/recommended-settings-for-eop-and-office365)
- [Preset security policies](https://learn.microsoft.com/defender-office-365/preset-security-policies)
- [Third-party cloud mail flow](https://learn.microsoft.com/exchange/mail-flow-best-practices/manage-mail-flow-using-third-party-cloud)
- [Enhanced Filtering for Connectors](https://learn.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/enhanced-filtering-for-connectors)
- [Configure DKIM](https://learn.microsoft.com/defender-office-365/email-authentication-dkim-configure)
- [Configure DMARC](https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure)
- [Disable SMTP AUTH](https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission)
- [Monitoring and message tracing](https://learn.microsoft.com/exchange/monitoring/monitoring)
- [Microsoft 365 SIEM integration](https://learn.microsoft.com/defender-office-365/siem-server-integration)
- [Zero Trust for Microsoft 365](https://learn.microsoft.com/security/zero-trust/microsoft-365-zero-trust)
