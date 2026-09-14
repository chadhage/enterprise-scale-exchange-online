# Control Catalog

`MUST` controls are onboarding gates. `SHOULD` controls require a documented risk acceptance when omitted. `AVOID` entries are known weakening patterns.

| ID | Priority | Setting or practice | Required state | Evidence |
| --- | --- | --- | --- | --- |
| EXO-001 | MUST | Accepted domain | `Authoritative` for cloud-only recipients | `Get-AcceptedDomain` |
| EXO-002 | MUST | SMTP AUTH | Disabled tenant-wide | `Get-TransportConfig` |
| EXO-003 | MUST | Legacy authentication | Blocked by Conditional Access | Entra policy export and sign-in test |
| EXO-004 | MUST | Automatic external forwarding | `Off` | `Get-HostedOutboundSpamFilterPolicy` |
| EXO-005 | SHOULD | External postmaster | Monitored business address | `Get-TransportConfig` |
| MDO-001 | MUST | Standard preset | Enabled for all normal recipients | EOP and ATP policy-rule exports |
| MDO-002 | MUST | Strict preset | Enabled for priority users | Group membership plus policy-rule exports |
| MDO-003 | MUST | Built-in protection | Enabled; no broad exclusions | `Get-ATPBuiltInProtectionRule` |
| MDO-004 | MUST | Safe Attachments for SPO/ODB/Teams | Enabled | `Get-AtpPolicyForO365` |
| MDO-005 | SHOULD | Safe Documents | Enabled when licensed; no click-through | `Get-AtpPolicyForO365` |
| MDO-006 | MUST | User submissions | Microsoft reporting enabled; SecOps receives copy | Defender portal export and functional test |
| MDO-007 | MUST | Tenant allow/block entries | Investigated, scoped, owner and expiry | TABL export plus ticket |
| PP-001 | MUST | Proofpoint inbound connector | Partner, enabled, TLS, constrained sources | `Get-InboundConnector` |
| PP-002 | MUST | Enhanced Filtering | Enabled with every non-Microsoft public hop | Connector export and message headers |
| PP-003 | MUST | Proofpoint outbound connector | Partner smart hosts with domain validation | `Get-OutboundConnector` and validation test |
| PP-004 | SHOULD | Trusted ARC sealer | Verified Proofpoint domain when supported | ARC configuration and Authentication-Results headers |
| AUTH-001 | MUST | DKIM | Enabled, valid, 2048-bit for sending domains | `Get-DkimSigningConfig` and DNS query |
| AUTH-002 | MUST | SPF | One approved record; `-all` target state | Authoritative DNS query |
| AUTH-003 | MUST | DMARC | `p=reject; pct=100; sp=reject` target state | Authoritative DNS query and aggregate reports |
| ABN-001 | MUST | Abnormal integration | Microsoft API post-delivery mode | Enterprise app, vendor health, test case |
| ABN-002 | MUST | Abnormal permissions | Least privilege; reviewed every 90 days | Consent export and access-review record |
| MON-001 | MUST | Central telemetry | Microsoft, Proofpoint, and Abnormal sources in SIEM | Connector health and synthetic alert |
| MON-002 | MUST | Unified audit | Enabled and retained | Purview audit search/export |
| MON-003 | MUST | Drift evidence | Scheduled collection; minimum 180-day retention | Timestamped evidence JSON |
| OPS-001 | MUST | Change safety | WhatIf, pilot, approval, rollback, validation | Change record |
| OPS-002 | SHOULD | Incident exercise | Quarterly phish/remediation tabletop or simulation | Exercise record and actions |

## Practices to Avoid

| ID | AVOID | Why |
| --- | --- | --- |
| BAD-001 | SCL `-1` rules for Proofpoint traffic | Bypasses Microsoft spam/phish evaluation and degrades signals |
| BAD-002 | Adding Proofpoint IPs to connection-filter allow lists | Over-trusts all traffic from a shared gateway |
| BAD-003 | Trusting MX records as the only ingress control | Senders can deliver directly to the tenant endpoint |
| BAD-004 | Broad permanent sender/domain allows | Creates durable impersonation and malware paths |
| BAD-005 | Disabling Built-in, Safe Links, or Safe Attachments because Proofpoint scans first | Removes defense in depth and post-delivery capabilities |
| BAD-006 | Routing Abnormal through SMTP | Adds loops and bypass risk to an API-oriented integration |
| BAD-007 | Guessing Proofpoint IPs, TLS names, ARC domains, or DKIM CNAMEs | Vendor and Microsoft values are tenant/service specific and change |
| BAD-008 | Global Administrator for routine operations | Violates least privilege and expands credential impact |
| BAD-009 | Enabling SMTP AUTH globally for one application | Exposes every mailbox to an unnecessary legacy protocol |
| BAD-010 | Freezing custom copies of preset-policy values | Misses Microsoft-managed threat-setting updates |
