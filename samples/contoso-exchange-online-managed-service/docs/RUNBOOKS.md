# Setting-Level Runbooks

**Active entrypoint:** [Exchange-only execution](EXCHANGE-ONLY.md).

**Historical reference only:** these cross-workload runbooks are retained for historical regression and traceability. They are not the active Exchange-only procedure and do not authorize tenant, Graph, Purview, SIEM or gateway configuration. EXR-012 owns their comprehensive replacement.

Step procedures for every control in the [control catalog](CONTROL-CATALOG.md). Each runbook gives the **portal path**, the **exact cmdlet and value**, a **verification cmdlet**, and the **expected output**.

Authoritative-source review date: **2026-09-16**.

## Before you start

| Step | Command |
| --- | --- |
| Install the module | `Install-Module ExchangeOnlineManagement -MinimumVersion 3.0.0 -Scope CurrentUser` |
| Connect to Exchange Online | `Connect-ExchangeOnline -UserPrincipalName admin@contoso.com` |
| Connect to Security & Compliance (GOV-* runbooks) | `Connect-IPPSSession -UserPrincipalName admin@contoso.com` |
| Connect to Graph (EXO-003, ABN-*, licensing) | `Connect-MgGraph -Scopes 'Policy.Read.All','Organization.Read.All','Application.Read.All'` |

Replace `contoso.com`, `secops@contoso.com`, and `PriorityUsers@contoso.com` with your values. Confirm your entitlement in [LICENSING-GATE.md](LICENSING-GATE.md) before running a runbook marked with a tier above `EOP`.

Every change below is covered by [R-OPS-001](#r-ops-001-change-safety). Run the deployment script without `-Apply` first; it invokes each supported cmdlet with `-WhatIf`.

---

## Exchange Online Service Hardening

### R-EXO-001 Accepted domain type

**Portal** — Exchange admin center → Mail flow → Accepted domains → select the domain → Domain type.

**Set**

```powershell
Set-AcceptedDomain -Identity contoso.com -DomainType Authoritative
```

Use `InternalRelay` only for a documented split-domain design where valid recipients exist outside Exchange Online. `Authoritative` lets Exchange Online reject unknown recipients at the edge instead of generating backscatter.

**Verify**

```powershell
Get-AcceptedDomain -Identity contoso.com | Format-List Name, DomainName, DomainType, Default
```

**Expected**

```text
DomainType : Authoritative
Default    : True
```

---

### R-EXO-002 Disable SMTP AUTH tenant-wide

**Portal** — Microsoft 365 admin center → Settings → Org settings → Modern authentication → clear **Authenticated SMTP**.

**Set**

```powershell
Set-TransportConfig -SmtpClientAuthenticationDisabled $true
```

Grant an exception only to a named service mailbox that has no OAuth alternative, and record an owner and expiry:

```powershell
Set-CASMailbox -Identity scanner@contoso.com -SmtpClientAuthenticationDisabled $false
```

**Verify**

```powershell
Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled
Get-CASMailbox -ResultSize Unlimited |
    Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false } |
    Select-Object PrimarySmtpAddress
```

**Expected**

```text
SmtpClientAuthenticationDisabled : True
```

The second command returns only mailboxes on the approved exception register. Any other result is a finding.

---

### R-EXO-003 Block legacy authentication

**Portal** — Microsoft Entra admin center → Protection → Conditional Access → Policies → New policy.

**Set** — Users: All users, excluding the break-glass accounts. Target resources: All cloud apps. Conditions → Client apps: select **Exchange ActiveSync clients** and **Other clients**. Grant: **Block access**. Enable in report-only first, review sign-in logs, then set to On.

There is no Exchange Online cmdlet for this control. The Graph equivalent is `New-MgIdentityConditionalAccessPolicy`.

**Verify**

```powershell
Get-MgIdentityConditionalAccessPolicy |
    Where-Object { $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or
                   $_.Conditions.ClientAppTypes -contains 'other' } |
    Select-Object DisplayName, State
```

**Expected**

```text
DisplayName                      State
-----------                      -----
Block legacy authentication      enabled
```

Then filter the Entra sign-in logs on **Client app = Other clients** for the last seven days and confirm every entry shows `Failure` with `53003 Blocked by Conditional Access`.

---

### R-EXO-004 Disable automatic external forwarding

**Portal** — Defender portal → Email & collaboration → Policies & rules → Threat policies → Anti-spam → **Anti-spam outbound policy (Default)** → Automatic forwarding rules → **Off — Forwarding is disabled**.

**Set**

```powershell
Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off
```

**Verify**

```powershell
Get-HostedOutboundSpamFilterPolicy | Select-Object Name, AutoForwardingMode
Get-Mailbox -ResultSize Unlimited |
    Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } |
    Select-Object PrimarySmtpAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward
```

**Expected**

```text
Name    AutoForwardingMode
----    ------------------
Default Off
```

The second command returns nothing, or only mailboxes on the approved exception register. `AutoForwardingMode Off` blocks user-created forwarding; it does not remove pre-existing mailbox forwarding, which is why the second check exists.

---

### R-EXO-005 External postmaster address

**Portal** — No portal surface. PowerShell only.

**Set**

```powershell
Set-TransportConfig -ExternalPostmasterAddress postmaster@contoso.com
```

Use a monitored shared mailbox, not a personal mailbox. Non-delivery reports to external senders will carry this address.

**Verify**

```powershell
Get-TransportConfig | Select-Object ExternalPostmasterAddress
```

**Expected**

```text
ExternalPostmasterAddress
-------------------------
postmaster@contoso.com
```

---

### R-EXO-006 Mailbox auditing

**Portal** — No portal surface for the organization default. Purview portal → Audit shows the resulting records.

**Set**

```powershell
Set-OrganizationConfig -AuditDisabled $false
```

Remove any audit bypass associations:

```powershell
Get-MailboxAuditBypassAssociation -ResultSize Unlimited |
    Where-Object { $_.AuditBypassEnabled } |
    ForEach-Object { Set-MailboxAuditBypassAssociation -Identity $_.Identity -AuditBypassEnabled $false }
```

**Verify**

```powershell
Get-OrganizationConfig | Select-Object AuditDisabled
Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Where-Object { $_.AuditBypassEnabled }
```

**Expected**

```text
AuditDisabled
-------------
        False
```

The second command returns nothing. An audit bypass association silently suppresses mailbox audit records for that identity, which defeats `MON-002`.

---

### R-EXO-007 External sender identification

**Portal** — No portal surface. PowerShell only.

**Set**

```powershell
Set-ExternalInOutlook -Enabled $true
```

Keep the allow list empty. Every entry removes the external tag for that sender and is a phishing opportunity:

```powershell
Set-ExternalInOutlook -Enabled $true -AllowList @()
```

**Verify**

```powershell
Get-ExternalInOutlook | Format-List Enabled, AllowList
```

**Expected**

```text
Enabled   : True
AllowList : {}
```

Allow up to 24–48 hours for the tag to appear in Outlook clients.

---

### R-EXO-008 Default remote domain

**Portal** — Exchange admin center → Mail flow → Remote domains → **Default**.

**Set**

```powershell
Set-RemoteDomain -Identity Default `
    -AutoForwardEnabled $false `
    -AutoReplyEnabled $false `
    -AllowedOOFType None `
    -DeliveryReportEnabled $false `
    -NDREnabled $false
```

This sample implements the locally approved **block-external-OOF** policy: `AllowedOOFType None` sends no OOF to recipients in the remote domain. `InternalLegacy` instead permits internal replies and undesignated legacy replies; it can also set `IsInternal` to true. It is not an internal-disclosure protection. `ExternalLegacy` permits undesignated legacy replies and is not an approved option here.

Microsoft documents `External` as the service default: only replies designated external are sent. Use `External` only when the Exchange service owner has explicitly approved an external-reply policy. In configuration, set `allowedOOFType` to `External` and supply a nonblank `externalReplyApproval` change/policy reference. This reference records the policy decision, not cryptographic approval or proof of authorization; the deployment approval gate still applies. Mailbox automatic-reply audience/settings can further restrict delivery. `AutoReplyEnabled` governs client-rule automatic replies and is not a substitute for `AllowedOOFType`.

The forwarding, client-rule auto-reply, delivery-report and NDR values above are separate local business choices, not universal Microsoft best-practice defaults. In particular, disabling NDRs can suppress useful failure notices. Preserve approved choices in the four corresponding configuration properties when changing OOF policy.

**Microsoft sources, reviewed 2026-09-20:** [Set-RemoteDomain: AllowedOOFType, IsInternal, AutoReplyEnabled and NDREnabled](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-remotedomain?view=exchange-ps) and [Remote domains in Exchange Online](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/remote-domains/remote-domains). The date is this repository's review date, not the publication date.

**Verify**

```powershell
Get-RemoteDomain -ErrorAction Stop |
    Format-List Identity, DomainName, AutoForwardEnabled, AutoReplyEnabled, AllowedOOFType, DeliveryReportEnabled, NDREnabled, IsInternal
```

**Expected**

```text
Identity              : Default
DomainName            : *
AutoForwardEnabled    : False
AutoReplyEnabled      : False
AllowedOOFType        : None
DeliveryReportEnabled : False
NDREnabled            : False
```

The wildcard Default covers domains without a more specific remote-domain entry. Specific domains (including wildcard subdomain entries) take precedence, so **every returned domain** must have the selected OOF value and the approved forwarding/reporting values. Default alone is not sufficient readback. `IsInternal` is displayed to expose the side effect of a previous `InternalLegacy` configuration; do not silently change domain trust as part of OOF repair.

Deployment validates the policy and enumerates remote domains before organization writes. A conflicting specific OOF entry stops with `RemoteDomainOverrideConflict`; missing Default or failed collection also stops. The approved deployment operation still targets Default only. Have the Exchange change owner approve an identity-scoped change for each conflicting override, preserving its independently approved forwarding/NDR settings, then repeat all-domain verification and the approved deployment workflow. This runbook's default command is a settings reference, not a substitute for that workflow. The evaluator fails any conflicting effective override and never infers compliance from Default alone.

---

### R-EXO-009 Legacy protocol restriction

**Portal** — Microsoft 365 admin center → Users → Active users → select user → Mail → Manage email apps (per user only).

**Set** — Organization-wide EWS:

```powershell
Set-OrganizationConfig -EwsEnabled $false -EwsApplicationAccessPolicy EnforceAllowList -EwsAllowList @()
```

This is the approved local disabled default and the exception rollback target, not a universal Microsoft default. Organization disablement overrides mailbox enablement; an allow-list entry does not reopen EWS.

**Retirement review: 2026-09-20.** Microsoft's [retirement guidance](https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/deprecation-of-ews-exchange-online) and [phased disablement announcement](https://techcommunity.microsoft.com/blog/exchange/exchange-online-ews-your-time-is-almost-up/4492361) specify default disablement starting October 2026 and complete shutdown in April 2027. Temporary continuation requires explicit organization enablement and an AppID allow list. No exception here is offered at or after 2027-04-01 UTC; this conservative boundary is not an assurance of availability until that instant. The contract is reviewed for Worldwide only; other environments need a separate source-backed review, not a guessed exception. Review sources again before each live change and at least quarterly.

`EwsAllowList` contains user-agent patterns, **not authenticated application identities**. User agents can be spoofed. `EwsApplicationAccessPolicy EnforceAllowList` is mandatory for the filter to operate. `EwsAllowedAppIDs` is a separate organization control containing externally supplied application GUIDs. Neither setting grants OAuth permissions, establishes consent, nor provisions an app. Consult [EWS access control](https://learn.microsoft.com/exchange/client-developer/exchange-web-services/how-to-control-access-to-ews-in-exchange) and [Set-CASMailbox](https://learn.microsoft.com/powershell/module/exchangepowershell/set-casmailbox?view=exchange-ps). Client-specific Outlook/Entourage switches are not governed by the user-agent filter; AppID restriction and externally owned identity controls remain necessary.

An enabled exception must supply `ewsEnabled: true`, `ewsApplicationAccessPolicy: EnforceAllowList`, exact nonempty `ewsAllowList` and `ewsAllowedAppIds` arrays, and `ewsException` with nonblank `owner`, external `approval` reference, timezone-qualified `expiresAt`, `cloud: Worldwide`, `rollback: DisableEws`, and a specific `clientImpact` statement. Expiry must be future and no later than 2027-04-01 UTC. Source review and a typed approval reference do not authenticate an approval: external risk/change authorization is still required. Keep this deviation separate from conformance to the disabled default.

Use the approved preview/change workflow, not an ad hoc enable command. Deployment resolves this contract before any Exchange mutation (including connectors and preset protection), reads all CAS mailboxes with terminating errors, and refuses contradictory overrides. The organization helper repeats admission immediately before its own writes. It sends the exact mode and replacement user-agent list together with `EwsEnabled` and the comma-delimited `EwsAllowedAppIDs`. It never creates applications or changes mailbox exceptions implicitly. A mailbox with null mode inherits the organization filter and must have no dormant list; an explicit mailbox allow mode must contain the exact approved list. A mailbox with `EwsEnabled False` remains blocked. Resolve conflicts through separately approved identity-scoped Exchange changes, then repeat collection.

The exception owner must schedule rollback before expiry, preserve the before-state and change artifacts, migrate dependent clients, and confirm disabled readback afterward. Expiry checks refuse continued approval; they do not run a scheduler or silently mutate a tenant. Run the disabled command above through the approved change workflow to close EWS. Record expected loss of archiving, integration, or legacy client functions in `clientImpact`, notify their owners, and test the replacement client. Do not roll back by broadening the list, using `EnforceBlockList`, or re-enabling a retired service.

New mailboxes:

```powershell
Get-CASMailboxPlan -ResultSize Unlimited |
    Set-CASMailboxPlan -PopEnabled $false -ImapEnabled $false
```

Existing mailboxes:

```powershell
Get-CASMailbox -ResultSize Unlimited |
    Where-Object { $_.PopEnabled -or $_.ImapEnabled } |
    Set-CASMailbox -PopEnabled $false -ImapEnabled $false
```

**Verify**

```powershell
Get-OrganizationConfig -RetrieveEwsOperationAccessPolicy -ErrorAction Stop | Select-Object EwsEnabled, EwsApplicationAccessPolicy, EwsAllowList, EwsAllowedAppIDs
Get-CASMailboxPlan -ResultSize Unlimited | Select-Object Identity, PopEnabled, ImapEnabled
Get-CASMailbox -ResultSize Unlimited -ErrorAction Stop |
    Select-Object Identity, EwsEnabled, EwsApplicationAccessPolicy, EwsAllowList, PopEnabled, ImapEnabled
```

Microsoft's [EWSAllowedAppIDs guidance](https://techcommunity.microsoft.com/blog/exchange/introducing-ewsallowedappids-preparing-for-the-final-phase-of-ews-retirement/4529471), reviewed 2026-09-20, requires `-RetrieveEwsOperationAccessPolicy` to retrieve the AppID list. AppID changes replace the full list and can take up to 24 hours to take effect. Configuration readback alone does not prove effective client access: preserve the readback, allow for propagation, and have the exception owner validate approved and denied clients before claiming live readiness.

**Expected**

```text
EwsEnabled EwsAllowList
---------- ------------
     False {}
```

Every mailbox plan and existing mailbox shows `PopEnabled False` and `ImapEnabled False`. For an enabled exception, require exact organization mode, user-agent and AppID readback plus the complete effective mailbox checks above; a populated list alone is not a pass. Collection failure or missing properties is unresolved evidence, not success. Offline verification does not certify live client compatibility or external readiness.

---

### R-EXO-010 Exchange RBAC hygiene

Supply the independently approved Exchange administrator/end-user assignment graph, management scopes, effective members and per-mailbox role-policy bindings. Follow the [RBAC contract](EXCHANGE-GOVERNANCE.md#rbac). Do not assume any generic set of privileged members is appropriate or use this runbook to provision PIM. Entra identities, privileged access and linked-partner provenance are RAID-D02/D03 handoffs.

The signed `GovernanceMailboxPolicy` scope updates existing mailbox policy bindings only. Other role/group changes need their own reviewed Exchange authorization and current readback. Prohibited end-user add-in roles cannot be approved around the EXO-012 restriction.

**Verify**

```powershell
Get-RoleGroup -ResultSize Unlimited | Select-Object Name, @{n='Members';e={$_.Members -join '; '}}
Get-ManagementRoleAssignment -GetEffectiveUsers |
    Select-Object EffectiveUserName, Role, RoleAssigneeName
Get-ManagementScope
Get-RoleAssignmentPolicy
Get-Mailbox -ResultSize Unlimited | Select-Object Identity, PrimarySmtpAddress, RoleAssignmentPolicy
```

**Expected** — The collector compares complete raw properties, not this abbreviated display. Direct/delegating assignments, read/write/custom/exclusive scopes, effective nested users, nondefault policies and mailbox bindings must match approval exactly. Unresolved partner provenance or incomplete collection fails. Exchange success does not certify PIM or external identity readiness.

---

### R-EXO-011 MTA-STS and TLS-RPT

**Portal** — Your DNS provider and a web host that can serve HTTPS on `mta-sts.contoso.com`.

**Set**

1. Publish the policy file at `https://mta-sts.contoso.com/.well-known/mta-sts.txt`, served with `Content-Type: text/plain`:

   ```text
   version: STSv1
   mode: enforce
   mx: contoso-com.mail.protection.outlook.com
   max_age: 604800
   ```

   Use the exact MX hostname from `Get-AcceptedDomain`. Start with `mode: testing` and move to `mode: enforce` only after reviewing TLS reports.

2. Publish the discovery record. Change `id` on every policy change:

   ```text
   _mta-sts.contoso.com    TXT    "v=STSv1; id=20260916T000000Z"
   ```

3. Publish the TLS reporting record:

   ```text
   _smtp._tls.contoso.com  TXT    "v=TLSRPTv1; rua=mailto:tlsrpt@contoso.com"
   ```

**Verify**

```powershell
Resolve-DnsName -Name _mta-sts.contoso.com -Type TXT -Server 8.8.8.8 | Select-Object -ExpandProperty Strings
Resolve-DnsName -Name _smtp._tls.contoso.com -Type TXT -Server 8.8.8.8 | Select-Object -ExpandProperty Strings
(Invoke-WebRequest -Uri 'https://mta-sts.contoso.com/.well-known/mta-sts.txt').Content
```

**Expected**

```text
v=STSv1; id=20260916T000000Z
v=TLSRPTv1; rua=mailto:tlsrpt@contoso.com
version: STSv1
mode: enforce
mx: contoso-com.mail.protection.outlook.com
max_age: 604800
```

---

### R-EXO-012 Outlook add-in acquisition

**Portal** — Exchange admin center → Roles → User roles → **Default Role Assignment Policy** → clear **My Custom Apps**, **My Marketplace Apps**, and **My ReadWriteMailboxApps**.

**Set**

```powershell
Get-ManagementRoleAssignment -RoleAssignee 'Default Role Assignment Policy' |
    Where-Object { $_.Role -in 'My Custom Apps', 'My Marketplace Apps', 'My ReadWriteMailboxApps' } |
    Remove-ManagementRoleAssignment -Confirm:$false
```

Users can no longer side-load add-ins. Deploy approved add-ins centrally through Integrated Apps in the Microsoft 365 admin center.

**Verify**

```powershell
Get-ManagementRoleAssignment -RoleAssignee 'Default Role Assignment Policy' |
    Select-Object Role | Sort-Object Role
```

**Expected** — The output contains none of `My Custom Apps`, `My Marketplace Apps`, or `My ReadWriteMailboxApps`.

---

## Microsoft Defender for Office 365

### R-MDO-001 Standard preset assignment

**Portal** — `https://security.microsoft.com/presetSecurityPolicies` → Standard protection → Manage protection settings.

Initialize the presets in the portal once. Microsoft does not support recreating the backing policies and rules by hand, and their values change as threats evolve — see `BAD-010`.

**Set**

```powershell
Set-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' `
    -RecipientDomainIs 'contoso.com' `
    -ExceptIfSentToMemberOf 'PriorityUsers@contoso.com' `
    -ExceptIfSentTo 'secops@contoso.com'
Enable-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy'
```

At `MDO_P1` or higher, also assign the Safe Links and Safe Attachments half:

```powershell
Set-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' `
    -RecipientDomainIs 'contoso.com' `
    -ExceptIfSentToMemberOf 'PriorityUsers@contoso.com' `
    -ExceptIfSentTo 'secops@contoso.com'
Enable-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy'
```

**Verify**

```powershell
Get-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' |
    Format-List Name, State, RecipientDomainIs, ExceptIfSentToMemberOf, ExceptIfSentTo
Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' | Format-List Name, State
```

**Expected**

```text
Name                    : Standard Preset Security Policy
State                   : Enabled
RecipientDomainIs       : {contoso.com}
ExceptIfSentToMemberOf  : {PriorityUsers@contoso.com}
ExceptIfSentTo          : {secops@contoso.com}
```

---

### R-MDO-002 Strict preset assignment

**Portal** — `https://security.microsoft.com/presetSecurityPolicies` → Strict protection → Manage protection settings.

**Set**

```powershell
Set-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -SentToMemberOf 'PriorityUsers@contoso.com'
Enable-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy'
Set-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -SentToMemberOf 'PriorityUsers@contoso.com'
Enable-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy'
```

Strict takes precedence over Standard, so a user in `PriorityUsers` receives Strict even though Standard also targets the domain.

**Verify**

```powershell
Get-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' | Format-List Name, State, SentToMemberOf, Priority
Get-DistributionGroupMember -Identity 'PriorityUsers@contoso.com' | Select-Object PrimarySmtpAddress
```

**Expected**

```text
Name           : Strict Preset Security Policy
State          : Enabled
SentToMemberOf : {PriorityUsers@contoso.com}
Priority       : 0
```

`Priority 0` confirms Strict evaluates before Standard.

---

### R-MDO-003 Built-in protection

**Tier: MDO P1.** **Portal** — `https://security.microsoft.com/presetSecurityPolicies` → Built-in protection → Manage protection settings.

Built-in protection is the Safe Links and Safe Attachments floor for anyone not covered by Standard or Strict. It has no include list, only exclusions. Every exclusion is an unprotected recipient.

**Set**

```powershell
Set-ATPBuiltInProtectionRule -Identity 'ATP Built-In Protection Rule' `
    -ExceptIfRecipientDomainIs $null `
    -ExceptIfSentTo $null `
    -ExceptIfSentToMemberOf $null
```

**Verify**

```powershell
Get-ATPBuiltInProtectionRule |
    Format-List Name, State, ExceptIfRecipientDomainIs, ExceptIfSentTo, ExceptIfSentToMemberOf
```

**Expected**

```text
Name                      : ATP Built-In Protection Rule
State                     : Enabled
ExceptIfRecipientDomainIs :
ExceptIfSentTo            :
ExceptIfSentToMemberOf    :
```

---

### R-MDO-004 Safe Attachments for SharePoint, OneDrive, and Teams

**Tier: MDO P1.** **Portal** — `https://security.microsoft.com/safeattachmentv2` → Global settings.

**Set**

```powershell
Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true
```

Block download of files that detonation has flagged:

```powershell
# SharePoint Online Management Shell
Set-SPOTenant -DisallowInfectedFileDownload $true
```

**Verify**

```powershell
Get-AtpPolicyForO365 | Format-List Name, EnableATPForSPOTeamsODB
Get-SPOTenant | Select-Object DisallowInfectedFileDownload
```

**Expected**

```text
Name                    : Default
EnableATPForSPOTeamsODB : True
```

---

### R-MDO-005 Safe Documents

**Tier: MDO P2.** **Portal** — `https://security.microsoft.com/safeattachmentv2` → Global settings → Safe Documents.

**Set**

```powershell
Set-AtpPolicyForO365 -EnableSafeDocs $true -AllowSafeDocsOpen $false
```

`AllowSafeDocsOpen $false` stops a user from leaving Protected View on a file that Safe Documents flagged as malicious. Leaving it `$true` makes the control advisory only.

**Verify**

```powershell
Get-AtpPolicyForO365 | Format-List EnableSafeDocs, AllowSafeDocsOpen
```

**Expected**

```text
EnableSafeDocs    : True
AllowSafeDocsOpen : False
```

If the cmdlet returns a licensing error, your tier is below `MDO_P2`. Record the gap and set `messagingTier` accordingly so the control reports `NotEntitled` instead of failing.

---

### R-MDO-006 User submissions

**Portal** — `https://security.microsoft.com/securitysettings/userSubmission`.

**Set**

```powershell
Set-ReportSubmissionPolicy -Identity DefaultReportSubmissionPolicy `
    -EnableReportToMicrosoft $true `
    -ReportJunkToCustomizedAddress $true `
    -ReportNotJunkToCustomizedAddress $true `
    -ReportPhishToCustomizedAddress $true

New-ReportSubmissionRule -Name DefaultReportSubmissionRule `
    -ReportSubmissionPolicy DefaultReportSubmissionPolicy `
    -SentTo 'secops@contoso.com'
```

If the rule already exists, use `Set-ReportSubmissionRule` instead of `New-ReportSubmissionRule`.

**Verify**

```powershell
Get-ReportSubmissionPolicy | Format-List EnableReportToMicrosoft, ReportJunkToCustomizedAddress, ReportPhishToCustomizedAddress
Get-ReportSubmissionRule | Format-List Name, State, SentTo
```

**Expected**

```text
EnableReportToMicrosoft        : True
ReportJunkToCustomizedAddress  : True
ReportPhishToCustomizedAddress : True

Name   : DefaultReportSubmissionRule
State  : Enabled
SentTo : {secops@contoso.com}
```

Finish with a functional test: send a benign test message, report it from Outlook, and confirm it lands in `secops@contoso.com` and in Defender portal → Submissions.

---

### R-MDO-007 Tenant Allow/Block List

**Portal** — `https://security.microsoft.com/tenantAllowBlockList`.

**Set** — Block entries are permanent-capable; allow entries must always expire.

```powershell
New-TenantAllowBlockListItems -ListType Sender -Block `
    -Entries 'badsender@malicious.example' -NoExpiration

New-TenantAllowBlockListItems -ListType Sender -Allow `
    -Entries 'newsletter@partner.example' `
    -ExpirationDate (Get-Date).AddDays(30) `
    -Notes 'CHG0012345 — partner DKIM repair in progress'
```

Never create a permanent allow. Repair the sender's SPF or DKIM instead — see `BAD-004`.

**Verify**

```powershell
Get-TenantAllowBlockListItems -ListType Sender |
    Select-Object Value, Action, ExpirationDate, Notes
Get-TenantAllowBlockListItems -ListType Sender -Allow |
    Where-Object { -not $_.ExpirationDate }
```

**Expected** — Every `Allow` row has a future `ExpirationDate` and a `Notes` value carrying the change or ticket reference. The second command returns nothing.

---

### R-MDO-008 Quarantine policies and notifications

**Portal** — `https://security.microsoft.com/quarantinePolicies` → Global settings.

The Standard and Strict presets already assign Microsoft-managed quarantine policies: `AdminOnlyAccessPolicy` for malware and high-confidence phish, and a limited-access policy for spam and bulk. Do not replace those assignments; doing so recreates `BAD-010` and `BAD-014`. Configure only the global notification settings.

**Set**

```powershell
Set-QuarantinePolicy -Identity DefaultGlobalTag `
    -EndUserSpamNotificationFrequency (New-TimeSpan -Days 1) `
    -OrganizationBrandingEnabled $false
```

**Verify**

```powershell
Get-QuarantinePolicy -Identity DefaultGlobalTag |
    Format-List Name, EndUserSpamNotificationFrequency, OrganizationBrandingEnabled
Get-QuarantinePolicy |
    Select-Object Name, EndUserQuarantinePermissionsValue, ESNEnabled
```

**Expected**

```text
Name                            : DefaultGlobalTag
EndUserSpamNotificationFrequency: 1.00:00:00
OrganizationBrandingEnabled     : False
```

The second command lists `AdminOnlyAccessPolicy` among the policies. Confirm in the portal that malware and high-confidence phish map to it.

---

### R-MDO-009 Priority account protection

**Tier: MDO P2.** **Portal** — Microsoft 365 admin center → Setup → **Priority accounts**, and Defender portal → Settings → Email & collaboration → **User tags**.

**Set** — Tag the same identities that `PriorityUsers@contoso.com` contains. There is no supported Exchange Online cmdlet for user tags; this control is portal-managed.

**Verify** — Export the user tag membership from Defender portal → Settings → Email & collaboration → User tags, and reconcile it against the distribution group:

```powershell
Get-DistributionGroupMember -Identity 'PriorityUsers@contoso.com' | Select-Object PrimarySmtpAddress
```

**Expected** — The portal user tag membership and the group membership match exactly. A mismatch means a priority user receives Strict preset protection but no priority-account telemetry, or the reverse.

---

## Mail Gateway

Run this section only when `desiredState.mailFlow.gateway.declared` is `true`. In the Microsoft-native profile, `Assert-Configuration` rejects these connectors — see [R-PP-005](#r-pp-005-no-undeclared-partner-inbound-connector).

Obtain the current public sending ranges, smart hosts, TLS certificate subject, SPF include, MX target, and ARC support from the contracted vendor's documentation or support channel. Never guess them — see `BAD-007`.

### R-PP-001 Gateway inbound connector

**Portal** — Exchange admin center → Mail flow → Connectors → Add a connector → From: Partner organization, To: Office 365.

**Set**

```powershell
New-InboundConnector -Name 'Proofpoint Inbound' `
    -ConnectorType Partner `
    -Enabled $true `
    -SenderDomains '*' `
    -SenderIPAddresses @('203.0.113.0/24') `
    -RequireTls $true `
    -RestrictDomainsToIPAddresses $true `
    -RestrictDomainsToCertificate $false
```

`RestrictDomainsToIPAddresses $true` is what makes MX redirection insufficient for an attacker: mail claiming your domains is only accepted from the listed sources.

**Verify**

```powershell
Get-InboundConnector -Identity 'Proofpoint Inbound' |
    Format-List Name, Enabled, ConnectorType, RequireTls, RestrictDomainsToIPAddresses, SenderIPAddresses
```

**Expected**

```text
Name                         : Proofpoint Inbound
Enabled                      : True
ConnectorType                : Partner
RequireTls                   : True
RestrictDomainsToIPAddresses : True
SenderIPAddresses            : {203.0.113.0/24}
```

---

### R-PP-002 Enhanced Filtering for Connectors

**Portal** — Defender portal → Email & collaboration → Policies & rules → Threat policies → **Enhanced filtering**.

Without this, Exchange Online Protection sees the gateway as the sending host and loses the true originating IP, which degrades spoof intelligence, SPF evaluation, and connection filtering.

**Set**

```powershell
Set-InboundConnector -Identity 'Proofpoint Inbound' `
    -EFSkipLastIP $false `
    -EFSkipIPs @('203.0.113.0/24') `
    -EFUsers $null
```

List **every** non-Microsoft public hop, not only the last one. `EFUsers $null` applies the skip list to all recipients; scope it to pilot recipients first if this is an existing production flow.

**Verify**

```powershell
Get-InboundConnector -Identity 'Proofpoint Inbound' | Format-List Name, EFSkipLastIP, EFSkipIPs, EFUsers
```

**Expected**

```text
EFSkipLastIP : False
EFSkipIPs    : {203.0.113.0/24}
EFUsers      : {}
```

Then send a test message from an external SPF-pass source and inspect the headers:

```powershell
Get-MessageTraceDetail -MessageTraceId <id> -RecipientAddress test@contoso.com
```

Confirm `X-MS-Exchange-ExternalOriginalInternetSender` and `X-MS-Exchange-SkipListedInternetSender` are present.

---

### R-PP-003 Gateway outbound connector

**Portal** — Exchange admin center → Mail flow → Connectors → Add a connector → From: Office 365, To: Partner organization.

**Set**

```powershell
New-OutboundConnector -Name 'Proofpoint Outbound' `
    -ConnectorType Partner `
    -Enabled $true `
    -RecipientDomains '*' `
    -RouteAllMessagesViaOnPremises $true `
    -UseMXRecord $false `
    -SmartHosts @('outbound.gateway.example') `
    -TlsSettings DomainValidation `
    -TlsDomain 'outbound.gateway.example'
```

**Verify**

```powershell
Get-OutboundConnector -Identity 'Proofpoint Outbound' |
    Format-List Name, Enabled, ConnectorType, SmartHosts, TlsSettings, TlsDomain
Validate-OutboundConnector -Identity 'Proofpoint Outbound' -Recipients 'test@external.example'
```

**Expected**

```text
Enabled     : True
TlsSettings : DomainValidation
TlsDomain   : outbound.gateway.example
```

`Validate-OutboundConnector` returns `Succeeded` for connectivity and certificate validation. Change MX only after this passes and after the rollback test.

---

### R-PP-004 Trusted ARC sealer

**Portal** — `https://security.microsoft.com/authentication` → ARC.

Configure this only when the gateway modifies messages and the vendor publishes a verified ARC sealing domain. Never guess the domain.

**Set**

```powershell
Set-ArcConfig -Identity Default -ArcTrustedSealers 'arc.gateway.example'
```

**Verify**

```powershell
Get-ArcConfig | Format-List Identity, ArcTrustedSealers
```

**Expected**

```text
ArcTrustedSealers : {arc.gateway.example}
```

Send a test message through the gateway and confirm the `Authentication-Results` header shows `arc=pass` and that `compauth` reflects the original sender rather than the gateway.

---

### R-PP-005 No undeclared Partner inbound connector

**Applies to the Microsoft-native profile.** A leftover enabled Partner inbound connector accepts mail for your domains from whatever sources it lists, bypassing the connection filter's normal evaluation. In a tenant with no gateway, there should be none.

**Set** — Disable, confirm no delivery impact for a full business cycle, then remove:

```powershell
Get-InboundConnector | Where-Object { $_.ConnectorType -eq 'Partner' -and $_.Enabled } |
    Set-InboundConnector -Enabled $false
```

**Verify**

```powershell
Get-InboundConnector | Select-Object Name, ConnectorType, Enabled, SenderIPAddresses
```

**Expected** — No row shows `ConnectorType Partner` with `Enabled True`.

---

## Email Authentication

### R-AUTH-001 DKIM

**Portal** — `https://security.microsoft.com/authentication` → DKIM.

**Set** — Create the configuration disabled, publish the exact CNAME targets Exchange Online returns, then enable. Since May 2025 new domains can receive a dynamic partition in the CNAME target, so never construct the target by hand.

```powershell
New-DkimSigningConfig -DomainName contoso.com -KeySize 2048 -Enabled $false
Get-DkimSigningConfig -Identity contoso.com | Format-List Selector1CNAME, Selector2CNAME
```

Publish both records exactly as returned:

```text
selector1._domainkey.contoso.com   CNAME   <Selector1CNAME value>
selector2._domainkey.contoso.com   CNAME   <Selector2CNAME value>
```

After DNS propagation:

```powershell
Set-DkimSigningConfig -Identity contoso.com -Enabled $true
```

**Verify**

```powershell
Get-DkimSigningConfig -Identity contoso.com |
    Format-List Name, Enabled, Status, Selector1KeySize, Selector2KeySize
Resolve-DnsName -Name selector1._domainkey.contoso.com -Type CNAME -Server 8.8.8.8
```

**Expected**

```text
Name             : contoso.com
Enabled          : True
Status           : Valid
Selector1KeySize : 2048
Selector2KeySize : 2048
```

`Status Valid` is the gate. Enabling before the CNAMEs resolve produces `CnameMissing` and breaks signing.

---

### R-AUTH-002 SPF

**Portal** — Your authoritative DNS provider.

**Set** — Publish exactly one SPF TXT record at the domain apex. Multiple SPF records are a permanent error and cause SPF to fail entirely.

Microsoft-native profile:

```text
contoso.com   TXT   "v=spf1 include:spf.protection.outlook.com -all"
```

Gateway profile — use the include value the vendor approves for your actual outbound path:

```text
contoso.com   TXT   "v=spf1 include:<vendor-approved-include> -all"
```

Stage with `~all` while you enumerate legitimate senders, then move to `-all`.

**Verify**

```powershell
(Resolve-DnsName -Name contoso.com -Type TXT -Server 8.8.8.8).Strings |
    Where-Object { $_ -like 'v=spf1*' }
```

**Expected** — Exactly one string, ending in `-all`:

```text
v=spf1 include:spf.protection.outlook.com -all
```

More than one returned string is a finding. Fix it before enforcing DMARC.

---

### R-AUTH-003 DMARC

**Portal** — Your authoritative DNS provider.

**Set** — Stage through monitoring before enforcing. Publish at `_dmarc.contoso.com`:

```text
# Stage 1 — discovery
_dmarc.contoso.com   TXT   "v=DMARC1; p=none; pct=100; rua=mailto:dmarc@contoso.com; fo=1"

# Stage 2 — partial enforcement after reviewing aggregate reports
_dmarc.contoso.com   TXT   "v=DMARC1; p=quarantine; pct=100; sp=quarantine; rua=mailto:dmarc@contoso.com; fo=1"

# Stage 3 — target state
_dmarc.contoso.com   TXT   "v=DMARC1; p=reject; pct=100; sp=reject; rua=mailto:dmarc@contoso.com; fo=1"
```

Do not advance a stage until aggregate reports show every sanctioned bulk sender and SaaS system passing aligned SPF or DKIM.

**Verify**

```powershell
(Resolve-DnsName -Name _dmarc.contoso.com -Type TXT -Server 8.8.8.8).Strings
```

**Expected**

```text
v=DMARC1; p=reject; pct=100; sp=reject; rua=mailto:dmarc@contoso.com; fo=1
```

`sp=reject` matters: without it, an attacker uses an unregistered subdomain.

---

## Third-Party Post-Delivery Integration

### R-ABN-001 Abnormal Security integration mode

**Portal** — Microsoft Entra admin center → Enterprise applications; vendor onboarding workflow.

**Set** — Use the vendor's current Microsoft 365 onboarding workflow. Do **not** create an Exchange connector, journal rule, SCL bypass, or transport exception for Abnormal. It is API-based post-delivery processing, not an SMTP hop — see `BAD-006`.

**Verify**

```powershell
Get-InboundConnector  | Where-Object { $_.Name -match 'abnormal' }
Get-OutboundConnector | Where-Object { $_.Name -match 'abnormal' }
Get-JournalRule       | Where-Object { $_.JournalEmailAddress -match 'abnormal' }
Get-TransportRule     | Where-Object { $_.SetSCL -eq '-1' }
```

**Expected** — All four commands return nothing. Then confirm in the vendor console that detection, message removal, restoration, and audit attribution all function against a test message.

---

### R-ABN-002 Abnormal Security permissions

**Portal** — Microsoft Entra admin center → Enterprise applications → the Abnormal application → Permissions.

**Set** — Grant only the permissions the contracted features require. Restrict who may consent:

Microsoft 365 admin center → Settings → Org settings → **User consent to apps** → *Do not allow user consent*.

**Verify**

```powershell
$sp = Get-MgServicePrincipal -Filter "displayName eq 'Abnormal Security'"
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id |
    Select-Object AppRoleId, ResourceDisplayName
Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $sp.Id |
    Select-Object Scope, ConsentType
```

**Expected** — The granted scopes match the vendor's documented minimum for your contracted features, and nothing more. Record the review date; repeat within 90 days.

---

## Monitoring and Operations

### R-MON-001 Central telemetry

**Portal** — Your SIEM's data connector catalogue; Defender portal → Settings → Microsoft Defender XDR → Streaming API.

**Set** — Connect every source listed in `desiredState.centralMonitoring.siemIntegration.sources`. Use supported Microsoft connectors and APIs rather than legacy Exchange reporting cmdlets, many of which no longer return useful data.

**Verify** — Confirm connector health in the SIEM, then raise a synthetic alert and confirm it arrives. In Defender:

```powershell
Get-ServicePrincipal | Where-Object { $_.DisplayName -match 'siem|sentinel' } | Select-Object DisplayName, AppId
```

**Expected** — Every declared source shows data received within the last hour, and the synthetic alert appears end to end.

---

### R-MON-002 Unified audit log

**Portal** — Purview portal → Audit.

**Set** — Unified audit is on by default in current tenants. Confirm rather than assume.

**Verify**

```powershell
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) `
    -RecordType ExchangeAdmin -ResultSize 10 | Select-Object CreationDate, Operations, UserIds
```

**Expected**

```text
UnifiedAuditLogIngestionEnabled
-------------------------------
                           True
```

`Search-UnifiedAuditLog` returns the Exchange administration you performed in the runbooks above. An empty result means ingestion is not working, regardless of the flag.

---

### R-MON-003 Drift evidence

**Portal** — None. Scheduled automation.

**Set** — Run the evidence collector after every approved change and on a schedule:

```powershell
./scripts/Test-ExchangeOnlineBaseline.ps1 `
    -ParameterPath ./config/parameters.contoso.json `
    -ConfigurationPath ./config/exchange-online-secure-baseline.json
```

Retain the output JSON with the change record for at least 180 days, or the organization's longer regulatory period.

**Verify**

```powershell
Get-ChildItem ./evidence/exchange-online-evidence-*.json |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 5 Name, LastWriteTime
(Get-Content ./evidence/<latest>.json -Raw | ConvertFrom-Json).summary
```

**Expected**

```text
Pass          : 18
Manual        : 11
NotEntitled   : 0
NotApplicable : 0
```

Any `Fail` count above zero is an open finding. The collector exits non-zero so a scheduled run fails loudly.

---

### R-OPS-001 Change safety

**Portal** — Your change management system.

**Set** — For every change:

1. Preview. Omitting `-Apply` invokes each supported cmdlet with `-WhatIf`:

   ```powershell
   ./scripts/Deploy-ExchangeOnlineBaseline.ps1 -ParameterPath ./config/parameters.contoso.json
   ```

2. Attach the preview output and the current evidence JSON to the change record.
3. Obtain approval.
4. Pilot with representative users for at least five business days.
5. Apply:

   ```powershell
   ./scripts/Deploy-ExchangeOnlineBaseline.ps1 -ParameterPath ./config/parameters.contoso.json -Apply
   ```

6. Collect evidence and attach it to the change record.

Record the previous DNS values, connector settings, and preset assignments in the rollback plan. For an outage, revert the most recent scoped change. Never introduce an unauthenticated open relay or a broad SCL bypass as a recovery step.

**Verify**

```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
    -RecordType ExchangeAdmin -ResultSize 100 |
    Select-Object CreationDate, UserIds, Operations
```

**Expected** — Every administrative operation in the window maps to an approved change record.

---

### R-OPS-002 Incident exercise

**Tier: MDO P2.** **Portal** — `https://security.microsoft.com/attacksimulator`.

**Set** — Run a quarterly credential-harvest or attachment simulation against a representative population, or a tabletop covering detection, triage, purge, and communication.

**Verify** — Export the simulation report and confirm: users reported the message, SecOps received the submission, the purge action succeeded, and any action items have owners and due dates.

```powershell
Get-ComplianceSearchAction | Where-Object { $_.SearchName -match 'phish' } |
    Select-Object Name, Status, JobEndTime
```

**Expected** — A completed purge action exists for the exercise, and the exercise record lists closed or scheduled follow-ups.

---

## Exchange Governance and External Handoffs

Use the approved [Exchange governance contract](EXCHANGE-GOVERNANCE.md). No Security and Compliance session is opened by the Exchange-only workflow. External legal, identity and preservation readiness remains Unverified.

### R-GOV-001 Audit retention policy

External handoff: RAID-I02/D03. The tenant audit owner supplies approved retention and ingestion evidence. Exchange organization auditing and audit-bypass readback are EXO-006; they do not prove tenant audit retention. Do not provision a global audit retention policy from this walkthrough.

**Verify** - Obtain the audit owner's current approved retention and ingestion record.

**Expected** - Named owner, scope, retention and evidence reference are present; external readiness remains Unverified until independently accepted.

---

### R-GOV-002 Exchange DLP policy

External handoff: RAID-I02/D03. Data owners approve regulated classes, locations, exceptions and enforcement; the Purview owner supplies policy evidence. DLP provisioning is not an Exchange-only action. The historical example has been removed rather than presented as a universal data policy.

**Verify** - Obtain the data owner's policy scope and enforcement evidence through the external handoff.

**Expected** - Approved data classes, locations and exceptions are independently recorded; Exchange conformance does not certify DLP.

---

### R-GOV-003 Mailbox retention policy

Exchange MRM is a lifecycle and archive interface, not Purview preservation. Supply the records owner's exact policy, tag types/actions/ages/enabled states, mailbox scope, archive entitlements and processing-age limit in GOV-003. No deletion period is assumed.

Use the signed `GovernanceMrm` scope for existing tags, policy links and mailbox assignments. Provisioning a new tag or archive and clearing retention holds are not implicit side effects. Readback resolves `Get-RetentionPolicy`, every linked `Get-RetentionPolicyTag`, mailbox processing flags, organization ELC state and the last successful MRM diagnostic timestamp. Wrong semantics, blocked processing or missing archive entitlement fails closed. Rollback restores captured configuration; it cannot recover items already processed or deleted by MRM.

Follow [Exchange governance](EXCHANGE-GOVERNANCE.md) and rerun frozen evidence. Preservation policy remains externally owned under RAID-I02/D03 and separately Unverified.

**Verify** - Run GOV-003 collection/evaluation with the approved configuration, then the frozen evidence gate.

**Expected** - Exact tag semantics, mailbox assignments, archive entitlement and successful processing match approval; preservation remains Unverified.

---

### R-GOV-004 Litigation hold

Supply the legal owner's custodian inventory, exact duration and owner, per-mailbox entitlement, active/inactive/soft-deleted applicability and Recoverable Items capacity threshold in GOV-004. Priority-account membership does not authorize a hold. Missing custodians and unauthorized holds both fail.

The collector enumerates all three mailbox classes with unlimited results and reads Recoverable Items usage by Exchange GUID. An inactive mailbox also returned in the soft-deleted inventory is counted once; incompatible duplicates fail. Legal hold application or release requires a separately authorized legal procedure, not automatic baseline remediation or rollback. Tenant cases and preservation policy remain RAID-I02/D03 handoffs. See [Exchange governance](EXCHANGE-GOVERNANCE.md).

**Verify** - Run GOV-004 against the approved legal inventory and per-mailbox capacity threshold.

**Expected** - Exact custodian, duration, owner, class and entitlement match with sufficient headroom; unauthorized holds and missing custodians fail.

---

### R-GOV-005 Information Rights Management

Supply approved business-message classes, exact rule/header/recipient/template/sender bindings, entitlement, IRM values and explicit transport/journal decryption authorization in GOV-005. Use the signed `GovernanceEncryption` scope for existing Exchange rule settings and IRM configuration. RMS activation, keys and labels remain external prerequisites under RAID-D02/D03/A03.

Verify rule readback, enabled enforcement, matching recipient scope, protection-removal and precedence conflicts, then run `Test-IRMConfiguration` for each approved sender/recipient pair. Supply current independent recipient observations in `governanceEvidence.recipientFlows`; both authorized decryption and unauthorized-recipient rejection must be evidenced. A self-test alone is insufficient. Offline success does not certify live delivery: EXR-016/017 own that acceptance. Follow [Exchange governance](EXCHANGE-GOVERNANCE.md).

**Verify** - Run GOV-005 collection/evaluation with complete raw rule predicates and independent recipient observations.

**Expected** - Approved class/recipient/template/IRM/decryption settings and functional evidence match; actual live delivery remains separately unverified.

---

### R-GOV-006 Sensitivity labels

External handoff: RAID-I02/D03. The information-protection owner supplies approved labels and publication evidence. Do not create labels or label policies in the Exchange walkthrough.

**Verify** - Obtain the information-protection owner's current publication evidence.

**Expected** - Approved taxonomy, recipients and publication are documented externally; Exchange success is not label-policy acceptance.

---

### R-GOV-007 eDiscovery readiness

External handoff: RAID-I02/D03. Legal and Purview case owners supply case access and search-readiness evidence. Exchange mailbox hold readback is not proof of case access or tenant eDiscovery readiness.

**Verify** - Obtain independently approved case access and search-readiness records from the named owners.

**Expected** - External owners supply scoped evidence; Exchange-only checks leave eDiscovery readiness Unverified.

---

## Completion gate

Use the active [Frozen Exchange Evidence Gate](EXCHANGE-GO-LIVE.md): collect once, freeze and review the exact bytes, sign with the externally authorized certificate using `-SignEvidence`, then verify that same file with `-GoLive` and the documented tenant/configuration/hash/age/signer inputs. Do not use a historical-profile collection-only exit as completion evidence.

In-scope `Manual`, `NotEntitled`, missing records and unknown statuses fail closed; `Error` is a collection failure. Approved deviations remain `ApprovedException`, never Pass. The gate's distinct exits are documented in the linked workflow. Even exit `0` leaves `ExternalReadiness.Status` Unverified and does not certify tenant security or service launch.

## Authoritative References

- [Recommended EOP and Defender for Office 365 settings](https://learn.microsoft.com/defender-office-365/recommended-settings-for-eop-and-office365)
- [Preset security policies](https://learn.microsoft.com/defender-office-365/preset-security-policies)
- [Quarantine policies](https://learn.microsoft.com/defender-office-365/quarantine-policies)
- [Third-party cloud mail flow](https://learn.microsoft.com/exchange/mail-flow-best-practices/manage-mail-flow-using-third-party-cloud)
- [Enhanced Filtering for Connectors](https://learn.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/enhanced-filtering-for-connectors)
- [Configure DKIM](https://learn.microsoft.com/defender-office-365/email-authentication-dkim-configure)
- [Configure DMARC](https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure)
- [Disable SMTP AUTH](https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission)
- [External sender identification](https://learn.microsoft.com/exchange/mail-flow-best-practices/external-email-tagging)
- [Manage mailbox auditing](https://learn.microsoft.com/purview/audit-mailboxes)
- [Data loss prevention policies](https://learn.microsoft.com/purview/dlp-policy-reference)
- [Retention policies and labels](https://learn.microsoft.com/purview/retention)
- [Microsoft 365 SIEM integration](https://learn.microsoft.com/defender-office-365/siem-server-integration)
- [Zero Trust for Microsoft 365](https://learn.microsoft.com/security/zero-trust/microsoft-365-zero-trust)
