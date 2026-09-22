# Approved Exchange Change

Run PowerShell 7.5+ from `samples/contoso-exchange-online-managed-service`. This is an explicit scoped change, not whole-baseline conformance or tenant readiness. Workflow version 1.0.0 supports the following reversible Exchange-only scopes. Select the intended scopes at Preview; the signed preview fixes the scope for every subsequent phase. Unsupported scopes stop instead of falling through to legacy mutations.

| Scope | Exact adapter coverage |
| --- | --- |
| `Transport` | Organization SMTP AUTH disablement and external postmaster address (`TransportConfig`). |
| `Organization` | Default mailbox auditing and organization EWS policy (`OrganizationConfig`). |
| `ExternalSender` | Outlook external-sender identification and allow list (`ExternalInOutlook`). |
| `RemoteDomains` | Default remote-domain forwarding, auto-reply, OOF and delivery/NDR reporting (`RemoteDomain`). |
| `MailboxProtocols` | Existing mailbox POP and IMAP settings (`CASMailbox`). |
| `MailboxPlans` | New-mailbox POP and IMAP defaults (`CASMailboxPlan`). |
| `OutboundSpam` | Default automatic external forwarding policy (`HostedOutboundSpamFilterPolicy`). |
| `AcceptedDomains` | Primary accepted domain creation or domain-type update (`AcceptedDomain`). |
| `ReportSubmission` | Report submission destination and reporting settings (`ReportSubmissionPolicy`). |
| `SecOpsOverride` | Security operations mailbox delivery override (`SecOpsOverridePolicy`). |
| `Impersonation` | Named impersonation policy targets and exceptions (`AntiPhishPolicy`). |
| `EopPresets` | Standard and Strict assignments and enable/disable state (`EOPProtectionPolicyRule`). |
| `AtpPresets` | Standard and Strict assignments and enable/disable state (`ATPProtectionPolicyRule`). |
| `BuiltInProtection` | Built-in protection exclusions (`ATPBuiltInProtectionRule`). |
| `Quarantine` | Access policies, global cadence/settings, content-filter and malware-filter quarantine tags (`QuarantinePolicy`, `HostedContentFilterPolicy`, `MalwareFilterPolicy`). |
| `Forwarding` | Mailbox forwarding addresses and external-forwarding inbox-rule enable/disable state (`Mailbox`, `InboxRule`). |
| `AddInAcquisition` | Remove and restore supported default-policy app role grants (`ManagementRoleAssignment`). |
| `Dkim` | Primary-domain DKIM configuration creation and enabled state (`DkimSigningConfig`). |
| `TenantAllowBlockList` | Governed sender/domain, URL and file-hash entries, including replacement and restoration (`TenantAllowBlockListItems`). |
| `GovernanceMailboxPolicy` | Existing mailbox role-assignment-policy bindings; no role/group creation or grants. |
| `GovernanceMrm` | Existing MRM tag action/age/enabled state, policy tag links and approved mailbox assignments; no archive provisioning or hold clearing. |
| `GovernanceEncryption` | Existing Exchange encryption-rule scope/template/mode and IRM settings; no RMS activation, rule creation or tenant labels. |

Governance scopes require the explicit [Exchange governance contract](EXCHANGE-GOVERNANCE.md) in an approved configuration copy. Supply that path instead of the shipped template in the command block below. Legal holds are observation-only in this workflow. Rollback restores configuration, never already-deleted MRM data or legal obligations. Rerun the complete frozen evidence gate after changes.

All existing Exchange-only baseline mutation adapters are covered. Deliberately omitted historical adapters are inbound/outbound gateway connectors (including enhanced filtering), trusted ARC sealers, and `AtpPolicyForO365` (SPO/OneDrive/Teams protection and Safe Documents), as excluded by the Exchange-only manifest. Evidence-only/manual controls, DNS publication, identity/licensing, enterprise signing, tenant-wide Purview and SIEM are not mutation adapters. Their external readiness is not implied. Mailbox SMTP AUTH overrides, preset initialization, and policy/rule surfaces beyond the listed baseline adapters are not added by this workflow.

`AtpPresets`, `BuiltInProtection`, and `Impersonation` require `ATP_ENTERPRISE` in the externally verified entitlement. Existing preset rules must already be initialized. Administrator parameter JSON may include `workflowOptions` with `enableDkim` (Boolean, default false) and `tenantAllowBlockEntries` (array). Each TABL entry requires `entryType` (`Sender`, `Domain`, `Url`, or `File`), `entryValue`, `action` (`Allow` or `Block`), `owner`, `ticket`, `createdDateTime`, `expirationDateTime`, and `justification`. UTC timestamps and durations must satisfy MDO-007 governance. Resolve DKIM DNS externally before approving activation. Parameter bytes are parsed and canonically hashed into `ParameterHash`; changing options after approval requires a new preview. Use these signed options, not the historical Deploy `-EnableDkim` switch.

## External Prerequisites

The operator supplies `$parameterPath` (absolute path to a resolved Exchange-only parameter JSON with a current RAID-D02 licensing handoff), `$artifactRoot` (a new protected absolute directory), `$changeId` (unique letters/digits/hyphens), and `$requestedBy` (the authenticated change requester). Establish exactly one authorized Exchange Online session to the tenant in the parameter file before preview/apply/rollback. The commands do not connect, collect credentials, provision a tenant, install PKI or change trust stores.

RAID-D05 supplies `$authorityPath`, an independently administered JSON array with `Identity`, `Subject`, and `Authority` (`ExchangeOnlineChangeApproval`) for each approved signer. Keep it protected from the requester; do not derive it from the incoming signature. The independent approver supplies `$approvalIdentity` and `$certificate`, an existing enterprise `X509Certificate2` with an accessible signing key (for example obtained from their approved certificate-store or HSM integration). Never place private keys in the repository. Chain, certificate validity and cached revocation evidence must verify offline; unavailable trust stops with `ChangeApprovalSignatureUnverified`. There is no self-signed production fallback. The requester and approver must be different people; these identity inputs come from the trusted change channel, not an untrusted web request.

The independent approver inspects the immutable preview before running the Approve line in their own controlled session. Signing does not require an Exchange connection. The approval binds the SHA-256 of the exact preview bytes, ChangeId, tenant GUID, resolved configuration hash, approver identity, authority and time. The signed payload is canonical UTF-8 JSON of every approval member except `Signature`; `Signature` is `{ "Model": "DetachedCms", "Value": "base64 CMS bytes" }`. Moving approved files to another host is permitted only while preserving their bytes and supplying paths consistently on that host.

## Commands

Execute each phase separately with review between phases. `-Confirm:$false` below assumes that the authorized operator has deliberately chosen to execute that phase; omit it for a prompt. The final rollback line is a recovery command, not a routine deployment step. The offline acceptance test executes the entire block to prove restoration. Production users execute rollback only when the approved recovery decision calls for it, within the preview's 24-hour validity window.

<!-- executable-workflow -->
```powershell
$change = @{
    ParameterPath = $parameterPath
    ConfigurationPath = './config/exchange-only.v1.json'
    ArtifactRoot = $artifactRoot
    ChangeId = $changeId
    RequestedBy = $requestedBy
    AuthorizedSignerPath = $authorityPath
    PreviewPath = Join-Path $artifactRoot "preview-$changeId.json"
    ApprovalPath = Join-Path $artifactRoot "approval-$changeId.json"
}
./scripts/Invoke-ExchangeOnlineChange.ps1 -Stage Preview @change -Scope Transport -Confirm:$false
./scripts/Invoke-ExchangeOnlineChange.ps1 -Stage Approve @change -ApprovalIdentity $approvalIdentity -SigningCertificate $certificate -Confirm:$false
./scripts/Invoke-ExchangeOnlineChange.ps1 -Stage Validate @change
./scripts/Deploy-ExchangeOnlineBaseline.ps1 @change -Apply -SkipConnection -Confirm:$false
& (Join-Path $artifactRoot "rollback-$changeId.ps1") -Apply -Confirm:$false
```

`Deploy` without `-Apply` is only an inventory. Its console output or a WhatIf transcript is not an approval artifact. To rehearse the signed change use the complete Apply invocation with `-WhatIf`; it checks approval/session/state but emits no execution artifacts and makes no mutation. Preview captures concrete typed before/after parameter values; apply refuses state or configuration drift and executes those exact approved values.

## Files And Recovery

Each change retains canonical UTF-8 JSON `preview-<id>.json`, `approval-<id>.json`, `prechange-<id>.json`, `apply-<id>.json`, and `postchange-<id>.json`; `rollback-<id>.ps1` is an executable wrapper around the same guarded workflow, not untyped `-Value` commands. Pre-change and rollback are written before mutation. Post-change includes observed values, success/failure and a fault. Rollback reads and restores only attempted operations from the apply journal, verifies readback, and emits immutable `rollback-result-<id>.json` on success. A repeated successful rollback verifies the restored targets and makes no writes. Apply locks prevent replay; rollback locks prevent concurrent recovery but allow a guarded retry. Preserve all files and protect the directory with operator/change-authority ACLs.

Creation receipts record `ObjectFingerprint`, a SHA-256 fingerprint of the full observed object, separately from managed typed values. Before any rollback writes, deletion of a created object requires that fingerprint still match, including unrelated properties. Missing fingerprints or intervening object changes fail closed. A failed rollback execution emits a new immutable `rollback-attempt-<id>-<unique>.json`, not a successful result. Retry uses the same approved invocation after investigating and resolving the failure; it never overwrites prior receipts.

For TABL replacement, a successful apply can be followed by rollback removal and a failed recreation of the original entry. Retry may restore that absent intermediate state only from validated removal evidence. Failed rollback receipts bind the exact apply-receipt hash, change, tenant, profile, preview, configuration, ordered predecessor and completion time. The existing `rollback-<id>.lock` also retains the ordered receipt names and byte hashes, updated under exclusive rollback ownership. Preflight validates that index and the receipts; execution validates again under the exclusive lock. Recovery requires failed `Removed` progress and an absent readback for the exact approved operation. Later observations supersede earlier removal evidence; present or intervening values still pass the ordinary drift checks.

Preserve the lock/index along with all receipts when transferring or retaining a change. Tampered, unindexed, missing, replayed, unbound or mismatched attempts fail closed. Older failed attempts without this index cannot authorize automatic retry; investigate and obtain a separately reviewed change instead of fabricating an index or deleting artifacts. A crash between receipt creation and index persistence also fails closed for investigation. The index provides integrity within the protected artifact directory, not independent cryptographic authentication: an actor able to rewrite both receipts and the index is outside this trust boundary. Operator/change-authority ACLs remain required; this is not EXR-006 evidence signing.

- Missing approval or signer metadata: obtain the missing external authorization; do not edit or fabricate signature fields.
- Expired, wrong ChangeId, changed bytes or configuration: create a new change directory and ChangeId, preview again, review and obtain new approval. Never reserialize or overwrite approved JSON.
- Wrong tenant/session: disconnect incorrect sessions and establish exactly one authorized session to the approved tenant; retry validation.
- State drift or incomplete reads: investigate the target and re-preview. Rollback refuses unreviewed intervening state rather than overwriting it.
- Partial apply or readback failure: inspect immutable apply/post-change faults and the pre-change capture. Use the scoped rollback within its approval window when current values still match the approved before/after state. Untouched operations are not read or restored. A journaled TABL removal followed by failed replacement can restore the original entry from its absent intermediate state. Failed rollback attempts retain their faults and observed state; fix the underlying command availability or transient failure and retry within the same approval window. A later recovery needs a separately reviewed change with explicitly restored desired configuration and new approval; never remove execution locks to force a replay.
- Unsupported scope: no changes occur. Do not use the historical all-operation path as a workaround. This workflow does not implement EXR-006 evidence signing or confer go-live approval.

Offline verification: `Invoke-Pester -Path ./tests/unit/ApprovedWorkflow.Tests.ps1,./tests/unit/ApprovedWorkflowCommand.Tests.ps1,./tests/unit/ApprovedAdapters.Tests.ps1,./tests/unit/ApprovedAdapterRoundTrip.Tests.ps1 -Output Detailed`. Complete regression: `Invoke-Pester -Path ./tests -Output Detailed`. The tests replace Exchange boundaries, use only ephemeral test signing material and simulate trust. They do not establish RAID-D05 readiness or live Exchange compatibility.
