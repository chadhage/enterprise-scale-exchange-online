# Net-New Exchange Administrator Journey

EXR-008, source review 2026-09-21. Start with an independently provisioned Worldwide tenant, verified custom domain, existing licensed user mailboxes, approved operator access and current owner attestations. This is an ordered Exchange-only procedure, not a tenant build or universal conformance claim. Run one numbered step at a time in PowerShell 7.5+ from `samples/contoso-exchange-online-managed-service`; retain variables in the same controlled session. Stop at every refusal. Do not paste the entire page into a production session.

The active contracts are [Exchange-only scope](EXCHANGE-ONLY.md), [approved change and rollback](APPROVED-CHANGE.md), and [frozen evidence](EXCHANGE-GO-LIVE.md). Those guides own artifact formats, trust, recovery and exit meanings; this page supplies their onboarding sequence, not replacement gates. The [dated inventory](EXR007-RECOMMENDATION-INVENTORY.md) and its admitted gaps remain authoritative. EXR-009/010/011 and EXR-007-A01 through A08 are not implemented or certified by this journey. Broad documentation reconciliation remains EXR-012.

## 1. Resolve Inputs And Owner Handoffs

Use a protected, independently reviewed JSON input file outside source control. Load it with `$journey = Get-Content -LiteralPath 'C:\ApprovedExchange\journey.json' -Raw | ConvertFrom-Json -AsHashtable`. Every example value below is synthetic; substitute approved values. Handoff `Approved` is an externally supplied attestation, not something this procedure discovers or certifies. Protect its provenance through the independent change channel. Never set it to true just to continue.

| Input | Example / provenance and stop condition |
| --- | --- |
| `TenantId`, `Cloud` | Tenant GUID from platform owner; `O365Default` only in this procedure. Sovereign/hybrid environments require a separately reviewed journey. |
| `Domain`, `DomainType` | `contoso.example`, `Authoritative` from verified-domain and routing design. Authoritative is a local all-recipients-in-Exchange topology choice, not a universal recommendation. Internal relay requires reviewed routing/connectors and is outside this net-new example. |
| `Operator` | `operator@contoso.example`, approved interactive Exchange identity, authentication and consent already provided by the identity owner. |
| `Mailboxes` | `["pilot@contoso.example"]`, complete approved onboarding/pilot user list from licensing owner, already provisioned. The script never creates these users or assigns licenses. |
| `OperationsMailbox` | `secops@contoso.example`, approved shared mailbox name/address. Also use an approved existing address for `EXTERNAL_POSTMASTER_SMTP_ADDRESS` in baseline parameters. |
| `PriorityGroup`, `PriorityMembers`, `GroupOwner` | `priority-users@contoso.example`, `["pilot@contoso.example"]`, `pilot@contoso.example`; approved flat membership and manager, not nested expansion or a delegation grant. |
| `Preset` | `Standard`, with Strict for the priority group in the shipped profile. This is a supplied rollout choice; exact effective setting reconciliation remains EXR-010. |
| `ParameterPath` | `C:\ApprovedExchange\parameters.json`, resolved copy of [sample parameters](../config/parameters.exchange-only.sample.json). Domain, tenant, operations address and group must match this journey. Licensing owner supplies current tenant and per-recipient entitlement. EOP checks run without Defender; the full licensed journey needs applicable Exchange and ATP plans. Unavailable Defender controls remain NotEntitled, not Pass. Tabletop cadence does not require THREAT_INTELLIGENCE. Supply the approved recipient matrix and reporting delivery observations described in [Exchange email protection](EXCHANGE-EMAIL-PROTECTION.md). |
| `ConfigurationPath` | Approved Exchange-only configuration with explicit RBAC, MRM, hold and encryption contracts. The shipped template is not legal authorization; resolve governance values before running the journey. |
| `ArtifactRoot`, `ChangeId` | New protected absolute directory `C:\ApprovedExchange\CHG008`, unique `CHG008`. Protect receipts and signer metadata separately as required in APPROVED-CHANGE. |
| `AuthorityPath`, `ApprovalIdentity`, `CertificateThumbprint` | Independently administered public signer JSON, different approver identity, existing certificate thumbprint supplied by PKI/change authority. No private keys in JSON or the repository. |
| `ConfigurationHash` | Independently approved resolved SHA256 for the shipped Exchange-only profile and parameters, obtained using `Get-BaselineExchangeContext` as in the frozen guide. Do not learn expected bindings from incoming evidence. |
| `Handoffs` | Records named Tenant, Domain, Identity, License, Access, Dns, Signing, Change and Client. Each has `Owner`, `Reference`, `TenantId`, boolean `Approved`, future `ExpiresUtc`. Reference binds this entire approved input bundle and its scope; owner names and ticket strings alone are not proof. |
| `Validation` | Supplied after step 10, one record each for Inbound, Outbound, Internal, OWA and Outlook, fields below. Do not pre-fill success before execution. |

Example handoff record (repeat with the actual accountable owner and evidence for each required name):

```json
{"Owner":"Named platform owner","Reference":"approved-record-008","TenantId":"11111111-2222-3333-4444-555555555555","Approved":false,"ExpiresUtc":"2026-09-22T12:00:00Z"}
```

Tenant/isolation approval routes to RAID-D01; domain, identities, licensing, mailbox provisioning and client access to RAID-D02; authentication, consent, scoped Exchange permissions and PIM to RAID-D02/D03; DNS publication and cutover to RAID-D04; signing and independent change authorization to RAID-D05. These are [external handoffs](../../../.github/RAID.md), never instructions to provision them. Change approval must explicitly cover foundational recipient creation, accepted-domain type, exact membership, portal initialization and later signed hardening. Foundation steps are not covered by the hardening rollback file.

<!-- journey:inputs -->
```powershell
$ErrorActionPreference = 'Stop'
foreach ($field in @('TenantId','Cloud','Domain','DomainType','Operator','Mailboxes','OperationsMailbox','PriorityGroup','PriorityMembers','GroupOwner','Preset','ParameterPath','ArtifactRoot','ChangeId','AuthorityPath','ApprovalIdentity','CertificateThumbprint','ConfigurationHash','ConfigurationPath','Handoffs')) {
    if (-not $journey.ContainsKey($field) -or $null -eq $journey[$field] -or @($journey[$field]).Count -eq 0 -or [string]::IsNullOrWhiteSpace([string]$journey[$field])) { throw "JourneyInputRequired:$field" }
}
$tenantGuid = [guid]::Empty
if (-not [guid]::TryParse($journey.TenantId, [ref]$tenantGuid) -or $tenantGuid -eq [guid]::Empty) { throw 'JourneyTenantInvalid: RAID-D01' }
$routes = @{ Tenant = 'RAID-D01'; Domain = 'RAID-D02'; Identity = 'RAID-D02'; License = 'RAID-D02'; Access = 'RAID-D03'; Dns = 'RAID-D04'; Signing = 'RAID-D05'; Change = 'RAID-D05'; Client = 'RAID-D02' }
foreach ($name in @('Tenant','Domain','Identity','License','Access','Dns','Signing','Change','Client')) {
    if (-not $journey.Handoffs.ContainsKey($name)) { throw "JourneyHandoffRequired:$name $($routes[$name])" }
    $record = $journey.Handoffs[$name]
    $expires = [datetimeoffset]::MinValue
    if ($record -isnot [Collections.IDictionary] -or [string]::IsNullOrWhiteSpace($record.Owner) -or [string]::IsNullOrWhiteSpace($record.Reference) -or $record.TenantId -ne $journey.TenantId -or $record.Approved -isnot [bool] -or -not $record.Approved -or -not [datetimeoffset]::TryParse($record.ExpiresUtc, [ref]$expires) -or $expires -le [datetimeoffset]::UtcNow) { throw "JourneyHandoffInvalid:$name $($routes[$name])" }
}
if ($journey.Cloud -ne 'O365Default') { throw 'JourneyCloudUnsupported: RAID-D02' }
if ($journey.DomainType -ne 'Authoritative') { throw 'JourneyTopologyUnsupported: obtain a reviewed routing design' }
if ($journey.Preset -ne 'Standard') { throw 'JourneyPresetUnsupported: reconcile rollout with approved profile' }
foreach ($address in @($journey.Mailboxes) + @($journey.OperationsMailbox,$journey.PriorityGroup)) {
    if ($address -notmatch '^[^@\s]+@[^@\s]+$' -or ($address -split '@')[1] -ne $journey.Domain) { throw 'JourneyRecipientScope: RAID-D02' }
}
if (@($journey.PriorityMembers | Where-Object { $_ -notin $journey.Mailboxes }).Count -or $journey.GroupOwner -notin $journey.Mailboxes) { throw 'JourneyMembershipUnapproved: obtain approved provisioned recipients' }
if ($journey.ApprovalIdentity -eq $journey.Operator) { throw 'JourneyIndependentApproverRequired: RAID-D05' }
```

## 2. Module, Access And Tenant Session

Have the workstation owner supply PowerShell 7.5+ and ExchangeOnlineManagement 3.7+ (including `Get-MessageTraceV2`). No module installation occurs here. The access owner must authorize the specific commands, parameters and recipient/configuration scopes, including recipient creation/group membership, accepted domains, transport/organization/client policies and preset assignments. Typical Exchange roles include Mail Recipients, Distribution Groups, Remote and Accepted Domains, Transport Hygiene and the appropriate organization configuration roles; names alone do not prove effective scope. The owner uses the supported [cmdlet permission discovery procedure](https://learn.microsoft.com/powershell/exchange/find-exchange-cmdlet-permissions). Do not grant Organization Management or Global Administrator as a workaround. Group membership below uses approved Exchange administrator rights, not a claim that the operator owns every group.

Start without other Exchange sessions. Authenticate interactively through the already approved mechanism; never put credentials in this guide. Inspect identity, tenant and connected state. Any denied parameter/scope or collection failure stops; do not catch it and assume the object is absent.

<!-- journey:session -->
```powershell
if ($PSVersionTable.PSVersion -lt [version]'7.5') { throw 'JourneyPowerShellRequired: workstation owner' }
$module = @(Get-Module -ListAvailable ExchangeOnlineManagement | Where-Object Version -GE ([version]'3.7.0'))
if (-not $module.Count) { throw 'JourneyModuleRequired: ExchangeOnlineManagement 3.7+; workstation owner' }
Import-Module ExchangeOnlineManagement -MinimumVersion 3.7.0
Connect-ExchangeOnline -UserPrincipalName $journey.Operator -ExchangeEnvironmentName $journey.Cloud -ShowBanner:$false
$sessions = @(Get-ConnectionInformation | Where-Object State -EQ Connected)
if ($sessions.Count -ne 1 -or $sessions[0].TenantID -ne $journey.TenantId -or $sessions[0].UserPrincipalName -ne $journey.Operator) { throw 'JourneySessionMismatch: disconnect wrong sessions; RAID-D02' }
$requiredCommands = @('Get-AcceptedDomain','Set-AcceptedDomain','Get-Mailbox','Get-Recipient','New-Mailbox','Get-DistributionGroup','New-DistributionGroup','Get-DistributionGroupMember','Add-DistributionGroupMember','Get-EOPProtectionPolicyRule','Get-ATPProtectionPolicyRule','Get-TransportConfig','Set-TransportConfig','Get-OrganizationConfig','Set-OrganizationConfig','Get-ExternalInOutlook','Set-ExternalInOutlook','Get-RemoteDomain','Set-RemoteDomain','Get-CASMailbox','Set-CASMailbox','Get-CASMailboxPlan','Set-CASMailboxPlan','Get-HostedOutboundSpamFilterPolicy','Set-HostedOutboundSpamFilterPolicy','Set-EOPProtectionPolicyRule','Enable-EOPProtectionPolicyRule','Set-ATPProtectionPolicyRule','Enable-ATPProtectionPolicyRule','Get-MessageTraceV2')
foreach ($commandName in $requiredCommands) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) { throw "JourneyPermissionRequired:$commandName RAID-D02/RAID-D03" }
}
$requiredParameters = @{
    'Get-AcceptedDomain' = @('Identity')
    'Set-AcceptedDomain' = @('Identity','DomainType')
    'Get-Mailbox' = @('Identity')
    'Get-Recipient' = @('ResultSize')
    'New-Mailbox' = @('Shared','Name','Alias','PrimarySmtpAddress')
    'Get-DistributionGroup' = @('Identity')
    'New-DistributionGroup' = @('Type','Name','Alias','PrimarySmtpAddress','ManagedBy','MemberJoinRestriction','MemberDepartRestriction')
    'Get-DistributionGroupMember' = @('Identity','ResultSize')
    'Add-DistributionGroupMember' = @('Identity','Member','BypassSecurityGroupManagerCheck')
    'Get-MessageTraceV2' = @('MessageId','SenderAddress','RecipientAddress','StartDate','EndDate','ResultSize')
}
foreach ($commandName in $requiredParameters.Keys) {
    $availableCommand = Get-Command $commandName -ErrorAction Stop
    foreach ($parameterName in $requiredParameters[$commandName]) {
        if (-not $availableCommand.Parameters.ContainsKey($parameterName)) { throw "JourneyPermissionRequired:$commandName.$parameterName RAID-D02/RAID-D03" }
    }
}
if (-not (Test-Path -LiteralPath $journey.ParameterPath -PathType Leaf)) { throw 'JourneyParameterFileRequired: obtain the approved resolved parameter file' }
Import-Module ./scripts/ExchangeOnlineBaseline.Common.psd1 -Force -DisableNameChecking
$context = Get-BaselineExchangeContext -ParameterPath $journey.ParameterPath -ConfigurationPath $journey.ConfigurationPath
if ($context.Parameters.MICROSOFT_ENTRA_TENANT_GUID -ne $journey.TenantId -or $context.Parameters.PRIMARY_SMTP_DOMAIN -ne $journey.Domain -or $context.Parameters.SECURITY_OPERATIONS_MAILBOX -ne $journey.OperationsMailbox -or $context.Parameters.MAIL_ENABLED_PRIORITY_USERS_GROUP -ne $journey.PriorityGroup) { throw 'JourneyParameterMismatch: obtain one consistent independently approved input bundle' }
if ($context.Hash -ne $journey.ConfigurationHash) { throw 'JourneyConfigurationMismatch: stop and obtain the approved resolved digest' }
```

## 3. Check The Accepted Domain And Approved Type

In `https://admin.exchange.microsoft.com`, inspect **Mail flow > Accepted domains**, select the approved verified domain and confirm **Authoritative** only for this approved all-cloud topology. PowerShell below is the executable equivalent. Missing domain means return to domain/platform owner; this journey neither verifies nor creates a tenant domain. Capture before/after type in the change record. Never derive an MX target from `Get-AcceptedDomain`.

<!-- journey:domain -->
```powershell
try { $domains = @(Get-AcceptedDomain -ErrorAction Stop | Where-Object { [string]$_.DomainName -eq $journey.Domain }) }
catch { throw "JourneyReadFailed:AcceptedDomain $($_.Exception.Message)" }
if ($domains.Count -eq 0) { throw 'JourneyAcceptedDomainMissing: RAID-D02 verified-domain owner' }
if ($domains.Count -ne 1) { throw 'JourneyAcceptedDomainAmbiguous: investigate domain inventory' }
$domainBefore = $domains[0].DomainType
if ([string]$domainBefore -ne $journey.DomainType) { Set-AcceptedDomain -Identity $domains[0].Identity -DomainType $journey.DomainType -ErrorAction Stop }
$domainAfter = @(Get-AcceptedDomain -Identity $domains[0].Identity -ErrorAction Stop)
if ($domainAfter.Count -ne 1 -or [string]$domainAfter[0].DomainType -ne $journey.DomainType) { throw 'JourneyDomainReadback: stop and investigate' }
```

## 4. Check User Mailboxes, Then Create The Operations Shared Mailbox

EAC **Recipients > Mailboxes** must already show each approved licensed user as UserMailbox. Provisioning delay is not permission to create an identity or reassign a license. Stop with the licensing/platform owner. For the shared mailbox use **Add a shared mailbox**, approved name/address, then verify SharedMailbox. The equivalent command creates only the Exchange shared mailbox; its associated account must not be used for direct sign-in. Identity owner separately attests sign-in blocking under RAID-D02/D03. Capacity over 50 GB, archive/hold features and delegates require their applicable licenses and separately approved scope. This step grants neither FullAccess nor SendAs; independent delegation is EXR-007-A05, not implicit in creation.

<!-- journey:mailboxes -->
```powershell
foreach ($address in $journey.Mailboxes) {
    try { $mailbox = @(Get-Mailbox -Identity $address -ErrorAction Stop) }
    catch { throw "JourneyMailboxNotProvisioned:$address RAID-D02" }
    if ($mailbox.Count -ne 1 -or [string]$mailbox[0].PrimarySmtpAddress -ne $address -or [string]$mailbox[0].RecipientTypeDetails -ne 'UserMailbox') { throw "JourneyMailboxNotProvisioned:$address RAID-D02" }
}
$recipients = @(Get-Recipient -ResultSize Unlimited -ErrorAction Stop)
$existing = @($recipients | Where-Object { [string]$_.PrimarySmtpAddress -eq $journey.OperationsMailbox -or @($_.EmailAddresses) -icontains "smtp:$($journey.OperationsMailbox)" })
if ($existing.Count -gt 1 -or ($existing.Count -eq 1 -and [string]$existing[0].RecipientTypeDetails -ne 'SharedMailbox')) { throw 'JourneyRecipientCollision: operations address; do not overwrite' }
if ($existing.Count -eq 0) {
    New-Mailbox -Shared -Name 'Exchange Security Operations' -Alias ($journey.OperationsMailbox -split '@')[0] -PrimarySmtpAddress $journey.OperationsMailbox -ErrorAction Stop | Out-Null
}
$shared = @(Get-Mailbox -Identity $journey.OperationsMailbox -ErrorAction Stop)
if ($shared.Count -ne 1 -or [string]$shared[0].PrimarySmtpAddress -ne $journey.OperationsMailbox -or [string]$shared[0].RecipientTypeDetails -ne 'SharedMailbox') { throw 'JourneySharedReadback: stop; retain created-object identity for reviewed recovery' }
```

## 5. Create The Mail-Enabled Priority Group And Exact Membership

EAC **Recipients > Groups > Add a group > Mail-enabled security**: use the approved name, address, owner and members. PowerShell below performs that same Exchange operation. This is an email policy targeting group, not Entra priority-account tagging, license assignment or an access grant. Keep membership closed. Existing surplus members cause refusal, not automatic deletion. Record newly created object identity; foundational recovery requires an independently reviewed removal/change, never deletion of an existing mailbox or group to restart.

<!-- journey:groups -->
```powershell
$recipients = @(Get-Recipient -ResultSize Unlimited -ErrorAction Stop)
$existing = @($recipients | Where-Object { [string]$_.PrimarySmtpAddress -eq $journey.PriorityGroup -or @($_.EmailAddresses) -icontains "smtp:$($journey.PriorityGroup)" })
if ($existing.Count -gt 1 -or ($existing.Count -eq 1 -and [string]$existing[0].RecipientTypeDetails -ne 'MailUniversalSecurityGroup')) { throw 'JourneyRecipientCollision: priority address; do not overwrite' }
if (-not $existing.Count) {
    New-DistributionGroup -Type Security -Name 'Exchange Priority Users' -Alias ($journey.PriorityGroup -split '@')[0] -PrimarySmtpAddress $journey.PriorityGroup -ManagedBy $journey.GroupOwner -MemberJoinRestriction Closed -MemberDepartRestriction Closed -ErrorAction Stop | Out-Null
}
$group = @(Get-DistributionGroup -Identity $journey.PriorityGroup -ErrorAction Stop)
if ($group.Count -ne 1 -or [string]$group[0].PrimarySmtpAddress -ne $journey.PriorityGroup -or [string]$group[0].RecipientTypeDetails -ne 'MailUniversalSecurityGroup') { throw 'JourneyGroupReadback: stop and investigate' }
$members = @(Get-DistributionGroupMember -Identity $journey.PriorityGroup -ResultSize Unlimited -ErrorAction Stop)
if (@($members | Where-Object { [string]$_.PrimarySmtpAddress -notin $journey.PriorityMembers }).Count) { throw 'JourneyMembershipDrift: obtain a separately reviewed membership change' }
foreach ($address in $journey.PriorityMembers) {
    if ($address -notin @($members | ForEach-Object { [string]$_.PrimarySmtpAddress })) { Add-DistributionGroupMember -Identity $journey.PriorityGroup -Member $address -BypassSecurityGroupManagerCheck -ErrorAction Stop }
}
$membersAfter = @(Get-DistributionGroupMember -Identity $journey.PriorityGroup -ResultSize Unlimited -ErrorAction Stop | ForEach-Object { [string]$_.PrimarySmtpAddress })
if ($membersAfter.Count -ne @($journey.PriorityMembers).Count -or @(Compare-Object @($journey.PriorityMembers | Sort-Object) @($membersAfter | Sort-Object)).Count) { throw 'JourneyMembershipReadback: stop and investigate' }
```

## 6. Initialize Presets In The Supported Portal

This is a deliberate operator pause and an Exchange protection change under the foundational approval. In `https://security.microsoft.com/presetSecurityPolicies` (**Email & collaboration > Policies & rules > Threat policies > Preset Security Policies**), turn **Standard protection** On and select **Manage protection settings**. On **Apply Exchange Online Protection**, choose **Specific recipients > Domains** and the approved domain. On **Apply Defender for Office 365 protection**, choose the same fully licensed domain, review approved impersonation targets, then review and confirm. Do not also select Users or Groups on the Standard condition: different condition types combine with AND. Repeat for **Strict protection**, choosing **Specific recipients > Groups** and the approved priority group on both recipient pages. Record the actual portal review and recipient selections. Do not select Safe Documents or other workloads. Do not publish MX yet.

First activation creates Microsoft-managed component policies and their rules. Do not call `New-EOPProtectionPolicyRule`/`New-ATPProtectionPolicyRule` to manufacture them, and do not edit individual preset component settings. Domain targeting at initialization is itself an approved protection change, even before MX cutover. Step 8 previews the final Standard priority/operations exclusions and Strict group from the approved profile using the existing supported rule adapters. Missing entitlement or portal permission returns to the licensing/access owner. After portal propagation, run this readback; absent or disabled rules stop before hardening preview.

<!-- journey:presets -->
```powershell
try {
    $eopRules = @(Get-EOPProtectionPolicyRule -ErrorAction Stop)
    $atpRules = @(Get-ATPProtectionPolicyRule -ErrorAction Stop)
}
catch { throw "JourneyPresetReadFailed: check Exchange permissions/service health before resuming; $($_.Exception.Message)" }
foreach ($name in @('Standard Preset Security Policy','Strict Preset Security Policy')) {
    $eop = @($eopRules | Where-Object Name -EQ $name)
    $atp = @($atpRules | Where-Object Name -EQ $name)
    if ($eop.Count -ne 1 -or $atp.Count -ne 1 -or [string]$eop[0].State -ne 'Enabled' -or [string]$atp[0].State -ne 'Enabled') { throw "JourneyPresetInitializationRequired:$name use the Defender portal, then read back" }
}
```

## 7. Resolve Approved Hardening, Not A Universal Default

Use the shipped Exchange-only profile. Review resolved values with the client and security owners before changes: disable SMTP AUTH by default, POP/IMAP on existing mailboxes and plans, EWS disabled, default mailbox auditing on, external sender identification on, external automatic forwarding off and external OOF blocked (`None`). These include local hardening/business choices; EWS exceptions require the existing retirement/approval contract. Do not disable MAPI/OWA or configure lifecycle/holds by copying historical examples. Audit SMTP AUTH mailbox overrides and forwarding separately with retained evidence; this scoped change does not claim to remediate every control. Reporting, quarantine, DKIM activation and other supported scopes use APPROVED-CHANGE only when individually approved; their broader gaps remain on the backlog.

<!-- journey:hardening -->
```powershell
Import-Module ./scripts/ExchangeOnlineBaseline.Common.psd1 -Force -DisableNameChecking
$context = Get-BaselineExchangeContext -ParameterPath $journey.ParameterPath -ConfigurationPath $journey.ConfigurationPath
if ($context.Parameters.MICROSOFT_ENTRA_TENANT_GUID -ne $journey.TenantId -or $context.Parameters.PRIMARY_SMTP_DOMAIN -ne $journey.Domain -or $context.Parameters.SECURITY_OPERATIONS_MAILBOX -ne $journey.OperationsMailbox -or $context.Parameters.MAIL_ENABLED_PRIORITY_USERS_GROUP -ne $journey.PriorityGroup) { throw 'JourneyParameterMismatch: obtain one consistent independently approved input bundle' }
if ($context.Hash -ne $journey.ConfigurationHash) { throw 'JourneyConfigurationMismatch: stop and obtain the approved resolved digest' }
$change = @{
    ParameterPath = $journey.ParameterPath; ConfigurationPath = $journey.ConfigurationPath
    ArtifactRoot = $journey.ArtifactRoot; ChangeId = $journey.ChangeId; RequestedBy = $journey.Operator
    AuthorizedSignerPath = $journey.AuthorityPath
    PreviewPath = Join-Path $journey.ArtifactRoot "preview-$($journey.ChangeId).json"
    ApprovalPath = Join-Path $journey.ArtifactRoot "approval-$($journey.ChangeId).json"
}
```

## 8. Immutable Preview And Review

Review the typed before/after operations and independent configuration digest; a console plan or WhatIf transcript is not approval. Unsupported scopes or missing rules stop. The preview uses the existing reversible scopes and never repeats foundational creation.

<!-- journey:preview -->
```powershell
./scripts/Invoke-ExchangeOnlineChange.ps1 -Stage Preview @change -Scope Transport,Organization,ExternalSender,RemoteDomains,MailboxProtocols,MailboxPlans,OutboundSpam,EopPresets,AtpPresets -Confirm:$false
```

## 9. Independent Approval

Stop for the different approver to review the exact preview bytes. The approver reconstructs `$change` from the protected approved paths in their own controlled signing session. Use the existing enterprise certificate and authority file; never create self-signed production trust. Transfer approved artifacts unchanged. The requester must not run this as the approver merely by changing a string.

<!-- journey:approve -->
```powershell
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$($journey.CertificateThumbprint)"
./scripts/Invoke-ExchangeOnlineChange.ps1 -Stage Approve @change -ApprovalIdentity $journey.ApprovalIdentity -SigningCertificate $certificate -Confirm:$false
./scripts/Invoke-ExchangeOnlineChange.ps1 -Stage Validate @change
```

## 10. Approved Apply And Readback

The authorized Exchange operator resumes with the same `$change`, after the approved window begins. `-SkipConnection` consumes the one checked session, not synthetic evidence. The real apply performs pre/post readback and stores immutable receipts. Review `postchange-<ChangeId>.json` for Succeeded. On drift, expiry, partial mutation or readback failure, stop and use APPROVED-CHANGE recovery; the generated rollback covers only these signed attempted operations, not foundational objects or external DNS. Do not replay by deleting locks. The command below is documentation, not authorization to apply to a tenant during offline engineering.

<!-- journey:apply -->
```powershell
./scripts/Deploy-ExchangeOnlineBaseline.ps1 @change -Apply -SkipConnection -Confirm:$false
$postchange = Get-Content -LiteralPath (Join-Path $journey.ArtifactRoot "postchange-$($journey.ChangeId).json") -Raw | ConvertFrom-Json
if ($postchange.Status -ne 'Succeeded') { throw 'JourneyApplyFailed: inspect immutable receipts and approved rollback' }
```

## 11. Collect, Freeze, Sign And Verify

Complete the three independently signed operational artifacts and all retained evidence prerequisites in EXCHANGE-ONLY first. Do not fabricate an exercise, a policy outcome or a signed phase merely to reach exit 0. Run the following integration of the existing frozen guide, preserving its independent review pause and signer role. If collection finds unresolved controls, stop and route findings to their owner; do not manufacture desired observations. A new environment can legitimately stop here pending EXR-009/010/011 or external prerequisites. This does not block offline authoring of the journey or certify a live environment.

<!-- journey:frozen -->
```powershell
$runDirectory = Join-Path $journey.ArtifactRoot 'evidence'
./scripts/Test-ExchangeOnlineBaseline.ps1 -ParameterPath $journey.ParameterPath -ConfigurationPath $journey.ConfigurationPath -OutputPath $runDirectory -SkipConnection
if ($LASTEXITCODE -ne 0) { throw "JourneyCollectionRefused:$LASTEXITCODE inspect findings; do not sign replacements" }
$evidencePath = Join-Path $runDirectory 'frozen-exchange-evidence.json'
if (Test-Path -LiteralPath $evidencePath) { throw 'JourneyFrozenPathExists: use a new reviewed run' }
Copy-Item -LiteralPath (Join-Path $runDirectory 'exchange-online-evidence.json') -Destination $evidencePath
$evidenceHash = (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash
(Get-Item -LiteralPath $evidencePath).IsReadOnly = $true
$gateInputs = @{
    ParameterPath = $journey.ParameterPath; ConfigurationPath = $journey.ConfigurationPath
    EvidencePath = $evidencePath; EvidenceSignaturePath = Join-Path $runDirectory 'frozen-exchange-evidence.p7s'
    EvidenceSignerIdentity = $journey.ApprovalIdentity; AuthorizedSignerPath = $journey.AuthorityPath
    ExpectedEvidenceHash = $evidenceHash; ExpectedConfigurationHash = $journey.ConfigurationHash
    MaximumEvidenceAge = [timespan]::FromHours(24)
}
Write-Output "Independent reviewer: retain and compare exact-file SHA256 $evidenceHash with the approved change record before signing."
Read-Host 'Pause: independent reviewer/signing session must review these exact bytes; Enter only after approval' | Out-Null
./scripts/Test-ExchangeOnlineBaseline.ps1 @gateInputs -SignEvidence -SigningCertificate $certificate
if ($LASTEXITCODE -ne 0) { throw "JourneySigningRefused:$LASTEXITCODE RAID-D05" }
$gate = ./scripts/Test-ExchangeOnlineBaseline.ps1 @gateInputs -GoLive
if ($LASTEXITCODE -ne 0) { throw "JourneyFrozenVerifyRefused:$LASTEXITCODE" }
$gate
```

Verifier reconstructs `$gateInputs` from the independently retained hashes and approved paths when using another host. Never recompute the expected hash from an untrusted incoming artifact. Verification performs no recollection. `ApprovedException` stays distinct from Pass; `ExternalReadiness.Status` remains Unverified even when Exchange exit is 0. This is not permission for DNS cutover.

## 12. DNS-Owner Release, Mail Flow And Clients

**Do not move MX before DNS-owner readiness approval.** This page contains no DNS publishing command. The DNS owner supplies the exact Microsoft-provided MX target (not an accepted-domain property), Autodiscover/SPF/DKIM/DMARC publication and propagation proof, cutover/rollback window and approval reference under RAID-D04. Populate `Handoffs.Dns.CutoverApproved` with the actual boolean approval only when that owner releases the window; renew expired attestations. Domain completeness/authentication automation remains EXR-011. All sender/receiver tests use isolated approved test recipients and content.

After that owner performs authorized publication, the approved pilot sends one uniquely identifiable message to an external controlled recipient, receives one reply, and sends an internal message to the operations mailbox. Both recipients verify actual delivery, headers, reply behavior and no unexpected NDR. In EAC **Mail flow > Message trace** match each Internet Message-ID, sender, recipient and time. Outlook on the web (`https://outlook.office.com/mail/`) must open the pilot mailbox and send/receive; supported desktop Outlook must discover the mailbox via approved Autodiscover, sign in using approved modern authentication, and send/receive. Keep intended POP/IMAP/EWS-disabled client impact in the acceptance record. Trace Delivered alone does not prove recipient reading, application functionality or DNS authentication.

Supply `Validation` records for `Inbound`, `Outbound`, `Internal`, `OWA`, `Outlook`: `Kind`, boolean `Passed`, `Owner`, `Reference`, `TenantId`, `Mailbox` (the pilot), `ObservedUtc`. Mail-flow records also require `Sender`, `Recipient`, `MessageId`, `StartUtc`, `EndUtc`, bound to the approved test scope and within the last 24 hours; the first three must respectively receive at the pilot, send from the pilot, and deliver pilot-to-operations. Client records identify version/device, authentication and send/receive evidence in the referenced record. An external failure remains a failure, not an Exchange Pass. The code reads Exchange trace; it does not send unauthenticated SMTP or enable a legacy protocol for testing.

<!-- journey:validation -->
```powershell
$dns = $journey.Handoffs.Dns
if ($dns.CutoverApproved -isnot [bool] -or -not $dns.CutoverApproved -or [datetimeoffset]$dns.ExpiresUtc -le [datetimeoffset]::UtcNow) { throw 'JourneyDnsCutoverRequired: RAID-D04; do not move MX' }
foreach ($kind in @('Inbound','Outbound','Internal','OWA','Outlook')) {
    $records = @($journey.Validation | Where-Object Kind -EQ $kind)
    if ($records.Count -ne 1) { throw "JourneyValidationRequired:$kind client/mail owner" }
    $record = $records[0]
    $observed = [datetimeoffset]::MinValue
    if ($record.Passed -isnot [bool] -or -not $record.Passed -or [string]::IsNullOrWhiteSpace($record.Owner) -or [string]::IsNullOrWhiteSpace($record.Reference) -or $record.TenantId -ne $journey.TenantId -or $record.Mailbox -notin $journey.Mailboxes -or -not [datetimeoffset]::TryParse($record.ObservedUtc, [ref]$observed) -or $observed -gt [datetimeoffset]::UtcNow -or $observed -lt [datetimeoffset]::UtcNow.AddHours(-24)) { throw "JourneyValidationFailed:$kind obtain current actual test evidence" }
    if ($kind -in @('Inbound','Outbound','Internal')) {
        $start = [datetimeoffset]::MinValue
        $end = [datetimeoffset]::MinValue
        if ([string]::IsNullOrWhiteSpace($record.MessageId) -or [string]::IsNullOrWhiteSpace($record.Sender) -or [string]::IsNullOrWhiteSpace($record.Recipient) -or -not [datetimeoffset]::TryParse($record.StartUtc, [ref]$start) -or -not [datetimeoffset]::TryParse($record.EndUtc, [ref]$end) -or $start -ge $end -or $start -lt [datetimeoffset]::UtcNow.AddHours(-24) -or $end -gt [datetimeoffset]::UtcNow) { throw "JourneyValidationFailed:$kind invalid message/time binding" }
        if (($kind -eq 'Inbound' -and $record.Recipient -ne $record.Mailbox) -or ($kind -eq 'Outbound' -and $record.Sender -ne $record.Mailbox) -or ($kind -eq 'Internal' -and ($record.Sender -ne $record.Mailbox -or $record.Recipient -ne $journey.OperationsMailbox))) { throw "JourneyValidationFailed:$kind wrong recipient scope" }
        if ($kind -in @('Inbound','Outbound')) {
            $externalAddress = if ($kind -eq 'Inbound') { $record.Sender } else { $record.Recipient }
            if ($externalAddress -notmatch '^[^@\s]+@[^@\s]+$' -or ($externalAddress -split '@')[1] -eq $journey.Domain) { throw "JourneyValidationFailed:$kind external endpoint required" }
        }
        $trace = @(Get-MessageTraceV2 -MessageId $record.MessageId -SenderAddress $record.Sender -RecipientAddress $record.Recipient -StartDate $start.UtcDateTime -EndDate $end.UtcDateTime -ResultSize 5000 -ErrorAction Stop)
        if ($trace.Count -ne 1 -or $trace[0].MessageId -ne $record.MessageId -or $trace[0].SenderAddress -ne $record.Sender -or $trace[0].RecipientAddress -ne $record.Recipient -or $trace[0].Status -ne 'Delivered') { throw "JourneyMessageTraceMissing:$kind incomplete, ambiguous or undelivered trace" }
    }
}
[pscustomobject]@{ Status = 'ExchangeJourneyValidated'; TenantId = $journey.TenantId; ExternalReadiness = 'Unverified'; ReleaseAuthorized = $false }
```

Retain original user/client observations and trace with the frozen evidence hash and change receipts. Failure stops rollout and invokes the appropriate Exchange scoped rollback or DNS-owner rollback decision; this procedure never changes external routing. Get a separate launch decision from the service owner. Offline synthetic mail/client evidence is not live delivery proof.

## Verification And Sources

### Offline Walkthrough

Use PowerShell 7.5+ with Pester 5.7.1+ from the sample directory. No ExchangeOnlineManagement installation, tenant connection, credentials, DNS access or production certificate is needed for this test. Do not run the numbered operational blocks directly to perform the offline exercise; invoke the test harness instead:

```powershell
$result = Invoke-Pester -Path ./tests/unit/ExchangeAdministratorJourney.Tests.ps1 -Output Detailed -PassThru
'Total={0} Passed={1} Failed={2} Skipped={3} NotRun={4} FailedContainers={5}' -f $result.TotalCount, $result.PassedCount, $result.FailedCount, $result.SkippedCount, $result.NotRunCount, $result.FailedContainersCount
if ($result.FailedCount -or $result.FailedContainersCount -or $result.NotRunCount -or $result.PassedCount -ne $result.TotalCount) { throw 'Offline journey verification failed or incomplete' }
```

The [test](../tests/unit/ExchangeAdministratorJourney.Tests.ps1) extracts and executes the twelve marked PowerShell blocks in their documented order. Its [doubles helper](../tests/helpers/ExchangeJourneyDoubles.ps1) supplies synthetic owner attestations, a licensed pilot mailbox, an accepted domain initially requiring correction, and absent shared mailbox/group/preset rules. Creation changes the in-memory recipient inventory; preview and hardening include both the existing pilot and newly created shared mailbox. A modeled operator event initializes preset rules only after group membership exists.

The repository's actual preview, approval, validation, apply, collection and frozen-evidence code runs against local command doubles and temporary files. Cryptographic operations use a disposable test-only certificate and an isolated test trust root; the approved-change signature double checks signature bytes and that root but models revocation as Good. It does not validate enterprise PKI, revocation service availability or independent human approval. Synthetic operational evidence represents supplied prerequisites, not real exercises. The portal double is not portal automation or live compatibility proof. Command doubles are removed and the original module signature/chain functions restored after each case so later tests do not inherit synthetic trust.

Expected focused result: **78 passed, 0 failed**, comprising **77 negative cases and one ordered end-to-end positive case**, with no skipped or unrun tests. The positive case checks changed Exchange state, immutable preview/postchange artifacts, one evidence collection, a frozen hash and an admitted Exchange gate whose external readiness remains **Unverified**. Pester removes temporary artifacts on completion; they are not a retained live acceptance package.

Run the complete offline regression in a fresh process before accepting changes; reused interactive sessions can retain doubles from earlier test suites:

```powershell
pwsh -NoProfile -NonInteractive -Command '$result = Invoke-Pester -Path ./tests -Output None -PassThru; "Total=$($result.TotalCount) Passed=$($result.PassedCount) Failed=$($result.FailedCount) Skipped=$($result.SkippedCount) NotRun=$($result.NotRunCount) FailedContainers=$($result.FailedContainersCount)"; if ($result.FailedCount -or $result.FailedContainersCount -or $result.NotRunCount -or $result.PassedCount -ne $result.TotalCount) { exit 1 }'
```

EXR-008 verification: **3,747 passed, 0 failed**, baseline **3,669 + 78 journey cases**, no skipped/unrun tests or failed containers. Focused verification followed by the complete suite also passed sequentially in the same fresh process, checking journey teardown before full regression. This does not establish arbitrary interactive-session order independence. These counts describe offline repository verification, not live readiness.

| EXR-008 acceptance | Documented steps | Executable check |
| --- | --- | --- |
| Externally ready inputs, provenance and named stops | 1-2 | Missing fields/handoffs, invalid attestations, module/role/session and entitlement refusals before writes |
| Accepted domain and provisioned/created recipients | 3-5 | Domain/readback failures, mailbox/group collisions, membership drift; created shared mailbox included in preview |
| Supported preset initialization and approved hardening | 6-10 | Missing/disabled/unreadable rules, configuration binding; ordered portal event and actual local signed artifacts |
| Frozen evidence without external readiness promotion | 11 | One collection, exact frozen hash and admitted gate with external readiness Unverified |
| DNS-owner release, mail flow and client validation | 12 | Cutover refusal, missing/failed observations and missing trace; synthetic successful client/mail-flow evidence |

Offline success does not authorize live Apply, prove DNS publication or actual mail delivery, certify external readiness, or close the separately owned gaps listed at the top of this guide.

Microsoft sources reviewed 2026-09-21; re-review with EXR-007's 90-day/before-release cadence:

- [Accepted domains](https://learn.microsoft.com/exchange/mail-flow-best-practices/manage-accepted-domains/manage-accepted-domains), [Set-AcceptedDomain](https://learn.microsoft.com/powershell/module/exchangepowershell/set-accepteddomain).
- [Shared mailboxes](https://learn.microsoft.com/exchange/collaboration-exo/shared-mailboxes), [New-Mailbox](https://learn.microsoft.com/powershell/module/exchangepowershell/new-mailbox).
- [New-DistributionGroup](https://learn.microsoft.com/powershell/module/exchangepowershell/new-distributiongroup), [Add-DistributionGroupMember](https://learn.microsoft.com/powershell/module/exchangepowershell/add-distributiongroupmember).
- [Preset security policies](https://learn.microsoft.com/defender-office-365/preset-security-policies), [New-EOPProtectionPolicyRule](https://learn.microsoft.com/powershell/module/exchangepowershell/new-eopprotectionpolicyrule), [New-ATPProtectionPolicyRule](https://learn.microsoft.com/powershell/module/exchangepowershell/new-atpprotectionpolicyrule): first activation in portal, do not hand-create component policies.
- [Get-MessageTraceV2](https://learn.microsoft.com/powershell/module/exchangepowershell/get-messagetracev2), [Connect-ExchangeOnline](https://learn.microsoft.com/powershell/module/exchangepowershell/connect-exchangeonline).
