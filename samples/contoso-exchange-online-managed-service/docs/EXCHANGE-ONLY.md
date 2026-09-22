# Exchange-Only Execution Boundary

EXR-001 defines an execution boundary, not live readiness or a complete administrator walkthrough. Use PowerShell 7.5 or later for the scoped command path. The working directory for the example is `samples/contoso-exchange-online-managed-service`.

Start with the [net-new Exchange administrator journey](EXCHANGE-ADMINISTRATOR-JOURNEY.md) for ordered owner handoffs, module/access admission, accepted-domain and recipient setup, supported portal preset initialization, approved hardening, frozen verification and DNS-gated mail/client validation. It consumes this boundary and the existing change/evidence contracts; it does not provision a tenant or close the independently tracked recommendation gaps.

Both public scripts default to [exchange-only.v1.json](../config/exchange-only.v1.json). The [versioned manifest](../config/exchange-only.manifest.v1.json) retains 25 controls, declares 15 exclusions, and separately identifies 3 externally owned checks. The [schema](../config/exchange-only.schema.v1.json) rejects malformed settings. Unknown settings, excluded controls and missing retained controls are refused before connections or collection.

## Inputs And Preview

The [sample parameters](../config/parameters.exchange-only.sample.json) deliberately contain an unverified licensing handoff. The licensing owner supplies current tenant-bound service-plan names, recipient domains, owner, evidence reference and expiry under [RAID-D02](../../../.github/RAID.md). A tier label is not entitlement. Do not mark a handoff verified without independent evidence. Replace synthetic administrator values with externally approved inputs in a change-controlled parameter file outside source control, and substitute its path in this example.

```powershell
./scripts/Deploy-ExchangeOnlineBaseline.ps1 -ParameterPath ./config/parameters.exchange-only.sample.json -SkipConnection
```

The unmodified sample stops with `ExchangeEntitlementUnverified`. With an approved handoff the command returns `ExchangeOnlyPlan`, the resolved configuration hash, manifest version, retained control IDs and permitted Exchange operations. It connects to no service, performs no pre-change reads and makes no changes. This inventory is not a signed approval artifact. Use [Approved Exchange Change](APPROVED-CHANGE.md) for the executable immutable preview, external certificate approval, offline approval validation, scoped apply, pre/post readback and rollback procedure. It explicitly names the supported reversible scope; it does not apply or certify every control in this inventory. Exchange-only apply cannot fall back to the historical untyped rollback path.

## Domain Inventory

EXO-001 consumes explicit `domainInventory` from the active parameter file, using the [v1 input schema](../config/domain-inventory.schema.v1.json). It never infers a complete business inventory from the primary domain or from Exchange discovery. The inventory owner must enumerate all accepted, sending, initial onmicrosoft, subdomain and parked domains and supply tenant binding, source reference and timestamp. Sending domains need their own `senderSource` owner/reference/timestamp and `sendingSystem` (`ExchangeOnline` or `External`); inventory provenance is not substituted for sender provenance.

The following parameter fragment is synthetic, not approval, a discovered tenant or external readiness evidence. Its all-zero tenant, fixture references, owners and dates must be replaced with independently supplied change-controlled inputs. `complete: true` asserts only that the supplier has enumerated its intended denominator. Keep the existing licensing handoff unverified until the licensing owner supplies actual evidence. The sample below does not authorize any tenant connection or mutation.

```json
{
	"MICROSOFT_ENTRA_TENANT_GUID": "00000000-0000-0000-0000-000000000000",
	"PRIMARY_SMTP_DOMAIN": "contoso.example",
	"INITIAL_ONMICROSOFT_DOMAIN": "contoso.onmicrosoft.com",
	"domainInventory": {
		"schemaVersion": 1,
		"tenantId": "00000000-0000-0000-0000-000000000000",
		"complete": true,
		"source": { "owner": "Synthetic inventory owner", "reference": "fixture:inventory-not-approval", "suppliedAtUtc": "2026-09-21T00:00:00Z" },
		"domains": [
			{
				"domainName": "contoso.example", "accepted": true, "sending": true, "parked": false,
				"parentDomain": null, "domainType": "InternalRelay", "owner": "Synthetic Exchange owner",
				"topologyApproval": { "owner": "Synthetic routing owner", "reference": "fixture:split-routing-not-approval", "expiresOn": "2026-09-23T00:00:00Z" },
				"sendingSystem": "ExchangeOnline",
				"senderSource": { "owner": "Synthetic Exchange sender owner", "reference": "fixture:exchange-senders", "suppliedAtUtc": "2026-09-21T00:00:00Z" }
			},
			{
				"domainName": "contoso.onmicrosoft.com", "accepted": true, "sending": false, "parked": false,
				"parentDomain": null, "domainType": "Authoritative", "owner": "Synthetic Exchange owner"
			},
			{
				"domainName": "child.contoso.example", "accepted": true, "sending": false, "parked": false,
				"parentDomain": "contoso.example", "domainType": "Authoritative", "owner": "Synthetic subdomain owner"
			},
			{
				"domainName": "parked.accepted.example", "accepted": true, "sending": false, "parked": true,
				"parentDomain": null, "domainType": "Authoritative", "owner": "Synthetic parked-domain owner"
			},
			{
				"domainName": "sender.external.example", "accepted": false, "sending": true, "parked": false,
				"parentDomain": null, "domainType": null, "owner": "Synthetic external sender owner",
				"sendingSystem": "External",
				"senderSource": { "owner": "Synthetic external sender owner", "reference": "fixture:external-senders", "suppliedAtUtc": "2026-09-21T00:00:00Z" }
			},
			{
				"domainName": "parked.external.example", "accepted": false, "sending": false, "parked": true,
				"parentDomain": null, "domainType": null, "owner": "Synthetic external domain owner",
				"ownerAttestation": { "reference": "fixture:owner-assertion-not-certification", "suppliedAtUtc": "2026-09-21T00:00:00Z", "expiresOn": "2026-09-23T00:00:00Z" }
			}
		]
	}
}
```

From the sample directory, validate a supplied file's structure offline before any authorized collection:

```powershell
$parameters = Get-Content -LiteralPath ./config/parameters.exchange-only.sample.json -Raw | ConvertFrom-Json -AsHashtable -DateKind String
$inventoryJson = $parameters.domainInventory | ConvertTo-Json -Depth 30
Test-Json -Json $inventoryJson -SchemaFile ./config/domain-inventory.schema.v1.json
```

Runtime also validates exact tenant binding, integer version, strict booleans, nonfuture ISO 8601 provenance timestamps with explicit timezone, nonexpired approvals/attestations, IDNA domain syntax and unique normalized identities. Names normalize casing, surrounding whitespace and the trailing root dot. `parentDomain` must be explicitly null or a declared proper ancestor; known inventory ancestry cannot be hidden. Parked sending domains, unclassified entries, unowned domains and ExchangeOnline senders not marked accepted are refused. `InternalRelay` requires a separately supplied routing approval owner/reference/expiry, not a universal Authoritative conversion. Optional owner attestations require reference, supplied timestamp and expiry; their presence never certifies external readiness.

The approved primary inventory `domainType` must agree with `controls['EXO-001'].domainType` in the active configuration. For the approved relay example above, configure that control as `InternalRelay` as well; do not rewrite the inventory to conceal a routing conflict. Conflicting approved and configured primary topology is refused before an actionable preview or assessment Pass.

The adapter calls `Get-AcceptedDomain -ResultSize Unlimited` once, without `-Identity`. Complete observations are reconciled against all inventory entries marked accepted, including the explicitly configured initial onmicrosoft domain and primary domain. Missing or extra accepted names and domain-type drift produce `Fail`; malformed inputs are non-Pass. Raw errors, warnings, continuation envelopes, missing properties and ambiguous normalized identities produce `Error`, preserving partial raw output and collection timestamps. An empty but complete observation is membership drift, not a collection error. External-only sending and parked entries stay in the denominator without being required in Exchange or mislabeled NotApplicable.

`exchange-online-evidence.json` retains `Evidence[ControlId=EXO-001].DomainInventory` with normalized membership, topology, owner and independent source/sender/attestation provenance, alongside unchanged raw `Observation` records. Every entry's `ownerReadiness` remains `Unverified`, even when Exchange membership passes. Read evidence with `ConvertFrom-Json -DateKind String` to preserve supplied timestamp text. Historical direct `Test-AcceptedDomainControl -ExpectedDomain` calls retain their prior Authoritative-only behavior; the active ExchangeOnly path requires the supplied inventory.

Source S01 maps this contract to EXO-001 / `Test-AcceptedDomainControl` / `exchangeOnline.acceptedDomain`. This is the bounded EXR-011-A01 implementation, pending independent acceptance, not completion of EXR-011. DKIM selectors/signing lifecycle, DNS/SPF/DMARC/MX provenance and received-message proof remain A02/A03/A04; RAID-D04 is still Unconfirmed. No DNS, domain verification, tenant provisioning or external-owner certification is performed.

## Evidence And Scope

Invoke `scripts/Test-ExchangeOnlineBaseline.ps1` with `-ParameterPath` and `-OutputPath` to collect Exchange evidence. It connects only to Exchange Online unless `-SkipConnection` is supplied for an already established Exchange session or an offline test boundary. `exchange-online-evidence.json` contains exactly one evidence/result record per retained control, the profile version, manifest content hash, configuration hash, tenant, exclusions, external checks and explicitly unverified external readiness. No Graph inventory, PIM/access-review collector, global directory scan, DNS resolver, Purview, SIEM, Safe Documents or SPO/ODB/Teams collector is required, even with Defender service plans present.

EXO-010 observes Exchange role groups, members and role assignments without Graph. GOV-003 observes Exchange MRM `Get-RetentionPolicy` and mailbox policy assignments, not Purview retention. AUTH-001 observes Exchange DKIM state; DNS publication remains externally owned. These narrowed controls do not certify the external portion of the historical control. Other setting correctness and raw-adapter compatibility work remains tracked in EXR-002/003/005/009/010/011.

The [EXR-005 all-25 adapter audit](EXR005-ADAPTER-AUDIT.md) records each retained adapter's raw source, enumeration contract, decision boundary, reviewer-case coverage and remaining compatibility limits. It distinguishes 22 raw Exchange adapters from 3 signed local operational-artifact adapters and does not treat offline passing fixtures as live acceptance.

MON-003, OPS-001 and OPS-002 remain required operational controls. Missing or invalid signed local artifacts produce Error, never Pass or an exclusion. Optional `operationalEvidence` in the parameter file maps each of these IDs to `path`, `signerIdentity`, and `authorizedSigner` records (`Identity`, `Subject`, `Authority` equal to `ExchangeOnlineChangeApproval`). Trust/authority metadata comes from the external change authority, not from the evidence author.

Each operational JSON document carries `ControlId`, `TenantId`, `DeploymentProfile` (`ExchangeOnly`), `ConfigurationHash`, `ManifestHash`, `GeneratedAtUtc`, `Payload`, and `Signature`. The detached CMS signature covers canonical JSON of all members except `Signature`; its descriptor is `{ "Model": "DetachedCms", "Value": "base64 CMS bytes" }`. Binding, age, signature, approved signer, certificate validity, offline chain and revocation checks must succeed. Unknown/offline-unavailable trust fails closed. Signing infrastructure is [RAID-D05](../../../.github/RAID.md), not provisioned by this command.

Operational chain verification disables certificate downloads. An optional externally approved `trustedRoot` object supplies a local certificate `path` and `sha256` pin for custom-root trust without installing certificates in a certificate store. Supplying a root does not bypass binding, signature, validity or signer-authorization checks. This setting applies to the local operational-artifact verifier, not the separate frozen-evidence go-live workflow.

Payloads use the existing retained evaluator contracts: MON-003 scheduled collection, cadence, retention, timestamp, drift and findings; OPS-001 ChangeId, timestamp, and completed/bound preview, pilot, approval, rollback and post-change phases; OPS-002 exercise ID, completion timestamp, exercise types, owners and tracked actions. OPS-002 uses the supported supplied Exchange entitlement; tabletop cadence has no Defender P2 mandate. A `SignatureVerified` field supplied by an artifact is never accepted as proof; it is set only after verification. See [Exchange email protection](EXCHANGE-EMAIL-PROTECTION.md) for the effective recipient matrix and reporting prerequisites.

Use [Frozen Exchange Evidence Gate](EXCHANGE-GO-LIVE.md) for the supported collect/freeze/`-SignEvidence`/`-GoLive` commands, required independent hashes, authorized signer metadata and distinct exits. A subject string alone is not authorization. Verification measures the exact frozen bytes without collecting again. The gate always uses the shipped Exchange manifest even if an internal caller supplies a smaller catalog. Missing controls, excluded Pass records, unbound manifest contents, forged external dispositions, unresolved results and unverified signatures are refused. Approved deviations remain `ApprovedException`, not Pass. Exchange conformance does not establish tenant security or service-launch readiness; [RAID](../../../.github/RAID.md) remains authoritative for external gaps.

## Email Catalogue Review

EXR-010-A01 is bounded offline catalogue admission, pending independent acceptance. It does not complete EXR-010-A02 recipient precedence/effective evaluation or the EXR-010 parent. Source S14 / assessment A08 remains Partial in [the recommendation inventory](../config/exchange-recommendations.v1.json); [Email Catalogue Boundary](CONTROL-CATALOG.md#email-catalogue-boundary) maps the work to MDO-001/002/003/008/009 and EXO-004 without adding evidence keys or claiming runtime results.

1. Review [Email Settings Sources](EMAIL-SETTINGS-SOURCES.md): source sections, revisions, captured-artifact digests, review date and all 114 field classifications/capabilities. The file-list binding identifies the captured representation, not necessarily raw immutable bytes. It does not certify latest/future content.
2. Preserve typed Standard values and sparse Strict overlays in [the catalogue](../config/exchange-email-settings.v1.json). SafeLinks BuiltIn has three genuine differences; SafeAttachment BuiltIn is explicitly empty, not disabled. Retain all 23 configurable LocalPolicy fields. MicrosoftRecommendation is source-pinned; ApprovedException requires separate approved evidence, never a catalogue label or profile.
3. From the sample directory, run the two offline checks below. Admission rejects missing/duplicate/case-colliding/unsupported fields and profiles, wrong JSON types, mismatched source bindings and fabricated classifications. Retain exact commands, counters and tested input hashes for independent review; tests alone do not mark a card Done.

```powershell
Invoke-Pester -Path ./tests/unit/ExchangeEmailSettingCatalog.Tests.ps1 -PassThru -Output Detailed
Invoke-Pester -Path ./tests/unit/ExchangeProtectionMatrix.Tests.ps1 -PassThru -Output Detailed
```

Outbound spam recommendations are outside presets; BccSuspiciousOutboundMail and BccSuspiciousOutboundAdditionalRecipients are default-policy-only. Encrypted-attachment recommendations are conditional on Enable=true / Action=Block and the blocking switch; the three encrypted fields' cmdlet support is uncertain in the captured references. Classification and capability do not certify operational support, mutation support, raw getter shape or live compatibility. See the source document before interpreting those values. This procedure makes no connection or service mutation, supplies no credentials and does not provision licensing; external capability evidence remains RAID-D02.

## Historical Regression

The MicrosoftNative and ThirdPartyGateway configurations and their historical Pester tests remain preserved. Historical public execution requires both an explicit historical `-ConfigurationPath` and `-AllowHistoricalProfile`. They are never the default or a fallback for ExchangeOnly. Historical examples in README, IMPLEMENTATION-GUIDE and RUNBOOKS are isolated pending EXR-012; they must not be used as the active scoped procedure.

Offline acceptance runs the actual default public entrypoint through recording Exchange stubs, exercises raw accepted-domain data, checks all 25 records, and denies excluded-service calls. Separate tests cover malformed input, registry admission, mutation readers, operational artifacts, manifest-bound go-live and the preview example above. No offline fixture is live Microsoft compatibility evidence; live acceptance remains EXR-017 with independently confirmed prerequisites.