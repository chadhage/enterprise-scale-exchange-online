# Quarantined Content

Nothing in this folder is a supported deployment path. It is retained only for history, diffing, and migration reference. Do not run it against a tenant.

## `mdo-baseline-config-custom-policies/`

**Status:** Quarantined. **Replaced by:** [`../samples/contoso-exchange-online-managed-service/`](../samples/contoso-exchange-online-managed-service/).

This solution built **custom** anti-phishing, anti-malware, anti-spam, Safe Attachments, and Safe Links policies from transcribed setting values. Microsoft's guidance is to use **preset security policies** (Standard and Strict), whose values are Microsoft-managed and change as threats evolve. Freezing a local copy of those values is recorded as `BAD-010` in the control catalog, so the solution violated a control that this repository declares a MUST-avoid.

It was quarantined rather than repaired because the supported sample already delivers the same outcome through the Microsoft-managed path.

### Defects recorded at quarantine time

| # | Defect | Location |
| --- | --- | --- |
| 1 | Creates policies but never creates the matching `New-AntiPhishRule`, `New-MalwareFilterRule`, `New-HostedContentFilterRule`, `New-SafeAttachmentRule`, or `New-SafeLinksRule` objects. A policy with no rule has no recipient scope and is inert, so a run reports success while the tenant stays on default protection. | `scripts/Deploy-MDOBaseline.ps1` |
| 2 | Passes parameters that do not exist on the target cmdlets: `SpoofIntelligenceAction`, `ExternalPartnerDomainSpoof`, `ImpersonationProtectionAction`, `EnableDomainImpersonationProtection`, `DomainImpersonationProtectionAction`, `ProtectedDomains`, `Identity` on `New-*Policy`, and `Enabled` on `Set-MalwareFilterPolicy`. The run aborts on the first call. | `scripts/Deploy-MDOBaseline.ps1` |
| 3 | Anti-malware file-type list blocks `xlsx`, `pptx`, `txt`, `xml`, `zip`, `pst`, `ttf`, and `tmp`. Deploying it quarantines routine business mail on day one. | `config-templates/baseline-standard.json` |
| 4 | Setting values diverge from Microsoft's recommended tables (`phishingThreshold`, `bulkThreshold`) and the DMARC target is `p=quarantine` rather than the `p=reject; sp=reject; pct=100` end state required by `AUTH-003`. | `config-templates/baseline-standard.json` |
| 5 | Documentation claimed Connection Filter and DMARC/DKIM/SPF coverage that no code implemented. DMARC and SPF are DNS records and are not reachable from Exchange Online cmdlets at all. | `docs/`, `../SOLUTION_SUMMARY.md` |

### If you previously deployed it

1. Inventory what exists: `Get-AntiPhishPolicy`, `Get-MalwareFilterPolicy`, `Get-HostedContentFilterPolicy`, `Get-SafeAttachmentPolicy`, `Get-SafeLinksPolicy`.
2. Remove the custom policies and any matching rules created by this solution.
3. Follow [`../samples/contoso-exchange-online-managed-service/docs/RUNBOOKS.md`](../samples/contoso-exchange-online-managed-service/docs/RUNBOOKS.md) to assign the Standard and Strict presets.
4. Collect evidence with `Test-ExchangeOnlineBaseline.ps1` and attach it to the change record.
