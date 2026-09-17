# Exchange Online Managed Service Sample

An evidence-oriented starting point for onboarding a net-new business entity to Exchange Online, Exchange Online Protection (EOP), and Microsoft Defender for Office 365 (MDO).

Pick a profile:

| Profile | When to use | Configuration | Parameters |
| --- | --- | --- | --- |
| **Microsoft-native** | No third-party SMTP gateway. Internet → EOP → Exchange Online. | `config/exchange-online-secure-baseline.microsoft-native.json` | `config/parameters.microsoft-native.sample.json` |
| **Third-party gateway** | A vendor gateway fronts inbound and outbound SMTP. | `config/exchange-online-secure-baseline.json` | `config/parameters.sample.json` |

Both profiles assume:

- Standard preset security protection covers the organization; Strict covers priority users.
- Microsoft filtering stays active end to end. In the gateway profile that requires Enhanced Filtering for Connectors.
- Security events are centralized in the organization's SIEM and Defender XDR.

The gateway profile additionally assumes Proofpoint as the SMTP gateway and Abnormal Security as API-based post-delivery detection and remediation.

The sample does not contain tenant IDs, domains, vendor endpoints, public IPs, or identities. Every value an engineer must supply is marked `__ADMIN_REQUIRED:NAME__`.

## Contents

| Path | Purpose |
| --- | --- |
| `config/exchange-online-secure-baseline.json` | Gateway profile desired state |
| `config/exchange-online-secure-baseline.microsoft-native.json` | Microsoft-native desired state |
| `config/exchange-online-secure-baseline.schema.json` | Schema, including the gateway conditional |
| `config/parameters.sample.json` | Administrator input contract (gateway) |
| `config/parameters.microsoft-native.sample.json` | Administrator input contract (native) |
| `scripts/Deploy-ExchangeOnlineBaseline.ps1` | WhatIf-by-default, idempotent deployment |
| `scripts/Test-ExchangeOnlineBaseline.ps1` | Live control tests and JSON evidence export |
| `tests/SecureBaseline.Tests.ps1` | Static Pester guardrails |
| `docs/IMPLEMENTATION-GUIDE.md` | End-to-end setup and operating guide |
| `docs/RUNBOOKS.md` | Per-control portal path, cmdlet, value, verification, expected output |
| `docs/CONTROL-CATALOG.md` | MUST, SHOULD, and AVOID control matrix |
| `docs/LICENSING-GATE.md` | Which controls each licence tier entitles |
| `dashboard/index.html` | Local evidence viewer and control dashboard |

## Quick Start

1. Read [`docs/LICENSING-GATE.md`](docs/LICENSING-GATE.md) and record the tenant's `messagingTier` and `complianceTier`.
2. Copy the parameters file for your profile to a change-controlled tenant file outside source control.
3. Replace every `__ADMIN_REQUIRED:...__` value using approved Microsoft, vendor, DNS, and identity records.
4. Initialize Standard and Strict preset policies in the Defender portal as described in the implementation guide.
5. Run a static test:

   ```powershell
   Invoke-Pester ./tests/SecureBaseline.Tests.ps1
   ```

6. Preview tenant changes. Omitting `-Apply` invokes each supported Exchange cmdlet with `-WhatIf`:

   ```powershell
   ./scripts/Deploy-ExchangeOnlineBaseline.ps1 `
       -ParameterPath ./config/parameters.contoso.json `
       -ConfigurationPath ./config/exchange-online-secure-baseline.microsoft-native.json
   ```

7. Apply only through an approved change by adding `-Apply`.
8. Publish the exact DKIM CNAME values returned by Exchange Online, then rerun with `-EnableDkim -Apply`.
9. Work through [`docs/RUNBOOKS.md`](docs/RUNBOOKS.md) for every control the deployment reports as `Manual`.
10. Collect evidence:

    ```powershell
    ./scripts/Test-ExchangeOnlineBaseline.ps1 `
        -ParameterPath ./config/parameters.contoso.json `
        -ConfigurationPath ./config/exchange-online-secure-baseline.microsoft-native.json
    ```

11. Open `dashboard/index.html` and load the generated evidence JSON. The dashboard processes the file only in the browser.

## Outcome Statuses

| Status | Meaning | Fails the run? |
| --- | --- | --- |
| `Applied` / `Planned` | Configured, or would be under `-WhatIf` | — |
| `Pass` / `Fail` | Live state confirmed or contradicted | `Fail` exits non-zero |
| `NotEntitled` | Above the declared licence tier | No |
| `NotApplicable` | Belongs to the other deployment profile | No |
| `Manual` | Owned by DNS, Entra, Purview, SharePoint, or the SIEM | No |

Every `Manual` and `NotEntitled` outcome needs a completed runbook or a recorded risk acceptance before the service goes live.

## Security Boundary

The script configures supported Exchange Online controls. It intentionally does not automate DNS, licensing, Conditional Access, Privileged Identity Management, Microsoft Sentinel or third-party SIEM ingestion, SharePoint tenant settings, Microsoft Purview, gateway vendor administration, or OAuth consent. Those cross-system steps require separate owners, approvals, and evidence, and each has a runbook in [`docs/RUNBOOKS.md`](docs/RUNBOOKS.md).

Review the Microsoft references in the implementation guide at least quarterly. Microsoft-managed preset values evolve; avoid copying their individual values into custom policies unless a documented exception requires it.
