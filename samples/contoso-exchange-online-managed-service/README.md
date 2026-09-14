# Contoso Exchange Online Managed Service Sample

This sample is an evidence-oriented starting point for onboarding a net-new business entity to Exchange Online, Exchange Online Protection (EOP), and Microsoft Defender for Office 365 (MDO). It assumes:

- Proofpoint is the inbound and outbound SMTP gateway.
- Microsoft filtering remains active through Enhanced Filtering for Connectors.
- Abnormal Security performs API-based post-delivery detection and remediation.
- Standard preset security protection covers the organization; Strict covers priority users.
- Security events are centralized in the organization's SIEM and Defender XDR.

The sample does not contain tenant IDs, domains, vendor endpoints, public IPs, or identities. Every value an engineer must supply is marked `__ADMIN_REQUIRED:NAME__`.

## Contents

| Path | Purpose |
| --- | --- |
| `config/exchange-online-secure-baseline.json` | Parameter and setting-level desired state |
| `config/parameters.sample.json` | Administrator input contract |
| `scripts/Deploy-ExchangeOnlineBaseline.ps1` | WhatIf-by-default, idempotent deployment |
| `scripts/Test-ExchangeOnlineBaseline.ps1` | Live control tests and JSON evidence export |
| `tests/SecureBaseline.Tests.ps1` | Static Pester guardrails |
| `docs/IMPLEMENTATION-GUIDE.md` | End-to-end setup and operating guide |
| `docs/CONTROL-CATALOG.md` | MUST, SHOULD, and AVOID control matrix |
| `dashboard/index.html` | Local evidence viewer and control dashboard |

## Quick Start

1. Copy `config/parameters.sample.json` to a change-controlled tenant parameter file outside source control.
2. Replace every `__ADMIN_REQUIRED:...__` value using approved Microsoft, Proofpoint, Abnormal, DNS, and identity records.
3. Initialize Standard and Strict preset policies in the Defender portal as described in the implementation guide.
4. Run a static test:

   ```powershell
   Invoke-Pester ./tests/SecureBaseline.Tests.ps1
   ```

5. Preview tenant changes. Omitting `-Apply` invokes each supported Exchange cmdlet with `-WhatIf`:

   ```powershell
   ./scripts/Deploy-ExchangeOnlineBaseline.ps1 -ParameterPath ./config/parameters.contoso.json
   ```

6. Apply only through an approved change:

   ```powershell
   ./scripts/Deploy-ExchangeOnlineBaseline.ps1 -ParameterPath ./config/parameters.contoso.json -Apply
   ```

7. Publish the exact DKIM CNAME values returned by Exchange Online, then rerun with `-EnableDkim -Apply`.
8. Collect evidence:

   ```powershell
   ./scripts/Test-ExchangeOnlineBaseline.ps1 -ParameterPath ./config/parameters.contoso.json
   ```

9. Open `dashboard/index.html` and load the generated evidence JSON. The dashboard processes the file only in the browser.

## Security Boundary

The script configures supported Exchange Online controls. It intentionally does not automate DNS, licensing, Conditional Access, Privileged Identity Management, Microsoft Sentinel/third-party SIEM ingestion, Proofpoint administration, or Abnormal OAuth consent. Those cross-system steps require separate owners, approvals, and evidence.

Review the Microsoft references in the implementation guide at least quarterly. Microsoft-managed preset values evolve; avoid copying their individual values into custom policies unless a documented exception requires it.
