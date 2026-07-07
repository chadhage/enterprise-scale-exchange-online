# Microsoft Defender for Office 365 Baseline Configuration

Infrastructure as Code (IaC) templates for deploying Microsoft Defender for Office 365 (MDO) baseline security configurations. Tenant-specific values are parameterized rather than hardcoded.

## Overview

This project provides example baseline configuration templates for Microsoft Defender for Office 365 in both **Standard** and **Strict** protection levels, based on Microsoft's published recommended settings for EOP and Defender for Office 365. It includes:

- **Parameterized JSON Configuration Templates** - Tenant-specific values supplied at generation time
- **PowerShell Automation Scripts** - IaC deployment with dry-run and audit mode support
- **Interactive Microsite** - Web-based configuration builder and deployment guide
- **SharePoint Modern App** - SPFx package structure for deployment in SharePoint environments
- **Documentation** - Deployment, customization, and troubleshooting guides

## Key Features

- **Two Protection Levels**: Standard (recommended) and Strict (high-risk environments)
- **Phased Rollout Support**: Pilot, Staged, and Organization-wide deployment phases
- **Audit & Enforce Modes**: Test in Audit mode before enforcement, with logging
- **Policy Coverage**: Anti-phishing, Anti-malware, Anti-spam, Safe Attachments, Safe Links, Outbound Spam, Connection Filtering
- **Authentication Configuration**: DMARC, DKIM, and SPF configuration support
- **Allow/Block List Management**: Tenant Allow/Block List integration
- **Validation**: Schema validation and configuration checking tools
- **Multi-Cloud Support**: Commercial, GCC, GCC-High, and DoD environments
- **Logging**: Deployment logs and validation reporting

## 📁 Project Structure

```
mdo-baseline-config/
├── config-templates/                   # Configuration templates and schema
│   ├── mdo-config-schema.json         # JSON schema for validation
│   ├── baseline-standard.json         # Standard protection baseline
│   └── baseline-strict.json           # Strict protection baseline
│
├── scripts/                            # PowerShell automation scripts
│   ├── Deploy-MDOBaseline.ps1         # Main deployment script
│   ├── Generate-ConfigFromTemplate.ps1 # Configuration generator
│   └── Validate-MDOConfiguration.ps1   # Configuration validator
│
├── microsite/                          # Interactive web interface
│   ├── index.html                     # Main microsite page
│   ├── styles.css                     # Styling (Fluent Design)
│   └── script.js                      # Interactive functionality
│
├── spfx-app/                          # SharePoint Framework app
│   ├── config/
│   │   ├── config.json
│   │   └── serve.json
│   ├── src/
│   │   ├── webparts/
│   │   │   └── MdoBaseline/
│   │   │       ├── MdoBaselineWebPart.ts
│   │   │       └── MdoBaselineWebPart.module.scss
│   │   └── index.ts
│   ├── package.json
│   └── package-solution.json
│
├── docs/                               # Documentation
│   ├── README.md                      # Project overview
│   ├── DEPLOYMENT.md                  # Deployment guide
│   ├── CUSTOMIZATION.md               # Customization guide
│   └── TROUBLESHOOTING.md             # Troubleshooting guide
│
└── .gitignore
```

## 🚀 Quick Start

### Prerequisites

- PowerShell 7.0 or later
- ExchangeOnlineManagement module
- Global Administrator or Security Administrator role
- Microsoft Defender for Office 365 Plan 1 or Plan 2 license

### Installation

1. **Install Required Modules**
   ```powershell
   Install-Module ExchangeOnlineManagement -Force -AllowClobber
   Install-Module Microsoft.Graph.Authentication -Force
   Install-Module Microsoft.Graph.Users -Force
   ```

2. **Generate Configuration**
   - Use the interactive microsite at `microsite/index.html`
   - Or use the generation script:
   ```powershell
   .\Generate-ConfigFromTemplate.ps1 `
       -TemplateFile "./baseline-standard.json" `
       -OutputFile "./contoso-standard.json" `
       -TenantId "your-tenant-guid" `
       -TenantName "Your Organization" `
       -TenantDomain "yourdomain.com" `
       -SecurityAdminEmail "admin@yourdomain.com"
   ```

3. **Validate Configuration**
   ```powershell
   .\Validate-MDOConfiguration.ps1 -ConfigPath "./contoso-standard.json"
   ```

4. **Test Deployment (Dry Run)**
   ```powershell
   .\Deploy-MDOBaseline.ps1 `
       -ConfigPath "./contoso-standard.json" `
       -TenantId "your-tenant-guid" `
       -TenantName "Your Organization" `
       -TenantDomain "yourdomain.com" `
       -SecurityAdminEmail "admin@yourdomain.com" `
       -DryRun
   ```

5. **Deploy Configuration**
   ```powershell
   .\Deploy-MDOBaseline.ps1 `
       -ConfigPath "./contoso-standard.json" `
       -TenantId "your-tenant-guid" `
       -TenantName "Your Organization" `
       -TenantDomain "yourdomain.com" `
       -SecurityAdminEmail "admin@yourdomain.com"
   ```

## 📊 Protection Levels

### Standard Protection (Recommended)

Suitable for most organizations. Provides protection against common threats:

- Anti-phishing with spoofing detection (Level 1)
- Anti-malware with file type filtering
- Anti-spam with bulk threshold tuning (Level 7)
- Safe Attachments scanning
- Safe Links detonation
- Default policies apply to all recipients

### Strict Protection (High-Risk)

Recommended for financial institutions, government agencies, and organizations handling sensitive data:

- All Standard features, plus:
- User and domain impersonation protection
- Aggressive phishing thresholds (Level 1)
- Quarantine by default for suspicious messages
- Automated Investigation & Response (AIR)
- Threat Explorer and Campaign View
- Attack Simulation Training

## 🔧 Supported Policies

### Core Protection (All Organizations)

- ✓ Anti-Phishing Policies
- ✓ Anti-Malware Policies
- ✓ Anti-Spam Policies
- ✓ Connection Filter Policies
- ✓ Outbound Spam Policies

### Advanced Protection (MDO Plan 1+)

- ✓ Safe Attachments Policies
- ✓ Safe Links Policies
- ✓ Tenant Allow/Block Lists
- ✓ Impersonation Protection
- ✓ User & Domain Spoofing Detection

### Authentication & Email Validation

- ✓ DMARC Configuration (policy: quarantine/reject)
- ✓ DKIM Signing
- ✓ SPF Validation
- ✓ Email Authentication Reports

## 📝 Configuration Schema

Configurations are validated against `mdo-config-schema.json`. Key sections:

- **organizationSettings**: Tenant identity, protection strategy, deployment mode
- **protectionLevel**: Standard/Strict preset and custom risk thresholds
- **policies**: All threat policies (anti-phishing, malware, spam, etc.)
- **recipients**: Target users, groups, domains for policy application
- **allowBlockList**: Allowed/blocked senders and URLs
- **authentication**: DMARC, DKIM, SPF configuration
- **advancedThreatProtection**: AIR, Threat Explorer, Campaign View settings
- **notifications**: Alert email configuration
- **metadata**: Version control and creation information

## 🎮 Interactive Microsite

The microsite (`microsite/index.html`) provides:

1. **Overview** - Feature overview and baseline protection levels
2. **Configurator** - Interactive form to build custom configurations
3. **Deployment** - Step-by-step deployment instructions
4. **FAQ** - Common questions and answers
5. **Resources** - Links to documentation and scripts

### Usage

1. Open `microsite/index.html` in a modern web browser
2. Fill in organization details
3. Select protection level
4. Configure deployment settings
5. Generate and download configuration JSON

## 📚 Documentation

### DEPLOYMENT.md
- Step-by-step deployment procedures
- Prerequisite validation
- Phased rollout strategy (3 phases)
- Monitoring and validation procedures
- Rollback procedures

### CUSTOMIZATION.md
- Modifying baseline templates
- Creating custom policies
- Policy precedence and priority
- Recipient targeting strategies
- Threshold tuning for false positives

### TROUBLESHOOTING.md
- Common deployment issues
- Troubleshooting connection problems
- Policy validation issues
- Permission and RBAC requirements
- Logging and diagnostic tools

## Security Best Practices

The configurations are based on Microsoft's published recommended settings for EOP and Defender for Office 365 and include:

- Principle of least privilege (recipient targeting)
- Defense in depth (multiple detection layers)
- Audit mode before enforcement
- Logging and monitoring
- DMARC/DKIM/SPF authentication configuration
- Priority account protection

## 🎁 SharePoint Modern App

The SPFx app package includes:

- Web part for viewing baseline configuration details
- Integration with SharePoint sites and pages
- Responsive design for all devices
- One-click deployment to SharePoint

### Deploy SPFx App

```bash
cd spfx-app
npm install
npm run build
npm run bundle -- --ship
npm run package-solution -- --ship
```

Upload the `.sppkg` file from `sharepoint/solution/` to your SharePoint App Catalog.

## 📈 Monitoring & Reporting

Post-deployment monitoring tools:

- **Configuration Analyzer** (Microsoft Defender portal) - Policy compliance checking
- **Mail Flow Reports** - Message action tracking
- **Threat Reports** - Malware, phishing, spam detection
- **Detection Tuning** - Automated detection analysis
- **Submissions** - User-reported message handling

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Validate configurations against schema
4. Test with dry-run before committing
5. Submit a pull request with detailed description

## 📞 Support

- Review the [Troubleshooting Guide](docs/TROUBLESHOOTING.md)
- Check [Microsoft Defender for Office 365 Documentation](https://learn.microsoft.com/defender-office-365/)
- Review Configuration Analyzer in Microsoft Defender portal

## 📄 License

This project is provided as-is for organizations deploying Microsoft Defender for Office 365.

## 🔗 References

- [Microsoft Defender for Office 365 Documentation](https://learn.microsoft.com/defender-office-365/)
- [Preset Security Policies](https://learn.microsoft.com/defender-office-365/preset-security-policies)
- [Recommended Settings for EOP & MDO](https://learn.microsoft.com/defender-office-365/recommended-settings-for-eop-and-office365)
- [Configuration Analyzer](https://security.microsoft.com/configuration-analyzer)

---

**Version**: 1.0.0  
**Last Updated**: January 2026  
**Maintainer**: Exchange Online Protection Baseline Configuration Team
