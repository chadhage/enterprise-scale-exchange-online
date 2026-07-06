# MDO Baseline Configuration - Deployment Guide

Complete step-by-step guide for deploying Microsoft Defender for Office 365 baseline configurations in your organization.

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Pre-Deployment Checklist](#pre-deployment-checklist)
3. [Configuration Generation](#configuration-generation)
4. [Validation Process](#validation-process)
5. [Dry-Run Testing](#dry-run-testing)
6. [Production Deployment](#production-deployment)
7. [Phased Rollout Strategy](#phased-rollout-strategy)
8. [Post-Deployment Validation](#post-deployment-validation)
9. [Monitoring & Tuning](#monitoring--tuning)
10. [Troubleshooting](#troubleshooting)

## Prerequisites

### Software Requirements

- **PowerShell**: Version 7.0 or later (PowerShell Core)
  ```powershell
  $PSVersionTable.PSVersion
  ```

- **ExchangeOnlineManagement Module** (Latest version)
  ```powershell
  Install-Module ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser
  Update-Module ExchangeOnlineManagement
  ```

- **Microsoft.Graph Modules**
  ```powershell
  Install-Module Microsoft.Graph.Authentication -Force -Scope CurrentUser
  Install-Module Microsoft.Graph.Users -Force -Scope CurrentUser
  ```

### Licensing Requirements

- **Minimum**: Microsoft Defender for Office 365 Plan 1
  - All core policies (anti-phishing, malware, spam)
  - Safe Attachments
  - Safe Links
  
- **Recommended**: Microsoft Defender for Office 365 Plan 2
  - All Plan 1 features
  - Automated Investigation & Response (AIR)
  - Threat Explorer
  - Campaign View
  - Attack Simulation Training

### Administrative Requirements

- **Role**: Global Administrator OR Security Administrator
- **Tenant Access**: Full administrative access to Microsoft 365 tenant
- **Permissions**: "Core security settings - Manage" permission in Unified RBAC

### Information Required

Gather the following before starting deployment:

- Tenant ID (Azure AD Directory ID) - GUID format
- Organization name
- Primary email domain(s)
- Security admin email address
- Intended protection level (Standard or Strict)
- Target recipient groups/domains
- Any existing allow/block lists to migrate

## Pre-Deployment Checklist

Use this checklist before starting deployment:

- [ ] All prerequisites installed and verified
- [ ] Administrative access confirmed
- [ ] Backup of current MDO policies created
- [ ] Change control approval obtained
- [ ] Stakeholders notified
- [ ] Support procedures documented
- [ ] Pilot user group identified
- [ ] Rollback procedures documented
- [ ] Monitoring tools configured
- [ ] Configuration file generated and validated

## Configuration Generation

### Method 1: Interactive Microsite (Recommended)

1. **Open the Microsite**
   - Navigate to `microsite/index.html` in your web browser
   - No installation required

2. **Fill Organization Details**
   - Tenant ID: GUID format (e.g., `12345678-1234-1234-1234-123456789012`)
   - Organization Name: Display name (e.g., "Contoso Inc")
   - Domain: Primary domain (e.g., "contoso.com")
   - Admin Email: Security admin email (e.g., "security@contoso.com")

3. **Select Settings**
   - Protection Level: Standard or Strict
   - Deployment Mode: Audit or Enforce
   - Rollout Phase: 1, 2, or 3
   - Optional: Enable AIR (Automated Investigation & Response)

4. **Configure Allow/Block Lists** (Optional)
   - Add trusted sender domains
   - Add blocked domains/senders
   - Configure URL allow/block entries

5. **Generate & Download**
   - Click "Generate Configuration"
   - Review JSON preview
   - Click "Download" to save configuration file

### Method 2: PowerShell Script Generation

```powershell
# Generate from template with parameters
.\Generate-ConfigFromTemplate.ps1 `
    -TemplateFile "./baseline-standard.json" `
    -OutputFile "./contoso-standard-$(Get-Date -Format 'yyyyMMdd').json" `
    -TenantId "12345678-1234-1234-1234-123456789012" `
    -TenantName "Contoso Inc" `
    -TenantDomain "contoso.com" `
    -SecurityAdminEmail "security@contoso.com"
```

### Method 3: Using Parameters File

Create a JSON file with organization details:

```json
{
  "tenantId": "12345678-1234-1234-1234-123456789012",
  "tenantName": "Contoso Inc",
  "tenantDomain": "contoso.com",
  "securityAdminEmail": "security@contoso.com"
}
```

Then generate configuration:

```powershell
.\Generate-ConfigFromTemplate.ps1 `
    -TemplateFile "./baseline-standard.json" `
    -OutputFile "./contoso-standard.json" `
    -ParametersFile "./contoso-params.json"
```

## Validation Process

### Schema Validation

Validate configuration file against JSON schema:

```powershell
.\Validate-MDOConfiguration.ps1 -ConfigPath "./contoso-standard.json"
```

Expected output:

```
Validating MDO Configuration: ./contoso-standard.json
================================================

[✓] Configuration file loaded successfully
[✓] Required field present: organizationSettings
[✓] Required field present: protectionLevel
[✓] Required field present: policies
[✓] Required field present: metadata

[✓] Tenant ID format is valid (GUID)
[✓] Tenant name specified: Contoso Inc
[✓] Protection strategy is valid: Standard

[!] Deployment mode is AUDIT (detection only, no enforcement)

[✓] Policies will apply to all recipients
[✓] Total policies defined: 7

================================================
Validation Summary
================================================
Passed:   18
Failed:   0
Warnings: 1
================================================
✓ Configuration validation completed successfully
```

### Configuration Review Checklist

- [ ] All required organization fields populated
- [ ] Tenant ID in valid GUID format
- [ ] Protection level set (Standard or Strict)
- [ ] Deployment mode selected (Audit or Enforce)
- [ ] At least one policy defined per category
- [ ] Recipient targeting configured correctly
- [ ] Notification email addresses valid
- [ ] Authentication settings (DMARC/DKIM/SPF) enabled
- [ ] Allow/Block lists properly formatted
- [ ] No hardcoded values in configuration

## Dry-Run Testing

### Step 1: Connect to Exchange Online

```powershell
# Connect with managed identity (if using automation)
Connect-ExchangeOnline -ManagedIdentity -Organization "contoso.com"

# Or connect interactively
Connect-ExchangeOnline -UserPrincipalName admin@contoso.com
```

### Step 2: Execute Dry-Run Deployment

```powershell
.\Deploy-MDOBaseline.ps1 `
    -ConfigPath "./contoso-standard.json" `
    -TenantId "12345678-1234-1234-1234-123456789012" `
    -TenantName "Contoso Inc" `
    -TenantDomain "contoso.com" `
    -SecurityAdminEmail "security@contoso.com" `
    -DryRun
```

### Step 3: Review Dry-Run Output

The dry-run will:
- Display all policies that would be created/modified
- Show exact settings for each policy
- List Allow/Block list entries to be added
- NOT make any actual changes to the tenant

### Step 4: Validate Dry-Run Results

- [ ] Correct number of policies shown
- [ ] Policy settings match organizational requirements
- [ ] Recipient targeting is correct
- [ ] Alert notifications set to correct addresses
- [ ] No unexpected policy modifications

### Step 5: Adjust Configuration if Needed

If changes are needed:

1. Modify the JSON configuration file
2. Re-validate with `Validate-MDOConfiguration.ps1`
3. Run dry-run again
4. Verify results

Repeat until configuration is correct.

## Production Deployment

### Phase 1: Pilot Deployment (Week 1-2)

Target: 10-20% of users (pilot group)

1. **Create Pilot Group** (in Azure AD)
   ```powershell
   # Create security group for pilots
   New-MgGroup -DisplayName "MDO-Pilot-Group" -MailNickname "mdopilot" -GroupTypes "DynamicMembership"
   ```

2. **Deploy with Audit Mode**
   - Keep deployment mode as "Audit" initially
   - This ensures detection without enforcement

3. **Execute Deployment**
   ```powershell
   .\Deploy-MDOBaseline.ps1 `
       -ConfigPath "./contoso-standard.json" `
       -TenantId "12345678-1234-1234-1234-123456789012" `
       -TenantName "Contoso Inc" `
       -TenantDomain "contoso.com" `
       -SecurityAdminEmail "security@contoso.com" `
       -DeploymentMode "Audit"
   ```

4. **Monitor for 1-2 Weeks**
   - Review threat reports
   - Check for false positives
   - Gather user feedback
   - Note any issues

5. **Adjust Thresholds** (If needed)
   - Modify JSON configuration for false positives
   - Re-run deployment
   - Document changes

### Phase 2: Staged Expansion (Week 3-4)

Target: 50-70% of users (departments/teams)

1. **Create Staged Deployment Group**
   ```powershell
   New-MgGroup -DisplayName "MDO-Staged-Group" -MailNickname "mdostaged" -GroupTypes "DynamicMembership"
   # Add departments: Finance, HR, Executive
   ```

2. **Switch to Enforce Mode**
   - Modify configuration: `"deploymentMode": "Enforce"`
   - Policies will now actively block threats

3. **Execute Deployment**
   ```powershell
   .\Deploy-MDOBaseline.ps1 `
       -ConfigPath "./contoso-staged.json" `
       -TenantId "12345678-1234-1234-1234-123456789012" `
       -TenantName "Contoso Inc" `
       -TenantDomain "contoso.com" `
       -SecurityAdminEmail "security@contoso.com" `
       -DeploymentMode "Enforce"
   ```

4. **User Training**
   - Conduct phishing awareness training
   - Explain policy changes
   - Document how to report false positives

5. **Monitor Closely**
   - Daily threat report review
   - Quick response to false positives
   - Maintain support queue for issues

### Phase 3: Organization-Wide Deployment (Week 5+)

Target: All remaining users

1. **Final Configuration Update**
   ```json
   {
     "recipients": {
       "applyToAllRecipients": true
     }
   }
   ```

2. **Execute Full Deployment**
   ```powershell
   .\Deploy-MDOBaseline.ps1 `
       -ConfigPath "./contoso-standard-final.json" `
       -TenantId "12345678-1234-1234-1234-123456789012" `
       -TenantName "Contoso Inc" `
       -TenantDomain "contoso.com" `
       -SecurityAdminEmail "security@contoso.com" `
       -DeploymentMode "Enforce"
   ```

3. **Ongoing Monitoring**
   - Weekly threat report reviews
   - Monthly policy effectiveness assessment
   - Quarterly policy tuning
   - Continuous user education

## Phased Rollout Strategy

### Timeline Overview

```
Week 1-2        Week 3-4           Week 5+
[PILOT]     →   [STAGED]      →    [ORG-WIDE]
10-20% users    50-70% users       100% users

Audit Mode      Enforce Mode       Enforce Mode
Monitor         Train Users        Ongoing Monitoring
Tune Config     Expand Coverage    Policy Tuning
```

### Success Criteria

**Pilot Phase**
- ✓ No critical policy issues
- ✓ False positive rate < 5%
- ✓ User feedback positive
- ✓ Threat detection working

**Staged Phase**
- ✓ Departments operational
- ✓ Support queue manageable
- ✓ False positives trending down
- ✓ Threat blocks appropriate

**Organization-Wide**
- ✓ All users protected
- ✓ Established monitoring routine
- ✓ Support procedures stable
- ✓ Regular tuning schedule active

## Post-Deployment Validation

### Immediate (Day 1-2)

```powershell
# Verify policies were created
Get-AntiPhishPolicy
Get-MalwareFilterPolicy
Get-HostedContentFilterPolicy
Get-SafeAttachmentPolicy
Get-SafeLinksPolicy

# Check policy details
Get-AntiPhishPolicy -Identity "Standard Anti-Phishing Policy" | Format-List
```

### Short-Term (Week 1)

1. **Review Configuration Analyzer**
   - Go to Microsoft Defender portal
   - Navigate to Configuration Analyzer
   - Verify policies are at Standard or Strict level
   - Review any recommendations

2. **Monitor Mail Flow**
   - Review mail flow reports
   - Check policy action counts
   - Identify high-impact policies

3. **Threat Detection**
   - Check malware detections
   - Review phishing detections
   - Validate spam filtering

### Mid-Term (Week 2-4)

1. **Fine-Tune Settings**
   - Adjust phishing thresholds if needed
   - Add false positives to allow list
   - Block additional threat domains

2. **User Feedback**
   - Gather feedback from pilot users
   - Address false positive complaints
   - Train users on submission process

3. **Security Reviews**
   - Audit policy priorities
   - Review recipient targeting
   - Validate authentication settings

### Long-Term (Ongoing)

1. **Weekly Reviews**
   - Threat report analysis
   - False positive assessment
   - Policy effectiveness review

2. **Monthly Tuning**
   - Adjust thresholds based on trends
   - Update allow/block lists
   - Review detection trends

3. **Quarterly Assessment**
   - Full policy audit
   - Organization impact review
   - Planning for improvements

## Monitoring & Tuning

### Key Monitoring Tools

#### 1. Configuration Analyzer
- **Location**: Microsoft Defender portal > Configuration Analyzer
- **Purpose**: Compare current policies to Microsoft recommended settings
- **Frequency**: Weekly review

#### 2. Mail Protection Reports
- **Location**: Microsoft Defender portal > Reports > Mail protection
- **Metrics**: Messages processed, malware detected, phishing detected, spam detected
- **Action**: Identify unusual patterns

#### 3. Threat Reports
- **Location**: Microsoft Defender portal > Reports > Threats
- **Metrics**: Top malware, phishing trends, URLs
- **Action**: Adjust policies for emerging threats

#### 4. Detection Tuning
- **Location**: Microsoft Defender portal > Detection tuning
- **Purpose**: Review and tune automated detections
- **Frequency**: Monthly

### Common Tuning Adjustments

#### High False Positives

**Symptom**: Legitimate emails being quarantined

**Actions**:
1. Review quarantine logs
2. Add senders to allow list
3. Adjust phishing threshold (1→2 or 2→3)
4. Modify bulk threshold (6→7 or 7→8)

**Command**:
```powershell
# Add sender to allow list
New-TenantAllowBlockListSpoofItems -SpoofedUser user@contoso.com -Action Allow
```

#### Missing Detections

**Symptom**: Known threats not being detected

**Actions**:
1. Review threat reports
2. Adjust detection thresholds (lower)
3. Add domains to block list
4. Enable additional scanning

**Command**:
```powershell
# Add domain to block list
New-TenantAllowBlockListItems -ListType Domain -Entries malicious.com -Action Block
```

#### Policy Conflicts

**Symptom**: Multiple policies affecting same messages

**Actions**:
1. Review policy priorities
2. Adjust priority values (lower = higher priority)
3. Add recipient exclusions
4. Consolidate policies if needed

**Command**:
```powershell
# Update policy priority
Set-AntiPhishPolicy -Identity "Policy Name" -Priority 0
```

## Troubleshooting

### Common Issues

#### Issue: Connection Fails to Exchange Online

**Error Message**: "The term 'Connect-ExchangeOnline' is not recognized"

**Solution**:
```powershell
# Verify module is installed
Get-Module ExchangeOnlineManagement -ListAvailable

# If not found, install
Install-Module ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser

# Restart PowerShell and try again
```

#### Issue: Permission Denied

**Error Message**: "You do not have permission to perform this operation"

**Solution**:
1. Verify administrative role
2. Check Unified RBAC permissions
3. Try with Global Administrator account
4. Check for MFA and conditional access policies

#### Issue: Policy Creation Fails

**Error Message**: "New-AntiPhishPolicy : [Error] Operation failed."

**Solution**:
1. Validate configuration with Validate-MDOConfiguration.ps1
2. Check for duplicate policy names
3. Review policy settings for invalid values
4. Check tenant license level

#### Issue: Dry-Run Shows But Deployment Doesn't Apply

**Cause**: Connection lost or deployment not confirmed

**Solution**:
1. Verify connection status: `Get-ConnectionInformation`
2. Reconnect if needed: `Disconnect-ExchangeOnline -Confirm:$false` then reconnect
3. Re-run deployment without -DryRun flag
4. Check deployment logs for errors

### Diagnostic Commands

```powershell
# Check module versions
Get-Module ExchangeOnlineManagement | Select-Object Name, Version
Get-Module Microsoft.Graph.Authentication | Select-Object Name, Version

# Verify connection
Get-ConnectionInformation

# Check existing policies
Get-AntiPhishPolicy
Get-MalwareFilterPolicy  
Get-HostedContentFilterPolicy
Get-SafeAttachmentPolicy
Get-SafeLinksPolicy

# Review tenant configuration
Get-TenantAllowBlockListItems

# Check for deployment issues
Get-MailTrail -ResultSize 10 -RecipientAddress admin@contoso.com
```

### Getting Help

1. **Review Logs**
   - Check deployment script logs in working directory
   - Look for detailed error messages

2. **Validate Configuration**
   - Run Validate-MDOConfiguration.ps1
   - Fix any validation errors

3. **Check Microsoft Documentation**
   - [MDO Deployment Guide](https://learn.microsoft.com/defender-office-365/mdo-deployment-guide)
   - [Configuration Analyzer](https://learn.microsoft.com/defender-office-365/configuration-analyzer-for-security-policies)

4. **Contact Support**
   - Microsoft Defender for Office 365 support
   - Include deployment logs and configuration files

---

**Last Updated**: January 2026  
**Version**: 1.0.0
