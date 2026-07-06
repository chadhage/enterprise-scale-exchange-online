# MDO Baseline Configuration - Troubleshooting Guide

Common issues and solutions for Microsoft Defender for Office 365 baseline configuration deployment and operations.

## Pre-Deployment Issues

### Issue: PowerShell Module Not Found

**Error Message**:
```
The term 'Connect-ExchangeOnline' is not recognized as the name of a cmdlet, 
function, script file, or operable program.
```

**Cause**: ExchangeOnlineManagement module not installed or not in PATH

**Solution**:
```powershell
# Check if module is installed
Get-Module ExchangeOnlineManagement -ListAvailable

# If not found, install it
Install-Module ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser

# Update to latest version
Update-Module ExchangeOnlineManagement -Force

# Import the module
Import-Module ExchangeOnlineManagement

# Verify import
Get-Command Connect-ExchangeOnline
```

### Issue: PowerShell Version Too Old

**Error Message**:
```
This module requires PowerShell 7.0 or later
```

**Cause**: PowerShell 5.1 (Windows PowerShell) instead of PowerShell 7+ (PowerShell Core)

**Solution**:
```powershell
# Check current version
$PSVersionTable.PSVersion

# Download PowerShell 7+ from https://github.com/PowerShell/PowerShell/releases
# Or use Windows Package Manager
winget install Microsoft.PowerShell

# Launch PowerShell 7 and verify
pwsh
$PSVersionTable.PSVersion  # Should be 7.x or higher
```

### Issue: Access Denied / Permission Denied

**Error Message**:
```
[AuthenticationException] : 
The token provided does not have permission to execute this operation.
```

**Cause**: Insufficient permissions in Microsoft 365

**Solution**:
1. **Verify Role Assignment**
   ```powershell
   # Connect with admin account
   Connect-ExchangeOnline -UserPrincipalName admin@contoso.com
   
   # Check current user roles
   Get-MgDirectoryRole | Where-Object DisplayName -contains "Global Administrator"
   ```

2. **Required Roles**:
   - Global Administrator (most permissive)
   - Security Administrator (recommended)
   - Exchange Administrator (limited features)

3. **Check Unified RBAC**
   - Go to Microsoft Defender portal > Permissions > Roles
   - Assign "Core security settings - Manage" permission

4. **Try with Global Admin**:
   ```powershell
   # Disconnect current session
   Disconnect-ExchangeOnline -Confirm:$false
   
   # Connect with global admin account
   Connect-ExchangeOnline -UserPrincipalName global-admin@contoso.com
   ```

## Configuration Issues

### Issue: Configuration File Invalid

**Error Message**:
```
Validation failed: Configuration JSON is not valid
```

**Solution**:
1. **Validate JSON Syntax**
   ```powershell
   # Test if JSON is valid
   $json = Get-Content "config.json" -Raw
   $json | ConvertFrom-Json
   ```

2. **Run Validation Script**
   ```powershell
   .\Validate-MDOConfiguration.ps1 -ConfigPath "./config.json"
   ```

3. **Common JSON Errors**:
   - Missing commas between properties
   - Unclosed braces/brackets
   - Unescaped quotes in values
   - Invalid email addresses
   - Invalid GUIDs

4. **Fix and Revalidate**
   - Use JSON formatter: https://jsonformatter.org
   - Review error messages carefully
   - Check line numbers mentioned in errors

### Issue: Template Placeholders Not Replaced

**Error Message**:
```
Configuration contains unreplaced template variables: {{TENANT_ID}}, {{TENANT_DOMAIN}}
```

**Cause**: Parameter values not provided to deployment script

**Solution**:
```powershell
# Ensure all parameters are provided
.\Deploy-MDOBaseline.ps1 `
    -ConfigPath "./config.json" `
    -TenantId "12345678-1234-1234-1234-123456789012" `
    -TenantName "Contoso Inc" `
    -TenantDomain "contoso.com" `
    -SecurityAdminEmail "admin@contoso.com"

# Verify no {{}} placeholders in config
(Get-Content "./config.json" -Raw) -match "\{\{" # Should return nothing
```

### Issue: Validation Passes but Deployment Fails

**Cause**: Schema validation passes but policy creation fails

**Solutions**:

1. **Check Policy Naming Conflicts**
   ```powershell
   # List existing policies
   Get-AntiPhishPolicy | Select-Object Name
   Get-SafeAttachmentPolicy | Select-Object Name
   
   # Rename conflicting policies in configuration
   ```

2. **Verify License Level**
   ```powershell
   # Check tenant capabilities
   Get-Tenant | Select-Object DisplayName, F5_is_Advanced_Audit_Enabled
   
   # May need MDO Plan 2 for some features
   ```

3. **Check Tenant Limits**
   ```powershell
   # Exchange Online limits
   @(Get-AntiPhishPolicy).Count  # Check count of policies
   
   # Limits typically allow 100+ policies
   ```

4. **Review Actual Error**
   - Run with -Verbose flag
   - Check deployment log file
   - Note exact error message

## Deployment Issues

### Issue: Deployment Hangs or Times Out

**Symptoms**: Script runs but doesn't complete, no output for extended period

**Causes**: Connection lost, unresponsive tenant, network issues

**Solutions**:

1. **Increase Timeout**
   ```powershell
   # Modify script timeout (in Deploy-MDOBaseline.ps1)
   $PSDefaultParameterValues = @{
       '*:Timeout' = '3600'  # 1 hour instead of default
   }
   ```

2. **Verify Connection**
   ```powershell
   # Check connection status
   Get-ConnectionInformation
   
   # If stale, reconnect
   Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
   Connect-ExchangeOnline -UserPrincipalName admin@contoso.com
   ```

3. **Try Smaller Configuration**
   - Reduce number of policies
   - Deploy one policy type at a time
   - Deploy to subset of users

4. **Check Tenant Status**
   - Go to Microsoft 365 Service Health
   - Look for Exchange Online or Defender incidents

### Issue: Some Policies Deploy, Others Fail

**Symptoms**: Partial deployment, some policies created but others missing

**Solution**:

1. **Identify Failed Policies**
   - Review deployment logs
   - Check which policies were created: `Get-AntiPhishPolicy`
   - Compare to configuration file

2. **Possible Causes**:
   - Policy naming conflict
   - Conflicting recipient conditions
   - Invalid policy settings
   - Permission restriction

3. **Re-run Deployment**
   ```powershell
   # After fixing issues
   .\Deploy-MDOBaseline.ps1 ... # Without -DryRun
   
   # Already-created policies will be updated
   # Failed policies will be retried
   ```

## Post-Deployment Issues

### Issue: Policies Not Applied to Users

**Symptoms**: Users not receiving policy protections

**Cause**: Recipient targeting misconfigured

**Diagnosis**:
```powershell
# Check policy recipient scope
Get-AntiPhishPolicy "Policy Name" | Select-Object RecipientDomainIs*, RecipientFilter

# Check mail flow rule impact
Get-TransportRule | Select-Object Name, Enabled, RecipientDomainIs*

# Review specific user's effective policies
Get-EffectiveAntiSpamPolicy -Identity user@contoso.com
```

**Solution**:

1. **Verify Configuration**
   ```json
   "recipients": {
     "applyToAllRecipients": true  // OR specify recipients
   }
   ```

2. **Update Recipient Filter**
   ```powershell
   # Update policy to apply to all
   Set-AntiPhishPolicy "Policy Name" -RecipientDomainIs @()
   
   # Add specific domains
   Set-HostedContentFilterPolicy "Policy Name" `
       -RecipientDomainIs "contoso.com", "contoso-subsidiary.com"
   ```

3. **Verify Domain Configuration**
   ```powershell
   # Check accepted domains
   Get-AcceptedDomain
   
   # Ensure policy targets accepted domains
   ```

### Issue: High False Positive Rate

**Symptoms**: Legitimate emails marked as spam/phishing

**Metrics**: More than 3-5% of legitimate mail being blocked

**Solutions**:

1. **Review Quarantine**
   ```powershell
   # In Microsoft Defender portal
   # Go to Review > Quarantine
   # Filter by policy action
   # Check for false positives
   ```

2. **Adjust Thresholds**
   - Phishing threshold: 1 (aggressive) → 2-3 (less aggressive)
   - Spam confidence level: 6 → 7-8
   - Bulk threshold: 6 → 7-8

3. **Add to Allow List**
   ```powershell
   # Add trusted sender
   New-TenantAllowBlockListSpoofItems `
       -SpoofedUser "trusted@partner.com" `
       -Action Allow
   
   # Add trusted domain
   New-TenantAllowBlockListItems `
       -ListType Domain `
       -Entries "trusteddomain.com" `
       -Action Allow
   ```

4. **Create Exception Policy**
   ```json
   {
     "name": "Partner Exception Policy",
     "priority": 1,
     "phishingThreshold": 4,  // Less aggressive
     "recipientFilter": "department -eq 'Partner Relations'"
   }
   ```

5. **Review Mail Flow Rules**
   ```powershell
   # Check for conflicting rules
   Get-TransportRule | Select-Object Name, Enabled, Priority
   
   # Rules may override policies
   ```

### Issue: Threats Not Being Detected

**Symptoms**: Known malware/phishing getting through

**Causes**: Policies disabled, thresholds too high, allow list too permissive

**Solutions**:

1. **Verify Policies Enabled**
   ```powershell
   # Check if policies are actually enabled
   Get-AntiPhishPolicy | Select-Object Name, Enabled
   Get-MalwareFilterPolicy | Select-Object Name, Enabled
   Get-HostedContentFilterPolicy | Select-Object Name, Enabled
   ```

2. **Tighten Thresholds**
   ```json
   "phishingThreshold": 1,          // Most aggressive
   "spamConfidenceLevel": 5         // More sensitive
   ```

3. **Check Allow List**
   ```powershell
   # Review allow entries that might be too permissive
   Get-TenantAllowBlockListItems -ListType Sender -Action Allow
   
   # Remove overly broad entries
   ```

4. **Enable Advanced Features**
   ```powershell
   # Enable Safe Attachments scanning
   Set-SafeAttachmentPolicy "Policy" -Enable $true
   
   # Enable Safe Links tracking
   Set-SafeLinksPolicy "Policy" -IsEnabled $true
   ```

## Connectivity Issues

### Issue: Cannot Connect to Exchange Online

**Error Message**:
```
The term 'Connect-ExchangeOnline' is not recognized...
OR
Access Denied: Credentials cannot be empty
```

**Solutions**:

1. **Check Credentials**
   ```powershell
   # Interactive connection
   Connect-ExchangeOnline -UserPrincipalName admin@contoso.com
   
   # Follow MFA prompt if required
   ```

2. **Check MFA/Conditional Access**
   - Ensure your admin account can authenticate
   - Check for device compliance policies
   - Verify conditional access rules

3. **Use Managed Identity** (For Automation)
   ```powershell
   # For automation accounts
   Connect-ExchangeOnline -ManagedIdentity -Organization "contoso.com"
   ```

4. **Check Network**
   ```powershell
   # Verify connectivity
   Test-NetConnection -ComputerName "outlook.office365.com" -Port 443
   
   # Should return TcpTestSucceeded: True
   ```

## Monitoring and Tuning Issues

### Issue: Configuration Analyzer Shows Non-Compliance

**Symptoms**: Configuration Analyzer says policies don't match Standard/Strict

**Cause**: Policies were customized after baseline deployment

**Solutions**:

1. **Review Recommendations**
   - Go to Microsoft Defender portal > Configuration Analyzer
   - Note recommended settings
   - Decide if change aligns with security goals

2. **Apply Recommendations** (If Appropriate)
   ```powershell
   # Update policy to recommended value
   Set-HostedContentFilterPolicy "Policy Name" `
       -BulkThreshold 7  # Recommended value
   ```

3. **Or Document Deviation**
   - Maintain exception list
   - Note business justification
   - Review quarterly

### Issue: Reports Not Showing Data

**Symptoms**: Threat reports empty or no mail flow data

**Causes**: Policies active for less than 24 hours, no messages processed

**Solutions**:

1. **Wait for Data Collection**
   - Reports populate 24-48 hours after deployment
   - Test with email to verify processing

2. **Send Test Email**
   ```powershell
   # Send harmless test email to trigger scanning
   # Example: send to test@contoso.com with "This is a test" subject
   ```

3. **Check Mail Flow**
   ```powershell
   # Review if mail is actually flowing
   Get-MessageTrace -SenderAddress admin@contoso.com -ResultSize 10
   ```

## Recovery and Rollback

### Restoring Previous Configuration

```powershell
# Export current configuration before changes
$policy = Get-AntiPhishPolicy "Policy Name"
$policy | Export-CliXml "backup-policy.xml"

# Restore from backup
$restored = Import-CliXml "backup-policy.xml"
Set-AntiPhishPolicy -Instance $restored
```

### Disabling All Policies Quickly

```powershell
# If emergency disable needed
Get-AntiPhishPolicy | Set-AntiPhishPolicy -Enabled $false
Get-MalwareFilterPolicy | Set-MalwareFilterPolicy -Enabled $false
Get-HostedContentFilterPolicy | Set-HostedContentFilterPolicy -Enabled $false
```

### Complete Rollback to Defaults

```powershell
# Set policies to default
Set-HostedContentFilterPolicy Default -MakeDefault

# Remove custom policies
Get-HostedContentFilterPolicy | Where-Object { $_.Name -like "*Baseline*" } | 
    Remove-HostedContentFilterPolicy -Confirm:$false
```

## Getting Additional Help

### Resources

- [Microsoft Defender for Office 365 Troubleshooting](https://learn.microsoft.com/defender-office-365/troubleshooting-smtp-authentication-issues-microsoft-365)
- [Exchange Online Troubleshooting](https://learn.microsoft.com/exchange/troubleshoot/troubleshoot-eop)
- [Microsoft 365 Service Health Dashboard](https://admin.microsoft.com/Adminportal/Home#/servicehealth)

### Support Channels

1. **Microsoft Support**: Create support ticket in Microsoft 365 admin center
2. **Community Forums**: Microsoft Tech Community - Exchange Online
3. **Documentation**: Microsoft Learn - Defender for Office 365

### Information to Collect for Support

- Exact error message
- Configuration JSON (sanitized)
- Deployment script logs
- Validation output
- Recent PowerShell commands executed
- Tenant ID and organization name

---

**Version**: 1.0.0  
**Last Updated**: January 2026
