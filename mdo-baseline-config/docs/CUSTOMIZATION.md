# MDO Baseline Configuration - Customization Guide

Guide for customizing Microsoft Defender for Office 365 baseline configurations for your organization's specific needs.

## Overview

While the baseline configurations represent Microsoft best practices, most organizations need customizations for their specific security policies, user groups, and threat profiles. This guide covers common customization scenarios.

## Configuration Structure Review

Before customizing, understand the configuration JSON structure:

```json
{
  "organizationSettings": { ... },     // Organization identity
  "protectionLevel": { ... },          // Standard or Strict
  "policies": { ... },                 // All threat policies
  "recipients": { ... },               // Who policies apply to
  "allowBlockList": { ... },           // Allow/block entries
  "authentication": { ... },           // DMARC/DKIM/SPF
  "advancedThreatProtection": { ... }, // AIR, Threat Explorer
  "notifications": { ... },            // Alert recipients
  "metadata": { ... }                  // Version and creator
}
```

## Common Customizations

### 1. Recipient Targeting

#### Applying to Specific Users Only

```json
"recipients": {
  "applyToAllRecipients": false,
  "includedUsers": [
    "john@contoso.com",
    "sarah@contoso.com",
    "finance-team@contoso.com"
  ]
}
```

#### Excluding Specific Groups

```json
"recipients": {
  "applyToAllRecipients": true,
  "excludedGroups": [
    "00000000-0000-0000-0000-000000000001",  // External Partners Group
    "00000000-0000-0000-0000-000000000002"   // Service Accounts Group
  ]
}
```

#### Targeting by Domain

```json
"recipients": {
  "applyToAllRecipients": false,
  "includedDomains": [
    "contoso.com",
    "contosocorp.com"
  ]
}
```

### 2. Policy Action Customization

#### Quarantine vs. Junk Folder

**More Aggressive (Quarantine)**:
```json
"spamAction": "Quarantine",
"highConfidenceSpamAction": "Quarantine"
```

**More Permissive (Junk Folder)**:
```json
"spamAction": "MoveToJmf",
"highConfidenceSpamAction": "MoveToJmf"
```

#### Safe Attachments Actions

**Block and Redirect** (Safest):
```json
{
  "action": "Block",
  "redirectToRecipients": ["security-team@contoso.com"]
}
```

**Dynamic Delivery** (Least Disruptive):
```json
{
  "action": "DynamicDelivery"
}
```

### 3. Risk Threshold Tuning

#### Reducing False Positives

```json
"protectionLevel": {
  "customRiskThresholds": {
    "phishingThreshold": 2,           // Increase from 1 (less aggressive)
    "advancedPhishingThreshold": 3,   // Increase from 2
    "spamConfidenceLevel": 7          // Increase from 6
  }
}
```

#### Increasing Protection

```json
"protectionLevel": {
  "customRiskThresholds": {
    "phishingThreshold": 1,           // Most aggressive
    "advancedPhishingThreshold": 1,   // Most aggressive
    "spamConfidenceLevel": 5          // More sensitive
  }
}
```

#### Bulk Email Threshold

```json
{
  "bulkSpamAction": "Quarantine",
  "bulkThreshold": 5    // More aggressive (lower = more strict)
}
```

### 4. Protected Users & Domains

Add VIP protection through impersonation settings:

```json
{
  "name": "Executive Protection Policy",
  "impersonationProtection": {
    "enableUserImpersonationProtection": true,
    "protectedUsers": [
      "ceo@contoso.com",
      "cfo@contoso.com",
      "ciso@contoso.com"
    ],
    "userImpersonationAction": "Quarantine",
    "protectedDomains": [
      "contoso.com",
      "contoso-subsidiary.com"
    ]
  }
}
```

### 5. Allow/Block List Management

#### Add Trusted Partners

```json
"allowBlockList": {
  "allowedSenders": [
    "partner@trustedcompany.com",
    "billing@vendor.com"
  ],
  "allowedDomains": [
    "trustedpartner.com",
    "supplier.com"
  ]
}
```

#### Block Malicious Domains

```json
"allowBlockList": {
  "blockedSenders": [
    "spam@malicious.com"
  ],
  "blockedDomains": [
    "phishingsite.com",
    "malware-distribution.net"
  ],
  "blockedUrls": [
    "https://malicious-site.com/payload",
    "https://phishing-page.net/login"
  ]
}
```

### 6. Authentication Framework Customization

#### Strict DMARC Enforcement

```json
"authentication": {
  "dmarc": {
    "enabled": true,
    "policy": "reject",              // Reject vs quarantine
    "percentageToFilter": 100,       // Apply to all messages
    "alignmentDmarc": "Strict"       // Strict vs Relaxed
  }
}
```

#### Relaxed Authentication (If Needed)

```json
"authentication": {
  "dmarc": {
    "policy": "quarantine",          // Quarantine instead of reject
    "percentageToFilter": 50,        // Apply to 50% initially
    "alignmentDmarc": "Relaxed"      // More permissive
  }
}
```

### 7. Notification Recipients

#### Multiple Alert Destinations

```json
"notifications": {
  "alertNotifications": [
    "security-team@contoso.com",
    "infosec-manager@contoso.com",
    "it-director@contoso.com"
  ],
  "quarantineNotifications": true,
  "dailyReport": true
}
```

### 8. Advanced Threat Protection

#### Enable All Advanced Features

```json
"advancedThreatProtection": {
  "automatedInvestigationResponse": true,
  "threatExplorer": true,
  "campaignView": true,
  "attackSimulationTraining": true
}
```

#### Budget-Conscious Approach

```json
"advancedThreatProtection": {
  "automatedInvestigationResponse": true,  // Most valuable
  "threatExplorer": false,
  "campaignView": false,
  "attackSimulationTraining": false
}
```

## Creating Custom Policies

### Multi-Policy Strategy

Instead of relying solely on baseline policies, create specialized policies:

```json
"policies": {
  "antiPhishing": [
    {
      "name": "Standard Anti-Phishing Policy",
      "priority": 0,
      "phishingThreshold": 1
    },
    {
      "name": "Relaxed Policy for Partners",
      "priority": 1,
      "recipientDomainIsManaged": false,
      "phishingThreshold": 3
    },
    {
      "name": "Strict Policy for Finance",
      "priority": 2,
      "phishingThreshold": 1,
      "impersonationProtection": {
        "enableUserImpersonationProtection": true,
        "protectedUsers": ["treasurer@contoso.com"]
      }
    }
  ]
}
```

### Policy Priority Explanation

- **Priority 0** = Highest priority (evaluated first)
- **Priority 1** = Medium priority
- **Priority 2+** = Lower priority

First matching policy wins! Order matters.

## Implementation Patterns

### Pattern 1: Aggressive for Finance, Moderate for Others

```json
{
  "policies": {
    "antiPhishing": [
      {
        "name": "Finance-Strict Policy",
        "priority": 0,
        "phishingThreshold": 1,
        "impersonationProtection": {
          "protectedUsers": ["finance@contoso.com"]
        }
      },
      {
        "name": "Standard Policy",
        "priority": 1,
        "phishingThreshold": 1
      }
    ]
  }
}
```

### Pattern 2: Gradual Enforcement Timeline

Phase configurations with increasing restrictions:

**Phase 1 - Audit Only**:
```json
"deploymentMode": "Audit"
```

**Phase 2 - Soft Enforcement** (30 days later):
```json
{
  "spamAction": "MoveToJmf",          // Not quarantine
  "phishSpamAction": "Quarantine",    // But phishing is quarantined
  "deploymentMode": "Enforce"
}
```

**Phase 3 - Full Enforcement** (60 days later):
```json
{
  "spamAction": "Quarantine",         // Strict enforcement
  "phishSpamAction": "Quarantine",
  "deploymentMode": "Enforce"
}
```

### Pattern 3: Exception Management

Handle legitimate senders that trigger false positives:

```json
{
  "allowBlockList": {
    "allowedSenders": [
      "notification@service-x.com"    // Third-party service
    ],
    "allowedUrls": [
      "https://safe-url.com/notifications"
    ]
  }
}
```

## Deployment After Customization

1. **Update Configuration File**
   - Modify JSON with your customizations
   - Save as new version: `contoso-custom-v2.json`

2. **Validate Changes**
   ```powershell
   .\Validate-MDOConfiguration.ps1 -ConfigPath "./contoso-custom-v2.json"
   ```

3. **Test with Dry-Run**
   ```powershell
   .\Deploy-MDOBaseline.ps1 `
       -ConfigPath "./contoso-custom-v2.json" `
       -TenantId "..." `
       -TenantName "..." `
       -TenantDomain "..." `
       -SecurityAdminEmail "..." `
       -DryRun
   ```

4. **Review Output**
   - Verify all policies are as intended
   - Check recipient targeting
   - Confirm alert recipients

5. **Deploy**
   ```powershell
   .\Deploy-MDOBaseline.ps1 `
       -ConfigPath "./contoso-custom-v2.json" `
       -TenantId "..." `
       -TenantName "..." `
       -TenantDomain "..." `
       -SecurityAdminEmail "..."
   ```

## Best Practices for Customization

1. **Start with Baseline**
   - Don't start from scratch
   - Use Standard or Strict baseline as foundation
   - Make incremental changes

2. **Document Changes**
   - Note why each customization was made
   - Track version changes in metadata
   - Maintain change log

3. **Test Before Production**
   - Always use dry-run first
   - Test with pilot group
   - Validate no unintended side effects

4. **Monitor Results**
   - Track false positive rate
   - Monitor legitimate mail delivery
   - Adjust thresholds based on results

5. **Version Control**
   ```
   contoso-standard-v1-baseline.json
   contoso-custom-v2-finance-strict.json
   contoso-custom-v3-pilot-phase.json
   contoso-custom-v4-production-stable.json
   ```

6. **Regular Review**
   - Review quarterly
   - Adjust for threat landscape changes
   - Update for organizational changes

## Common Customization Mistakes

❌ **Don't**: Overly aggressive thresholds causing excessive false positives  
✅ **Do**: Start conservative, tighten after monitoring

❌ **Don't**: Hardcode email addresses (use configuration parameters)  
✅ **Do**: Use template variables {{SECURITY_ADMIN_EMAIL}}

❌ **Don't**: Create conflicting policies  
✅ **Do**: Plan policy priority and precedence

❌ **Don't**: Forget to update metadata version  
✅ **Do**: Increment version and document changes

❌ **Don't**: Deploy without dry-run testing  
✅ **Do**: Always test with dry-run first

## Troubleshooting Customizations

### Issue: Policy Not Applying to Expected Users

1. Check recipient configuration
2. Verify policy priority (lower = higher)
3. Confirm no exclusions are matching
4. Review mail flow logs

### Issue: False Positives Increased

1. Review phishing threshold (reduce from 1 to 2)
2. Check bulk threshold setting
3. Add legitimate senders to allow list
4. Analyze threat reports for patterns

### Issue: Policy Changes Not Taking Effect

1. Verify deployment completed
2. Check for policy conflicts
3. Review policy priority
4. Test with mail flow rules

---

**Version**: 1.0.0  
**Last Updated**: January 2026
