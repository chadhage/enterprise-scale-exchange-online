/**
 * Microsoft Defender for Office 365 Baseline Configuration Microsite
 * Interactive functionality and configuration generation
 */

'use strict';

// ============================================================================
// Section Navigation
// ============================================================================

function showSection(sectionId) {
    // Hide all sections
    const sections = document.querySelectorAll('.section');
    sections.forEach(section => {
        section.classList.remove('active');
    });

    // Show selected section
    const selectedSection = document.getElementById(sectionId);
    if (selectedSection) {
        selectedSection.classList.add('active');
        window.scrollTo(0, 0);
    }

    // Update nav active state
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.classList.remove('active');
    });
    event.target.classList.add('active');
}

// ============================================================================
// Configuration Form Handling
// ============================================================================

function updateProtectionDescription(level) {
    const descriptions = {
        'Standard': 'Standard protection is recommended for most organizations as a starting point and automatically protects against current threats.',
        'Strict': 'Strict protection is recommended for high-risk environments, financial institutions, government agencies, and organizations handling highly sensitive data. It includes aggressive detection thresholds and Automated Investigation & Response.'
    };
    
    const descElement = document.getElementById('protectionDescription');
    if (descElement) {
        descElement.innerHTML = `<p>${descriptions[level]}</p>`;
    }
}

function generateConfig() {
    try {
        // Get form data
        const formData = new FormData(document.getElementById('configForm'));
        
        // Validate required fields
        const tenantId = formData.get('tenantId');
        const tenantName = formData.get('tenantName');
        const tenantDomain = formData.get('tenantDomain');
        const securityAdminEmail = formData.get('securityAdminEmail');
        
        if (!tenantId || !tenantName || !tenantDomain || !securityAdminEmail) {
            alert('Please fill in all required fields (marked with *)');
            return;
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(securityAdminEmail)) {
            alert('Please enter a valid email address');
            return;
        }

        // Validate GUID format
        const guidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!guidRegex.test(tenantId)) {
            alert('Please enter a valid Tenant ID (GUID format)');
            return;
        }

        // Build configuration object
        const protectionLevel = formData.get('protectionLevel');
        const baseConfig = protectionLevel === 'Standard' ? BASELINE_STANDARD : BASELINE_STRICT;
        
        // Replace placeholders
        const configStr = JSON.stringify(baseConfig)
            .replace(/\{\{TENANT_ID\}\}/g, tenantId)
            .replace(/\{\{TENANT_NAME\}\}/g, tenantName)
            .replace(/\{\{TENANT_DOMAIN\}\}/g, tenantDomain)
            .replace(/\{\{SECURITY_ADMIN_EMAIL\}\}/g, securityAdminEmail);
        
        const config = JSON.parse(configStr);

        // Add custom settings if specified
        const allowedSenders = formData.get('allowedSenders');
        if (allowedSenders) {
            config.allowBlockList.allowedSenders = allowedSenders
                .split(',')
                .map(s => s.trim())
                .filter(s => s.length > 0);
        }

        const blockedSenders = formData.get('blockedSenders');
        if (blockedSenders) {
            config.allowBlockList.blockedSenders = blockedSenders
                .split(',')
                .map(s => s.trim())
                .filter(s => s.length > 0);
        }

        // Update deployment settings
        config.organizationSettings.deploymentMode = formData.get('deploymentMode');
        config.organizationSettings.rolloutPhase = parseInt(formData.get('rolloutPhase'));
        
        if (formData.get('enableAIR')) {
            config.advancedThreatProtection.automatedInvestigationResponse = true;
            config.advancedThreatProtection.threatExplorer = true;
            config.advancedThreatProtection.campaignView = true;
        }

        // Add metadata
        config.metadata.createdDate = new Date().toISOString();
        config.metadata.lastModified = new Date().toISOString();

        // Display preview
        const preview = document.getElementById('configPreview');
        const content = document.getElementById('configContent');
        
        content.textContent = JSON.stringify(config, null, 2);
        preview.style.display = 'block';
        
        // Scroll to preview
        preview.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        
    } catch (error) {
        console.error('Configuration generation error:', error);
        alert('Error generating configuration: ' + error.message);
    }
}

function copyToClipboard() {
    const content = document.getElementById('configContent');
    const text = content.textContent;
    
    navigator.clipboard.writeText(text).then(() => {
        alert('Configuration copied to clipboard!');
    }).catch(() => {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        alert('Configuration copied to clipboard!');
    });
}

function downloadConfigFile() {
    const content = document.getElementById('configContent').textContent;
    const config = JSON.parse(content);
    const filename = `${config.organizationSettings.tenantName}-${config.protectionLevel.preset.toLowerCase()}-${new Date().toISOString().split('T')[0]}.json`;
    
    const element = document.createElement('a');
    element.setAttribute('href', 'data:application/json;charset=utf-8,' + encodeURIComponent(content));
    element.setAttribute('download', filename);
    element.style.display = 'none';
    
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
}

// ============================================================================
// Baseline Configuration Templates (Embedded)
// ============================================================================

const BASELINE_STANDARD = {
    "$schema": "./mdo-config-schema.json",
    "organizationSettings": {
        "tenantId": "{{TENANT_ID}}",
        "tenantName": "{{TENANT_NAME}}",
        "protectionStrategy": "Standard",
        "executionEnvironment": "Cloud",
        "deploymentMode": "Audit",
        "rolloutPhase": 1,
        "userTags": ["C-Suite", "Board Members", "Finance Department"]
    },
    "protectionLevel": {
        "preset": "Standard",
        "customRiskThresholds": {
            "phishingThreshold": 1,
            "advancedPhishingThreshold": 2,
            "spamConfidenceLevel": 6
        }
    },
    "policies": {
        "antiPhishing": [{
            "name": "Standard Anti-Phishing Policy",
            "enabled": true,
            "spoofSettings": {
                "spoofingAction": "MoveToJmf",
                "intraOrgSpoof": true,
                "externalPartnerSpoof": true
            },
            "impersonationProtection": {
                "enableUserImpersonationProtection": true,
                "enableDomainImpersonationProtection": true,
                "userImpersonationAction": "Quarantine",
                "domainImpersonationAction": "Quarantine",
                "protectedDomains": ["{{TENANT_DOMAIN}}"],
                "trustLevel": "Advanced"
            },
            "phishingThreshold": 1,
            "recipientDomainIsManaged": true,
            "priority": 0
        }],
        "antiMalware": [{
            "name": "Standard Anti-Malware Policy",
            "enabled": true,
            "commonAttachmentTypesFilter": true,
            "enableFileTypeFilter": true,
            "scanResultAction": "Quarantine",
            "zeroDayAction": "Quarantine",
            "enableInternalScan": true,
            "enableExternalScan": true,
            "fallbackAction": "Block",
            "priority": 0
        }],
        "antiSpam": [{
            "name": "Standard Anti-Spam Policy",
            "enabled": true,
            "spamAction": "MoveToJmf",
            "highConfidenceSpamAction": "Quarantine",
            "bulkSpamAction": "MoveToJmf",
            "bulkThreshold": 7,
            "phishSpamAction": "Quarantine",
            "enableLanguageBlockList": false,
            "enableRegionBlockList": false,
            "priority": 0
        }],
        "safeAttachments": [{
            "name": "Standard Safe Attachments Policy",
            "enable": true,
            "action": "Block",
            "redirectToRecipients": [],
            "actionOnError": "Block",
            "enableScanTeamsAttachments": true,
            "priority": 0
        }],
        "safeLinks": [{
            "name": "Standard Safe Links Policy",
            "enabled": true,
            "scanUrls": true,
            "detonationAction": "Block",
            "enableForTeams": true,
            "trackClicks": true,
            "allowClickThrough": false,
            "priority": 0
        }],
        "outboundSpam": [{
            "name": "Standard Outbound Spam Policy",
            "enabled": true,
            "spamOutboundAction": "Block",
            "notifyOutboundSpam": true,
            "notifyOutboundSpamRecipients": ["{{SECURITY_ADMIN_EMAIL}}"]
        }]
    },
    "recipients": {
        "applyToAllRecipients": true,
        "includedDomains": ["{{TENANT_DOMAIN}}"],
        "excludedDomains": [],
        "includedGroups": [],
        "excludedGroups": [],
        "includedUsers": [],
        "excludedUsers": []
    },
    "allowBlockList": {
        "allowedSenders": [],
        "blockedSenders": [],
        "allowedDomains": [],
        "blockedDomains": [],
        "allowedUrls": [],
        "blockedUrls": []
    },
    "authentication": {
        "dmarc": {
            "enabled": true,
            "policy": "quarantine",
            "percentageToFilter": 100,
            "alignmentDmarc": "Strict"
        },
        "dkim": {
            "enabled": true,
            "signingEnabled": true
        },
        "spf": {
            "enabled": true
        }
    },
    "advancedThreatProtection": {
        "automatedInvestigationResponse": false,
        "threatExplorer": false,
        "campaignView": false,
        "attackSimulationTraining": false
    },
    "notifications": {
        "alertNotifications": ["{{SECURITY_ADMIN_EMAIL}}"],
        "quarantineNotifications": true,
        "dailyReport": true
    },
    "metadata": {
        "version": "1.0.0",
        "createdDate": "2026-01-01T00:00:00Z",
        "lastModified": "2026-01-01T00:00:00Z",
        "createdBy": "MDO Baseline Configuration Generator",
        "description": "Standard protection level baseline configuration"
    }
};

const BASELINE_STRICT = {
    "$schema": "./mdo-config-schema.json",
    "organizationSettings": {
        "tenantId": "{{TENANT_ID}}",
        "tenantName": "{{TENANT_NAME}}",
        "protectionStrategy": "Strict",
        "executionEnvironment": "Cloud",
        "deploymentMode": "Audit",
        "rolloutPhase": 1,
        "userTags": ["C-Suite", "Board Members", "Finance Department", "Legal Department", "HR Department"]
    },
    "protectionLevel": {
        "preset": "Strict",
        "customRiskThresholds": {
            "phishingThreshold": 1,
            "advancedPhishingThreshold": 1,
            "spamConfidenceLevel": 6
        }
    },
    "policies": {
        "antiPhishing": [{
            "name": "Strict Anti-Phishing Policy",
            "enabled": true,
            "spoofSettings": {
                "spoofingAction": "Quarantine",
                "intraOrgSpoof": true,
                "externalPartnerSpoof": true
            },
            "impersonationProtection": {
                "enableUserImpersonationProtection": true,
                "enableDomainImpersonationProtection": true,
                "userImpersonationAction": "Quarantine",
                "domainImpersonationAction": "Quarantine",
                "protectedDomains": ["{{TENANT_DOMAIN}}"],
                "trustLevel": "Advanced"
            },
            "phishingThreshold": 1,
            "recipientDomainIsManaged": true,
            "priority": 0
        }],
        "antiMalware": [{
            "name": "Strict Anti-Malware Policy",
            "enabled": true,
            "commonAttachmentTypesFilter": true,
            "enableFileTypeFilter": true,
            "scanResultAction": "Quarantine",
            "zeroDayAction": "Quarantine",
            "enableInternalScan": true,
            "enableExternalScan": true,
            "fallbackAction": "Block",
            "priority": 0
        }],
        "antiSpam": [{
            "name": "Strict Anti-Spam Policy",
            "enabled": true,
            "spamAction": "Quarantine",
            "highConfidenceSpamAction": "Quarantine",
            "bulkSpamAction": "Quarantine",
            "bulkThreshold": 6,
            "phishSpamAction": "Quarantine",
            "enableLanguageBlockList": false,
            "enableRegionBlockList": false,
            "priority": 0
        }],
        "safeAttachments": [{
            "name": "Strict Safe Attachments Policy",
            "enable": true,
            "action": "Block",
            "redirectToRecipients": ["{{SECURITY_ADMIN_EMAIL}}"],
            "actionOnError": "Block",
            "enableScanTeamsAttachments": true,
            "priority": 0
        }],
        "safeLinks": [{
            "name": "Strict Safe Links Policy",
            "enabled": true,
            "scanUrls": true,
            "detonationAction": "Block",
            "enableForTeams": true,
            "trackClicks": true,
            "allowClickThrough": false,
            "priority": 0
        }],
        "outboundSpam": [{
            "name": "Strict Outbound Spam Policy",
            "enabled": true,
            "spamOutboundAction": "Block",
            "notifyOutboundSpam": true,
            "notifyOutboundSpamRecipients": ["{{SECURITY_ADMIN_EMAIL}}"]
        }]
    },
    "recipients": {
        "applyToAllRecipients": false,
        "includedDomains": ["{{TENANT_DOMAIN}}"],
        "excludedDomains": [],
        "includedGroups": [],
        "excludedGroups": [],
        "includedUsers": [],
        "excludedUsers": []
    },
    "allowBlockList": {
        "allowedSenders": [],
        "blockedSenders": [],
        "allowedDomains": [],
        "blockedDomains": [],
        "allowedUrls": [],
        "blockedUrls": []
    },
    "authentication": {
        "dmarc": {
            "enabled": true,
            "policy": "reject",
            "percentageToFilter": 100,
            "alignmentDmarc": "Strict"
        },
        "dkim": {
            "enabled": true,
            "signingEnabled": true
        },
        "spf": {
            "enabled": true
        }
    },
    "advancedThreatProtection": {
        "automatedInvestigationResponse": true,
        "threatExplorer": true,
        "campaignView": true,
        "attackSimulationTraining": true
    },
    "notifications": {
        "alertNotifications": ["{{SECURITY_ADMIN_EMAIL}}"],
        "quarantineNotifications": true,
        "dailyReport": true
    },
    "metadata": {
        "version": "1.0.0",
        "createdDate": "2026-01-01T00:00:00Z",
        "lastModified": "2026-01-01T00:00:00Z",
        "createdBy": "MDO Baseline Configuration Generator",
        "description": "Strict protection level baseline configuration"
    }
};

// ============================================================================
// Event Listeners & Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', function () {
    // Set initial protection description
    updateProtectionDescription('Standard');

    // Add form submission handling
    const configForm = document.getElementById('configForm');
    if (configForm) {
        configForm.addEventListener('submit', function (e) {
            e.preventDefault();
        });
    }

    // Add keyboard shortcuts
    document.addEventListener('keydown', function (e) {
        if (e.ctrlKey || e.metaKey) {
            if (e.key === 'Enter') {
                generateConfig();
            }
        }
    });
});

// ============================================================================
// Utilities
// ============================================================================

function formatDate(date) {
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });
}

function validateEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

function validateGUID(guid) {
    const regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return regex.test(guid);
}

console.log('MDO Baseline Configuration Microsite loaded successfully');
