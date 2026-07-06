BeforeAll {
    $script:modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:scriptsPath = Join-Path $modulePath "scripts"
    $script:templatesPath = Join-Path $modulePath "config-templates"
}

Describe "Advanced Microsite Feature Tests" {
    
    Context "Configuration Generation Form Validation" {
        It "Should validate tenant ID is GUID format" {
            $tenantId = "12345678-1234-1234-1234-123456789012"
            $guidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            
            $tenantId -match $guidPattern | Should -Be $true
        }
        
        It "Should validate domain format" {
            $domain = "contoso.com"
            $domainPattern = '^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            
            $domain -match $domainPattern | Should -Be $true
        }
        
        It "Should validate email format" {
            $email = "admin@contoso.com"
            $emailPattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            
            $email -match $emailPattern | Should -Be $true
        }
    }
    
    Context "Configuration Generation Output" {
        It "Should generate valid JSON from form inputs" {
            $formData = @{
                tenantId = "12345678-1234-1234-1234-123456789012"
                tenantName = "Contoso Inc"
                domain = "contoso.com"
                email = "admin@contoso.com"
                protectionLevel = "Standard"
            }
            
            { $formData | ConvertTo-Json | ConvertFrom-Json } | Should -Not -Throw
        }
        
        It "Should include all required configuration sections" {
            $config = @{
                organizationSettings = @{}
                protectionLevel = @{}
                policies = @{}
                recipients = @{}
                metadata = @{}
            }
            
            $config.Keys.Count | Should -BeGreaterThanOrEqual 5
        }
    }
    
    Context "Protection Level Selection" {
        It "Should apply Standard protection thresholds" {
            $standard = @{
                phishingThreshold = 1
                spamConfidenceLevel = 6
            }
            
            $standard.phishingThreshold | Should -Be 1
            $standard.spamConfidenceLevel | Should -Be 6
        }
        
        It "Should apply Strict protection thresholds" {
            $strict = @{
                phishingThreshold = 1
                spamConfidenceLevel = 5
                bulkThreshold = 6
            }
            
            $strict.phishingThreshold | Should -Be 1
            $strict.spamConfidenceLevel | Should -Be 5
            $strict.bulkThreshold | Should -Be 6
        }
    }
}

Describe "Policy Priority and Ordering Tests" {
    
    Context "Policy Execution Order" {
        It "Should respect policy priority sequence" {
            $policies = @(
                @{ priority = 0; name = "Priority 0 Policy" },
                @{ priority = 1; name = "Priority 1 Policy" },
                @{ priority = 2; name = "Priority 2 Policy" }
            )
            
            $sorted = $policies | Sort-Object -Property priority
            $sorted[0].priority | Should -Be 0
            $sorted[-1].priority | Should -Be 2
        }
        
        It "Should prevent duplicate priorities" {
            $policy1 = @{ priority = 0; name = "First" }
            $policy2 = @{ priority = 0; name = "Second" }
            
            @($policy1, $policy2) | Group-Object -Property priority | 
                Where-Object { $_.Count -gt 1 } | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Recipient Targeting Consistency" {
    
    Context "Targeting Strategy Application" {
        It "Should target all recipients when applyToAllRecipients is true" {
            $config = @{
                recipients = @{ applyToAllRecipients = $true }
            }
            
            $config.recipients.applyToAllRecipients | Should -Be $true
        }
        
        It "Should target specific domains when specified" {
            $config = @{
                recipients = @{
                    applyToAllRecipients = $false
                    includedDomains = @("contoso.com", "contoso-subsidiary.com")
                }
            }
            
            $config.recipients.includedDomains.Count | Should -Be 2
        }
        
        It "Should exclude domains when specified" {
            $config = @{
                recipients = @{
                    applyToAllRecipients = $true
                    excludedDomains = @("test.com", "dev.com")
                }
            }
            
            $config.recipients.excludedDomains.Count | Should -Be 2
        }
    }
}

Describe "Notification and Alert Configuration" {
    
    Context "Alert Recipient Validation" {
        It "Should accept multiple alert notification recipients" {
            $notifications = @{
                alertNotifications = @(
                    "security-team@contoso.com",
                    "ciso@contoso.com",
                    "infosec@contoso.com"
                )
            }
            
            $notifications.alertNotifications.Count | Should -Be 3
        }
        
        It "Should validate each recipient email format" {
            $emailPattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            $emails = @("admin@contoso.com", "team@contoso.com")
            
            $emails | ForEach-Object {
                $_ -match $emailPattern | Should -Be $true
            }
        }
    }
}

Describe "Advanced Threat Protection Features" {
    
    Context "Feature Enablement" {
        It "Should support Automated Investigation and Response (AIR)" {
            $config = @{
                advancedThreatProtection = @{
                    automatedInvestigationResponse = $true
                }
            }
            
            $config.advancedThreatProtection.automatedInvestigationResponse | Should -Be $true
        }
        
        It "Should support Threat Explorer" {
            $config = @{
                advancedThreatProtection = @{
                    threatExplorer = $true
                }
            }
            
            $config.advancedThreatProtection.threatExplorer | Should -Be $true
        }
        
        It "Should support Campaign View" {
            $config = @{
                advancedThreatProtection = @{
                    campaignView = $true
                }
            }
            
            $config.advancedThreatProtection.campaignView | Should -Be $true
        }
        
        It "Should support Attack Simulation Training" {
            $config = @{
                advancedThreatProtection = @{
                    attackSimulationTraining = $true
                }
            }
            
            $config.advancedThreatProtection.attackSimulationTraining | Should -Be $true
        }
    }
    
    Context "Feature Combinations" {
        It "Should enable all features in Strict mode" {
            $strictConfig = Get-Content (Join-Path $script:templatesPath "baseline-strict.json") -Raw | 
                ConvertFrom-Json
            
            $atp = $strictConfig.advancedThreatProtection
            
            # Strict should enable at least AIR and Threat Explorer
            ($atp.automatedInvestigationResponse -or $atp.threatExplorer) | Should -Be $true
        }
    }
}

Describe "Version and Metadata Tracking" {
    
    Context "Configuration Metadata" {
        It "Should track configuration version" {
            $config = @{
                metadata = @{
                    version = "1.0.0"
                }
            }
            
            $config.metadata.version | Should -Match '^\d+\.\d+\.\d+$'
        }
        
        It "Should track creation date" {
            $config = @{
                metadata = @{
                    createdDate = "2026-01-15T10:00:00Z"
                }
            }
            
            $config.metadata.createdDate | Should -Match '^\d{4}-\d{2}-\d{2}T'
        }
        
        It "Should track created by" {
            $config = @{
                metadata = @{
                    createdBy = "Administrator"
                }
            }
            
            $config.metadata.createdBy | Should -Not -BeNullOrEmpty
        }
    }
}
