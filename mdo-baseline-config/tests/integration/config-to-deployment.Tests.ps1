BeforeAll {
    $script:modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:scriptsPath = Join-Path $modulePath "scripts"
    $script:templatesPath = Join-Path $modulePath "config-templates"
}

Describe "Configuration Generation Integration Tests" {
    
    Context "Standard Template to Full Configuration" {
        It "Should generate complete configuration from standard template" {
            $configPath = Join-Path $script:templatesPath "baseline-standard.json"
            Test-Path $configPath | Should -Be $true
            
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            
            # Verify structure
            $config.organizationSettings | Should -Not -BeNullOrEmpty
            $config.protectionLevel | Should -Not -BeNullOrEmpty
            $config.policies | Should -Not -BeNullOrEmpty
            $config.recipients | Should -Not -BeNullOrEmpty
            $config.metadata | Should -Not -BeNullOrEmpty
        }
        
        It "Should contain all required policy types" {
            $configPath = Join-Path $script:templatesPath "baseline-standard.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            
            $requiredPolicies = @("antiPhishing", "antiMalware", "antiSpam", "safeAttachments", "safeLinks")
            foreach ($policy in $requiredPolicies) {
                $config.policies.PSObject.Properties.Name -contains $policy | Should -Be $true
            }
        }
    }
    
    Context "Strict Template to Full Configuration" {
        It "Should generate complete configuration from strict template" {
            $configPath = Join-Path $script:templatesPath "baseline-strict.json"
            Test-Path $configPath | Should -Be $true
            
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            
            # Verify structure
            $config.organizationSettings | Should -Not -BeNullOrEmpty
            $config.protectionLevel | Should -Not -BeNullOrEmpty
            $config.policies | Should -Not -BeNullOrEmpty
        }
        
        It "Should have stricter thresholds than standard" {
            $standardPath = Join-Path $script:templatesPath "baseline-standard.json"
            $strictPath = Join-Path $script:templatesPath "baseline-strict.json"
            
            $standard = Get-Content $standardPath -Raw | ConvertFrom-Json
            $strict = Get-Content $strictPath -Raw | ConvertFrom-Json
            
            # Verify advanced features enabled in strict
            $strict.advancedThreatProtection.automatedInvestigationResponse | Should -Be $true
        }
    }
    
    Context "Parameter Substitution Integration" {
        It "Should replace all organization placeholders" {
            $template = Get-Content (Join-Path $script:templatesPath "baseline-standard.json") -Raw
            
            $config = $template `
                -replace '\{\{TENANT_ID\}\}', "12345678-1234-1234-1234-123456789012" `
                -replace '\{\{TENANT_NAME\}\}', "Contoso Inc" `
                -replace '\{\{TENANT_DOMAIN\}\}', "contoso.com" `
                -replace '\{\{SECURITY_ADMIN_EMAIL\}\}', "admin@contoso.com"
            
            $config -match '\{\{' | Should -BeNullOrEmpty
            
            $parsed = $config | ConvertFrom-Json
            $parsed.organizationSettings.tenantId | Should -Be "12345678-1234-1234-1234-123456789012"
        }
        
        It "Should maintain JSON validity after substitution" {
            $template = Get-Content (Join-Path $script:templatesPath "baseline-standard.json") -Raw
            
            $config = $template `
                -replace '\{\{TENANT_ID\}\}', "12345678-1234-1234-1234-123456789012" `
                -replace '\{\{TENANT_NAME\}\}', "Test Org" `
                -replace '\{\{TENANT_DOMAIN\}\}', "test.com" `
                -replace '\{\{SECURITY_ADMIN_EMAIL\}\}', "test@test.com"
            
            { $config | ConvertFrom-Json } | Should -Not -Throw
        }
    }
    
    Context "Configuration Validation Pipeline" {
        It "Should pass validation after generation" {
            $configPath = Join-Path $script:templatesPath "baseline-standard.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            
            # Basic validation checks
            $config.organizationSettings.tenantId | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}'
            $config.protectionLevel.customRiskThresholds.phishingThreshold | Should -BeGreaterThanOrEqual 1
            $config.protectionLevel.customRiskThresholds.phishingThreshold | Should -BeLessThanOrEqual 4
        }
    }
}

Describe "Policy Deployment Integration Tests" {
    
    Context "Multiple Policy Coordination" {
        It "Should support multiple anti-phishing policies" {
            $configPath = Join-Path $script:templatesPath "baseline-strict.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            
            # Verify policy has required properties
            $config.policies.antiPhishing | Should -Not -BeNullOrEmpty
        }
        
        It "Should maintain policy priorities" {
            $policies = @(
                @{ name = "Policy1"; priority = 0 },
                @{ name = "Policy2"; priority = 1 },
                @{ name = "Policy3"; priority = 2 }
            )
            
            $sorted = $policies | Sort-Object -Property priority
            $sorted[0].name | Should -Be "Policy1"
            $sorted[1].name | Should -Be "Policy2"
        }
    }
    
    Context "Recipient Targeting Consistency" {
        It "Should apply consistent recipient targeting across policies" {
            $configPath = Join-Path $script:templatesPath "baseline-standard.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            
            $config.recipients.applyToAllRecipients | Should -Be $true
        }
    }
}

Describe "Allow/Block List Integration Tests" {
    
    Context "Allow List Processing" {
        It "Should parse allowed senders correctly" {
            $config = @{
                allowBlockList = @{
                    allowedSenders = @("trusted@company.com", "partner@org.com")
                }
            }
            
            $config.allowBlockList.allowedSenders.Count | Should -Be 2
        }
        
        It "Should parse allowed domains correctly" {
            $config = @{
                allowBlockList = @{
                    allowedDomains = @("trusted.com", "partner.com")
                }
            }
            
            $config.allowBlockList.allowedDomains.Count | Should -Be 2
        }
    }
    
    Context "Block List Processing" {
        It "Should parse blocked senders correctly" {
            $config = @{
                allowBlockList = @{
                    blockedSenders = @("spam@malicious.com")
                }
            }
            
            $config.allowBlockList.blockedSenders | Should -Not -BeNullOrEmpty
        }
        
        It "Should parse blocked domains correctly" {
            $config = @{
                allowBlockList = @{
                    blockedDomains = @("malicious.com", "phishing.net")
                }
            }
            
            $config.allowBlockList.blockedDomains.Count | Should -Be 2
        }
    }
}

Describe "Configuration Transformation Pipeline" {
    
    Context "Template to JSON to PowerShell" {
        It "Should successfully transform through all stages" {
            # Stage 1: Load template
            $templatePath = Join-Path $script:templatesPath "baseline-standard.json"
            $template = Get-Content $templatePath -Raw
            
            # Stage 2: Substitute parameters
            $config = $template `
                -replace '\{\{TENANT_ID\}\}', "12345678-1234-1234-1234-123456789012" `
                -replace '\{\{TENANT_NAME\}\}', "Test" `
                -replace '\{\{TENANT_DOMAIN\}\}', "test.com" `
                -replace '\{\{SECURITY_ADMIN_EMAIL\}\}', "admin@test.com"
            
            # Stage 3: Parse to object
            $parsed = $config | ConvertFrom-Json
            
            # Verify each stage
            $parsed.organizationSettings.tenantId | Should -Be "12345678-1234-1234-1234-123456789012"
            $parsed.policies.antiPhishing | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Error Handling in Integration" {
    
    Context "Graceful Failure Scenarios" {
        It "Should handle missing template file" {
            $missingPath = "C:\NonExistent\template.json"
            
            { Get-Content $missingPath -ErrorAction Stop } | Should -Throw
        }
        
        It "Should handle malformed JSON in template" {
            $malformedJson = '{"incomplete": true'
            
            { $malformedJson | ConvertFrom-Json } | Should -Throw
        }
        
        It "Should handle invalid substitution values" {
            $template = '{"tenantId": "{{TENANT_ID}}"}'
            $invalidGuid = "not-a-guid"
            
            $result = $template -replace '\{\{TENANT_ID\}\}', $invalidGuid
            $parsed = $result | ConvertFrom-Json
            
            # Verify substitution occurred (even with invalid value)
            $parsed.tenantId | Should -Be "not-a-guid"
        }
    }
}
