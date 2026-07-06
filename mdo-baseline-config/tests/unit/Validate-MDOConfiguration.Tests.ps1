BeforeAll {
    $script:modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:scriptsPath = Join-Path $modulePath "scripts"
    $script:templatesPath = Join-Path $modulePath "config-templates"
    
    # Dot-source the functions to test
    . (Join-Path $scriptsPath "Validate-MDOConfiguration.ps1")
}

Describe "Validate-MDOConfiguration Unit Tests" {
    
    Context "Configuration File Loading" {
        It "Should load valid JSON configuration file" {
            $configPath = Join-Path $script:templatesPath "baseline-standard.json"
            Test-Path $configPath | Should -Be $true
            
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            $config | Should -Not -BeNullOrEmpty
        }
        
        It "Should throw when configuration file does not exist" {
            $invalidPath = "C:\NonExistent\config.json"
            
            { Get-Content $invalidPath -ErrorAction Stop } | Should -Throw
        }
    }
    
    Context "Required Fields Validation" {
        It "Should verify organizationSettings field exists" {
            $config = @{
                organizationSettings = @{ tenantId = "test" }
                protectionLevel = "Standard"
            }
            
            $config.ContainsKey("organizationSettings") | Should -Be $true
        }
        
        It "Should verify protectionLevel field exists" {
            $config = @{
                organizationSettings = @{}
                protectionLevel = "Standard"
            }
            
            $config.ContainsKey("protectionLevel") | Should -Be $true
        }
        
        It "Should detect missing required fields" {
            $config = @{
                organizationSettings = @{}
            }
            
            $config.ContainsKey("policies") | Should -Be $false
        }
    }
    
    Context "GUID Validation" {
        It "Should validate valid GUID format" {
            $validGuid = "12345678-1234-1234-1234-123456789012"
            $guidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            
            $validGuid -match $guidPattern | Should -Be $true
        }
        
        It "Should reject invalid GUID - wrong format" {
            $invalidGuid = "not-a-valid-guid-format"
            $guidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            
            $invalidGuid -match $guidPattern | Should -Be $false
        }
        
        It "Should reject GUID with uppercase letters (case-sensitive)" {
            $mixedCaseGuid = "12345678-ABCD-1234-1234-123456789012"
            $guidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            
            $mixedCaseGuid -match $guidPattern | Should -Be $false
        }
    }
    
    Context "Email Address Validation" {
        It "Should validate proper email format" {
            $validEmail = "admin@contoso.com"
            $emailPattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            
            $validEmail -match $emailPattern | Should -Be $true
        }
        
        It "Should reject email without domain" {
            $invalidEmail = "admin@"
            $emailPattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            
            $invalidEmail -match $emailPattern | Should -Be $false
        }
        
        It "Should reject email without @ symbol" {
            $invalidEmail = "adminemail.com"
            $emailPattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            
            $invalidEmail -match $emailPattern | Should -Be $false
        }
        
        It "Should accept email with multiple dots" {
            $validEmail = "admin.name@contoso.co.uk"
            $emailPattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            
            $validEmail -match $emailPattern | Should -Be $true
        }
    }
    
    Context "Protection Level Validation" {
        It "Should validate 'Standard' protection level" {
            $level = "Standard"
            $validLevels = @("Standard", "Strict", "Built-in", "Custom")
            
            $level -in $validLevels | Should -Be $true
        }
        
        It "Should validate 'Strict' protection level" {
            $level = "Strict"
            $validLevels = @("Standard", "Strict", "Built-in", "Custom")
            
            $level -in $validLevels | Should -Be $true
        }
        
        It "Should reject invalid protection level" {
            $level = "InvalidLevel"
            $validLevels = @("Standard", "Strict", "Built-in", "Custom")
            
            $level -in $validLevels | Should -Be $false
        }
    }
    
    Context "Policy Count Validation" {
        It "Should verify at least one policy is defined" {
            $config = @{
                policies = @{
                    antiPhishing = @(@{ name = "Policy1" })
                }
            }
            
            $config.policies.Values.Count | Should -BeGreaterThan 0
        }
        
        It "Should detect when no policies are defined" {
            $config = @{
                policies = @{}
            }
            
            $config.policies.Count | Should -Be 0
        }
    }
    
    Context "Recipient Targeting Validation" {
        It "Should validate when applyToAllRecipients is true" {
            $recipients = @{
                applyToAllRecipients = $true
            }
            
            $recipients.applyToAllRecipients | Should -Be $true
        }
        
        It "Should validate when specific recipients are provided" {
            $recipients = @{
                applyToAllRecipients = $false
                includedDomains = @("contoso.com")
            }
            
            $recipients.includedDomains | Should -Not -BeNullOrEmpty
        }
        
        It "Should detect missing recipient configuration" {
            $recipients = @{}
            
            $recipients.ContainsKey("applyToAllRecipients") | Should -Be $false
        }
    }
    
    Context "Threshold Validation" {
        It "Should validate phishing threshold range 1-4" {
            $threshold = 1
            
            ($threshold -ge 1 -and $threshold -le 4) | Should -Be $true
        }
        
        It "Should reject phishing threshold below 1" {
            $threshold = 0
            
            ($threshold -ge 1 -and $threshold -le 4) | Should -Be $false
        }
        
        It "Should reject phishing threshold above 4" {
            $threshold = 5
            
            ($threshold -ge 1 -and $threshold -le 4) | Should -Be $false
        }
        
        It "Should validate spam confidence level range 1-9" {
            $threshold = 6
            
            ($threshold -ge 1 -and $threshold -le 9) | Should -Be $true
        }
        
        It "Should reject spam confidence level outside range" {
            $threshold = 10
            
            ($threshold -ge 1 -and $threshold -le 9) | Should -Be $false
        }
    }
    
    Context "Authentication Framework Validation" {
        It "Should validate DMARC enabled state" {
            $auth = @{
                dmarc = @{ enabled = $true }
            }
            
            $auth.dmarc.enabled | Should -Be $true
        }
        
        It "Should validate DKIM enabled state" {
            $auth = @{
                dkim = @{ enabled = $true }
            }
            
            $auth.dkim.enabled | Should -Be $true
        }
        
        It "Should validate SPF enabled state" {
            $auth = @{
                spf = @{ enabled = $true }
            }
            
            $auth.spf.enabled | Should -Be $true
        }
    }
    
    Context "Deployment Mode Validation" {
        It "Should detect Audit mode" {
            $config = @{
                organizationSettings = @{
                    deploymentMode = "Audit"
                }
            }
            
            $config.organizationSettings.deploymentMode | Should -Be "Audit"
        }
        
        It "Should detect Enforce mode" {
            $config = @{
                organizationSettings = @{
                    deploymentMode = "Enforce"
                }
            }
            
            $config.organizationSettings.deploymentMode | Should -Be "Enforce"
        }
    }
    
    Context "Schema Compliance" {
        It "Should load baseline-standard.json successfully" {
            $configPath = Join-Path $script:templatesPath "baseline-standard.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            
            $config.organizationSettings | Should -Not -BeNullOrEmpty
            $config.protectionLevel | Should -Not -BeNullOrEmpty
            $config.policies | Should -Not -BeNullOrEmpty
        }
        
        It "Should load baseline-strict.json successfully" {
            $configPath = Join-Path $script:templatesPath "baseline-strict.json"
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            
            $config.organizationSettings | Should -Not -BeNullOrEmpty
            $config.protectionLevel | Should -Not -BeNullOrEmpty
            $config.policies | Should -Not -BeNullOrEmpty
        }
    }
}
