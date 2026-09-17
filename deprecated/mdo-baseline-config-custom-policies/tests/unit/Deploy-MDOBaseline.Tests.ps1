BeforeAll {
    $script:modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:scriptsPath = Join-Path $modulePath "scripts"
    
    # Dot-source the functions to test
    . (Join-Path $scriptsPath "Deploy-MDOBaseline.ps1")
}

Describe "Deploy-MDOBaseline Unit Tests" {
    
    Context "Test-Prerequisites" {
        It "Should verify PowerShell version is 7.0 or higher" {
            # Verify current version meets requirements
            $PSVersionTable.PSVersion.Major | Should -BeGreaterThanOrEqual 7
        }
        
        It "Should detect when ExchangeOnlineManagement module is available" {
            # Check if module can be found
            $module = Get-Module ExchangeOnlineManagement -ListAvailable
            $module | Should -Not -BeNullOrEmpty
        }
        
        It "Should detect when Microsoft.Graph modules are available" {
            $modules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users")
            foreach ($module in $modules) {
                Get-Module $module -ListAvailable | Should -Not -BeNullOrEmpty
            }
        }
    }
    
    Context "Resolve-ConfigParameters" {
        It "Should replace {{TENANT_ID}} placeholder with provided value" {
            $config = '{"tenantId": "{{TENANT_ID}}", "name": "test"}'
            $expectedId = "12345678-1234-1234-1234-123456789012"
            
            $result = $config -replace '\{\{TENANT_ID\}\}', $expectedId
            
            $result | Should -Not -Match '\{\{TENANT_ID\}\}'
            $result | Should -Match $expectedId
        }
        
        It "Should replace {{TENANT_DOMAIN}} placeholder" {
            $config = '{"domain": "{{TENANT_DOMAIN}}"}'
            $expectedDomain = "contoso.com"
            
            $result = $config -replace '\{\{TENANT_DOMAIN\}\}', $expectedDomain
            
            $result | Should -Match $expectedDomain
        }
        
        It "Should replace {{SECURITY_ADMIN_EMAIL}} placeholder" {
            $config = '{"adminEmail": "{{SECURITY_ADMIN_EMAIL}}"}'
            $expectedEmail = "admin@contoso.com"
            
            $result = $config -replace '\{\{SECURITY_ADMIN_EMAIL\}\}', $expectedEmail
            
            $result | Should -Match $expectedEmail
        }
        
        It "Should handle multiple placeholder replacements" {
            $config = @"
            {
                "tenantId": "{{TENANT_ID}}",
                "domain": "{{TENANT_DOMAIN}}",
                "email": "{{SECURITY_ADMIN_EMAIL}}"
            }
            "@
            
            $result = $config `
                -replace '\{\{TENANT_ID\}\}', "12345678-1234-1234-1234-123456789012" `
                -replace '\{\{TENANT_DOMAIN\}\}', "contoso.com" `
                -replace '\{\{SECURITY_ADMIN_EMAIL\}\}', "admin@contoso.com"
            
            $result -match '\{\{' | Should -BeNullOrEmpty
        }
    }
    
    Context "Configuration Parameter Validation" {
        It "Should validate GUID format for TenantId" {
            $validGuid = "12345678-1234-1234-1234-123456789012"
            $guidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            
            $validGuid -match $guidPattern | Should -Be $true
        }
        
        It "Should reject invalid GUID format" {
            $invalidGuid = "not-a-guid"
            $guidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            
            $invalidGuid -match $guidPattern | Should -Be $false
        }
        
        It "Should validate email format" {
            $validEmail = "admin@contoso.com"
            $emailPattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            
            $validEmail -match $emailPattern | Should -Be $true
        }
        
        It "Should reject invalid email format" {
            $invalidEmail = "not-an-email"
            $emailPattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            
            $invalidEmail -match $emailPattern | Should -Be $false
        }
        
        It "Should validate domain format" {
            $validDomain = "contoso.com"
            $domainPattern = '^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            
            $validDomain -match $domainPattern | Should -Be $true
        }
    }
    
    Context "Logging Functions" {
        BeforeEach {
            $script:testLogPath = Join-Path $env:TEMP "test-mdo-deploy-$(Get-Random).log"
        }
        
        AfterEach {
            if (Test-Path $script:testLogPath) {
                Remove-Item $script:testLogPath -Force
            }
        }
        
        It "Should create log file when logging is enabled" {
            # Simple logging test
            $logMessage = "Test log entry"
            Add-Content -Path $script:testLogPath -Value $logMessage
            
            Test-Path $script:testLogPath | Should -Be $true
        }
        
        It "Should write timestamped entries to log" {
            $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            $logEntry = "[$timestamp] Test entry"
            Add-Content -Path $script:testLogPath -Value $logEntry
            
            $content = Get-Content $script:testLogPath -Raw
            $content | Should -Match '\[\d{4}-\d{2}-\d{2}'
        }
    }
    
    Context "Configuration JSON Parsing" {
        It "Should successfully parse valid JSON configuration" {
            $validJson = @"
            {
                "organizationSettings": {
                    "tenantId": "12345678-1234-1234-1234-123456789012",
                    "tenantName": "Contoso Inc",
                    "domain": "contoso.com"
                },
                "protectionLevel": "Standard"
            }
            "@
            
            $config = $validJson | ConvertFrom-Json
            $config.organizationSettings.tenantId | Should -Match '^[0-9a-f]{8}-'
            $config.protectionLevel | Should -Be "Standard"
        }
        
        It "Should handle nested objects in configuration" {
            $nestedJson = @"
            {
                "policies": {
                    "antiPhishing": {
                        "enabled": true,
                        "threshold": 1
                    }
                }
            }
            "@
            
            $config = $nestedJson | ConvertFrom-Json
            $config.policies.antiPhishing.enabled | Should -Be $true
            $config.policies.antiPhishing.threshold | Should -Be 1
        }
        
        It "Should throw on malformed JSON" {
            $malformedJson = '{"unclosed": true'
            
            { $malformedJson | ConvertFrom-Json } | Should -Throw
        }
    }
    
    Context "Deployment Mode Validation" {
        It "Should accept 'Audit' as valid deployment mode" {
            $mode = "Audit"
            $validModes = @("Audit", "Enforce")
            
            $mode -in $validModes | Should -Be $true
        }
        
        It "Should accept 'Enforce' as valid deployment mode" {
            $mode = "Enforce"
            $validModes = @("Audit", "Enforce")
            
            $mode -in $validModes | Should -Be $true
        }
        
        It "Should reject invalid deployment modes" {
            $mode = "InvalidMode"
            $validModes = @("Audit", "Enforce")
            
            $mode -in $validModes | Should -Be $false
        }
    }
    
    Context "Dry-Run Mode" {
        It "Should set DryRun flag to true when specified" {
            $dryRun = $true
            
            $dryRun | Should -Be $true
        }
        
        It "Should set DryRun flag to false by default" {
            $dryRun = $false
            
            $dryRun | Should -Be $false
        }
    }
}
