BeforeAll {
    $script:root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:readiness = Join-Path $script:root 'scripts/Test-ExchangeOnlineChangeReadiness.ps1'
    $script:tenant = '11111111-2222-3333-4444-555555555555'

    function global:Get-ConnectionInformation { @($global:readinessConnections) }
    function global:Get-TransportConfig { [pscustomobject]@{ SmtpClientAuthenticationDisabled = $true } }

    function Get-ReadinessArgument {
        param([switch]$Unverified, [string]$RequesterIsOnlySigner)
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory $directory
        $parameters = Get-Content (Join-Path $script:root 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
        if (-not $Unverified) {
            $parameters.MICROSOFT_ENTRA_TENANT_GUID = $script:tenant
            $parameters.domainInventory.tenantId = $script:tenant
            $parameters.entitlement.tenantId = $script:tenant
            $parameters.entitlement.verified = $true
            $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
            $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE')
            $parameters.entitlement.recipients = @(@{ address = 'user@contoso.example'; servicePlans = @('EXCHANGE_S_ENTERPRISE') })
        }
        $parameterPath = Join-Path $directory 'parameters.json'
        $parameters | ConvertTo-Json -Depth 20 | Set-Content $parameterPath
        $signerIdentity = if ($RequesterIsOnlySigner) { $RequesterIsOnlySigner } else { 'approver@contoso.example' }
        $signerPath = Join-Path $directory 'signers.json'
        @(@{ Identity = $signerIdentity; Subject = 'CN=Approver'; Authority = 'ExchangeOnlineChangeApproval' }) | ConvertTo-Json -AsArray | Set-Content $signerPath
        @{
            ParameterPath            = $parameterPath
            ArtifactRoot             = Join-Path $directory 'artifacts'
            ChangeId                 = 'CHG-1001'
            RequestedBy              = 'requester@contoso.example'
            AuthorizedSignerPath     = $signerPath
            Scope                    = @('Transport')
            MinimumPowerShellVersion = '7.0'
            MinimumModuleVersion     = '0.0'
            ConfirmSession           = $false
            NonInteractive           = $true
            InformationAction        = 'Ignore'
            PassThru                 = $true
        }
    }

    function Get-FailedCheck {
        param($Result)
        @($Result.Results | Where-Object Status -eq 'FAIL' | ForEach-Object Check)
    }
}

Describe 'Test-ExchangeOnlineChangeReadiness' {
    BeforeEach {
        Mock Get-Module -ParameterFilter { $ListAvailable } -MockWith { [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.0' } }
        $global:readinessConnections = @([pscustomobject]@{ TenantID = $script:tenant; State = 'Connected'; UserPrincipalName = 'admin@contoso.example'; ConnectionUri = 'https://outlook.office365.com' })
    }

    AfterAll {
        Remove-Item Function:\Get-ConnectionInformation, Function:\Get-TransportConfig, Variable:\readinessConnections -ErrorAction SilentlyContinue
    }

    It 'refuses the unmodified synthetic sample with tenant and licensing fixes' {
        # Arrange
        $arguments = Get-ReadinessArgument -Unverified

        # Act
        $result = & $script:readiness @arguments

        # Assert
        $LASTEXITCODE | Should -Be 1
        $result.Ready | Should -BeFalse
        Get-FailedCheck $result | Should -Contain 'Tenant ID is real'
        Get-FailedCheck $result | Should -Contain 'Licensing entitlement verified'
        $result.Results.Where({ $_.Check -eq 'Licensing entitlement verified' }).Fix | Should -Match 'Never set verified yourself'
    }

    It 'refuses an unsupported or duplicate scope' {
        # Arrange
        $arguments = Get-ReadinessArgument
        $arguments.Scope = @('Transport', 'Transport')

        # Act
        $result = & $script:readiness @arguments

        # Assert
        $LASTEXITCODE | Should -Be 1
        Get-FailedCheck $result | Should -Contain 'Scope is supported'
    }

    It 'refuses when the requester is the only authorized signer' {
        # Arrange
        $arguments = Get-ReadinessArgument -RequesterIsOnlySigner 'requester@contoso.example'

        # Act
        $result = & $script:readiness @arguments

        # Assert
        Get-FailedCheck $result | Should -Contain 'Authorized signer metadata'
        $result.Results.Where({ $_.Check -eq 'Authorized signer metadata' }).Detail | Should -Be 'every authorized signer is the requester'
    }

    It 'refuses duplicate authorized signer entries after case-insensitive normalization' {
        # Arrange
        $arguments = Get-ReadinessArgument
        $signers = @(Get-Content -LiteralPath $arguments.AuthorizedSignerPath -Raw | ConvertFrom-Json -AsHashtable)
        $signers += @{ Identity = ' APPROVER@CONTOSO.EXAMPLE '; Subject = ' cn=approver '; Authority = 'ExchangeOnlineChangeApproval' }
        $signers | ConvertTo-Json -AsArray | Set-Content -LiteralPath $arguments.AuthorizedSignerPath
        # Act
        $result = & $script:readiness @arguments
        # Assert
        Get-FailedCheck $result | Should -Contain 'Authorized signer metadata'
        $result.Results.Where({ $_.Check -eq 'Authorized signer metadata' }).Detail |
            Should -Be 'duplicate authorized signer entries after case-insensitive normalization'
    }

    It 'refuses a parameter file stored inside the kit' {
        # Arrange
        $arguments = Get-ReadinessArgument
        $arguments.ParameterPath = Join-Path $script:root 'config/parameters.exchange-only.sample.json'

        # Act
        $result = & $script:readiness @arguments

        # Assert
        Get-FailedCheck $result | Should -Contain 'Parameter file location'
    }

    It 'refuses a change ID that already has a preview' {
        # Arrange
        $arguments = Get-ReadinessArgument
        $null = New-Item -ItemType Directory $arguments.ArtifactRoot
        Set-Content -LiteralPath (Join-Path $arguments.ArtifactRoot 'preview-CHG-1001.json') -Value '{}'

        # Act
        $result = & $script:readiness @arguments

        # Assert
        Get-FailedCheck $result | Should -Contain 'Artifact folder'
    }

    It 'refuses a session connected to a different tenant' {
        # Arrange
        $arguments = Get-ReadinessArgument
        $global:readinessConnections[0].TenantID = '99999999-2222-3333-4444-555555555555'

        # Act
        $result = & $script:readiness @arguments

        # Assert
        Get-FailedCheck $result | Should -Contain 'Session tenant matches parameters'
        $result.Results.Where({ $_.Check -eq 'Session tenant matches parameters' }).Fix | Should -Match 'Connect-ExchangeOnline'
    }

    It 'refuses when no Exchange Online session is connected' {
        # Arrange
        $arguments = Get-ReadinessArgument
        $global:readinessConnections = @()

        # Act
        $result = & $script:readiness @arguments

        # Assert
        Get-FailedCheck $result | Should -Contain 'Exactly one Exchange Online session'
        $check = $result.Results.Where({ $_.Check -eq 'Exactly one Exchange Online session' })
        $check.Detail | Should -Match '^ExchangeSessionMissing'
        $check.Fix | Should -Match 'Connect-ExchangeOnline'
        $check.Fix | Should -Match 'UseDeviceCode'
    }

    It 'refuses to reuse an unconfirmed session when it cannot prompt' {
        # Arrange
        $arguments = Get-ReadinessArgument
        $arguments.ConfirmSession = $true

        # Act
        $result = & $script:readiness @arguments

        # Assert
        $LASTEXITCODE | Should -Be 1
        $check = $result.Results.Where({ $_.Check -eq 'Exactly one Exchange Online session' })
        $check.Status | Should -Be 'FAIL'
        $check.Detail | Should -Match 'ExchangeSessionConfirmationRequired'
        $check.Detail | Should -Match ([regex]::Escape('-ConfirmSession:$false'))
    }

    It 'refuses a session signed in as a different account than requested' {
        # Arrange
        $arguments = Get-ReadinessArgument
        $arguments.UserPrincipalName = 'other.admin@contoso.example'

        # Act
        $result = & $script:readiness @arguments

        # Assert
        $check = $result.Results.Where({ $_.Check -eq 'Exactly one Exchange Online session' })
        $check.Status | Should -Be 'FAIL'
        $check.Detail | Should -Match 'ExchangeSessionWrongAccount'
        $check.Fix | Should -Match ([regex]::Escape("-UserPrincipalName 'other.admin@contoso.example'"))
    }

    It 'refuses a role that does not expose the scope read cmdlet' {
        # Arrange
        $arguments = Get-ReadinessArgument
        $arguments.Scope = @('Dkim')
        $parameters = Get-Content -LiteralPath $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable
        $parameters.workflowOptions = @{ enableDkim = $true }
        $parameters | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $arguments.ParameterPath
        Mock Get-Command -ParameterFilter { $Name -eq 'Get-DkimSigningConfig' } -MockWith { $null }

        # Act
        $result = & $script:readiness @arguments

        # Assert
        Get-FailedCheck $result | Should -Contain 'Role grants Get-DkimSigningConfig for Dkim'
    }

    It 'reports a preset rule read failure as a role problem, not as uninitialized presets' {
        # Arrange
        $arguments = Get-ReadinessArgument
        $arguments.Scope = @('EopPresets')
        function global:Get-EOPProtectionPolicyRule { throw 'Access denied for Get-EOPProtectionPolicyRule' }
        try {
            # Act
            $result = & $script:readiness @arguments
        }
        finally { Remove-Item Function:\Get-EOPProtectionPolicyRule -ErrorAction SilentlyContinue }

        # Assert
        $check = @($result.Results | Where-Object Check -EQ 'EopPresets rules initialized')
        $check.Count | Should -Be 1
        $check[0].Status | Should -Be 'FAIL'
        $check[0].Detail | Should -Match 'could not read preset rules: Access denied'
        $check[0].Fix | Should -Match 'Exchange role'
    }

    It 'refuses a parameter file that still contains REPLACE- placeholders from the microsite templates' {
        # Arrange
        $arguments = Get-ReadinessArgument
        $parameters = Get-Content -LiteralPath $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable
        $parameters.workflowOptions = @{ tenantAllowBlockEntries = @(@{ owner = 'REPLACE-owner@contoso.com' }) }
        $parameters | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $arguments.ParameterPath
        $arguments.Scope = @('TenantAllowBlockList')
        $arguments.SkipTenantConnection = $true

        # Act
        $result = & $script:readiness @arguments

        # Assert
        $LASTEXITCODE | Should -Be 1
        Get-FailedCheck $result | Should -Contain 'No REPLACE- placeholders remain'
        $result.Results.Where({ $_.Check -eq 'No REPLACE- placeholders remain' }).Detail | Should -Match 'workflowOptions'
    }

    It 'refuses a scope whose required workflowOptions section is missing' {
        # Arrange
        $arguments = Get-ReadinessArgument
        $arguments.Scope = @('SendAs')
        $arguments.SkipTenantConnection = $true

        # Act
        $result = & $script:readiness @arguments

        # Assert
        $LASTEXITCODE | Should -Be 1
        Get-FailedCheck $result | Should -Contain 'Required workflowOptions present'
        $result.Results.Where({ $_.Check -eq 'Required workflowOptions present' }).Detail | Should -Match 'sendAsDelegations'
    }

    It 'refuses governance scopes that use the shipped configuration template' {
        # Arrange
        $arguments = Get-ReadinessArgument
        $arguments.Scope = @('GovernanceMrm')
        $arguments.SkipTenantConnection = $true

        # Act
        $result = & $script:readiness @arguments

        # Assert
        $LASTEXITCODE | Should -Be 1
        Get-FailedCheck $result | Should -Contain 'Governance uses an approved configuration copy'
    }

    It 'reports ready and prints the exact change block and Preview command' {
        # Arrange
        $arguments = Get-ReadinessArgument

        # Act
        $result = & $script:readiness @arguments

        # Assert
        $LASTEXITCODE | Should -Be 0
        Get-FailedCheck $result | Should -BeNullOrEmpty
        $result.Ready | Should -BeTrue
        $result.ChangeBlock | Should -Match ([regex]::Escape("ParameterPath        = '$($arguments.ParameterPath)'"))
        $result.ChangeBlock | Should -Match ([regex]::Escape("PreviewPath          = '$(Join-Path $arguments.ArtifactRoot 'preview-CHG-1001.json')'"))
        $result.ChangeBlock | Should -Match ([regex]::Escape("ConfigurationPath    = './config/exchange-only.v1.json'"))
        $result.PreviewCommand | Should -BeExactly "./scripts/Invoke-ExchangeOnlineChange.ps1 -Stage Preview @change -Scope 'Transport' -Confirm:`$false"
        $result.Results.Where({ $_.Check -eq 'Exactly one Exchange Online session' }).Detail | Should -Be "admin@contoso.example in tenant $($script:tenant)"
        Test-Path -LiteralPath $arguments.ArtifactRoot | Should -BeFalse
    }
}
