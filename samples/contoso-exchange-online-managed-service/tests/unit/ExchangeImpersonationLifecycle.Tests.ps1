#requires -Version 7.0

BeforeAll {
    $script:adapterRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:adapterCommand = Join-Path $script:adapterRoot 'scripts/Invoke-ExchangeOnlineChange.ps1'
    Import-Module (Join-Path $script:adapterRoot 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking
    . (Join-Path $PSScriptRoot '../helpers/ApprovedAdapterDoubles.ps1')

    $script:adapterKey = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Offline Adapter',
        $script:adapterKey,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $script:adapterCertificate = $request.CreateSelfSigned(
        [datetimeoffset]::UtcNow.AddMinutes(-1),
        [datetimeoffset]::UtcNow.AddDays(1)
    )

    function Set-ImpersonationConfiguration {
        param($Arguments, [object[]]$ApprovedExceptions = @())

        $configuration = Get-Content $Arguments.ConfigurationPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $configuration.controls['MDO-009'].approvedExceptions = @($ApprovedExceptions)
        $configuration | ConvertTo-Json -Depth 60 | Set-Content $Arguments.ConfigurationPath
    }

    function Set-ImpersonationEntitlement {
        param($Arguments, [switch]$RemoveProtectedRecipientPlan)

        $parameters = Get-Content $Arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        if ($RemoveProtectedRecipientPlan) {
            $protectedRecipient = @($parameters.entitlement.recipients | Where-Object address -EQ $parameters.SECURITY_OPERATIONS_MAILBOX)[0]
            $protectedRecipient.servicePlans = @('EXCHANGE_S_ENTERPRISE')
        }
        $parameters | ConvertTo-Json -Depth 30 | Set-Content $Arguments.ParameterPath
    }

    function Approve-ImpersonationFixture {
        param($Arguments)

        & $script:adapterCommand -Stage Preview @Arguments -Scope Impersonation -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
    }

    function New-CustomImpersonationRule {
        param(
            [string]$Policy = 'Contoso Impersonation Protection',
            [string]$State = 'Enabled',
            [string[]]$RecipientDomainIs = @('contoso.example')
        )

        @{
            Identity = 'Contoso Impersonation Protection Rule'
            Name = 'Contoso Impersonation Protection Rule'
            State = $State
            AntiPhishPolicy = $Policy
            Priority = 0
            RecipientDomainIs = @($RecipientDomainIs)
            SentTo = @()
            SentToMemberOf = @()
            ExceptIfSentTo = @()
            ExceptIfSentToMemberOf = @()
            ExceptIfRecipientDomainIs = @()
        }
    }
}

Describe 'EXR-010-A06 effective impersonation lifecycle' {
    BeforeEach {
        Initialize-AdapterDoubles
        $global:adapterState.AntiPhishRule = @(New-CustomImpersonationRule)
        function global:Get-AntiPhishRule {
            [CmdletBinding()]
            param([string]$Identity)

            foreach ($rule in @($global:adapterState.AntiPhishRule)) {
                if ([string]::IsNullOrWhiteSpace($Identity) -or $rule.Identity -eq $Identity) {
                    [pscustomobject]$rule.Clone()
                }
            }
        }
        $global:adapterCommands.Add('Get-AntiPhishRule')

        Mock Test-BaselineDetachedCmsSignature -ModuleName ExchangeOnlineBaseline.Common {
            param($CanonicalBytes, $Signature)
            $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($CanonicalBytes), $true)
            $cms.Decode([Convert]::FromBase64String($Signature.Value))
            $cms.CheckSignature($true)
            @{
                Verified = $true
                SignerSubject = $cms.SignerInfos[0].Certificate.Subject
                SigningTimeUtc = [datetimeoffset]::UtcNow
                CertificateNotBeforeUtc = [datetimeoffset]::UtcNow.AddDays(-1)
                CertificateNotAfterUtc = [datetimeoffset]::UtcNow.AddDays(1)
                ChainTrusted = $true
                RevocationStatus = 'Good'
            }
        }
    }

    It 'refuses impersonation targets on a shadowed policy before writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Impersonation
        Approve-ImpersonationFixture -Arguments $arguments
        $global:adapterState.ATPProtectionPolicyRule[0].State = 'Enabled'
        $global:adapterState.ATPProtectionPolicyRule[0].RecipientDomainIs = @('contoso.example')

        # Act
        $invoke = { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ImpersonationPolicyShadowed*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses a missing or misbound impersonation rule before writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Impersonation
        Approve-ImpersonationFixture -Arguments $arguments
        $global:adapterState.AntiPhishRule = @(New-CustomImpersonationRule -Policy 'Unapproved AntiPhish Policy')

        # Act
        $invoke = { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ImpersonationRuleBindingInvalid*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses broad or expired impersonation exceptions before writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Impersonation
        Set-ImpersonationConfiguration -Arguments $arguments -ApprovedExceptions @(
            @{
                exceptionType = 'TrustedDomain'
                value = 'example'
                owner = 'Security Operations'
                ticket = 'SEC-EXPIRED'
                expiresOn = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o')
            }
        )

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope Impersonation -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ImpersonationExceptionInvalid*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses unlicensed impersonation recipients before writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Impersonation
        Set-ImpersonationEntitlement -Arguments $arguments -RemoveProtectedRecipientPlan

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope Impersonation -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ImpersonationRecipientNotEntitled*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'round trips effective impersonation targets on the protecting policy' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Impersonation
        $before = Get-AdapterSnapshot

        # Act
        $result = Invoke-AdapterRoundTrip -Arguments $arguments -Scope Impersonation

        # Assert
        $result.Status | Should -BeExactly 'Succeeded'
        (Get-AdapterSnapshot) | Should -BeExactly $before
        $result.RepeatedStatus | Should -BeExactly 'Succeeded'
        $result.RepeatedWrites | Should -Be 0
        @($global:adapterCalls | Where-Object { $_.Command -eq 'Set-AntiPhishPolicy' -and $_.Parameters.Identity -eq 'Contoso Impersonation Protection' }).Count | Should -BeGreaterThan 0
        @($global:adapterCalls | Where-Object { $_.Command -match 'ProtectionPolicy' }).Count | Should -Be 0
    }
}

AfterAll {
    foreach ($name in @($global:adapterCommands) + @('Get-ConnectionInformation','Invoke-OfflineAdapterCommand')) {
        Remove-Item "Function:global:$name" -ErrorAction SilentlyContinue
    }
    $script:adapterCertificate.Dispose()
    $script:adapterKey.Dispose()
    Get-Variable -Name 'adapter*' -Scope Global | Remove-Variable -Scope Global
    Remove-Module ExchangeOnlineBaseline.Common -Force -ErrorAction SilentlyContinue
}