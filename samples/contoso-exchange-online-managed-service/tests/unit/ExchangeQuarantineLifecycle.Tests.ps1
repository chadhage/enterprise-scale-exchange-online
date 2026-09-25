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

    function Set-QuarantineConfiguration {
        param($Arguments, [scriptblock]$Configure)

        $configuration = Get-Content $Arguments.ConfigurationPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        & $Configure $configuration.controls['MDO-008']
        $configuration | ConvertTo-Json -Depth 60 | Set-Content $Arguments.ConfigurationPath
    }

    function Add-ManagedQuarantinePolicies {
        $global:adapterState.HostedContentFilterPolicy += @{
            Identity = 'Standard Preset Security Policy'
            HighConfidencePhishQuarantineTag = 'AdminOnlyAccessPolicy'
            PhishQuarantineTag = 'DefaultFullAccessPolicy'
            HighConfidenceSpamQuarantineTag = 'DefaultFullAccessPolicy'
            SpamQuarantineTag = 'DefaultFullAccessPolicy'
            BulkQuarantineTag = 'DefaultFullAccessPolicy'
            SpoofQuarantineTag = 'DefaultFullAccessPolicy'
        }
        $global:adapterState.MalwareFilterPolicy += @{
            Identity = 'Built-In Protection Policy'
            QuarantineTag = 'AdminOnlyAccessPolicy'
        }
        $global:adapterState.AntiPhishPolicy += @{
            Identity = 'Strict Preset Security Policy'
            SpoofQuarantineTag = 'DefaultFullAccessPolicy'
        }
    }

    function Invoke-QuarantineLifecycle {
        param($Arguments)

        Add-ManagedQuarantinePolicies
        $managedBefore = ConvertTo-CanonicalJson @{
            Content = @($global:adapterState.HostedContentFilterPolicy | Where-Object Identity -CEQ 'Standard Preset Security Policy')
            Malware = @($global:adapterState.MalwareFilterPolicy | Where-Object Identity -CEQ 'Built-In Protection Policy')
            Phish = @($global:adapterState.AntiPhishPolicy | Where-Object Identity -CEQ 'Strict Preset Security Policy')
        }
        $before = Get-AdapterSnapshot
        & $script:adapterCommand -Stage Preview @Arguments -Scope Quarantine -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:adapterCommand -Stage Apply @Arguments -Apply -Confirm:$false
        $writesAfterApply = $global:adapterCalls.Count

        $repeatArguments = New-StatefulAdapterFixture -Scope Quarantine
        $repeatArguments.ChangeId = 'ADAPTER004-REPEAT'
        $repeatArguments.PreviewPath = Join-Path $repeatArguments.ArtifactRoot 'preview-ADAPTER004-REPEAT.json'
        $repeatArguments.ApprovalPath = Join-Path $repeatArguments.ArtifactRoot 'approval-ADAPTER004-REPEAT.json'
        & $script:adapterCommand -Stage Preview @repeatArguments -Scope Quarantine -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Approve @repeatArguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Validate @repeatArguments | Out-Null
        $repeat = & $script:adapterCommand -Stage Apply @repeatArguments -Apply -Confirm:$false
        $repeatWrites = $global:adapterCalls.Count - $writesAfterApply

        $global:adapterState.QuarantinePolicy[0].EndUserQuarantinePermissionsValue = 106
        $writesBeforeDrift = $global:adapterCalls.Count
        $drift = $null
        try { & $script:adapterCommand -Stage Rollback @Arguments -Apply -Confirm:$false | Out-Null } catch { $drift = $_ }
        $driftWrites = $global:adapterCalls.Count - $writesBeforeDrift
        $global:adapterState.QuarantinePolicy[0].EndUserQuarantinePermissionsValue = 0

        $rollback = & $script:adapterCommand -Stage Rollback @Arguments -Apply -Confirm:$false
        $managedAfter = ConvertTo-CanonicalJson @{
            Content = @($global:adapterState.HostedContentFilterPolicy | Where-Object Identity -CEQ 'Standard Preset Security Policy')
            Malware = @($global:adapterState.MalwareFilterPolicy | Where-Object Identity -CEQ 'Built-In Protection Policy')
            Phish = @($global:adapterState.AntiPhishPolicy | Where-Object Identity -CEQ 'Strict Preset Security Policy')
        }

        [pscustomobject]@{
            ApplyStatus = $apply.Status
            RepeatStatus = $repeat.Status
            RepeatWrites = $repeatWrites
            DriftMessage = $drift.Exception.Message
            DriftWrites = $driftWrites
            RollbackStatus = $rollback.Status
            RestoredSnapshot = Get-AdapterSnapshot
            BeforeSnapshot = $before
            ManagedBefore = $managedBefore
            ManagedAfter = $managedAfter
            ManagedWrites = @($global:adapterCalls | Where-Object { $_.Parameters.Identity -in @('Standard Preset Security Policy','Strict Preset Security Policy','Built-In Protection Policy') }).Count
        }
    }
}

Describe 'EXR-010-A07 approved quarantine permission lifecycle' {
    BeforeEach {
        Initialize-AdapterDoubles
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

    It 'refuses a Microsoft-managed preset or built-in quarantine target before writes' {
        # Arrange
        Add-ManagedQuarantinePolicies
        $arguments = New-StatefulAdapterFixture -Scope Quarantine
        & $script:adapterCommand -Stage Preview @arguments -Scope Quarantine -Confirm:$false | Out-Null
        $preview = Get-Content $arguments.PreviewPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $managedOperation = @($preview.Operation | Where-Object OperationId -CLike 'QuarantineContent-*')[0]
        $managedOperation.Identity = ConvertTo-CanonicalJson @{ Identity = 'Standard Preset Security Policy' }
        $preview | ConvertTo-Json -Depth 40 | Set-Content $arguments.PreviewPath

        # Act
        $invoke = { & $script:adapterCommand -Stage Approve @arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false }

        # Assert
        $invoke | Should -Throw 'QuarantineManagedPolicyMutationUnsupported: Microsoft-managed quarantine policies cannot be changed.'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses excessive end-user permission on a high-risk category before writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Quarantine
        Set-QuarantineConfiguration $arguments {
            param($settings)
            @($settings.categoryPermissions | Where-Object category -CEQ 'Malware')[0].accessLevel = 'FullAccess'
        }

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope Quarantine -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*QuarantineHighRiskPermissionExcessive*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses a conflicting message-category and quarantine-tag binding before writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Quarantine
        Set-QuarantineConfiguration $arguments {
            param($settings)
            $settings.categoryPermissions += @{ category = 'Phish'; accessLevel = 'AdminOnlyAccess' }
        }

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope Quarantine -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*QuarantineCategoryBindingInvalid*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses a local custom permission deviation without exact approved mapping or exception before writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Quarantine
        Set-QuarantineConfiguration $arguments {
            param($settings)
            $settings.endUserAccessLevel = 'LimitedAccess'
        }

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope Quarantine -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*QuarantineCustomDeviationUnapproved*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'round trips the approved local custom-policy permission mapping without managed-policy mutation' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Quarantine

        # Act
        $result = Invoke-QuarantineLifecycle -Arguments $arguments

        # Assert
        $result.ApplyStatus | Should -BeExactly 'Succeeded'
        $result.RepeatStatus | Should -BeExactly 'Succeeded'
        $result.RepeatWrites | Should -Be 0
        $result.DriftMessage | Should -BeLike '*ChangeStateDrift*'
        $result.DriftWrites | Should -Be 0
        $result.RollbackStatus | Should -BeExactly 'Succeeded'
        $result.RestoredSnapshot | Should -BeExactly $result.BeforeSnapshot
        $result.ManagedAfter | Should -BeExactly $result.ManagedBefore
        $result.ManagedWrites | Should -Be 0
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