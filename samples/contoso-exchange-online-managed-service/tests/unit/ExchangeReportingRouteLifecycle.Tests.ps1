#requires -Version 7.0

BeforeAll {
    $script:root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:adapterRoot = $script:root
    $script:changeCommand = Join-Path $script:root 'scripts/Invoke-ExchangeOnlineChange.ps1'
    Import-Module (Join-Path $script:root 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking
    . (Join-Path $PSScriptRoot '../helpers/ApprovedAdapterDoubles.ps1')
    . (Join-Path $PSScriptRoot '../helpers/ExchangeProtectionFixture.ps1')

    $script:signingKey = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Offline Adapter',
        $script:signingKey,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $script:signingCertificate = $request.CreateSelfSigned(
        [datetimeoffset]::UtcNow.AddMinutes(-1),
        [datetimeoffset]::UtcNow.AddDays(1)
    )

    function Initialize-ReportingRouteState {
        $mailbox = 'secops@contoso.example'
        $global:adapterState.Mailbox = @(@{
            Identity = $mailbox
            PrimarySmtpAddress = $mailbox
            RecipientTypeDetails = 'SharedMailbox'
            ForwardingAddress = $null
            ForwardingSmtpAddress = $null
            DeliverToMailboxAndForward = $false
        })
        $global:adapterState.ExoSecOpsOverrideRule = @(@{
            Identity = 'SecOpsRule'
            Policy = 'SecOpsOverridePolicy'
            Mode = 'Enforce'
        })
    }

    function New-ReportingRouteFixture {
        param([switch]$Approved, [string]$ChangeId = 'REPORTING-A10')

        $arguments = New-StatefulAdapterFixture -Scope @('ReportSubmission','SecOpsOverride')
        $arguments.ChangeId = $ChangeId
        $arguments.PreviewPath = Join-Path $arguments.ArtifactRoot "preview-$ChangeId.json"
        $arguments.ApprovalPath = Join-Path $arguments.ArtifactRoot "approval-$ChangeId.json"

        $configuration = Get-Content $arguments.ConfigurationPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $configuration.controls['MDO-006'].reportingMailbox = 'secops@contoso.example'
        $configuration.controls['MDO-006'].approval = @{
            reference = 'SYNTHETIC-A10'
            owner = 'security@contoso.example'
            expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
        }
        $configuration | ConvertTo-Json -Depth 60 | Set-Content $arguments.ConfigurationPath

        $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.SECURITY_OPERATIONS_MAILBOX = 'secops@contoso.example'
        $parameters.reportingEvidence = @{
            mailbox = 'secops@contoso.example'
            dlp = @{
                mailbox = 'secops@contoso.example'
                status = 'NotApplicable'
                approval = @{
                    reference = 'SYNTHETIC-DLP-A10'
                    owner = 'security@contoso.example'
                    expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
                }
            }
        }
        $parameters | ConvertTo-Json -Depth 30 | Set-Content $arguments.ParameterPath

        if ($Approved) {
            & $script:changeCommand -Stage Preview @arguments -Scope @('ReportSubmission','SecOpsOverride') -Confirm:$false | Out-Null
            & $script:changeCommand -Stage Approve @arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
        }
        $arguments
    }

    function Invoke-ReportingRoutePreview {
        param($Arguments)
        & $script:changeCommand -Stage Preview @Arguments -Scope @('ReportSubmission','SecOpsOverride') -Confirm:$false
    }

    function Get-ReportingRouteResult {
        $protectionRawFixture = New-ProtectionFixture
        $protectionRawFixture.Raw['Get-Mailbox'].ByIdentity['secops@contoso.example'] = @($global:adapterState.Mailbox | ForEach-Object { $_.Clone() })
        $protectionRawFixture.Raw['Get-ReportSubmissionPolicy'].Items = @($global:adapterState.ReportSubmissionPolicy | ForEach-Object { $_.Clone() })
        $protectionRawFixture.Raw['Get-ReportSubmissionRule'].Items = @($global:adapterState.ReportSubmissionRule | ForEach-Object { $_.Clone() })
        $protectionRawFixture.Raw['Get-SecOpsOverridePolicy'].Items = @($global:adapterState.SecOpsOverridePolicy | ForEach-Object { $_.Clone() })
        Invoke-ProtectionRawRegistry $protectionRawFixture (Get-Module ExchangeOnlineBaseline.Common) | Where-Object ControlId -CEQ 'MDO-006'
    }

    function Invoke-ReportingRouteLifecycle {
        param($Arguments)

        $before = Get-AdapterSnapshot
        Invoke-ReportingRoutePreview $Arguments | Out-Null
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
        & $script:changeCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:changeCommand -Stage Apply @Arguments -Apply -Confirm:$false
        $applied = Get-AdapterSnapshot
        $readback = Get-ReportingRouteResult
        $writesAfterApply = $global:adapterCalls.Count

        $repeatArguments = New-ReportingRouteFixture -ChangeId 'REPORTING-A10-REPEAT'
        Invoke-ReportingRoutePreview $repeatArguments | Out-Null
        & $script:changeCommand -Stage Approve @repeatArguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
        & $script:changeCommand -Stage Validate @repeatArguments | Out-Null
        $repeat = & $script:changeCommand -Stage Apply @repeatArguments -Apply -Confirm:$false
        $repeatWrites = $global:adapterCalls.Count - $writesAfterApply

        $rollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false
        $writesAfterRollback = $global:adapterCalls.Count
        $repeatedRollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false

        [pscustomobject]@{
            Apply = $apply
            Applied = $applied
            Readback = $readback
            Repeat = $repeat
            RepeatWrites = $repeatWrites
            Rollback = $rollback
            Restored = Get-AdapterSnapshot
            Before = $before
            RepeatedRollback = $repeatedRollback
            RepeatedRollbackWrites = $global:adapterCalls.Count - $writesAfterRollback
        }
    }
}

Describe 'EXR-010-A10 approved reporting route lifecycle' {
    BeforeEach {
        Initialize-AdapterDoubles
        Initialize-ReportingRouteState
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

    It 'refuses an absent reporting mailbox prerequisite before writes' {
        # Arrange
        $arguments = New-ReportingRouteFixture
        $global:adapterState.Mailbox = @()

        # Act
        $invoke = { Invoke-ReportingRoutePreview $arguments }

        # Assert
        $invoke | Should -Throw '*ChangeReportingPrerequisite*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-REPORTING-A10.json') | Should -BeFalse
    }

    It 'refuses an absent DLP-owner prerequisite before writes' {
        # Arrange
        $arguments = New-ReportingRouteFixture
        $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.reportingEvidence.Remove('dlp')
        $parameters | ConvertTo-Json -Depth 30 | Set-Content $arguments.ParameterPath

        # Act
        $invoke = { Invoke-ReportingRoutePreview $arguments }

        # Assert
        $invoke | Should -Throw '*ChangeReportingPrerequisite*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-REPORTING-A10.json') | Should -BeFalse
    }

    It 'refuses a broad non-mailbox reporting target before writes' {
        # Arrange
        $arguments = New-ReportingRouteFixture
        $global:adapterState.Mailbox[0].RecipientTypeDetails = 'MailUniversalDistributionGroup'

        # Act
        $invoke = { Invoke-ReportingRoutePreview $arguments }

        # Assert
        $invoke | Should -Throw '*ChangeReportingPrerequisite*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-REPORTING-A10.json') | Should -BeFalse
    }

    It 'refuses a reporting mailbox resolved to the wrong address before writes' {
        # Arrange
        $arguments = New-ReportingRouteFixture
        $global:adapterState.Mailbox[0].PrimarySmtpAddress = 'other@contoso.example'

        # Act
        $invoke = { Invoke-ReportingRoutePreview $arguments }

        # Assert
        $invoke | Should -Throw '*ChangeReportingPrerequisite*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-REPORTING-A10.json') | Should -BeFalse
    }

    It 'refuses a missing portal-initialized reporting object before writes' {
        # Arrange
        $arguments = New-ReportingRouteFixture
        $global:adapterState.ReportSubmissionPolicy = @()

        # Act
        $invoke = { Invoke-ReportingRoutePreview $arguments }

        # Assert
        $invoke | Should -Throw '*ChangeReportingPrerequisite*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-REPORTING-A10.json') | Should -BeFalse
    }

    It 'refuses a reporting rule bound to the wrong portal-initialized policy before writes' {
        # Arrange
        $arguments = New-ReportingRouteFixture
        $global:adapterState.ReportSubmissionRule[0].ReportSubmissionPolicy = 'OtherReportSubmissionPolicy'

        # Act
        $invoke = { Invoke-ReportingRoutePreview $arguments }

        # Assert
        $invoke | Should -Throw '*ChangeReportingPrerequisite*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-REPORTING-A10.json') | Should -BeFalse
    }

    It 'refuses an inactive SecOps Advanced Delivery rule before writes' {
        # Arrange
        $arguments = New-ReportingRouteFixture
        $global:adapterState.ExoSecOpsOverrideRule[0].Mode = 'Audit'

        # Act
        $invoke = { Invoke-ReportingRoutePreview $arguments }

        # Assert
        $invoke | Should -Throw '*ChangeReportingPrerequisite*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-REPORTING-A10.json') | Should -BeFalse
    }

    It 'refuses a stale reporting approval before writes' {
        # Arrange
        $arguments = New-ReportingRouteFixture
        $configuration = Get-Content $arguments.ConfigurationPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $configuration.controls['MDO-006'].approval.expiresOn = '2000-01-01T00:00:00Z'
        $configuration | ConvertTo-Json -Depth 60 | Set-Content $arguments.ConfigurationPath

        # Act
        $invoke = { Invoke-ReportingRoutePreview $arguments }

        # Assert
        $invoke | Should -Throw '*ApprovalExpired*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-REPORTING-A10.json') | Should -BeFalse
    }

    It 'refuses reporting state drift after approval and before writes' {
        # Arrange
        $arguments = New-ReportingRouteFixture -Approved
        $global:adapterState.ReportSubmissionPolicy[0].EnableReportToMicrosoft = $true

        # Act
        $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ChangeStateDrift*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-REPORTING-A10.json') | Should -BeFalse
    }

    It 'round trips one signed exact reporting and SecOps route with joined A09 receipt readback' {
        # Arrange
        $arguments = New-ReportingRouteFixture

        # Act
        $result = Invoke-ReportingRouteLifecycle $arguments

        # Assert
        $result.Apply.Status | Should -BeExactly 'Succeeded'
        $result.Readback.Result.Status | Should -BeExactly 'Pass'
        $result.Readback.Result.Reason | Should -Match 'ReportingVerified'
        $result.Readback.Evidence.Value.ReportingState.Mailbox.PrimarySmtpAddress | Should -BeExactly 'secops@contoso.example'
        @($result.Readback.Evidence.Value.ReportingState.SecOps.SentTo) | Should -Be @('secops@contoso.example')
        @($result.Readback.Evidence.Value.ReportingEvidence.deliveries).Count | Should -Be 3
        @($result.Readback.Evidence.Value.ReportingEvidence.deliveries.category | Sort-Object -Unique) | Should -Be @('Junk','NotJunk','Phish')
        $result.Repeat.Status | Should -BeExactly 'Succeeded'
        $result.RepeatWrites | Should -Be 0
        $result.Rollback.Status | Should -BeExactly 'Succeeded'
        $result.Restored | Should -BeExactly $result.Before
        $result.RepeatedRollback.Status | Should -BeExactly 'Succeeded'
        $result.RepeatedRollbackWrites | Should -Be 0
    }
}

AfterAll {
    foreach ($name in @($global:adapterCommands) + @('Get-ConnectionInformation','Invoke-OfflineAdapterCommand')) {
        Remove-Item "Function:global:$name" -ErrorAction SilentlyContinue
    }
    $script:signingCertificate.Dispose()
    $script:signingKey.Dispose()
    Get-Variable -Name 'adapter*' -Scope Global | Remove-Variable -Scope Global
    Remove-Module ExchangeOnlineBaseline.Common -Force -ErrorAction SilentlyContinue
}