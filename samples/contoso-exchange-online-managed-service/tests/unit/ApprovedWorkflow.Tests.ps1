BeforeAll {
    $script:sampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $script:sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking
    function New-WorkflowGateFixture {
        param([string]$Fault)
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $now = [datetime]::UtcNow
        $preview = New-BaselineChangePreview -ChangeId 'CHG004' -Tenant 'offline.onmicrosoft.com' -Context @{
            DeploymentProfile = 'ExchangeOnly'; Algorithm = 'SHA256'; Hash = ('a' * 64)
        } -Operation @(@{ OperationId = 'transport'; Command = 'Set-TransportConfig'; Identity = 'Transport'; Before = @{ Exists = $true; Value = @{ SmtpClientAuthenticationDisabled = $false } }; After = @{ Exists = $true; Value = @{ SmtpClientAuthenticationDisabled = $true } } }) -GeneratedOn $now.AddMinutes(-10)
        $written = Write-BaselineChangeArtifact -ChangeId CHG004 -Artifact Preview -Root $root -Content $preview
        $approval = @{
            SchemaVersion = '1.0.0'; ChangeId = 'CHG004'; Tenant = 'offline.onmicrosoft.com'; DeploymentProfile = 'ExchangeOnly'
            PreviewHash = $written.Hash; ApprovalIdentity = 'reviewer@example.test'; ApprovalAuthority = 'ExchangeOnlineChangeApproval'
            ApprovalTimeUtc = $now.AddMinutes(-5).ToString('o'); Signature = @{ Model = 'DetachedCms'; Value = 'Zm9yZ2Vk' }
        }
        switch ($Fault) {
            CaseChange { $approval.ChangeId = 'chg004' }
            Future { $approval.ApprovalTimeUtc = $now.AddHours(1).ToString('o') }
            Predates { $approval.ApprovalTimeUtc = $now.AddHours(-1).ToString('o') }
        }
        $approved = Write-BaselineChangeArtifact -ChangeId CHG004 -Artifact Approval -Root $root -Content $approval
        return @{ PreviewPath = $written.Path; ApprovalPath = $approved.Path; Tenant = 'offline.onmicrosoft.com'; DeploymentProfile = 'ExchangeOnly'; ConfigurationHash = ('a' * 64); RequestedBy = 'operator@example.test'; AsOf = $now }
    }
}

Describe 'EXR-004 approval admission' {
    It 'does not overwrite artifact bytes if a file appears after the existence check' {
        # Arrange
        $arguments = New-WorkflowGateFixture
        $before = [IO.File]::ReadAllText($arguments.PreviewPath)
        $script:racedPreviewPath = $arguments.PreviewPath
        Mock Test-Path -ModuleName ExchangeOnlineBaseline.Common { $false } -ParameterFilter { $LiteralPath -eq $script:racedPreviewPath }
        # Act
        $invoke = { Write-BaselineChangeArtifact -ChangeId CHG004 -Artifact Preview -Root (Split-Path $arguments.PreviewPath) -Content @{ Replaced = $true } }
        # Assert
        $invoke | Should -Throw
        [IO.File]::ReadAllText($arguments.PreviewPath) | Should -BeExactly $before
    }

    It 'refuses a forged CMS descriptor instead of treating nonempty text as verification' {
        # Arrange
        $arguments = New-WorkflowGateFixture
        # Act
        $decision = Test-BaselineChangeApproval @arguments
        # Assert
        $decision.Permitted | Should -BeFalse
        ($decision.Finding -join ';') | Should -Match 'ChangeApprovalSignatureUnverified'
    }

    It 'refuses a case-mismatched ChangeId' {
        # Arrange
        $arguments = New-WorkflowGateFixture -Fault CaseChange
        # Act
        $decision = Test-BaselineChangeApproval @arguments
        # Assert
        ($decision.Finding -join ';') | Should -Match 'ChangeApprovalChangeMismatch'
    }

    It 'refuses an approval from the future' {
        # Arrange
        $arguments = New-WorkflowGateFixture -Fault Future
        # Act
        $decision = Test-BaselineChangeApproval @arguments
        # Assert
        ($decision.Finding -join ';') | Should -Match 'ChangeApprovalTimeInvalid'
    }

    It 'refuses an approval predating the preview' {
        # Arrange
        $arguments = New-WorkflowGateFixture -Fault Predates
        # Act
        $decision = Test-BaselineChangeApproval @arguments
        # Assert
        ($decision.Finding -join ';') | Should -Match 'ChangeApprovalTimeInvalid'
    }

    It 'refuses <Fault> signer verification' -ForEach @(
        @{ Fault = 'Untrusted'; Reason = 'SignerChainUntrusted' }
        @{ Fault = 'Revoked'; Reason = 'SignerRevoked' }
        @{ Fault = 'UnknownRevocation'; Reason = 'SignerRevocationInconclusive' }
        @{ Fault = 'ExpiredCertificate'; Reason = 'SignerCertificateExpired' }
        @{ Fault = 'Unauthorized'; Reason = 'SignerUnauthorized' }
    ) {
        # Arrange
        $arguments = New-WorkflowGateFixture
        $script:trustFault = $Fault
        Mock Test-BaselineDetachedCmsSignature -ModuleName ExchangeOnlineBaseline.Common {
            @{ Verified = $true; SignerSubject = $(if ($script:trustFault -eq 'Unauthorized') { 'CN=Stranger' } else { 'CN=Offline Approver' }); SigningTimeUtc = [datetimeoffset]::UtcNow.AddMinutes(-5); CertificateNotBeforeUtc = [datetimeoffset]::UtcNow.AddDays(-1); CertificateNotAfterUtc = $(if ($script:trustFault -eq 'ExpiredCertificate') { [datetimeoffset]::UtcNow.AddMinutes(-1) } else { [datetimeoffset]::UtcNow.AddDays(1) }); ChainTrusted = ($script:trustFault -ne 'Untrusted'); RevocationStatus = $(switch ($script:trustFault) { Revoked { 'Revoked' } UnknownRevocation { 'Unknown' } default { 'Good' } }) }
        }
        $arguments.AuthorizedSigner = @(@{ Identity = 'reviewer@example.test'; Subject = 'CN=Offline Approver'; Authority = 'ExchangeOnlineChangeApproval' })
        # Act
        $decision = Test-BaselineChangeApproval @arguments
        # Assert
        $decision.Permitted | Should -BeFalse
        ($decision.Finding -join ';') | Should -Match $Reason
    }

    It 'admits one current byte-bound independently authorized change' {
        # Arrange
        $arguments = New-WorkflowGateFixture
        Mock Test-BaselineDetachedCmsSignature -ModuleName ExchangeOnlineBaseline.Common {
            @{ Verified = $true; SignerSubject = 'CN=Offline Approver'; SigningTimeUtc = [datetimeoffset]::UtcNow.AddMinutes(-5); CertificateNotBeforeUtc = [datetimeoffset]::UtcNow.AddDays(-1); CertificateNotAfterUtc = [datetimeoffset]::UtcNow.AddDays(1); ChainTrusted = $true; RevocationStatus = 'Good' }
        }
        $arguments.AuthorizedSigner = @(@{ Identity = 'reviewer@example.test'; Subject = 'CN=Offline Approver'; Authority = 'ExchangeOnlineChangeApproval' })
        # Act
        $decision = Test-BaselineChangeApproval @arguments
        # Assert
        $decision.Permitted | Should -BeTrue
        $decision.ChangeId | Should -BeExactly 'CHG004'
        $decision.Finding.Count | Should -Be 0
    }
}