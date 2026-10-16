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

    It 'verifies a real detached CMS approval and refuses changed signed fields' {
        # Arrange
        $arguments = New-WorkflowGateFixture
        $rsa = [Security.Cryptography.RSA]::Create(2048)
        $certificate = $null
        try {
            $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=Offline Approver', $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $certificate = $request.CreateSelfSigned(
                [datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(1)
            )
            $approvalDocument = Get-Content -LiteralPath $arguments.ApprovalPath -Raw |
                ConvertFrom-Json -AsHashtable -DateKind String
            $signedApproval = [ordered]@{}
            foreach ($member in $approvalDocument.Keys) {
                if ($member -cne 'Signature') { $signedApproval[$member] = $approvalDocument[$member] }
            }
            $approvalTime = [datetimeoffset]::Parse($approvalDocument.ApprovalTimeUtc)
            $cms = [Security.Cryptography.Pkcs.SignedCms]::new(
                [Security.Cryptography.Pkcs.ContentInfo]::new(
                    [Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson -InputObject $signedApproval))
                ), $true
            )
            $signer = [Security.Cryptography.Pkcs.CmsSigner]::new($certificate)
            $signer.DigestAlgorithm = [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
            $null = $signer.SignedAttributes.Add(
                [Security.Cryptography.Pkcs.Pkcs9SigningTime]::new($approvalTime.UtcDateTime)
            )
            $cms.ComputeSignature($signer, $true)
            $approvalDocument.Signature = @{
                Model = 'DetachedCms'
                Value = [Convert]::ToBase64String($cms.Encode())
            }
            [IO.File]::WriteAllText(
                $arguments.ApprovalPath,
                ($approvalDocument | ConvertTo-Json -Depth 20),
                [Text.UTF8Encoding]::new($false)
            )
            $arguments.AuthorizedSigner = @(@{
                Identity = 'reviewer@example.test'
                Subject = $certificate.Subject
                Authority = 'ExchangeOnlineChangeApproval'
            })
            Mock Test-BaselineEvidenceCertificateChain -ModuleName ExchangeOnlineBaseline.Common {
                @{ ChainTrusted = $true; RevocationStatus = 'Good' }
            }

            # Act
            $decision = Test-BaselineChangeApproval @arguments

            # Assert
            $decision.Permitted | Should -BeTrue
            $decision.Finding.Count | Should -Be 0

            $approvalDocument.ApprovalIdentity = 'attacker@example.test'
            [IO.File]::WriteAllText(
                $arguments.ApprovalPath,
                ($approvalDocument | ConvertTo-Json -Depth 20),
                [Text.UTF8Encoding]::new($false)
            )
            $tamperedDecision = Test-BaselineChangeApproval @arguments
            $tamperedDecision.Permitted | Should -BeFalse
            ($tamperedDecision.Finding -join ';') | Should -Match 'ChangeApprovalSignatureUnverified'
        }
        finally {
            if ($null -ne $certificate) { $certificate.Dispose() }
            $rsa.Dispose()
        }
    }
}