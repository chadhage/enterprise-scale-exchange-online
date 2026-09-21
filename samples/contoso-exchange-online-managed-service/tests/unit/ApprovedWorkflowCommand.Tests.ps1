BeforeAll {
    $script:root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:command = Join-Path $script:root 'scripts/Invoke-ExchangeOnlineChange.ps1'
    Import-Module (Join-Path $script:root 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking
    function global:Get-ConnectionInformation { [pscustomobject]@{ TenantID = $global:workflowTenant; State = 'Connected' } }
    function global:Get-TransportConfig {
        [CmdletBinding()]param()
        if ($global:workflowReadFailure -and $global:workflowWrites -gt 0) { throw 'Offline readback failure' }
        [pscustomobject]$global:workflowState.Clone()
    }
    function global:Set-TransportConfig {
        [CmdletBinding(SupportsShouldProcess)]param([bool]$SmtpClientAuthenticationDisabled, [string]$ExternalPostmasterAddress)
        if ($PSCmdlet.ShouldProcess('Offline transport', 'Record simulated mutation')) {
            $global:workflowWrites++
            if ($global:workflowWriteFailure) { throw 'Offline simulated Exchange failure' }
            $global:workflowState.SmtpClientAuthenticationDisabled = $SmtpClientAuthenticationDisabled
            $global:workflowState.ExternalPostmasterAddress = $ExternalPostmasterAddress
        }
    }
    function New-WorkflowCommandFixture {
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory $directory
        $parameters = Get-Content (Join-Path $script:root 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
        $parameters.entitlement.verified = $true
        $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
        $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE')
        $parameterPath = Join-Path $directory 'parameters.json'
        $parameters | ConvertTo-Json -Depth 20 | Set-Content $parameterPath
        $configurationPath = Join-Path $script:root 'config/exchange-only.v1.json'
        $context = Get-BaselineExchangeContext -ConfigurationPath $configurationPath -ParameterPath $parameterPath
        $operations = @(@{ OperationId = 'Transport'; Command = 'Set-TransportConfig'; Identity = 'Transport'; Before = @{ Exists = $true; Value = $global:workflowState.Clone() }; After = @{ Exists = $true; Value = @{ SmtpClientAuthenticationDisabled = $true; ExternalPostmasterAddress = 'postmaster@contoso.example' } } })
        $preview = New-BaselineChangePreview -ChangeId CHG004 -Tenant $parameters.MICROSOFT_ENTRA_TENANT_GUID -Context @{ DeploymentProfile = 'ExchangeOnly'; Algorithm = 'SHA256'; Hash = $context.Hash } -Operation $operations -GeneratedOn ([datetime]::UtcNow.AddMinutes(-10))
        $document = $preview | ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable -DateKind String
        $document.Scope = @('Transport')
        $document.WorkflowVersion = '1.0.0'
        $previewFile = Write-BaselineChangeArtifact -ChangeId CHG004 -Artifact Preview -Root $directory -Content $document
        $approval = @{ SchemaVersion = '1.0.0'; ChangeId = 'CHG004'; Tenant = $parameters.MICROSOFT_ENTRA_TENANT_GUID; DeploymentProfile = 'ExchangeOnly'; PreviewHash = $previewFile.Hash; ApprovalIdentity = 'reviewer@example.test'; ApprovalAuthority = 'ExchangeOnlineChangeApproval'; ApprovalTimeUtc = [datetime]::UtcNow.AddMinutes(-5).ToString('o'); Signature = @{ Model = 'DetachedCms'; Value = 'b2ZmbGluZQ==' } }
        $approvalFile = Write-BaselineChangeArtifact -ChangeId CHG004 -Artifact Approval -Root $directory -Content $approval
        $signerPath = Join-Path $directory 'authority.json'
        @(@{ Identity = 'reviewer@example.test'; Subject = 'CN=Offline'; Authority = 'ExchangeOnlineChangeApproval' }) | ConvertTo-Json -AsArray | Set-Content $signerPath
        @{ ParameterPath = $parameterPath; ConfigurationPath = $configurationPath; PreviewPath = $previewFile.Path; ApprovalPath = $approvalFile.Path; ArtifactRoot = $directory; ChangeId = 'CHG004'; RequestedBy = 'operator@example.test'; AuthorizedSignerPath = $signerPath }
    }
}

Describe 'EXR-004 public approved workflow refusals' {
BeforeEach {
    $global:workflowTenant = '00000000-0000-0000-0000-000000000000'
    $global:workflowState = @{ SmtpClientAuthenticationDisabled = $false; ExternalPostmasterAddress = 'old@contoso.example' }
    $global:workflowWrites = 0
    $global:workflowWriteFailure = $false
    $global:workflowReadFailure = $false
    Mock Test-BaselineDetachedCmsSignature -ModuleName ExchangeOnlineBaseline.Common {
        @{ Verified = $true; SignerSubject = 'CN=Offline'; SigningTimeUtc = [datetimeoffset]::UtcNow.AddMinutes(-5); CertificateNotBeforeUtc = [datetimeoffset]::UtcNow.AddDays(-1); CertificateNotAfterUtc = [datetimeoffset]::UtcNow.AddDays(1); ChainTrusted = $true; RevocationStatus = 'Good' }
    }
}

AfterAll {
    'Get-ConnectionInformation','Get-TransportConfig','Set-TransportConfig' | ForEach-Object { Remove-Item "Function:global:$_" -ErrorAction SilentlyContinue }
    Get-Variable -Name 'workflow*' -Scope Global | Remove-Variable -Scope Global
}

    It 'refuses <Fault> before any mutation' -ForEach @(
        @{ Fault = 'MissingApproval'; Reason = 'ChangeApprovalNotFound' }
        @{ Fault = 'ChangeMismatch'; Reason = 'ApplyChangeMismatch' }
        @{ Fault = 'TamperedBytes'; Reason = 'ChangeApprovalPreviewTampered' }
        @{ Fault = 'Expired'; Reason = 'ChangeApprovalPreviewExpired' }
        @{ Fault = 'MissingAuthority'; Reason = 'ChangeSigningPrerequisite' }
        @{ Fault = 'WrongTenant'; Reason = 'ChangeSessionTenantMismatch' }
        @{ Fault = 'Drift'; Reason = 'ChangeStateDrift' }
        @{ Fault = 'ReusedRoot'; Reason = 'ChangeArtifactAlreadyEmitted' }
        @{ Fault = 'NoApply'; Reason = 'ChangeApplySwitchRequired' }
        @{ Fault = 'UnapprovedOperation'; Reason = 'ChangeOperationMismatch' }
        @{ Fault = 'UnknownScope'; Reason = 'ChangeScopeUnsupported' }
    ) {
        # Arrange
        $arguments = New-WorkflowCommandFixture
        $apply = $true
        switch ($Fault) {
            MissingApproval { Remove-Item $arguments.ApprovalPath }
            ChangeMismatch { $arguments.ChangeId = 'CHG999' }
            TamperedBytes { [IO.File]::AppendAllText($arguments.PreviewPath, ' ') }
            MissingAuthority { $arguments.AuthorizedSignerPath = Join-Path $TestDrive 'missing-authority.json' }
            WrongTenant { $global:workflowTenant = '11111111-1111-1111-1111-111111111111' }
            Drift { $global:workflowState.ExternalPostmasterAddress = 'drift@contoso.example' }
            ReusedRoot { Set-Content (Join-Path $arguments.ArtifactRoot 'prechange-CHG004.json') '{}' }
            NoApply { $apply = $false }
            default {
                $preview = Get-Content $arguments.PreviewPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
                switch ($Fault) {
                    Expired { $preview.ExpiresOn = [datetime]::UtcNow.AddSeconds(-1).ToString('o') }
                    UnapprovedOperation { $preview.Operation[0].After.Value.SmtpClientAuthenticationDisabled = $false }
                    UnknownScope { $preview.Scope = @('Purview') }
                }
                $preview | ConvertTo-Json -Depth 40 | Set-Content $arguments.PreviewPath
                $approval = Get-Content $arguments.ApprovalPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
                $approval.PreviewHash = (Get-FileHash $arguments.PreviewPath).Hash.ToLowerInvariant()
                $approval | ConvertTo-Json -Depth 20 | Set-Content $arguments.ApprovalPath
            }
        }
        # Act
        $invoke = { & $script:command -Stage Apply @arguments -Apply:$apply -Confirm:$false }
        # Assert
        $invoke | Should -Throw "*$Reason*"
        $global:workflowWrites | Should -Be 0
    }

    It 'stops approval when enterprise signing capability is missing' {
        # Arrange
        $arguments = New-WorkflowCommandFixture
        Remove-Item $arguments.ApprovalPath
        # Act
        $invoke = { & $script:command -Stage Approve @arguments -ApprovalIdentity 'reviewer@example.test' }
        # Assert
        $invoke | Should -Throw '*ChangeSigningPrerequisite*'
    }

    It 'stops the deployment entrypoint clearly when signer metadata is absent' {
        # Arrange
        $arguments = New-WorkflowCommandFixture
        $arguments.Remove('AuthorizedSignerPath')
        # Act
        $invoke = { & (Join-Path $script:root 'scripts/Deploy-ExchangeOnlineBaseline.ps1') @arguments -Apply -SkipConnection -Confirm:$false }
        # Assert
        $invoke | Should -Throw '*ChangeSigningPrerequisite*'
        $global:workflowWrites | Should -Be 0
    }

    It 'refuses to overwrite an immutable preview' {
        # Arrange
        $arguments = New-WorkflowCommandFixture
        # Act
        $invoke = { & $script:command -Stage Preview @arguments -Scope Transport }
        # Assert
        $invoke | Should -Throw '*ChangeArtifactAlreadyEmitted*'
        $global:workflowWrites | Should -Be 0
    }

    It 'refuses an unsupported signed operation during offline validation' {
        # Arrange
        $arguments = New-WorkflowCommandFixture
        $preview = Get-Content $arguments.PreviewPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $preview.Operation[0].Command = 'Set-AtpPolicyForO365'
        $preview | ConvertTo-Json -Depth 40 | Set-Content $arguments.PreviewPath
        $approval = Get-Content $arguments.ApprovalPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $approval.PreviewHash = (Get-FileHash $arguments.PreviewPath).Hash.ToLowerInvariant()
        $approval | ConvertTo-Json -Depth 20 | Set-Content $arguments.ApprovalPath
        # Act
        $invoke = { & $script:command -Stage Validate @arguments }
        # Assert
        $invoke | Should -Throw '*ChangeOperationMismatch*'
        $global:workflowWrites | Should -Be 0
    }

    It 'refuses to silently ignore DKIM activation outside the approved scope' {
        # Arrange
        $arguments = New-WorkflowCommandFixture
        # Act
        $invoke = { & (Join-Path $script:root 'scripts/Deploy-ExchangeOnlineBaseline.ps1') @arguments -Apply -EnableDkim -SkipConnection -Confirm:$false }
        # Assert
        $invoke | Should -Throw '*ChangeScopeUnsupported*workflowOptions.enableDkim*'
        $global:workflowWrites | Should -Be 0
    }

    It 'does not mutate or consume execution artifacts during WhatIf' {
        # Arrange
        $arguments = New-WorkflowCommandFixture
        # Act
        & $script:command -Stage Apply @arguments -Apply -WhatIf
        # Assert
        $global:workflowWrites | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-CHG004.json') | Should -BeFalse
        Test-Path (Join-Path $arguments.ArtifactRoot 'apply-CHG004.lock') | Should -BeFalse
    }

    It 'records <Failure> without reporting success' -ForEach @(
        @{ Failure = 'Write' }
        @{ Failure = 'Readback' }
    ) {
        # Arrange
        $arguments = New-WorkflowCommandFixture
        $global:workflowWriteFailure = $Failure -eq 'Write'
        $global:workflowReadFailure = $Failure -eq 'Readback'
        # Act
        $invoke = { & $script:command -Stage Apply @arguments -Apply -Confirm:$false }
        # Assert
        $invoke | Should -Throw '*ChangeExecutionFailed*'
        foreach ($name in 'apply','postchange') {
            $receipt = Get-Content (Join-Path $arguments.ArtifactRoot "$name-CHG004.json") -Raw | ConvertFrom-Json
            $receipt.Status | Should -BeExactly 'Failed'
            $receipt.Fault | Should -Not -BeNullOrEmpty
        }
        Test-Path (Join-Path $arguments.ArtifactRoot 'rollback-CHG004.ps1') | Should -BeTrue
    }

    It 'refuses rollback over intervening drift' {
        # Arrange
        $arguments = New-WorkflowCommandFixture
        & $script:command -Stage Apply @arguments -Apply -Confirm:$false | Out-Null
        $global:workflowState.ExternalPostmasterAddress = 'later-change@contoso.example'
        # Act
        $invoke = { & $script:command -Stage Rollback @arguments -Apply -Confirm:$false }
        # Assert
        $invoke | Should -Throw '*ChangeStateDrift*'
        $global:workflowWrites | Should -Be 1
    }

    It 'refuses a second apply of the same change' {
        # Arrange
        $arguments = New-WorkflowCommandFixture
        & $script:command -Stage Apply @arguments -Apply -Confirm:$false | Out-Null
        # Act
        $invoke = { & $script:command -Stage Apply @arguments -Apply -Confirm:$false }
        # Assert
        $invoke | Should -Throw
        $global:workflowWrites | Should -Be 1
    }

    It 'executes the documented immutable artifact round trip and scoped rollback' {
        # Arrange
        $arguments = New-WorkflowCommandFixture
        Remove-Item $arguments.PreviewPath, $arguments.ApprovalPath
        $artifactRoot = $arguments.ArtifactRoot
        $changeId = $arguments.ChangeId
        $key = [Security.Cryptography.RSA]::Create(2048)
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Offline', $key, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $certificate = $request.CreateSelfSigned([datetimeoffset]::UtcNow.AddMinutes(-1), [datetimeoffset]::UtcNow.AddDays(1))
        $workflowInputs = @{
            parameterPath = $arguments.ParameterPath; artifactRoot = $artifactRoot; changeId = $changeId
            requestedBy = $arguments.RequestedBy; authorityPath = $arguments.AuthorizedSignerPath
            approvalIdentity = 'reviewer@example.test'; certificate = $certificate
        }
        Mock Test-BaselineDetachedCmsSignature -ModuleName ExchangeOnlineBaseline.Common {
            param($CanonicalBytes, $Signature)
            $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($CanonicalBytes), $true)
            $cms.Decode([Convert]::FromBase64String($Signature.Value))
            $cms.CheckSignature($true)
            @{ Verified = $true; SignerSubject = $cms.SignerInfos[0].Certificate.Subject; SigningTimeUtc = [datetimeoffset]::UtcNow; CertificateNotBeforeUtc = [datetimeoffset]::UtcNow.AddDays(-1); CertificateNotAfterUtc = [datetimeoffset]::UtcNow.AddDays(1); ChainTrusted = $true; RevocationStatus = 'Good' }
        }
        $guide = Get-Content (Join-Path $script:root 'docs/APPROVED-CHANGE.md') -Raw
        $commands = [regex]::Match($guide, '(?s)<!-- executable-workflow -->\s*```powershell\s*(.*?)```').Groups[1].Value
        $commands | Should -Not -BeNullOrEmpty
        Push-Location $script:root
        try {
            # Act
            $result = & ([scriptblock]::Create('param($parameterPath, $artifactRoot, $changeId, $requestedBy, $authorityPath, $approvalIdentity, $certificate)' + "`n" + $commands)) @workflowInputs
            # Assert
            @($result).Count | Should -Be 5
            $global:workflowWrites | Should -Be 2
            $global:workflowState.SmtpClientAuthenticationDisabled | Should -BeFalse
            $global:workflowState.ExternalPostmasterAddress | Should -BeExactly 'old@contoso.example'
            foreach ($artifact in (New-BaselineChangeArtifactSet -ChangeId $changeId -Root $artifactRoot)) {
                Test-Path $artifact.Path | Should -BeTrue
            }
            $approval = Get-Content $arguments.ApprovalPath -Raw | ConvertFrom-Json
            $approval.PreviewHash | Should -BeExactly (Get-FileHash $arguments.PreviewPath).Hash.ToLowerInvariant()
            $approval.ChangeId | Should -BeExactly $changeId
            (Get-Content (Join-Path $artifactRoot "postchange-$changeId.json") -Raw | ConvertFrom-Json).Status | Should -BeExactly 'Succeeded'
            (Get-Content (Join-Path $artifactRoot "rollback-result-$changeId.json") -Raw | ConvertFrom-Json).Status | Should -BeExactly 'Succeeded'
        }
        finally { Pop-Location; $certificate.Dispose(); $key.Dispose() }
    }
}