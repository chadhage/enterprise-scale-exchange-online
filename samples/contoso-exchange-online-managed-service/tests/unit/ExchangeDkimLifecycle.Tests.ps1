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

    function Initialize-DkimLifecycleDoubles {
        Initialize-AdapterDoubles
        $global:adapterState.DkimSigningConfig = @(@{
            Identity = 'contoso.example'
            Domain = 'contoso.example'
            Enabled = $false
            Status = 'Valid'
            Selector1CNAME = 'selector1-contoso._domainkey.contoso.onmicrosoft.example'
            Selector2CNAME = 'selector2-contoso._domainkey.contoso.onmicrosoft.example'
            Selector1KeySize = 2048
            Selector2KeySize = 2048
            KeySize = 2048
        })
    }

    function Approve-DkimFixture {
        param($Arguments)

        & $script:adapterCommand -Stage Preview @Arguments -Scope Dkim -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
    }

    function Add-DkimSendingDomain {
        param($Arguments)

        $parameters = Get-Content $Arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.domainInventory.domains += @{
            domainName = 'fabrikam.example'
            accepted = $true
            sending = $true
            parked = $false
            parentDomain = $null
            domainType = 'Authoritative'
            owner = 'Synthetic Exchange owner'
            sendingSystem = 'ExchangeOnline'
            senderSource = @{
                owner = 'Synthetic sender owner'
                reference = 'fixture:dkim-sender-inventory'
                suppliedAtUtc = [datetimeoffset]::UtcNow.AddMinutes(-5).ToString('o')
            }
        }
        $parameters | ConvertTo-Json -Depth 30 | Set-Content $Arguments.ParameterPath
    }

    function Invoke-DkimLifecycle {
        param($Arguments)

        $before = Get-AdapterSnapshot
        & $script:adapterCommand -Stage Preview @Arguments -Scope Dkim -Confirm:$false | Out-Null
        $previewHash = (Get-FileHash -LiteralPath $Arguments.PreviewPath -Algorithm SHA256).Hash
        & $script:adapterCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
        $approval = Get-Content $Arguments.ApprovalPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        & $script:adapterCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:adapterCommand -Stage Apply @Arguments -Apply -Confirm:$false
        $applied = $global:adapterState.DkimSigningConfig[0].Clone()
        $writesAfterApply = $global:adapterCalls.Count

        $repeatArguments = New-StatefulAdapterFixture -Scope Dkim
        $repeatArguments.ChangeId = 'ADAPTER004-REPEAT'
        $repeatArguments.PreviewPath = Join-Path $repeatArguments.ArtifactRoot 'preview-ADAPTER004-REPEAT.json'
        $repeatArguments.ApprovalPath = Join-Path $repeatArguments.ArtifactRoot 'approval-ADAPTER004-REPEAT.json'
        Approve-DkimFixture -Arguments $repeatArguments
        & $script:adapterCommand -Stage Validate @repeatArguments | Out-Null
        $repeat = & $script:adapterCommand -Stage Apply @repeatArguments -Apply -Confirm:$false
        $repeatWrites = $global:adapterCalls.Count - $writesAfterApply

        $global:adapterState.DkimSigningConfig = @()
        $writesBeforeDrift = $global:adapterCalls.Count
        $drift = $null
        try { & $script:adapterCommand -Stage Rollback @Arguments -Apply -Confirm:$false | Out-Null } catch { $drift = $_ }
        $driftWrites = $global:adapterCalls.Count - $writesBeforeDrift
        $global:adapterState.DkimSigningConfig = @($applied.Clone())

        $rollback = & $script:adapterCommand -Stage Rollback @Arguments -Apply -Confirm:$false
        $writesAfterRollback = $global:adapterCalls.Count
        $repeatedRollback = & $script:adapterCommand -Stage Rollback @Arguments -Apply -Confirm:$false

        [pscustomobject]@{
            PreviewHash = $previewHash
            ApprovedPreviewHash = [string]$approval.PreviewHash
            ApplyStatus = $apply.Status
            Applied = $applied
            RepeatStatus = $repeat.Status
            RepeatWrites = $repeatWrites
            DriftMessage = $drift.Exception.Message
            DriftWrites = $driftWrites
            RollbackStatus = $rollback.Status
            RestoredSnapshot = Get-AdapterSnapshot
            BeforeSnapshot = $before
            RepeatedRollbackStatus = $repeatedRollback.Status
            RepeatedRollbackWrites = $global:adapterCalls.Count - $writesAfterRollback
        }
    }
}

Describe 'EXR-011-A02 approved Exchange DKIM lifecycle' {
    BeforeEach {
        Initialize-DkimLifecycleDoubles
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

    It 'refuses a wrong DKIM selector before writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Dkim
        Approve-DkimFixture -Arguments $arguments
        $global:adapterState.DkimSigningConfig[0].Selector1CNAME = 'selector1-wrong._domainkey.tenant.example'

        # Act
        $invoke = { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ChangeStateDrift*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses a missing DKIM selector before writes' {
        # Arrange
        $global:adapterState.DkimSigningConfig[0].Remove('Selector2CNAME')
        $arguments = New-StatefulAdapterFixture -Scope Dkim

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope Dkim -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ChangeReadIncomplete*Dkim*Selector2CNAME*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses an undersized DKIM key before writes' {
        # Arrange
        $global:adapterState.DkimSigningConfig[0].Selector2KeySize = 1024
        $arguments = New-StatefulAdapterFixture -Scope Dkim

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope Dkim -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*DkimKeyTooShort*1024*2048*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses an invalid DKIM signing status before writes' {
        # Arrange
        $global:adapterState.DkimSigningConfig[0].Enabled = $true
        $global:adapterState.DkimSigningConfig[0].Status = 'CnameMissing'
        $arguments = New-StatefulAdapterFixture -Scope Dkim

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope Dkim -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*DkimSigningInvalid*CnameMissing*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses an unsupported DKIM change before writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Dkim
        $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions.dkim = @{ rotateKeys = $true }
        $parameters | ConvertTo-Json -Depth 30 | Set-Content $arguments.ParameterPath

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope Dkim -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ChangeOptionsInvalid*unsupported option dkim*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses an unapproved DKIM change outside the approved denominator before writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Dkim
        Approve-DkimFixture -Arguments $arguments
        Add-DkimSendingDomain -Arguments $arguments

        # Act
        $invoke = { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ChangePreviewBindingMismatch*administrator parameters or workflow options changed*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses incomplete raw DKIM collection before writes' {
        # Arrange
        $global:adapterState.DkimSigningConfig[0].Remove('Status')
        $arguments = New-StatefulAdapterFixture -Scope Dkim

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope Dkim -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ChangeReadIncomplete*Dkim*Status*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses a raw DKIM collection error before writes' {
        # Arrange
        $global:adapterReadFault = 'DkimSigningConfig'
        $arguments = New-StatefulAdapterFixture -Scope Dkim

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope Dkim -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ChangeReadIncomplete*offline DkimSigningConfig collection failure*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses an incomplete applicable-domain DKIM collection before writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Dkim
        Add-DkimSendingDomain -Arguments $arguments

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope Dkim -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ChangeReadIncomplete*Dkim*fabrikam.example*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses duplicate or ambiguous raw DKIM identity before writes' {
        # Arrange
        $duplicate = $global:adapterState.DkimSigningConfig[0].Clone()
        $duplicate.Domain = 'CONTOSO.EXAMPLE.'
        $global:adapterState.DkimSigningConfig += $duplicate
        $arguments = New-StatefulAdapterFixture -Scope Dkim

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope Dkim -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ChangeReadIncomplete*Get-DkimSigningConfig returned duplicate identities*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'round trips the approved DKIM denominator with exact binding and independent readback' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope Dkim

        # Act
        $result = Invoke-DkimLifecycle -Arguments $arguments

        # Assert
        $result.ApprovedPreviewHash | Should -Be $result.PreviewHash
        $result.ApplyStatus | Should -BeExactly 'Succeeded'
        $result.Applied.Identity | Should -BeExactly 'contoso.example'
        $result.Applied.Selector1CNAME | Should -BeExactly 'selector1-contoso._domainkey.contoso.onmicrosoft.example'
        $result.Applied.Selector2CNAME | Should -BeExactly 'selector2-contoso._domainkey.contoso.onmicrosoft.example'
        $result.Applied.Selector1KeySize | Should -Be 2048
        $result.Applied.Selector2KeySize | Should -Be 2048
        $result.Applied.Enabled | Should -BeTrue
        $result.Applied.Status | Should -BeExactly 'Valid'
        $result.RepeatStatus | Should -BeExactly 'Succeeded'
        $result.RepeatWrites | Should -Be 0
        $result.DriftMessage | Should -BeLike '*ChangeStateDrift*'
        $result.DriftWrites | Should -Be 0
        $result.RollbackStatus | Should -BeExactly 'Succeeded'
        $result.RestoredSnapshot | Should -BeExactly $result.BeforeSnapshot
        $result.RepeatedRollbackStatus | Should -BeExactly 'Succeeded'
        $result.RepeatedRollbackWrites | Should -Be 0
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