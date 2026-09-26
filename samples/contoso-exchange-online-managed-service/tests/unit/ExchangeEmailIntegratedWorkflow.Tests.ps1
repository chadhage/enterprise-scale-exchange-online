#requires -Version 7.0

BeforeAll {
    $script:root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:adapterRoot = $script:root
    $script:adapterCommand = Join-Path $script:root 'scripts/Invoke-ExchangeOnlineChange.ps1'
    $script:deployCommand = Join-Path $script:root 'scripts/Deploy-ExchangeOnlineBaseline.ps1'
    $script:emailModule = Import-Module (Join-Path $script:root 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking -PassThru
    . (Join-Path $PSScriptRoot '../helpers/ApprovedAdapterDoubles.ps1')
    . (Join-Path $PSScriptRoot '../helpers/ExchangeProtectionFixture.ps1')

    $script:adapterKey = [Security.Cryptography.RSA]::Create(2048)
    $adapterRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Offline Adapter',
        $script:adapterKey,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $script:adapterCertificate = $adapterRequest.CreateSelfSigned(
        [datetimeoffset]::UtcNow.AddMinutes(-1),
        [datetimeoffset]::UtcNow.AddDays(1)
    )

    $script:evidenceKey = [Security.Cryptography.RSA]::Create(2048)
    $evidenceRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Offline Email Evidence',
        $script:evidenceKey,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $script:evidenceCertificate = $evidenceRequest.CreateSelfSigned(
        [datetimeoffset]::UtcNow.AddMinutes(-1),
        [datetimeoffset]::UtcNow.AddDays(1)
    )
    $global:ExchangeEmailA12EvidenceTestRoot = $script:evidenceCertificate
    $global:ExchangeEmailA12AdapterTestRoot = $script:adapterCertificate

    Mock New-BaselineEvidenceCertificateChain -ModuleName ExchangeOnlineBaseline.Common {
        $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.TrustMode = [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
        $null = $chain.ChainPolicy.CustomTrustStore.Add($global:ExchangeEmailA12EvidenceTestRoot)
        $null = $chain.ChainPolicy.CustomTrustStore.Add($global:ExchangeEmailA12AdapterTestRoot)
        $chain
    }

    function New-IntegratedEmailFixture {
        $fixture = New-ProtectionFixture
        foreach ($recipient in $fixture.Context.Configuration.controls['MDO-001'].recipientMatrix) {
            if ($recipient.expectedPolicy -eq 'Default') {
                $recipient.expectedPolicy = 'Standard Preset Security Policy'
            }
        }
        foreach ($kind in @('EOP','ATP')) {
            $fixture.Raw["Get-${kind}ProtectionPolicyRule"].ByIdentity['Standard Preset Security Policy'][0].ExceptIfSentTo = @('custom@contoso.example')
        }
        $fixture.Raw['Get-SafeLinksPolicy'].Items[2].DisableURLRewrite = $true
        $fixture.Context.Configuration.controls['MDO-001'].settingExceptions = @(@{
            recipient = 'custom@contoso.example'
            family = 'SafeLinks'
            setting = 'DisableURLRewrite'
            value = $true
            approval = @{
                reference = 'OFFLINE-EXCEPTION-A12'
                owner = 'security@contoso.example'
                expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
            }
        })

        $reportingApproval = @{
            reference = 'OFFLINE-REPORTING-A12'
            owner = 'security@contoso.example'
            expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
        }
        $fixture.Context.Configuration.controls['MDO-006'].reportingMailbox = 'secops@contoso.example'
        $fixture.Context.Configuration.controls['MDO-006'].approval = $reportingApproval
        $fixture.Context.Configuration.controls['MDO-006'].preSubmitMessageEnabled = $true
        $fixture.Context.Configuration.controls['MDO-006'].postSubmitMessageEnabled = $true
        $fixture.Context.Parameters.reportingEvidence = @{
            mailbox = 'secops@contoso.example'
            approval = $reportingApproval.Clone()
            dlp = @{ mailbox = 'secops@contoso.example'; status = 'NotApplicable'; approval = $reportingApproval.Clone() }
            deliveries = @(foreach ($category in @('Junk','NotJunk','Phish')) {
                @{
                    category = $category
                    recipient = 'secops@contoso.example'
                    reporter = 'user@contoso.example'
                    messageId = "$category-message"
                    microsoftSubmissionId = "$category-submission"
                    feedbackMessageId = "$category-feedback"
                    receivedAt = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o')
                    originalMessagePreserved = $true
                }
            })
        }
        $fixture.Raw['Get-Mailbox'].ByIdentity['secops@contoso.example'] = @(@{
            Identity = 'secops@contoso.example'
            PrimarySmtpAddress = 'secops@contoso.example'
            RecipientTypeDetails = 'SharedMailbox'
            ForwardingAddress = $null
            ForwardingSmtpAddress = $null
            DeliverToMailboxAndForward = $false
        })
        $fixture.Raw['Get-ReportSubmissionPolicy'].Items[0].PreSubmitMessageEnabled = $true
        $fixture.Raw['Get-ReportSubmissionPolicy'].Items[0].PostSubmitMessageEnabled = $true
        $fixture.Raw['Get-ReportSubmissionRule'].Items[0].State = 'Enabled'
        $fixture.Raw['Get-ReportSubmissionRule'].Items[0].ReportSubmissionPolicy = 'DefaultReportSubmissionPolicy'
        $fixture.Raw['Get-ReportSubmissionRule'].Items[0].SentTo = @('secops@contoso.example')

        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $directory
        $configurationPath = Join-Path $directory 'configuration.json'
        $parameterPath = Join-Path $directory 'parameters.json'
        $fixture.Context.Configuration | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $configurationPath
        $fixture.Context.Parameters | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $parameterPath
        $fixture.Context = Get-BaselineExchangeContext -ConfigurationPath $configurationPath -ParameterPath $parameterPath
        $fixture.Context.Parameters.reportingEvidence = $fixture.Context.Parameters.reportingEvidence
        $fixture.Directory = $directory
        $fixture.ParameterPath = $parameterPath
        $fixture
    }

    function New-FrozenEmailEvidence {
        param($Fixture, [object[]]$Execution)

        $manifest = Get-BaselineExchangeManifest
        $envelope = [ordered]@{
            SchemaVersion = '1.0.0'
            DeploymentProfile = 'ExchangeOnly'
            ProfileVersion = $manifest.Version
            TenantId = $Fixture.Context.Parameters.MICROSOFT_ENTRA_TENANT_GUID
            ConfigurationHash = $Fixture.Context.Hash
            CollectedAtUtc = [datetimeoffset]::UtcNow.ToString('o')
            Entitlement = $Fixture.Context.Entitlement
            Evidence = @($Execution | ForEach-Object Evidence)
            Check = @($Execution | ForEach-Object Result)
            ManifestHash = $manifest.Hash
            Exclusion = $manifest.Exclusion
            ExternalCheck = $manifest.ExternalCheck
            ExternalReadiness = $manifest.ExternalReadiness
        }
        $evidencePath = Join-Path $Fixture.Directory 'exchange-email-evidence.json'
        $signaturePath = Join-Path $Fixture.Directory 'exchange-email-evidence.p7s'
        $authorityPath = Join-Path $Fixture.Directory 'evidence-authority.json'
        $envelope | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $evidencePath
        @(@{
            Identity = 'offline-email-reviewer'
            Subject = $script:evidenceCertificate.Subject
            Thumbprint = $script:evidenceCertificate.Thumbprint
            Authority = 'ExchangeOnlineChangeApproval'
        }) | ConvertTo-Json -AsArray | Set-Content -LiteralPath $authorityPath
        $evidenceHash = (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash
        $arguments = @{
            Context = $Fixture.Context
            EvidencePath = $evidencePath
            SignaturePath = $signaturePath
            SignerIdentity = 'offline-email-reviewer'
            AuthorizedSignerPath = $authorityPath
            ExpectedEvidenceHash = $evidenceHash
            ExpectedConfigurationHash = $Fixture.Context.Hash
            MaximumEvidenceAge = [timespan]::FromHours(1)
        }
        $signed = Invoke-BaselineExchangeGoLive @arguments -SignEvidence -SigningCertificate $script:evidenceCertificate
        @{ Arguments = $arguments; Envelope = $envelope; Signed = $signed }
    }
}

AfterAll {
    if ($script:evidenceCertificate) { $script:evidenceCertificate.Dispose() }
    if ($script:evidenceKey) { $script:evidenceKey.Dispose() }
    if ($script:adapterCertificate) { $script:adapterCertificate.Dispose() }
    if ($script:adapterKey) { $script:adapterKey.Dispose() }
    Remove-Variable -Name ExchangeEmailA12EvidenceTestRoot -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name ExchangeEmailA12AdapterTestRoot -Scope Global -ErrorAction SilentlyContinue
    if ($global:adapterCommands) {
        @($global:adapterCommands) + @('Get-ConnectionInformation','Invoke-OfflineAdapterCommand') |
            Select-Object -Unique |
            ForEach-Object { Remove-Item "Function:global:$_" -ErrorAction SilentlyContinue }
    }
}

Describe 'EXR-010-A12 integrated email workflow' {
    BeforeEach {
        Initialize-AdapterDoubles
    }

    It 'refuses tampered frozen evidence against its detached signature' {
        # Arrange
        $fixture = New-IntegratedEmailFixture
        $execution = @(Invoke-ProtectionRawRegistry $fixture $script:emailModule)
        $frozen = New-FrozenEmailEvidence -Fixture $fixture -Execution $execution
        [IO.File]::AppendAllText($frozen.Arguments.EvidencePath, ' ')
        $frozen.Arguments.ExpectedEvidenceHash = (Get-FileHash -LiteralPath $frozen.Arguments.EvidencePath -Algorithm SHA256).Hash
        $verifyArguments = $frozen.Arguments

        # Act
        $invoke = { Invoke-BaselineExchangeGoLive @verifyArguments }

        # Assert
        $invoke | Should -Throw '*ExchangeSignatureUnverified*'
        $global:adapterCalls.Count | Should -Be 0
    }

    It 'refuses recipient drift before any approved write' {
        # Arrange
        $fixture = New-IntegratedEmailFixture
        $fixture.Raw['Get-Recipient'].Items += @{
            Identity = 'undeclared-shared'
            PrimarySmtpAddress = 'undeclared@contoso.example'
            RecipientTypeDetails = 'SharedMailbox'
        }

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:emailModule | Where-Object ControlId -CEQ 'MDO-001'

        # Assert
        $result.Result.Status | Should -Not -BeIn @('Pass','ApprovedException')
        $result.Result.Reason | Should -Match 'EmailProtectionRecipientInventory'
        $global:adapterCalls.Count | Should -Be 0
    }

    It 'refuses effective rule scope drift before any approved write' {
        # Arrange
        $fixture = New-IntegratedEmailFixture
        $fixture.Raw['Get-SafeLinksRule'].Items[0].ExceptIfSentTo = @('custom@contoso.example')
        $fixture.Context.Configuration.controls['MDO-001'].settingExceptions = @()

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:emailModule | Where-Object ControlId -CEQ 'MDO-001'

        # Assert
        $result.Result.Status | Should -Not -BeIn @('Pass','ApprovedException')
        $result.Result.Reason | Should -Match 'EmailProtectionPrecedence'
        $global:adapterCalls.Count | Should -Be 0
    }

    It 'refuses missing independent reporting proof before any approved write' {
        # Arrange
        $fixture = New-IntegratedEmailFixture
        $fixture.Context.Parameters.Remove('reportingEvidence')

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:emailModule | Where-Object ControlId -CEQ 'MDO-006'

        # Assert
        $result.Result.Status | Should -Not -Be 'Pass'
        $result.Result.Reason | Should -Match 'ReportingEvidenceMissing'
        $global:adapterCalls.Count | Should -Be 0
    }

    It 'refuses unsupported recipient capability before any approved write' {
        # Arrange
        $fixture = New-IntegratedEmailFixture
        $recipient = @($fixture.Context.Entitlement.recipients | Where-Object address -CEQ 'strict@contoso.example')[0]
        $recipient.servicePlans = @('EXCHANGE_S_ENTERPRISE')

        # Act
        $result = Invoke-ProtectionRawRegistry $fixture $script:emailModule | Where-Object ControlId -CEQ 'MDO-001'

        # Assert
        $result.Result.Status | Should -Not -BeIn @('Pass','ApprovedException')
        $result.Result.Reason | Should -Match 'EmailProtectionNotEntitled'
        $global:adapterCalls.Count | Should -Be 0
    }

    It 'runs one licensed mixed-recipient approved workflow through raw evidence, signing and rollback' {
        # Arrange
        $before = Get-AdapterSnapshot
        $change = New-StatefulAdapterFixture -Scope @('Transport')
        $fixture = New-IntegratedEmailFixture

        # Act
        & $script:adapterCommand -Stage Preview @change -Scope @('Transport') -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Approve @change -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Validate @change | Out-Null
        & $script:deployCommand @change -Apply -SkipConnection -Confirm:$false | Out-Null
        $execution = @(Invoke-ProtectionRawRegistry $fixture $script:emailModule)
        $frozen = New-FrozenEmailEvidence -Fixture $fixture -Execution $execution
        $verifyArguments = $frozen.Arguments
        $verified = Invoke-BaselineExchangeGoLive @verifyArguments
        $rollback = & $script:adapterCommand -Stage Rollback @change -Apply -Confirm:$false

        # Assert
        $matrix = @($execution | Where-Object ControlId -CEQ 'MDO-001')
        $reporting = @($execution | Where-Object ControlId -CEQ 'MDO-006')
        $matrix.Count | Should -Be 1
        $matrix[0].Result.Status | Should -BeExactly 'ApprovedException'
        @($matrix[0].Evidence.Value.Matrix.Recipient | Sort-Object -Unique).Count | Should -BeGreaterThan 1
        @($fixture.Context.Entitlement.recipients | Where-Object { @($_.servicePlans).Count -gt 1 }).Count | Should -BeGreaterThan 1
        $reporting.Count | Should -Be 1
        $reporting[0].Result.Status | Should -BeExactly 'Pass'
        $frozen.Signed.Decision.Admitted | Should -BeTrue -Because ($frozen.Signed.Decision.Finding -join '; ')
        $verified.Decision.Admitted | Should -BeTrue -Because ($verified.Decision.Finding -join '; ')
        $verified.Decision.ExternalReadiness.Status | Should -BeExactly 'Unverified'
        $rollback.Status | Should -BeExactly 'Succeeded'
        (Get-AdapterSnapshot) | Should -BeExactly $before
        @($execution.Evidence.Observation.Command | Where-Object { $_ -match '^(Set|New|Remove|Enable|Disable)-|^[^-]+-(Mg|SPO|Teams)|Graph|AtpPolicyForO365|License' }).Count | Should -Be 0
        @($global:adapterCalls | Where-Object Command -Match 'Mg|SPO|Teams|Graph|AtpPolicyForO365|License').Count | Should -Be 0
    }
}