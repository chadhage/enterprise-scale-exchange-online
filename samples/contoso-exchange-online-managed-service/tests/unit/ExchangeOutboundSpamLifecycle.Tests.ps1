BeforeAll {
    $script:root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:adapterRoot = $script:root
    $script:changeCommand = Join-Path $script:root 'scripts/Invoke-ExchangeOnlineChange.ps1'
    $script:deployCommand = Join-Path $script:root 'scripts/Deploy-ExchangeOnlineBaseline.ps1'
    Import-Module (Join-Path $script:root 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking
    . (Join-Path $PSScriptRoot '../helpers/ApprovedAdapterDoubles.ps1')

    $script:signingKey = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Offline Outbound Lifecycle',
        $script:signingKey,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $script:signingCertificate = $request.CreateSelfSigned(
        [datetimeoffset]::UtcNow.AddMinutes(-1),
        [datetimeoffset]::UtcNow.AddDays(1)
    )

    function Initialize-OutboundSpamDoubles {
        Initialize-AdapterDoubles
        $global:adapterState.HostedOutboundSpamFilterPolicy = @(@{
            Identity = 'Contoso Strict Outbound'
            RecipientLimitExternalPerHour = 900
            RecipientLimitInternalPerHour = 1800
            RecipientLimitPerDay = 1800
            ActionWhenThresholdReached = 'Alert'
            AutoForwardingMode = 'Automatic'
            BccSuspiciousOutboundMail = $true
            BccSuspiciousOutboundAdditionalRecipients = @('audit@contoso.example')
            NotifyOutboundSpam = $true
            NotifyOutboundSpamRecipients = @('notify@contoso.example')
        })
        $global:adapterState.HostedOutboundSpamFilterRule = @(@{
            Identity = 'Contoso Strict Outbound Rule'
            HostedOutboundSpamFilterPolicy = 'Contoso Strict Outbound'
            State = 'Enabled'
            From = @('legacy@contoso.example')
            FromMemberOf = @()
            SenderDomainIs = @()
            ExceptIfFrom = @()
            ExceptIfFromMemberOf = @()
            ExceptIfSenderDomainIs = @()
        })

        function global:Get-HostedOutboundSpamFilterPolicy {
            [CmdletBinding()]
            param([string]$Identity)
            Invoke-OfflineAdapterCommand 'Get' 'HostedOutboundSpamFilterPolicy' $PSBoundParameters
        }
        function global:Set-HostedOutboundSpamFilterPolicy {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [int]$RecipientLimitExternalPerHour,
                [int]$RecipientLimitInternalPerHour,
                [int]$RecipientLimitPerDay,
                [string]$ActionWhenThresholdReached,
                [string]$AutoForwardingMode,
                [bool]$BccSuspiciousOutboundMail,
                [string[]]$BccSuspiciousOutboundAdditionalRecipients,
                [bool]$NotifyOutboundSpam,
                [string[]]$NotifyOutboundSpamRecipients
            )
            Invoke-OfflineAdapterCommand 'Set' 'HostedOutboundSpamFilterPolicy' $PSBoundParameters
        }
        function global:Get-HostedOutboundSpamFilterRule {
            [CmdletBinding()]
            param([string]$Identity)
            Invoke-OfflineAdapterCommand 'Get' 'HostedOutboundSpamFilterRule' $PSBoundParameters
        }
        function global:Set-HostedOutboundSpamFilterRule {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [string[]]$From,
                [string[]]$FromMemberOf,
                [string[]]$SenderDomainIs,
                [string[]]$ExceptIfFrom,
                [string[]]$ExceptIfFromMemberOf,
                [string[]]$ExceptIfSenderDomainIs
            )
            Invoke-OfflineAdapterCommand 'Set' 'HostedOutboundSpamFilterRule' $PSBoundParameters
        }
    }

    function New-OutboundSpamFixture {
        param(
            [string]$TestDrive,
            [string]$PolicyIdentity = 'Contoso Strict Outbound',
            [switch]$IncompleteSettings,
            [switch]$MismatchedScope,
            [switch]$Approved
        )
        $arguments = New-StatefulAdapterFixture -Scope OutboundSpam
        $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions.outboundSpam = @{
            policyIdentity = $PolicyIdentity
            ruleIdentity = 'Contoso Strict Outbound Rule'
            profile = 'Strict'
            settings = @{
                RecipientLimitExternalPerHour = 400
                RecipientLimitInternalPerHour = 800
                RecipientLimitPerDay = 800
                ActionWhenThresholdReached = 'BlockUser'
                AutoForwardingMode = 'Off'
                BccSuspiciousOutboundMail = $false
                BccSuspiciousOutboundAdditionalRecipients = @()
                NotifyOutboundSpam = $false
                NotifyOutboundSpamRecipients = @()
            }
            senderScope = @{
                From = @('strict@contoso.example')
                FromMemberOf = @()
                SenderDomainIs = @()
                ExceptIfFrom = @()
                ExceptIfFromMemberOf = @()
                ExceptIfSenderDomainIs = @()
            }
        }
        if ($IncompleteSettings) {
            $parameters.workflowOptions.outboundSpam.settings.Remove('RecipientLimitPerDay')
        }
        $parameters | ConvertTo-Json -Depth 30 | Set-Content $arguments.ParameterPath
        if ($MismatchedScope) {
            $global:adapterState.HostedOutboundSpamFilterRule[0].From = @('other@contoso.example')
        }
        if ($Approved) {
            & $script:changeCommand -Stage Preview @arguments -Scope OutboundSpam -Confirm:$false | Out-Null
            & $script:changeCommand -Stage Approve @arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
        }
        $arguments
    }

    function Invoke-OutboundSpamLifecycle {
        param($Arguments)
        $before = Get-AdapterSnapshot
        & $script:changeCommand -Stage Preview @Arguments -Scope OutboundSpam -Confirm:$false | Out-Null
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
        & $script:changeCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:deployCommand @Arguments -Apply -SkipConnection -Confirm:$false
        $applied = Get-AdapterSnapshot
        $writesAfterApply = $global:adapterCalls.Count
        $secondApply = & $script:deployCommand @Arguments -Apply -SkipConnection -Confirm:$false
        $noOpWrites = $global:adapterCalls.Count - $writesAfterApply
        $global:adapterState.HostedOutboundSpamFilterPolicy[0].AutoForwardingMode = 'Automatic'
        $drift = $null
        try { & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false | Out-Null } catch { $drift = $_ }
        $global:adapterState.HostedOutboundSpamFilterPolicy[0].AutoForwardingMode = 'Off'
        $rollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false
        $writesAfterRollback = $global:adapterCalls.Count
        $repeatedRollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false
        @{
            Before = $before
            Applied = $applied
            After = Get-AdapterSnapshot
            Apply = $apply
            SecondApply = $secondApply
            NoOpWrites = $noOpWrites
            Drift = $drift
            Rollback = $rollback
            RepeatedRollback = $repeatedRollback
            RepeatedRollbackWrites = $global:adapterCalls.Count - $writesAfterRollback
        }
    }
}

Describe 'EXR-010-A05 approved outbound spam lifecycle' {
    BeforeEach {
        Initialize-OutboundSpamDoubles
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

    It 'refuses an unapproved outbound policy identity before writes' {
        # Arrange
        $arguments = New-OutboundSpamFixture -TestDrive $TestDrive -PolicyIdentity Default -Approved

        # Act
        $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*OutboundSpamIdentityUnapproved*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses incomplete outbound limits and actions before writes' {
        # Arrange
        $arguments = New-OutboundSpamFixture -TestDrive $TestDrive -IncompleteSettings -Approved

        # Act
        $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*OutboundSpamSettingsIncomplete*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses mismatched outbound sender scope before writes' {
        # Arrange
        $arguments = New-OutboundSpamFixture -TestDrive $TestDrive -MismatchedScope -Approved

        # Act
        $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*OutboundSpamSenderScopeMismatch*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses missing outbound readback before writes' {
        # Arrange
        $arguments = New-OutboundSpamFixture -TestDrive $TestDrive -Approved
        $global:adapterReadFault = 'HostedOutboundSpamFilterPolicy'

        # Act
        $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ChangeReadIncomplete*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'round trips all nine approved outbound settings and sender scope' {
        # Arrange
        $arguments = New-OutboundSpamFixture -TestDrive $TestDrive
        $expectedSettings = @{
            RecipientLimitExternalPerHour = 400
            RecipientLimitInternalPerHour = 800
            RecipientLimitPerDay = 800
            ActionWhenThresholdReached = 'BlockUser'
            AutoForwardingMode = 'Off'
            BccSuspiciousOutboundMail = $false
            BccSuspiciousOutboundAdditionalRecipients = @()
            NotifyOutboundSpam = $false
            NotifyOutboundSpamRecipients = @()
        }

        # Act
        $result = Invoke-OutboundSpamLifecycle -Arguments $arguments

        # Assert
        $result.Apply.Status | Should -BeExactly 'Succeeded'
        foreach ($field in $expectedSettings.Keys) {
            $result.Applied | Should -Match ([regex]::Escape($field))
            $global:adapterState.HostedOutboundSpamFilterPolicy[0][$field] | Should -Be $expectedSettings[$field]
        }
        $result.Applied | Should -Match 'strict@contoso\.example'
        $result.SecondApply.Status | Should -BeExactly 'Succeeded'
        $result.NoOpWrites | Should -Be 0
        $result.Drift.Exception.Message | Should -BeLike '*ChangeStateDrift*'
        $result.Rollback.Status | Should -BeExactly 'Succeeded'
        $result.After | Should -BeExactly $result.Before
        $result.RepeatedRollback.Status | Should -BeExactly 'Succeeded'
        $result.RepeatedRollbackWrites | Should -Be 0
    }
}