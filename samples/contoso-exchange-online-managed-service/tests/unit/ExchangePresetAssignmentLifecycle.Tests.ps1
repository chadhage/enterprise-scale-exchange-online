#requires -Version 7.0

BeforeAll {
    $script:adapterRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:adapterCommand = Join-Path $script:adapterRoot 'scripts/Invoke-ExchangeOnlineChange.ps1'
    Import-Module (Join-Path $script:adapterRoot 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking
    . (Join-Path $PSScriptRoot '../helpers/ApprovedAdapterDoubles.ps1')

    $script:adapterKey = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Offline Adapter', $script:adapterKey, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $script:adapterCertificate = $request.CreateSelfSigned([datetimeoffset]::UtcNow.AddMinutes(-1), [datetimeoffset]::UtcNow.AddDays(1))
    $script:presetScope = @('EopPresets', 'AtpPresets', 'BuiltInProtection')
    $script:presetFields = @('RecipientDomainIs', 'SentTo', 'SentToMemberOf', 'ExceptIfRecipientDomainIs', 'ExceptIfSentTo', 'ExceptIfSentToMemberOf')

    function Initialize-CompletePresetAssignmentDoubles {
        Initialize-AdapterDoubles
        foreach ($noun in @('EOPProtectionPolicyRule', 'ATPProtectionPolicyRule')) {
            foreach ($rule in $global:adapterState[$noun]) {
                foreach ($field in $script:presetFields) {
                    if (-not $rule.ContainsKey($field)) { $rule[$field] = @() }
                }
            }
            $setBody = @'
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Identity,
    [string[]]$RecipientDomainIs,
    [string[]]$SentTo,
    [string[]]$SentToMemberOf,
    [string[]]$ExceptIfRecipientDomainIs,
    [string[]]$ExceptIfSentTo,
    [string[]]$ExceptIfSentToMemberOf
)
Invoke-OfflineAdapterCommand 'Set' '__NOUN__' $PSBoundParameters
'@ -replace '__NOUN__', $noun
            Set-Item "Function:global:Set-$noun" ([scriptblock]::Create($setBody))
        }
    }

    function New-ApprovedPresetAssignmentFixture {
        param([scriptblock]$Configure)

        $arguments = New-StatefulAdapterFixture -Scope $script:presetScope
        if ($null -ne $Configure) { & $Configure $arguments }
        & $script:adapterCommand -Stage Preview @arguments -Scope $script:presetScope -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Approve @arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
        $arguments
    }

    function Invoke-PresetAssignmentLifecycle {
        param($Arguments)

        $before = Get-AdapterSnapshot
        & $script:adapterCommand -Stage Preview @Arguments -Scope $script:presetScope -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:adapterCommand -Stage Apply @Arguments -Apply -Confirm:$false
        $afterApply = $global:adapterState | ConvertTo-Json -Depth 40 | ConvertFrom-Json -AsHashtable -DateKind String
        $writesAfterApply = $global:adapterCalls.Count
        $repeatArguments = New-StatefulAdapterFixture -Scope $script:presetScope
        $repeatArguments.ChangeId = 'ADAPTER004-REPEAT'
        $repeatArguments.PreviewPath = Join-Path $repeatArguments.ArtifactRoot 'preview-ADAPTER004-REPEAT.json'
        $repeatArguments.ApprovalPath = Join-Path $repeatArguments.ArtifactRoot 'approval-ADAPTER004-REPEAT.json'
        & $script:adapterCommand -Stage Preview @repeatArguments -Scope $script:presetScope -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Approve @repeatArguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
        & $script:adapterCommand -Stage Validate @repeatArguments | Out-Null
        $repeat = & $script:adapterCommand -Stage Apply @repeatArguments -Apply -Confirm:$false
        $repeatWrites = $global:adapterCalls.Count - $writesAfterApply

        $standardEop = @($global:adapterState.EOPProtectionPolicyRule | Where-Object Identity -CEQ 'Standard Preset Security Policy')[0]
        $standardEop.SentTo = @('drift@example.test')
        $writesBeforeDriftCheck = $global:adapterCalls.Count
        $driftFailure = $null
        try { & $script:adapterCommand -Stage Rollback @Arguments -Apply -Confirm:$false | Out-Null } catch { $driftFailure = $_ }
        $writesDuringDriftCheck = $global:adapterCalls.Count - $writesBeforeDriftCheck
        $standardEop.SentTo = @()

        $rollback = & $script:adapterCommand -Stage Rollback @Arguments -Apply -Confirm:$false
        $writesAfterRollback = $global:adapterCalls.Count
        $repeatedRollback = & $script:adapterCommand -Stage Rollback @Arguments -Apply -Confirm:$false

        [pscustomobject]@{
            ApplyStatus            = $apply.Status
            AfterApply             = $afterApply
            RepeatStatus           = $repeat.Status
            RepeatWrites           = $repeatWrites
            DriftMessage           = $driftFailure.Exception.Message
            DriftWrites            = $writesDuringDriftCheck
            RollbackStatus         = $rollback.Status
            RestoredSnapshot       = Get-AdapterSnapshot
            BeforeSnapshot         = $before
            RepeatedRollbackStatus = $repeatedRollback.Status
            RepeatedRollbackWrites = $global:adapterCalls.Count - $writesAfterRollback
            Commands               = @($global:adapterCalls.Command)
        }
    }
}

Describe 'EXR-010-A04 exact preset assignment lifecycle' {
    BeforeEach {
        Initialize-CompletePresetAssignmentDoubles
        Mock Test-BaselineDetachedCmsSignature -ModuleName ExchangeOnlineBaseline.Common {
            param($CanonicalBytes, $Signature)
            $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($CanonicalBytes), $true)
            $cms.Decode([Convert]::FromBase64String($Signature.Value))
            $cms.CheckSignature($true)
            @{ Verified = $true; SignerSubject = $cms.SignerInfos[0].Certificate.Subject; SigningTimeUtc = [datetimeoffset]::UtcNow; CertificateNotBeforeUtc = [datetimeoffset]::UtcNow.AddDays(-1); CertificateNotAfterUtc = [datetimeoffset]::UtcNow.AddDays(1); ChainTrusted = $true; RevocationStatus = 'Good' }
        }
    }

    It 'refuses a missing preset before writes' {
        # Arrange
        $global:adapterState.EOPProtectionPolicyRule = @($global:adapterState.EOPProtectionPolicyRule | Where-Object Identity -CNE 'Standard Preset Security Policy')
        $arguments = New-StatefulAdapterFixture -Scope $script:presetScope

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope $script:presetScope -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ChangeReadIncomplete*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses residual preset scope before writes' {
        # Arrange
        $standardEop = @($global:adapterState.EOPProtectionPolicyRule | Where-Object Identity -CEQ 'Standard Preset Security Policy')[0]
        $standardEop.SentTo = @('residual@example.test')
        $arguments = New-StatefulAdapterFixture -Scope $script:presetScope

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope $script:presetScope -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ChangePresetScopeResidual*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses an unauthorized preset exclusion before writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope $script:presetScope
        $configuration = Get-Content $arguments.ConfigurationPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $configuration.controls['MDO-001'].excludedGroups = @('unapproved-group@contoso.example')
        $configuration.controls['MDO-001'].excludedSecOpsMailbox = @('unapproved-mailbox@contoso.example')
        $configuration | ConvertTo-Json -Depth 60 | Set-Content $arguments.ConfigurationPath

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope $script:presetScope -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ChangePresetExclusionUnapproved*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'refuses an unlicensed ATP assignment before writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope $script:presetScope
        $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE')
        foreach ($recipient in $parameters.entitlement.recipients) { $recipient.servicePlans = @('EXCHANGE_S_ENTERPRISE') }
        $parameters | ConvertTo-Json -Depth 30 | Set-Content $arguments.ParameterPath

        # Act
        $invoke = { & $script:adapterCommand -Stage Preview @arguments -Scope $script:presetScope -Confirm:$false }

        # Assert
        $invoke | Should -Throw '*ChangeScopeNotEntitled*'
        $global:adapterCalls.Count | Should -Be 0
        Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-ADAPTER004.json') | Should -BeFalse
    }

    It 'round trips exact EOP and ATP preset assignments without collaboration writes' {
        # Arrange
        $arguments = New-StatefulAdapterFixture -Scope $script:presetScope
        $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $primaryDomain = $parameters.PRIMARY_SMTP_DOMAIN
        $priorityGroup = $parameters.MAIL_ENABLED_PRIORITY_USERS_GROUP
        $secOpsMailbox = $parameters.SECURITY_OPERATIONS_MAILBOX

        # Act
        $result = Invoke-PresetAssignmentLifecycle -Arguments $arguments

        # Assert
        $result.ApplyStatus | Should -BeExactly 'Succeeded'
        foreach ($noun in @('EOPProtectionPolicyRule', 'ATPProtectionPolicyRule')) {
            $standard = @($result.AfterApply[$noun] | Where-Object Identity -CEQ 'Standard Preset Security Policy')[0]
            $strict = @($result.AfterApply[$noun] | Where-Object Identity -CEQ 'Strict Preset Security Policy')[0]
            @($standard.RecipientDomainIs) | Should -BeExactly @($primaryDomain)
            @($standard.ExceptIfSentToMemberOf) | Should -BeExactly @($priorityGroup)
            @($standard.ExceptIfSentTo) | Should -BeExactly @($secOpsMailbox)
            @($standard.SentTo) | Should -BeNullOrEmpty
            @($standard.SentToMemberOf) | Should -BeNullOrEmpty
            @($standard.ExceptIfRecipientDomainIs) | Should -BeNullOrEmpty
            $standard.State | Should -BeExactly 'Enabled'
            @($strict.SentToMemberOf) | Should -BeExactly @($priorityGroup)
            foreach ($field in @('RecipientDomainIs', 'SentTo', 'ExceptIfRecipientDomainIs', 'ExceptIfSentTo', 'ExceptIfSentToMemberOf')) {
                @($strict[$field]) | Should -BeNullOrEmpty
            }
            $strict.State | Should -BeExactly 'Enabled'
        }
        $result.RepeatStatus | Should -BeExactly 'Succeeded'
        $result.RepeatWrites | Should -Be 0
        $result.DriftMessage | Should -BeLike '*ChangeStateDrift*'
        $result.DriftWrites | Should -Be 0
        $result.RollbackStatus | Should -BeExactly 'Succeeded'
        $result.RestoredSnapshot | Should -BeExactly $result.BeforeSnapshot
        $result.RepeatedRollbackStatus | Should -BeExactly 'Succeeded'
        $result.RepeatedRollbackWrites | Should -Be 0
        @($result.Commands | Where-Object { $_ -match 'Mg|Graph|SPO|SharePoint|OneDrive|Teams|SafeDocs|AtpPolicyForO365' }).Count | Should -Be 0
    }
}

AfterAll {
    foreach ($command in @($global:adapterCommands)) { Remove-Item "Function:global:$command" -ErrorAction SilentlyContinue }
    Remove-Item Function:global:Get-ConnectionInformation -ErrorAction SilentlyContinue
    Remove-Item Function:global:Invoke-OfflineAdapterCommand -ErrorAction SilentlyContinue
    Remove-Variable -Name adapterCalls,adapterCommands,adapterState,adapterWriteFault,adapterReadFault,adapterReadbackFault,adapterMissingCommand -Scope Global -ErrorAction SilentlyContinue
    if ($null -ne $script:adapterCertificate) { $script:adapterCertificate.Dispose() }
    if ($null -ne $script:adapterKey) { $script:adapterKey.Dispose() }
}