BeforeAll {
    $script:adapterRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:adapterCommand = Join-Path $script:adapterRoot 'scripts/Invoke-ExchangeOnlineChange.ps1'
    $script:governanceModule = Import-Module (Join-Path $script:adapterRoot 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -PassThru
    . (Join-Path $script:adapterRoot 'tests/helpers/ExchangeGovernanceRawFixture.ps1')
    . (Join-Path $script:adapterRoot 'tests/helpers/ApprovedAdapterDoubles.ps1')
    $script:adapterKey = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Offline Adapter', $script:adapterKey, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $script:adapterCertificate = $request.CreateSelfSigned([datetimeoffset]::UtcNow.AddMinutes(-1), [datetimeoffset]::UtcNow.AddDays(1))
    function New-GovernanceAdapterContext {
        $parameters = Get-Content (Join-Path $script:adapterRoot 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
        $fixture = New-ExchangeGovernanceRawFixture $parameters
        @{ Configuration = $fixture.Configuration; Parameters = $parameters; Entitlement = @{ servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE') } }
    }
    function New-GovernanceRoundTripFixture {
        param([string]$Scope, [switch]$Approved)
        $arguments = New-StatefulAdapterFixture -Scope $Scope
        $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable
        $fixture = New-ExchangeGovernanceRawFixture $parameters
        $arguments.ConfigurationPath = Join-Path $arguments.ArtifactRoot 'governance.json'
        $fixture.Configuration | ConvertTo-Json -Depth 60 | Set-Content $arguments.ConfigurationPath
        foreach ($noun in @('Mailbox','RetentionPolicy','RetentionPolicyTag','IRMConfiguration','TransportRule')) {
            $global:adapterState[$noun] = @($fixture.Raw["Get-$noun"].Items)
        }
        $global:adapterState.Mailbox[0].Identity = $global:adapterState.Mailbox[0].PrimarySmtpAddress
        $global:adapterState.Mailbox[0].RoleAssignmentPolicy = 'Previous approved policy'
        $global:adapterState.Mailbox[0].RetentionPolicy = 'Previous lifecycle'
        $global:adapterState.RetentionPolicyTag[0].AgeLimitForRetention = [timespan]::FromDays(730)
        $global:adapterState.RetentionPolicy[0].RetentionPolicyTagLinks = @('Previous tag')
        $global:adapterState.IRMConfiguration[0].TransportDecryptionSetting = 'Optional'
        $global:adapterState.TransportRule[0].Mode = 'Audit'
        $specifications = @(
            @{ Noun = 'Mailbox'; Fields = '[string]$RoleAssignmentPolicy,[AllowNull()][string]$RetentionPolicy' }
            @{ Noun = 'RetentionPolicy'; Fields = '[string[]]$RetentionPolicyTagLinks' }
            @{ Noun = 'RetentionPolicyTag'; Fields = '[string]$RetentionAction,[timespan]$AgeLimitForRetention,[bool]$RetentionEnabled' }
            @{ Noun = 'IRMConfiguration'; Fields = '[bool]$InternalLicensingEnabled,[bool]$AzureRMSLicensingEnabled,[string]$TransportDecryptionSetting,[bool]$JournalReportDecryptionEnabled' }
            @{ Noun = 'TransportRule'; Fields = '[string]$Mode,[string]$HeaderContainsMessageHeader,[string[]]$HeaderContainsWords,[string[]]$SentTo,[string]$ApplyRightsProtectionTemplate' }
        )
        foreach ($spec in $specifications) {
            foreach ($verb in @('Get','Set')) {
                $name = "$verb-$($spec.Noun)"
                $fields = if ($verb -eq 'Set') { ',' + $spec.Fields } else { '' }
                $body = "[CmdletBinding(SupportsShouldProcess)]param([string]`$Identity$fields) Invoke-OfflineAdapterCommand '$verb' '$($spec.Noun)' `$PSBoundParameters"
                Set-Item "Function:global:$name" ([scriptblock]::Create($body))
                if ($name -notin $global:adapterCommands) { $global:adapterCommands.Add($name) }
            }
        }
        if ($Approved) {
            & $script:adapterCommand -Stage Preview @arguments -Scope $Scope -Confirm:$false | Out-Null
            & $script:adapterCommand -Stage Approve @arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
        }
        $arguments
    }
}

Describe 'EXR-009 approved governance adapter admission' {
    It 'rejects absent external approval for <Scope>' -ForEach @(
        @{ Scope = 'GovernanceMailboxPolicy'; Control = 'EXO-010' }
        @{ Scope = 'GovernanceMrm'; Control = 'GOV-003' }
        @{ Scope = 'GovernanceEncryption'; Control = 'GOV-005' }
    ) {
        $context = New-GovernanceAdapterContext
        $context.Configuration.controls[$Control].Remove('approval')
        { & $script:governanceModule { param($context,$scope) @(Get-ApprovedAdapterDefinitions $context @($scope) -DesiredOnly) } $context $Scope } | Should -Throw '*ApprovalMissing*'
    }

    It 'rejects Purview semantics in the MRM adapter' {
        $context = New-GovernanceAdapterContext
        $context.Configuration.controls['GOV-003'].policyType = 'PurviewRetention'
        { & $script:governanceModule { param($context) @(Get-ApprovedAdapterDefinitions $context @('GovernanceMrm') -DesiredOnly) } $context } | Should -Throw '*PolicyTypeInvalid*'
    }

    It 'rejects unapproved transport decryption in the encryption adapter' {
        $context = New-GovernanceAdapterContext
        $context.Configuration.controls['GOV-005'].transportDecryptionSetting = 'Mandatory'
        { & $script:governanceModule { param($context) @(Get-ApprovedAdapterDefinitions $context @('GovernanceEncryption') -DesiredOnly) } $context } | Should -Throw '*DecryptionUnapproved*'
    }

    It 'builds existing-object-only operations for all three approved governance contracts' {
        $context = New-GovernanceAdapterContext
        $definitions = & $script:governanceModule { param($context) @(Get-ApprovedAdapterDefinitions $context @('GovernanceMailboxPolicy','GovernanceMrm','GovernanceEncryption') -DesiredOnly) } $context
        $definitions.Count | Should -BeGreaterThan 5
        @($definitions | Where-Object { $_.New -or $_.Remove -or $_.Delete }).Count | Should -Be 0
        @($definitions | ForEach-Object { $_['Set'] }) | Should -Contain 'Set-Mailbox'
        @($definitions | ForEach-Object { $_['Set'] }) | Should -Contain 'Set-RetentionPolicyTag'
        @($definitions | ForEach-Object { $_['Set'] }) | Should -Contain 'Set-TransportRule'
        @($definitions | ForEach-Object { $_['Set'] }) | Should -Contain 'Set-IRMConfiguration'
    }
}

Describe 'EXR-009 public governance change and rollback' {
    BeforeEach {
        Initialize-AdapterDoubles
        Mock Test-BaselineDetachedCmsSignature -ModuleName ExchangeOnlineBaseline.Common {
            param($CanonicalBytes, $Signature)
            $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($CanonicalBytes), $true)
            $cms.Decode([Convert]::FromBase64String($Signature.Value))
            $cms.CheckSignature($true)
            @{ Verified = $true; SignerSubject = $cms.SignerInfos[0].Certificate.Subject; SigningTimeUtc = [datetimeoffset]::UtcNow; CertificateNotBeforeUtc = [datetimeoffset]::UtcNow.AddDays(-1); CertificateNotAfterUtc = [datetimeoffset]::UtcNow.AddDays(1); ChainTrusted = $true; RevocationStatus = 'Good' }
        }
    }
    AfterEach {
        foreach ($name in $global:adapterCommands) { Remove-Item "Function:global:$name" -ErrorAction SilentlyContinue }
        Remove-Item Function:global:Get-ConnectionInformation -ErrorAction SilentlyContinue
    }
    AfterAll { $script:adapterCertificate.Dispose(); $script:adapterKey.Dispose() }
    It 'refuses a wrong immutable tag type before preview' {
        $arguments = New-GovernanceRoundTripFixture GovernanceMrm
        $global:adapterState.RetentionPolicyTag[0].Type = 'DeletedItems'
        { & $script:adapterCommand -Stage Preview @arguments -Scope GovernanceMrm -Confirm:$false } | Should -Throw '*ChangeGovernancePrerequisite*'
        $global:adapterCalls.Count | Should -Be 0
    }
    It 'refuses an unapproved rule exception before preview' {
        $arguments = New-GovernanceRoundTripFixture GovernanceEncryption
        $global:adapterState.TransportRule[0].Exceptions = @(@{ Name = 'SentTo' })
        { & $script:adapterCommand -Stage Preview @arguments -Scope GovernanceEncryption -Confirm:$false } | Should -Throw '*ChangeGovernancePrerequisite*'
        $global:adapterCalls.Count | Should -Be 0
    }
    Context '<Scope> lifecycle' -ForEach @(
        @{ Scope = 'GovernanceMailboxPolicy'; Noun = 'Mailbox'; Field = 'RoleAssignmentPolicy' }
        @{ Scope = 'GovernanceMrm'; Noun = 'RetentionPolicyTag'; Field = 'RetentionAction' }
        @{ Scope = 'GovernanceEncryption'; Noun = 'TransportRule'; Field = 'Mode' }
    ) {
        It 'rejects changed authorization before any mutation' {
            $arguments = New-GovernanceRoundTripFixture $Scope -Approved
            $configuration = Get-Content $arguments.ConfigurationPath -Raw | ConvertFrom-Json -AsHashtable
            $configuration.controls['EXO-010'].approval.reference = 'changed-after-signing'
            $configuration | ConvertTo-Json -Depth 60 | Set-Content $arguments.ConfigurationPath
            { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false } | Should -Throw '*ChangePreviewBindingMismatch*'
            $global:adapterCalls.Count | Should -Be 0
        }
        It 'rejects missing preflight properties before mutation' {
            $arguments = New-GovernanceRoundTripFixture $Scope -Approved
            $global:adapterState[$Noun][0].Remove($Field)
            { & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeReadIncomplete*'
            $global:adapterCalls.Count | Should -Be 0
        }
        It 'refuses rollback over a later administrator change' {
            $arguments = New-GovernanceRoundTripFixture $Scope -Approved
            & $script:adapterCommand -Stage Apply @arguments -Apply -Confirm:$false | Out-Null
            $global:adapterState[$Noun][0][$Field] = 'Later administrator value'
            $writes = $global:adapterCalls.Count
            { & $script:adapterCommand -Stage Rollback @arguments -Apply -Confirm:$false } | Should -Throw '*ChangeStateDrift*'
            $global:adapterCalls.Count | Should -Be $writes
        }
        It 'round trips the approved scope without changing unrelated fields' {
            $arguments = New-GovernanceRoundTripFixture $Scope
            $before = Get-AdapterSnapshot
            $result = Invoke-AdapterRoundTrip -Arguments $arguments -Scope $Scope
            $result.Status | Should -BeExactly Succeeded
            $result.RepeatedWrites | Should -Be 0
            Get-AdapterSnapshot | Should -BeExactly $before
            $global:adapterCalls.Count | Should -BeGreaterThan 0
            @($global:adapterCalls.Command | Where-Object { $_ -match 'Compliance|Label|Dlp|Graph|Litigation' }).Count | Should -Be 0
        }
    }
}