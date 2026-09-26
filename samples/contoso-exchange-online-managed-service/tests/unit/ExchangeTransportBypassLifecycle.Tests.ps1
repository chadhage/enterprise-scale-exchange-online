#requires -Version 7.0

BeforeAll {
    $script:adapterRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:changeCommand = Join-Path $script:adapterRoot 'scripts/Invoke-ExchangeOnlineChange.ps1'
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

    function New-AuthenticatedSclRule {
        param(
            [string]$Identity = 'Approved Authenticated SCL Exception',
            [string[]]$SenderDomainIs = @('partner.example'),
            [string[]]$SenderIpRanges = @('203.0.113.10/32'),
            [string]$HeaderContainsMessageHeader = 'Authentication-Results',
            [string[]]$HeaderContainsWords = @('dkim=pass', 'dmarc=pass', 'spf=pass'),
            [int]$SetScl = 0
        )

        @{
            Identity = $Identity
            Name = $Identity
            State = 'Enabled'
            Mode = 'Enforce'
            SenderDomainIs = @($SenderDomainIs)
            SenderIpRanges = @($SenderIpRanges)
            HeaderContainsMessageHeader = $HeaderContainsMessageHeader
            HeaderContainsWords = @($HeaderContainsWords)
            SetSCL = $SetScl
            PrependSubject = $null
            Priority = 4
            StopRuleProcessing = $false
        }
    }

    function New-ExternalPrefixRule {
        param([string]$Identity = 'Legacy External Subject Prefix')

        @{
            Identity = $Identity
            Name = $Identity
            State = 'Enabled'
            Mode = 'Enforce'
            SenderDomainIs = @()
            SenderIpRanges = @()
            HeaderContainsMessageHeader = $null
            HeaderContainsWords = @()
            SetSCL = 0
            PrependSubject = '[EXTERNAL] '
            Priority = 5
            StopRuleProcessing = $false
        }
    }

    function Initialize-TransportBypassDoubles {
        Initialize-AdapterDoubles
        $global:adapterState.TransportRule = @(
            (New-AuthenticatedSclRule)
            (New-ExternalPrefixRule)
        )
        $global:transportRuleReads = [Collections.Generic.List[object]]::new()
        $global:transportRuleCollectionFailure = ''
        $global:transportRuleCollectionPartial = $false

        function global:Get-TransportRule {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            $global:transportRuleReads.Add(@{} + $PSBoundParameters)
            $rows = @($global:adapterState.TransportRule | Where-Object {
                    [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -eq $Identity
                })
            if ($global:transportRuleCollectionPartial -and $rows.Count) {
                [pscustomobject]$rows[0].Clone()
                throw 'ChangeReadIncomplete: Get-TransportRule returned a partial paged result.'
            }
            if (-not [string]::IsNullOrWhiteSpace($global:transportRuleCollectionFailure)) {
                throw "ChangeReadIncomplete: Get-TransportRule failed: $global:transportRuleCollectionFailure"
            }
            foreach ($row in $rows) { [pscustomobject]$row.Clone() }
        }
        function global:Set-TransportRule {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [string]$Mode,
                [string[]]$SenderDomainIs,
                [string[]]$SenderIpRanges,
                [AllowNull()][string]$HeaderContainsMessageHeader,
                [string[]]$HeaderContainsWords,
                [int]$SetSCL,
                [AllowNull()][object]$PrependSubject,
                [int]$Priority,
                [bool]$StopRuleProcessing
            )
            Invoke-OfflineAdapterCommand 'Set' 'TransportRule' $PSBoundParameters
        }
        function global:New-TransportRule {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Name,
                [string]$Mode,
                [string[]]$SenderDomainIs,
                [string[]]$SenderIpRanges,
                [AllowNull()][string]$HeaderContainsMessageHeader,
                [string[]]$HeaderContainsWords,
                [int]$SetSCL,
                [AllowNull()][string]$PrependSubject,
                [int]$Priority,
                [bool]$StopRuleProcessing
            )
            Invoke-OfflineAdapterCommand 'New' 'TransportRule' $PSBoundParameters
        }
        function global:Remove-TransportRule {
            [CmdletBinding(SupportsShouldProcess)]
            param([Parameter(Mandatory)][string]$Identity)
            Invoke-OfflineAdapterCommand 'Remove' 'TransportRule' $PSBoundParameters
        }
        $global:adapterCommands.Add('Get-TransportRule')
        $global:adapterCommands.Add('Set-TransportRule')
        $global:adapterCommands.Add('New-TransportRule')
        $global:adapterCommands.Add('Remove-TransportRule')
    }

    function Set-TransportBypassOptions {
        param(
            $Arguments,
            [string[]]$SenderDomains = @('partner.example'),
            [string[]]$SenderIpRanges = @('203.0.113.10/32'),
            [string]$Owner = 'security@contoso.example',
            [string]$Approval = 'SEC-TRANSPORT-001',
            [string]$ExpiresOn = [datetimeoffset]::UtcNow.AddDays(7).ToString('o'),
            [object[]]$PrefixRules = @(@{ identity = 'Legacy External Subject Prefix'; prefix = '[EXTERNAL] '; action = 'Remove' })
        )

        $parameters = Get-Content $Arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions.transportSclExceptions = @(
            @{
                identity = 'Approved Authenticated SCL Exception'
                senderDomains = @($SenderDomains)
                senderIpRanges = @($SenderIpRanges)
                authentication = @{
                    header = 'Authentication-Results'
                    requiredResults = @('spf=pass', 'dkim=pass', 'dmarc=pass')
                }
                setScl = -1
                owner = $Owner
                approval = $Approval
                expiresOn = $ExpiresOn
            }
        )
        $parameters.workflowOptions.externalSubjectPrefixRules = @($PrefixRules)
        $parameters | ConvertTo-Json -Depth 40 | Set-Content $Arguments.ParameterPath
    }

    function New-TransportBypassFixture {
        param([switch]$Approved, [string]$ChangeId = 'TRANSPORT-T01')

        $arguments = New-StatefulAdapterFixture -Scope @('TransportBypass', 'ExternalSender')
        $arguments.ChangeId = $ChangeId
        $arguments.PreviewPath = Join-Path $arguments.ArtifactRoot "preview-$ChangeId.json"
        $arguments.ApprovalPath = Join-Path $arguments.ArtifactRoot "approval-$ChangeId.json"
        Set-TransportBypassOptions -Arguments $arguments
        if ($Approved) { Approve-TransportBypassFixture -Arguments $arguments }
        $arguments
    }

    function Approve-TransportBypassFixture {
        param($Arguments)

        & $script:changeCommand -Stage Preview @Arguments -Scope @('TransportBypass', 'ExternalSender') -Confirm:$false | Out-Null
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
    }

    function Get-IndependentTransportVerdict {
        param($Arguments)

        $parameters = Get-Content $Arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $transportEvidence = Get-TransportBypassEvidence -Collection { @(Get-TransportRule -ResultSize Unlimited) }
        $transport = Test-TransportBypassControl -Evidence $transportEvidence -ApprovedExceptions @($parameters.workflowOptions.transportSclExceptions)
        $externalEvidence = Get-ExternalSenderTagEvidence -Collection { @(Get-ExternalInOutlook)[0] }
        $external = Test-ExternalSenderTagControl -Evidence $externalEvidence -ExpectedAllowList @()
        [pscustomobject]@{ Transport = $transport; External = $external; Evidence = $transportEvidence }
    }

    function Invoke-TransportBypassLifecycle {
        param($Arguments)

        $before = Get-AdapterSnapshot
        Approve-TransportBypassFixture -Arguments $Arguments
        & $script:changeCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:changeCommand -Stage Apply @Arguments -Apply -Confirm:$false
        $readback = Get-IndependentTransportVerdict -Arguments $Arguments
        $applied = Get-AdapterSnapshot
        $writesAfterApply = $global:adapterCalls.Count

        $repeatArguments = New-TransportBypassFixture -ChangeId 'TRANSPORT-T01-REPEAT'
        Approve-TransportBypassFixture -Arguments $repeatArguments
        & $script:changeCommand -Stage Validate @repeatArguments | Out-Null
        $repeat = & $script:changeCommand -Stage Apply @repeatArguments -Apply -Confirm:$false
        $repeatWrites = $global:adapterCalls.Count - $writesAfterApply

        $global:adapterState.TransportRule[0].SenderIpRanges = @('203.0.113.11/32')
        $writesBeforeDrift = $global:adapterCalls.Count
        $drift = $null
        try { & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false | Out-Null } catch { $drift = $_ }
        $driftWrites = $global:adapterCalls.Count - $writesBeforeDrift
        $global:adapterState.TransportRule[0].SenderIpRanges = @('203.0.113.10/32')

        $rollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false
        $writesAfterRollback = $global:adapterCalls.Count
        $repeatedRollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false

        [pscustomobject]@{
            Before = $before
            Apply = $apply
            Applied = $applied
            Readback = $readback
            Repeat = $repeat
            RepeatWrites = $repeatWrites
            Drift = $drift
            DriftWrites = $driftWrites
            Rollback = $rollback
            Restored = Get-AdapterSnapshot
            RepeatedRollback = $repeatedRollback
            RepeatedRollbackWrites = $global:adapterCalls.Count - $writesAfterRollback
        }
    }
}

Describe 'EXR-007-A02-T01 transport bypass and external-tag lifecycle' {
    BeforeEach {
        Initialize-TransportBypassDoubles
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

    Context 'Negative: unsafe or ungoverned transport exceptions refuse before writes' {
        It 'refuses a sender-domain-only unauthenticated SCL bypass' {
            # Arrange
            $arguments = New-TransportBypassFixture
            Set-TransportBypassOptions -Arguments $arguments -SenderIpRanges @()

            # Act
            $invoke = { & $script:changeCommand -Stage Preview @arguments -Scope TransportBypass -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*TransportBypassAuthenticationRequired*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a broad sender IP range' {
            # Arrange
            $arguments = New-TransportBypassFixture
            Set-TransportBypassOptions -Arguments $arguments -SenderIpRanges @('0.0.0.0/0')

            # Act
            $invoke = { & $script:changeCommand -Stage Preview @arguments -Scope TransportBypass -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*TransportBypassScopeTooBroad*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an exception without an accountable owner' {
            # Arrange
            $arguments = New-TransportBypassFixture
            Set-TransportBypassOptions -Arguments $arguments -Owner ''

            # Act
            $invoke = { & $script:changeCommand -Stage Preview @arguments -Scope TransportBypass -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*TransportBypassOwnerRequired*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an exception without an approval reference' {
            # Arrange
            $arguments = New-TransportBypassFixture
            Set-TransportBypassOptions -Arguments $arguments -Approval ''

            # Act
            $invoke = { & $script:changeCommand -Stage Preview @arguments -Scope TransportBypass -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*TransportBypassApprovalRequired*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an expired exception' {
            # Arrange
            $arguments = New-TransportBypassFixture
            Set-TransportBypassOptions -Arguments $arguments -ExpiresOn '2000-01-01T00:00:00Z'

            # Act
            $invoke = { & $script:changeCommand -Stage Preview @arguments -Scope TransportBypass -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*TransportBypassApprovalExpired*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: incomplete, ambiguous, paged, or failed raw reads never pass' {
        It 'refuses a raw transport rule missing an effective action' {
            # Arrange
            $arguments = New-TransportBypassFixture
            $global:adapterState.TransportRule[0].Remove('SetSCL')

            # Act
            $invoke = { & $script:changeCommand -Stage Preview @arguments -Scope TransportBypass -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*TransportRule*SetSCL*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses duplicate normalized transport identities' {
            # Arrange
            $arguments = New-TransportBypassFixture
            $duplicate = $global:adapterState.TransportRule[0].Clone()
            $duplicate.Identity = 'approved authenticated scl exception'
            $duplicate.Name = $duplicate.Identity
            $global:adapterState.TransportRule += $duplicate

            # Act
            $invoke = { & $script:changeCommand -Stage Preview @arguments -Scope TransportBypass -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*Get-TransportRule returned duplicate identities*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses partial output followed by a paging failure' {
            # Arrange
            $arguments = New-TransportBypassFixture
            $global:transportRuleCollectionPartial = $true

            # Act
            $invoke = { & $script:changeCommand -Stage Preview @arguments -Scope TransportBypass -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*partial paged result*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a raw transport collection error' {
            # Arrange
            $arguments = New-TransportBypassFixture
            $global:transportRuleCollectionFailure = 'Access is denied.'

            # Act
            $invoke = { & $script:changeCommand -Stage Preview @arguments -Scope TransportBypass -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*Get-TransportRule failed*Access is denied*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: redundant external subject prefixes and stale approved state refuse' {
        It 'refuses duplicate external subject-prefix rules' {
            # Arrange
            $arguments = New-TransportBypassFixture
            $global:adapterState.TransportRule += New-ExternalPrefixRule -Identity 'Second External Subject Prefix'

            # Act
            $invoke = { & $script:changeCommand -Stage Preview @arguments -Scope @('TransportBypass', 'ExternalSender') -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ExternalSubjectPrefixDuplicate*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses transport drift after signed approval' {
            # Arrange
            $arguments = New-TransportBypassFixture -Approved
            $global:adapterState.TransportRule[0].SenderIpRanges = @('203.0.113.11/32')

            # Act
            $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeStateDrift*'
            $global:adapterCalls.Count | Should -Be 0
            Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-TRANSPORT-T01.json') | Should -BeFalse
        }

        It 'refuses external-tag drift after signed approval' {
            # Arrange
            $arguments = New-TransportBypassFixture -Approved
            $global:adapterState.ExternalInOutlook[0].AllowList = @('unexpected.example')

            # Act
            $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeStateDrift*'
            $global:adapterCalls.Count | Should -Be 0
            Test-Path (Join-Path $arguments.ArtifactRoot 'prechange-TRANSPORT-T01.json') | Should -BeFalse
        }
    }

    Context 'Negative: rollback failures remain typed and bounded' {
        It 'refuses rollback when the current transport state has drifted' {
            # Arrange
            $arguments = New-TransportBypassFixture -Approved
            & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false | Out-Null
            $global:adapterState.TransportRule[0].HeaderContainsWords = @('spf=fail')
            $writesBeforeRollback = $global:adapterCalls.Count

            # Act
            $invoke = { & $script:changeCommand -Stage Rollback @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeStateDrift*'
            ($global:adapterCalls.Count - $writesBeforeRollback) | Should -Be 0
        }

        It 'refuses rollback when independent transport readback fails' {
            # Arrange
            $arguments = New-TransportBypassFixture -Approved
            & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false | Out-Null
            $global:transportRuleCollectionFailure = 'rollback read denied'
            $writesBeforeRollback = $global:adapterCalls.Count

            # Act
            $invoke = { & $script:changeCommand -Stage Rollback @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*rollback read denied*'
            ($global:adapterCalls.Count - $writesBeforeRollback) | Should -Be 0
        }

        It 'records a typed rollback failure when restoration is refused' {
            # Arrange
            $arguments = New-TransportBypassFixture -Approved
            & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false | Out-Null
            $global:adapterWriteFault = 'Set-TransportRule'

            # Act
            $invoke = { & $script:changeCommand -Stage Rollback @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeExecutionFailed*Set-TransportRule*'
            @(Get-ChildItem $arguments.ArtifactRoot -Filter 'rollback-attempt-*.json').Count | Should -Be 1
        }
    }

    Context 'Positive: independent raw transport evaluation' {
        It 'passes one authenticated narrow SCL exception without a duplicate external prefix' {
            # Arrange
            $arguments = New-TransportBypassFixture
            $global:adapterState.TransportRule[0].SetSCL = -1
            $global:adapterState.TransportRule = @($global:adapterState.TransportRule[0])
            $global:adapterState.ExternalInOutlook[0].Enabled = $true
            $global:adapterState.ExternalInOutlook[0].AllowList = @()

            # Act
            $result = Get-IndependentTransportVerdict -Arguments $arguments

            # Assert
            $result.Transport.Status | Should -BeExactly 'Pass'
            $result.External.Status | Should -BeExactly 'Pass'
            $result.Evidence.Command | Should -BeExactly 'Get-TransportRule'
            @($result.Evidence.Value).Count | Should -Be 1
            @($global:transportRuleReads | Where-Object ResultSize -CEQ 'Unlimited').Count | Should -BeGreaterThan 0
        }
    }

    Context 'Positive: signed shared atomic lifecycle' {
        It 'applies, reads back, no-ops, refuses drift, and rolls back typed transport state without TABL mutation' {
            # Arrange
            $arguments = New-TransportBypassFixture

            # Act
            $result = Invoke-TransportBypassLifecycle -Arguments $arguments

            # Assert
            $result.Apply.Status | Should -BeExactly 'Succeeded'
            $result.Readback.Transport.Status | Should -BeExactly 'Pass'
            $result.Readback.External.Status | Should -BeExactly 'Pass'
            $result.Applied | Should -Match '"SetSCL":-1'
            $result.Applied | Should -Not -Match '\[EXTERNAL\]'
            $result.Repeat.Status | Should -BeExactly 'Succeeded'
            $result.RepeatWrites | Should -Be 0
            $result.Drift.Exception.Message | Should -BeLike '*ChangeStateDrift*'
            $result.DriftWrites | Should -Be 0
            $result.Rollback.Status | Should -BeExactly 'Succeeded'
            $result.Restored | Should -BeExactly $result.Before
            $result.RepeatedRollback.Status | Should -BeExactly 'Succeeded'
            $result.RepeatedRollbackWrites | Should -Be 0
            $global:adapterState.TransportRule[0].SetSCL | Should -BeOfType [int]
            $global:adapterState.TransportRule[0].SenderDomainIs | Should -BeOfType [object[]]
            @($global:adapterCalls | Where-Object Command -Match 'TenantAllowBlockList').Count | Should -Be 0
        }
    }
}

AfterAll {
    foreach ($name in @($global:adapterCommands) + @('Get-ConnectionInformation', 'Invoke-OfflineAdapterCommand')) {
        Remove-Item "Function:global:$name" -ErrorAction SilentlyContinue
    }
    $script:adapterCertificate.Dispose()
    $script:adapterKey.Dispose()
    Get-Variable -Name 'adapter*' -Scope Global | Remove-Variable -Scope Global
    Get-Variable -Name 'transportRule*' -Scope Global | Remove-Variable -Scope Global
    Remove-Module ExchangeOnlineBaseline.Common -Force -ErrorAction SilentlyContinue
}