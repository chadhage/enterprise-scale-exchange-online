#requires -Version 7.0

BeforeAll {
    $script:adapterRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:changeCommand = Join-Path $script:adapterRoot 'scripts/Invoke-ExchangeOnlineChange.ps1'
    Import-Module (Join-Path $script:adapterRoot 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking
    . (Join-Path $PSScriptRoot '../helpers/ApprovedAdapterDoubles.ps1')

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

    function Initialize-OrganizationAllowListDoubles {
        Initialize-AdapterDoubles
        $global:adapterState.HostedConnectionFilterPolicy = @(@{
            Identity = 'Default'
            Name = 'Default'
            IPAllowList = @('198.51.100.8/32')
            EnableSafeList = $false
        })
        $global:adapterState.HostedContentFilterPolicy = @(@{
            Identity = 'Default'
            Name = 'Default'
            AllowedSenders = @('legacy-sender@partner.example')
            AllowedSenderDomains = @('legacy.partner.example')
            BlockedSenders = @()
            BlockedSenderDomains = @()
        })
        $global:adapterState.MailboxJunkEmailConfiguration = @(@{
            Identity = 'user@contoso.example'
            TrustedSendersAndDomains = @('personal.example')
        })
        $global:adapterState.InboundConnector = @(@{
            Identity = 'Partner inbound'
            SenderIPAddresses = @('192.0.2.20')
            RestrictDomainsToIPAddresses = $true
        })
        $global:organizationAllowListReads = [Collections.Generic.List[object]]::new()
        $global:organizationAllowListCollectionFailure = @{
            HostedConnectionFilterPolicy = ''
            HostedContentFilterPolicy = ''
        }
        $global:organizationAllowListCollectionPartial = @{
            HostedConnectionFilterPolicy = $false
            HostedContentFilterPolicy = $false
        }

        function global:Get-HostedConnectionFilterPolicy {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            $global:organizationAllowListReads.Add(@{ Command = 'Get-HostedConnectionFilterPolicy'; Parameters = @{} + $PSBoundParameters })
            $rows = @($global:adapterState.HostedConnectionFilterPolicy | Where-Object {
                    [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -eq $Identity
                })
            if ($global:organizationAllowListCollectionPartial.HostedConnectionFilterPolicy -and $rows.Count) {
                [pscustomobject]$rows[0].Clone()
                throw 'ChangeReadIncomplete: Get-HostedConnectionFilterPolicy returned a partial paged result.'
            }
            if (-not [string]::IsNullOrWhiteSpace($global:organizationAllowListCollectionFailure.HostedConnectionFilterPolicy)) {
                throw "ChangeReadIncomplete: Get-HostedConnectionFilterPolicy failed: $($global:organizationAllowListCollectionFailure.HostedConnectionFilterPolicy)"
            }
            foreach ($row in $rows) { [pscustomobject]$row.Clone() }
        }
        function global:Set-HostedConnectionFilterPolicy {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [string[]]$IPAllowList,
                [bool]$EnableSafeList
            )

            $bound = @{} + $PSBoundParameters
            if ($bound.ContainsKey('IPAllowList')) { $bound.IPAllowList = @($IPAllowList) }
            $global:adapterCalls.Add(@{ Command = 'Set-HostedConnectionFilterPolicy'; Parameters = $bound })
            if ($global:adapterWriteFault -eq 'Set-HostedConnectionFilterPolicy') { throw 'Offline write refused: Set-HostedConnectionFilterPolicy' }
            $target = @($global:adapterState.HostedConnectionFilterPolicy | Where-Object Identity -EQ $Identity)
            if ($target.Count -ne 1) { throw "Offline target not unique: Set-HostedConnectionFilterPolicy ($($target.Count))." }
            if ($bound.ContainsKey('IPAllowList')) { $target[0].IPAllowList = @($bound.IPAllowList) }
            if ($bound.ContainsKey('EnableSafeList')) { $target[0].EnableSafeList = $EnableSafeList }
        }
        function global:Get-HostedContentFilterPolicy {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            $global:organizationAllowListReads.Add(@{ Command = 'Get-HostedContentFilterPolicy'; Parameters = @{} + $PSBoundParameters })
            $rows = @($global:adapterState.HostedContentFilterPolicy | Where-Object {
                    [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -eq $Identity
                })
            if ($global:organizationAllowListCollectionPartial.HostedContentFilterPolicy -and $rows.Count) {
                [pscustomobject]$rows[0].Clone()
                throw 'ChangeReadIncomplete: Get-HostedContentFilterPolicy returned a partial paged result.'
            }
            if (-not [string]::IsNullOrWhiteSpace($global:organizationAllowListCollectionFailure.HostedContentFilterPolicy)) {
                throw "ChangeReadIncomplete: Get-HostedContentFilterPolicy failed: $($global:organizationAllowListCollectionFailure.HostedContentFilterPolicy)"
            }
            foreach ($row in $rows) { [pscustomobject]$row.Clone() }
        }
        function global:Set-HostedContentFilterPolicy {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [string[]]$AllowedSenders,
                [string[]]$AllowedSenderDomains
            )

            $bound = @{} + $PSBoundParameters
            foreach ($field in @('AllowedSenders','AllowedSenderDomains')) {
                if ($bound.ContainsKey($field)) { $bound[$field] = @($bound[$field]) }
            }
            $global:adapterCalls.Add(@{ Command = 'Set-HostedContentFilterPolicy'; Parameters = $bound })
            if ($global:adapterWriteFault -eq 'Set-HostedContentFilterPolicy') { throw 'Offline write refused: Set-HostedContentFilterPolicy' }
            $target = @($global:adapterState.HostedContentFilterPolicy | Where-Object Identity -EQ $Identity)
            if ($target.Count -ne 1) { throw "Offline target not unique: Set-HostedContentFilterPolicy ($($target.Count))." }
            foreach ($field in @('AllowedSenders','AllowedSenderDomains')) {
                if ($bound.ContainsKey($field)) { $target[0][$field] = @($bound[$field]) }
            }
        }
        foreach ($command in @(
                'Get-HostedConnectionFilterPolicy',
                'Set-HostedConnectionFilterPolicy',
                'Get-HostedContentFilterPolicy',
                'Set-HostedContentFilterPolicy'
            )) {
            $global:adapterCommands.Add($command)
        }
    }

    function New-OrganizationAllowEntry {
        param(
            [Parameter(Mandatory)][ValidateSet('IpAddress','Sender','Domain')][string]$Kind,
            [Parameter(Mandatory)][string]$Value,
            [string]$Owner = 'security@contoso.example',
            [string]$Approval = 'SEC-ALLOW-202',
            [string]$ExpiresOn = [datetimeoffset]::UtcNow.AddDays(7).ToString('o'),
            [bool]$Shared = $false,
            [bool]$Authenticated = $true
        )

        @{
            kind = $Kind
            value = $Value
            owner = $Owner
            approval = $Approval
            expiresOn = $ExpiresOn
            shared = $Shared
            authentication = @{
                required = $true
                verified = $Authenticated
                evidence = $(if ($Authenticated) { "fixture:authenticated:$Value" } else { '' })
            }
        }
    }

    function Set-OrganizationAllowListOptions {
        param(
            $Arguments,
            [object[]]$IpAllowEntries = @((New-OrganizationAllowEntry -Kind IpAddress -Value '203.0.113.10/32')),
            [object[]]$AllowedSenders = @((New-OrganizationAllowEntry -Kind Sender -Value 'approved-sender@partner.example')),
            [object[]]$AllowedSenderDomains = @((New-OrganizationAllowEntry -Kind Domain -Value 'approved.partner.example'))
        )

        $parameters = Get-Content $Arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions.organizationAllowList = @{
            connectionFilter = @{
                identity = 'Default'
                ipAllowEntries = @($IpAllowEntries)
                enableSafeList = $false
            }
            antiSpam = @{
                identity = 'Default'
                allowedSenders = @($AllowedSenders)
                allowedSenderDomains = @($AllowedSenderDomains)
            }
        }
        $parameters | ConvertTo-Json -Depth 40 | Set-Content $Arguments.ParameterPath
    }

    function New-OrganizationAllowListFixture {
        param([string]$ChangeId = 'ORGALLOW-T02', [switch]$Approved)

        $arguments = New-StatefulAdapterFixture -Scope OrganizationAllowList
        $arguments.ChangeId = $ChangeId
        $arguments.PreviewPath = Join-Path $arguments.ArtifactRoot "preview-$ChangeId.json"
        $arguments.ApprovalPath = Join-Path $arguments.ArtifactRoot "approval-$ChangeId.json"
        Set-OrganizationAllowListOptions -Arguments $arguments
        if ($Approved) { Approve-OrganizationAllowListFixture -Arguments $arguments }
        $arguments
    }

    function Approve-OrganizationAllowListFixture {
        param($Arguments)

        & $script:changeCommand -Stage Preview @Arguments -Scope OrganizationAllowList -Confirm:$false | Out-Null
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
    }

    function Invoke-OrganizationAllowListPreview {
        param($Arguments)
        & $script:changeCommand -Stage Preview @Arguments -Scope OrganizationAllowList -Confirm:$false
    }

    function Get-OrganizationAllowListStateSnapshot {
        ConvertTo-CanonicalJson ([ordered]@{
            HostedConnectionFilterPolicy = @($global:adapterState.HostedConnectionFilterPolicy)
            HostedContentFilterPolicy = @($global:adapterState.HostedContentFilterPolicy)
        })
    }

    function Get-OrganizationAllowListBoundarySnapshot {
        ConvertTo-CanonicalJson ([ordered]@{
            MailboxJunkEmailConfiguration = @($global:adapterState.MailboxJunkEmailConfiguration)
            TenantAllowBlockListItems = @($global:adapterState.TenantAllowBlockListItems)
            InboundConnector = @($global:adapterState.InboundConnector)
        })
    }

    function Get-IndependentOrganizationAllowListReadback {
        $connection = @(Get-HostedConnectionFilterPolicy -ResultSize Unlimited)
        $content = @(Get-HostedContentFilterPolicy -ResultSize Unlimited)
        if ($connection.Count -ne 1 -or $content.Count -ne 1) { throw 'ChangeReadIncomplete: organization allow-list readback was not unique.' }

        [pscustomobject]@{
            ConnectionIdentity = [string]$connection[0].Identity
            IPAllowList = @($connection[0].IPAllowList)
            EnableSafeList = [bool]$connection[0].EnableSafeList
            ContentIdentity = [string]$content[0].Identity
            AllowedSenders = @($content[0].AllowedSenders)
            AllowedSenderDomains = @($content[0].AllowedSenderDomains)
        }
    }

    function Invoke-OrganizationAllowListLifecycle {
        param($Arguments)

        $before = Get-OrganizationAllowListStateSnapshot
        $boundariesBefore = Get-OrganizationAllowListBoundarySnapshot
        Approve-OrganizationAllowListFixture -Arguments $Arguments
        & $script:changeCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:changeCommand -Stage Apply @Arguments -Apply -Confirm:$false
        $readback = Get-IndependentOrganizationAllowListReadback
        $writesAfterApply = $global:adapterCalls.Count

        $repeatArguments = New-OrganizationAllowListFixture -ChangeId 'ORGALLOW-T02-REPEAT'
        Approve-OrganizationAllowListFixture -Arguments $repeatArguments
        & $script:changeCommand -Stage Validate @repeatArguments | Out-Null
        $repeat = & $script:changeCommand -Stage Apply @repeatArguments -Apply -Confirm:$false
        $repeatWrites = $global:adapterCalls.Count - $writesAfterApply

        $global:adapterState.HostedContentFilterPolicy[0].AllowedSenders = @('drift@partner.example')
        $writesBeforeDrift = $global:adapterCalls.Count
        $drift = $null
        try { & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false | Out-Null } catch { $drift = $_ }
        $driftWrites = $global:adapterCalls.Count - $writesBeforeDrift
        $global:adapterState.HostedContentFilterPolicy[0].AllowedSenders = @('approved-sender@partner.example')

        $rollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false
        $writesAfterRollback = $global:adapterCalls.Count
        $repeatedRollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false

        [pscustomobject]@{
            Before = $before
            BoundariesBefore = $boundariesBefore
            Apply = $apply
            Readback = $readback
            Repeat = $repeat
            RepeatWrites = $repeatWrites
            Drift = $drift
            DriftWrites = $driftWrites
            Rollback = $rollback
            Restored = Get-OrganizationAllowListStateSnapshot
            BoundariesAfter = Get-OrganizationAllowListBoundarySnapshot
            RepeatedRollback = $repeatedRollback
            RepeatedRollbackWrites = $global:adapterCalls.Count - $writesAfterRollback
        }
    }
}

Describe 'EXR-007-A02-T02 organization filtering allow-list lifecycle' {
    BeforeEach {
        Initialize-OrganizationAllowListDoubles
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

    Context 'Negative: broad or shared connection-filter trust refuses before writes' {
        It 'refuses a broad connection-filter IP range' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture
            Set-OrganizationAllowListOptions -Arguments $arguments -IpAllowEntries @(
                (New-OrganizationAllowEntry -Kind IpAddress -Value '0.0.0.0/0')
            )

            # Act
            $invoke = { Invoke-OrganizationAllowListPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*OrganizationAllowListIpScopeTooBroad*0.0.0.0/0*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an IP range shared by unrelated senders or tenants' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture
            Set-OrganizationAllowListOptions -Arguments $arguments -IpAllowEntries @(
                (New-OrganizationAllowEntry -Kind IpAddress -Value '203.0.113.10/32' -Shared $true)
            )

            # Act
            $invoke = { Invoke-OrganizationAllowListPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*OrganizationAllowListSharedIpTrust*203.0.113.10/32*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: sender and domain allows require ownership, approval lifetime, and authentication' {
        It 'refuses an unowned anti-spam sender allow' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture
            Set-OrganizationAllowListOptions -Arguments $arguments -AllowedSenders @(
                (New-OrganizationAllowEntry -Kind Sender -Value 'approved-sender@partner.example' -Owner '')
            )

            # Act
            $invoke = { Invoke-OrganizationAllowListPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*OrganizationAllowListOwnerRequired*approved-sender@partner.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an unowned anti-spam sender-domain allow' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture
            Set-OrganizationAllowListOptions -Arguments $arguments -AllowedSenderDomains @(
                (New-OrganizationAllowEntry -Kind Domain -Value 'approved.partner.example' -Owner '')
            )

            # Act
            $invoke = { Invoke-OrganizationAllowListPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*OrganizationAllowListOwnerRequired*approved.partner.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an expired anti-spam sender allow' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture
            Set-OrganizationAllowListOptions -Arguments $arguments -AllowedSenders @(
                (New-OrganizationAllowEntry -Kind Sender -Value 'approved-sender@partner.example' -ExpiresOn '2000-01-01T00:00:00Z')
            )

            # Act
            $invoke = { Invoke-OrganizationAllowListPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*OrganizationAllowListApprovalExpired*approved-sender@partner.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an expired anti-spam sender-domain allow' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture
            Set-OrganizationAllowListOptions -Arguments $arguments -AllowedSenderDomains @(
                (New-OrganizationAllowEntry -Kind Domain -Value 'approved.partner.example' -ExpiresOn '2000-01-01T00:00:00Z')
            )

            # Act
            $invoke = { Invoke-OrganizationAllowListPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*OrganizationAllowListApprovalExpired*approved.partner.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an unauthenticated anti-spam sender bypass' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture
            Set-OrganizationAllowListOptions -Arguments $arguments -AllowedSenders @(
                (New-OrganizationAllowEntry -Kind Sender -Value 'approved-sender@partner.example' -Authenticated $false)
            )

            # Act
            $invoke = { Invoke-OrganizationAllowListPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*OrganizationAllowListAuthenticationRequired*approved-sender@partner.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an unauthenticated anti-spam sender-domain bypass' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture
            Set-OrganizationAllowListOptions -Arguments $arguments -AllowedSenderDomains @(
                (New-OrganizationAllowEntry -Kind Domain -Value 'approved.partner.example' -Authenticated $false)
            )

            # Act
            $invoke = { Invoke-OrganizationAllowListPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*OrganizationAllowListAuthenticationRequired*approved.partner.example*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: incomplete, paged, or failed raw collection never authorizes a change' {
        It 'refuses an incomplete connection-filter policy row' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture
            $global:adapterState.HostedConnectionFilterPolicy[0].Remove('IPAllowList')

            # Act
            $invoke = { Invoke-OrganizationAllowListPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*HostedConnectionFilterPolicy*IPAllowList*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an incomplete anti-spam policy row' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture
            $global:adapterState.HostedContentFilterPolicy[0].Remove('AllowedSenderDomains')

            # Act
            $invoke = { Invoke-OrganizationAllowListPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*HostedContentFilterPolicy*AllowedSenderDomains*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses partial connection-filter output followed by a paging failure' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture
            $global:organizationAllowListCollectionPartial.HostedConnectionFilterPolicy = $true

            # Act
            $invoke = { Invoke-OrganizationAllowListPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*Get-HostedConnectionFilterPolicy*partial paged result*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses partial anti-spam output followed by a paging failure' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture
            $global:organizationAllowListCollectionPartial.HostedContentFilterPolicy = $true

            # Act
            $invoke = { Invoke-OrganizationAllowListPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*Get-HostedContentFilterPolicy*partial paged result*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a connection-filter collection error' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture
            $global:organizationAllowListCollectionFailure.HostedConnectionFilterPolicy = 'Access is denied.'

            # Act
            $invoke = { Invoke-OrganizationAllowListPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*Get-HostedConnectionFilterPolicy failed*Access is denied*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an anti-spam collection error' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture
            $global:organizationAllowListCollectionFailure.HostedContentFilterPolicy = 'The operation timed out.'

            # Act
            $invoke = { Invoke-OrganizationAllowListPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*Get-HostedContentFilterPolicy failed*operation timed out*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Positive: one narrow independently approved organization allow-list lifecycle' {
        It 'applies, independently reads back, no-ops, refuses drift, and rolls back without crossing adjacent trust boundaries' {
            # Arrange
            $arguments = New-OrganizationAllowListFixture

            # Act
            $result = Invoke-OrganizationAllowListLifecycle -Arguments $arguments

            # Assert
            $result.Apply.Status | Should -BeExactly 'Succeeded'
            $result.Readback.ConnectionIdentity | Should -BeExactly 'Default'
            $result.Readback.ContentIdentity | Should -BeExactly 'Default'
            $result.Readback.IPAllowList | Should -Be @('203.0.113.10/32')
            $result.Readback.EnableSafeList | Should -BeFalse
            $result.Readback.AllowedSenders | Should -Be @('approved-sender@partner.example')
            $result.Readback.AllowedSenderDomains | Should -Be @('approved.partner.example')
            @($global:organizationAllowListReads | Where-Object { $_.Parameters.ResultSize -ceq 'Unlimited' }).Count | Should -BeGreaterOrEqual 2
            $result.Repeat.Status | Should -BeExactly 'Succeeded'
            $result.RepeatWrites | Should -Be 0
            $result.Drift.Exception.Message | Should -BeLike '*ChangeStateDrift*'
            $result.DriftWrites | Should -Be 0
            $result.Rollback.Status | Should -BeExactly 'Succeeded'
            $result.Restored | Should -BeExactly $result.Before
            $result.RepeatedRollback.Status | Should -BeExactly 'Succeeded'
            $result.RepeatedRollbackWrites | Should -Be 0
            $result.BoundariesAfter | Should -BeExactly $result.BoundariesBefore
            @($global:adapterCalls | Where-Object Command -Match 'MailboxJunkEmailConfiguration|TenantAllowBlockList|InboundConnector|OutboundConnector').Count | Should -Be 0
        }
    }
}

AfterAll {
    foreach ($name in @($global:adapterCommands) + @('Get-ConnectionInformation', 'Invoke-OfflineAdapterCommand')) {
        Remove-Item "Function:global:$name" -ErrorAction SilentlyContinue
    }
    $script:signingCertificate.Dispose()
    $script:signingKey.Dispose()
    Get-Variable -Name 'adapter*' -Scope Global | Remove-Variable -Scope Global
    Get-Variable -Name 'organizationAllowList*' -Scope Global | Remove-Variable -Scope Global
    Remove-Module ExchangeOnlineBaseline.Common -Force -ErrorAction SilentlyContinue
}