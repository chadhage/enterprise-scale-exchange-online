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

    function Initialize-ConnectorTrustDoubles {
        Initialize-AdapterDoubles
        $global:adapterState.InboundConnector = @(@{
            Identity = 'Approved partner inbound'
            Name = 'Approved partner inbound'
            Enabled = $false
            ConnectorType = 'Partner'
            SenderDomains = @('old.partner.example')
            SenderIPAddresses = @()
            TlsSenderCertificateName = 'old.partner.example'
            RestrictDomainsToCertificate = $false
            RestrictDomainsToIPAddresses = $false
            RequireTls = $false
        })
        $global:adapterState.OutboundConnector = @(@{
            Identity = 'Approved partner outbound'
            Name = 'Approved partner outbound'
            Enabled = $false
            ConnectorType = 'Partner'
            RecipientDomains = @('old.partner.example')
            SmartHosts = @('old-gateway.partner.example')
            TlsSettings = 'EncryptionOnly'
            TlsDomain = 'old.partner.example'
            RouteAllMessagesViaOnPremises = $false
            UseMxRecord = $true
        })
        $global:connectorTrustReads = [Collections.Generic.List[object]]::new()

        function global:Get-InboundConnector {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            $global:connectorTrustReads.Add(@{ Command = 'Get-InboundConnector'; Parameters = @{} + $PSBoundParameters })
            foreach ($row in @($global:adapterState.InboundConnector | Where-Object {
                        [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -eq $Identity
                    })) {
                [pscustomobject]$row.Clone()
            }
        }

        function global:Set-InboundConnector {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [bool]$Enabled,
                [string[]]$SenderDomains,
                [string[]]$SenderIPAddresses,
                [string]$TlsSenderCertificateName,
                [bool]$RestrictDomainsToCertificate,
                [bool]$RestrictDomainsToIPAddresses,
                [bool]$RequireTls
            )

            $bound = @{} + $PSBoundParameters
            foreach ($field in @('SenderDomains', 'SenderIPAddresses')) {
                if ($bound.ContainsKey($field)) { $bound[$field] = @($bound[$field]) }
            }
            $global:adapterCalls.Add(@{ Command = 'Set-InboundConnector'; Parameters = $bound })
            $target = @($global:adapterState.InboundConnector | Where-Object Identity -CEQ $Identity)
            if ($target.Count -ne 1) { throw "Offline target not unique: Set-InboundConnector ($($target.Count))." }
            foreach ($field in @(
                    'Enabled',
                    'SenderDomains',
                    'SenderIPAddresses',
                    'TlsSenderCertificateName',
                    'RestrictDomainsToCertificate',
                    'RestrictDomainsToIPAddresses',
                    'RequireTls'
                )) {
                if ($bound.ContainsKey($field)) { $target[0][$field] = $bound[$field] }
            }
        }

        function global:Get-OutboundConnector {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            $global:connectorTrustReads.Add(@{ Command = 'Get-OutboundConnector'; Parameters = @{} + $PSBoundParameters })
            foreach ($row in @($global:adapterState.OutboundConnector | Where-Object {
                        [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -eq $Identity
                    })) {
                [pscustomobject]$row.Clone()
            }
        }

        function global:Set-OutboundConnector {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [bool]$Enabled,
                [string[]]$RecipientDomains,
                [string[]]$SmartHosts,
                [string]$TlsSettings,
                [string]$TlsDomain,
                [bool]$RouteAllMessagesViaOnPremises,
                [bool]$UseMxRecord
            )

            $bound = @{} + $PSBoundParameters
            foreach ($field in @('RecipientDomains', 'SmartHosts')) {
                if ($bound.ContainsKey($field)) { $bound[$field] = @($bound[$field]) }
            }
            $global:adapterCalls.Add(@{ Command = 'Set-OutboundConnector'; Parameters = $bound })
            $target = @($global:adapterState.OutboundConnector | Where-Object Identity -CEQ $Identity)
            if ($target.Count -ne 1) { throw "Offline target not unique: Set-OutboundConnector ($($target.Count))." }
            foreach ($field in @(
                    'Enabled',
                    'RecipientDomains',
                    'SmartHosts',
                    'TlsSettings',
                    'TlsDomain',
                    'RouteAllMessagesViaOnPremises',
                    'UseMxRecord'
                )) {
                if ($bound.ContainsKey($field)) { $target[0][$field] = $bound[$field] }
            }
        }

        foreach ($command in @(
                'Get-InboundConnector',
                'Set-InboundConnector',
                'Get-OutboundConnector',
                'Set-OutboundConnector'
            )) {
            $global:adapterCommands.Add($command)
        }
    }

    function New-ConnectorTrustDeclaration {
        param(
            [Parameter(Mandatory)][ValidateSet('Inbound', 'Outbound')][string]$Direction,
            [string]$Identity = $(if ($Direction -eq 'Inbound') { 'Approved partner inbound' } else { 'Approved partner outbound' }),
            [string]$Owner = 'messaging@contoso.example',
            [string]$Approval = 'SEC-CONNECTOR-204',
            [string]$ExpiresOn = [datetimeoffset]::UtcNow.AddDays(14).ToString('o'),
            [bool]$Declared = $true,
            [bool]$Authenticated = $true,
            [string[]]$RoutingScope = @('approved.partner.example')
        )

        @{
            direction = $Direction
            identity = $Identity
            owner = $Owner
            approval = $Approval
            expiresOn = $ExpiresOn
            declared = $Declared
            routingScope = @($RoutingScope)
            authentication = @{
                required = $true
                verified = $Authenticated
                mechanism = 'TlsCertificate'
                evidence = $(if ($Authenticated) { "fixture:tls:$Direction" } else { '' })
            }
        }
    }

    function New-ConnectorTrustHandoff {
        param(
            [bool]$Reconciled = $true,
            [string]$Owner = 'network@partner.example',
            [string]$Evidence = 'fixture:external-routing-readback'
        )

        @{
            name = 'Partner smart-host handoff'
            target = 'smtp.partner.example'
            owner = $Owner
            reconciled = $Reconciled
            evidence = $Evidence
            observedOn = [datetimeoffset]::UtcNow.ToString('o')
        }
    }

    function Set-ConnectorTrustOptions {
        param(
            $Arguments,
            [object[]]$Inbound = @((New-ConnectorTrustDeclaration -Direction Inbound)),
            [object[]]$Outbound = @((New-ConnectorTrustDeclaration -Direction Outbound)),
            [object[]]$ExternalRoutingHandoffs = @((New-ConnectorTrustHandoff)),
            [bool]$ProvisionExternalInfrastructure = $false
        )

        $parameters = Get-Content $Arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions.connectorTrust = @{
            inbound = @($Inbound)
            outbound = @($Outbound)
            externalRoutingHandoffs = @($ExternalRoutingHandoffs)
            provisionExternalInfrastructure = $ProvisionExternalInfrastructure
            desired = @{
                inbound = @{
                    identity = 'Approved partner inbound'
                    enabled = $true
                    senderDomains = @('approved.partner.example')
                    senderIPAddresses = @()
                    tlsSenderCertificateName = 'smtp.partner.example'
                    restrictDomainsToCertificate = $true
                    restrictDomainsToIPAddresses = $false
                    requireTls = $true
                }
                outbound = @{
                    identity = 'Approved partner outbound'
                    enabled = $true
                    recipientDomains = @('approved.partner.example')
                    smartHosts = @('smtp.partner.example')
                    tlsSettings = 'DomainValidation'
                    tlsDomain = 'smtp.partner.example'
                    routeAllMessagesViaOnPremises = $false
                    useMxRecord = $false
                }
            }
        }
        $parameters | ConvertTo-Json -Depth 40 | Set-Content $Arguments.ParameterPath
    }

    function New-ConnectorTrustFixture {
        param([string]$ChangeId = 'CONNECTOR-TRUST-T04')

        $arguments = New-StatefulAdapterFixture -Scope ConnectorTrust
        $arguments.ChangeId = $ChangeId
        $arguments.PreviewPath = Join-Path $arguments.ArtifactRoot "preview-$ChangeId.json"
        $arguments.ApprovalPath = Join-Path $arguments.ArtifactRoot "approval-$ChangeId.json"
        Set-ConnectorTrustOptions -Arguments $arguments
        $arguments
    }

    function Invoke-ConnectorTrustPreview {
        param($Arguments)
        & $script:changeCommand -Stage Preview @Arguments -Scope ConnectorTrust -Confirm:$false
    }

    function Approve-ConnectorTrustFixture {
        param($Arguments)

        & $script:changeCommand -Stage Preview @Arguments -Scope ConnectorTrust -Confirm:$false | Out-Null
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
    }

    function Get-ConnectorTrustStateSnapshot {
        ConvertTo-CanonicalJson ([ordered]@{
            InboundConnector = @($global:adapterState.InboundConnector)
            OutboundConnector = @($global:adapterState.OutboundConnector)
        })
    }

    function Get-IndependentConnectorTrustReadback {
        $inbound = @(Get-InboundConnector -ResultSize Unlimited)
        $outbound = @(Get-OutboundConnector -ResultSize Unlimited)
        if ($inbound.Count -ne 1 -or $outbound.Count -ne 1) {
            throw 'ChangeReadIncomplete: connector trust readback was not unique.'
        }

        [pscustomobject]@{
            Inbound = $inbound[0]
            Outbound = $outbound[0]
        }
    }

    function Invoke-ConnectorTrustLifecycle {
        param($Arguments)

        $before = Get-ConnectorTrustStateSnapshot
        Approve-ConnectorTrustFixture -Arguments $Arguments
        & $script:changeCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:changeCommand -Stage Apply @Arguments -Apply -Confirm:$false
        $readback = Get-IndependentConnectorTrustReadback
        $rollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false

        [pscustomobject]@{
            Before = $before
            Apply = $apply
            Readback = $readback
            Rollback = $rollback
            Restored = Get-ConnectorTrustStateSnapshot
        }
    }
}

Describe 'EXR-007-A02-T04 Exchange connector trust lifecycle' {
    BeforeEach {
        Initialize-ConnectorTrustDoubles
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

    Context 'Negative 01: both connector directions require explicit coverage' {
        It 'refuses a trust inventory with no outbound connector coverage' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            Set-ConnectorTrustOptions -Arguments $arguments -Outbound @()

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustOutboundCoverageRequired*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 02-03: raw connector identities must be complete' {
        It 'refuses an inbound connector whose raw identity is missing' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $global:adapterState.InboundConnector[0].Remove('Identity')

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*InboundConnector*Identity*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an outbound connector whose raw identity is missing' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $global:adapterState.OutboundConnector[0].Remove('Identity')

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*OutboundConnector*Identity*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 04-05: every enabled trust must be declared' {
        It 'refuses undeclared inbound connector trust' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $inbound = New-ConnectorTrustDeclaration -Direction Inbound -Declared $false
            Set-ConnectorTrustOptions -Arguments $arguments -Inbound @($inbound)

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustUndeclared*Inbound*Approved partner inbound*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses undeclared outbound connector trust' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $outbound = New-ConnectorTrustDeclaration -Direction Outbound -Declared $false
            Set-ConnectorTrustOptions -Arguments $arguments -Outbound @($outbound)

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustUndeclared*Outbound*Approved partner outbound*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 06-07: routing scope must remain narrow' {
        It 'refuses tenant-wide inbound routing trust' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $inbound = New-ConnectorTrustDeclaration -Direction Inbound -RoutingScope @('*')
            Set-ConnectorTrustOptions -Arguments $arguments -Inbound @($inbound)

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustRoutingScopeTooBroad*Inbound***'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses tenant-wide outbound routing trust' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $outbound = New-ConnectorTrustDeclaration -Direction Outbound -RoutingScope @('*')
            Set-ConnectorTrustOptions -Arguments $arguments -Outbound @($outbound)

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustRoutingScopeTooBroad*Outbound***'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 08-09: both directions require authenticated trust' {
        It 'refuses unauthenticated inbound connector trust' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $inbound = New-ConnectorTrustDeclaration -Direction Inbound -Authenticated $false
            Set-ConnectorTrustOptions -Arguments $arguments -Inbound @($inbound)

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustAuthenticationRequired*Inbound*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses unauthenticated outbound connector trust' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $outbound = New-ConnectorTrustDeclaration -Direction Outbound -Authenticated $false
            Set-ConnectorTrustOptions -Arguments $arguments -Outbound @($outbound)

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustAuthenticationRequired*Outbound*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 10-11: both directions require accountable owners' {
        It 'refuses inbound connector trust without an owner' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $inbound = New-ConnectorTrustDeclaration -Direction Inbound -Owner ''
            Set-ConnectorTrustOptions -Arguments $arguments -Inbound @($inbound)

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustOwnerRequired*Inbound*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses outbound connector trust without an owner' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $outbound = New-ConnectorTrustDeclaration -Direction Outbound -Owner ''
            Set-ConnectorTrustOptions -Arguments $arguments -Outbound @($outbound)

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustOwnerRequired*Outbound*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 12-13: both directions require independent approval' {
        It 'refuses inbound connector trust without approval evidence' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $inbound = New-ConnectorTrustDeclaration -Direction Inbound -Approval ''
            Set-ConnectorTrustOptions -Arguments $arguments -Inbound @($inbound)

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustApprovalRequired*Inbound*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses outbound connector trust without approval evidence' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $outbound = New-ConnectorTrustDeclaration -Direction Outbound -Approval ''
            Set-ConnectorTrustOptions -Arguments $arguments -Outbound @($outbound)

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustApprovalRequired*Outbound*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 14-15: approval lifetime bounds both directions' {
        It 'refuses inbound connector trust with an expired approval' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $inbound = New-ConnectorTrustDeclaration -Direction Inbound -ExpiresOn '2000-01-01T00:00:00Z'
            Set-ConnectorTrustOptions -Arguments $arguments -Inbound @($inbound)

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustApprovalExpired*Inbound*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses outbound connector trust with an expired approval' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $outbound = New-ConnectorTrustDeclaration -Direction Outbound -ExpiresOn '2000-01-01T00:00:00Z'
            Set-ConnectorTrustOptions -Arguments $arguments -Outbound @($outbound)

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustApprovalExpired*Outbound*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 16: external routing ownership requires independent reconciliation' {
        It 'refuses an unreconciled declared external routing handoff' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            $handoff = New-ConnectorTrustHandoff -Reconciled $false -Evidence ''
            Set-ConnectorTrustOptions -Arguments $arguments -ExternalRoutingHandoffs @($handoff)

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustExternalHandoffUnreconciled*Partner smart-host handoff*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 17: lifecycle authority stops at the Exchange boundary' {
        It 'refuses attempted vendor or gateway infrastructure provisioning' {
            # Arrange
            $arguments = New-ConnectorTrustFixture
            Set-ConnectorTrustOptions -Arguments $arguments -ProvisionExternalInfrastructure $true

            # Act
            $invoke = { Invoke-ConnectorTrustPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ConnectorTrustExternalProvisioningForbidden*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Positive 18: one narrow approved both-direction Exchange connector lifecycle' {
        It 'applies both connectors, independently reads them back, and performs a scoped rollback' {
            # Arrange
            $arguments = New-ConnectorTrustFixture

            # Act
            $result = Invoke-ConnectorTrustLifecycle -Arguments $arguments

            # Assert
            $result.Apply.Status | Should -BeExactly 'Succeeded'
            $result.Readback.Inbound.Identity | Should -BeExactly 'Approved partner inbound'
            $result.Readback.Inbound.Enabled | Should -BeTrue
            @($result.Readback.Inbound.SenderDomains) | Should -BeExactly @('approved.partner.example')
            $result.Readback.Inbound.TlsSenderCertificateName | Should -BeExactly 'smtp.partner.example'
            $result.Readback.Inbound.RestrictDomainsToCertificate | Should -BeTrue
            $result.Readback.Inbound.RequireTls | Should -BeTrue
            $result.Readback.Outbound.Identity | Should -BeExactly 'Approved partner outbound'
            $result.Readback.Outbound.Enabled | Should -BeTrue
            @($result.Readback.Outbound.RecipientDomains) | Should -BeExactly @('approved.partner.example')
            @($result.Readback.Outbound.SmartHosts) | Should -BeExactly @('smtp.partner.example')
            $result.Readback.Outbound.TlsSettings | Should -BeExactly 'DomainValidation'
            $result.Readback.Outbound.TlsDomain | Should -BeExactly 'smtp.partner.example'
            $result.Readback.Outbound.RouteAllMessagesViaOnPremises | Should -BeFalse
            @($global:connectorTrustReads | Where-Object { $_.Parameters.ResultSize -ceq 'Unlimited' }).Count |
                Should -BeGreaterOrEqual 2
            $result.Rollback.Status | Should -BeExactly 'Succeeded'
            $result.Restored | Should -BeExactly $result.Before
            @($global:adapterCalls | Where-Object Command -NotMatch '^(Set-InboundConnector|Set-OutboundConnector)$').Count |
                Should -Be 0
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
    Get-Variable -Name 'connectorTrust*' -Scope Global | Remove-Variable -Scope Global
    Remove-Module ExchangeOnlineBaseline.Common -Force -ErrorAction SilentlyContinue
}
