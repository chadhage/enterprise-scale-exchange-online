BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $script:SampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SampleRoot 'scripts/Deploy-ExchangeOnlineBaseline.ps1'), [ref]$tokens, [ref]$errors)
    $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Set-OrganizationControls' }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
    function Add-Outcome { }
    function Set-TransportConfig { $script:OtherWrites++ }
    function Set-HostedOutboundSpamFilterPolicy { }
    function Set-OrganizationConfig { }
    function Set-ExternalInOutlook { }
    function Get-CASMailboxPlan { }
    function Set-QuarantinePolicy { }
    function Get-RemoteDomain { $script:Domains }
    function Set-RemoteDomain {
        param($Identity, $AutoForwardEnabled, $AutoReplyEnabled, $AllowedOOFType, $DeliveryReportEnabled, $NDREnabled, $WhatIf)
        $script:RemoteWrites += $PSBoundParameters
    }
}

Describe 'EXR-002 deployment OOF admission' {
    BeforeEach {
        $script:Configuration = Get-Content (Join-Path $script:SampleRoot 'config/exchange-online-secure-baseline.microsoft-native.json') -Raw | ConvertFrom-Json
        $script:Configuration.desiredState.exchangeOnline.remoteDomainDefault.allowedOOFType = 'None'
        $script:RemoteWrites = @()
        $script:OtherWrites = 0
        $script:Domains = @([pscustomobject]@{ Identity = 'Default'; DomainName = '*'; AllowedOOFType = 'External' })
    }

    It 'refuses unsafe or unapproved policy before any organization write: <Type>' -ForEach @(
        @{ Type = 'InternalLegacy'; Reason = 'RemoteDomainOofPolicyInvalid' },
        @{ Type = 'External'; Reason = 'RemoteDomainExternalApprovalRequired' }
    ) {
        # Arrange
        $script:Configuration.desiredState.exchangeOnline.remoteDomainDefault.allowedOOFType = $Type
        # Act
        $act = { Set-OrganizationControls -Configuration $script:Configuration -UseWhatIf $true -ExchangeOnly }
        # Assert
        $act | Should -Throw "*$Reason*"
        $script:RemoteWrites.Count | Should -Be 0
        $script:OtherWrites | Should -Be 0
    }

    It 'refuses a conflicting specific override <Type> without silently rewriting it' -ForEach @(
        @{ Type = 'InternalLegacy' }, @{ Type = 'External' }, @{ Type = 'ExternalLegacy' }
    ) {
        # Arrange
        $script:Domains += [pscustomobject]@{ Identity = 'Partner'; DomainName = 'partner.example'; AllowedOOFType = $Type }
        # Act
        $act = { Set-OrganizationControls -Configuration $script:Configuration -UseWhatIf $true -ExchangeOnly }
        # Assert
        $act | Should -Throw '*RemoteDomainOverrideConflict*Partner*'
        $script:RemoteWrites.Count | Should -Be 0
        $script:OtherWrites | Should -Be 0
    }

    It 'refuses missing Default rather than assuming enumeration was complete' {
        # Arrange
        $script:Domains = @()
        # Act
        $act = { Set-OrganizationControls -Configuration $script:Configuration -UseWhatIf $true -ExchangeOnly }
        # Assert
        $act | Should -Throw '*RemoteDomainDefaultMissing*'
        $script:RemoteWrites.Count | Should -Be 0
    }

    It 'propagates collection refusal before any write' {
        # Arrange
        Mock Get-RemoteDomain { throw 'remote enumeration denied' }
        # Act
        $act = { Set-OrganizationControls -Configuration $script:Configuration -UseWhatIf $true -ExchangeOnly }
        # Assert
        $act | Should -Throw '*remote enumeration denied*'
        $script:RemoteWrites.Count | Should -Be 0
    }

    It 'checks every domain and sends only the approved Default settings while preserving forwarding and NDR choices' {
        # Arrange
        $remote = $script:Configuration.desiredState.exchangeOnline.remoteDomainDefault
        $remote.allowedOOFType = 'External'
        $remote | Add-Member externalReplyApproval 'CHG-2026-0042'
        $remote.autoForwardEnabled = $true
        $remote.nonDeliveryReportEnabled = $true
        $script:Domains += [pscustomobject]@{ Identity = 'Partner'; DomainName = 'partner.example'; AllowedOOFType = 'External' }
        Mock Get-RemoteDomain { $script:Domains }
        # Act
        Set-OrganizationControls -Configuration $script:Configuration -UseWhatIf $true -ExchangeOnly
        # Assert
        Should -Invoke Get-RemoteDomain -Times 1 -Exactly
        $script:RemoteWrites.Count | Should -Be 1
        $script:RemoteWrites[0].Identity | Should -BeExactly Default
        $script:RemoteWrites[0].AllowedOOFType | Should -BeExactly External
        $script:RemoteWrites[0].AutoForwardEnabled | Should -BeTrue
        $script:RemoteWrites[0].NDREnabled | Should -BeTrue
        $script:RemoteWrites[0].WhatIf | Should -BeTrue
    }
}