#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $script:SampleRoot 'scripts\ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking

    function New-PartnerEvidence {
        param([object[]]$Connector = @())
        Get-PartnerInboundConnectorEvidence -InboundConnectorCollection { $Connector }.GetNewClosure()
    }
}

Describe 'PP-005 Partner inbound connector collector' {
    It 'refuses a missing inbound connector collection seam' {
        # Arrange
        $act = { Get-PartnerInboundConnectorEvidence -InboundConnectorCollection $null }
        # Act / Assert
        $act | Should -Throw '*InboundConnectorCollectionRequired*'
    }

    It 'records an inbound connector collection failure' {
        # Arrange
        $collection = { throw 'offline throttle' }
        # Act
        $evidence = Get-PartnerInboundConnectorEvidence -InboundConnectorCollection $collection
        # Assert
        $evidence.ControlId | Should -BeExactly 'PP-005'
        $evidence.Collected | Should -BeFalse
    }

    It 'does not filter disabled or non-Partner connectors during collection' {
        # Arrange
        $payload = @(
            [pscustomobject]@{ Name = 'disabled'; ConnectorType = 'Partner'; Enabled = $false; SenderIPAddresses = @('192.0.2.1') },
            [pscustomobject]@{ Name = 'on-premises'; ConnectorType = 'OnPremises'; Enabled = $true; SenderIPAddresses = @() }
        )
        # Act
        $evidence = New-PartnerEvidence -Connector $payload
        # Assert
        @($evidence.Value).Count | Should -Be 2
        $evidence.Command | Should -BeExactly 'Get-InboundConnector'
    }

    It 'collects a successful empty observation rather than a failure' {
        # Arrange
        $payload = @()
        # Act
        $evidence = New-PartnerEvidence -Connector $payload
        # Assert
        $evidence.Collected | Should -BeTrue
        $evidence.Value | Should -BeNullOrEmpty
        $evidence.ControlId | Should -BeExactly 'PP-005'
    }
}

Describe 'PP-005 Partner inbound connector evaluator' {
    It 'returns Error when connector collection failed' {
        # Arrange
        $evidence = Get-PartnerInboundConnectorEvidence -InboundConnectorCollection { throw 'denied' }
        # Act
        $result = Test-PartnerInboundConnectorControl -Evidence $evidence
        # Assert
        $result.Status | Should -BeExactly 'Error'
    }

    It 'returns Error when an observed connector has no type or enabled state' {
        # Arrange
        $evidence = New-PartnerEvidence -Connector @([pscustomobject]@{ Name = 'partial' })
        # Act
        $result = Test-PartnerInboundConnectorControl -Evidence $evidence
        # Assert
        $result.Status | Should -BeExactly 'Error'
    }

    It 'fails every enabled Partner connector and identifies PP-005' {
        # Arrange
        $evidence = New-PartnerEvidence -Connector @(
            [pscustomobject]@{ Name = 'undeclared-one'; ConnectorType = 'Partner'; Enabled = $true },
            [pscustomobject]@{ Name = 'undeclared-two'; ConnectorType = 'Partner'; Enabled = $true }
        )
        # Act
        $result = Test-PartnerInboundConnectorControl -Evidence $evidence
        # Assert
        $result.ControlId | Should -BeExactly 'PP-005'
        $result.Status | Should -BeExactly 'Fail'
        $result.Reason | Should -Match 'undeclared-one'
        $result.Reason | Should -Match 'undeclared-two'
    }

    It 'ignores disabled Partner and enabled non-Partner connectors' {
        # Arrange
        $evidence = New-PartnerEvidence -Connector @(
            [pscustomobject]@{ Name = 'disabled'; ConnectorType = 'Partner'; Enabled = $false },
            [pscustomobject]@{ Name = 'on-premises'; ConnectorType = 'OnPremises'; Enabled = $true }
        )
        # Act
        $result = Test-PartnerInboundConnectorControl -Evidence $evidence
        # Assert
        $result.Status | Should -BeExactly 'Pass'
    }

    It 'passes only from a successful empty Native observation' {
        # Arrange
        $evidence = New-PartnerEvidence -Connector @()
        # Act
        $result = Test-PartnerInboundConnectorControl -Evidence $evidence
        # Assert
        $result.ControlId | Should -BeExactly 'PP-005'
        $result.Status | Should -BeExactly 'Pass'
        $result.GoLiveSuccess | Should -BeTrue
    }
}