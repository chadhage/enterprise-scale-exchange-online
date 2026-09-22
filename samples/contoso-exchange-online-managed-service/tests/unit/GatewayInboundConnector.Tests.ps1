#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
    $script:GatewayConfigurationPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'
    $script:CommonModule = Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -PassThru -ErrorAction Stop

    $script:DesiredInboundConnector = [pscustomobject]@{
        connectorType                = 'Partner'
        enabled                      = $true
        senderDomains                = @('*')
        requireTls                   = $true
        restrictDomainsToIpAddresses = $true
        restrictDomainsToCertificate = $false
        senderIpAddresses            = @('192.0.2.10', '198.51.100.0/24')
    }

    function New-InboundConnector {
        param(
            [object]$Identity = 'Contoso inbound gateway',
            [object]$ConnectorType = 'Partner',
            [object]$Enabled = $true,
            [object]$SenderDomains = @('*'),
            [object]$RequireTls = $true,
            [object]$RestrictDomainsToIPAddresses = $true,
            [object]$RestrictDomainsToCertificate = $false,
            [object]$SenderIPAddresses = @('192.0.2.10', '198.51.100.0/24')
        )

        [pscustomobject]@{
            Identity                     = $Identity
            Name                         = $Identity
            ConnectorType                = $ConnectorType
            Enabled                      = $Enabled
            SenderDomains                = $SenderDomains
            RequireTls                   = $RequireTls
            RestrictDomainsToIPAddresses = $RestrictDomainsToIPAddresses
            RestrictDomainsToCertificate = $RestrictDomainsToCertificate
            SenderIPAddresses            = $SenderIPAddresses
            EFSkipLastIP                  = $false
            EFSkipIPs                     = @('192.0.2.10')
            EFUsers                       = @()
        }
    }

    function Get-GatewayInboundEvidence {
        param([scriptblock]$Collection)

        & $script:CommonModule { param($Seam) Get-GatewayInboundConnectorEvidence -InboundConnectorCollection $Seam } $Collection
    }

    function Test-GatewayInboundEvidence {
        param([object]$Evidence, [object]$DesiredState = $script:DesiredInboundConnector, [object]$Identity = 'Contoso inbound gateway')

        & $script:CommonModule {
            param($Record, $Desired, $ConnectorIdentity)
            Test-GatewayInboundConnectorControl -Evidence $Record -DesiredState $Desired -ConnectorIdentity $ConnectorIdentity
        } $Evidence $DesiredState $Identity
    }

    function New-GatewayInboundEvidence {
        param([object[]]$Connector)

        Get-GatewayInboundEvidence -Collection { $Connector }.GetNewClosure()
    }

    function New-GatewayConfigurationMutation {
        param([scriptblock]$Mutate, [string]$Path)

        $document = Get-Content -LiteralPath $script:GatewayConfigurationPath -Raw | ConvertFrom-Json -AsHashtable
        & $Mutate $document
        $document | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Path
        return $Path
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'PP-001 gateway inbound connector' {
    Context 'Negative: collection requires and preserves the whole tenant payload' {
        It 'refuses a missing inbound connector collection seam' {
            # Arrange
            $missing = $null

            # Act
            $act = { Get-GatewayInboundEvidence -Collection $missing }

            # Assert
            $act | Should -Throw -ExpectedMessage '*InboundConnectorCollectionRequired*'
        }

        It 'records a collection fault instead of propagating it' {
            # Arrange
            $refusing = { throw 'inbound connector query throttled' }

            # Act
            $evidence = Get-GatewayInboundEvidence -Collection $refusing

            # Assert
            ('{0}|{1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'False|CollectionFailed:*inbound connector query throttled*'
        }

        It 'records an empty connector collection as a successful observation' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-GatewayInboundEvidence -Collection $empty

            # Assert
            ('{0}|{1}' -f $evidence.Collected, (ConvertTo-CanonicalJson -InputObject $evidence.Value)) |
                Should -BeExactly 'True|{"InboundConnector":[]}'
        }

        It 'does not narrow or reshape the connector payload' {
            # Arrange
            $connector = New-InboundConnector -Identity ' Raw connector ' -Enabled $false -SenderDomains @('example.com', '*')

            # Act
            $evidence = Get-GatewayInboundEvidence -Collection { @($connector) }.GetNewClosure()

            # Assert
            (ConvertTo-CanonicalJson -InputObject $evidence.Value) |
                Should -BeExactly ('{"InboundConnector":[{"ConnectorType":"Partner","EFSkipIPs":["192.0.2.10"],' +
                    '"EFSkipLastIP":false,"EFUsers":[],"Enabled":false,"Identity":" Raw connector ","Name":" Raw connector ",' +
                    '"RequireTls":true,"RestrictDomainsToCertificate":false,"RestrictDomainsToIPAddresses":true,' +
                    '"SenderDomains":["example.com","*"],"SenderIPAddresses":["192.0.2.10","198.51.100.0/24"]}]}')
        }
    }

    Context 'Negative: evaluation requires resolved identity and desired state' {
        It 'refuses a decision with no evidence' {
            # Arrange
            $missing = $null

            # Act
            $act = { Test-GatewayInboundEvidence -Evidence $missing }

            # Assert
            $act | Should -Throw -ExpectedMessage '*EvidenceRequired*'
        }

        It 'refuses evidence collected for PP-002' {
            # Arrange
            $foreign = & $script:CommonModule {
                New-BaselineEvidence -ControlId 'PP-002' -Source 'ExchangeOnline' -Command 'Get-InboundConnector' -Value ([ordered]@{ InboundConnector = @() })
            }

            # Act
            $act = { Test-GatewayInboundEvidence -Evidence $foreign }

            # Assert
            $act | Should -Throw -ExpectedMessage '*EvidenceControlMismatch*'
        }

        It 'refuses a decision with no resolved connector desired state' {
            # Arrange
            $evidence = New-GatewayInboundEvidence -Connector @(New-InboundConnector)

            # Act
            $act = { Test-GatewayInboundEvidence -Evidence $evidence -DesiredState $null }

            # Assert
            $act | Should -Throw -ExpectedMessage '*DesiredGatewayInboundConnectorStateRequired*'
        }

        It 'refuses a decision with no resolved connector identity' {
            # Arrange
            $evidence = New-GatewayInboundEvidence -Connector @(New-InboundConnector)

            # Act
            $act = { Test-GatewayInboundEvidence -Evidence $evidence -Identity ' ' }

            # Assert
            $act | Should -Throw -ExpectedMessage '*GatewayInboundConnectorIdentityRequired*'
        }

        It 'refuses desired state that omits <Member>' -ForEach @(
            @{ Member = 'connectorType' }
            @{ Member = 'enabled' }
            @{ Member = 'senderDomains' }
            @{ Member = 'requireTls' }
            @{ Member = 'restrictDomainsToIpAddresses' }
            @{ Member = 'restrictDomainsToCertificate' }
            @{ Member = 'senderIpAddresses' }
        ) {
            # Arrange
            $desired = [ordered]@{}
            $script:DesiredInboundConnector.PSObject.Properties | ForEach-Object { $desired[$_.Name] = $_.Value }
            $desired.Remove($Member)
            $evidence = New-GatewayInboundEvidence -Connector @(New-InboundConnector)

            # Act
            $act = { Test-GatewayInboundEvidence -Evidence $evidence -DesiredState ([pscustomobject]$desired) }

            # Assert
            $act | Should -Throw -ExpectedMessage "*DesiredGatewayInboundConnectorMemberRequired*$Member*"
        }
    }

    Context 'Negative: incomplete or ambiguous evidence is an Error' {
        It 'returns Error when collection did not complete' {
            # Arrange
            $evidence = Get-GatewayInboundEvidence -Collection { throw 'service unavailable' }

            # Act
            $result = Test-GatewayInboundEvidence -Evidence $evidence

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) | Should -BeLike 'Error|EvidenceCollectionFailed:*'
        }

        It 'returns Error when the declared observation is absent' {
            # Arrange
            $evidence = & $script:CommonModule {
                New-BaselineEvidence -ControlId 'PP-001' -Source 'ExchangeOnline' -Command 'Get-InboundConnector' -Value ([ordered]@{ Connector = @() })
            }

            # Act
            $result = Test-GatewayInboundEvidence -Evidence $evidence

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) | Should -BeExactly "Error|GatewayInboundConnectorEvidenceIncomplete: the record carries no 'InboundConnector' observation."
        }

        It 'returns Error when two connectors have the resolved identity' {
            # Arrange
            $evidence = New-GatewayInboundEvidence -Connector @((New-InboundConnector), (New-InboundConnector))

            # Act
            $result = Test-GatewayInboundEvidence -Evidence $evidence

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) | Should -BeLike "Error|GatewayInboundConnectorEvidenceAmbiguous:*2*Contoso inbound gateway*"
        }

        It 'returns Error when the resolved connector omits <Member>' -ForEach @(
            @{ Member = 'Identity' }
            @{ Member = 'ConnectorType' }
            @{ Member = 'Enabled' }
            @{ Member = 'SenderDomains' }
            @{ Member = 'RequireTls' }
            @{ Member = 'RestrictDomainsToIPAddresses' }
            @{ Member = 'RestrictDomainsToCertificate' }
            @{ Member = 'SenderIPAddresses' }
        ) {
            # Arrange
            $connector = [ordered]@{}
            (New-InboundConnector).PSObject.Properties | ForEach-Object { $connector[$_.Name] = $_.Value }
            $connector.Remove($Member)
            if ($Member -ceq 'Identity') { $connector['Name'] = $null }
            $evidence = New-GatewayInboundEvidence -Connector @([pscustomobject]$connector)

            # Act
            $result = Test-GatewayInboundEvidence -Evidence $evidence

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) | Should -BeLike "Error|GatewayInboundConnectorEvidenceIncomplete:*$Member*"
        }
    }

    Context 'Negative: every inbound connector constraint is attributed to PP-001' {
        It 'fails when the resolved connector is absent' {
            # Arrange
            $evidence = New-GatewayInboundEvidence -Connector @()

            # Act
            $result = Test-GatewayInboundEvidence -Evidence $evidence

            # Assert
            ('{0}|{1}|{2}' -f $result.ControlId, $result.Status, $result.Reason) |
                Should -BeLike 'PP-001|Fail|GatewayInboundConnectorDrift:*Contoso inbound gateway*not present*'
        }

        It 'fails on <Member> drift and names that member' -ForEach @(
            @{ Member = 'ConnectorType'; Value = 'OnPremises' }
            @{ Member = 'Enabled'; Value = $false }
            @{ Member = 'SenderDomains'; Value = @('example.com') }
            @{ Member = 'RequireTls'; Value = $false }
            @{ Member = 'RestrictDomainsToIPAddresses'; Value = $false }
            @{ Member = 'RestrictDomainsToCertificate'; Value = $true }
            @{ Member = 'SenderIPAddresses'; Value = @('203.0.113.9') }
        ) {
            # Arrange
            $argument = @{ $Member = $Value }
            $evidence = New-GatewayInboundEvidence -Connector @(New-InboundConnector @argument)

            # Act
            $result = Test-GatewayInboundEvidence -Evidence $evidence

            # Assert
            ('{0}|{1}|{2}' -f $result.ControlId, $result.Status, $result.Reason) |
                Should -BeLike "PP-001|Fail|GatewayInboundConnectorDrift:*$Member*"
        }
    }

    Context 'Negative: the Gateway profile schema rejects an unsafe PP-001 declaration' {
        It 'rejects <Case>' -ForEach @(
            @{ Case = 'a non-Partner connector'; Mutate = { param($d) $d.desiredState.mailFlow.gatewayInboundConnector.connectorType = 'OnPremises' } }
            @{ Case = 'a disabled connector'; Mutate = { param($d) $d.desiredState.mailFlow.gatewayInboundConnector.enabled = $false } }
            @{ Case = 'a connector that does not require TLS'; Mutate = { param($d) $d.desiredState.mailFlow.gatewayInboundConnector.requireTls = $false } }
            @{ Case = 'an empty sender-domain scope'; Mutate = { param($d) $d.desiredState.mailFlow.gatewayInboundConnector.senderDomains = @() } }
            @{ Case = 'an empty source-IP scope'; Mutate = { param($d) $d.desiredState.mailFlow.gatewayInboundConnector.senderIpAddresses = @() } }
            @{ Case = 'a connector not restricted to source IPs'; Mutate = { param($d) $d.desiredState.mailFlow.gatewayInboundConnector.restrictDomainsToIpAddresses = $false } }
            @{ Case = 'a connector restricted to an undeclared certificate'; Mutate = { param($d) $d.desiredState.mailFlow.gatewayInboundConnector.restrictDomainsToCertificate = $true } }
        ) {
            # Arrange
            $path = New-GatewayConfigurationMutation -Mutate $Mutate -Path (Join-Path $TestDrive (($Case -replace '[^A-Za-z0-9]', '-') + '.json'))

            # Act
            $valid = Test-Json -Json (Get-Content -LiteralPath $path -Raw) -SchemaFile $script:SchemaPath -ErrorAction SilentlyContinue

            # Assert
            $valid | Should -BeFalse
        }
    }

    Context 'Positive: one exact Gateway inbound connector satisfies PP-001' {
        It 'passes one complete observation that exactly matches the resolved connector state' {
            # Arrange
            $evidence = & $script:CommonModule {
                param($Connector)
                New-BaselineEvidence -ControlId 'PP-001' -Source 'ExchangeOnline' -Command 'Get-InboundConnector' `
                    -Value ([ordered]@{ InboundConnector = @($Connector) })
            } (New-InboundConnector)

            # Act
            $result = Test-GatewayInboundEvidence -Evidence $evidence

            # Assert
            ('{0}|{1}|golive={2}|{3}' -f $result.ControlId, $result.Status, $result.GoLiveSuccess, $result.Evidence.Command) |
                Should -BeExactly 'PP-001|Pass|golive=True|Get-InboundConnector'
        }
    }
}