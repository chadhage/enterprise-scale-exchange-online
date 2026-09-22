#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
    $script:GatewayConfigurationPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'
    $script:CommonModule = Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -PassThru -ErrorAction Stop

    $script:DesiredEnhancedFiltering = [pscustomobject]@{
        enabled              = $true
        skipLastIp           = $false
        skipIpAddresses      = @('192.0.2.10', '198.51.100.0/24')
        applyToAllRecipients = $true
    }

    function New-EnhancedFilteringConnector {
        param(
            [object]$Identity = 'Contoso inbound gateway',
            [object]$EFSkipLastIP = $false,
            [object]$EFSkipIPs = @('192.0.2.10', '198.51.100.0/24'),
            [object]$EFUsers = @()
        )

        [pscustomobject]@{
            Identity                     = $Identity
            Name                         = $Identity
            ConnectorType                = 'Partner'
            Enabled                      = $true
            SenderDomains                = @('*')
            RequireTls                   = $true
            RestrictDomainsToIPAddresses = $true
            RestrictDomainsToCertificate = $false
            SenderIPAddresses            = @('192.0.2.10', '198.51.100.0/24')
            EFSkipLastIP                  = $EFSkipLastIP
            EFSkipIPs                     = $EFSkipIPs
            EFUsers                       = $EFUsers
        }
    }

    function Get-EnhancedFilteringRecord {
        param([scriptblock]$Collection)

        & $script:CommonModule { param($Seam) Get-EnhancedFilteringEvidence -InboundConnectorCollection $Seam } $Collection
    }

    function Test-EnhancedFilteringRecord {
        param([object]$Evidence, [object]$DesiredState = $script:DesiredEnhancedFiltering, [object]$Identity = 'Contoso inbound gateway')

        & $script:CommonModule {
            param($Record, $Desired, $ConnectorIdentity)
            Test-EnhancedFilteringControl -Evidence $Record -DesiredState $Desired -ConnectorIdentity $ConnectorIdentity
        } $Evidence $DesiredState $Identity
    }

    function New-EnhancedFilteringEvidence {
        param([object[]]$Connector)

        Get-EnhancedFilteringRecord -Collection { $Connector }.GetNewClosure()
    }

    function New-EnhancedFilteringConfigurationMutation {
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

Describe 'PP-002 Enhanced Filtering for Connectors' {
    Context 'Negative: collection requires and preserves the whole connector payload' {
        It 'refuses a missing inbound connector collection seam' {
            # Arrange
            $missing = $null

            # Act
            $act = { Get-EnhancedFilteringRecord -Collection $missing }

            # Assert
            $act | Should -Throw -ExpectedMessage '*InboundConnectorCollectionRequired*'
        }

        It 'records a collection fault instead of propagating it' {
            # Arrange
            $refusing = { throw 'enhanced filtering query failed' }

            # Act
            $evidence = Get-EnhancedFilteringRecord -Collection $refusing

            # Assert
            ('{0}|{1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'False|CollectionFailed:*enhanced filtering query failed*'
        }

        It 'records an empty connector collection as a successful observation' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-EnhancedFilteringRecord -Collection $empty

            # Assert
            ('{0}|{1}' -f $evidence.Collected, (ConvertTo-CanonicalJson -InputObject $evidence.Value)) |
                Should -BeExactly 'True|{"InboundConnector":[]}'
        }

        It 'does not narrow the connector to Enhanced Filtering members' {
            # Arrange
            $connector = New-EnhancedFilteringConnector -Identity ' Raw connector ' -EFSkipLastIP $true -EFUsers @('pilot@contoso.com')

            # Act
            $evidence = Get-EnhancedFilteringRecord -Collection { @($connector) }.GetNewClosure()

            # Assert
            (ConvertTo-CanonicalJson -InputObject $evidence.Value) |
                Should -Match '"ConnectorType":"Partner".*"EFUsers":\["pilot@contoso\.com"\].*"Identity":" Raw connector "'
        }
    }

    Context 'Negative: evaluation requires resolved identity and desired state' {
        It 'refuses a decision with no evidence' {
            # Arrange
            $missing = $null

            # Act
            $act = { Test-EnhancedFilteringRecord -Evidence $missing }

            # Assert
            $act | Should -Throw -ExpectedMessage '*EvidenceRequired*'
        }

        It 'refuses evidence collected for PP-001' {
            # Arrange
            $foreign = & $script:CommonModule {
                New-BaselineEvidence -ControlId 'PP-001' -Source 'ExchangeOnline' -Command 'Get-InboundConnector' -Value ([ordered]@{ InboundConnector = @() })
            }

            # Act
            $act = { Test-EnhancedFilteringRecord -Evidence $foreign }

            # Assert
            $act | Should -Throw -ExpectedMessage '*EvidenceControlMismatch*'
        }

        It 'refuses a decision with no resolved Enhanced Filtering state' {
            # Arrange
            $evidence = New-EnhancedFilteringEvidence -Connector @(New-EnhancedFilteringConnector)

            # Act
            $act = { Test-EnhancedFilteringRecord -Evidence $evidence -DesiredState $null }

            # Assert
            $act | Should -Throw -ExpectedMessage '*DesiredEnhancedFilteringStateRequired*'
        }

        It 'refuses a decision with no resolved connector identity' {
            # Arrange
            $evidence = New-EnhancedFilteringEvidence -Connector @(New-EnhancedFilteringConnector)

            # Act
            $act = { Test-EnhancedFilteringRecord -Evidence $evidence -Identity '' }

            # Assert
            $act | Should -Throw -ExpectedMessage '*EnhancedFilteringConnectorIdentityRequired*'
        }

        It 'refuses desired state that omits <Member>' -ForEach @(
            @{ Member = 'enabled' }
            @{ Member = 'skipLastIp' }
            @{ Member = 'skipIpAddresses' }
            @{ Member = 'applyToAllRecipients' }
        ) {
            # Arrange
            $desired = [ordered]@{}
            $script:DesiredEnhancedFiltering.PSObject.Properties | ForEach-Object { $desired[$_.Name] = $_.Value }
            $desired.Remove($Member)
            $evidence = New-EnhancedFilteringEvidence -Connector @(New-EnhancedFilteringConnector)

            # Act
            $act = { Test-EnhancedFilteringRecord -Evidence $evidence -DesiredState ([pscustomobject]$desired) }

            # Assert
            $act | Should -Throw -ExpectedMessage "*DesiredEnhancedFilteringMemberRequired*$Member*"
        }
    }

    Context 'Negative: incomplete or ambiguous evidence is an Error' {
        It 'returns Error when collection did not complete' {
            # Arrange
            $evidence = Get-EnhancedFilteringRecord -Collection { throw 'service unavailable' }

            # Act
            $result = Test-EnhancedFilteringRecord -Evidence $evidence

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) | Should -BeLike 'Error|EvidenceCollectionFailed:*'
        }

        It 'returns Error when the declared observation is absent' {
            # Arrange
            $evidence = & $script:CommonModule {
                New-BaselineEvidence -ControlId 'PP-002' -Source 'ExchangeOnline' -Command 'Get-InboundConnector' -Value ([ordered]@{ EnhancedFiltering = @() })
            }

            # Act
            $result = Test-EnhancedFilteringRecord -Evidence $evidence

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) | Should -BeExactly "Error|EnhancedFilteringEvidenceIncomplete: the record carries no 'InboundConnector' observation."
        }

        It 'returns Error when two connectors have the resolved identity' {
            # Arrange
            $evidence = New-EnhancedFilteringEvidence -Connector @((New-EnhancedFilteringConnector), (New-EnhancedFilteringConnector))

            # Act
            $result = Test-EnhancedFilteringRecord -Evidence $evidence

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) | Should -BeLike "Error|EnhancedFilteringEvidenceAmbiguous:*2*Contoso inbound gateway*"
        }

        It 'returns Error when the resolved connector omits <Member>' -ForEach @(
            @{ Member = 'EFSkipLastIP' }
            @{ Member = 'EFSkipIPs' }
            @{ Member = 'EFUsers' }
        ) {
            # Arrange
            $connector = [ordered]@{}
            (New-EnhancedFilteringConnector).PSObject.Properties | ForEach-Object { $connector[$_.Name] = $_.Value }
            $connector.Remove($Member)
            $evidence = New-EnhancedFilteringEvidence -Connector @([pscustomobject]$connector)

            # Act
            $result = Test-EnhancedFilteringRecord -Evidence $evidence

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) | Should -BeLike "Error|EnhancedFilteringEvidenceIncomplete:*$Member*"
        }
    }

    Context 'Negative: skip-hop and recipient drift is attributed to PP-002' {
        It 'fails when the resolved connector is absent' {
            # Arrange
            $evidence = New-EnhancedFilteringEvidence -Connector @()

            # Act
            $result = Test-EnhancedFilteringRecord -Evidence $evidence

            # Assert
            ('{0}|{1}|{2}' -f $result.ControlId, $result.Status, $result.Reason) |
                Should -BeLike 'PP-002|Fail|EnhancedFilteringDrift:*Contoso inbound gateway*not present*'
        }

        It 'fails when skip-last-IP differs from the resolved state' {
            # Arrange
            $evidence = New-EnhancedFilteringEvidence -Connector @(New-EnhancedFilteringConnector -EFSkipLastIP $true)

            # Act
            $result = Test-EnhancedFilteringRecord -Evidence $evidence

            # Assert
            ('{0}|{1}|{2}' -f $result.ControlId, $result.Status, $result.Reason) | Should -BeLike 'PP-002|Fail|EnhancedFilteringDrift:*EFSkipLastIP*'
        }

        It 'fails when the skip-IP set differs from every resolved non-Microsoft hop' {
            # Arrange
            $evidence = New-EnhancedFilteringEvidence -Connector @(New-EnhancedFilteringConnector -EFSkipIPs @('192.0.2.10', '203.0.113.8'))

            # Act
            $result = Test-EnhancedFilteringRecord -Evidence $evidence

            # Assert
            ('{0}|{1}|{2}' -f $result.ControlId, $result.Status, $result.Reason) | Should -BeLike 'PP-002|Fail|EnhancedFilteringDrift:*EFSkipIPs*'
        }

        It 'fails when all-recipient scope was resolved but the connector carries pilot recipients' {
            # Arrange
            $evidence = New-EnhancedFilteringEvidence -Connector @(New-EnhancedFilteringConnector -EFUsers @('pilot@contoso.com'))

            # Act
            $result = Test-EnhancedFilteringRecord -Evidence $evidence

            # Assert
            ('{0}|{1}|{2}' -f $result.ControlId, $result.Status, $result.Reason) | Should -BeLike 'PP-002|Fail|EnhancedFilteringDrift:*EFUsers*pilot@contoso.com*'
        }
    }

    Context 'Negative: the Gateway profile schema rejects unsafe PP-002 state' {
        It 'rejects <Case>' -ForEach @(
            @{ Case = 'skip-last-IP enabled'; Mutate = { param($d) $d.desiredState.mailFlow.enhancedFiltering.skipLastIp = $true } }
            @{ Case = 'an empty skip-IP set'; Mutate = { param($d) $d.desiredState.mailFlow.enhancedFiltering.skipIpAddresses = @() } }
            @{ Case = 'pilot-recipient scope'; Mutate = { param($d) $d.desiredState.mailFlow.enhancedFiltering.applyToAllRecipients = $false } }
        ) {
            # Arrange
            $path = New-EnhancedFilteringConfigurationMutation -Mutate $Mutate -Path (Join-Path $TestDrive (($Case -replace '[^A-Za-z0-9]', '-') + '.json'))

            # Act
            $valid = Test-Json -Json (Get-Content -LiteralPath $path -Raw) -SchemaFile $script:SchemaPath -ErrorAction SilentlyContinue

            # Assert
            $valid | Should -BeFalse
        }
    }

    Context 'Positive: exact skip-hop and all-recipient state satisfies PP-002' {
        It 'passes one complete observation that exactly matches the resolved Enhanced Filtering state' {
            # Arrange
            $evidence = & $script:CommonModule {
                param($Connector)
                New-BaselineEvidence -ControlId 'PP-002' -Source 'ExchangeOnline' -Command 'Get-InboundConnector' `
                    -Value ([ordered]@{ InboundConnector = @($Connector) })
            } (New-EnhancedFilteringConnector)

            # Act
            $result = Test-EnhancedFilteringRecord -Evidence $evidence

            # Assert
            ('{0}|{1}|golive={2}|{3}' -f $result.ControlId, $result.Status, $result.GoLiveSuccess, $result.Evidence.Command) |
                Should -BeExactly 'PP-002|Pass|golive=True|Get-InboundConnector'
        }
    }
}