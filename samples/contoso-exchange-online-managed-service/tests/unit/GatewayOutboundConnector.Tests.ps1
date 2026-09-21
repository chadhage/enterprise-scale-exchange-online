#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:DeploymentScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
    $script:ConfigurationPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    Set-Item function:Get-OutboundConnector { param($Identity, $ErrorAction) }
    Set-Item function:New-OutboundConnector { param($Name, $Enabled, $ConnectorType, $RecipientDomains, $RouteAllMessagesViaOnPremises, $UseMXRecord, $SmartHosts, $TlsSettings, $TlsDomain, $WhatIf) }
    Set-Item function:Set-OutboundConnector { param($Identity, $Enabled, $ConnectorType, $RecipientDomains, $RouteAllMessagesViaOnPremises, $UseMXRecord, $SmartHosts, $TlsSettings, $TlsDomain, $WhatIf) }

    $tokens = $null
    $parseErrors = $null
    $deploymentAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:DeploymentScriptPath,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join [Environment]::NewLine) }

    $definition = @($deploymentAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Set-OutboundGatewayConnector'
            }, $true))
    if ($definition.Count -ne 1) { throw 'Expected one Set-OutboundGatewayConnector definition in the deployment script.' }
    . ([scriptblock]::Create($definition[0].Extent.Text))

    function Add-Outcome {
        param([string]$Control, [string]$Status, [string]$Detail, [string[]]$Operation = @())
        $script:OutboundOutcomes.Add([pscustomobject]@{ Control = $Control; Status = $Status; Detail = $Detail; Operation = @($Operation) })
    }

    function New-OutboundDesiredState {
        return [pscustomobject]@{
            enabled                       = $true
            connectorType                 = 'Partner'
            recipientDomains              = @('*')
            routeAllMessagesViaOnPremises = $true
            useMxRecord                   = $false
            smartHosts                    = @('smtp1.gateway.example', 'smtp2.gateway.example')
            tlsSettings                   = 'DomainValidation'
            tlsDomain                     = '*.gateway.example'
        }
    }

    function New-OutboundConnectorRecord {
        param([hashtable]$Override = @{})

        $record = [ordered]@{
            Name                          = 'Contoso outbound gateway'
            Enabled                       = $true
            ConnectorType                 = 'Partner'
            RecipientDomains              = @('*')
            RouteAllMessagesViaOnPremises = $true
            UseMXRecord                   = $false
            SmartHosts                    = @('smtp1.gateway.example', 'smtp2.gateway.example')
            TlsSettings                   = 'DomainValidation'
            TlsDomain                     = '*.gateway.example'
        }
        foreach ($key in $Override.Keys) { $record[$key] = $Override[$key] }
        return [pscustomobject]$record
    }

    function New-OutboundEvidence {
        param([object[]]$Connector = @((New-OutboundConnectorRecord)))
        return Get-GatewayOutboundConnectorEvidence -Collection { $Connector }.GetNewClosure()
    }

    function New-OutboundDeploymentConfiguration {
        return [pscustomobject]@{
            administratorInputs = [pscustomobject]@{ gatewayOutboundConnectorName = 'Contoso outbound gateway' }
            desiredState = [pscustomobject]@{
                mailFlow = [pscustomobject]@{ gatewayOutboundConnector = New-OutboundDesiredState }
            }
        }
    }

    function Test-MutatedOutboundConfiguration {
        param([scriptblock]$Mutation)

        $configuration = Get-Content -LiteralPath $script:ConfigurationPath -Raw | ConvertFrom-Json -Depth 100
        & $Mutation $configuration.desiredState.mailFlow.gatewayOutboundConnector
        return ($configuration | ConvertTo-Json -Depth 100) | Test-Json -SchemaFile $script:SchemaPath -ErrorAction SilentlyContinue
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'PP-003 gateway outbound connector collector' {
    Context 'Negative: collection must be complete and raw' {
        It 'refuses a collection with no Exchange Online call to run' {
            # Arrange
            $collection = $null

            # Act
            $act = { Get-GatewayOutboundConnectorEvidence -Collection $collection }

            # Assert
            $act | Should -Throw -ExpectedMessage 'CollectionRequired*'
        }

        It 'records a refused Get-OutboundConnector call as uncollected evidence' {
            # Arrange
            $collection = { throw 'outbound connector collection failed' }

            # Act
            $evidence = Get-GatewayOutboundConnectorEvidence -Collection $collection

            # Assert
            $evidence.ControlId | Should -BeExactly 'PP-003'
            $evidence.Collected | Should -BeFalse
            $evidence.FailureReason | Should -BeLike 'CollectionFailed:*outbound connector collection failed*'
        }

        It 'does not reshape the whole connector payload into selected members' {
            # Arrange
            $connector = New-OutboundConnectorRecord -Override @{ Identity = 'connector-id'; WhenChanged = '2026-09-19T00:00:00Z' }

            # Act
            $evidence = Get-GatewayOutboundConnectorEvidence -Collection { $connector }.GetNewClosure()

            # Assert
            $evidence.Value.Identity | Should -BeExactly 'connector-id'
            $evidence.Value.WhenChanged | Should -BeExactly '2026-09-19T00:00:00Z'
        }

        It 'returns evidence whose nested payload rejects assignment' {
            # Arrange
            $evidence = New-OutboundEvidence

            # Act
            $act = { $evidence.Value[0].Enabled = $false }

            # Assert
            $act | Should -Throw
        }
    }
}

Describe 'PP-003 gateway outbound connector evaluator' {
    Context 'Negative: a decision requires PP-003 evidence and complete desired state' {
        It 'refuses a decision with no evidence' {
            # Arrange
            $evidence = $null

            # Act
            $act = { Test-GatewayOutboundConnectorControl -Evidence $evidence -DesiredState (New-OutboundDesiredState) }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceRequired*'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $evidence = New-BaselineEvidence -ControlId 'PP-001' -Source 'ExchangeOnline' -Command 'Get-InboundConnector' -Value $null

            # Act
            $act = { Test-GatewayOutboundConnectorControl -Evidence $evidence -DesiredState (New-OutboundDesiredState) }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceControlMismatch*'
        }

        It 'refuses a decision with no resolved outbound desired state' {
            # Arrange
            $evidence = New-OutboundEvidence

            # Act
            $act = { Test-GatewayOutboundConnectorControl -Evidence $evidence -DesiredState $null }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DesiredStateRequired*'
        }

        It 'returns Error when connector collection failed' {
            # Arrange
            $evidence = Get-GatewayOutboundConnectorEvidence -Collection { throw 'session disconnected' }

            # Act
            $result = Test-GatewayOutboundConnectorControl -Evidence $evidence -DesiredState (New-OutboundDesiredState)

            # Assert
            $result.Status | Should -BeExactly 'Error'
            $result.Reason | Should -BeLike 'EvidenceCollectionFailed:*session disconnected*'
            $result.GoLiveSuccess | Should -BeFalse
        }

        It 'fails when the named outbound connector is absent' {
            # Arrange
            $evidence = New-OutboundEvidence -Connector @()

            # Act
            $result = Test-GatewayOutboundConnectorControl -Evidence $evidence -DesiredState (New-OutboundDesiredState)

            # Assert
            $result.Status | Should -BeExactly 'Fail'
            $result.Reason | Should -BeLike 'GatewayOutboundConnectorDrift:*no gateway outbound connector*'
        }

        It 'returns Error when an observed connector omits a decided member' {
            # Arrange
            $connector = New-OutboundConnectorRecord
            $connector.PSObject.Properties.Remove('TlsDomain')
            $evidence = New-OutboundEvidence -Connector @($connector)

            # Act
            $result = Test-GatewayOutboundConnectorControl -Evidence $evidence -DesiredState (New-OutboundDesiredState)

            # Assert
            $result.Status | Should -BeExactly 'Error'
            $result.Reason | Should -BeLike '*TlsDomain*'
        }
    }

    Context 'Negative: every outbound connector member is attributed to PP-003' {
        It 'fails PP-003 when <Member> drifts' -ForEach @(
            @{ Member = 'Enabled'; Value = $false; Label = 'Enabled' }
            @{ Member = 'ConnectorType'; Value = 'OnPremises'; Label = 'ConnectorType' }
            @{ Member = 'RecipientDomains'; Value = @('contoso.com'); Label = 'RecipientDomains' }
            @{ Member = 'RouteAllMessagesViaOnPremises'; Value = $false; Label = 'RouteAllMessagesViaOnPremises' }
            @{ Member = 'UseMXRecord'; Value = $true; Label = 'UseMXRecord' }
            @{ Member = 'SmartHosts'; Value = @('wrong.gateway.example'); Label = 'SmartHosts' }
            @{ Member = 'TlsSettings'; Value = 'CertificateValidation'; Label = 'TlsSettings' }
            @{ Member = 'TlsDomain'; Value = '*.wrong.example'; Label = 'TlsDomain' }
        ) {
            # Arrange
            $evidence = New-OutboundEvidence -Connector @((New-OutboundConnectorRecord -Override @{ $Member = $Value }))

            # Act
            $result = Test-GatewayOutboundConnectorControl -Evidence $evidence -DesiredState (New-OutboundDesiredState)

            # Assert
            $result.ControlId | Should -BeExactly 'PP-003'
            $result.Status | Should -BeExactly 'Fail'
            $result.Reason | Should -BeLike "GatewayOutboundConnectorDrift:*$Label*"
            $result.GoLiveSuccess | Should -BeFalse
        }
    }
}

Describe 'PP-003 gateway outbound connector desired-state schema' {
    Context 'Negative: routing, smart-host and TLS state are mandatory and constrained' {
        It 'rejects gateway outbound state missing <Member>' -ForEach @(
            @{ Member = 'enabled' }
            @{ Member = 'connectorType' }
            @{ Member = 'recipientDomains' }
            @{ Member = 'routeAllMessagesViaOnPremises' }
            @{ Member = 'useMxRecord' }
            @{ Member = 'smartHosts' }
            @{ Member = 'tlsSettings' }
            @{ Member = 'tlsDomain' }
        ) {
            # Arrange
            $mutation = { param($outbound) $outbound.PSObject.Properties.Remove($Member) }.GetNewClosure()

            # Act
            $valid = Test-MutatedOutboundConfiguration -Mutation $mutation

            # Assert
            $valid | Should -BeFalse
        }

        It 'rejects <Member> set to an unsafe value' -ForEach @(
            @{ Member = 'enabled'; Value = $false }
            @{ Member = 'connectorType'; Value = 'OnPremises' }
            @{ Member = 'recipientDomains'; Value = @('contoso.com') }
            @{ Member = 'routeAllMessagesViaOnPremises'; Value = $false }
            @{ Member = 'useMxRecord'; Value = $true }
            @{ Member = 'smartHosts'; Value = @() }
            @{ Member = 'tlsSettings'; Value = 'CertificateValidation' }
            @{ Member = 'tlsDomain'; Value = '' }
        ) {
            # Arrange
            $mutation = { param($outbound) $outbound.$Member = $Value }.GetNewClosure()

            # Act
            $valid = Test-MutatedOutboundConfiguration -Mutation $mutation

            # Assert
            $valid | Should -BeFalse
        }
    }
}

Describe 'PP-003 outbound connector deployment failures' {
    BeforeEach {
        $script:OutboundOutcomes = [System.Collections.Generic.List[object]]::new()
        Mock Get-OutboundConnector { $null }
        Mock New-OutboundConnector { }
        Mock Set-OutboundConnector { }
    }

    Context 'Negative: discovery and mutation failures never report success' {
        It 'propagates connector discovery failure before mutation' {
            # Arrange
            $configuration = New-OutboundDeploymentConfiguration
            Mock Get-OutboundConnector { throw 'outbound discovery failed' }

            # Act
            $act = { Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw '*outbound discovery failed*'
            $script:OutboundOutcomes.Count | Should -Be 0
            Should -Invoke New-OutboundConnector -Times 0 -Exactly
            Should -Invoke Set-OutboundConnector -Times 0 -Exactly
        }

        It 'propagates connector creation failure without reporting success' {
            # Arrange
            $configuration = New-OutboundDeploymentConfiguration
            Mock New-OutboundConnector { throw 'outbound creation failed' }

            # Act
            $act = { Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw '*outbound creation failed*'
            $script:OutboundOutcomes.Count | Should -Be 0
        }

        It 'propagates connector update failure without reporting success' {
            # Arrange
            $configuration = New-OutboundDeploymentConfiguration
            Mock Get-OutboundConnector { New-OutboundConnectorRecord -Override @{ Enabled = $false } }
            Mock Set-OutboundConnector { throw 'outbound update failed' }

            # Act
            $act = { Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw '*outbound update failed*'
            $script:OutboundOutcomes.Count | Should -Be 0
        }
    }
}

Describe 'PP-003 gateway outbound connector positives' {
    Context 'Positive: one collection preserves the complete service payload' {
        It 'records every outbound connector whole under PP-003' {
            # Arrange
            $connectors = @(
                (New-OutboundConnectorRecord -Override @{ Identity = 'primary-id'; WhenChanged = '2026-09-19T00:00:00Z' }),
                (New-OutboundConnectorRecord -Override @{ Name = 'Unrelated connector'; Enabled = $false; Identity = 'other-id' })
            )

            # Act
            $evidence = Get-GatewayOutboundConnectorEvidence -Collection { $connectors }.GetNewClosure()

            # Assert
            $evidence.ControlId | Should -BeExactly 'PP-003'
            $evidence.Source | Should -BeExactly 'ExchangeOnline'
            $evidence.Command | Should -BeExactly 'Get-OutboundConnector'
            $evidence.Collected | Should -BeTrue
            @($evidence.Value).Count | Should -Be 2
            $evidence.Value[0].Identity | Should -BeExactly 'primary-id'
            $evidence.Value[0].WhenChanged | Should -BeExactly '2026-09-19T00:00:00Z'
            $evidence.Value[1].Identity | Should -BeExactly 'other-id'
        }
    }

    Context 'Positive: exact desired connector state is the only passing verdict' {
        It 'passes formatting-equivalent domains and smart hosts with every required member exact' {
            # Arrange
            $desired = New-OutboundDesiredState
            $desired.smartHosts = @(' SMTP2.GATEWAY.EXAMPLE. ', 'smtp1.gateway.example')
            $desired.tlsDomain = ' *.GATEWAY.EXAMPLE. '
            $connector = New-OutboundConnectorRecord -Override @{
                SmartHosts = @('smtp1.gateway.example.', 'SMTP2.GATEWAY.EXAMPLE')
                TlsDomain  = '*.gateway.example'
            }
            $evidence = New-OutboundEvidence -Connector @($connector)

            # Act
            $result = Test-GatewayOutboundConnectorControl -Evidence $evidence -DesiredState $desired

            # Assert
            $result.ControlId | Should -BeExactly 'PP-003'
            $result.Status | Should -BeExactly 'Pass'
            $result.GoLiveSuccess | Should -BeTrue
            $result.Evidence.Command | Should -BeExactly 'Get-OutboundConnector'
        }
    }

    Context 'Positive: the shipped Gateway outbound desired state satisfies its schema' {
        It 'admits the complete Partner smart-host route with domain-validated TLS' {
            # Arrange
            $configuration = Get-Content -LiteralPath $script:ConfigurationPath -Raw

            # Act
            $valid = $configuration | Test-Json -SchemaFile $script:SchemaPath -ErrorAction SilentlyContinue

            # Assert
            $valid | Should -BeTrue
        }
    }
}

Describe 'PP-003 outbound connector deployment positives' {
    BeforeEach {
        $script:OutboundOutcomes = [System.Collections.Generic.List[object]]::new()
        Mock Get-OutboundConnector { $null }
        Mock New-OutboundConnector { }
        Mock Set-OutboundConnector { }
    }

    Context 'Positive: create branch' {
        It 'creates a missing connector with every resolved routing and TLS argument' {
            # Arrange
            $configuration = New-OutboundDeploymentConfiguration

            # Act
            Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $true -Confirm:$false

            # Assert
            Should -Invoke New-OutboundConnector -Times 1 -Exactly -ParameterFilter {
                $Name -eq 'Contoso outbound gateway' -and
                $Enabled -eq $true -and
                $ConnectorType -eq 'Partner' -and
                (@($RecipientDomains) -join '|') -eq '*' -and
                $RouteAllMessagesViaOnPremises -eq $true -and
                $UseMXRecord -eq $false -and
                (@($SmartHosts) -join '|') -eq 'smtp1.gateway.example|smtp2.gateway.example' -and
                $TlsSettings -eq 'DomainValidation' -and
                $TlsDomain -eq '*.gateway.example' -and
                $WhatIf -eq $true
            }
            Should -Invoke Set-OutboundConnector -Times 0 -Exactly
            $script:OutboundOutcomes[0].Control | Should -BeExactly 'PP-003'
            $script:OutboundOutcomes[0].Status | Should -BeExactly 'Planned'
        }
    }

    Context 'Positive: update branch' {
        It 'updates a drifted connector with every resolved routing and TLS argument' {
            # Arrange
            $configuration = New-OutboundDeploymentConfiguration
            Mock Get-OutboundConnector { New-OutboundConnectorRecord -Override @{ UseMXRecord = $true } }

            # Act
            Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke Set-OutboundConnector -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Contoso outbound gateway' -and
                $Enabled -eq $true -and
                $ConnectorType -eq 'Partner' -and
                (@($RecipientDomains) -join '|') -eq '*' -and
                $RouteAllMessagesViaOnPremises -eq $true -and
                $UseMXRecord -eq $false -and
                (@($SmartHosts) -join '|') -eq 'smtp1.gateway.example|smtp2.gateway.example' -and
                $TlsSettings -eq 'DomainValidation' -and
                $TlsDomain -eq '*.gateway.example' -and
                $WhatIf -eq $false
            }
            Should -Invoke New-OutboundConnector -Times 0 -Exactly
            $script:OutboundOutcomes[0].Status | Should -BeExactly 'Applied'
        }
    }

    Context 'Positive: no-op branch' {
        It 'does not mutate a connector whose normalized set state already matches' {
            # Arrange
            $configuration = New-OutboundDeploymentConfiguration
            Mock Get-OutboundConnector {
                New-OutboundConnectorRecord -Override @{
                    RecipientDomains = @(' * ', '*')
                    SmartHosts       = @('SMTP2.GATEWAY.EXAMPLE.', ' smtp1.gateway.example ')
                    TlsDomain        = ' *.GATEWAY.EXAMPLE. '
                }
            }

            # Act
            Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke Get-OutboundConnector -Times 1 -Exactly -ParameterFilter { $Identity -eq 'Contoso outbound gateway' }
            Should -Invoke New-OutboundConnector -Times 0 -Exactly
            Should -Invoke Set-OutboundConnector -Times 0 -Exactly
            $script:OutboundOutcomes[0].Status | Should -BeExactly 'Applied'
        }
    }
}
