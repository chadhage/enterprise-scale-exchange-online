#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:DeploymentScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'

    Set-Item function:Get-InboundConnector { param($Identity, $ErrorAction) }
    Set-Item function:New-InboundConnector { param($Name, $Enabled, $ConnectorType, $SenderDomains, $SenderIPAddresses, $RequireTls, $RestrictDomainsToIPAddresses, $RestrictDomainsToCertificate, $WhatIf) }
    Set-Item function:Set-InboundConnector { param($Identity, $Enabled, $ConnectorType, $SenderDomains, $SenderIPAddresses, $RequireTls, $RestrictDomainsToIPAddresses, $RestrictDomainsToCertificate, $EFSkipLastIP, $EFSkipIPs, $EFUsers, $WhatIf) }
    Set-Item function:Get-OutboundConnector { param($Identity, $ErrorAction) }
    Set-Item function:New-OutboundConnector { param($Name, $Enabled, $ConnectorType, $RecipientDomains, $RouteAllMessagesViaOnPremises, $UseMXRecord, $SmartHosts, $TlsSettings, $TlsDomain, $WhatIf) }
    Set-Item function:Set-OutboundConnector { param($Identity, $Enabled, $ConnectorType, $RecipientDomains, $RouteAllMessagesViaOnPremises, $UseMXRecord, $SmartHosts, $TlsSettings, $TlsDomain, $WhatIf) }
    Set-Item function:Get-EOPProtectionPolicyRule { param($Identity, $ErrorAction) }
    Set-Item function:Set-EOPProtectionPolicyRule { param($Identity, $RecipientDomainIs, $ExceptIfSentToMemberOf, $ExceptIfSentTo, $SentToMemberOf, $WhatIf) }
    Set-Item function:Enable-EOPProtectionPolicyRule { param($Identity, $WhatIf) }
    Set-Item function:Get-ATPProtectionPolicyRule { param($Identity, $ErrorAction) }
    Set-Item function:Set-ATPProtectionPolicyRule { param($Identity, $RecipientDomainIs, $ExceptIfSentToMemberOf, $ExceptIfSentTo, $SentToMemberOf, $WhatIf) }
    Set-Item function:Enable-ATPProtectionPolicyRule { param($Identity, $WhatIf) }
    Set-Item function:Get-ATPBuiltInProtectionRule { param($Identity, $ErrorAction) }
    Set-Item function:Set-ATPBuiltInProtectionRule { param($Identity, $ExceptIfRecipientDomainIs, $ExceptIfSentTo, $ExceptIfSentToMemberOf, $WhatIf) }

    $tokens = $null
    $parseErrors = $null
    $deploymentAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:DeploymentScriptPath,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join [Environment]::NewLine) }

    foreach ($functionName in @('Set-InboundGatewayConnector', 'Set-OutboundGatewayConnector', 'Set-PresetProtection')) {
        $definition = @($deploymentAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
                }, $true))
        if ($definition.Count -ne 1) { throw "Expected one $functionName definition in the deployment script." }
        . ([scriptblock]::Create($definition[0].Extent.Text))
    }

    function Add-Outcome {
        param([string]$Control, [string]$Status, [string]$Detail, [string[]]$Operation = @())

        $script:GatewayOutcomes.Add([pscustomobject]@{
                Control   = $Control
                Status    = $Status
                Detail    = $Detail
                Operation = @($Operation)
            })
    }

    function New-GatewayDeploymentConfiguration {
        return [pscustomobject]@{
            administratorInputs = [pscustomobject]@{
                primaryDomain                = 'contoso.com'
                priorityUsersGroup           = 'priority@contoso.com'
                securityOperationsMailbox    = 'secops@contoso.com'
                gatewayInboundConnectorName  = 'Contoso inbound gateway'
                gatewayOutboundConnectorName = 'Contoso outbound gateway'
            }
            desiredState = [pscustomobject]@{
                mailFlow = [pscustomobject]@{
                    gatewayInboundConnector = [pscustomobject]@{
                        enabled                      = $true
                        connectorType                = 'Partner'
                        senderDomains                = @('*')
                        senderIpAddresses            = @('192.0.2.10', '198.51.100.0/24')
                        requireTls                   = $true
                        restrictDomainsToIpAddresses = $true
                        restrictDomainsToCertificate = $false
                    }
                    enhancedFiltering = [pscustomobject]@{
                        skipLastIp     = $false
                        skipIpAddresses = @('192.0.2.10')
                    }
                    gatewayOutboundConnector = [pscustomobject]@{
                        enabled                       = $true
                        connectorType                 = 'Partner'
                        recipientDomains              = @('*')
                        routeAllMessagesViaOnPremises = $true
                        useMxRecord                   = $false
                        smartHosts                    = @('smarthost.contoso.example')
                        tlsSettings                   = 'DomainValidation'
                        tlsDomain                     = '*.contoso.example'
                    }
                }
            }
        }
    }

    function New-PresetEntitlement {
        param([bool]$AtpPresets = $true)

        return [pscustomobject]@{
            AtpPresets = $AtpPresets
            Capability = @([pscustomobject]@{
                    Name   = 'AtpPresets'
                    Reason = 'ATP preset protection is not entitled.'
                })
        }
    }
}

Describe 'TST-002 gateway deployment cmdlet coverage' {
    BeforeEach {
        $script:GatewayOutcomes = [System.Collections.Generic.List[object]]::new()

        Mock Get-InboundConnector { $null }
        Mock New-InboundConnector { }
        Mock Set-InboundConnector { }
        Mock Get-OutboundConnector { $null }
        Mock New-OutboundConnector { }
        Mock Set-OutboundConnector { }
        Mock Get-EOPProtectionPolicyRule { [pscustomobject]@{ Identity = $Identity; State = 'Enabled' } }
        Mock Set-EOPProtectionPolicyRule { }
        Mock Enable-EOPProtectionPolicyRule { }
        Mock Get-ATPProtectionPolicyRule { [pscustomobject]@{ Identity = $Identity; State = 'Enabled' } }
        Mock Set-ATPProtectionPolicyRule { }
        Mock Enable-ATPProtectionPolicyRule { }
        Mock Get-ATPBuiltInProtectionRule {
            [pscustomobject]@{ ExceptIfRecipientDomainIs = @('legacy.example'); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @() }
        }
        Mock Set-ATPBuiltInProtectionRule { }
    }

    Context 'Negative: inbound connector discovery or mutation fails' {
        It 'propagates inbound connector discovery failure without reporting success' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            Mock Get-InboundConnector { throw 'inbound discovery failed' }

            # Act
            $fault = { Set-InboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $fault | Should -Throw '*inbound discovery failed*'
            $script:GatewayOutcomes.Count | Should -Be 0
            Should -Invoke New-InboundConnector -Times 0 -Exactly
            Should -Invoke Set-InboundConnector -Times 0 -Exactly
        }

        It 'propagates inbound connector creation failure before enhanced filtering or success is reported' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            Mock New-InboundConnector { throw 'inbound creation failed' }

            # Act
            $fault = { Set-InboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $fault | Should -Throw '*inbound creation failed*'
            $script:GatewayOutcomes.Count | Should -Be 0
            Should -Invoke Set-InboundConnector -Times 0 -Exactly
        }

        It 'propagates inbound connector update failure before enhanced filtering or success is reported' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            Mock Get-InboundConnector { [pscustomobject]@{ Name = 'Contoso inbound gateway'; Enabled = $false } }
            Mock Set-InboundConnector { throw 'inbound update failed' } -ParameterFilter { $null -eq $EFUsers }

            # Act
            $fault = { Set-InboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $fault | Should -Throw '*inbound update failed*'
            $script:GatewayOutcomes.Count | Should -Be 0
            Should -Invoke Set-InboundConnector -Times 1 -Exactly
        }

        It 'propagates enhanced-filtering failure without reporting success' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            Mock Set-InboundConnector { throw 'enhanced filtering failed' } -ParameterFilter { $null -ne $EFSkipIPs }

            # Act
            $fault = { Set-InboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $fault | Should -Throw '*enhanced filtering failed*'
            $script:GatewayOutcomes.Count | Should -Be 0
        }
    }

    Context 'Negative: outbound connector discovery or mutation fails' {
        It 'propagates outbound connector discovery failure without reporting success' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            Mock Get-OutboundConnector { throw 'outbound discovery failed' }

            # Act
            $fault = { Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $fault | Should -Throw '*outbound discovery failed*'
            $script:GatewayOutcomes.Count | Should -Be 0
            Should -Invoke New-OutboundConnector -Times 0 -Exactly
            Should -Invoke Set-OutboundConnector -Times 0 -Exactly
        }

        It 'propagates outbound connector creation failure without reporting success' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            Mock New-OutboundConnector { throw 'outbound creation failed' }

            # Act
            $fault = { Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $fault | Should -Throw '*outbound creation failed*'
            $script:GatewayOutcomes.Count | Should -Be 0
        }

        It 'propagates outbound connector update failure without reporting success' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            Mock Get-OutboundConnector { [pscustomobject]@{ Name = 'Contoso outbound gateway'; Enabled = $false } }
            Mock Set-OutboundConnector { throw 'outbound update failed' }

            # Act
            $fault = { Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $fault | Should -Throw '*outbound update failed*'
            $script:GatewayOutcomes.Count | Should -Be 0
        }
    }

    Context 'Negative: preset prerequisites or mutations fail' {
        It 'refuses a missing Standard EOP preset before any mutation' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            $entitlement = New-PresetEntitlement
            Mock Get-EOPProtectionPolicyRule { $null } -ParameterFilter { $Identity -eq 'Standard Preset Security Policy' }

            # Act
            $fault = { Set-PresetProtection -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -Confirm:$false }

            # Assert
            $fault | Should -Throw '*Initialize the Standard and Strict preset policies*'
            $script:GatewayOutcomes.Count | Should -Be 0
            Should -Invoke Set-EOPProtectionPolicyRule -Times 0 -Exactly
        }

        It 'refuses a missing Strict EOP preset before any mutation' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            $entitlement = New-PresetEntitlement
            Mock Get-EOPProtectionPolicyRule { $null } -ParameterFilter { $Identity -eq 'Strict Preset Security Policy' }

            # Act
            $fault = { Set-PresetProtection -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -Confirm:$false }

            # Assert
            $fault | Should -Throw '*Initialize the Standard and Strict preset policies*'
            $script:GatewayOutcomes.Count | Should -Be 0
            Should -Invoke Set-EOPProtectionPolicyRule -Times 0 -Exactly
        }

        It 'refuses a missing Standard ATP preset before any mutation' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            $entitlement = New-PresetEntitlement
            Mock Get-ATPProtectionPolicyRule { $null } -ParameterFilter { $Identity -eq 'Standard Preset Security Policy' }

            # Act
            $fault = { Set-PresetProtection -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -Confirm:$false }

            # Assert
            $fault | Should -Throw '*Initialize the Standard and Strict preset policies*'
            $script:GatewayOutcomes.Count | Should -Be 0
            Should -Invoke Set-EOPProtectionPolicyRule -Times 0 -Exactly
        }

        It 'refuses a missing Strict ATP preset before any mutation' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            $entitlement = New-PresetEntitlement
            Mock Get-ATPProtectionPolicyRule { $null } -ParameterFilter { $Identity -eq 'Strict Preset Security Policy' }

            # Act
            $fault = { Set-PresetProtection -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -Confirm:$false }

            # Assert
            $fault | Should -Throw '*Initialize the Standard and Strict preset policies*'
            $script:GatewayOutcomes.Count | Should -Be 0
            Should -Invoke Set-EOPProtectionPolicyRule -Times 0 -Exactly
        }

        It 'propagates an EOP preset scope failure before reporting success' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            $entitlement = New-PresetEntitlement
            Mock Set-EOPProtectionPolicyRule { throw 'EOP preset scope failed' }

            # Act
            $fault = { Set-PresetProtection -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -Confirm:$false }

            # Assert
            $fault | Should -Throw '*EOP preset scope failed*'
            $script:GatewayOutcomes.Count | Should -Be 0
        }

        It 'propagates an EOP preset enable failure before reporting success' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            $entitlement = New-PresetEntitlement
            Mock Enable-EOPProtectionPolicyRule { throw 'EOP preset enable failed' }

            # Act
            $fault = { Set-PresetProtection -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -Confirm:$false }

            # Assert
            $fault | Should -Throw '*EOP preset enable failed*'
            $script:GatewayOutcomes.Count | Should -Be 0
        }

        It 'propagates an ATP preset scope failure before reporting ATP success' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            $entitlement = New-PresetEntitlement
            Mock Set-ATPProtectionPolicyRule { throw 'ATP preset scope failed' }

            # Act
            $fault = { Set-PresetProtection -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -Confirm:$false }

            # Assert
            $fault | Should -Throw '*ATP preset scope failed*'
            @($script:GatewayOutcomes).Control | Should -Not -Contain 'MDO-001/MDO-002/MDO-003'
        }

        It 'propagates an ATP preset enable failure before reporting ATP success' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            $entitlement = New-PresetEntitlement
            Mock Enable-ATPProtectionPolicyRule { throw 'ATP preset enable failed' }

            # Act
            $fault = { Set-PresetProtection -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -Confirm:$false }

            # Assert
            $fault | Should -Throw '*ATP preset enable failed*'
            @($script:GatewayOutcomes).Control | Should -Not -Contain 'MDO-001/MDO-002/MDO-003'
        }

        It 'propagates a Built-in protection failure before reporting ATP success' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            $entitlement = New-PresetEntitlement
            Mock Set-ATPBuiltInProtectionRule { throw 'Built-in protection failed' }

            # Act
            $fault = { Set-PresetProtection -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -Confirm:$false }

            # Assert
            $fault | Should -Throw '*Built-in protection failed*'
            @($script:GatewayOutcomes).Control | Should -Not -Contain 'MDO-001/MDO-002/MDO-003'
        }

        It 'propagates a Built-in protection discovery failure before reporting ATP success' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            $entitlement = New-PresetEntitlement
            Mock Get-ATPBuiltInProtectionRule { throw 'Built-in protection discovery failed' }

            # Act
            $fault = { Set-PresetProtection -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -Confirm:$false }

            # Assert
            $fault | Should -Throw '*Built-in protection discovery failed*'
            @($script:GatewayOutcomes).Control | Should -Not -Contain 'MDO-001/MDO-002/MDO-003'
        }
    }

    Context 'Positive: inbound connector create unit' {
        It 'creates the connector and configures Enhanced Filtering with every resolved argument' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration

            # Act
            Set-InboundGatewayConnector -Configuration $configuration -UseWhatIf $true -Confirm:$false

            # Assert
            Should -Invoke Get-InboundConnector -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Contoso inbound gateway'
            }
            Should -Invoke New-InboundConnector -Times 1 -Exactly -ParameterFilter {
                $Name -eq 'Contoso inbound gateway' -and
                $Enabled -eq $true -and
                $ConnectorType -eq 'Partner' -and
                (@($SenderDomains) -join '|') -eq '*' -and
                (@($SenderIPAddresses) -join '|') -eq '192.0.2.10|198.51.100.0/24' -and
                $RequireTls -eq $true -and
                $RestrictDomainsToIPAddresses -eq $true -and
                $RestrictDomainsToCertificate -eq $false -and
                $WhatIf -eq $true
            }
            Should -Invoke Set-InboundConnector -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Contoso inbound gateway' -and
                $EFSkipLastIP -eq $false -and
                (@($EFSkipIPs) -join '|') -eq '192.0.2.10' -and
                $null -eq $EFUsers -and
                $WhatIf -eq $true
            }
            $script:GatewayOutcomes[0].Status | Should -Be 'Planned'
        }
    }

    Context 'Positive: inbound connector update unit' {
        It 'updates the connector and Enhanced Filtering with every resolved argument' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            Mock Get-InboundConnector { [pscustomobject]@{ Name = 'Contoso inbound gateway'; Enabled = $false } }

            # Act
            Set-InboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke Get-InboundConnector -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Contoso inbound gateway'
            }
            Should -Invoke Set-InboundConnector -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Contoso inbound gateway' -and
                $Enabled -eq $true -and
                $ConnectorType -eq 'Partner' -and
                (@($SenderDomains) -join '|') -eq '*' -and
                (@($SenderIPAddresses) -join '|') -eq '192.0.2.10|198.51.100.0/24' -and
                $RequireTls -eq $true -and
                $RestrictDomainsToIPAddresses -eq $true -and
                $RestrictDomainsToCertificate -eq $false -and
                $WhatIf -eq $false
            }
            Should -Invoke Set-InboundConnector -Times 1 -Exactly -ParameterFilter { $null -ne $EFSkipIPs }
            Should -Invoke New-InboundConnector -Times 0 -Exactly
        }
    }

    Context 'Positive: inbound connector no-op unit' {
        It 'does not mutate an inbound connector that already matches connector and Enhanced Filtering state' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            Mock Get-InboundConnector {
                [pscustomobject]@{
                    Enabled = $true; ConnectorType = 'Partner'; SenderDomains = @('*')
                    SenderIPAddresses = @('192.0.2.10', '198.51.100.0/24'); RequireTls = $true
                    RestrictDomainsToIPAddresses = $true; RestrictDomainsToCertificate = $false
                    EFSkipLastIP = $false; EFSkipIPs = @('192.0.2.10'); EFUsers = @()
                }
            }

            # Act
            Set-InboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke Get-InboundConnector -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Contoso inbound gateway'
            }
            Should -Invoke New-InboundConnector -Times 0 -Exactly
            Should -Invoke Set-InboundConnector -Times 0 -Exactly
        }
    }

    Context 'Positive: outbound connector create unit' {
        It 'creates the outbound connector with every resolved argument' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration

            # Act
            Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $true -Confirm:$false

            # Assert
            Should -Invoke Get-OutboundConnector -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Contoso outbound gateway'
            }
            Should -Invoke New-OutboundConnector -Times 1 -Exactly -ParameterFilter {
                $Name -eq 'Contoso outbound gateway' -and
                $Enabled -eq $true -and
                $ConnectorType -eq 'Partner' -and
                (@($RecipientDomains) -join '|') -eq '*' -and
                $RouteAllMessagesViaOnPremises -eq $true -and
                $UseMXRecord -eq $false -and
                (@($SmartHosts) -join '|') -eq 'smarthost.contoso.example' -and
                $TlsSettings -eq 'DomainValidation' -and
                $TlsDomain -eq '*.contoso.example' -and
                $WhatIf -eq $true
            }
            $script:GatewayOutcomes[0].Status | Should -Be 'Planned'
        }
    }

    Context 'Positive: outbound connector update unit' {
        It 'updates the outbound connector with every resolved argument' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            Mock Get-OutboundConnector { [pscustomobject]@{ Name = 'Contoso outbound gateway'; Enabled = $false } }

            # Act
            Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke Get-OutboundConnector -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Contoso outbound gateway'
            }
            Should -Invoke Set-OutboundConnector -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Contoso outbound gateway' -and
                $Enabled -eq $true -and
                $ConnectorType -eq 'Partner' -and
                (@($RecipientDomains) -join '|') -eq '*' -and
                $RouteAllMessagesViaOnPremises -eq $true -and
                $UseMXRecord -eq $false -and
                (@($SmartHosts) -join '|') -eq 'smarthost.contoso.example' -and
                $TlsSettings -eq 'DomainValidation' -and
                $TlsDomain -eq '*.contoso.example' -and
                $WhatIf -eq $false
            }
            Should -Invoke New-OutboundConnector -Times 0 -Exactly
        }
    }

    Context 'Positive: outbound connector no-op unit' {
        It 'does not mutate an outbound connector that already matches desired state' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            Mock Get-OutboundConnector {
                [pscustomobject]@{
                    Enabled = $true; ConnectorType = 'Partner'; RecipientDomains = @('*')
                    RouteAllMessagesViaOnPremises = $true; UseMXRecord = $false
                    SmartHosts = @('smarthost.contoso.example'); TlsSettings = 'DomainValidation'
                    TlsDomain = '*.contoso.example'
                }
            }

            # Act
            Set-OutboundGatewayConnector -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke Get-OutboundConnector -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Contoso outbound gateway'
            }
            Should -Invoke New-OutboundConnector -Times 0 -Exactly
            Should -Invoke Set-OutboundConnector -Times 0 -Exactly
        }
    }

    Context 'Positive: unentitled preset unit' {
        It 'configures only EOP presets and reports the ATP entitlement reason' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            $entitlement = New-PresetEntitlement -AtpPresets $false

            # Act
            Set-PresetProtection -Configuration $configuration -UseWhatIf $true -Entitlement $entitlement -Confirm:$false

            # Assert
            Should -Invoke Set-EOPProtectionPolicyRule -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Standard Preset Security Policy' -and $RecipientDomainIs -eq 'contoso.com' -and
                $ExceptIfSentToMemberOf -eq 'priority@contoso.com' -and $ExceptIfSentTo -eq 'secops@contoso.com' -and $WhatIf -eq $true
            }
            Should -Invoke Set-EOPProtectionPolicyRule -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Strict Preset Security Policy' -and $SentToMemberOf -eq 'priority@contoso.com' -and $WhatIf -eq $true
            }
            Should -Invoke Enable-EOPProtectionPolicyRule -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Standard Preset Security Policy' -and $WhatIf -eq $true
            }
            Should -Invoke Enable-EOPProtectionPolicyRule -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Strict Preset Security Policy' -and $WhatIf -eq $true
            }
            Should -Invoke Set-ATPProtectionPolicyRule -Times 0 -Exactly
            Should -Invoke Set-ATPBuiltInProtectionRule -Times 0 -Exactly
            @($script:GatewayOutcomes | Where-Object Status -eq 'NotEntitled')[0].Detail | Should -Be 'ATP preset protection is not entitled.'
        }
    }

    Context 'Positive: entitled preset unit' {
        It 'configures every EOP, ATP, and Built-in protection argument' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            $entitlement = New-PresetEntitlement

            # Act
            Set-PresetProtection -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -Confirm:$false

            # Assert
            Should -Invoke Set-EOPProtectionPolicyRule -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Standard Preset Security Policy' -and $RecipientDomainIs -eq 'contoso.com' -and
                $ExceptIfSentToMemberOf -eq 'priority@contoso.com' -and $ExceptIfSentTo -eq 'secops@contoso.com' -and $WhatIf -eq $false
            }
            Should -Invoke Set-EOPProtectionPolicyRule -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Strict Preset Security Policy' -and $SentToMemberOf -eq 'priority@contoso.com' -and $WhatIf -eq $false
            }
            Should -Invoke Enable-EOPProtectionPolicyRule -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Standard Preset Security Policy' -and $WhatIf -eq $false
            }
            Should -Invoke Enable-EOPProtectionPolicyRule -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Strict Preset Security Policy' -and $WhatIf -eq $false
            }
            Should -Invoke Set-ATPProtectionPolicyRule -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Standard Preset Security Policy' -and $RecipientDomainIs -eq 'contoso.com' -and
                $ExceptIfSentToMemberOf -eq 'priority@contoso.com' -and $ExceptIfSentTo -eq 'secops@contoso.com' -and $WhatIf -eq $false
            }
            Should -Invoke Set-ATPProtectionPolicyRule -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Strict Preset Security Policy' -and $SentToMemberOf -eq 'priority@contoso.com' -and $WhatIf -eq $false
            }
            Should -Invoke Enable-ATPProtectionPolicyRule -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Standard Preset Security Policy' -and $WhatIf -eq $false
            }
            Should -Invoke Enable-ATPProtectionPolicyRule -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'Strict Preset Security Policy' -and $WhatIf -eq $false
            }
            Should -Invoke Get-ATPBuiltInProtectionRule -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'ATP Built-In Protection Rule'
            }
            Should -Invoke Set-ATPBuiltInProtectionRule -Times 1 -Exactly -ParameterFilter {
                $Identity -eq 'ATP Built-In Protection Rule' -and $null -eq $ExceptIfRecipientDomainIs -and
                $null -eq $ExceptIfSentTo -and $null -eq $ExceptIfSentToMemberOf -and $WhatIf -eq $false
            }
        }
    }

    Context 'Positive: preset no-op unit' {
        It 'does not mutate preset rules or Built-in protection when every value already matches' {
            # Arrange
            $configuration = New-GatewayDeploymentConfiguration
            $entitlement = New-PresetEntitlement
            $standard = [pscustomobject]@{
                Identity = 'Standard Preset Security Policy'; State = 'Enabled'; RecipientDomainIs = @('contoso.com')
                ExceptIfSentToMemberOf = @('priority@contoso.com'); ExceptIfSentTo = @('secops@contoso.com')
            }
            $strict = [pscustomobject]@{
                Identity = 'Strict Preset Security Policy'; State = 'Enabled'; SentToMemberOf = @('priority@contoso.com')
            }
            Mock Get-EOPProtectionPolicyRule { if ($Identity -like 'Standard*') { $standard } else { $strict } }
            Mock Get-ATPProtectionPolicyRule { if ($Identity -like 'Standard*') { $standard } else { $strict } }
            Mock Get-ATPBuiltInProtectionRule {
                [pscustomobject]@{ ExceptIfRecipientDomainIs = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @() }
            }

            # Act
            Set-PresetProtection -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -Confirm:$false

            # Assert
            Should -Invoke Set-EOPProtectionPolicyRule -Times 0 -Exactly
            Should -Invoke Enable-EOPProtectionPolicyRule -Times 0 -Exactly
            Should -Invoke Set-ATPProtectionPolicyRule -Times 0 -Exactly
            Should -Invoke Enable-ATPProtectionPolicyRule -Times 0 -Exactly
            Should -Invoke Set-ATPBuiltInProtectionRule -Times 0 -Exactly
        }
    }
}