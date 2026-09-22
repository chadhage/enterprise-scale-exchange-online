#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:DeploymentScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'
    Import-Module (Join-Path $script:SampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force

    function Get-DeploymentFunctionText {
        param([Parameter(Mandatory)][string[]]$Name)

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:DeploymentScriptPath,
            [ref]$tokens,
            [ref]$errors
        )
        if ($errors.Count -gt 0) { throw ($errors.Message -join '; ') }

        foreach ($functionName in $Name) {
            $definition = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq $functionName
            }, $true))
            if ($definition.Count -ne 1) { throw "Expected one '$functionName' definition, found $($definition.Count)." }
            $definition[0].Extent.Text
        }
    }

    $stubText = @'
function Set-TransportConfig { param($SmtpClientAuthenticationDisabled, $ExternalPostmasterAddress, $WhatIf) }
function Set-HostedOutboundSpamFilterPolicy { param($Identity, $AutoForwardingMode, $WhatIf) }
function Set-OrganizationConfig { param($AuditDisabled, $EwsEnabled, $EwsAllowList, $WhatIf) }
function Set-ExternalInOutlook { param($Enabled, $AllowList, $WhatIf) }
function Set-RemoteDomain { param($Identity, $AutoForwardEnabled, $AutoReplyEnabled, $AllowedOOFType, $DeliveryReportEnabled, $NDREnabled, $WhatIf) }
function Get-RemoteDomain { [pscustomobject]@{ Identity = 'Default'; DomainName = '*'; AllowedOOFType = 'None' } }
function Get-CASMailboxPlan { param($ResultSize) }
function Set-CASMailboxPlan { param($Identity, $PopEnabled, $ImapEnabled, $WhatIf) }
function Set-QuarantinePolicy { param($Identity, $EndUserSpamNotificationFrequency, $WhatIf) }
function Set-AtpPolicyForO365 { param($EnableATPForSPOTeamsODB, $EnableSafeDocs, $AllowSafeDocsOpen, $WhatIf) }
function Get-DkimSigningConfig { param($Identity, $ErrorAction) }
function New-DkimSigningConfig { param($DomainName, $Enabled, $KeySize, $WhatIf) }
function Set-DkimSigningConfig { param($Identity, $Enabled, $WhatIf) }
'@
    $functionText = Get-DeploymentFunctionText -Name @('Add-Outcome', 'Set-OrganizationControls', 'Set-DomainAuthentication')
    $harnessText = @"
`$script:Outcomes = [System.Collections.Generic.List[object]]::new()
`$script:MutationStatus = [ordered]@{}
$stubText
$($functionText -join [Environment]::NewLine)
function Reset-DeploymentOrganizationHarness {
    `$script:Outcomes.Clear()
    `$script:MutationStatus = [ordered]@{}
}
function Get-DeploymentOrganizationOutcome { return @(`$script:Outcomes) }
Export-ModuleMember -Function *
"@
    $script:Harness = New-Module -Name 'DeploymentOrganizationHarness' -ScriptBlock ([scriptblock]::Create($harnessText))
    Import-Module $script:Harness -Force -DisableNameChecking

    function New-OrganizationConfiguration {
        [pscustomobject]@{
            administratorInputs = [pscustomobject]@{ primaryDomain = 'contoso.example' }
            desiredState = [pscustomobject]@{
                exchangeOnline = [pscustomobject]@{
                    smtpClientAuthenticationDisabled = $true
                    externalPostmasterAddress = 'postmaster@contoso.example'
                    automaticExternalForwarding = 'Off'
                    mailboxAuditingDefault = $true
                    externalSenderIdentification = [pscustomobject]@{
                        enabled = $true
                        allowList = @('partner@fabrikam.example')
                    }
                    remoteDomainDefault = [pscustomobject]@{
                        autoForwardEnabled = $false
                        autoReplyEnabled = $false
                        allowedOOFType = 'None'
                        deliveryReportEnabled = $false
                        nonDeliveryReportEnabled = $false
                    }
                    protocolRestriction = [pscustomobject]@{
                        ewsEnabled = $false
                        ewsAllowList = @('ews-app')
                        popEnabledByDefault = $false
                        imapEnabledByDefault = $false
                    }
                }
                defenderForOffice365 = [pscustomobject]@{
                    quarantinePolicies = [pscustomobject]@{
                        endUserSpamNotificationFrequencyInDays = 3
                    }
                    safeAttachmentsForSharePointOneDriveTeams = $true
                    safeDocuments = [pscustomobject]@{
                        enabled = $true
                        allowBypass = $false
                    }
                }
            }
        }
    }

    function New-OrganizationEntitlement {
        param([bool]$SafeAttachmentsSpo)

        [pscustomobject]@{
            SafeAttachmentsSpo = $SafeAttachmentsSpo
            Capability = @(
                [pscustomobject]@{
                    Name = 'SafeAttachmentsSpo'
                    Reason = 'SAFEDOCS or ATP capability is unavailable.'
                }
            )
        }
    }

    function Get-GatewayDispatchResult {
        param([Parameter(Mandatory)][string]$Path)

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) { throw ($errors.Message -join '; ') }

        $assignment = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -ceq '$gatewayDeclared'
        }, $true))
        $dispatch = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.IfStatementAst] -and
                @($node.Clauses | ForEach-Object { $_.Item1.Extent.Text }) -contains '$gatewayDeclared' -and
                $node.Extent.Text -match 'Set-InboundGatewayConnector'
        }, $true))

        $gatewayCommands = @()
        $nativeCommands = @()
        if ($dispatch.Count -eq 1) {
            $gatewayCommands = @($dispatch[0].Clauses[0].Item2.FindAll({
                param($node) $node -is [System.Management.Automation.Language.CommandAst]
            }, $true) | ForEach-Object { $_.GetCommandName() })
            if ($null -ne $dispatch[0].ElseClause) {
                $nativeCommands = @($dispatch[0].ElseClause.FindAll({
                    param($node) $node -is [System.Management.Automation.Language.CommandAst]
                }, $true) | ForEach-Object { $_.GetCommandName() })
            }
        }

        [pscustomobject]@{
            AssignmentCount = $assignment.Count
            AssignmentText = if ($assignment.Count -eq 1) { $assignment[0].Right.Extent.Text } else { '' }
            DispatchCount = $dispatch.Count
            GatewayCommands = $gatewayCommands
            NativeCommands = $nativeCommands
            NativeText = if ($dispatch.Count -eq 1 -and $null -ne $dispatch[0].ElseClause) { $dispatch[0].ElseClause.Extent.Text } else { '' }
        }
    }
}

AfterAll {
    Remove-Module DeploymentOrganizationHarness -Force -ErrorAction SilentlyContinue
}

Describe 'TST-002 organization-control deployment' {
    BeforeEach {
        Reset-DeploymentOrganizationHarness
        Mock Write-Host {} -ModuleName DeploymentOrganizationHarness
        Mock Set-TransportConfig {} -ModuleName DeploymentOrganizationHarness
        Mock Set-HostedOutboundSpamFilterPolicy {} -ModuleName DeploymentOrganizationHarness
        Mock Set-OrganizationConfig {} -ModuleName DeploymentOrganizationHarness
        Mock Set-ExternalInOutlook {} -ModuleName DeploymentOrganizationHarness
        Mock Set-RemoteDomain {} -ModuleName DeploymentOrganizationHarness
        Mock Get-CASMailboxPlan {
            @([pscustomobject]@{ Identity = 'Plan-A' }, [pscustomobject]@{ Identity = 'Plan-B' })
        } -ModuleName DeploymentOrganizationHarness
        Mock Set-CASMailboxPlan {} -ModuleName DeploymentOrganizationHarness
        Mock Set-QuarantinePolicy {} -ModuleName DeploymentOrganizationHarness
        Mock Set-AtpPolicyForO365 {} -ModuleName DeploymentOrganizationHarness
    }

    Context 'Negative: no-op and dependency branches' {
        It 'performs no tenant mutation when ShouldProcess declines the organization change' {
            # Arrange
            $configuration = New-OrganizationConfiguration
            $entitlement = New-OrganizationEntitlement -SafeAttachmentsSpo $true
            $preflight = [pscustomobject]@{ MayApply = $true; Status = 'Pass'; Reason = 'Every target is entitled.' }

            # Act
            Set-OrganizationControls -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -SafeDocumentsPreflight $preflight -WhatIf

            # Assert
            Should -Invoke Set-TransportConfig -ModuleName DeploymentOrganizationHarness -Times 0
            Should -Invoke Set-HostedOutboundSpamFilterPolicy -ModuleName DeploymentOrganizationHarness -Times 0
            Should -Invoke Set-OrganizationConfig -ModuleName DeploymentOrganizationHarness -Times 0
            Should -Invoke Set-ExternalInOutlook -ModuleName DeploymentOrganizationHarness -Times 0
            Should -Invoke Set-RemoteDomain -ModuleName DeploymentOrganizationHarness -Times 0
            Should -Invoke Set-CASMailboxPlan -ModuleName DeploymentOrganizationHarness -Times 0
            Should -Invoke Set-QuarantinePolicy -ModuleName DeploymentOrganizationHarness -Times 0
            Should -Invoke Set-AtpPolicyForO365 -ModuleName DeploymentOrganizationHarness -Times 0
        }

        It 'does not configure ATP policy when the tenant is not entitled' {
            # Arrange
            $configuration = New-OrganizationConfiguration
            $entitlement = New-OrganizationEntitlement -SafeAttachmentsSpo $false

            # Act
            Set-OrganizationControls -Configuration $configuration -UseWhatIf $true -Entitlement $entitlement -SafeDocumentsPreflight $null

            # Assert
            Should -Invoke Set-AtpPolicyForO365 -ModuleName DeploymentOrganizationHarness -Times 0
            $outcome = @(Get-DeploymentOrganizationOutcome | Where-Object Control -eq 'MDO-004/MDO-005')
            $outcome.Count | Should -Be 1
            $outcome[0].Status | Should -Be 'NotEntitled'
            $outcome[0].Detail | Should -Be 'SAFEDOCS or ATP capability is unavailable.'
        }

        It 'omits Safe Documents arguments when no preflight verdict was collected' {
            # Arrange
            $configuration = New-OrganizationConfiguration
            $entitlement = New-OrganizationEntitlement -SafeAttachmentsSpo $true

            # Act
            Set-OrganizationControls -Configuration $configuration -UseWhatIf $true -Entitlement $entitlement -SafeDocumentsPreflight $null

            # Assert
            Should -Invoke Set-AtpPolicyForO365 -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $EnableATPForSPOTeamsODB -eq $true -and
                $null -eq $EnableSafeDocs -and
                $null -eq $AllowSafeDocsOpen -and
                $WhatIf -eq $true
            }
            $outcome = @(Get-DeploymentOrganizationOutcome | Where-Object Control -eq 'MDO-005')
            $outcome[0].Status | Should -Be 'NotEntitled'
            $outcome[0].Detail | Should -Match 'no tenant evidence was collected'
        }

        It 'omits Safe Documents arguments and records the reason when preflight fails' {
            # Arrange
            $configuration = New-OrganizationConfiguration
            $entitlement = New-OrganizationEntitlement -SafeAttachmentsSpo $true
            $preflight = [pscustomobject]@{ MayApply = $false; Status = 'Fail'; Reason = 'alex@contoso.example lacks SAFEDOCS.' }

            # Act
            Set-OrganizationControls -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -SafeDocumentsPreflight $preflight

            # Assert
            Should -Invoke Set-AtpPolicyForO365 -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $EnableATPForSPOTeamsODB -eq $true -and $null -eq $EnableSafeDocs -and $null -eq $AllowSafeDocsOpen
            }
            $outcome = @(Get-DeploymentOrganizationOutcome | Where-Object Control -eq 'MDO-005')
            $outcome[0].Status | Should -Be 'Failed'
            $outcome[0].Detail | Should -Be 'alex@contoso.example lacks SAFEDOCS.'
        }
    }

    Context 'Negative: mutation failures remain failures' {
        It 'propagates an organization mutation failure and does not report that mutation applied' {
            # Arrange
            $configuration = New-OrganizationConfiguration
            $entitlement = New-OrganizationEntitlement -SafeAttachmentsSpo $true
            $preflight = [pscustomobject]@{ MayApply = $true; Status = 'Pass'; Reason = 'Every target is entitled.' }
            Mock Set-RemoteDomain { throw 'remote-domain refused' } -ModuleName DeploymentOrganizationHarness

            # Act
            $failure = { Set-OrganizationControls -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -SafeDocumentsPreflight $preflight }

            # Assert
            $failure | Should -Throw '*remote-domain refused*'
            @(Get-DeploymentOrganizationOutcome | Where-Object Control -eq 'EXO-008').Count | Should -Be 0
            Should -Invoke Set-CASMailboxPlan -ModuleName DeploymentOrganizationHarness -Times 0
        }
    }

    Context 'Positive: the complete resolved organization state is applied' {
        It 'passes every resolved value to its owning Exchange Online cmdlet' {
            # Arrange
            $configuration = New-OrganizationConfiguration
            $entitlement = New-OrganizationEntitlement -SafeAttachmentsSpo $true
            $preflight = [pscustomobject]@{ MayApply = $true; Status = 'Pass'; Reason = 'Every target is entitled.' }

            # Act
            Set-OrganizationControls -Configuration $configuration -UseWhatIf $false -Entitlement $entitlement -SafeDocumentsPreflight $preflight

            # Assert
            Should -Invoke Set-TransportConfig -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $SmtpClientAuthenticationDisabled -eq $true -and
                $ExternalPostmasterAddress -eq 'postmaster@contoso.example' -and $WhatIf -eq $false
            }
            Should -Invoke Set-HostedOutboundSpamFilterPolicy -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $Identity -eq 'Default' -and $AutoForwardingMode -eq 'Off' -and $WhatIf -eq $false
            }
            Should -Invoke Set-OrganizationConfig -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $AuditDisabled -eq $false -and $null -eq $EwsEnabled -and $null -eq $EwsAllowList -and $WhatIf -eq $false
            }
            Should -Invoke Set-OrganizationConfig -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $null -eq $AuditDisabled -and $EwsEnabled -eq $false -and
                @($EwsAllowList).Count -eq 1 -and $EwsAllowList[0] -eq 'ews-app' -and $WhatIf -eq $false
            }
            Should -Invoke Set-ExternalInOutlook -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $Enabled -eq $true -and @($AllowList).Count -eq 1 -and
                $AllowList[0] -eq 'partner@fabrikam.example' -and $WhatIf -eq $false
            }
            Should -Invoke Set-RemoteDomain -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $Identity -eq 'Default' -and $AutoForwardEnabled -eq $false -and
                $AutoReplyEnabled -eq $false -and $AllowedOOFType -eq 'None' -and
                $DeliveryReportEnabled -eq $false -and $NDREnabled -eq $false -and $WhatIf -eq $false
            }
            Should -Invoke Get-CASMailboxPlan -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $ResultSize -eq 'Unlimited'
            }
            Should -Invoke Set-CASMailboxPlan -ModuleName DeploymentOrganizationHarness -Times 2 -ParameterFilter {
                $Identity -in @('Plan-A', 'Plan-B') -and $PopEnabled -eq $false -and
                $ImapEnabled -eq $false -and $WhatIf -eq $false
            }
            Should -Invoke Set-QuarantinePolicy -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $Identity -eq 'DefaultGlobalTag' -and
                $EndUserSpamNotificationFrequency -eq [timespan]::FromDays(3) -and $WhatIf -eq $false
            }
            Should -Invoke Set-AtpPolicyForO365 -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $EnableATPForSPOTeamsODB -eq $true -and $EnableSafeDocs -eq $true -and
                $AllowSafeDocsOpen -eq $false -and $WhatIf -eq $false
            }
            @(Get-DeploymentOrganizationOutcome | Where-Object Status -eq 'Applied').Count | Should -Be 8
        }
    }
}

Describe 'TST-002 domain-authentication deployment' {
    BeforeEach {
        Reset-DeploymentOrganizationHarness
        Mock Write-Host {} -ModuleName DeploymentOrganizationHarness
        Mock Get-DkimSigningConfig { [pscustomobject]@{ Identity = 'contoso.example'; Enabled = $false } } -ModuleName DeploymentOrganizationHarness
        Mock New-DkimSigningConfig {} -ModuleName DeploymentOrganizationHarness
        Mock Set-DkimSigningConfig {} -ModuleName DeploymentOrganizationHarness
    }

    Context 'Negative: create, update, no-op, manual, and failure branches' {
        It 'stages a missing DKIM configuration disabled and leaves activation manual' {
            # Arrange
            $configuration = New-OrganizationConfiguration
            Mock Get-DkimSigningConfig { $null } -ModuleName DeploymentOrganizationHarness

            # Act
            Set-DomainAuthentication -Configuration $configuration -UseWhatIf $true -ActivateDkim $false

            # Assert
            Should -Invoke Get-DkimSigningConfig -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $Identity -eq 'contoso.example'
            }
            (Get-DeploymentFunctionText -Name 'Set-DomainAuthentication') | Should -Match '-ErrorAction\s+SilentlyContinue'
            Should -Invoke New-DkimSigningConfig -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $DomainName -eq 'contoso.example' -and $Enabled -eq $false -and $KeySize -eq 2048 -and $WhatIf -eq $true
            }
            Should -Invoke Set-DkimSigningConfig -ModuleName DeploymentOrganizationHarness -Times 0
            $outcome = @(Get-DeploymentOrganizationOutcome | Where-Object Control -eq 'AUTH-001')
            $outcome[0].Status | Should -Be 'Manual'
            $outcome[0].Detail | Should -Match 'Publish the exact CNAMEs'
        }

        It 'does not recreate an existing DKIM configuration when activation remains manual' {
            # Arrange
            $configuration = New-OrganizationConfiguration

            # Act
            Set-DomainAuthentication -Configuration $configuration -UseWhatIf $false -ActivateDkim $false

            # Assert
            Should -Invoke New-DkimSigningConfig -ModuleName DeploymentOrganizationHarness -Times 0
            Should -Invoke Set-DkimSigningConfig -ModuleName DeploymentOrganizationHarness -Times 0
            @(Get-DeploymentOrganizationOutcome | Where-Object Status -eq 'Manual').Count | Should -Be 1
        }

        It 'updates an existing DKIM configuration without recreating it when activation is requested' {
            # Arrange
            $configuration = New-OrganizationConfiguration

            # Act
            Set-DomainAuthentication -Configuration $configuration -UseWhatIf $false -ActivateDkim $true

            # Assert
            Should -Invoke New-DkimSigningConfig -ModuleName DeploymentOrganizationHarness -Times 0
            Should -Invoke Set-DkimSigningConfig -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $Identity -eq 'contoso.example' -and $Enabled -eq $true -and $WhatIf -eq $false
            }
            $outcome = @(Get-DeploymentOrganizationOutcome | Where-Object Control -eq 'AUTH-001')
            $outcome[0].Status | Should -Be 'Applied'
        }

        It 'performs no DKIM mutation when ShouldProcess declines it' {
            # Arrange
            $configuration = New-OrganizationConfiguration
            Mock Get-DkimSigningConfig { $null } -ModuleName DeploymentOrganizationHarness

            # Act
            Set-DomainAuthentication -Configuration $configuration -UseWhatIf $false -ActivateDkim $true -WhatIf

            # Assert
            Should -Invoke New-DkimSigningConfig -ModuleName DeploymentOrganizationHarness -Times 0
            Should -Invoke Set-DkimSigningConfig -ModuleName DeploymentOrganizationHarness -Times 0
        }

        It 'propagates a DKIM discovery failure without reporting an outcome' {
            # Arrange
            $configuration = New-OrganizationConfiguration
            Mock Get-DkimSigningConfig { throw 'dkim discovery refused' } -ModuleName DeploymentOrganizationHarness

            # Act
            $failure = { Set-DomainAuthentication -Configuration $configuration -UseWhatIf $false -ActivateDkim $true }

            # Assert
            $failure | Should -Throw '*dkim discovery refused*'
            @(Get-DeploymentOrganizationOutcome).Count | Should -Be 0
        }

        It 'propagates a DKIM creation failure without attempting activation or reporting success' {
            # Arrange
            $configuration = New-OrganizationConfiguration
            Mock Get-DkimSigningConfig { $null } -ModuleName DeploymentOrganizationHarness
            Mock New-DkimSigningConfig { throw 'dkim creation refused' } -ModuleName DeploymentOrganizationHarness

            # Act
            $failure = { Set-DomainAuthentication -Configuration $configuration -UseWhatIf $false -ActivateDkim $true }

            # Assert
            $failure | Should -Throw '*dkim creation refused*'
            Should -Invoke Set-DkimSigningConfig -ModuleName DeploymentOrganizationHarness -Times 0
            @(Get-DeploymentOrganizationOutcome).Count | Should -Be 0
        }

        It 'propagates a DKIM activation failure without reporting success' {
            # Arrange
            $configuration = New-OrganizationConfiguration
            Mock Set-DkimSigningConfig { throw 'dkim activation refused' } -ModuleName DeploymentOrganizationHarness

            # Act
            $failure = { Set-DomainAuthentication -Configuration $configuration -UseWhatIf $false -ActivateDkim $true }

            # Assert
            $failure | Should -Throw '*dkim activation refused*'
            @(Get-DeploymentOrganizationOutcome).Count | Should -Be 0
        }
    }

    Context 'Positive: a missing DKIM configuration is created and activated' {
        It 'creates the 2048-bit disabled configuration before enabling the resolved domain' {
            # Arrange
            $configuration = New-OrganizationConfiguration
            Mock Get-DkimSigningConfig { $null } -ModuleName DeploymentOrganizationHarness

            # Act
            Set-DomainAuthentication -Configuration $configuration -UseWhatIf $false -ActivateDkim $true

            # Assert
            Should -Invoke New-DkimSigningConfig -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $DomainName -eq 'contoso.example' -and $Enabled -eq $false -and
                $KeySize -eq 2048 -and $WhatIf -eq $false
            }
            Should -Invoke Set-DkimSigningConfig -ModuleName DeploymentOrganizationHarness -Times 1 -ParameterFilter {
                $Identity -eq 'contoso.example' -and $Enabled -eq $true -and $WhatIf -eq $false
            }
            $outcome = @(Get-DeploymentOrganizationOutcome | Where-Object Control -eq 'AUTH-001')
            $outcome.Count | Should -Be 1
            $outcome[0].Status | Should -Be 'Applied'
            $outcome[0].Detail | Should -Be 'DKIM signing enabled'
        }
    }
}

Describe 'TST-002 gateway declaration dispatch' {
    Context 'Negative: native profile never reaches gateway connector mutation' {
        It 'derives the dispatch flag from the resolved context rather than gateway placeholders' {
            # Arrange
            $path = $script:DeploymentScriptPath

            # Act
            $dispatch = Get-GatewayDispatchResult -Path $path

            # Assert
            $dispatch.AssignmentCount | Should -Be 1
            $dispatch.AssignmentText | Should -Be '$context.GatewayDeclared'
        }

        It 'keeps both connector helpers out of the native branch and records the skip' {
            # Arrange
            $path = $script:DeploymentScriptPath

            # Act
            $dispatch = Get-GatewayDispatchResult -Path $path

            # Assert
            $dispatch.DispatchCount | Should -Be 1
            $dispatch.NativeCommands | Should -Not -Contain 'Set-InboundGatewayConnector'
            $dispatch.NativeCommands | Should -Not -Contain 'Set-OutboundGatewayConnector'
            $dispatch.NativeCommands | Should -Contain 'Add-Outcome'
            $dispatch.NativeText | Should -Match 'No mail gateway declared'
        }
    }

    Context 'Positive: a declared gateway reaches both connector helpers' {
        It 'dispatches inbound and outbound connector configuration from one resolved flag' {
            # Arrange
            $path = $script:DeploymentScriptPath

            # Act
            $dispatch = Get-GatewayDispatchResult -Path $path

            # Assert
            $dispatch.DispatchCount | Should -Be 1
            @($dispatch.GatewayCommands | Where-Object { $_ -eq 'Set-InboundGatewayConnector' }).Count | Should -Be 1
            @($dispatch.GatewayCommands | Where-Object { $_ -eq 'Set-OutboundGatewayConnector' }).Count | Should -Be 1
        }
    }
}
