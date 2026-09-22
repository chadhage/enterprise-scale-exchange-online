#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:DeploymentScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'

    $tokens = $null
    $parseErrors = $null
    $script:DeploymentAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:DeploymentScriptPath,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join [Environment]::NewLine) }

    function Get-DeploymentFunctionText {
        param([Parameter(Mandatory)][string]$Name)

        $definition = @($script:DeploymentAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                        $node.Name -ceq $Name
                }, $true))
        if ($definition.Count -eq 0) { return '' }
        if ($definition.Count -ne 1) { throw "Expected one '$Name' definition, found $($definition.Count)." }
        return $definition[0].Extent.Text
    }

    $stubText = @'
function Get-AcceptedDomain { param($Identity, $ResultSize, $ErrorAction) }
function New-AcceptedDomain { param($Name, $DomainName, $DomainType, $WhatIf) }
function Set-AcceptedDomain { param($Identity, $DomainType, $WhatIf) }
function Get-CASMailbox { param($ResultSize, $ErrorAction) }
function Set-CASMailbox { param($Identity, $PopEnabled, $ImapEnabled, $WhatIf) }
'@
    $functionText = @(
        Get-DeploymentFunctionText -Name 'Set-BaselineAcceptedDomainState'
        Get-DeploymentFunctionText -Name 'Set-BaselineExistingMailboxProtocolState'
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $harnessText = @"
`$script:Outcomes = [System.Collections.Generic.List[object]]::new()
`$script:MutationStatus = [ordered]@{}
$stubText
function Add-Outcome {
    param([string]`$Control, [string]`$Status, [string]`$Detail, [string[]]`$Operation = @())
    `$script:Outcomes.Add([pscustomobject]@{ Control = `$Control; Status = `$Status; Detail = `$Detail; Operation = @(`$Operation) })
    foreach (`$operationId in `$Operation) { `$script:MutationStatus[`$operationId] = `$Status }
}
$($functionText -join [Environment]::NewLine)
function Reset-ExoDomainProtocolHarness {
    `$script:Outcomes.Clear()
    `$script:MutationStatus = [ordered]@{}
}
function Get-ExoDomainProtocolOutcome { return @(`$script:Outcomes) }
function Invoke-ExoDomainProtocolEnforcement {
    param([object]`$Configuration, [bool]`$UseWhatIf)
    Set-BaselineAcceptedDomainState -Configuration `$Configuration -UseWhatIf `$UseWhatIf -Confirm:`$false
    Set-BaselineExistingMailboxProtocolState -Configuration `$Configuration -UseWhatIf `$UseWhatIf -Confirm:`$false
}
Export-ModuleMember -Function *
"@
    $script:Harness = New-Module -Name 'ExoDomainProtocolHarness' -ScriptBlock ([scriptblock]::Create($harnessText))
    Import-Module $script:Harness -Force -DisableNameChecking

    function New-DomainProtocolConfiguration {
        [pscustomobject]@{
            desiredState = [pscustomobject]@{
                acceptedDomain = [pscustomobject]@{
                    domainName = 'contoso.example'
                    domainType = 'Authoritative'
                }
                exchangeOnline = [pscustomobject]@{
                    protocolRestriction = [pscustomobject]@{
                        popEnabledByDefault = $false
                        imapEnabledByDefault = $false
                    }
                }
            }
        }
    }

    function Get-DeploymentCommandCount {
        param([Parameter(Mandatory)][string]$FunctionName, [Parameter(Mandatory)][string]$CommandName)

        $function = @($script:DeploymentAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                        $node.Name -ceq $FunctionName
                }, $true))
        if ($function.Count -ne 1) { return 0 }
        return @($function[0].Body.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.CommandAst] -and
                        $node.GetCommandName() -ceq $CommandName
                }, $true)).Count
    }

    function Get-OwnedMutationPlanEntry {
        $assignment = @($script:DeploymentAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                        $node.Left.Extent.Text -ceq '$MutationPlan'
                }, $true))
        if ($assignment.Count -ne 1) { return @() }

        return @($assignment[0].Right.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.HashtableAst]
                }, $true) | Where-Object {
                    $_.Extent.Text -match "OperationId\s*=\s*'exo-(accepted-domain|existing-mailbox-protocol)"
                })
    }
}

AfterAll {
    Remove-Module ExoDomainProtocolHarness -Force -ErrorAction SilentlyContinue
}

Describe 'EXO-015 accepted-domain and existing-mailbox protocol enforcement' {
    BeforeEach {
        Reset-ExoDomainProtocolHarness
        Mock Get-AcceptedDomain { $null } -ModuleName ExoDomainProtocolHarness
        Mock New-AcceptedDomain {} -ModuleName ExoDomainProtocolHarness
        Mock Set-AcceptedDomain {} -ModuleName ExoDomainProtocolHarness
        Mock Get-CASMailbox { @() } -ModuleName ExoDomainProtocolHarness
        Mock Set-CASMailbox {} -ModuleName ExoDomainProtocolHarness
    }

    Context 'Negative: an accepted domain is absent or drifted' {
        It 'creates a missing accepted domain from the resolved desired name and type' {
            # Arrange
            $configuration = New-DomainProtocolConfiguration

            # Act
            Set-BaselineAcceptedDomainState -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke New-AcceptedDomain -ModuleName ExoDomainProtocolHarness -Times 1 -Exactly -ParameterFilter {
                $Name -ceq 'contoso.example' -and $DomainName -ceq 'contoso.example' -and
                $DomainType -ceq 'Authoritative' -and $WhatIf -eq $false
            }
            Should -Invoke Set-AcceptedDomain -ModuleName ExoDomainProtocolHarness -Times 0 -Exactly
        }

        It 'corrects only the type of an existing accepted domain from resolved desired state' {
            # Arrange
            $configuration = New-DomainProtocolConfiguration
            Mock Get-AcceptedDomain {
                [pscustomobject]@{ Name = 'contoso.example'; DomainName = 'contoso.example'; DomainType = 'InternalRelay' }
            } -ModuleName ExoDomainProtocolHarness

            # Act
            Set-BaselineAcceptedDomainState -Configuration $configuration -UseWhatIf $true -Confirm:$false

            # Assert
            Should -Invoke New-AcceptedDomain -ModuleName ExoDomainProtocolHarness -Times 0 -Exactly
            Should -Invoke Set-AcceptedDomain -ModuleName ExoDomainProtocolHarness -Times 1 -Exactly -ParameterFilter {
                $Identity -ceq 'contoso.example' -and $DomainType -ceq 'Authoritative' -and $WhatIf -eq $true
            }
        }

        It 'does not mutate an accepted domain already at the exact desired state' {
            # Arrange
            $configuration = New-DomainProtocolConfiguration
            Mock Get-AcceptedDomain {
                [pscustomobject]@{ Name = 'contoso.example'; DomainName = 'contoso.example'; DomainType = 'Authoritative' }
            } -ModuleName ExoDomainProtocolHarness

            # Act
            Set-BaselineAcceptedDomainState -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke New-AcceptedDomain -ModuleName ExoDomainProtocolHarness -Times 0 -Exactly
            Should -Invoke Set-AcceptedDomain -ModuleName ExoDomainProtocolHarness -Times 0 -Exactly
        }
    }

    Context 'Negative: accepted-domain discovery or mutation fails' {
        It 'propagates accepted-domain discovery failure without reporting success' {
            # Arrange
            $configuration = New-DomainProtocolConfiguration
            Mock Get-AcceptedDomain { throw 'accepted-domain discovery refused' } -ModuleName ExoDomainProtocolHarness

            # Act
            $act = { Set-BaselineAcceptedDomainState -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw -ExpectedMessage '*accepted-domain discovery refused*'
            @(Get-ExoDomainProtocolOutcome).Count | Should -Be 0
        }

        It 'propagates accepted-domain creation failure without reporting success' {
            # Arrange
            $configuration = New-DomainProtocolConfiguration
            Mock New-AcceptedDomain { throw 'accepted-domain creation refused' } -ModuleName ExoDomainProtocolHarness

            # Act
            $act = { Set-BaselineAcceptedDomainState -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw -ExpectedMessage '*accepted-domain creation refused*'
            @(Get-ExoDomainProtocolOutcome).Count | Should -Be 0
        }

        It 'propagates accepted-domain correction failure without reporting success' {
            # Arrange
            $configuration = New-DomainProtocolConfiguration
            Mock Get-AcceptedDomain {
                [pscustomobject]@{ Name = 'contoso.example'; DomainName = 'contoso.example'; DomainType = 'InternalRelay' }
            } -ModuleName ExoDomainProtocolHarness
            Mock Set-AcceptedDomain { throw 'accepted-domain correction refused' } -ModuleName ExoDomainProtocolHarness

            # Act
            $act = { Set-BaselineAcceptedDomainState -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw -ExpectedMessage '*accepted-domain correction refused*'
            @(Get-ExoDomainProtocolOutcome).Count | Should -Be 0
        }
    }

    Context 'Negative: existing mailbox protocols are drifted or cannot be completely enforced' {
        It 'enumerates every existing mailbox and updates only each mailbox whose POP or IMAP state drifts' {
            # Arrange
            $configuration = New-DomainProtocolConfiguration
            $script:MailboxResultSize = $null
            Mock Get-CASMailbox {
                $script:MailboxResultSize = [string]$ResultSize
                @(
                    [pscustomobject]@{ Identity = 'alpha@contoso.example'; PopEnabled = $true; ImapEnabled = $false }
                    [pscustomobject]@{ Identity = 'bravo@contoso.example'; PopEnabled = $false; ImapEnabled = $false }
                    [pscustomobject]@{ Identity = 'charlie@contoso.example'; PopEnabled = $false; ImapEnabled = $true }
                )
            } -ModuleName ExoDomainProtocolHarness

            # Act
            Set-BaselineExistingMailboxProtocolState -Configuration $configuration -UseWhatIf $true -Confirm:$false

            # Assert
            Should -Invoke Get-CASMailbox -ModuleName ExoDomainProtocolHarness -Times 1 -Exactly
            $script:MailboxResultSize | Should -BeExactly 'Unlimited'
            (Get-DeploymentFunctionText -Name 'Set-BaselineExistingMailboxProtocolState') |
                Should -Match 'Get-CASMailbox\s+-ResultSize\s+Unlimited\s+-ErrorAction\s+Stop'
            Should -Invoke Set-CASMailbox -ModuleName ExoDomainProtocolHarness -Times 2 -Exactly -ParameterFilter {
                $Identity -in @('alpha@contoso.example', 'charlie@contoso.example') -and
                $PopEnabled -eq $false -and $ImapEnabled -eq $false -and $WhatIf -eq $true
            }
        }

        It 'does not mutate any existing mailbox already at the exact desired protocol state' {
            # Arrange
            $configuration = New-DomainProtocolConfiguration
            Mock Get-CASMailbox {
                @(
                    [pscustomobject]@{ Identity = 'alpha@contoso.example'; PopEnabled = $false; ImapEnabled = $false }
                    [pscustomobject]@{ Identity = 'bravo@contoso.example'; PopEnabled = $false; ImapEnabled = $false }
                )
            } -ModuleName ExoDomainProtocolHarness

            # Act
            Set-BaselineExistingMailboxProtocolState -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke Set-CASMailbox -ModuleName ExoDomainProtocolHarness -Times 0 -Exactly
        }

        It 'propagates complete-mailbox enumeration failure before any mailbox mutation or success' {
            # Arrange
            $configuration = New-DomainProtocolConfiguration
            Mock Get-CASMailbox { throw 'mailbox enumeration refused' } -ModuleName ExoDomainProtocolHarness

            # Act
            $act = { Set-BaselineExistingMailboxProtocolState -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw -ExpectedMessage '*mailbox enumeration refused*'
            Should -Invoke Set-CASMailbox -ModuleName ExoDomainProtocolHarness -Times 0 -Exactly
            @(Get-ExoDomainProtocolOutcome).Count | Should -Be 0
        }

        It 'propagates a per-mailbox mutation failure and does not report protocol enforcement success' {
            # Arrange
            $configuration = New-DomainProtocolConfiguration
            Mock Get-CASMailbox {
                @(
                    [pscustomobject]@{ Identity = 'alpha@contoso.example'; PopEnabled = $true; ImapEnabled = $true }
                    [pscustomobject]@{ Identity = 'bravo@contoso.example'; PopEnabled = $true; ImapEnabled = $true }
                )
            } -ModuleName ExoDomainProtocolHarness
            Mock Set-CASMailbox { throw 'alpha protocol mutation refused' } -ModuleName ExoDomainProtocolHarness -ParameterFilter {
                $Identity -ceq 'alpha@contoso.example'
            }

            # Act
            $act = { Set-BaselineExistingMailboxProtocolState -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw -ExpectedMessage '*alpha protocol mutation refused*'
            Should -Invoke Set-CASMailbox -ModuleName ExoDomainProtocolHarness -Times 0 -Exactly -ParameterFilter {
                $Identity -ceq 'bravo@contoso.example'
            }
            @(Get-ExoDomainProtocolOutcome).Count | Should -Be 0
        }
    }

    Context 'Negative: ShouldProcess refuses a requested mutation' {
        It 'does not create or correct an accepted domain when ShouldProcess declines' {
            # Arrange
            $configuration = New-DomainProtocolConfiguration

            # Act
            Set-BaselineAcceptedDomainState -Configuration $configuration -UseWhatIf $false -WhatIf

            # Assert
            Should -Invoke New-AcceptedDomain -ModuleName ExoDomainProtocolHarness -Times 0 -Exactly
            Should -Invoke Set-AcceptedDomain -ModuleName ExoDomainProtocolHarness -Times 0 -Exactly
        }

        It 'does not update a drifted existing mailbox when ShouldProcess declines' {
            # Arrange
            $configuration = New-DomainProtocolConfiguration
            Mock Get-CASMailbox {
                [pscustomobject]@{ Identity = 'alpha@contoso.example'; PopEnabled = $true; ImapEnabled = $true }
            } -ModuleName ExoDomainProtocolHarness

            # Act
            Set-BaselineExistingMailboxProtocolState -Configuration $configuration -UseWhatIf $false -WhatIf

            # Assert
            Should -Invoke Set-CASMailbox -ModuleName ExoDomainProtocolHarness -Times 0 -Exactly
        }
    }

    Context 'Negative: deployment orchestration omits owned enforcement or safety declarations' {
        It 'calls each owned enforcement helper exactly once from Set-OrganizationControls' {
            # Arrange
            $expected = @('Set-BaselineAcceptedDomainState', 'Set-BaselineExistingMailboxProtocolState')

            # Act
            $counts = @($expected | ForEach-Object { Get-DeploymentCommandCount -FunctionName 'Set-OrganizationControls' -CommandName $_ })

            # Assert
            $counts | Should -Be @(1, 1) -Because 'organization enforcement must reach both owned helpers exactly once'
        }

        It 'declares accepted-domain create and correction plus existing-mailbox protocol mutations in the safety plan' {
            # Arrange
            $expected = @(
                "exo-accepted-domain-create|New-AcceptedDomain"
                "exo-accepted-domain-set|Set-AcceptedDomain"
                "exo-existing-mailbox-protocol|Set-CASMailbox"
            )

            # Act
            $actual = @(Get-OwnedMutationPlanEntry | ForEach-Object {
                    $operation = [regex]::Match($_.Extent.Text, "OperationId\s*=\s*'([^']+)'").Groups[1].Value
                    $command = [regex]::Match($_.Extent.Text, "Command\s*=\s*'([^']+)'").Groups[1].Value
                    "$operation|$command"
                })

            # Assert
            $actual | Should -Be $expected -Because 'every owned tenant mutation needs a preview, capture, journal and rollback identity'
        }
    }

    Context 'Positive: one mixed resolved fixture reaches the required domain and mailbox state' {
        It 'creates the missing domain, corrects the wrong type, preserves exact members and closes mixed POP and IMAP drift' {
            # Arrange
            $configuration = New-DomainProtocolConfiguration
            $configuration.desiredState.acceptedDomain = @(
                [pscustomobject]@{ domainName = 'contoso.example'; domainType = 'Authoritative' }
                [pscustomobject]@{ domainName = 'fabrikam.example'; domainType = 'InternalRelay' }
            )
            $script:DomainState = [ordered]@{
                'fabrikam.example' = [pscustomobject]@{
                    Name = 'fabrikam.example'; DomainName = 'fabrikam.example'; DomainType = 'Authoritative'
                }
            }
            $script:MailboxState = [ordered]@{
                'alpha@contoso.example' = [pscustomobject]@{ Identity = 'alpha@contoso.example'; PopEnabled = $true; ImapEnabled = $false }
                'bravo@contoso.example' = [pscustomobject]@{ Identity = 'bravo@contoso.example'; PopEnabled = $false; ImapEnabled = $false }
                'charlie@contoso.example' = [pscustomobject]@{ Identity = 'charlie@contoso.example'; PopEnabled = $false; ImapEnabled = $true }
            }
            Mock Get-AcceptedDomain { @($script:DomainState.Values) } -ModuleName ExoDomainProtocolHarness
            Mock New-AcceptedDomain {
                $script:DomainState[$DomainName] = [pscustomobject]@{
                    Name = $Name; DomainName = $DomainName; DomainType = $DomainType
                }
            } -ModuleName ExoDomainProtocolHarness
            Mock Set-AcceptedDomain {
                $script:DomainState[$Identity].DomainType = $DomainType
            } -ModuleName ExoDomainProtocolHarness
            Mock Get-CASMailbox { @($script:MailboxState.Values) } -ModuleName ExoDomainProtocolHarness
            Mock Set-CASMailbox {
                $script:MailboxState[$Identity].PopEnabled = $PopEnabled
                $script:MailboxState[$Identity].ImapEnabled = $ImapEnabled
            } -ModuleName ExoDomainProtocolHarness

            # Act
            Invoke-ExoDomainProtocolEnforcement -Configuration $configuration -UseWhatIf $false

            # Assert
            @($script:DomainState.Keys) | Should -Be @('fabrikam.example', 'contoso.example')
            $script:DomainState['contoso.example'].DomainType | Should -BeExactly 'Authoritative'
            $script:DomainState['fabrikam.example'].DomainType | Should -BeExactly 'InternalRelay'
            @($script:MailboxState.Values | Where-Object { $_.PopEnabled -or $_.ImapEnabled }).Count | Should -Be 0
            Should -Invoke New-AcceptedDomain -ModuleName ExoDomainProtocolHarness -Times 1 -Exactly
            Should -Invoke Set-AcceptedDomain -ModuleName ExoDomainProtocolHarness -Times 1 -Exactly
            Should -Invoke Set-CASMailbox -ModuleName ExoDomainProtocolHarness -Times 2 -Exactly
        }
    }
}