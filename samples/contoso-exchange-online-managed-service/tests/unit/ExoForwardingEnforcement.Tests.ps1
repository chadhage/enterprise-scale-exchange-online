#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:DeploymentScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    function Get-DeploymentFunctionText {
        param([Parameter(Mandatory)][string]$Name)

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:DeploymentScriptPath,
            [ref]$tokens,
            [ref]$errors
        )
        if ($errors.Count -gt 0) { throw ($errors.Message -join '; ') }

        $definition = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $Name
        }, $true))
        if ($definition.Count -ne 1) { throw "Expected one '$Name' definition, found $($definition.Count)." }
        return $definition[0].Extent.Text
    }

    $helperText = Get-DeploymentFunctionText -Name 'Set-BaselineForwardingState'
    $harnessText = @"
Import-Module '$($script:CommonModulePath.Replace("'", "''"))' -Force -DisableNameChecking
function Set-Mailbox { param(`$Identity, `$ForwardingAddress, `$ForwardingSmtpAddress, `$WhatIf) }
function Disable-InboxRule { param(`$Mailbox, `$Identity, `$Confirm, `$WhatIf) }
$helperText
Export-ModuleMember -Function Set-BaselineForwardingState
"@
    $script:Harness = New-Module -Name 'ExoForwardingEnforcementHarness' -ScriptBlock ([scriptblock]::Create($harnessText))
    Import-Module $script:Harness -Force -DisableNameChecking

    function New-Mailbox {
        param(
            [string]$Identity,
            [object]$ForwardingAddress = $null,
            [object]$ForwardingSmtpAddress = $null
        )

        [pscustomobject]@{
            Identity = $Identity
            PrimarySmtpAddress = $Identity
            ForwardingAddress = $ForwardingAddress
            ForwardingSmtpAddress = $ForwardingSmtpAddress
        }
    }

    function New-Rule {
        param(
            [string]$Identity,
            [bool]$Enabled = $true,
            [object[]]$ForwardTo = @(),
            [object[]]$ForwardAsAttachmentTo = @(),
            [object[]]$RedirectTo = @()
        )

        [pscustomobject]@{
            Identity = $Identity
            Enabled = $Enabled
            ForwardTo = @($ForwardTo)
            ForwardAsAttachmentTo = @($ForwardAsAttachmentTo)
            RedirectTo = @($RedirectTo)
        }
    }

    function New-ForwardingFixture {
        param(
            [object[]]$Mailbox = @((New-Mailbox 'alice@contoso.example')),
            [hashtable]$Rules = @{},
            [scriptblock]$PageCollection,
            [scriptblock]$RuleCollection
        )

        $mailboxSet = @($Mailbox)
        $ruleSet = $Rules
        if ($null -eq $PageCollection) {
            $PageCollection = {
                param($ContinuationToken)
                [pscustomobject]@{ Mailbox = $mailboxSet; ContinuationToken = $null }
            }.GetNewClosure()
        }
        if ($null -eq $RuleCollection) {
            $RuleCollection = {
                param($MailboxRecord, $TimeoutSecond)
                $identity = [string]$MailboxRecord.PrimarySmtpAddress
                [pscustomobject]@{
                    Status = 'Success'
                    Complete = $true
                    Rules = @($ruleSet[$identity] | Where-Object { $null -ne $_ })
                }
            }.GetNewClosure()
        }

        [pscustomobject]@{
            AcceptedDomain = @('contoso.example')
            PageCollection = $PageCollection
            RuleCollection = $RuleCollection
            Wait = { param($Second) }
            Clock = { 0 }
        }
    }

    function Invoke-ForwardingFixture {
        param([Parameter(Mandatory)][object]$Fixture, [bool]$UseWhatIf = $false)

        Set-BaselineForwardingState -AcceptedDomain $Fixture.AcceptedDomain `
            -PageCollection $Fixture.PageCollection -InboxRuleCollection $Fixture.RuleCollection `
            -Wait $Fixture.Wait -Clock $Fixture.Clock -UseWhatIf $UseWhatIf
    }
}

AfterAll {
    Remove-Module ExoForwardingEnforcementHarness -Force -ErrorAction SilentlyContinue
}

Describe 'EXO-015 mailbox and inbox-rule forwarding enforcement' {
    BeforeEach {
        Mock Set-Mailbox {} -ModuleName ExoForwardingEnforcementHarness
        Mock Disable-InboxRule {} -ModuleName ExoForwardingEnforcementHarness
    }

    Context 'Negative: compliant and preserved forwarding routes are not mutated' {
        It 'is an exact no-op when no mailbox or rule forwards externally' {
            # Arrange
            $fixture = New-ForwardingFixture -Mailbox @(
                (New-Mailbox 'alice@contoso.example')
            ) -Rules @{
                'alice@contoso.example' = @(
                    (New-Rule -Identity 'Internal copy' -ForwardTo @('manager@contoso.example'))
                )
            }

            # Act
            Invoke-ForwardingFixture -Fixture $fixture

            # Assert
            Should -Invoke Set-Mailbox -ModuleName ExoForwardingEnforcementHarness -Times 0
            Should -Invoke Disable-InboxRule -ModuleName ExoForwardingEnforcementHarness -Times 0
        }

        It 'preserves disabled external rules and enabled internal-only rules' {
            # Arrange
            $fixture = New-ForwardingFixture -Rules @{
                'alice@contoso.example' = @(
                    (New-Rule -Identity 'Disabled external' -Enabled $false -RedirectTo @('outside@fabrikam.example'))
                    (New-Rule -Identity 'Internal attachment' -ForwardAsAttachmentTo @([pscustomobject]@{ Address = 'archive@contoso.example' }))
                )
            }

            # Act
            Invoke-ForwardingFixture -Fixture $fixture

            # Assert
            Should -Invoke Disable-InboxRule -ModuleName ExoForwardingEnforcementHarness -Times 0
        }
    }

    Context 'Negative: every external forwarding route is removed' {
        It 'clears mailbox ForwardingAddress and ForwardingSmtpAddress together' {
            # Arrange
            $fixture = New-ForwardingFixture -Mailbox @(
                (New-Mailbox 'alice@contoso.example' -ForwardingAddress 'legacy-contact' -ForwardingSmtpAddress 'smtp:outside@fabrikam.example')
            )

            # Act
            Invoke-ForwardingFixture -Fixture $fixture

            # Assert
            Should -Invoke Set-Mailbox -ModuleName ExoForwardingEnforcementHarness -Times 1 -ParameterFilter {
                $Identity -eq 'alice@contoso.example' -and $null -eq $ForwardingAddress -and
                $null -eq $ForwardingSmtpAddress -and $WhatIf -eq $false
            }
        }

        It 'disables an enabled rule using external ForwardTo' {
            # Arrange
            $fixture = New-ForwardingFixture -Rules @{
                'alice@contoso.example' = @((New-Rule -Identity 'Forward out' -ForwardTo @('outside@fabrikam.example')))
            }

            # Act
            Invoke-ForwardingFixture -Fixture $fixture

            # Assert
            Should -Invoke Disable-InboxRule -ModuleName ExoForwardingEnforcementHarness -Times 1 -ParameterFilter {
                $Mailbox -eq 'alice@contoso.example' -and $Identity -eq 'Forward out' -and $Confirm -eq $false
            }
        }

        It 'disables an enabled rule using external ForwardAsAttachmentTo' {
            # Arrange
            $fixture = New-ForwardingFixture -Rules @{
                'alice@contoso.example' = @((New-Rule -Identity 'Attach out' -ForwardAsAttachmentTo @('outside@fabrikam.example')))
            }

            # Act
            Invoke-ForwardingFixture -Fixture $fixture

            # Assert
            Should -Invoke Disable-InboxRule -ModuleName ExoForwardingEnforcementHarness -Times 1 -ParameterFilter {
                $Mailbox -eq 'alice@contoso.example' -and $Identity -eq 'Attach out'
            }
        }

        It 'disables an enabled rule using external RedirectTo' {
            # Arrange
            $fixture = New-ForwardingFixture -Rules @{
                'alice@contoso.example' = @((New-Rule -Identity 'Redirect out' -RedirectTo @([pscustomobject]@{ Address = 'outside@fabrikam.example' })))
            }

            # Act
            Invoke-ForwardingFixture -Fixture $fixture

            # Assert
            Should -Invoke Disable-InboxRule -ModuleName ExoForwardingEnforcementHarness -Times 1 -ParameterFilter {
                $Mailbox -eq 'alice@contoso.example' -and $Identity -eq 'Redirect out'
            }
        }
    }

    Context 'Negative: incomplete collection and mutation failures refuse enforcement' {
        It 'refuses when complete mailbox collection fails' {
            # Arrange
            $fixture = New-ForwardingFixture -PageCollection { throw 'MailboxPageRefused: page 2 failed' }

            # Act
            $act = { Invoke-ForwardingFixture -Fixture $fixture }

            # Assert
            $act | Should -Throw -ExpectedMessage '*MailboxPageRefused: page 2 failed*'
            Should -Invoke Set-Mailbox -ModuleName ExoForwardingEnforcementHarness -Times 0
            Should -Invoke Disable-InboxRule -ModuleName ExoForwardingEnforcementHarness -Times 0
        }

        It 'refuses when bounded inbox-rule collection is incomplete' {
            # Arrange
            $fixture = New-ForwardingFixture -RuleCollection {
                param($MailboxRecord, $TimeoutSecond)
                [pscustomobject]@{ Status = 'Inaccessible'; Complete = $false; Rules = @(); Reason = 'access denied' }
            }

            # Act
            $act = { Invoke-ForwardingFixture -Fixture $fixture }

            # Assert
            $act | Should -Throw -ExpectedMessage '*MailboxInboxRuleInaccessible*alice@contoso.example*access denied*'
            Should -Invoke Set-Mailbox -ModuleName ExoForwardingEnforcementHarness -Times 0
            Should -Invoke Disable-InboxRule -ModuleName ExoForwardingEnforcementHarness -Times 0
        }

        It 'propagates a mailbox forwarding mutation failure and stops before rule mutation' {
            # Arrange
            $fixture = New-ForwardingFixture -Mailbox @(
                (New-Mailbox 'alice@contoso.example' -ForwardingSmtpAddress 'outside@fabrikam.example')
            ) -Rules @{
                'alice@contoso.example' = @((New-Rule -Identity 'Forward out' -ForwardTo @('outside@fabrikam.example')))
            }
            Mock Set-Mailbox { throw 'mailbox mutation refused' } -ModuleName ExoForwardingEnforcementHarness

            # Act
            $act = { Invoke-ForwardingFixture -Fixture $fixture }

            # Assert
            $act | Should -Throw -ExpectedMessage '*mailbox mutation refused*'
            Should -Invoke Disable-InboxRule -ModuleName ExoForwardingEnforcementHarness -Times 0
        }

        It 'propagates an inbox-rule mutation failure' {
            # Arrange
            $fixture = New-ForwardingFixture -Rules @{
                'alice@contoso.example' = @((New-Rule -Identity 'Forward out' -ForwardTo @('outside@fabrikam.example')))
            }
            Mock Disable-InboxRule { throw 'rule mutation refused' } -ModuleName ExoForwardingEnforcementHarness

            # Act
            $act = { Invoke-ForwardingFixture -Fixture $fixture }

            # Assert
            $act | Should -Throw -ExpectedMessage '*rule mutation refused*'
        }
    }

    Context 'Positive: one complete mixed fixture closes every external forwarding route' {
        It 'removes mailbox forwarding and disables only enabled external rules across the complete mailbox set' {
            # Arrange
            $fixture = New-ForwardingFixture -Mailbox @(
                (New-Mailbox 'alice@contoso.example' -ForwardingAddress 'legacy-contact')
                (New-Mailbox 'bob@contoso.example' -ForwardingSmtpAddress 'smtp:outside@fabrikam.example')
                (New-Mailbox 'carol@contoso.example')
            ) -Rules @{
                'alice@contoso.example' = @(
                    (New-Rule -Identity 'Forward out' -ForwardTo @('outside@fabrikam.example'))
                    (New-Rule -Identity 'Internal copy' -RedirectTo @('archive@contoso.example'))
                )
                'bob@contoso.example' = @(
                    (New-Rule -Identity 'Attach out' -ForwardAsAttachmentTo @([pscustomobject]@{ Address = 'outside@fabrikam.example' }))
                    (New-Rule -Identity 'Disabled redirect' -Enabled $false -RedirectTo @('outside@fabrikam.example'))
                )
                'carol@contoso.example' = @(
                    (New-Rule -Identity 'Redirect out' -RedirectTo @('smtp:outside@fabrikam.example'))
                )
            }

            # Act
            Invoke-ForwardingFixture -Fixture $fixture

            # Assert
            Should -Invoke Set-Mailbox -ModuleName ExoForwardingEnforcementHarness -Times 2 -ParameterFilter {
                $Identity -in @('alice@contoso.example', 'bob@contoso.example') -and
                $null -eq $ForwardingAddress -and $null -eq $ForwardingSmtpAddress
            }
            Should -Invoke Disable-InboxRule -ModuleName ExoForwardingEnforcementHarness -Times 3 -ParameterFilter {
                $Identity -in @('Forward out', 'Attach out', 'Redirect out') -and
                $Mailbox -in @('alice@contoso.example', 'bob@contoso.example', 'carol@contoso.example')
            }
            Should -Invoke Disable-InboxRule -ModuleName ExoForwardingEnforcementHarness -Times 0 -ParameterFilter {
                $Identity -in @('Internal copy', 'Disabled redirect')
            }
        }
    }
}