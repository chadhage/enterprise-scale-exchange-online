#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:DeploymentScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'

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

    $helperText = Get-DeploymentFunctionText -Name 'Set-BaselineImpersonationProtectionState'
    $harnessText = @"
function Get-AntiPhishPolicy { param(`$Identity, `$ErrorAction) }
function New-AntiPhishPolicy {
    param(`$Name, `$EnableTargetedUserProtection, `$EnableTargetedDomainsProtection,
        `$TargetedUsersToProtect, `$TargetedDomainsToProtect, `$ExcludedSenders, `$ExcludedDomains, `$WhatIf)
}
function Set-AntiPhishPolicy {
    param(`$Identity, `$EnableTargetedUserProtection, `$EnableTargetedDomainsProtection,
        `$TargetedUsersToProtect, `$TargetedDomainsToProtect, `$ExcludedSenders, `$ExcludedDomains, `$WhatIf)
}
function Add-Outcome { param(`$Control, `$Status, `$Detail, `$Operation) }
$helperText
Export-ModuleMember -Function Set-BaselineImpersonationProtectionState
"@
    $script:Harness = New-Module -Name 'MdoImpersonationEnforcementHarness' -ScriptBlock ([scriptblock]::Create($harnessText))
    Import-Module $script:Harness -Force -DisableNameChecking

    function New-ImpersonationConfiguration {
        param(
            [string[]]$ProtectedUsers = @('ceo@contoso.example', 'legal@contoso.example'),
            [string[]]$ProtectedDomains = @('contoso.example', 'brand.example'),
            [object[]]$ApprovedExceptions = @(
                [pscustomobject]@{ exceptionType = 'TrustedSender'; value = 'partner@fabrikam.example' }
                [pscustomobject]@{ exceptionType = 'TrustedDomain'; value = 'simulation.fabrikam.example' }
            )
        )

        [pscustomobject]@{
            desiredState = [pscustomobject]@{
                defenderForOffice365 = [pscustomobject]@{
                    impersonationProtection = [pscustomobject]@{
                        enabled = $true
                        protectedUsers = @($ProtectedUsers)
                        protectedDomains = @($ProtectedDomains)
                        approvedExceptions = @($ApprovedExceptions)
                    }
                }
            }
        }
    }

    function New-CurrentPolicy {
        param(
            [bool]$EnableTargetedUserProtection = $true,
            [bool]$EnableTargetedDomainsProtection = $true,
            [string[]]$TargetedUsersToProtect = @('ceo@contoso.example', 'legal@contoso.example'),
            [string[]]$TargetedDomainsToProtect = @('contoso.example', 'brand.example'),
            [string[]]$ExcludedSenders = @('partner@fabrikam.example'),
            [string[]]$ExcludedDomains = @('simulation.fabrikam.example')
        )

        [pscustomobject]@{
            Identity = 'Contoso Impersonation Protection'
            EnableTargetedUserProtection = $EnableTargetedUserProtection
            EnableTargetedDomainsProtection = $EnableTargetedDomainsProtection
            TargetedUsersToProtect = @($TargetedUsersToProtect)
            TargetedDomainsToProtect = @($TargetedDomainsToProtect)
            ExcludedSenders = @($ExcludedSenders)
            ExcludedDomains = @($ExcludedDomains)
        }
    }
}

AfterAll {
    Remove-Module MdoImpersonationEnforcementHarness -Force -ErrorAction SilentlyContinue
}

Describe 'MDO-010 impersonation-protection enforcement' {
    BeforeEach {
        Mock Get-AntiPhishPolicy { New-CurrentPolicy } -ModuleName MdoImpersonationEnforcementHarness
        Mock New-AntiPhishPolicy {} -ModuleName MdoImpersonationEnforcementHarness
        Mock Set-AntiPhishPolicy {} -ModuleName MdoImpersonationEnforcementHarness
        Mock Add-Outcome {} -ModuleName MdoImpersonationEnforcementHarness
    }

    Context 'Negative: compliant resolved state is an exact no-op' {
        It 'does not rewrite an anti-phish policy whose six governed members already match' {
            # Arrange
            $configuration = New-ImpersonationConfiguration

            # Act
            Set-BaselineImpersonationProtectionState -Configuration $configuration -UseWhatIf $false

            # Assert
            Should -Invoke New-AntiPhishPolicy -ModuleName MdoImpersonationEnforcementHarness -Times 0
            Should -Invoke Set-AntiPhishPolicy -ModuleName MdoImpersonationEnforcementHarness -Times 0
            Should -Invoke Add-Outcome -ModuleName MdoImpersonationEnforcementHarness -Times 1 -ParameterFilter {
                $Control -eq 'MDO-009' -and @($Operation).Count -eq 0
            }
        }
    }

    Context 'Negative: absent state takes only the create branch' {
        It 'creates all protected and trusted members exactly from resolved state' {
            # Arrange
            $configuration = New-ImpersonationConfiguration
            Mock Get-AntiPhishPolicy { $null } -ModuleName MdoImpersonationEnforcementHarness

            # Act
            Set-BaselineImpersonationProtectionState -Configuration $configuration -UseWhatIf $false

            # Assert
            Should -Invoke New-AntiPhishPolicy -ModuleName MdoImpersonationEnforcementHarness -Times 1 -ParameterFilter {
                $Name -eq 'Contoso Impersonation Protection' -and
                $EnableTargetedUserProtection -eq $true -and $EnableTargetedDomainsProtection -eq $true -and
                (@($TargetedUsersToProtect) -join ',') -ceq 'ceo@contoso.example,legal@contoso.example' -and
                (@($TargetedDomainsToProtect) -join ',') -ceq 'contoso.example,brand.example' -and
                (@($ExcludedSenders) -join ',') -ceq 'partner@fabrikam.example' -and
                (@($ExcludedDomains) -join ',') -ceq 'simulation.fabrikam.example' -and $WhatIf -eq $false
            }
            Should -Invoke Set-AntiPhishPolicy -ModuleName MdoImpersonationEnforcementHarness -Times 0
            Should -Invoke Add-Outcome -ModuleName MdoImpersonationEnforcementHarness -Times 1 -ParameterFilter {
                @($Operation) -contains 'mdo-impersonation-policy-create'
            }
        }
    }

    Context 'Negative: drifted state takes only the exact update branch' {
        It 'replaces surplus, missing and disabled governed members' {
            # Arrange
            $configuration = New-ImpersonationConfiguration
            Mock Get-AntiPhishPolicy {
                New-CurrentPolicy -EnableTargetedUserProtection $false `
                    -TargetedUsersToProtect @('attacker@contoso.example') `
                    -TargetedDomainsToProtect @('old.example') `
                    -ExcludedSenders @('unapproved@fabrikam.example') `
                    -ExcludedDomains @('unapproved.example')
            } -ModuleName MdoImpersonationEnforcementHarness

            # Act
            Set-BaselineImpersonationProtectionState -Configuration $configuration -UseWhatIf $false

            # Assert
            Should -Invoke Set-AntiPhishPolicy -ModuleName MdoImpersonationEnforcementHarness -Times 1 -ParameterFilter {
                $Identity -eq 'Contoso Impersonation Protection' -and
                $EnableTargetedUserProtection -eq $true -and $EnableTargetedDomainsProtection -eq $true -and
                (@($TargetedUsersToProtect) -join ',') -ceq 'ceo@contoso.example,legal@contoso.example' -and
                (@($TargetedDomainsToProtect) -join ',') -ceq 'contoso.example,brand.example' -and
                (@($ExcludedSenders) -join ',') -ceq 'partner@fabrikam.example' -and
                (@($ExcludedDomains) -join ',') -ceq 'simulation.fabrikam.example'
            }
            Should -Invoke New-AntiPhishPolicy -ModuleName MdoImpersonationEnforcementHarness -Times 0
            Should -Invoke Add-Outcome -ModuleName MdoImpersonationEnforcementHarness -Times 1 -ParameterFilter {
                @($Operation) -contains 'mdo-impersonation-policy-set'
            }
        }
    }

    Context 'Negative: every anti-phish mutation remains behind ShouldProcess' {
        It 'performs neither create nor journal accounting when WhatIf declines creation' {
            # Arrange
            $configuration = New-ImpersonationConfiguration
            Mock Get-AntiPhishPolicy { $null } -ModuleName MdoImpersonationEnforcementHarness

            # Act
            Set-BaselineImpersonationProtectionState -Configuration $configuration -UseWhatIf $false -WhatIf

            # Assert
            Should -Invoke New-AntiPhishPolicy -ModuleName MdoImpersonationEnforcementHarness -Times 0
            Should -Invoke Set-AntiPhishPolicy -ModuleName MdoImpersonationEnforcementHarness -Times 0
            Should -Invoke Add-Outcome -ModuleName MdoImpersonationEnforcementHarness -Times 1 -ParameterFilter {
                @($Operation).Count -eq 0
            }
        }

        It 'performs neither update nor journal accounting when WhatIf declines update' {
            # Arrange
            $configuration = New-ImpersonationConfiguration
            Mock Get-AntiPhishPolicy {
                New-CurrentPolicy -TargetedDomainsToProtect @('old.example')
            } -ModuleName MdoImpersonationEnforcementHarness

            # Act
            Set-BaselineImpersonationProtectionState -Configuration $configuration -UseWhatIf $false -WhatIf

            # Assert
            Should -Invoke New-AntiPhishPolicy -ModuleName MdoImpersonationEnforcementHarness -Times 0
            Should -Invoke Set-AntiPhishPolicy -ModuleName MdoImpersonationEnforcementHarness -Times 0
            Should -Invoke Add-Outcome -ModuleName MdoImpersonationEnforcementHarness -Times 1 -ParameterFilter {
                @($Operation).Count -eq 0
            }
        }
    }

    Context 'Negative: collection and mutation failures never report a journalled success' {
        It 'propagates anti-phish collection failure before mutation' {
            # Arrange
            $configuration = New-ImpersonationConfiguration
            Mock Get-AntiPhishPolicy { throw 'anti-phish collection refused' } -ModuleName MdoImpersonationEnforcementHarness

            # Act
            $act = { Set-BaselineImpersonationProtectionState -Configuration $configuration -UseWhatIf $false }

            # Assert
            $act | Should -Throw -ExpectedMessage '*anti-phish collection refused*'
            Should -Invoke New-AntiPhishPolicy -ModuleName MdoImpersonationEnforcementHarness -Times 0
            Should -Invoke Set-AntiPhishPolicy -ModuleName MdoImpersonationEnforcementHarness -Times 0
            Should -Invoke Add-Outcome -ModuleName MdoImpersonationEnforcementHarness -Times 0
        }

        It 'propagates create failure without journal accounting' {
            # Arrange
            $configuration = New-ImpersonationConfiguration
            Mock Get-AntiPhishPolicy { $null } -ModuleName MdoImpersonationEnforcementHarness
            Mock New-AntiPhishPolicy { throw 'anti-phish create refused' } -ModuleName MdoImpersonationEnforcementHarness

            # Act
            $act = { Set-BaselineImpersonationProtectionState -Configuration $configuration -UseWhatIf $false }

            # Assert
            $act | Should -Throw -ExpectedMessage '*anti-phish create refused*'
            Should -Invoke Add-Outcome -ModuleName MdoImpersonationEnforcementHarness -Times 0
        }

        It 'propagates update failure without journal accounting' {
            # Arrange
            $configuration = New-ImpersonationConfiguration
            Mock Get-AntiPhishPolicy { New-CurrentPolicy -ExcludedSenders @() } -ModuleName MdoImpersonationEnforcementHarness
            Mock Set-AntiPhishPolicy { throw 'anti-phish update refused' } -ModuleName MdoImpersonationEnforcementHarness

            # Act
            $act = { Set-BaselineImpersonationProtectionState -Configuration $configuration -UseWhatIf $false }

            # Assert
            $act | Should -Throw -ExpectedMessage '*anti-phish update refused*'
            Should -Invoke Add-Outcome -ModuleName MdoImpersonationEnforcementHarness -Times 0
        }
    }

    Context 'Negative: mutation safety wiring covers both anti-phish commands' {
        It 'declares create and update operations with capture reads and resolved desired members' {
            # Arrange
            $scriptText = Get-Content -LiteralPath $script:DeploymentScriptPath -Raw

            # Act
            $createPlan = [regex]::Match($scriptText, "(?s)OperationId\s*=\s*'mdo-impersonation-policy-create'.*?Command\s*=\s*'New-AntiPhishPolicy'.*?Area\s*=\s*'ImpersonationProtection'.*?Desired\s*=.*?Read\s*=\s*\{")
            $setPlan = [regex]::Match($scriptText, "(?s)OperationId\s*=\s*'mdo-impersonation-policy-set'.*?Command\s*=\s*'Set-AntiPhishPolicy'.*?Area\s*=\s*'ImpersonationProtection'.*?Desired\s*=.*?Read\s*=\s*\{")

            # Assert
            $createPlan.Success | Should -BeTrue
            $setPlan.Success | Should -BeTrue
        }

        It 'calls the helper from resolved organization enforcement' {
            # Arrange
            $organizationText = Get-DeploymentFunctionText -Name 'Set-OrganizationControls'

            # Act
            $callCount = ([regex]::Matches($organizationText, '\bSet-BaselineImpersonationProtectionState\b')).Count

            # Assert
            $callCount | Should -Be 1
            $organizationText | Should -Match 'Set-BaselineImpersonationProtectionState\s+-Configuration\s+\$Configuration\s+-UseWhatIf\s+\$UseWhatIf'
        }
    }

    Context 'Positive: one resolved policy converges with auditable operation state' {
        It 'creates the exact anti-phish policy in preview mode and records only that planned mutation' {
            # Arrange
            $configuration = New-ImpersonationConfiguration -ApprovedExceptions @(
                [pscustomobject]@{ exceptionType = 'TrustedDomain'; value = 'simulation.fabrikam.example' }
                [pscustomobject]@{ exceptionType = 'TrustedSender'; value = 'partner@fabrikam.example' }
            )
            Mock Get-AntiPhishPolicy { $null } -ModuleName MdoImpersonationEnforcementHarness

            # Act
            Set-BaselineImpersonationProtectionState -Configuration $configuration -UseWhatIf $true

            # Assert
            Should -Invoke New-AntiPhishPolicy -ModuleName MdoImpersonationEnforcementHarness -Times 1 -ParameterFilter {
                $Name -eq 'Contoso Impersonation Protection' -and $WhatIf -eq $true -and
                (@($TargetedUsersToProtect) -join ',') -ceq 'ceo@contoso.example,legal@contoso.example' -and
                (@($TargetedDomainsToProtect) -join ',') -ceq 'contoso.example,brand.example' -and
                (@($ExcludedSenders) -join ',') -ceq 'partner@fabrikam.example' -and
                (@($ExcludedDomains) -join ',') -ceq 'simulation.fabrikam.example'
            }
            Should -Invoke Set-AntiPhishPolicy -ModuleName MdoImpersonationEnforcementHarness -Times 0
            Should -Invoke Add-Outcome -ModuleName MdoImpersonationEnforcementHarness -Times 1 -ParameterFilter {
                $Control -eq 'MDO-009' -and $Status -eq 'Planned' -and
                (@($Operation) -join ',') -ceq 'mdo-impersonation-policy-create'
            }
        }
    }
}
