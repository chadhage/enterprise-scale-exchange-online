#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:DeploymentScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'

    function Get-DeploymentFunctionText {
        param([Parameter(Mandatory)][string[]]$Name)

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:DeploymentScriptPath, [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) { throw ($errors.Message -join '; ') }

        foreach ($functionName in $Name) {
            $definition = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -in @($functionName, "script:$functionName")
            }, $true))
            if ($definition.Count -ne 1) { throw "Expected one '$functionName' definition, found $($definition.Count)." }
            $definition[0].Extent.Text
        }
    }

    $stubText = @'
function Get-RoleAssignmentPolicy { param($ErrorAction) }
function Get-ManagementRoleAssignment { param($ErrorAction) }
function Remove-ManagementRoleAssignment { param($Identity, $Confirm, $WhatIf) }
'@
    $functionText = Get-DeploymentFunctionText -Name @(
        'Add-Outcome',
        'Set-BaselineAddInAcquisitionState',
        'Test-BaselineExoPostChange'
    )
    $harnessText = @"
`$script:Outcomes = [System.Collections.Generic.List[object]]::new()
`$script:MutationStatus = [ordered]@{}
$stubText
$($functionText -join [Environment]::NewLine)
function Reset-ExoEnforcementHarness {
    `$script:Outcomes.Clear()
    `$script:MutationStatus = [ordered]@{}
}
function Get-ExoEnforcementOutcome { return @(`$script:Outcomes) }
Export-ModuleMember -Function *
"@
    $script:Harness = New-Module -Name 'ExoAddInPostChangeEnforcementHarness' -ScriptBlock ([scriptblock]::Create($harnessText))
    Import-Module $script:Harness -Force -DisableNameChecking

    function New-ExoConfiguration {
        param([bool]$OutlookAddInsForUsers = $false)

        [pscustomobject]@{
            desiredState = [pscustomobject]@{
                exchangeOnline = [pscustomobject]@{
                    protocolRestriction = [pscustomobject]@{
                        outlookAddInsForUsers = $OutlookAddInsForUsers
                    }
                }
            }
        }
    }

    function New-RoleAssignment {
        param(
            [string]$Role = 'My Custom Apps',
            [string]$RoleAssignee = 'Default Role Assignment Policy',
            [string]$Name = "$Role-$RoleAssignee"
        )

        [pscustomobject]@{ Name = $Name; Role = $Role; RoleAssignee = $RoleAssignee }
    }

    function New-PostChangeOperation {
        param(
            [string]$OperationId,
            [string]$Area,
            [string]$Identity,
            [hashtable]$Desired,
            [AllowNull()][object]$Observed
        )

        $read = { $Observed }.GetNewClosure()
        [ordered]@{
            OperationId = $OperationId
            Area = $Area
            Identity = $Identity
            Desired = $Desired
            Read = $read
        }
    }

    function New-CompletePostChangeOperation {
        @(
            (New-PostChangeOperation -OperationId 'exo-accepted-domain-set' -Area 'AcceptedDomain' `
                -Identity 'contoso.example' -Desired @{ DomainType = 'Authoritative' } `
                -Observed ([pscustomobject]@{ DomainType = 'Authoritative' })),
            (New-PostChangeOperation -OperationId 'exo-mailbox-protocol-set' -Area 'MailboxProtocol' `
                -Identity 'alex@contoso.example' -Desired @{ PopEnabled = $false; ImapEnabled = $false } `
                -Observed ([pscustomobject]@{ PopEnabled = $false; ImapEnabled = $false })),
            (New-PostChangeOperation -OperationId 'exo-mailbox-forwarding-clear' -Area 'MailboxForwarding' `
                -Identity 'alex@contoso.example' -Desired @{ ForwardingAddress = $null; ForwardingSmtpAddress = $null } `
                -Observed ([pscustomobject]@{ ForwardingAddress = $null; ForwardingSmtpAddress = $null })),
            (New-PostChangeOperation -OperationId 'exo-inbox-rule-forwarding-clear' -Area 'InboxRule' `
                -Identity 'alex@contoso.example/External redirect' `
                -Desired @{ ForwardTo = @(); ForwardAsAttachmentTo = @(); RedirectTo = @() } `
                -Observed ([pscustomobject]@{ ForwardTo = @(); ForwardAsAttachmentTo = @(); RedirectTo = @() })),
            (New-PostChangeOperation -OperationId 'exo-addin-acquisition-remove' -Area 'AddInAcquisition' `
                -Identity 'Default Role Assignment Policy' `
                -Desired @{ Roles = @() } -Observed ([pscustomobject]@{ Roles = @() }))
        )
    }
}

AfterAll {
    Remove-Module ExoAddInPostChangeEnforcementHarness -Force -ErrorAction SilentlyContinue
}

Describe 'EXO-015 add-in acquisition enforcement and exact post-change decision' {
    BeforeEach {
        Reset-ExoEnforcementHarness
        Mock Write-Host {} -ModuleName ExoAddInPostChangeEnforcementHarness
        Mock Get-RoleAssignmentPolicy {
            @([pscustomobject]@{ Identity = 'Default Role Assignment Policy'; IsDefault = $true })
        } -ModuleName ExoAddInPostChangeEnforcementHarness
        Mock Get-ManagementRoleAssignment { @() } -ModuleName ExoAddInPostChangeEnforcementHarness
        Mock Remove-ManagementRoleAssignment {} -ModuleName ExoAddInPostChangeEnforcementHarness
    }

    Context 'Negative: add-in acquisition enforcement changes only forbidden grants on the default policy' {
        It 'is an exact no-op when the default policy has no forbidden add-in grant' {
            # Arrange
            Mock Get-ManagementRoleAssignment {
                @(New-RoleAssignment -Role 'MyBaseOptions')
            } -ModuleName ExoAddInPostChangeEnforcementHarness

            # Act
            Set-BaselineAddInAcquisitionState -Configuration (New-ExoConfiguration) -UseWhatIf $false

            # Assert
            Should -Invoke Remove-ManagementRoleAssignment -ModuleName ExoAddInPostChangeEnforcementHarness -Times 0
        }

        It 'removes the forbidden <_> grant from the default policy' -ForEach @(
            'My Custom Apps',
            'My Marketplace Apps',
            'My ReadWriteMailboxApps'
        ) {
            # Arrange
            $assignment = New-RoleAssignment -Role $_ -Name "assignment-$_"
            Mock Get-ManagementRoleAssignment { @($assignment) } -ModuleName ExoAddInPostChangeEnforcementHarness

            # Act
            Set-BaselineAddInAcquisitionState -Configuration (New-ExoConfiguration) -UseWhatIf $false

            # Assert
            Should -Invoke Remove-ManagementRoleAssignment -ModuleName ExoAddInPostChangeEnforcementHarness -Times 1 -ParameterFilter {
                $Identity -eq $assignment.Name -and $Confirm -eq $false -and $WhatIf -eq $false
            }
        }

        It 'preserves unrelated roles and forbidden roles assigned to a non-default policy' {
            # Arrange
            $assignment = @(
                (New-RoleAssignment -Role 'MyBaseOptions' -Name 'unrelated-default'),
                (New-RoleAssignment -Role 'My Custom Apps' -RoleAssignee 'Restricted Recipients Policy' -Name 'forbidden-non-default')
            )
            Mock Get-ManagementRoleAssignment { $assignment } -ModuleName ExoAddInPostChangeEnforcementHarness

            # Act
            Set-BaselineAddInAcquisitionState -Configuration (New-ExoConfiguration) -UseWhatIf $false

            # Assert
            Should -Invoke Remove-ManagementRoleAssignment -ModuleName ExoAddInPostChangeEnforcementHarness -Times 0
        }

        It 'propagates a removal failure and never reports the add-in mutation applied' {
            # Arrange
            Mock Get-ManagementRoleAssignment {
                @(New-RoleAssignment -Role 'My Custom Apps' -Name 'refused-assignment')
            } -ModuleName ExoAddInPostChangeEnforcementHarness
            Mock Remove-ManagementRoleAssignment { throw 'removal refused' } -ModuleName ExoAddInPostChangeEnforcementHarness

            # Act
            $failure = { Set-BaselineAddInAcquisitionState -Configuration (New-ExoConfiguration) -UseWhatIf $false }

            # Assert
            $failure | Should -Throw '*removal refused*'
            @(Get-ExoEnforcementOutcome | Where-Object Control -eq 'EXO-012').Count | Should -Be 0
        }
    }

    Context 'Negative: every mutated EXO member must be observed at its resolved desired state' {
        It 'refuses accepted-domain drift' {
            # Arrange
            $operation = New-CompletePostChangeOperation
            $operation[0].Read = { [pscustomobject]@{ DomainType = 'InternalRelay' } }

            # Act
            $decision = Test-BaselineExoPostChange -Operation $operation -Evidence 'postchange-exo.json'

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" |
                Should -BeLike 'False|*AcceptedDomain*DomainType*InternalRelay*Authoritative*'
        }

        It 'refuses mailbox protocol drift' {
            # Arrange
            $operation = New-CompletePostChangeOperation
            $operation[1].Read = { [pscustomobject]@{ PopEnabled = $true; ImapEnabled = $false } }

            # Act
            $decision = Test-BaselineExoPostChange -Operation $operation -Evidence 'postchange-exo.json'

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" |
                Should -BeLike 'False|*MailboxProtocol*PopEnabled*True*False*'
        }

        It 'refuses mailbox forwarding drift' {
            # Arrange
            $operation = New-CompletePostChangeOperation
            $operation[2].Read = { [pscustomobject]@{ ForwardingAddress = $null; ForwardingSmtpAddress = 'outside@external.example' } }

            # Act
            $decision = Test-BaselineExoPostChange -Operation $operation -Evidence 'postchange-exo.json'

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" |
                Should -BeLike 'False|*MailboxForwarding*ForwardingSmtpAddress*outside@external.example*'
        }

        It 'refuses inbox-rule forwarding or redirect drift' {
            # Arrange
            $operation = New-CompletePostChangeOperation
            $operation[3].Read = {
                [pscustomobject]@{ ForwardTo = @(); ForwardAsAttachmentTo = @(); RedirectTo = @('outside@external.example') }
            }

            # Act
            $decision = Test-BaselineExoPostChange -Operation $operation -Evidence 'postchange-exo.json'

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" |
                Should -BeLike 'False|*InboxRule*RedirectTo*outside@external.example*'
        }

        It 'refuses add-in acquisition drift' {
            # Arrange
            $operation = New-CompletePostChangeOperation
            $operation[4].Read = { [pscustomobject]@{ Roles = @('My Marketplace Apps') } }

            # Act
            $decision = Test-BaselineExoPostChange -Operation $operation -Evidence 'postchange-exo.json'

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" |
                Should -BeLike 'False|*AddInAcquisition*Roles*My Marketplace Apps*'
        }

        It 'refuses any mutated EXO object that cannot be observed' {
            # Arrange
            $operation = New-CompletePostChangeOperation
            $operation[2].Read = { $null }

            # Act
            $decision = Test-BaselineExoPostChange -Operation $operation -Evidence 'postchange-exo.json'

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" |
                Should -BeLike 'False|*PostChangeObjectNotObserved*MailboxForwarding*alex@contoso.example*'
        }

            It 'refuses a known EXO mutation whose plan carries no resolved desired state' {
                # Arrange
                $operation = New-CompletePostChangeOperation
                $operation[1].Remove('Area')
                $operation[1].Remove('Desired')

                # Act
                $decision = Test-BaselineExoPostChange -Operation $operation -Evidence 'postchange-exo.json'

                # Assert
                "$($decision.Permitted)|$(@($decision.Finding) -join ';')" |
                Should -BeLike 'False|*PostChangeDesiredStateNotDeclared*MailboxProtocol*exo-mailbox-protocol-set*'
            }

        It 'wires add-in enforcement into organization controls and the real EXO decision into change success' {
            # Arrange
            $tokens = $null
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                $script:DeploymentScriptPath, [ref]$tokens, [ref]$errors)

            # Act
            $scriptText = $ast.Extent.Text

            # Assert
            $errors.Count | Should -Be 0
            $scriptText | Should -Match 'Set-BaselineAddInAcquisitionState\s+-Configuration\s+\$Configuration'
            $scriptText | Should -Match '\$postChangeDecision\s*=\s*Test-BaselineExoPostChange\s+-Operation\s+\$appliedOperation'
            $scriptText | Should -Match 'Test-BaselineChangeSuccess\s+-Application\s+\$changeApplication\s+-PostChange\s+\$postChangeDecision'
        }
    }

    Context 'Positive: one complete post-change fixture confirms every mutated EXO member' {
        It 'admits the exact resolved domain, protocol, forwarding, rule and add-in state' {
            # Arrange
            $operation = New-CompletePostChangeOperation

            # Act
            $decision = Test-BaselineExoPostChange -Operation $operation -Evidence 'postchange-exo-015.json'

            # Assert
            "$($decision.Permitted)|$($decision.Evidence)|$(@($decision.Observed).Count)|$(@($decision.Finding).Count)" |
                Should -BeExactly 'True|postchange-exo-015.json|5|0'
        }
    }
}