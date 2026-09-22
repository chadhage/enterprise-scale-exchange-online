#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:DeploymentScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'

    $tokens = $null
    $parseErrors = $null
    $script:DeploymentAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:DeploymentScriptPath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join [Environment]::NewLine) }

    function Get-DeploymentFunctionText {
        param([Parameter(Mandatory)][string]$Name)

        $definition = @($script:DeploymentAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                        $node.Name -in @($Name, "script:$Name")
                }, $true))
        if ($definition.Count -eq 0) { return '' }
        if ($definition.Count -ne 1) { throw "Expected one '$Name' definition, found $($definition.Count)." }
        return $definition[0].Extent.Text
    }

    function Get-DeploymentCommandCount {
        param([Parameter(Mandatory)][string]$FunctionName, [Parameter(Mandatory)][string]$CommandName)

        $function = @($script:DeploymentAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                        $node.Name -in @($FunctionName, "script:$FunctionName")
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
                    $_.Extent.Text -match "OperationId\s*=\s*'mdo-(report-submission|secops-override|tabl)-"
                })
    }

    $ownedFunction = @(
        'Set-BaselineReportSubmissionState'
        'Set-BaselineSecOpsOverrideState'
        'Set-BaselineTenantAllowBlockListState'
    )
    $functionText = @($ownedFunction | ForEach-Object { Get-DeploymentFunctionText -Name $_ }) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    $missingText = @($ownedFunction | Where-Object { [string]::IsNullOrWhiteSpace((Get-DeploymentFunctionText -Name $_)) } |
        ForEach-Object { "function $_ { throw 'MDO010NotImplemented: $_' }" })

    $stubText = @'
function Get-ReportSubmissionPolicy { param($Identity, $ErrorAction) }
function New-ReportSubmissionPolicy { param($Name, $EnableThirdPartyAddress, $EnableReportToMicrosoft, $ReportJunkToCustomizedAddress, $ReportNotJunkToCustomizedAddress, $ReportPhishToCustomizedAddress, $ReportJunkAddresses, $WhatIf) }
function Set-ReportSubmissionPolicy { param($Identity, $EnableThirdPartyAddress, $EnableReportToMicrosoft, $ReportJunkToCustomizedAddress, $ReportNotJunkToCustomizedAddress, $ReportPhishToCustomizedAddress, $ReportJunkAddresses, $WhatIf) }
function Get-SecOpsOverridePolicy { param($Identity, $ErrorAction) }
function New-SecOpsOverridePolicy { param($Name, $SentTo, $Mode, $WhatIf) }
function Set-SecOpsOverridePolicy { param($Identity, $SentTo, $Mode, $WhatIf) }
function Get-TenantAllowBlockListItems { param($ListType, $ErrorAction) }
function New-TenantAllowBlockListItems { param($ListType, $Entries, $Allow, $Block, $ExpirationDate, $Notes, $WhatIf) }
function Remove-TenantAllowBlockListItems { param($Identity, $ListType, $Confirm, $WhatIf) }
'@
    $harnessText = @"
`$script:Outcomes = [System.Collections.Generic.List[object]]::new()
`$script:MutationStatus = [ordered]@{}
$stubText
function Add-Outcome {
    param([string]`$Control, [string]`$Status, [string]`$Detail, [string[]]`$Operation = @())
    `$script:Outcomes.Add([pscustomobject]@{ Control = `$Control; Status = `$Status; Detail = `$Detail; Operation = @(`$Operation) })
    foreach (`$operationId in `$Operation) { `$script:MutationStatus[`$operationId] = `$Status }
}
$($missingText -join [Environment]::NewLine)
$($functionText -join [Environment]::NewLine)
function Reset-MdoAdvancedDeliveryTablHarness {
    `$script:Outcomes.Clear()
    `$script:MutationStatus = [ordered]@{}
}
function Get-MdoAdvancedDeliveryTablOutcome { return @(`$script:Outcomes) }
Export-ModuleMember -Function *
"@
    $script:Harness = New-Module -Name 'MdoAdvancedDeliveryTablHarness' -ScriptBlock ([scriptblock]::Create($harnessText))
    Import-Module $script:Harness -Force -DisableNameChecking

    function New-MdoEnforcementConfiguration {
        [pscustomobject]@{
            desiredState = [pscustomobject]@{
                defenderForOffice365 = [pscustomobject]@{
                    userSubmissions = [pscustomobject]@{
                        microsoftReportMessageButton = $true
                        sendReportedMessagesToMicrosoft = $true
                        sendCopyToSecOpsMailbox = $true
                        reportingDestination = 'MicrosoftAndCustomMailbox'
                        reportingMailbox = 'soc@contoso.example'
                    }
                    advancedDelivery = [pscustomobject]@{
                        secOpsMailbox = @('soc@contoso.example', 'phishtest@contoso.example')
                    }
                    tenantAllowBlockList = [pscustomobject]@{
                        allowEntryMaximumDurationDays = 30
                        blockEntryRetentionDays = 90
                        requiredEntryFields = @(
                            'entryType', 'entryValue', 'owner', 'ticket', 'createdDateTime',
                            'expirationDateTime', 'justification'
                        )
                    }
                }
            }
        }
    }

    function New-GovernedTablEntry {
        param(
            [string]$Identity = 'tabl-1',
            [string]$EntryType = 'Sender',
            [string]$EntryValue = 'newsletter@partner.example',
            [string]$Action = 'Allow',
            [string]$Owner = 'Messaging Security',
            [string]$Ticket = 'CHG0012345',
            [datetimeoffset]$CreatedDateTime = [datetimeoffset]'2026-09-01T12:00:00Z',
            [datetimeoffset]$ExpirationDateTime = [datetimeoffset]'2026-10-01T12:00:00Z',
            [string]$Justification = 'Temporary partner authentication repair.'
        )

        [pscustomobject]@{
            Identity = $Identity
            entryType = $EntryType
            entryValue = $EntryValue
            action = $Action
            owner = $Owner
            ticket = $Ticket
            createdDateTime = $CreatedDateTime
            expirationDateTime = $ExpirationDateTime
            justification = $Justification
        }
    }
}

AfterAll {
    Remove-Module MdoAdvancedDeliveryTablHarness -Force -ErrorAction SilentlyContinue
}

Describe 'MDO-010 report-submission, Advanced Delivery and TABL enforcement' {
    BeforeEach {
        Reset-MdoAdvancedDeliveryTablHarness
        Mock Get-ReportSubmissionPolicy { $null } -ModuleName MdoAdvancedDeliveryTablHarness
        Mock New-ReportSubmissionPolicy {} -ModuleName MdoAdvancedDeliveryTablHarness
        Mock Set-ReportSubmissionPolicy {} -ModuleName MdoAdvancedDeliveryTablHarness
        Mock Get-SecOpsOverridePolicy { $null } -ModuleName MdoAdvancedDeliveryTablHarness
        Mock New-SecOpsOverridePolicy {} -ModuleName MdoAdvancedDeliveryTablHarness
        Mock Set-SecOpsOverridePolicy {} -ModuleName MdoAdvancedDeliveryTablHarness
        Mock Get-TenantAllowBlockListItems { @() } -ModuleName MdoAdvancedDeliveryTablHarness
        Mock New-TenantAllowBlockListItems {} -ModuleName MdoAdvancedDeliveryTablHarness
        Mock Remove-TenantAllowBlockListItems {} -ModuleName MdoAdvancedDeliveryTablHarness
    }

    Context 'Negative: report destination and reporting mailbox require exact create, update and no-op behavior' {
        It 'creates the missing default report-submission policy with the exact resolved destination and mailbox' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration

            # Act
            Set-BaselineReportSubmissionState -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke New-ReportSubmissionPolicy -ModuleName MdoAdvancedDeliveryTablHarness -Times 1 -Exactly -ParameterFilter {
                $Name -ceq 'DefaultReportSubmissionPolicy' -and
                $EnableThirdPartyAddress -eq $false -and $EnableReportToMicrosoft -eq $true -and
                $ReportJunkToCustomizedAddress -eq $true -and $ReportNotJunkToCustomizedAddress -eq $true -and
                $ReportPhishToCustomizedAddress -eq $true -and
                @($ReportJunkAddresses).Count -eq 1 -and @($ReportJunkAddresses)[0] -ceq 'soc@contoso.example' -and
                $WhatIf -eq $false
            }
            Should -Invoke Set-ReportSubmissionPolicy -ModuleName MdoAdvancedDeliveryTablHarness -Times 0 -Exactly
        }

        It 'updates every drifted report destination and mailbox member exactly' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            Mock Get-ReportSubmissionPolicy {
                [pscustomobject]@{
                    Identity = 'DefaultReportSubmissionPolicy'; EnableThirdPartyAddress = $true
                    EnableReportToMicrosoft = $false; ReportJunkToCustomizedAddress = $false
                    ReportNotJunkToCustomizedAddress = $false; ReportPhishToCustomizedAddress = $false
                    ReportJunkAddresses = @('helpdesk@contoso.example')
                }
            } -ModuleName MdoAdvancedDeliveryTablHarness

            # Act
            Set-BaselineReportSubmissionState -Configuration $configuration -UseWhatIf $true -Confirm:$false

            # Assert
            Should -Invoke Set-ReportSubmissionPolicy -ModuleName MdoAdvancedDeliveryTablHarness -Times 1 -Exactly -ParameterFilter {
                $Identity -ceq 'DefaultReportSubmissionPolicy' -and
                $EnableThirdPartyAddress -eq $false -and $EnableReportToMicrosoft -eq $true -and
                $ReportJunkToCustomizedAddress -eq $true -and $ReportNotJunkToCustomizedAddress -eq $true -and
                $ReportPhishToCustomizedAddress -eq $true -and
                @($ReportJunkAddresses).Count -eq 1 -and @($ReportJunkAddresses)[0] -ceq 'soc@contoso.example' -and
                $WhatIf -eq $true
            }
        }

        It 'does not mutate an exact report-submission policy' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            Mock Get-ReportSubmissionPolicy {
                [pscustomobject]@{
                    Identity = 'DefaultReportSubmissionPolicy'; EnableThirdPartyAddress = $false
                    EnableReportToMicrosoft = $true; ReportJunkToCustomizedAddress = $true
                    ReportNotJunkToCustomizedAddress = $true; ReportPhishToCustomizedAddress = $true
                    ReportJunkAddresses = @('soc@contoso.example')
                }
            } -ModuleName MdoAdvancedDeliveryTablHarness

            # Act
            Set-BaselineReportSubmissionState -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke New-ReportSubmissionPolicy -ModuleName MdoAdvancedDeliveryTablHarness -Times 0 -Exactly
            Should -Invoke Set-ReportSubmissionPolicy -ModuleName MdoAdvancedDeliveryTablHarness -Times 0 -Exactly
        }

        It 'propagates report-policy discovery failure without reporting success' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            Mock Get-ReportSubmissionPolicy { throw 'report discovery refused' } -ModuleName MdoAdvancedDeliveryTablHarness

            # Act
            $act = { Set-BaselineReportSubmissionState -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw '*report discovery refused*'
            @(Get-MdoAdvancedDeliveryTablOutcome).Count | Should -Be 0
        }

        It 'propagates report-policy mutation failure without reporting success' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            Mock New-ReportSubmissionPolicy { throw 'report create refused' } -ModuleName MdoAdvancedDeliveryTablHarness

            # Act
            $act = { Set-BaselineReportSubmissionState -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw '*report create refused*'
            @(Get-MdoAdvancedDeliveryTablOutcome).Count | Should -Be 0
        }

        It 'does not mutate a missing report policy when ShouldProcess declines' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration

            # Act
            Set-BaselineReportSubmissionState -Configuration $configuration -UseWhatIf $false -WhatIf

            # Assert
            Should -Invoke New-ReportSubmissionPolicy -ModuleName MdoAdvancedDeliveryTablHarness -Times 0 -Exactly
        }
    }

    Context 'Negative: administrator-controlled SecOps registration requires exact create, update and no-op behavior' {
        It 'creates the missing Advanced Delivery SecOps registration in enforce mode' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration

            # Act
            Set-BaselineSecOpsOverrideState -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke New-SecOpsOverridePolicy -ModuleName MdoAdvancedDeliveryTablHarness -Times 1 -Exactly -ParameterFilter {
                $Name -ceq 'SecOpsOverridePolicy' -and $Mode -ceq 'Enforce' -and
                (@($SentTo) -join ',') -ceq 'soc@contoso.example,phishtest@contoso.example' -and $WhatIf -eq $false
            }
        }

        It 'updates a drifted SecOps registration to the exact administrator-resolved mailbox set' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            Mock Get-SecOpsOverridePolicy {
                [pscustomobject]@{ Identity = 'SecOpsOverridePolicy'; SentTo = @('everyone@contoso.example'); Mode = 'Audit' }
            } -ModuleName MdoAdvancedDeliveryTablHarness

            # Act
            Set-BaselineSecOpsOverrideState -Configuration $configuration -UseWhatIf $true -Confirm:$false

            # Assert
            Should -Invoke Set-SecOpsOverridePolicy -ModuleName MdoAdvancedDeliveryTablHarness -Times 1 -Exactly -ParameterFilter {
                $Identity -ceq 'SecOpsOverridePolicy' -and $Mode -ceq 'Enforce' -and
                (@($SentTo) -join ',') -ceq 'soc@contoso.example,phishtest@contoso.example' -and $WhatIf -eq $true
            }
        }

        It 'does not mutate an exact SecOps registration' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            Mock Get-SecOpsOverridePolicy {
                [pscustomobject]@{
                    Identity = 'SecOpsOverridePolicy'; SentTo = @('PHISHTEST@contoso.example', 'soc@contoso.example'); Mode = 'Enforce'
                }
            } -ModuleName MdoAdvancedDeliveryTablHarness

            # Act
            Set-BaselineSecOpsOverrideState -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke New-SecOpsOverridePolicy -ModuleName MdoAdvancedDeliveryTablHarness -Times 0 -Exactly
            Should -Invoke Set-SecOpsOverridePolicy -ModuleName MdoAdvancedDeliveryTablHarness -Times 0 -Exactly
        }

        It 'propagates SecOps registration mutation failure without reporting success' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            Mock New-SecOpsOverridePolicy { throw 'SecOps registration refused' } -ModuleName MdoAdvancedDeliveryTablHarness

            # Act
            $act = { Set-BaselineSecOpsOverrideState -Configuration $configuration -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw '*SecOps registration refused*'
            @(Get-MdoAdvancedDeliveryTablOutcome).Count | Should -Be 0
        }

        It 'does not create a SecOps registration when ShouldProcess declines' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration

            # Act
            Set-BaselineSecOpsOverrideState -Configuration $configuration -UseWhatIf $false -WhatIf

            # Assert
            Should -Invoke New-SecOpsOverridePolicy -ModuleName MdoAdvancedDeliveryTablHarness -Times 0 -Exactly
        }
    }

    Context 'Negative: TABL entries require exact typed scope, governance and action-specific windows' {
        It 'creates a missing governed allow with the declared type, exact value and allow duration' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            $desired = @(New-GovernedTablEntry)

            # Act
            Set-BaselineTenantAllowBlockListState -Configuration $configuration -DesiredEntry $desired -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke New-TenantAllowBlockListItems -ModuleName MdoAdvancedDeliveryTablHarness -Times 1 -Exactly -ParameterFilter {
                $ListType -ceq 'Sender' -and @($Entries).Count -eq 1 -and $Entries[0] -ceq 'newsletter@partner.example' -and
                $Allow -eq $true -and -not $Block -and
                ([datetimeoffset]$ExpirationDate).ToString('o') -ceq '2026-10-01T12:00:00.0000000+00:00' -and
                $Notes -like '*Messaging Security*CHG0012345*Temporary partner authentication repair*' -and $WhatIf -eq $false
            }
        }

        It 'replaces a drifted TABL entry rather than widening or retaining stale metadata' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            $desired = @(New-GovernedTablEntry)
            Mock Get-TenantAllowBlockListItems {
                @(New-GovernedTablEntry -Owner 'Unknown owner' -ExpirationDateTime ([datetimeoffset]'2026-10-10T12:00:00Z'))
            } -ModuleName MdoAdvancedDeliveryTablHarness

            # Act
            Set-BaselineTenantAllowBlockListState -Configuration $configuration -DesiredEntry $desired -UseWhatIf $true -Confirm:$false

            # Assert
            Should -Invoke Remove-TenantAllowBlockListItems -ModuleName MdoAdvancedDeliveryTablHarness -Times 1 -Exactly -ParameterFilter {
                $Identity -ceq 'tabl-1' -and $ListType -ceq 'Sender' -and $Confirm -eq $false -and $WhatIf -eq $true
            }
            Should -Invoke New-TenantAllowBlockListItems -ModuleName MdoAdvancedDeliveryTablHarness -Times 1 -Exactly -ParameterFilter {
                $ListType -ceq 'Sender' -and $Allow -eq $true -and $WhatIf -eq $true
            }
        }

        It 'does not mutate an exact governed TABL entry' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            $desired = @(New-GovernedTablEntry)
            Mock Get-TenantAllowBlockListItems { $desired } -ModuleName MdoAdvancedDeliveryTablHarness

            # Act
            Set-BaselineTenantAllowBlockListState -Configuration $configuration -DesiredEntry $desired -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke Remove-TenantAllowBlockListItems -ModuleName MdoAdvancedDeliveryTablHarness -Times 0 -Exactly
            Should -Invoke New-TenantAllowBlockListItems -ModuleName MdoAdvancedDeliveryTablHarness -Times 0 -Exactly
        }

        It 'refuses an unknown entry type before any mutation' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            $desired = @(New-GovernedTablEntry -EntryType 'IpAddress')

            # Act
            $act = { Set-BaselineTenantAllowBlockListState -Configuration $configuration -DesiredEntry $desired -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw 'TenantAllowBlockListEntryTypeNotSupported*'
            Should -Invoke New-TenantAllowBlockListItems -ModuleName MdoAdvancedDeliveryTablHarness -Times 0 -Exactly
        }

        It 'refuses an allow whose duration exceeds the declared allow maximum before any mutation' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            $desired = @(New-GovernedTablEntry -ExpirationDateTime ([datetimeoffset]'2026-10-02T12:00:00Z'))

            # Act
            $act = { Set-BaselineTenantAllowBlockListState -Configuration $configuration -DesiredEntry $desired -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw 'TenantAllowBlockListAllowDurationInvalid*'
            Should -Invoke New-TenantAllowBlockListItems -ModuleName MdoAdvancedDeliveryTablHarness -Times 0 -Exactly
        }

        It 'refuses a block whose retention differs from the separately declared block retention' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            $desired = @(New-GovernedTablEntry -EntryType 'Domain' -EntryValue 'malicious.example' -Action 'Block' `
                    -CreatedDateTime ([datetimeoffset]'2026-07-01T12:00:00Z') -ExpirationDateTime ([datetimeoffset]'2026-09-30T12:00:00Z'))

            # Act
            $act = { Set-BaselineTenantAllowBlockListState -Configuration $configuration -DesiredEntry $desired -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw 'TenantAllowBlockListBlockRetentionInvalid*'
            Should -Invoke New-TenantAllowBlockListItems -ModuleName MdoAdvancedDeliveryTablHarness -Times 0 -Exactly
        }

        It 'propagates TABL replacement failure without reporting success' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            $desired = @(New-GovernedTablEntry)
            Mock Get-TenantAllowBlockListItems { @(New-GovernedTablEntry -Owner 'Unknown owner') } -ModuleName MdoAdvancedDeliveryTablHarness
            Mock Remove-TenantAllowBlockListItems { throw 'TABL removal refused' } -ModuleName MdoAdvancedDeliveryTablHarness

            # Act
            $act = { Set-BaselineTenantAllowBlockListState -Configuration $configuration -DesiredEntry $desired -UseWhatIf $false -Confirm:$false }

            # Assert
            $act | Should -Throw '*TABL removal refused*'
            @(Get-MdoAdvancedDeliveryTablOutcome).Count | Should -Be 0
        }

        It 'does not create or replace TABL entries when ShouldProcess declines' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            $desired = @(New-GovernedTablEntry)

            # Act
            Set-BaselineTenantAllowBlockListState -Configuration $configuration -DesiredEntry $desired -UseWhatIf $false -WhatIf

            # Assert
            Should -Invoke New-TenantAllowBlockListItems -ModuleName MdoAdvancedDeliveryTablHarness -Times 0 -Exactly
            Should -Invoke Remove-TenantAllowBlockListItems -ModuleName MdoAdvancedDeliveryTablHarness -Times 0 -Exactly
        }
    }

    Context 'Negative: owned enforcement must be called, captured and journalled' {
        It 'calls each owned helper exactly once from organization controls' {
            # Arrange
            $expected = @(
                'Set-BaselineReportSubmissionState'
                'Set-BaselineSecOpsOverrideState'
                'Set-BaselineTenantAllowBlockListState'
            )

            # Act
            $counts = @($expected | ForEach-Object { Get-DeploymentCommandCount -FunctionName 'Set-OrganizationControls' -CommandName $_ })

            # Assert
            $counts | Should -Be @(1, 1, 1)
        }

        It 'declares every owned create, update and replacement command in the mutation plan' {
            # Arrange
            $expected = @(
                'mdo-report-submission-create|New-ReportSubmissionPolicy'
                'mdo-report-submission-set|Set-ReportSubmissionPolicy'
                'mdo-secops-override-create|New-SecOpsOverridePolicy'
                'mdo-secops-override-set|Set-SecOpsOverridePolicy'
                'mdo-tabl-create|New-TenantAllowBlockListItems'
                'mdo-tabl-remove|Remove-TenantAllowBlockListItems'
            )

            # Act
            $actual = @(Get-OwnedMutationPlanEntry | ForEach-Object {
                    $operation = [regex]::Match($_.Extent.Text, "OperationId\s*=\s*'([^']+)'").Groups[1].Value
                    $command = [regex]::Match($_.Extent.Text, "Command\s*=\s*'([^']+)'").Groups[1].Value
                    "$operation|$command"
                })

            # Assert
            $actual | Should -Be $expected -Because 'each mutation needs a pre-change read, journal identity and rollback source'
        }

        It 'records owned operation identifiers only after their guarded mutations run' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration

            # Act
            Set-BaselineReportSubmissionState -Configuration $configuration -UseWhatIf $false -Confirm:$false
            Set-BaselineSecOpsOverrideState -Configuration $configuration -UseWhatIf $false -Confirm:$false
            Set-BaselineTenantAllowBlockListState -Configuration $configuration `
                -DesiredEntry @(New-GovernedTablEntry) -UseWhatIf $false -Confirm:$false
            $operation = @((Get-MdoAdvancedDeliveryTablOutcome).Operation)

            # Assert
            $operation | Should -Contain 'mdo-report-submission-create'
            $operation | Should -Contain 'mdo-secops-override-create'
            $operation | Should -Contain 'mdo-tabl-create'
        }
    }

    Context 'Positive: one exact report-submission policy is enforced from resolved state' {
        It 'leaves the declared reporting destination and mailbox with one successful outcome' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration

            # Act
            Set-BaselineReportSubmissionState -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke New-ReportSubmissionPolicy -ModuleName MdoAdvancedDeliveryTablHarness -Times 1 -Exactly
            $outcome = @(Get-MdoAdvancedDeliveryTablOutcome)
            "$($outcome.Control)|$($outcome.Status)|$($outcome.Operation -join ',')" |
                Should -BeExactly 'MDO-006|Applied|mdo-report-submission-create'
        }
    }

    Context 'Positive: one exact Advanced Delivery SecOps registration is enforced from resolved state' {
        It 'registers only the administrator-resolved SecOps mailboxes with one successful outcome' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration

            # Act
            Set-BaselineSecOpsOverrideState -Configuration $configuration -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke New-SecOpsOverridePolicy -ModuleName MdoAdvancedDeliveryTablHarness -Times 1 -Exactly
            $outcome = @(Get-MdoAdvancedDeliveryTablOutcome)
            "$($outcome.Control)|$($outcome.Status)|$($outcome.Operation -join ',')" |
                Should -BeExactly 'MDO-006|Applied|mdo-secops-override-create'
        }
    }

    Context 'Positive: one exact typed and governed TABL set is enforced with separate action windows' {
        It 'creates sender, domain, URL and file entries with their declared allow duration or block retention' {
            # Arrange
            $configuration = New-MdoEnforcementConfiguration
            $desired = @(
                New-GovernedTablEntry -Identity 'sender-allow' -EntryType 'Sender' `
                    -EntryValue 'newsletter@partner.example' -Action 'Allow'
                New-GovernedTablEntry -Identity 'url-allow' -EntryType 'Url' `
                    -EntryValue 'https://partner.example/campaign' -Action 'Allow'
                New-GovernedTablEntry -Identity 'domain-block' -EntryType 'Domain' `
                    -EntryValue 'malicious.example' -Action 'Block' `
                    -CreatedDateTime ([datetimeoffset]'2026-07-01T12:00:00Z') `
                    -ExpirationDateTime ([datetimeoffset]'2026-09-29T12:00:00Z')
                New-GovernedTablEntry -Identity 'file-block' -EntryType 'File' `
                    -EntryValue '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' `
                    -Action 'Block' -CreatedDateTime ([datetimeoffset]'2026-07-01T12:00:00Z') `
                    -ExpirationDateTime ([datetimeoffset]'2026-09-29T12:00:00Z')
            )

            # Act
            Set-BaselineTenantAllowBlockListState -Configuration $configuration -DesiredEntry $desired `
                -UseWhatIf $false -Confirm:$false

            # Assert
            Should -Invoke New-TenantAllowBlockListItems -ModuleName MdoAdvancedDeliveryTablHarness -Times 4 -Exactly
            Should -Invoke New-TenantAllowBlockListItems -ModuleName MdoAdvancedDeliveryTablHarness -Times 2 -Exactly `
                -ParameterFilter { $Allow -eq $true -and -not $Block }
            Should -Invoke New-TenantAllowBlockListItems -ModuleName MdoAdvancedDeliveryTablHarness -Times 2 -Exactly `
                -ParameterFilter { $Block -eq $true -and -not $Allow }
            $outcome = @(Get-MdoAdvancedDeliveryTablOutcome)
            "$($outcome.Control)|$($outcome.Status)|$($outcome.Operation -join ',')" |
                Should -BeExactly 'MDO-007|Applied|mdo-tabl-create'
        }
    }
}
