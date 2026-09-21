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
            if ($definition.Count -eq 1) { $definition[0].Extent.Text }
            else { "function $functionName { [CmdletBinding(SupportsShouldProcess)] param() }" }
        }
    }

    $stubText = @'
function Get-QuarantinePolicy { param($Identity, $ErrorAction) }
function New-QuarantinePolicy { param($Name, $EndUserQuarantinePermissionsValue, $WhatIf) }
function Set-QuarantinePolicy { param($Identity, $EndUserQuarantinePermissionsValue, $EndUserSpamNotificationFrequency, $IncludeMessagesFromBlockedSenderAddress, $WhatIf) }
function Get-HostedContentFilterPolicy { param($Identity, $ErrorAction) }
function Set-HostedContentFilterPolicy { param($Identity, $HighConfidencePhishQuarantineTag, $PhishQuarantineTag, $HighConfidenceSpamQuarantineTag, $SpamQuarantineTag, $BulkQuarantineTag, $SpoofQuarantineTag, $WhatIf) }
function Get-MalwareFilterPolicy { param($Identity, $ErrorAction) }
function Set-MalwareFilterPolicy { param($Identity, $QuarantineTag, $WhatIf) }
'@
    $functionText = Get-DeploymentFunctionText -Name @(
        'Add-Outcome',
        'Set-BaselineQuarantineState',
        'Test-BaselineMdoPostChange'
    )
    $harnessText = @"
`$script:Outcomes = [System.Collections.Generic.List[object]]::new()
`$script:MutationStatus = [ordered]@{}
$stubText
$($functionText -join [Environment]::NewLine)
function Reset-MdoEnforcementHarness {
    `$script:Outcomes.Clear()
    `$script:MutationStatus = [ordered]@{}
}
function Get-MdoEnforcementOutcome { return @(`$script:Outcomes) }
Export-ModuleMember -Function *
"@
    $script:Harness = New-Module -Name 'MdoQuarantinePostChangeEnforcementHarness' -ScriptBlock ([scriptblock]::Create($harnessText))
    Import-Module $script:Harness -Force -DisableNameChecking

    function New-QuarantineConfiguration {
        [pscustomobject]@{
            desiredState = [pscustomobject]@{
                defenderForOffice365 = [pscustomobject]@{
                    quarantinePolicies = [pscustomobject]@{
                        endUserSpamNotificationFrequencyInDays = 1
                        includeMessagesFromBlockedSenderAddress = $false
                        categoryPermissions = @(
                            [pscustomobject]@{ category = 'Malware'; accessLevel = 'AdminOnlyAccess' }
                            [pscustomobject]@{ category = 'HighConfidencePhish'; accessLevel = 'AdminOnlyAccess' }
                            [pscustomobject]@{ category = 'Phish'; accessLevel = 'LimitedAccess' }
                            [pscustomobject]@{ category = 'HighConfidenceSpam'; accessLevel = 'LimitedAccess' }
                            [pscustomobject]@{ category = 'Spam'; accessLevel = 'LimitedAccess' }
                            [pscustomobject]@{ category = 'Bulk'; accessLevel = 'LimitedAccess' }
                            [pscustomobject]@{ category = 'SpoofIntelligence'; accessLevel = 'LimitedAccess' }
                        )
                    }
                }
            }
        }
    }

    function New-QuarantinePolicyState {
        param(
            [string]$Name,
            [int]$Permission = 0,
            [timespan]$Cadence = ([timespan]::FromDays(1)),
            [bool]$BlockedSender = $false
        )
        [pscustomobject]@{
            Name = $Name
            EndUserQuarantinePermissionsValue = $Permission
            EndUserSpamNotificationFrequency = $Cadence
            IncludeMessagesFromBlockedSenderAddress = $BlockedSender
        }
    }

    function New-MdoRegistry {
        @(
            [pscustomobject]@{ ControlId = 'MDO-006'; Collector = 'Get-ReportSubmissionEvidence'; Evaluator = 'Test-ReportSubmissionControl' }
            [pscustomobject]@{ ControlId = 'MDO-007'; Collector = 'Get-TenantAllowBlockListEvidence'; Evaluator = 'Test-TenantAllowBlockListControl' }
            [pscustomobject]@{ ControlId = 'MDO-008'; Collector = 'Get-QuarantinePolicyEvidence'; Evaluator = 'Test-QuarantinePolicyControl' }
            [pscustomobject]@{ ControlId = 'MDO-009'; Collector = 'Get-PriorityAccountEvidence'; Evaluator = 'Test-PriorityAccountControl' }
        )
    }

    function New-MdoEvidence {
        param(
            [datetimeoffset]$CollectedAtUtc = [datetimeoffset]'2026-09-19T11:55:00Z',
            [string[]]$ControlId = @('MDO-006', 'MDO-007', 'MDO-008', 'MDO-009')
        )
        @($ControlId | ForEach-Object {
            [pscustomobject]@{ ControlId = $_; Collected = $true; CollectedAtUtc = $CollectedAtUtc; Value = [pscustomobject]@{ Complete = $true } }
        })
    }

    function New-MdoOperation {
        param(
            [string]$OperationId = 'mdo-quarantine-policy-set',
            [string]$Area = 'Quarantine',
            [hashtable]$Desired = @{ EndUserSpamNotificationFrequency = [timespan]::FromDays(1) },
            [object]$Observed = ([pscustomobject]@{ EndUserSpamNotificationFrequency = [timespan]::FromDays(1) })
        )
        $read = { $Observed }.GetNewClosure()
        [ordered]@{ OperationId = $OperationId; Area = $Area; Identity = 'MDO object'; Desired = $Desired; Read = $read }
    }

    function Invoke-MdoPostChange {
        param(
            [object[]]$Operation = @((New-MdoOperation)),
            [object[]]$Registry = @(New-MdoRegistry),
            [object[]]$EvidenceByControl = @(New-MdoEvidence),
            [scriptblock]$Evaluation = { param($Entry, $Evidence) [pscustomobject]@{ ControlId = $Entry.ControlId; Status = 'Pass'; Reason = '' } }
        )
        Test-BaselineMdoPostChange -Operation $Operation -Registry $Registry -EvidenceByControl $EvidenceByControl `
            -Evaluation $Evaluation -AsOfUtc ([datetimeoffset]'2026-09-19T12:00:00Z') `
            -MaximumEvidenceAge ([timespan]::FromMinutes(30)) -Evidence 'postchange-mdo.json'
    }
}

AfterAll {
    Remove-Module MdoQuarantinePostChangeEnforcementHarness -Force -ErrorAction SilentlyContinue
}

Describe 'MDO-010 quarantine enforcement' {
    BeforeEach {
        Reset-MdoEnforcementHarness
        Mock Write-Host {} -ModuleName MdoQuarantinePostChangeEnforcementHarness
        Mock Get-QuarantinePolicy {
            @(
                (New-QuarantinePolicyState -Name 'DefaultGlobalTag'),
                (New-QuarantinePolicyState -Name 'Baseline-AdminOnlyAccess' -Permission 0),
                (New-QuarantinePolicyState -Name 'Baseline-LimitedAccess' -Permission 106)
            )
        } -ModuleName MdoQuarantinePostChangeEnforcementHarness
        Mock New-QuarantinePolicy {} -ModuleName MdoQuarantinePostChangeEnforcementHarness
        Mock Set-QuarantinePolicy {} -ModuleName MdoQuarantinePostChangeEnforcementHarness
        Mock Get-HostedContentFilterPolicy {
            @([pscustomobject]@{
                    Identity = 'Default'; HighConfidencePhishQuarantineTag = 'Baseline-AdminOnlyAccess'
                    PhishQuarantineTag = 'Baseline-LimitedAccess'; HighConfidenceSpamQuarantineTag = 'Baseline-LimitedAccess'
                    SpamQuarantineTag = 'Baseline-LimitedAccess'; BulkQuarantineTag = 'Baseline-LimitedAccess'
                    SpoofQuarantineTag = 'Baseline-LimitedAccess'
                })
        } -ModuleName MdoQuarantinePostChangeEnforcementHarness
        Mock Set-HostedContentFilterPolicy {} -ModuleName MdoQuarantinePostChangeEnforcementHarness
        Mock Get-MalwareFilterPolicy {
            @([pscustomobject]@{ Identity = 'Default'; QuarantineTag = 'Baseline-AdminOnlyAccess' })
        } -ModuleName MdoQuarantinePostChangeEnforcementHarness
        Mock Set-MalwareFilterPolicy {} -ModuleName MdoQuarantinePostChangeEnforcementHarness
    }

    Context 'Negative: a failed quarantine mutation is never reported applied' {
        It 'propagates a custom policy creation failure' {
            # Arrange
            Mock Get-QuarantinePolicy { @((New-QuarantinePolicyState -Name 'DefaultGlobalTag')) } -ModuleName MdoQuarantinePostChangeEnforcementHarness
            Mock New-QuarantinePolicy { throw 'create refused' } -ModuleName MdoQuarantinePostChangeEnforcementHarness

            # Act
            $act = { Set-BaselineQuarantineState -Configuration (New-QuarantineConfiguration) -UseWhatIf $false }

            # Assert
            $act | Should -Throw '*create refused*'
            @(Get-MdoEnforcementOutcome | Where-Object Control -eq 'MDO-008').Count | Should -Be 0
        }

        It 'propagates a global cadence or blocked-sender update failure' {
            # Arrange
            Mock Get-QuarantinePolicy {
                @(
                    (New-QuarantinePolicyState -Name 'DefaultGlobalTag' -Cadence ([timespan]::FromDays(2)) -BlockedSender $true),
                    (New-QuarantinePolicyState -Name 'Baseline-AdminOnlyAccess' -Permission 0),
                    (New-QuarantinePolicyState -Name 'Baseline-LimitedAccess' -Permission 106)
                )
            } -ModuleName MdoQuarantinePostChangeEnforcementHarness
            Mock Set-QuarantinePolicy { throw 'update refused' } -ModuleName MdoQuarantinePostChangeEnforcementHarness

            # Act
            $act = { Set-BaselineQuarantineState -Configuration (New-QuarantineConfiguration) -UseWhatIf $false }

            # Assert
            $act | Should -Throw '*update refused*'
            @(Get-MdoEnforcementOutcome | Where-Object Control -eq 'MDO-008').Count | Should -Be 0
        }

        It 'propagates a category tag update failure' {
            # Arrange
            Mock Get-HostedContentFilterPolicy {
                @([pscustomobject]@{
                        Identity = 'Default'; HighConfidencePhishQuarantineTag = 'wrong'
                        PhishQuarantineTag = 'wrong'; HighConfidenceSpamQuarantineTag = 'wrong'
                        SpamQuarantineTag = 'wrong'; BulkQuarantineTag = 'wrong'; SpoofQuarantineTag = 'wrong'
                    })
            } -ModuleName MdoQuarantinePostChangeEnforcementHarness
            Mock Set-HostedContentFilterPolicy { throw 'filter update refused' } -ModuleName MdoQuarantinePostChangeEnforcementHarness

            # Act
            $act = { Set-BaselineQuarantineState -Configuration (New-QuarantineConfiguration) -UseWhatIf $false }

            # Assert
            $act | Should -Throw '*filter update refused*'
            @(Get-MdoEnforcementOutcome | Where-Object Control -eq 'MDO-008').Count | Should -Be 0
        }
    }

    Context 'Positive: one exact enforcement unit covers create, update and no-op branches' {
        It 'creates missing access policies, corrects every category mapping, and leaves exact state untouched' {
            # Arrange
            Mock Get-QuarantinePolicy {
                @(
                    (New-QuarantinePolicyState -Name 'DefaultGlobalTag' -Cadence ([timespan]::FromDays(2)) -BlockedSender $true),
                    (New-QuarantinePolicyState -Name 'Baseline-AdminOnlyAccess' -Permission 236)
                )
            } -ModuleName MdoQuarantinePostChangeEnforcementHarness
            Mock Get-HostedContentFilterPolicy {
                @([pscustomobject]@{
                        Identity = 'Default'; HighConfidencePhishQuarantineTag = 'wrong'
                        PhishQuarantineTag = 'wrong'; HighConfidenceSpamQuarantineTag = 'wrong'
                        SpamQuarantineTag = 'wrong'; BulkQuarantineTag = 'wrong'; SpoofQuarantineTag = 'wrong'
                    })
            } -ModuleName MdoQuarantinePostChangeEnforcementHarness
            Mock Get-MalwareFilterPolicy { @([pscustomobject]@{ Identity = 'Default'; QuarantineTag = 'wrong' }) } -ModuleName MdoQuarantinePostChangeEnforcementHarness

            # Act
            Set-BaselineQuarantineState -Configuration (New-QuarantineConfiguration) -UseWhatIf $false

            # Assert
            Should -Invoke New-QuarantinePolicy -ModuleName MdoQuarantinePostChangeEnforcementHarness -Times 1 -ParameterFilter {
                $Name -eq 'Baseline-LimitedAccess' -and $EndUserQuarantinePermissionsValue -eq 106 -and $WhatIf -eq $false
            }
            Should -Invoke Set-QuarantinePolicy -ModuleName MdoQuarantinePostChangeEnforcementHarness -Times 2
            Should -Invoke Set-HostedContentFilterPolicy -ModuleName MdoQuarantinePostChangeEnforcementHarness -Times 1 -ParameterFilter {
                $HighConfidencePhishQuarantineTag -eq 'Baseline-AdminOnlyAccess' -and
                    $PhishQuarantineTag -eq 'Baseline-LimitedAccess' -and
                    $HighConfidenceSpamQuarantineTag -eq 'Baseline-LimitedAccess' -and
                    $SpamQuarantineTag -eq 'Baseline-LimitedAccess' -and
                    $BulkQuarantineTag -eq 'Baseline-LimitedAccess' -and
                    $SpoofQuarantineTag -eq 'Baseline-LimitedAccess'
            }
            Should -Invoke Set-MalwareFilterPolicy -ModuleName MdoQuarantinePostChangeEnforcementHarness -Times 1 -ParameterFilter {
                $QuarantineTag -eq 'Baseline-AdminOnlyAccess'
            }
            @(Get-MdoEnforcementOutcome | Where-Object Control -eq 'MDO-008').Count | Should -Be 1
        }
    }

    Context 'Positive: one exact idempotency unit performs no mutation' {
        It 'is a no-op when cadence, blocked sender, permissions, and all category tags already match' {
            # Arrange
            $configuration = New-QuarantineConfiguration

            # Act
            Set-BaselineQuarantineState -Configuration $configuration -UseWhatIf $false

            # Assert
            Should -Invoke New-QuarantinePolicy -ModuleName MdoQuarantinePostChangeEnforcementHarness -Times 0
            Should -Invoke Set-QuarantinePolicy -ModuleName MdoQuarantinePostChangeEnforcementHarness -Times 0
            Should -Invoke Set-HostedContentFilterPolicy -ModuleName MdoQuarantinePostChangeEnforcementHarness -Times 0
            Should -Invoke Set-MalwareFilterPolicy -ModuleName MdoQuarantinePostChangeEnforcementHarness -Times 0
        }
    }
}

Describe 'MDO-010 exact post-change integration' {
    Context 'Negative: the registered MDO result set must be complete, unique, evaluated, and current' {
        It 'refuses deploy wiring that does not collect every registered MDO control once before change success' {
            # Arrange
            $scriptText = Get-Content -LiteralPath $script:DeploymentScriptPath -Raw
            $collector = @(
                'Get-ReportSubmissionEvidence',
                'Get-TenantAllowBlockListEvidence',
                'Get-QuarantinePolicyEvidence',
                'Get-PriorityAccountEvidence'
            )

            # Act
            $collectorCount = @($collector | ForEach-Object { ([regex]::Matches($scriptText, "\b$($_)\b")).Count })

            # Assert
            $collectorCount | Should -Be @(1, 1, 1, 1)
            $scriptText | Should -Match '\$mdoPostChangeDecision\s*=\s*Test-BaselineMdoPostChange'
            $scriptText | Should -Match '\$postChangeDecision\s*=\s*\[ordered\]@\{(?s).*?Permitted\s*=\s*\(\$exoPostChangeDecision\.Permitted\s+-and\s+\$mdoPostChangeDecision\.Permitted\)'
            $scriptText | Should -Match 'Test-BaselineChangeSuccess\s+-Application\s+\$changeApplication\s+-PostChange\s+\$postChangeDecision'
        }

        It 'refuses missing or partial MDO evidence' {
            # Arrange
            $evidence = New-MdoEvidence -ControlId @('MDO-006', 'MDO-007', 'MDO-008')

            # Act
            $decision = Invoke-MdoPostChange -EvidenceByControl $evidence

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" | Should -BeLike 'False|*MDO-009*missing*'
        }

        It 'refuses duplicated MDO evidence' {
            # Arrange
            $evidence = @((New-MdoEvidence) + (New-MdoEvidence -ControlId @('MDO-008')))

            # Act
            $decision = Invoke-MdoPostChange -EvidenceByControl $evidence

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" | Should -BeLike 'False|*MDO-008*duplicate*'
        }

        It 'refuses an unknown MDO evidence identity' {
            # Arrange
            $evidence = @((New-MdoEvidence), (New-MdoEvidence -ControlId @('MDO-999')))

            # Act
            $decision = Invoke-MdoPostChange -EvidenceByControl $evidence

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" | Should -BeLike 'False|*MDO-999*unknown*'
        }

        It 'refuses stale evidence before invoking its evaluator' {
            # Arrange
            $evidence = New-MdoEvidence -CollectedAtUtc ([datetimeoffset]'2026-09-19T10:00:00Z')
            $script:evaluationCount = 0
            $evaluation = { param($Entry, $Evidence) $script:evaluationCount++; [pscustomobject]@{ ControlId = $Entry.ControlId; Status = 'Pass' } }

            # Act
            $decision = Invoke-MdoPostChange -EvidenceByControl $evidence -Evaluation $evaluation

            # Assert
            "$($decision.Permitted)|$script:evaluationCount|$(@($decision.Finding) -join ';')" | Should -BeLike 'False|0|*stale*'
        }

        It 'refuses a Manual result from a registered evaluator' {
            # Arrange
            $evaluation = { param($Entry, $Evidence) [pscustomobject]@{ ControlId = $Entry.ControlId; Status = $(if ($Entry.ControlId -eq 'MDO-007') { 'Manual' } else { 'Pass' }); Reason = 'operator review' } }

            # Act
            $decision = Invoke-MdoPostChange -Evaluation $evaluation

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" | Should -BeLike 'False|*MDO-007*Manual*'
        }

        It 'refuses an inline, mismatched result identity' {
            # Arrange
            $evaluation = { param($Entry, $Evidence) [pscustomobject]@{ ControlId = 'MDO-999'; Status = 'Pass'; Reason = '' } }

            # Act
            $decision = Invoke-MdoPostChange -Evaluation $evaluation

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" | Should -BeLike 'False|*MDO-999*inline*MDO-006*'
        }
    }

    Context 'Negative: every mutated MDO member must be compared with resolved desired state' {
        It 'refuses a duplicated mutation' {
            # Arrange
            $operation = @((New-MdoOperation), (New-MdoOperation))

            # Act
            $decision = Invoke-MdoPostChange -Operation $operation

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" | Should -BeLike 'False|*mdo-quarantine-policy-set*duplicate*'
        }

        It 'refuses an unknown MDO mutation area' {
            # Arrange
            $operation = @((New-MdoOperation -OperationId 'mdo-invented' -Area 'Invented'))

            # Act
            $decision = Invoke-MdoPostChange -Operation $operation

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" | Should -BeLike 'False|*mdo-invented*unknown*Invented*'
        }

        It 'refuses a known MDO mutation carrying no resolved desired members' {
            # Arrange
            $operation = @((New-MdoOperation -Desired @{}))

            # Act
            $decision = Invoke-MdoPostChange -Operation $operation

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" | Should -BeLike 'False|*mdo-quarantine-policy-set*desired*'
        }

        It 'refuses a mutated object that cannot be read back' {
            # Arrange
            $operation = @((New-MdoOperation -Observed $null))

            # Act
            $decision = Invoke-MdoPostChange -Operation $operation

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" | Should -BeLike 'False|*mdo-quarantine-policy-set*not observed*'
        }

        It 'refuses a partial observation missing a mutated member' {
            # Arrange
            $operation = @((New-MdoOperation -Desired @{ EndUserSpamNotificationFrequency = [timespan]::FromDays(1); IncludeMessagesFromBlockedSenderAddress = $false } `
                        -Observed ([pscustomobject]@{ EndUserSpamNotificationFrequency = [timespan]::FromDays(1) })))

            # Act
            $decision = Invoke-MdoPostChange -Operation $operation

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" | Should -BeLike 'False|*IncludeMessagesFromBlockedSenderAddress*missing*'
        }

        It 'refuses drift in any mutated member' {
            # Arrange
            $operation = @((New-MdoOperation -Observed ([pscustomobject]@{ EndUserSpamNotificationFrequency = [timespan]::FromDays(2) })))

            # Act
            $decision = Invoke-MdoPostChange -Operation $operation

            # Assert
            "$($decision.Permitted)|$(@($decision.Finding) -join ';')" | Should -BeLike 'False|*EndUserSpamNotificationFrequency*2.00:00:00*1.00:00:00*'
        }
    }

    Context 'Positive: one complete MDO result and mutation set admits change success' {
        It 'invokes each registered evaluator exactly once and compares every mutated member' {
            # Arrange
            $script:evaluated = [System.Collections.Generic.List[string]]::new()
            $evaluation = {
                param($Entry, $Evidence)
                $script:evaluated.Add($Entry.Evaluator)
                [pscustomobject]@{ ControlId = $Entry.ControlId; Status = 'Pass'; Reason = '' }
            }
            $operation = @(
                (New-MdoOperation -OperationId 'mdo-report-submission-set' -Area 'ReportSubmission' -Desired @{ ReportingMailbox = 'secops@contoso.example' } -Observed ([pscustomobject]@{ ReportingMailbox = 'secops@contoso.example' })),
                (New-MdoOperation -OperationId 'mdo-tabl-set' -Area 'TenantAllowBlockList' -Desired @{ Entries = @('Sender:blocked.example') } -Observed ([pscustomobject]@{ Entries = @('Sender:blocked.example') })),
                (New-MdoOperation),
                (New-MdoOperation -OperationId 'mdo-anti-phish-set' -Area 'ImpersonationProtection' -Desired @{ ProtectedDomains = @('contoso.example') } -Observed ([pscustomobject]@{ ProtectedDomains = @('contoso.example') }))
            )

            # Act
            $decision = Invoke-MdoPostChange -Operation $operation -Evaluation $evaluation

            # Assert
            "$($decision.Permitted)|$(@($script:evaluated | Sort-Object) -join ',')|$(@($decision.Observed).Count)|$(@($decision.Finding).Count)" |
                Should -BeExactly 'True|Test-PriorityAccountControl,Test-QuarantinePolicyControl,Test-ReportSubmissionControl,Test-TenantAllowBlockListControl|4|0'
        }
    }
}