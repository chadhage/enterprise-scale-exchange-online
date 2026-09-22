#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:EvidenceScriptPath = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:AcceptedDomain = @('contoso.com')
    $script:CompleteMailbox = @(
        [pscustomobject]@{
            Identity              = 'first@contoso.com'
            PrimarySmtpAddress    = 'first@contoso.com'
            ForwardingAddress     = $null
            ForwardingSmtpAddress = $null
        },
        [pscustomobject]@{
            Identity              = 'second@contoso.com'
            PrimarySmtpAddress    = 'second@contoso.com'
            ForwardingAddress     = $null
            ForwardingSmtpAddress = $null
        }
    )

    function New-HardenedOutboundForwardingEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [scriptblock]$RuleCollection
        )

        return Get-OutboundForwardingEvidence `
            -OutboundSpamPolicyCollection {
                [pscustomobject]@{ Name = 'Default'; AutoForwardingMode = 'Off' }
            } `
            -MailboxCollection { $script:CompleteMailbox } `
            -InboxRuleCollection $RuleCollection
    }

}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXO-013 hardened inbox-rule integration' {
    Context 'Negative: every bounded inbox-rule collection failure fails EXO-004 closed' {
        It 'returns Error for <FailureKind> without losing the named collection reason' -ForEach @(
            @{ FailureKind = 'paging'; Reason = 'MailboxPagingFailed: continuation token page-2 was refused.' }
            @{ FailureKind = 'timeout'; Reason = 'InboxRuleTimeout: second@contoso.com exceeded 00:00:05.' }
            @{ FailureKind = 'throttling'; Reason = 'InboxRuleThrottleExhausted: second@contoso.com exhausted 3 attempts.' }
            @{ FailureKind = 'inaccessible mailbox'; Reason = 'InboxRuleMailboxInaccessible: second@contoso.com denied access.' }
            @{ FailureKind = 'unsupported action'; Reason = 'InboxRuleUnsupportedAction: second@contoso.com rule unsupported-action carries DeleteMessage.' }
        ) {
            # Arrange
            $script:mailboxCollectionCount = 0
            $script:ruleCollectionCount = 0
            $failureReason = $Reason
            $ruleCollection = {
                param([object[]]$Mailbox)
                $script:ruleCollectionCount++
                $identity = @($Mailbox | ForEach-Object { [string]$_.Identity })
                if (($identity -join ';') -cne 'first@contoso.com;second@contoso.com') {
                    throw "CompleteMailboxSetNotPassed: observed '$($identity -join ';')'."
                }
                throw $failureReason
            }.GetNewClosure()
            $mailboxCollection = {
                $script:mailboxCollectionCount++
                $script:CompleteMailbox
            }

            # Act
            $evidence = Get-OutboundForwardingEvidence `
                -OutboundSpamPolicyCollection { [pscustomobject]@{ Name = 'Default'; AutoForwardingMode = 'Off' } } `
                -MailboxCollection $mailboxCollection `
                -InboxRuleCollection $ruleCollection
            $result = Test-OutboundForwardingControl -Evidence $evidence -AcceptedDomain $script:AcceptedDomain

            # Assert
            $result.Status | Should -BeExactly 'Error' -Because "$FailureKind leaves EXO-004 without a complete tenant observation"
            $result.Reason | Should -BeLike "*$failureReason*" -Because 'the operator needs the original bounded-collection refusal rather than a pass or an unrelated integration fault'
            $script:mailboxCollectionCount | Should -Be 1 -Because 'the tenant mailbox set must be completed in one pass'
        }
    }

    Context 'Negative: every accepted forwarding action remains visible to EXO-004' {
        It 'fails on an enabled external <Action> action after bounded collection' -ForEach @(
            @{ Action = 'ForwardTo'; Wording = 'forwards to' }
            @{ Action = 'ForwardAsAttachmentTo'; Wording = 'forwards as attachment to' }
            @{ Action = 'RedirectTo'; Wording = 'redirects to' }
        ) {
            # Arrange
            $actionName = $Action
            $externalRecipient = [pscustomobject]@{ Address = 'outside@fabrikam.example'; DisplayName = 'External recipient' }
            $ruleCollection = {
                param([object[]]$Mailbox)
                $identity = @($Mailbox | ForEach-Object { [string]$_.Identity })
                if (($identity -join ';') -cne 'first@contoso.com;second@contoso.com') {
                    throw "CompleteMailboxSetNotPassed: observed '$($identity -join ';')'."
                }
                $rule = [ordered]@{
                    Identity              = 'second@contoso.com\external-copy'
                    Enabled               = $true
                    ForwardTo             = @()
                    ForwardAsAttachmentTo = @()
                    RedirectTo            = @()
                }
                $rule[$actionName] = @($externalRecipient)
                [pscustomobject]$rule
            }.GetNewClosure()

            # Act
            $evidence = New-HardenedOutboundForwardingEvidence -RuleCollection $ruleCollection
            $result = Test-OutboundForwardingControl -Evidence $evidence -AcceptedDomain $script:AcceptedDomain

            # Assert
            $result.Status | Should -BeExactly 'Fail' -Because "$Action is one of the three forwarding actions the bounded collector admits"
            $result.Reason | Should -BeLike "*$Wording 'outside@fabrikam.example'*" -Because 'the existing evaluator must receive the accepted action without reshaping or filtering it'
        }
    }

    Context 'Negative: the shipped EXO-004 call site cannot bypass either hardened helper' {
        It 'routes complete paging into bounded rule collection and evaluates the resulting evidence' {
            # Arrange
            $scriptText = Get-Content -LiteralPath $script:EvidenceScriptPath -Raw

            # Act
            $helperUse = @(
                ([regex]::Matches($scriptText, '\bGet-BaselineCompleteMailboxCollection\b')).Count
                ([regex]::Matches($scriptText, '\bGet-BaselineMailboxInboxRuleCollection\b')).Count
                ([regex]::Matches($scriptText, '\bGet-OutboundForwardingEvidence\b')).Count
                ([regex]::Matches($scriptText, '\bTest-OutboundForwardingControl\b')).Count
                ([regex]::Matches($scriptText, "Add-Result 'EXO-004 automaticForwardingOff'")).Count
            )

            # Assert
            $helperUse | Should -Be @(1, 1, 1, 1, 0) -Because 'the public command must decide EXO-004 from one hardened collection path rather than the outbound policy alone'
        }
    }

    Context 'Positive: one complete tenant pass covers the hardened integration' {
        It 'passes the completed mailbox set once into bounded collection and preserves every accepted internal action' {
            # Arrange
            $script:mailboxCollectionCount = 0
            $script:ruleCollectionCount = 0
            $manager = [pscustomobject]@{ Address = 'manager@contoso.com'; DisplayName = 'Manager' }
            $archive = [pscustomobject]@{ Address = 'archive@contoso.com'; DisplayName = 'Archive' }
            $workflow = [pscustomobject]@{ Address = 'workflow@contoso.com'; DisplayName = 'Workflow' }
            $mailboxCollection = {
                $script:mailboxCollectionCount++
                $script:CompleteMailbox
            }
            $ruleCollection = {
                param([object[]]$Mailbox)
                $script:ruleCollectionCount++
                $identity = @($Mailbox | ForEach-Object { [string]$_.Identity })
                if (($identity -join ';') -cne 'first@contoso.com;second@contoso.com') {
                    throw "CompleteMailboxSetNotPassed: observed '$($identity -join ';')'."
                }

                [pscustomobject]@{
                    Identity              = 'first@contoso.com\internal-copies'
                    Enabled               = $true
                    ForwardTo             = @($manager)
                    ForwardAsAttachmentTo = @($archive)
                    RedirectTo            = @($workflow)
                }
                [pscustomobject]@{
                    Identity              = 'second@contoso.com\retired-external-copy'
                    Enabled               = $false
                    ForwardTo             = @()
                    ForwardAsAttachmentTo = @()
                    RedirectTo            = @('outside@fabrikam.example')
                }
            }

            # Act
            $evidence = Get-OutboundForwardingEvidence `
                -OutboundSpamPolicyCollection { [pscustomobject]@{ Name = 'Default'; AutoForwardingMode = 'Off' } } `
                -MailboxCollection $mailboxCollection `
                -InboxRuleCollection $ruleCollection
            $result = Test-OutboundForwardingControl -Evidence $evidence -AcceptedDomain $script:AcceptedDomain

            # Assert
            ('{0}|{1}|mailbox={2}|rules={3}' -f $result.ControlId, $result.Status, $script:mailboxCollectionCount, $script:ruleCollectionCount) |
                Should -BeExactly 'EXO-004|Pass|mailbox=1|rules=1' -Because 'one complete tenant observation with only internal enabled actions is the unit''s sole successful fixture'
        }
    }
}