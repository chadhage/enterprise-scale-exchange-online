#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-MailboxRecord {
        param([string]$Identity)

        return [pscustomobject]@{ PrimarySmtpAddress = $Identity }
    }

    function New-InboxRuleResponse {
        param(
            [string]$Status = 'Success',
            [object[]]$Rule = @(),
            [bool]$Complete = $true,
            [object]$RetryAfterSecond,
            [string]$Reason
        )

        $response = [ordered]@{ Status = $Status; Complete = $Complete; Rules = @($Rule) }
        if ($PSBoundParameters.ContainsKey('RetryAfterSecond')) { $response.RetryAfterSecond = $RetryAfterSecond }
        if ($PSBoundParameters.ContainsKey('Reason')) { $response.Reason = $Reason }
        return [pscustomobject]$response
    }

    function New-SequenceCollection {
        param(
            [object[]]$Response,
            [System.Collections.Generic.List[string]]$AttemptLog
        )

        $sequence = @($Response)
        $log = $AttemptLog
        return {
            param($Mailbox, $TimeoutSecond)

            $identity = if ($Mailbox.Identity) { $Mailbox.Identity } else { $Mailbox.PrimarySmtpAddress }
            $log.Add("$identity|$TimeoutSecond")
            $index = [Math]::Min($log.Count - 1, $sequence.Count - 1)
            return $sequence[$index]
        }.GetNewClosure()
    }

    function New-RecordingWait {
        param([System.Collections.Generic.List[object]]$WaitLog)

        $log = $WaitLog
        return { param($Second) $log.Add($Second) }.GetNewClosure()
    }

    function New-SequenceClock {
        param([object[]]$Second)

        $sequence = [System.Collections.Generic.Queue[object]]::new()
        foreach ($entry in @($Second)) { $sequence.Enqueue($entry) }
        return {
            if ($sequence.Count -gt 1) { return $sequence.Dequeue() }
            return $sequence.Peek()
        }.GetNewClosure()
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXO-013 bounded per-mailbox inbox-rule collection' {
    BeforeEach {
        $script:Mailbox = @(New-MailboxRecord -Identity 'alice@contoso.example')
        $script:AttemptLog = [System.Collections.Generic.List[string]]::new()
        $script:WaitLog = [System.Collections.Generic.List[object]]::new()
        $script:Wait = New-RecordingWait -WaitLog $script:WaitLog
        $script:Clock = New-SequenceClock -Second @(0, 0)
        $script:Success = New-InboxRuleResponse
        $script:Collection = New-SequenceCollection -Response @($script:Success) -AttemptLog $script:AttemptLog
    }

    Context 'Negative: all offline seams and bounds are required' {
        It 'refuses an absent complete mailbox set' {
            # Arrange
            $mailboxes = $null

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $mailboxes -Collection $script:Collection -Wait $script:Wait -Clock $script:Clock }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MailboxCollectionRequired*'
        }

        It 'refuses an absent inbox-rule collection seam' {
            # Arrange
            $collection = $null

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $collection -Wait $script:Wait -Clock $script:Clock }

            # Assert
            $act | Should -Throw -ExpectedMessage 'InboxRuleCollectionRequired*'
        }

        It 'refuses an absent retry wait seam' {
            # Arrange
            $wait = $null

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $script:Collection -Wait $wait -Clock $script:Clock }

            # Assert
            $act | Should -Throw -ExpectedMessage 'RetryWaitRequired*'
        }

        It 'refuses an absent attempt clock seam' {
            # Arrange
            $clock = $null

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $script:Collection -Wait $script:Wait -Clock $clock }

            # Assert
            $act | Should -Throw -ExpectedMessage 'AttemptClockRequired*'
        }

        It 'refuses a non-positive attempt timeout' -ForEach @(0, -1) {
            # Arrange
            $timeout = $_

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $script:Collection -Wait $script:Wait -Clock $script:Clock -AttemptTimeoutSecond $timeout }

            # Assert
            $act | Should -Throw -ExpectedMessage 'AttemptTimeoutOutOfRange*'
        }

        It 'refuses a retry bound below one' -ForEach @(0, -1) {
            # Arrange
            $maximumAttempt = $_

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $script:Collection -Wait $script:Wait -Clock $script:Clock -MaximumAttempt $maximumAttempt }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MaximumAttemptOutOfRange*'
        }

        It 'refuses a non-positive maximum wait' -ForEach @(0, -1) {
            # Arrange
            $maximumWait = $_

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $script:Collection -Wait $script:Wait -Clock $script:Clock -MaximumWaitSecond $maximumWait }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MaximumWaitOutOfRange*'
        }
    }

    Context 'Negative: every mailbox answer must be authoritative and complete' {
        It 'refuses a mailbox with no stable identity' {
            # Arrange
            $mailboxes = @([pscustomobject]@{ DisplayName = 'Alice' })

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $mailboxes -Collection $script:Collection -Wait $script:Wait -Clock $script:Clock }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MailboxIdentityRequired*'
        }

        It 'retains the mailbox and reason when access is refused' {
            # Arrange
            $collection = New-SequenceCollection -Response @(
                (New-InboxRuleResponse -Status 'Inaccessible' -Reason 'caller lacks Inbox Rules role')
            ) -AttemptLog $script:AttemptLog

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $collection -Wait $script:Wait -Clock $script:Clock }

            # Assert
            $act | Should -Throw -ExpectedMessage "MailboxInboxRuleInaccessible*alice@contoso.example*caller lacks Inbox Rules role*"
        }

        It 'retains the mailbox and reason when identity resolution is ambiguous' {
            # Arrange
            $collection = New-SequenceCollection -Response @(
                (New-InboxRuleResponse -Status 'Ambiguous' -Reason 'two recipients matched')
            ) -AttemptLog $script:AttemptLog

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $collection -Wait $script:Wait -Clock $script:Clock }

            # Assert
            $act | Should -Throw -ExpectedMessage "MailboxInboxRuleAmbiguous*alice@contoso.example*two recipients matched*"
        }

        It 'refuses a partial answer without returning earlier mailbox rules' {
            # Arrange
            $mailboxes = @(New-MailboxRecord 'alice@contoso.example'; New-MailboxRecord 'bob@contoso.example')
            $collection = New-SequenceCollection -Response @(
                (New-InboxRuleResponse -Rule @([pscustomobject]@{ Identity = 'alice-rule'; Enabled = $true; ForwardTo = @(); ForwardAsAttachmentTo = @(); RedirectTo = @() })),
                (New-InboxRuleResponse -Complete $false -Reason 'server truncated the result')
            ) -AttemptLog $script:AttemptLog

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $mailboxes -Collection $collection -Wait $script:Wait -Clock (New-SequenceClock @(0, 0, 0, 0)) }

            # Assert
            $act | Should -Throw -ExpectedMessage "MailboxInboxRulePartial*bob@contoso.example*server truncated the result*"
        }

        It 'refuses a null answer' {
            # Arrange
            $collection = New-SequenceCollection -Response @($null) -AttemptLog $script:AttemptLog

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $collection -Wait $script:Wait -Clock $script:Clock }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MailboxInboxRuleResponseMissing*alice@contoso.example*'
        }

        It 'refuses an answer status outside the contract' {
            # Arrange
            $collection = New-SequenceCollection -Response @((New-InboxRuleResponse -Status 'Maybe')) -AttemptLog $script:AttemptLog

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $collection -Wait $script:Wait -Clock $script:Clock }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MailboxInboxRuleStatusUnsupported*alice@contoso.example*Maybe*'
        }
    }

    Context 'Negative: timeout and throttling are bounded per mailbox' {
        It 'fails the named mailbox when an attempt exceeds its timeout' {
            # Arrange
            $clock = New-SequenceClock -Second @(10, 16)

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $script:Collection -Wait $script:Wait -Clock $clock -AttemptTimeoutSecond 5 }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MailboxInboxRuleTimedOut*alice@contoso.example*5 seconds*'
        }

        It 'fails a timeout status even when the injected clock returns promptly' {
            # Arrange
            $collection = New-SequenceCollection -Response @((New-InboxRuleResponse -Status 'TimedOut' -Reason 'remote operation expired')) -AttemptLog $script:AttemptLog

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $collection -Wait $script:Wait -Clock $script:Clock -AttemptTimeoutSecond 5 }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MailboxInboxRuleTimedOut*alice@contoso.example*remote operation expired*'
        }

        It 'does not retry past the declared attempt bound' {
            # Arrange
            $collection = New-SequenceCollection -Response @((New-InboxRuleResponse -Status 'Throttled' -RetryAfterSecond 1 -Reason 'busy')) -AttemptLog $script:AttemptLog

            # Act
            try { $null = Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $collection -Wait $script:Wait -Clock (New-SequenceClock @(0, 0, 0, 0, 0, 0)) -MaximumAttempt 3 } catch { }

            # Assert
            $script:AttemptLog.Count | Should -Be 3
        }

        It 'reports retry exhaustion with the mailbox and last reason' {
            # Arrange
            $collection = New-SequenceCollection -Response @((New-InboxRuleResponse -Status 'Throttled' -RetryAfterSecond 1 -Reason 'service busy')) -AttemptLog $script:AttemptLog

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $collection -Wait $script:Wait -Clock (New-SequenceClock @(0, 0, 0, 0)) -MaximumAttempt 2 }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MailboxInboxRuleRetryExhausted*alice@contoso.example*service busy*'
        }

        It 'caps a service-requested wait at the declared maximum' {
            # Arrange
            $collection = New-SequenceCollection -Response @(
                (New-InboxRuleResponse -Status 'Throttled' -RetryAfterSecond 86400),
                $script:Success
            ) -AttemptLog $script:AttemptLog

            # Act
            $null = Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $collection -Wait $script:Wait -Clock (New-SequenceClock @(0, 0, 0, 0)) -MaximumWaitSecond 7

            # Assert
            @($script:WaitLog) | Should -Be @(7)
        }

        It 'uses a positive bounded wait when Retry-After is invalid' {
            # Arrange
            $collection = New-SequenceCollection -Response @(
                (New-InboxRuleResponse -Status 'Throttled' -RetryAfterSecond -4),
                $script:Success
            ) -AttemptLog $script:AttemptLog

            # Act
            $null = Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $collection -Wait $script:Wait -Clock (New-SequenceClock @(0, 0, 0, 0))

            # Assert
            @($script:WaitLog) | Should -Be @(1)
        }
    }

    Context 'Negative: rule identities and action payloads must be decidable' {
        It 'refuses duplicate rule identities within one mailbox' {
            # Arrange
            $rule = [pscustomobject]@{ Identity = 'copy-out'; Enabled = $true; ForwardTo = @(); ForwardAsAttachmentTo = @(); RedirectTo = @() }
            $collection = New-SequenceCollection -Response @((New-InboxRuleResponse -Rule @($rule, $rule))) -AttemptLog $script:AttemptLog

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $collection -Wait $script:Wait -Clock $script:Clock }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MailboxInboxRuleDuplicated*alice@contoso.example*copy-out*'
        }

        It 'refuses a rule without an identity' {
            # Arrange
            $rule = [pscustomobject]@{ Enabled = $true; ForwardTo = @(); ForwardAsAttachmentTo = @(); RedirectTo = @() }
            $collection = New-SequenceCollection -Response @((New-InboxRuleResponse -Rule @($rule))) -AttemptLog $script:AttemptLog

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $collection -Wait $script:Wait -Clock $script:Clock }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MailboxInboxRuleIdentityRequired*alice@contoso.example*'
        }

        It 'refuses an enabled rule that carries an unsupported outbound action' {
            # Arrange
            $rule = [pscustomobject]@{ Identity = 'text-out'; Enabled = $true; ForwardTo = @(); ForwardAsAttachmentTo = @(); RedirectTo = @(); SendTextMessageNotificationTo = @('+15550100') }
            $collection = New-SequenceCollection -Response @((New-InboxRuleResponse -Rule @($rule))) -AttemptLog $script:AttemptLog

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $collection -Wait $script:Wait -Clock $script:Clock }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MailboxInboxRuleActionUnsupported*alice@contoso.example*SendTextMessageNotificationTo*'
        }

        It 'refuses an accepted action whose payload is scalar rather than a collection' -ForEach @('ForwardTo', 'ForwardAsAttachmentTo', 'RedirectTo') {
            # Arrange
            $rule = [ordered]@{ Identity = 'bad-payload'; Enabled = $true; ForwardTo = @(); ForwardAsAttachmentTo = @(); RedirectTo = @() }
            $rule[$_] = 'outside@fabrikam.example'
            $collection = New-SequenceCollection -Response @((New-InboxRuleResponse -Rule @([pscustomobject]$rule))) -AttemptLog $script:AttemptLog

            # Act
            $act = { Get-BaselineMailboxInboxRuleCollection -Mailbox $script:Mailbox -Collection $collection -Wait $script:Wait -Clock $script:Clock }

            # Assert
            $act | Should -Throw -ExpectedMessage "MailboxInboxRuleActionMalformed*alice@contoso.example*$_*"
        }
    }

    Context 'Positive: one complete mixed-mailbox pass retains raw forwarding actions' {
        It 'returns every rule in mailbox order after one attempt per mailbox without reshaping accepted action values' {
            # Arrange
            $mailboxes = @(New-MailboxRecord 'alice@contoso.example'; New-MailboxRecord 'bob@contoso.example')
            $forwardTo = [pscustomobject]@{ Address = 'forward@fabrikam.example'; DisplayName = 'Forward recipient' }
            $forwardAsAttachmentTo = [pscustomobject]@{ Address = 'attachment@fabrikam.example'; DisplayName = 'Attachment recipient' }
            $redirectTo = [pscustomobject]@{ Address = 'redirect@fabrikam.example'; DisplayName = 'Redirect recipient' }
            $aliceRule = [pscustomobject]@{
                Identity = 'alice-forward'; Enabled = $true; ForwardTo = @($forwardTo)
                ForwardAsAttachmentTo = @(); RedirectTo = @()
            }
            $bobRule = [pscustomobject]@{
                Identity = 'bob-mixed'; Enabled = $true; ForwardTo = @()
                ForwardAsAttachmentTo = @($forwardAsAttachmentTo); RedirectTo = @($redirectTo)
            }
            $disabledRule = [pscustomobject]@{
                Identity = 'bob-disabled'; Enabled = $false; ForwardTo = @()
                ForwardAsAttachmentTo = @(); RedirectTo = @(); SendTextMessageNotificationTo = @('+15550100')
            }
            $collection = New-SequenceCollection -Response @(
                (New-InboxRuleResponse -Rule @($aliceRule)),
                (New-InboxRuleResponse -Rule @($bobRule, $disabledRule))
            ) -AttemptLog $script:AttemptLog

            # Act
            $result = @(Get-BaselineMailboxInboxRuleCollection -Mailbox $mailboxes -Collection $collection -Wait $script:Wait -Clock (New-SequenceClock @(0, 0, 0, 0)))

            # Assert
            $summary = @(
                'Rules=' + (@($result.Identity) -join ',')
                'Attempts=' + (@($script:AttemptLog) -join ',')
                'Waits=' + $script:WaitLog.Count
                'ForwardToRaw=' + [object]::ReferenceEquals($result[0].ForwardTo[0], $forwardTo)
                'ForwardAsAttachmentToRaw=' + [object]::ReferenceEquals($result[1].ForwardAsAttachmentTo[0], $forwardAsAttachmentTo)
                'RedirectToRaw=' + [object]::ReferenceEquals($result[1].RedirectTo[0], $redirectTo)
            ) -join '; '
            $summary | Should -BeExactly (@(
                'Rules=alice-forward,bob-mixed,bob-disabled'
                'Attempts=alice@contoso.example|30,bob@contoso.example|30'
                'Waits=0'
                'ForwardToRaw=True'
                'ForwardAsAttachmentToRaw=True'
                'RedirectToRaw=True'
            ) -join '; ')
        }
    }
}