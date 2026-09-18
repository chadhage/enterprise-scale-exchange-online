#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement is not installed and must never be imported. Every Exchange Online
    # command EXO-004 depends on is reached only through a supplied collection seam, so each
    # collection here is a scriptblock returning a canned payload or throwing a canned failure.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # The registry is returned as one read-only collection deliberately protected from pipeline
    # unrolling, so the entry is read by index rather than by piping the collection.
    $script:ControlRegistry = @(Get-BaselineControlRegistry)[0]
    $script:OutboundForwardingRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'EXO-004') { $entry }
        })[0]

    function New-OutboundSpamPolicyRecord {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Name,

            [Parameter(Mandatory)]
            [string]$AutoForwardingMode
        )

        return [pscustomobject]@{
            Name               = $Name
            AutoForwardingMode = $AutoForwardingMode
        }
    }

    function New-ForwardingMailboxRecord {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$PrimarySmtpAddress,

            # A typed [string] would convert an unset member to an empty string, which is a
            # different observation from a mailbox that carries no forwarding member at all.
            [object]$ForwardingAddress = $null,

            [object]$ForwardingSmtpAddress = $null
        )

        return [pscustomobject]@{
            ForwardingAddress     = $ForwardingAddress
            ForwardingSmtpAddress = $ForwardingSmtpAddress
            PrimarySmtpAddress    = $PrimarySmtpAddress
        }
    }

    function New-InboxRuleRecord {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Identity,

            [Parameter(Mandatory)]
            [bool]$Enabled,

            [string[]]$ForwardTo = @(),

            [string[]]$ForwardAsAttachmentTo = @(),

            [string[]]$RedirectTo = @()
        )

        return [pscustomobject]@{
            Enabled               = $Enabled
            ForwardAsAttachmentTo = [string[]]@($ForwardAsAttachmentTo)
            ForwardTo             = [string[]]@($ForwardTo)
            Identity              = $Identity
            RedirectTo            = [string[]]@($RedirectTo)
        }
    }

    function New-OutboundForwardingEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]]$Policy,

            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]]$Mailbox,

            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]]$InboxRule
        )

        return Get-OutboundForwardingEvidence `
            -OutboundSpamPolicyCollection { $Policy }.GetNewClosure() `
            -MailboxCollection { $Mailbox }.GetNewClosure() `
            -InboxRuleCollection { $InboxRule }.GetNewClosure()
    }

    function Get-EvidenceFold {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Evidence
        )

        $memberName = [string[]]@($Evidence.Keys)
        [System.Array]::Sort($memberName, [System.StringComparer]::Ordinal)

        return '{0}|{1}|{2}|collected={3}|failure={4}|{5}|members={6}' -f `
            $Evidence.ControlId,
        $Evidence.Source,
        $Evidence.Command,
        $Evidence.Collected,
        $Evidence.FailureReason,
        (ConvertTo-CanonicalJson -InputObject $Evidence.Value),
        ($memberName -join ',')
    }

    $script:AcceptedDomain = @('contoso.com')

    function New-PartialForwardingEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'EXO-004' -Source 'ExchangeOnline' `
            -Command 'Get-HostedOutboundSpamFilterPolicy; Get-Mailbox; Get-InboxRule' -Value $Payload
    }

    function Get-VerdictFold {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Result
        )

        return '{0}|golive={1}|reason={2}' -f $Result.Status, $Result.GoLiveSuccess, $Result.Reason
    }

    function Get-ResultFold {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Result
        )

        return '{0}|{1}|normalized={2}|golive={3}|reason={4}|evidence={5}:{6}' -f `
            $Result.ControlId,
        $Result.Status,
        $Result.Normalized,
        $Result.GoLiveSuccess,
        $Result.Reason,
        $Result.Evidence.Command,
        $Result.Evidence.ControlId
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXO-004-A1 outbound-forwarding collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector EXO-004 is registered against' {
            # Arrange
            $registered = $script:OutboundForwardingRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes EXO-004, and a collector that is named but not shipped is a forwarding path nobody looks at"
        }
    }

    Context 'Negative: every forwarding path the control covers must be given a service call to make' {

        It 'refuses a run with no outbound spam policy collection' {
            # Arrange
            $policies = $null

            # Act
            $act = {
                Get-OutboundForwardingEvidence -OutboundSpamPolicyCollection $policies `
                    -MailboxCollection { @() } -InboxRuleCollection { @() }
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OutboundSpamPolicyCollectionRequired*' -Because 'a record assembled without looking at the outbound policies reports the tenant blocks forwarding on the strength of two of the three paths it actually travels'
        }

        It 'refuses a run with no mailbox collection' {
            # Arrange
            $mailboxes = $null

            # Act
            $act = {
                Get-OutboundForwardingEvidence -OutboundSpamPolicyCollection { @() } `
                    -MailboxCollection $mailboxes -InboxRuleCollection { @() }
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MailboxCollectionRequired*' -Because 'per-mailbox forwarding survives every policy setting, so a record that never looked at mailboxes cannot decide this control'
        }

        It 'refuses a run with no inbox rule collection' {
            # Arrange
            $rules = $null

            # Act
            $act = {
                Get-OutboundForwardingEvidence -OutboundSpamPolicyCollection { @() } `
                    -MailboxCollection { @() } -InboxRuleCollection $rules
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'InboxRuleCollectionRequired*' -Because 'a user-owned redirect rule is the exfiltration path this control exists to close, and it is invisible in both the policy and the mailbox view'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records an outbound spam policy collection that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The term Get-HostedOutboundSpamFilterPolicy is not recognized in this session.' }

            # Act
            $evidence = Get-OutboundForwardingEvidence -OutboundSpamPolicyCollection $refusing `
                -MailboxCollection { @() } -InboxRuleCollection { @() }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'a policy command that never answered proves nothing about forwarding, and a record that hides the refusal reads downstream exactly like a tenant that was checked and found clean'
        }

        It 'records a mailbox collection that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The remote session was disconnected part way through Get-Mailbox.' }

            # Act
            $evidence = Get-OutboundForwardingEvidence -OutboundSpamPolicyCollection { @() } `
                -MailboxCollection $refusing -InboxRuleCollection { @() }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'a mailbox enumeration that died half way through has seen an unknown subset of the tenant, and treating the part it did see as the whole tenant is how a forwarding mailbox passes'
        }

        It 'records an inbox rule collection that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The operation was throttled and could not be completed.' }

            # Act
            $evidence = Get-OutboundForwardingEvidence -OutboundSpamPolicyCollection { @() } `
                -MailboxCollection { @() } -InboxRuleCollection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'throttling is the ordinary outcome of enumerating rules across a large tenant, so the one failure the control will meet most often must be the one it refuses to read as a pass'
        }
    }

    Context 'Negative: a tenant with nothing to report is an observation, not a failure' {

        It 'records collections that all returned nothing as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-OutboundForwardingEvidence -OutboundSpamPolicyCollection $empty `
                -MailboxCollection $empty -InboxRuleCollection $empty

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeExactly 'collected=True|failure=' `
                    -Because 'a tenant that returned no outbound spam policy at all is a tenant that fails EXO-004, and calling that a collection failure hides a real finding behind an infrastructure excuse'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = New-OutboundForwardingEvidence `
                -Policy @(New-OutboundSpamPolicyRecord -Name 'Default' -AutoForwardingMode 'On') `
                -Mailbox @() `
                -InboxRule @()

            # Act
            $act = { $evidence.Value['OutboundSpamFilterPolicy'][0].AutoForwardingMode = 'Off' }

            # Assert
            $act | Should -Throw -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one run of all three collections is one record of exactly what each returned' {

        It 'records every policy, mailbox and rule the services returned under its own name, unfiltered and unreshaped' {
            # Arrange
            $policy = @(
                (New-OutboundSpamPolicyRecord -Name 'Default' -AutoForwardingMode 'Off'),
                (New-OutboundSpamPolicyRecord -Name 'Marketing' -AutoForwardingMode 'On')
            )
            $mailbox = @(
                (New-ForwardingMailboxRecord -PrimarySmtpAddress 'clean@contoso.com'),
                (New-ForwardingMailboxRecord -PrimarySmtpAddress 'leak@contoso.com' -ForwardingSmtpAddress 'smtp:outside@fabrikam.example')
            )
            $inboxRule = @(
                (New-InboxRuleRecord -Identity 'Archive old mail' -Enabled $true),
                (New-InboxRuleRecord -Identity 'Copy to personal' -Enabled $true -RedirectTo @('outside@fabrikam.example'))
            )
            $expected = 'EXO-004|ExchangeOnline|Get-HostedOutboundSpamFilterPolicy; Get-Mailbox; Get-InboxRule|collected=True|failure=|' +
            '{"InboxRule":' +
            '[{"Enabled":true,"ForwardAsAttachmentTo":[],"ForwardTo":[],"Identity":"Archive old mail","RedirectTo":[]},' +
            '{"Enabled":true,"ForwardAsAttachmentTo":[],"ForwardTo":[],"Identity":"Copy to personal","RedirectTo":["outside@fabrikam.example"]}],' +
            '"Mailbox":' +
            '[{"ForwardingAddress":null,"ForwardingSmtpAddress":null,"PrimarySmtpAddress":"clean@contoso.com"},' +
            '{"ForwardingAddress":null,"ForwardingSmtpAddress":"smtp:outside@fabrikam.example","PrimarySmtpAddress":"leak@contoso.com"}],' +
            '"OutboundSpamFilterPolicy":' +
            '[{"AutoForwardingMode":"Off","Name":"Default"},{"AutoForwardingMode":"On","Name":"Marketing"}]}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = New-OutboundForwardingEvidence -Policy $policy -Mailbox $mailbox -InboxRule $inboxRule

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so the forwarding policy, the forwarding mailbox and the redirecting rule the evaluator will fail on all have to survive collection unchanged and stay separable from each other'
        }
    }
}

Describe 'EXO-004-A2 outbound-forwarding evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator EXO-004 is registered against' {
            # Arrange
            $registered = $script:OutboundForwardingRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides EXO-004, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation and a definition of outside' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = { Test-OutboundForwardingControl -Evidence $noEvidence -AcceptedDomain $script:AcceptedDomain }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceRequired*' -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one, and this is the control that decides whether mail is leaving the organization'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value ([pscustomobject]@{ SmtpClientAuthenticationDisabled = $true })

            # Act
            $act = { Test-OutboundForwardingControl -Evidence $foreign -AcceptedDomain $script:AcceptedDomain }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' -Because 'deciding the forwarding control from another control record reports a forwarding posture that was never looked at'
        }

        It 'refuses a decision that names no accepted domain' {
            # Arrange
            $evidence = New-OutboundForwardingEvidence -Policy @(New-OutboundSpamPolicyRecord -Name 'Default' -AutoForwardingMode 'Off') -Mailbox @() -InboxRule @()

            # Act
            $act = { Test-OutboundForwardingControl -Evidence $evidence -AcceptedDomain @() }

            # Assert
            $act | Should -Throw -ExpectedMessage 'AcceptedDomainRequired*' -Because 'externality is defined by the domains the organization holds, and an evaluator that knows none of them either calls every recipient external or calls none of them external; both are guesses'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-OutboundForwardingEvidence -OutboundSpamPolicyCollection { throw 'The operation was throttled and could not be completed.' } -MailboxCollection { @() } -InboxRuleCollection { @() }

            # Act
            $result = Test-OutboundForwardingControl -Evidence $refused -AcceptedDomain $script:AcceptedDomain

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a control the run never managed to observe must cost the run its go-live, because the alternative is that throttling the tenant is the cheapest way to pass the forwarding control'
        }
    }

    Context 'Negative: a record that carries only part of the tenant decides nothing about the rest' {

        It 'decides a record carrying no outbound spam policy observation as an error' {
            # Arrange
            $partial = New-PartialForwardingEvidence -Payload ([ordered]@{ Mailbox = @(); InboxRule = @() })

            # Act
            $result = Test-OutboundForwardingControl -Evidence $partial -AcceptedDomain $script:AcceptedDomain

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=OutboundForwardingEvidenceIncomplete: the record carries no 'OutboundSpamFilterPolicy' observation." `
                    -Because 'an absent observation is not an observation of nothing, and reading it as one lets a record that never looked at the policies report that the policies block forwarding'
        }

        It 'decides a record carrying no mailbox observation as an error' {
            # Arrange
            $partial = New-PartialForwardingEvidence -Payload ([ordered]@{ OutboundSpamFilterPolicy = @(); InboxRule = @() })

            # Act
            $result = Test-OutboundForwardingControl -Evidence $partial -AcceptedDomain $script:AcceptedDomain

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=OutboundForwardingEvidenceIncomplete: the record carries no 'Mailbox' observation." `
                    -Because 'per-mailbox forwarding survives every policy setting, so a record with no mailbox view proves nothing about the route that needs no policy at all'
        }

        It 'decides a record carrying no inbox rule observation as an error' {
            # Arrange
            $partial = New-PartialForwardingEvidence -Payload ([ordered]@{ OutboundSpamFilterPolicy = @(); Mailbox = @() })

            # Act
            $result = Test-OutboundForwardingControl -Evidence $partial -AcceptedDomain $script:AcceptedDomain

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=OutboundForwardingEvidenceIncomplete: the record carries no 'InboxRule' observation." `
                    -Because 'the user-owned redirect rule is the route an attacker actually uses, and it is the one route neither of the other two observations can see'
        }
    }

    Context 'Negative: an outbound policy that permits automatic forwarding fails' {

        It 'fails a policy whose automatic forwarding mode is not Off' {
            # Arrange
            $evidence = New-OutboundForwardingEvidence -Policy @(
                (New-OutboundSpamPolicyRecord -Name 'Default' -AutoForwardingMode 'Off'),
                (New-OutboundSpamPolicyRecord -Name 'Marketing' -AutoForwardingMode 'On')
            ) -Mailbox @() -InboxRule @()

            # Act
            $result = Test-OutboundForwardingControl -Evidence $evidence -AcceptedDomain $script:AcceptedDomain

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ForwardingPathOpen: outbound spam policy 'Marketing' sets automatic forwarding to 'On' where 'Off' is required." `
                    -Because 'one policy scoped to one group is enough to carry the whole organization''s mail out of the tenant, so a compliant default policy must never mask a permissive one beside it'
        }

        It 'fails a tenant that holds no outbound spam policy at all' {
            # Arrange
            $evidence = New-OutboundForwardingEvidence -Policy @() -Mailbox @() -InboxRule @()

            # Act
            $result = Test-OutboundForwardingControl -Evidence $evidence -AcceptedDomain $script:AcceptedDomain

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=ForwardingPathOpen: the tenant holds no outbound spam filter policy.' `
                    -Because 'an empty policy set satisfies "every policy blocks forwarding" vacuously, which is the one way this control can be passed by a tenant that has never configured it'
        }
    }

    Context 'Negative: a mailbox that forwards fails however it was configured to' {

        It 'fails a mailbox carrying a forwarding address' {
            # Arrange
            $evidence = New-OutboundForwardingEvidence -Policy @(New-OutboundSpamPolicyRecord -Name 'Default' -AutoForwardingMode 'Off') -Mailbox @(
                (New-ForwardingMailboxRecord -PrimarySmtpAddress 'leak@contoso.com' -ForwardingAddress 'contoso.com/Users/Outside Contractor')
            ) -InboxRule @()

            # Act
            $result = Test-OutboundForwardingControl -Evidence $evidence -AcceptedDomain $script:AcceptedDomain

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ForwardingPathOpen: mailbox 'leak@contoso.com' sets ForwardingAddress to 'contoso.com/Users/Outside Contractor'." `
                    -Because 'a forwarding address points at a directory object whose own forwarding the control never sees, so the hop that leaves the tenant is one the evaluator cannot follow and must not permit'
        }

        It 'fails a mailbox carrying a forwarding SMTP address' {
            # Arrange
            $evidence = New-OutboundForwardingEvidence -Policy @(New-OutboundSpamPolicyRecord -Name 'Default' -AutoForwardingMode 'Off') -Mailbox @(
                (New-ForwardingMailboxRecord -PrimarySmtpAddress 'leak@contoso.com' -ForwardingSmtpAddress 'smtp:outside@fabrikam.example')
            ) -InboxRule @()

            # Act
            $result = Test-OutboundForwardingControl -Evidence $evidence -AcceptedDomain $script:AcceptedDomain

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ForwardingPathOpen: mailbox 'leak@contoso.com' sets ForwardingSmtpAddress to 'smtp:outside@fabrikam.example'." `
                    -Because 'this is the administrator-configured route out of the tenant, and it survives every outbound policy because the policy governs user forwarding rather than mailbox delivery'
        }
    }

    Context 'Negative: an enabled rule that sends mail outside fails whichever action it uses' {

        It 'fails an enabled rule that forwards to an external address' {
            # Arrange
            $evidence = New-OutboundForwardingEvidence -Policy @(New-OutboundSpamPolicyRecord -Name 'Default' -AutoForwardingMode 'Off') -Mailbox @() -InboxRule @(
                (New-InboxRuleRecord -Identity 'Copy to personal' -Enabled $true -ForwardTo @('outside@fabrikam.example'))
            )

            # Act
            $result = Test-OutboundForwardingControl -Evidence $evidence -AcceptedDomain $script:AcceptedDomain

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ForwardingPathOpen: enabled inbox rule 'Copy to personal' forwards to 'outside@fabrikam.example'." `
                    -Because 'forwarding is the plainest of the three rule actions and the one a compromised account creates first, so an evaluator that missed it would miss the ordinary case'
        }

        It 'fails an enabled rule that forwards to an external address as an attachment' {
            # Arrange
            $evidence = New-OutboundForwardingEvidence -Policy @(New-OutboundSpamPolicyRecord -Name 'Default' -AutoForwardingMode 'Off') -Mailbox @() -InboxRule @(
                (New-InboxRuleRecord -Identity 'Archive offsite' -Enabled $true -ForwardAsAttachmentTo @('outside@fabrikam.example'))
            )

            # Act
            $result = Test-OutboundForwardingControl -Evidence $evidence -AcceptedDomain $script:AcceptedDomain

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ForwardingPathOpen: enabled inbox rule 'Archive offsite' forwards as attachment to 'outside@fabrikam.example'." `
                    -Because 'forwarding as an attachment carries the original message and its headers out intact, so an evaluator that checks only ForwardTo leaves the higher-fidelity copy of the mailbox unguarded'
        }

        It 'fails an enabled rule that redirects to an external address' {
            # Arrange
            $evidence = New-OutboundForwardingEvidence -Policy @(New-OutboundSpamPolicyRecord -Name 'Default' -AutoForwardingMode 'Off') -Mailbox @() -InboxRule @(
                (New-InboxRuleRecord -Identity 'Hide invoices' -Enabled $true -RedirectTo @('outside@fabrikam.example'))
            )

            # Act
            $result = Test-OutboundForwardingControl -Evidence $evidence -AcceptedDomain $script:AcceptedDomain

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ForwardingPathOpen: enabled inbox rule 'Hide invoices' redirects to 'outside@fabrikam.example'." `
                    -Because 'a redirect leaves no copy in the mailbox, which is what makes it the action of choice for invoice fraud and the one the owner is least likely to notice'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $evidence = New-OutboundForwardingEvidence -Policy @() -Mailbox @() -InboxRule @()
            $result = Test-OutboundForwardingControl -Evidence $evidence -AcceptedDomain $script:AcceptedDomain

            # Act
            $act = { $result.Status = 'Pass' }

            # Assert
            $act | Should -Throw -Because 'a verdict a caller can rewrite turns an open forwarding path into a closed one without changing anything in the tenant'
        }
    }

    Context 'Positive: a tenant with every forwarding path closed is the only pass' {

        It 'returns one go-live-successful Pass naming the evidence it was decided from' {
            # Arrange
            $evidence = New-OutboundForwardingEvidence -Policy @(
                (New-OutboundSpamPolicyRecord -Name 'Default' -AutoForwardingMode 'Off'),
                (New-OutboundSpamPolicyRecord -Name 'Marketing' -AutoForwardingMode 'Off')
            ) -Mailbox @(
                (New-ForwardingMailboxRecord -PrimarySmtpAddress 'clean@contoso.com'),
                (New-ForwardingMailboxRecord -PrimarySmtpAddress 'shared@contoso.com')
            ) -InboxRule @(
                (New-InboxRuleRecord -Identity 'Copy my manager' -Enabled $true -ForwardTo @('manager@CONTOSO.com')),
                (New-InboxRuleRecord -Identity 'Old offsite copy' -Enabled $false -RedirectTo @('outside@fabrikam.example')),
                (New-InboxRuleRecord -Identity 'File into folder' -Enabled $true)
            )
            $expected = 'EXO-004|Pass|normalized=True|golive=True|reason=|evidence=Get-HostedOutboundSpamFilterPolicy; Get-Mailbox; Get-InboxRule:EXO-004'

            # Act
            $result = Test-OutboundForwardingControl -Evidence $evidence -AcceptedDomain @(' Contoso.COM. ')

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'the tenant that satisfies this control still runs inbox rules, so an enabled rule that forwards only inside the organization and a disabled rule that would have redirected outside it must both leave the verdict a pass, and the accepted domain that defines inside must survive the same casing, whitespace and trailing-dot differences every other domain comparison tolerates'
        }
    }
}
