#requires -Version 7.0

# Pester evaluates `-ForEach` during discovery, before any `BeforeAll` has run, so the observations
# EXO-002 is decided from and the members each observed mailbox is decided by are declared here.
$SmtpAuthenticationObservation = @('TransportConfig', 'CasMailbox')

$CasMailboxDecidedMember = @('Identity', 'SmtpClientAuthenticationDisabled')

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement is not installed and must never be imported. Both Exchange Online
    # commands EXO-002 depends on are reached only through a supplied collection seam, so every
    # collection here is a scriptblock returning a canned payload or throwing a canned failure and
    # no request leaves this process.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # The registry is returned as one read-only collection deliberately protected from pipeline
    # unrolling, so the entry is read by index rather than by piping the collection.
    $script:ControlRegistry = @(Get-BaselineControlRegistry)[0]
    $script:SmtpAuthenticationRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'EXO-002') { $entry }
        })[0]

    function New-TransportConfigRecord {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [bool]$SmtpClientAuthenticationDisabled
        )

        return [pscustomobject]@{
            SmtpClientAuthenticationDisabled = $SmtpClientAuthenticationDisabled
            Name                             = 'Transport Settings'
        }
    }

    function New-CasMailboxRecord {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Identity,

            [AllowNull()]
            [object]$SmtpClientAuthenticationDisabled = $null
        )

        return [pscustomobject]@{
            Identity                         = $Identity
            SmtpClientAuthenticationDisabled = $SmtpClientAuthenticationDisabled
            ActiveSyncEnabled                = $true
        }
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

    # The discovery-time copy of this list is not in scope while a test runs, and a list that read
    # as empty would build a record carrying nothing and let every omission assert the same absence.
    $script:ObservationName = @('TransportConfig', 'CasMailbox')

    # A tenant that satisfies EXO-002, with any one observation swapped out. Each negative changes
    # exactly the thing it is about, so a verdict it produces cannot be explained by anything else.
    function New-SmtpAuthenticationEvidenceRecord {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [object]$TransportConfig = (New-TransportConfigRecord -SmtpClientAuthenticationDisabled $true),

            [AllowNull()]
            [AllowEmptyCollection()]
            [object[]]$CasMailbox = @()
        )

        return Get-SmtpAuthenticationEvidence `
            -TransportConfigCollection { $TransportConfig }.GetNewClosure() `
            -CasMailboxCollection { $CasMailbox }.GetNewClosure()
    }

    function New-PartialSmtpAuthenticationEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' `
            -Command 'Get-TransportConfig; Get-CASMailbox' -Value $Payload
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

Describe 'EXO-002-A1 SMTP AUTH collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector EXO-002 is registered against' {
            # Arrange
            $registered = $script:SmtpAuthenticationRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes EXO-002, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: both halves of the control must be given a service call to make' {

        It 'refuses a run with no transport configuration collection' {
            # Arrange
            $transport = $null

            # Act
            $act = {
                Get-SmtpAuthenticationEvidence -TransportConfigCollection $transport `
                    -CasMailboxCollection { @() }
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'TransportConfigCollectionRequired*' `
                -Because 'the organization setting is the switch every mailbox inherits from, and a record that never read it cannot say whether basic authentication is closed anywhere at all'
        }

        It 'refuses a run with no client access mailbox collection' {
            # Arrange
            $mailbox = $null

            # Act
            $act = {
                Get-SmtpAuthenticationEvidence -TransportConfigCollection { New-TransportConfigRecord -SmtpClientAuthenticationDisabled $true } `
                    -CasMailboxCollection $mailbox
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'CasMailboxCollectionRequired*' `
                -Because 'a per-mailbox override re-opens SMTP AUTH for that mailbox while the organization setting still reads as disabled, so a record with no mailbox view reports a closed tenant on the strength of a switch the exposed mailboxes do not obey'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records a transport configuration collection that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The term Get-TransportConfig is not recognized in this session.' }

            # Act
            $evidence = Get-SmtpAuthenticationEvidence -TransportConfigCollection $refusing `
                -CasMailboxCollection { @() }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'a command that never answered proves nothing about legacy authentication, and a refusal that is not recorded as a refusal reads downstream exactly like a tenant that was read and found closed'
        }

        It 'records a client access mailbox collection that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The operation was throttled and could not be completed.' }

            # Act
            $evidence = Get-SmtpAuthenticationEvidence `
                -TransportConfigCollection { New-TransportConfigRecord -SmtpClientAuthenticationDisabled $true } `
                -CasMailboxCollection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'enumerating every mailbox is the call this control is throttled on most, and a half-read tenant recorded as a whole one reports that nobody overrides the organization setting because nobody managed to look'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a collection where both commands returned nothing as collected' {
            # Arrange
            $silent = { }

            # Act
            $evidence = Get-SmtpAuthenticationEvidence -TransportConfigCollection $silent -CasMailboxCollection $silent

            # Assert
            ('collected={0}|failure={1}|{2}' -f $evidence.Collected, $evidence.FailureReason, (ConvertTo-CanonicalJson -InputObject $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|{"CasMailbox":[],"TransportConfig":null}' `
                    -Because 'a tenant that holds no mailbox answers the second call with nothing, and that is an observation the evaluator decides rather than an infrastructure failure to hide the control behind'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = Get-SmtpAuthenticationEvidence `
                -TransportConfigCollection { New-TransportConfigRecord -SmtpClientAuthenticationDisabled $false } `
                -CasMailboxCollection { New-CasMailboxRecord -Identity 'service.account@contoso.com' -SmtpClientAuthenticationDisabled $false }

            # Act
            $act = { $evidence.Value['CasMailbox'] = @() }

            # Assert
            $act | Should -Throw `
                -Because 'raw evidence a caller can rewrite is not evidence of which mailboxes accept basic authentication, it is evidence of which ones the caller wanted to accept it'
        }
    }

    Context 'Positive: one collection of both sources is one record of exactly what the services returned' {

        It 'records both observations under the control, source and commands the registry declares' {
            # Arrange
            $transport = { New-TransportConfigRecord -SmtpClientAuthenticationDisabled $true }
            $mailbox = {
                New-CasMailboxRecord -Identity 'chief.executive@contoso.com'
                New-CasMailboxRecord -Identity 'scanner@contoso.com' -SmtpClientAuthenticationDisabled $false
            }
            $expected = 'EXO-002|ExchangeOnline|Get-TransportConfig; Get-CASMailbox|collected=True|failure=|' +
            '{"CasMailbox":[{"ActiveSyncEnabled":true,"Identity":"chief.executive@contoso.com","SmtpClientAuthenticationDisabled":null},' +
            '{"ActiveSyncEnabled":true,"Identity":"scanner@contoso.com","SmtpClientAuthenticationDisabled":false}],' +
            '"TransportConfig":{"Name":"Transport Settings","SmtpClientAuthenticationDisabled":true}}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = Get-SmtpAuthenticationEvidence -TransportConfigCollection $transport -CasMailboxCollection $mailbox

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so a mailbox that inherits the organization setting has to survive collection beside the one that overrides it: a collector that filtered to the overriding mailboxes would make a tenant whose mailboxes all inherit indistinguishable from one nobody enumerated, one that narrowed each mailbox to the member the control decides on would drop the identity the failure has to name, and one that folded the two observations into a verdict would decide the control before any evaluator saw it'
        }
    }
}

Describe 'EXO-002-A2 SMTP AUTH evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator EXO-002 is registered against' {
            # Arrange
            $registered = $script:SmtpAuthenticationRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides EXO-002, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation to decide' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $absent = $null

            # Act
            $act = { Test-SmtpAuthenticationControl -Evidence $absent }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceRequired*' `
                -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'EXO-005' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' `
                -Value ([pscustomobject]@{ ExternalPostmasterAddress = 'postmaster@contoso.com' })

            # Act
            $act = { Test-SmtpAuthenticationControl -Evidence $foreign }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' `
                -Because 'EXO-005 reads the same transport configuration for a different member, so a record that looks close enough decides this control from a member nobody observed'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-SmtpAuthenticationEvidence -TransportConfigCollection { throw 'The operation was throttled and could not be completed.' } `
                -CasMailboxCollection { @() }

            # Act
            $result = Test-SmtpAuthenticationControl -Evidence $refused

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a tenant the run never managed to read must cost the run its go-live, because the alternative is that a throttled mailbox enumeration is the cheapest way to pass this control'
        }
    }

    Context 'Negative: a record that carries only part of itself decides nothing about the rest' {

        It "decides a record carrying no '<_>' observation as an error" -ForEach $SmtpAuthenticationObservation {
            # Arrange
            $observation = [ordered]@{}
            foreach ($name in $script:ObservationName) {
                if ($name -cne $_) { $observation[$name] = @() }
            }
            $partial = New-PartialSmtpAuthenticationEvidence -Payload $observation

            # Act
            $result = Test-SmtpAuthenticationControl -Evidence $partial

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=SmtpAuthenticationEvidenceIncomplete: the record carries no '$_' observation." `
                    -Because 'an observation that is absent is not an observation of nothing, and read as one it reports that no mailbox overrides a switch nobody read'
        }

        It "decides an observed transport configuration carrying no 'SmtpClientAuthenticationDisabled' member as an error" {
            # Arrange
            $incomplete = New-SmtpAuthenticationEvidenceRecord -TransportConfig ([pscustomobject]@{ Name = 'Transport Settings' })

            # Act
            $result = Test-SmtpAuthenticationControl -Evidence $incomplete

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=SmtpAuthenticationEvidenceIncomplete: the observed transport configuration carries no 'SmtpClientAuthenticationDisabled' member." `
                    -Because 'an absent member read as false reports SMTP AUTH open and an absent member read as true reports it closed, and the second is the reading every evaluator that tests for truthiness quietly takes'
        }

        It "decides an observed mailbox carrying no '<_>' member as an error" -ForEach $CasMailboxDecidedMember {
            # Arrange
            $mailbox = New-CasMailboxRecord -Identity 'scanner@contoso.com' -SmtpClientAuthenticationDisabled $true
            $mailbox.PSObject.Properties.Remove($_)
            $incomplete = New-SmtpAuthenticationEvidenceRecord -CasMailbox @($mailbox)

            # Act
            $result = Test-SmtpAuthenticationControl -Evidence $incomplete

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=SmtpAuthenticationEvidenceIncomplete: an observed mailbox carries no '$_' member." `
                    -Because 'a mailbox with no setting cannot be told apart from one that inherits the organization switch, and a mailbox with no identity cannot be named in the failure that would have it closed'
        }
    }

    Context 'Negative: a tenant that accepts basic authentication fails' {

        It 'fails an organization that has left SMTP client authentication enabled' {
            # Arrange
            $open = New-SmtpAuthenticationEvidenceRecord -TransportConfig (New-TransportConfigRecord -SmtpClientAuthenticationDisabled $false)

            # Act
            $result = Test-SmtpAuthenticationControl -Evidence $open

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=SmtpAuthenticationOpen: SMTP client authentication is enabled organization-wide.' `
                    -Because 'SMTP AUTH is the one legacy protocol Conditional Access cannot reach, so an organization that leaves it on hands every credential in the tenant a path that no multi-factor policy will ever challenge'
        }

        It 'fails a mailbox whose per-mailbox setting enables SMTP client authentication, naming the mailbox' {
            # Arrange
            $override = New-SmtpAuthenticationEvidenceRecord -CasMailbox @(
                (New-CasMailboxRecord -Identity 'chief.executive@contoso.com')
                (New-CasMailboxRecord -Identity 'scanner@contoso.com' -SmtpClientAuthenticationDisabled $false)
            )

            # Act
            $result = Test-SmtpAuthenticationControl -Evidence $override

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=SmtpAuthenticationOpen: mailbox 'scanner@contoso.com' enables SMTP client authentication by a per-mailbox override." `
                    -Because 'the per-mailbox setting overrides the organization switch for the mailbox that carries it, the mailbox beside it that inherits the switch must not be reported as drift, and an unnamed override cannot be closed'
        }
    }

    Context 'Positive: a disabled organization switch no mailbox overrides is one go-live-successful pass' {

        It 'passes a tenant whose organization has SMTP client authentication disabled and whose mailboxes either inherit that switch or disable it outright' {
            # Arrange
            $closed = New-SmtpAuthenticationEvidenceRecord -CasMailbox @(
                (New-CasMailboxRecord -Identity 'chief.executive@contoso.com')
                (New-CasMailboxRecord -Identity 'scanner@contoso.com' -SmtpClientAuthenticationDisabled $true)
            )

            # Act
            $result = Test-SmtpAuthenticationControl -Evidence $closed

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly 'EXO-002|Pass|normalized=True|golive=True|reason=|evidence=Get-TransportConfig; Get-CASMailbox:EXO-002' `
                    -Because 'both clauses of the card are satisfied at once by exactly one tenant shape, and the two ways a mailbox can be compliant sit inside this pass rather than in negatives of their own: a mailbox whose setting is unset inherits the organization switch and a mailbox that sets it to disabled agrees with it, so an evaluator that read either as an override would fail every hardened tenant while passing every assertion above'
        }
    }
    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-SmtpAuthenticationControl -Evidence (New-SmtpAuthenticationEvidenceRecord -TransportConfig (New-TransportConfigRecord -SmtpClientAuthenticationDisabled $false))

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act | Should -Throw `
                -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }
}