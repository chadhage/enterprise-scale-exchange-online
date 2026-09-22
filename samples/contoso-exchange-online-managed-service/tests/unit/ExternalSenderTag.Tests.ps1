#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement is not installed and must never be imported. `Get-ExternalInOutlook`
    # is reached only through the supplied collection seam, so every collection here is a
    # scriptblock returning a canned configuration or throwing a canned failure.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # The registry is returned as one read-only collection deliberately protected from pipeline
    # unrolling, so the entry is read by index rather than by piping the collection.
    $script:ControlRegistry = @(Get-BaselineControlRegistry -Profile Historical)[0]
    $script:ExternalSenderTagRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'EXO-007') { $entry }
        })[0]

    function New-ExternalInOutlookRecord {
        [CmdletBinding()]
        param(
            # An untyped allow list keeps a configuration that carries no allow list member
            # distinguishable from one whose allow list is empty.
            [object]$AllowList = @(),

            [object]$Enabled = $true,

            [string]$Identity = 'contoso.onmicrosoft.com'
        )

        return [pscustomobject]@{
            AllowList = $AllowList
            Enabled   = $Enabled
            Identity  = $Identity
        }
    }

    function New-ExternalSenderTagEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Configuration
        )

        return Get-ExternalSenderTagEvidence -Collection { $Configuration }.GetNewClosure()
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

    $script:ExpectedAllowList = @('partner@fabrikam.example')

    function New-PartialSenderTagEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'EXO-007' -Source 'ExchangeOnline' -Command 'Get-ExternalInOutlook' -Value $Payload
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

Describe 'EXO-007-A1 sender-tag collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector EXO-007 is registered against' {
            # Arrange
            $registered = $script:ExternalSenderTagRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes EXO-007, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: the collector must be given a service call to make' {

        It 'refuses a collection with nothing to run' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-ExternalSenderTagEvidence -Collection $noCollection }

            # Assert
            $act | Should -Throw -ExpectedMessage 'CollectionRequired*' -Because 'a record assembled without reaching the external sender identification configuration reports a tagging posture nobody read from the tenant'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records a collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The term Get-ExternalInOutlook is not recognized in this session.' }

            # Act
            $evidence = Get-ExternalSenderTagEvidence -Collection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'an exception here discards every other control in the run, and a refused command that is not recorded as refused reads downstream exactly like a tenant that was read and found to be tagging its external mail'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a collection that returned nothing as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-ExternalSenderTagEvidence -Collection $empty

            # Assert
            ('collected={0}|failure={1}|observedAnything={2}' -f $evidence.Collected, $evidence.FailureReason, ($null -ne $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|observedAnything=False' `
                    -Because 'a tenant that has never configured external sender identification answers with nothing, and that is the finding EXO-007 exists to fail on rather than an infrastructure excuse to hide it behind'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = New-ExternalSenderTagEvidence -Configuration (New-ExternalInOutlookRecord -Enabled $false)

            # Act
            $act = { $evidence.Value['Enabled'] = $true }

            # Assert
            $act | Should -Throw -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one collection of the external sender identification configuration is one record of exactly what it returned' {

        It 'records the configuration the service returned under the control, source and command the registry declares' {
            # Arrange
            $configuration = New-ExternalInOutlookRecord -AllowList @('SMTP:Partner@Fabrikam.Example ', 'noreply@fabrikam.example') -Enabled $false
            $expected = 'EXO-007|ExchangeOnline|Get-ExternalInOutlook|collected=True|failure=|' +
            '{"AllowList":["SMTP:Partner@Fabrikam.Example ","noreply@fabrikam.example"],"Enabled":false,"Identity":"contoso.onmicrosoft.com"}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = New-ExternalSenderTagEvidence -Configuration $configuration

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so a configuration whose tagging is switched off has to survive collection alongside its allow list, and the allow list entry has to survive with its routing prefix, its casing and its trailing space intact; a collector that filtered to the enabled configurations, narrowed the payload to the allow list or normalized its entries on the way in would decide the control before the evaluator ever saw it'
        }
    }
}

Describe 'EXO-007-A2 sender-tag evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator EXO-007 is registered against' {
            # Arrange
            $registered = $script:ExternalSenderTagRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides EXO-007, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation and the allow list the baseline resolved' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = { Test-ExternalSenderTagControl -Evidence $noEvidence -ExpectedAllowList $script:ExpectedAllowList }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceRequired*' -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'EXO-005' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value ([pscustomobject]@{ ExternalPostmasterAddress = 'postmaster@contoso.com' })

            # Act
            $act = { Test-ExternalSenderTagControl -Evidence $foreign -ExpectedAllowList $script:ExpectedAllowList }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' -Because 'deciding the sender-tag control from another control record reports a tagging posture that was never looked at'
        }

        It 'refuses a decision that names no resolved desired allow list' {
            # Arrange
            $noAllowList = $null

            # Act
            $act = { Test-ExternalSenderTagControl -Evidence (New-ExternalSenderTagEvidence -Configuration (New-ExternalInOutlookRecord)) -ExpectedAllowList $noAllowList }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ExpectedAllowListRequired*' -Because 'the card demands the normalized allow list exactly match the resolved desired state, and an allow list that was never resolved is not the same desired state as one the baseline resolved to nothing; reading the first as the second decides the control on the absence of configuration rather than on the tenant'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-ExternalSenderTagEvidence -Collection { throw 'The operation was throttled and could not be completed.' }

            # Act
            $result = Test-ExternalSenderTagControl -Evidence $refused -ExpectedAllowList $script:ExpectedAllowList

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a control the run never managed to observe must cost the run its go-live, because the alternative is that throttling the tenant is the cheapest way to pass it'
        }
    }

    Context 'Negative: a configuration that carries only part of itself decides nothing about the rest' {

        It 'decides an observed configuration carrying no enabled member as an error' {
            # Arrange
            $partial = New-PartialSenderTagEvidence -Payload ([pscustomobject]@{ AllowList = @(); Identity = 'contoso.onmicrosoft.com' })

            # Act
            $result = Test-ExternalSenderTagControl -Evidence $partial -ExpectedAllowList @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=ExternalSenderTagEvidenceIncomplete: the observed external sender identification carries no 'Enabled' member." `
                    -Because 'an absent member read as enabled reports that external mail is being tagged on the strength of a member nobody observed, which is the most flattering possible reading of an incomplete answer'
        }

        It 'decides an observed configuration carrying no allow list member as an error' {
            # Arrange
            $partial = New-PartialSenderTagEvidence -Payload ([pscustomobject]@{ Enabled = $true; Identity = 'contoso.onmicrosoft.com' })

            # Act
            $result = Test-ExternalSenderTagControl -Evidence $partial -ExpectedAllowList @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=ExternalSenderTagEvidenceIncomplete: the observed external sender identification carries no 'AllowList' member." `
                    -Because 'an allow list that was never observed is not an empty allow list, and against the default desired state of no exemptions at all the two differ by exactly one silent pass'
        }
    }

    Context 'Negative: a tenant that is not tagging its external mail fails' {

        It 'fails a tenant that holds no external sender identification configuration at all' {
            # Arrange
            $nothing = Get-ExternalSenderTagEvidence -Collection { }

            # Act
            $result = Test-ExternalSenderTagControl -Evidence $nothing -ExpectedAllowList @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=ExternalSenderTagGap: the tenant holds no external sender identification configuration.' `
                    -Because 'a tenant that has never configured external sender identification is the default state of every tenant, so a control that reads the absence of a configuration as anything other than a failure passes before anybody configures it'
        }

        It 'fails a tenant whose external sender identification is disabled' {
            # Arrange
            $disabled = New-ExternalSenderTagEvidence -Configuration (New-ExternalInOutlookRecord -Enabled $false)

            # Act
            $result = Test-ExternalSenderTagControl -Evidence $disabled -ExpectedAllowList @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=ExternalSenderTagGap: external sender identification is disabled.' `
                    -Because 'the tag on the message is the only warning the recipient ever sees, and a tenant that is not applying it is not warning anybody no matter how empty its allow list is'
        }
    }

    Context 'Negative: an allow list that is not the resolved desired allow list fails' {

        It 'fails a tenant holding an allow-list entry the baseline does not declare, naming it' {
            # Arrange
            $surplus = New-ExternalSenderTagEvidence -Configuration (New-ExternalInOutlookRecord -AllowList @('partner@fabrikam.example'))

            # Act
            $result = Test-ExternalSenderTagControl -Evidence $surplus -ExpectedAllowList @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ExternalSenderTagGap: the allow list holds 'partner@fabrikam.example' which the baseline does not declare." `
                    -Because 'an undeclared allow-list entry is the whole exposure this control exists to close: that sender is delivered untagged, and the shipping check that reads only the enabled flag passes a tenant with every sender the attacker cares about exempted'
        }

        It 'fails a tenant that does not hold an allow-list entry the baseline declares, naming it' {
            # Arrange
            $missing = New-ExternalSenderTagEvidence -Configuration (New-ExternalInOutlookRecord -AllowList @())

            # Act
            $result = Test-ExternalSenderTagControl -Evidence $missing -ExpectedAllowList $script:ExpectedAllowList

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ExternalSenderTagGap: the allow list does not hold 'partner@fabrikam.example'." `
                    -Because 'the card demands exact equality rather than containment, so an allow list the baseline resolved and the tenant never applied is drift in its own right and not merely a safer tenant'
        }

        It 'fails a tenant whose allow list both holds an undeclared entry and omits a declared one, naming both' {
            # Arrange
            $drifted = New-ExternalSenderTagEvidence -Configuration (New-ExternalInOutlookRecord -AllowList @('partner@fabrikam.example'))

            # Act
            $result = Test-ExternalSenderTagControl -Evidence $drifted -ExpectedAllowList @('trusted@contoso-partner.example')

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ExternalSenderTagGap: the allow list holds 'partner@fabrikam.example' which the baseline does not declare; the allow list does not hold 'trusted@contoso-partner.example'." `
                    -Because 'an operator told only half of a two-sided difference removes the entry they were told about, re-runs, and is told about the other half; the failure has to carry the whole difference in one reading'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-ExternalSenderTagControl `
                -Evidence (New-ExternalSenderTagEvidence -Configuration (New-ExternalInOutlookRecord -Enabled $false)) `
                -ExpectedAllowList @()

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act | Should -Throw -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: tagging on with an allow list equal to the resolved desired state is one go-live-successful pass' {

        It 'passes a tenant that tags external mail and whose normalized allow list is set-equal to the resolved desired state' {
            # Arrange
            $configured = New-ExternalSenderTagEvidence -Configuration (New-ExternalInOutlookRecord `
                    -AllowList @('notices@contoso-partner.example', ' SMTP:Partner@Fabrikam.EXAMPLE ') -Enabled $true)
            $expected = 'EXO-007|Pass|normalized=True|golive=True|reason=|evidence=Get-ExternalInOutlook:EXO-007'

            # Act
            $result = Test-ExternalSenderTagControl -Evidence $configured -ExpectedAllowList @('partner@fabrikam.example', 'Notices@Contoso-Partner.Example')

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'both halves of the control have to hold at once: tagging switched on and an allow list set-equal to the resolved desired state, proved here over a tenant whose entries differ from the baseline in order, in casing, in surrounding whitespace and in the routing prefix Exchange Online reports back - none of which is drift under the declared SmtpAddress comparison, and a comparison that read any of them as drift would fail a correctly configured tenant; the verdict has to be one normalized go-live-successful pass naming the record it was decided from rather than a bare true'
        }
    }
}
