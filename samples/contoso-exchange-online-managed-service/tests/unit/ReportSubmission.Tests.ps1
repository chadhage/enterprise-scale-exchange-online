#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement is not installed and must never be imported. Both reporting commands
    # are reached only through the supplied collection seams, so every collection here is a
    # scriptblock returning canned policies or throwing a canned failure.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # Assigning before unrolling matters: the registry is returned as one read-only collection
    # deliberately protected from pipeline unrolling, so it is read by index rather than by pipe.
    $script:ControlRegistry = @(Get-BaselineControlRegistry)[0]
    $script:ReportSubmissionRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'MDO-006') { $entry }
        })[0]

    function New-ReportSubmissionPolicyObject {
        [CmdletBinding()]
        param(
            [object]$Identity = 'DefaultReportSubmissionPolicy',

            [object]$EnableReportToMicrosoft = $true,

            [object]$EnableThirdPartyAddress = $false,

            [object]$ReportJunkToCustomizedAddress = $true,

            [object]$ReportJunkAddresses = @('soc@contoso.com'),

            [object]$EnableUserEmailNotification = $false,

            [string[]]$Remove = @()
        )

        $policy = [ordered]@{
            Identity                      = $Identity
            EnableReportToMicrosoft       = $EnableReportToMicrosoft
            EnableThirdPartyAddress       = $EnableThirdPartyAddress
            ReportJunkToCustomizedAddress = $ReportJunkToCustomizedAddress
            ReportJunkAddresses           = $ReportJunkAddresses
            EnableUserEmailNotification   = $EnableUserEmailNotification
        }

        foreach ($member in $Remove) { $policy.Remove($member) }

        return [pscustomobject]$policy
    }

    function New-SecOpsOverridePolicyObject {
        [CmdletBinding()]
        param(
            [object]$Identity = 'SecOpsOverridePolicy',

            [object]$SentTo = @('soc@contoso.com'),

            [object]$Mode = 'Enforce',

            [string[]]$Remove = @()
        )

        $policy = [ordered]@{
            Identity = $Identity
            SentTo   = $SentTo
            Mode     = $Mode
        }

        foreach ($member in $Remove) { $policy.Remove($member) }

        return [pscustomobject]$policy
    }

    function New-ReportSubmissionEvidenceRecord {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [object]$ReportSubmissionPolicy,

            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [object]$SecOpsOverridePolicy
        )

        return Get-ReportSubmissionEvidence `
            -ReportSubmissionPolicyCollection { $ReportSubmissionPolicy }.GetNewClosure() `
            -SecOpsOverridePolicyCollection { $SecOpsOverridePolicy }.GetNewClosure()
    }

    function New-ReportSubmissionDesiredState {
        [CmdletBinding()]
        param(
            [object]$MicrosoftReportMessageButton = $true,

            [object]$SendReportedMessagesToMicrosoft = $true,

            [object]$SendCopyToSecOpsMailbox = $true,

            [object]$ReportingDestination = 'MicrosoftAndCustomMailbox',

            [object]$ReportingMailbox = 'soc@contoso.com',

            [string[]]$Remove = @()
        )

        $state = [ordered]@{
            microsoftReportMessageButton    = $MicrosoftReportMessageButton
            sendReportedMessagesToMicrosoft = $SendReportedMessagesToMicrosoft
            sendCopyToSecOpsMailbox         = $SendCopyToSecOpsMailbox
            reportingDestination            = $ReportingDestination
            reportingMailbox                = $ReportingMailbox
        }

        foreach ($member in $Remove) { $state.Remove($member) }

        return [pscustomobject]$state
    }

    function New-BaselineReportSubmissionEvidence {
        [CmdletBinding()]
        param(
            [object]$ReportSubmissionPolicy,

            [object]$SecOpsOverridePolicy
        )

        if (-not $PSBoundParameters.ContainsKey('ReportSubmissionPolicy')) { $ReportSubmissionPolicy = @(New-ReportSubmissionPolicyObject) }
        if (-not $PSBoundParameters.ContainsKey('SecOpsOverridePolicy')) { $SecOpsOverridePolicy = @(New-SecOpsOverridePolicyObject) }

        return New-ReportSubmissionEvidenceRecord -ReportSubmissionPolicy $ReportSubmissionPolicy -SecOpsOverridePolicy $SecOpsOverridePolicy
    }

    function New-PartialReportSubmissionEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'MDO-006' -Source 'ExchangeOnline' `
            -Command 'Get-ReportSubmissionPolicy; Get-SecOpsOverridePolicy' -Value $Payload
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

    $script:DesiredReportSubmission = New-ReportSubmissionDesiredState
    $script:DesiredSecOpsMailbox = @('soc@contoso.com')
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'MDO-008-A1 reporting and Advanced Delivery collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector MDO-006 is registered against' {
            # Arrange
            $registered = $script:ReportSubmissionRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes user reporting and Advanced Delivery, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: the collector must be given both service calls to make' {

        It 'refuses a collection with no report submission policy to read' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-ReportSubmissionEvidence -ReportSubmissionPolicyCollection $noCollection -SecOpsOverridePolicyCollection { @() } }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'ReportSubmissionPolicyCollectionRequired*' `
                    -Because 'the report submission policy carries every reporting decision the card calls exact, so a record assembled without it reports a reporting posture nobody looked at'
        }

        It 'refuses a collection with no SecOps override policy to read' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-ReportSubmissionEvidence -ReportSubmissionPolicyCollection { @() } -SecOpsOverridePolicyCollection $noCollection }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'SecOpsOverridePolicyCollectionRequired*' `
                    -Because 'the SecOps mailbox is registered on a separate Advanced Delivery override policy, so the card second clause is decidable from no part of the report submission policy at all'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records a report submission collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The term Get-ReportSubmissionPolicy is not recognized in this session.' }

            # Act
            $evidence = Get-ReportSubmissionEvidence -ReportSubmissionPolicyCollection $refusing -SecOpsOverridePolicyCollection { @(New-SecOpsOverridePolicyObject) }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'an exception here discards every other control in the run, and a refused command that is not recorded as refused reads downstream exactly like a reporting policy that was read and found correct'
        }

        It 'records a SecOps override collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The operation was throttled and could not be completed.' }

            # Act
            $evidence = Get-ReportSubmissionEvidence -ReportSubmissionPolicyCollection { @(New-ReportSubmissionPolicyObject) } -SecOpsOverridePolicyCollection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'the half of the card that was answered must never stand in for the half that was not, because a throttled tenant would otherwise pass Advanced Delivery on the strength of its reporting buttons'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a tenant that holds no reporting policy at all as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-ReportSubmissionEvidence -ReportSubmissionPolicyCollection $empty -SecOpsOverridePolicyCollection $empty

            # Assert
            ('collected={0}|failure={1}|{2}' -f $evidence.Collected, $evidence.FailureReason, (ConvertTo-CanonicalJson -InputObject $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|{"ReportSubmissionPolicy":[],"SecOpsOverridePolicy":[]}' `
                    -Because 'a tenant that has registered no SecOps mailbox in Advanced Delivery is the exact finding this control exists to report, and calling it a collection failure hides that finding behind an infrastructure excuse'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = New-ReportSubmissionEvidenceRecord -ReportSubmissionPolicy @(New-ReportSubmissionPolicyObject) -SecOpsOverridePolicy @(New-SecOpsOverridePolicyObject)

            # Act
            $act = { $evidence.Value['SecOpsOverridePolicy'] = @() }

            # Assert
            $act |
                Should -Throw `
                    -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one run of both collections is one record of exactly what each returned' {

        It 'records both policy sets whole under their own names, under the control, source and commands the registry declares' {
            # Arrange
            $defaultPolicy = New-ReportSubmissionPolicyObject -Identity ' DefaultReportSubmissionPolicy ' `
                -EnableReportToMicrosoft $false -ReportJunkAddresses @('SOC@Contoso.com')
            $legacyPolicy = New-ReportSubmissionPolicyObject -Identity 'ContosoLegacyPolicy'
            $expected = 'MDO-006|ExchangeOnline|Get-ReportSubmissionPolicy; Get-SecOpsOverridePolicy|collected=True|failure=|' +
            '{"ReportSubmissionPolicy":[{"EnableReportToMicrosoft":false,"EnableThirdPartyAddress":false,"EnableUserEmailNotification":false,' +
            '"Identity":" DefaultReportSubmissionPolicy ","ReportJunkAddresses":["SOC@Contoso.com"],' +
            '"ReportJunkToCustomizedAddress":true},' +
            '{"EnableReportToMicrosoft":true,"EnableThirdPartyAddress":false,"EnableUserEmailNotification":false,"Identity":"ContosoLegacyPolicy",' +
            '"ReportJunkAddresses":["soc@contoso.com"],"ReportJunkToCustomizedAddress":true}],' +
            '"SecOpsOverridePolicy":[{"Identity":"SecOpsOverridePolicy","Mode":"Enforce","SentTo":[" SOC@contoso.com "]}]}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = New-ReportSubmissionEvidenceRecord `
                -ReportSubmissionPolicy @($defaultPolicy, $legacyPolicy) `
                -SecOpsOverridePolicy @(New-SecOpsOverridePolicyObject -SentTo @(' SOC@contoso.com '))

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so the switched-off Microsoft reporting, the casing and whitespace around every identity and address, the legacy policy sitting beside the default one and every member no decision reads all have to survive collection; a collector that filtered to the default policy or narrowed each policy to the members the control decides on would settle the reporting destination and the SecOps registration before the evaluator ever saw them'
        }
    }
}

Describe 'MDO-008-A2 reporting and Advanced Delivery evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator MDO-006 is registered against' {
            # Arrange
            $registered = $script:ReportSubmissionRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides user reporting and Advanced Delivery, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation, the reporting state the baseline resolved and the SecOps mailboxes it resolved' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = { Test-ReportSubmissionControl -Evidence $noEvidence -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $script:DesiredSecOpsMailbox }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceRequired*' `
                    -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'MDO-001' -Source 'ExchangeOnline' `
                -Command 'Get-ReportSubmissionPolicy; Get-SecOpsOverridePolicy' `
                -Value ([ordered]@{
                    ReportSubmissionPolicy = @(New-ReportSubmissionPolicyObject)
                    SecOpsOverridePolicy   = @(New-SecOpsOverridePolicyObject)
                })

            # Act
            $act = { Test-ReportSubmissionControl -Evidence $foreign -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $script:DesiredSecOpsMailbox }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' `
                    -Because 'a record collected for one control is exactly the record that must not decide another, because the two carry two desired states'
        }

        It 'refuses a decision that names no resolved desired user-submission state' {
            # Arrange
            $evidence = New-BaselineReportSubmissionEvidence

            # Act
            $act = { Test-ReportSubmissionControl -Evidence $evidence -DesiredState $null -SecOpsMailbox $script:DesiredSecOpsMailbox }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredReportSubmissionStateRequired*' `
                    -Because 'an evaluator handed no desired state decides against whatever it defaults to rather than against what was approved'
        }

        It 'refuses a desired state that declares no <Decision>' -ForEach @(
            @{ Decision = 'microsoftReportMessageButton' }
            @{ Decision = 'sendReportedMessagesToMicrosoft' }
            @{ Decision = 'sendCopyToSecOpsMailbox' }
        ) {
            # Arrange
            $evidence = New-BaselineReportSubmissionEvidence
            $undecided = New-ReportSubmissionDesiredState -Remove @($Decision)

            # Act
            $act = { Test-ReportSubmissionControl -Evidence $evidence -DesiredState $undecided -SecOpsMailbox $script:DesiredSecOpsMailbox }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredReportSubmissionDecisionRequired*' `
                    -Because 'each reporting switch is a decision somebody made, and a baseline that never made it reads identically to a baseline that decided against it'
        }

        It 'refuses a desired state that declares no reporting destination' {
            # Arrange
            $evidence = New-BaselineReportSubmissionEvidence
            $undirected = New-ReportSubmissionDesiredState -Remove @('reportingDestination')

            # Act
            $act = { Test-ReportSubmissionControl -Evidence $evidence -DesiredState $undirected -SecOpsMailbox $script:DesiredSecOpsMailbox }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredReportingDestinationRequired*' `
                    -Because 'the card calls the destination exact, and a tenant compared against no destination at all passes whether reported phishing reaches Microsoft, the SecOps mailbox or nobody'
        }

        It 'refuses a reporting destination the contract does not name' {
            # Arrange
            $evidence = New-BaselineReportSubmissionEvidence
            $invented = New-ReportSubmissionDesiredState -ReportingDestination 'ThirdPartyGateway'

            # Act
            $act = { Test-ReportSubmissionControl -Evidence $evidence -DesiredState $invented -SecOpsMailbox $script:DesiredSecOpsMailbox }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredReportingDestinationUnknown*' `
                    -Because 'a destination with no declared switch combination behind it resolves to nothing, and comparing every tenant against nothing reports them all compliant'
        }

        It 'refuses a desired state whose reporting mailbox is <Shape>' -ForEach @(
            @{ Shape = 'absent'; Mailbox = $null }
            @{ Shape = 'blank'; Mailbox = '   ' }
        ) {
            # Arrange
            $evidence = New-BaselineReportSubmissionEvidence
            $unaddressed = if ($Shape -ceq 'absent') {
                New-ReportSubmissionDesiredState -Remove @('reportingMailbox')
            }
            else {
                New-ReportSubmissionDesiredState -ReportingMailbox $Mailbox
            }

            # Act
            $act = { Test-ReportSubmissionControl -Evidence $evidence -DesiredState $unaddressed -SecOpsMailbox $script:DesiredSecOpsMailbox }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredReportingMailboxRequired*' `
                    -Because 'the mailbox reported messages land in is the whole point of the custom destination, and a baseline naming none compares every tenant against no mailbox at all'
        }

        It 'refuses a reporting mailbox that is still an unresolved placeholder' {
            # Arrange
            $evidence = New-BaselineReportSubmissionEvidence
            $unresolved = New-ReportSubmissionDesiredState -ReportingMailbox '__ADMIN_REQUIRED:SECURITY_OPERATIONS_MAILBOX__'

            # Act
            $act = { Test-ReportSubmissionControl -Evidence $evidence -DesiredState $unresolved -SecOpsMailbox $script:DesiredSecOpsMailbox }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredReportingMailboxUnresolved*' `
                    -Because 'a placeholder that reached the evaluator is a parameter nobody supplied, and comparing a tenant against the literal placeholder text fails every tenant for the wrong reason'
        }

        It 'refuses a decision with <Shape> resolved SecOps mailbox for Advanced Delivery' -ForEach @(
            @{ Shape = 'no' }
            @{ Shape = 'an empty' }
        ) {
            # Arrange
            $evidence = New-BaselineReportSubmissionEvidence
            $mailbox = if ($Shape -ceq 'no') { $null } else { @() }

            # Act
            $act = { Test-ReportSubmissionControl -Evidence $evidence -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $mailbox }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredSecOpsMailboxRequired*' `
                    -Because 'the card requires SecOps to be registered in Advanced Delivery, and a tenant compared against no SecOps mailbox passes precisely when it registers nobody'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-ReportSubmissionEvidence `
                -ReportSubmissionPolicyCollection { throw 'The operation was throttled and could not be completed.' } `
                -SecOpsOverridePolicyCollection { @() }

            # Act
            $result = Test-ReportSubmissionControl -Evidence $refused -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $script:DesiredSecOpsMailbox

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a control the run never managed to observe must cost the run its go-live, because the alternative is that throttling the tenant is the cheapest way to pass it'
        }
    }

    Context 'Negative: a record that never observed a policy set decides nothing about it' {

        It 'decides a record carrying no <Observation> observation as an error' -ForEach @(
            @{ Observation = 'ReportSubmissionPolicy' }
            @{ Observation = 'SecOpsOverridePolicy' }
        ) {
            # Arrange
            $payload = [ordered]@{
                ReportSubmissionPolicy = @(New-ReportSubmissionPolicyObject)
                SecOpsOverridePolicy   = @(New-SecOpsOverridePolicyObject)
            }
            $payload.Remove($Observation)
            $partial = New-PartialReportSubmissionEvidence -Payload $payload

            # Act
            $result = Test-ReportSubmissionControl -Evidence $partial -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $script:DesiredSecOpsMailbox

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=ReportSubmissionEvidenceIncomplete: the record carries no '$Observation' observation." `
                    -Because 'an absent policy set is not an observation that the tenant holds no such policy, and reading it as one decides half the card from a command nobody ran'
        }

        It 'decides an observed report submission policy carrying no <Member> member as an error' -ForEach @(
            @{ Member = 'EnableThirdPartyAddress' }
            @{ Member = 'EnableReportToMicrosoft' }
            @{ Member = 'ReportJunkToCustomizedAddress' }
            @{ Member = 'ReportJunkAddresses' }
        ) {
            # Arrange
            $incomplete = New-BaselineReportSubmissionEvidence -ReportSubmissionPolicy @(New-ReportSubmissionPolicyObject -Remove @($Member))

            # Act
            $result = Test-ReportSubmissionControl -Evidence $incomplete -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $script:DesiredSecOpsMailbox

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=ReportSubmissionEvidenceIncomplete: an observed ReportSubmissionPolicy carries no '$Member' member." `
                    -Because 'an absent switch read as its default reports a reporting decision the collector never carried, which is indistinguishable from one the tenant actually holds'
        }

        It 'decides an observed SecOps override policy carrying no <Member> member as an error' -ForEach @(
            @{ Member = 'Identity' }
            @{ Member = 'SentTo' }
        ) {
            # Arrange
            $incomplete = New-BaselineReportSubmissionEvidence -SecOpsOverridePolicy @(New-SecOpsOverridePolicyObject -Remove @($Member))

            # Act
            $result = Test-ReportSubmissionControl -Evidence $incomplete -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $script:DesiredSecOpsMailbox

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=ReportSubmissionEvidenceIncomplete: an observed SecOpsOverridePolicy carries no '$Member' member." `
                    -Because 'an absent sender list read as empty reports an Advanced Delivery registration that reaches nobody, which is a finding about the collector rather than about the tenant'
        }

        It 'decides a record carrying two report submission policies as an error' {
            # Arrange
            $ambiguous = New-BaselineReportSubmissionEvidence -ReportSubmissionPolicy @(
                New-ReportSubmissionPolicyObject -Identity 'DefaultReportSubmissionPolicy'
                New-ReportSubmissionPolicyObject -Identity 'ContosoLegacyPolicy' -EnableReportToMicrosoft $false
            )

            # Act
            $result = Test-ReportSubmissionControl -Evidence $ambiguous -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $script:DesiredSecOpsMailbox

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Error|golive=False|reason=ReportSubmissionEvidenceAmbiguous: the record carries 2 report submission policies where the tenant holds one.' `
                    -Because 'the report submission policy is a single tenant-wide object, so deciding from one of two would pick the verdict by ordering'
        }
    }

    Context 'Negative: a tenant whose reporting state is not exactly the declared state fails' {

        It 'fails a tenant that observed no report submission policy at all' {
            # Arrange
            $bare = New-BaselineReportSubmissionEvidence -ReportSubmissionPolicy @()

            # Act
            $result = Test-ReportSubmissionControl -Evidence $bare -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $script:DesiredSecOpsMailbox

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=ReportSubmissionDrift: the tenant holds no report submission policy.' `
                    -Because 'a tenant that has never configured user reporting is the default state of every tenant, so a control that reads a missing policy as anything other than a failure passes before anybody configures it'
        }

        It 'fails a <Decision> that differs from the baseline, naming the member, the value observed and the value required' -ForEach @(
            @{
                Decision = 'report button'
                Argument = @{ EnableThirdPartyAddress = $true }
                Expected = "the report submission policy sets 'EnableThirdPartyAddress' to 'True' where 'False' is required"
            }
            @{
                Decision = 'send to Microsoft'
                Argument = @{ EnableReportToMicrosoft = $false }
                Expected = "the report submission policy sets 'EnableReportToMicrosoft' to 'False' where 'True' is required; " +
                "the report submission policy sends reported messages to 'CustomMailbox' where 'MicrosoftAndCustomMailbox' is required"
            }
            @{
                Decision = 'SecOps copy'
                Argument = @{ ReportJunkToCustomizedAddress = $false }
                Expected = "the report submission policy sets 'ReportJunkToCustomizedAddress' to 'False' where 'True' is required; " +
                "the report submission policy sends reported messages to 'Microsoft' where 'MicrosoftAndCustomMailbox' is required"
            }
        ) {
            # Arrange
            $drifted = New-BaselineReportSubmissionEvidence -ReportSubmissionPolicy @(New-ReportSubmissionPolicyObject @Argument)

            # Act
            $result = Test-ReportSubmissionControl -Evidence $drifted -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $script:DesiredSecOpsMailbox

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ReportSubmissionDrift: $Expected." `
                    -Because 'the card calls the reporting state exact, and a control that decided only the switches it happened to read reports a reporting posture the tenant is not applying'
        }

        It 'fails a reporting destination that is not exactly the declared destination, naming both' {
            # Arrange
            $microsoftOnly = New-ReportSubmissionDesiredState -SendCopyToSecOpsMailbox $false -ReportingDestination 'Microsoft'
            $drifted = New-BaselineReportSubmissionEvidence

            # Act
            $result = Test-ReportSubmissionControl -Evidence $drifted -DesiredState $microsoftOnly -SecOpsMailbox $script:DesiredSecOpsMailbox

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly ("Fail|golive=False|reason=ReportSubmissionDrift: " +
                    "the report submission policy sets 'ReportJunkToCustomizedAddress' to 'True' where 'False' is required; " +
                    "the report submission policy sends reported messages to 'MicrosoftAndCustomMailbox' where 'Microsoft' is required.") `
                    -Because 'where a reported message lands is the decision the card calls exact, and a verdict that did not name the destination observed alongside the destination required leaves the operator nothing to act on'
        }

        It 'fails a reporting mailbox that is not the mailbox the baseline resolved, naming both' {
            # Arrange
            $drifted = New-BaselineReportSubmissionEvidence -ReportSubmissionPolicy @(New-ReportSubmissionPolicyObject -ReportJunkAddresses @('helpdesk@contoso.com'))

            # Act
            $result = Test-ReportSubmissionControl -Evidence $drifted -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $script:DesiredSecOpsMailbox

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly ("Fail|golive=False|reason=ReportSubmissionDrift: " +
                    "the report submission policy does not report to 'soc@contoso.com'; " +
                    "the report submission policy reports to unapproved 'helpdesk@contoso.com'.") `
                    -Because 'reported phishing landing in a mailbox nobody approved is a reporting channel the security team never agreed to watch, and naming only one side of the difference hides which of the two is wrong'
        }
    }

    Context 'Negative: Advanced Delivery that does not register exactly the resolved SecOps mailboxes fails' {

        It 'fails a tenant that registers no SecOps override policy at all' {
            # Arrange
            $unregistered = New-BaselineReportSubmissionEvidence -SecOpsOverridePolicy @()

            # Act
            $result = Test-ReportSubmissionControl -Evidence $unregistered -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $script:DesiredSecOpsMailbox

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=ReportSubmissionDrift: the tenant registers no SecOps override policy in Advanced Delivery.' `
                    -Because 'Advanced Delivery is off until somebody turns it on, so a control that read an absent override policy as anything other than a failure passes the tenant the card exists to catch'
        }

        It 'fails a SecOps override policy that does not carry every resolved SecOps mailbox, naming the missing mailbox' {
            # Arrange
            $partial = New-BaselineReportSubmissionEvidence -SecOpsOverridePolicy @(New-SecOpsOverridePolicyObject -SentTo @('soc@contoso.com'))

            # Act
            $result = Test-ReportSubmissionControl -Evidence $partial -DesiredState $script:DesiredReportSubmission -SecOpsMailbox @('soc@contoso.com', 'phishtest@contoso.com')

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ReportSubmissionDrift: Advanced Delivery does not register SecOps mailbox 'phishtest@contoso.com'." `
                    -Because 'a SecOps mailbox left out of Advanced Delivery has its simulated and intelligence-gathering mail filtered like any other, which is the exact outcome registering it was meant to prevent'
        }

        It 'fails a SecOps override policy carrying a sender address the baseline never resolved, naming the surplus mailbox' {
            # Arrange
            $widened = New-BaselineReportSubmissionEvidence -SecOpsOverridePolicy @(New-SecOpsOverridePolicyObject -SentTo @('soc@contoso.com', 'everyone@contoso.com'))

            # Act
            $result = Test-ReportSubmissionControl -Evidence $widened -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $script:DesiredSecOpsMailbox

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ReportSubmissionDrift: Advanced Delivery registers unapproved SecOps mailbox 'everyone@contoso.com'." `
                    -Because 'an Advanced Delivery registration exempts its mailboxes from filtering, so a mailbox nobody approved is an unfiltered delivery path granted on an approval that was never given'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-ReportSubmissionControl `
                -Evidence (New-BaselineReportSubmissionEvidence -SecOpsOverridePolicy @()) `
                -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $script:DesiredSecOpsMailbox

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act |
                Should -Throw `
                    -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: the declared reporting state and exactly the resolved SecOps registration is one go-live-successful pass' {

        It 'passes a tenant whose report submission policy holds exactly the declared buttons, destination and mailbox and whose Advanced Delivery registers exactly the resolved SecOps mailboxes' {
            # Arrange
            $policy = New-ReportSubmissionPolicyObject -Identity ' DefaultReportSubmissionPolicy ' `
                -ReportJunkAddresses @(' SOC@Contoso.com ', 'smtp:soc@contoso.com')
            $override = New-SecOpsOverridePolicyObject -SentTo @('SMTP:SOC@Contoso.com', ' soc@contoso.com ')
            $configured = New-BaselineReportSubmissionEvidence -ReportSubmissionPolicy @($policy) -SecOpsOverridePolicy @($override)
            $expected = 'MDO-006|Pass|normalized=True|golive=True|reason=|evidence=Get-ReportSubmissionPolicy; Get-SecOpsOverridePolicy:MDO-006'

            # Act
            $result = Test-ReportSubmissionControl -Evidence $configured -DesiredState $script:DesiredReportSubmission -SecOpsMailbox $script:DesiredSecOpsMailbox

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'the declared SmtpAddress comparison trims, strips the routing prefix, lowers the casing and collapses the duplicate that produces, so the tenant Exchange Online reports back in its own formatting is the same tenant the baseline asked for; the verdict has to be one normalized pass naming the record it was decided from rather than a bare true'
        }
    }
}
