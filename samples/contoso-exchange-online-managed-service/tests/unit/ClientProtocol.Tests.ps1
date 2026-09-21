#requires -Version 7.0

# Pester evaluates `-ForEach` during discovery, before any `BeforeAll` has run, so the observations
# EXO-009 is decided from, the members each observed entry is decided by, and the switches that can
# drift are declared here.
$ClientProtocolObservation = @('OrganizationConfig', 'CasMailboxPlan', 'CasMailbox')

$OrganizationDecidedMember = @('EwsEnabled', 'EwsAllowList')

$ScopedDecidedMember = @('Identity', 'EwsEnabled', 'EwsAllowList', 'PopEnabled', 'ImapEnabled')

$DesiredProtocolMember = @('ewsEnabled', 'ewsAllowList', 'popEnabledByDefault', 'imapEnabledByDefault')

$ProtocolSwitchDrift = @(
    @{ Observed = 'EwsEnabled'; Live = 'True'; Want = 'False' }
    @{ Observed = 'PopEnabled'; Live = 'True'; Want = 'False' }
    @{ Observed = 'ImapEnabled'; Live = 'True'; Want = 'False' }
)

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement is not installed and must never be imported. All three Exchange
    # Online commands EXO-009 depends on are reached only through supplied collection seams, so
    # every collection here is a scriptblock returning a canned payload or throwing a canned
    # failure and no request leaves this process.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # The registry is returned as one read-only collection deliberately protected from pipeline
    # unrolling, so the entry is read by index rather than by piping the collection.
    $script:ControlRegistry = @(Get-BaselineControlRegistry -Profile Historical)[0]
    $script:ClientProtocolRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'EXO-009') { $entry }
        })[0]

    function New-OrganizationConfigRecord {
        [CmdletBinding()]
        param(
            [object]$EwsEnabled = $false,

            [object]$EwsAllowList = @(),

            # A member EXO-009 decides nothing about, so a collector that narrowed the payload to
            # the members the control reads is distinguishable from one that recorded the answer.
            [object]$EwsApplicationAccessPolicy = 'EnforceAllowList'
        )

        return [pscustomobject]@{
            EwsEnabled                 = $EwsEnabled
            EwsAllowList               = $EwsAllowList
            EwsApplicationAccessPolicy = $EwsApplicationAccessPolicy
        }
    }

    function New-CasMailboxPlanRecord {
        [CmdletBinding()]
        param(
            [string]$Identity = 'ExchangeOnlineEnterprise',

            [object]$EwsEnabled = $false,

            [object]$EwsAllowList = @(),

            [object]$PopEnabled = $false,

            [object]$ImapEnabled = $false,

            [object]$OwaMailboxPolicy = 'OwaMailboxPolicy-Default'
        )

        return [pscustomobject]@{
            Identity         = $Identity
            EwsEnabled       = $EwsEnabled
            EwsAllowList     = $EwsAllowList
            PopEnabled       = $PopEnabled
            ImapEnabled      = $ImapEnabled
            OwaMailboxPolicy = $OwaMailboxPolicy
        }
    }

    function New-ClientAccessMailboxRecord {
        [CmdletBinding()]
        param(
            [string]$Identity = 'chief.executive@contoso.com',

            [object]$EwsEnabled = $false,

            [object]$EwsAllowList = @(),

            [object]$PopEnabled = $false,

            [object]$ImapEnabled = $false,

            [object]$ActiveSyncEnabled = $true
        )

        return [pscustomobject]@{
            Identity          = $Identity
            EwsEnabled        = $EwsEnabled
            EwsAllowList      = $EwsAllowList
            PopEnabled        = $PopEnabled
            ImapEnabled       = $ImapEnabled
            ActiveSyncEnabled = $ActiveSyncEnabled
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

    # The discovery-time copies of these lists are not in scope while a test runs, and a list that
    # read as empty would let every omission assert the same absence.
    $script:ObservationName = @('OrganizationConfig', 'CasMailboxPlan', 'CasMailbox')

    # The desired protocol state the baseline resolves, as `protocolRestriction` declares it. The
    # allow list is deliberately non-empty, because an empty desired list makes a surplus entry the
    # only drift a comparison can ever report.
    function New-DesiredProtocolState {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{}
        )

        $state = [pscustomobject][ordered]@{
            ewsEnabled           = $false
            ewsAllowList         = @('Outlook-iOS-Android')
            popEnabledByDefault  = $false
            imapEnabledByDefault = $false
        }

        foreach ($name in $Override.Keys) {
            $state.PSObject.Properties[$name].Value = $Override[$name]
        }

        return $state
    }

    function New-CompliantOrganization {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{}
        )

        $argument = @{ EwsEnabled = $false; EwsAllowList = @('Outlook-iOS-Android') }
        foreach ($name in $Override.Keys) { $argument[$name] = $Override[$name] }

        return New-OrganizationConfigRecord @argument
    }

    function New-CompliantPlan {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{}
        )

        $argument = @{
            Identity     = 'ExchangeOnlineEnterprise'
            EwsEnabled   = $false
            EwsAllowList = @('Outlook-iOS-Android')
            PopEnabled   = $false
            ImapEnabled  = $false
        }
        foreach ($name in $Override.Keys) { $argument[$name] = $Override[$name] }

        return New-CasMailboxPlanRecord @argument
    }

    function New-CompliantMailbox {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{}
        )

        $argument = @{
            Identity     = 'chief.executive@contoso.com'
            EwsEnabled   = $false
            EwsAllowList = @('Outlook-iOS-Android')
            PopEnabled   = $false
            ImapEnabled  = $false
        }
        foreach ($name in $Override.Keys) { $argument[$name] = $Override[$name] }

        return New-ClientAccessMailboxRecord @argument
    }

    # A tenant that satisfies EXO-009, with exactly one thing changed per negative, so a verdict a
    # negative produces cannot be explained by anything else in the fixture.
    function New-ClientProtocolEvidenceRecord {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [object]$OrganizationConfig,

            [AllowNull()]
            [AllowEmptyCollection()]
            [object[]]$CasMailboxPlan,

            [AllowNull()]
            [AllowEmptyCollection()]
            [object[]]$CasMailbox
        )

        if (-not $PSBoundParameters.ContainsKey('OrganizationConfig')) { $OrganizationConfig = New-CompliantOrganization }
        if (-not $PSBoundParameters.ContainsKey('CasMailboxPlan')) { $CasMailboxPlan = @(New-CompliantPlan) }
        if (-not $PSBoundParameters.ContainsKey('CasMailbox')) { $CasMailbox = @(New-CompliantMailbox) }

        return Get-ClientProtocolEvidence `
            -OrganizationConfigCollection { $OrganizationConfig }.GetNewClosure() `
            -CasMailboxPlanCollection { $CasMailboxPlan }.GetNewClosure() `
            -CasMailboxCollection { $CasMailbox }.GetNewClosure()
    }

    function New-PartialClientProtocolEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'EXO-009' -Source 'ExchangeOnline' `
            -Command 'Get-OrganizationConfig; Get-CASMailboxPlan; Get-CASMailbox' -Value $Payload
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

Describe 'EXO-009-A1 client-protocol collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector EXO-009 is registered against' {
            # Arrange
            $registered = $script:ClientProtocolRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes EXO-009, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: all three halves of the control must be given a service call to make' {

        It 'refuses a run with no organization configuration collection' {
            # Arrange
            $organization = $null

            # Act
            $act = {
                Get-ClientProtocolEvidence -OrganizationConfigCollection $organization `
                    -CasMailboxPlanCollection { @() } -CasMailboxCollection { @() }
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OrganizationConfigCollectionRequired*' `
                    -Because 'the historical configuration comparison requires both declared properties; a dormant list does not reopen organization-disabled EWS'
        }

        It 'refuses a run with no mailbox plan collection' {
            # Arrange
            $plan = $null

            # Act
            $act = {
                Get-ClientProtocolEvidence -OrganizationConfigCollection { New-OrganizationConfigRecord } `
                    -CasMailboxPlanCollection $plan -CasMailboxCollection { @() }
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'CasMailboxPlanCollectionRequired*' `
                -Because 'the mailbox plan decides the protocols every mailbox created after today is born with, so a record with no plan view proves nothing about the tenant a week from now'
        }

        It 'refuses a run with no client access mailbox collection' {
            # Arrange
            $mailbox = $null

            # Act
            $act = {
                Get-ClientProtocolEvidence -OrganizationConfigCollection { New-OrganizationConfigRecord } `
                    -CasMailboxPlanCollection { @() } -CasMailboxCollection $mailbox
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'CasMailboxCollectionRequired*' `
                -Because 'hardening the plan changes nothing for a mailbox that already exists, so every mailbox created before the plan was hardened keeps POP and IMAP - and a record with no mailbox view is exactly the read the shipping script already makes'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records an organization configuration collection that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The term Get-OrganizationConfig is not recognized in this session.' }

            # Act
            $evidence = Get-ClientProtocolEvidence -OrganizationConfigCollection $refusing `
                -CasMailboxPlanCollection { @() } -CasMailboxCollection { @() }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'a command that never answered proves nothing about the protocol surface, and a refusal that is not recorded as a refusal reads downstream exactly like a tenant that was read and found closed'
        }

        It 'records a mailbox plan collection that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The operation could not be completed because the connection was closed.' }

            # Act
            $evidence = Get-ClientProtocolEvidence -OrganizationConfigCollection { New-OrganizationConfigRecord } `
                -CasMailboxPlanCollection $refusing -CasMailboxCollection { @() }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'a record assembled from two of the three sources reports a protocol posture that silently excludes the third, and the excluded one always reads as compliant'
        }

        It 'records a client access mailbox collection that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The operation was throttled and could not be completed.' }

            # Act
            $evidence = Get-ClientProtocolEvidence -OrganizationConfigCollection { New-OrganizationConfigRecord } `
                -CasMailboxPlanCollection { @() } -CasMailboxCollection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'enumerating every mailbox is the call this control is throttled on most, and it is the one observation the shipping script never makes, so a half-read tenant recorded as a whole one reports that no existing mailbox holds a legacy protocol because nobody managed to look'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a collection where all three commands returned nothing as collected' {
            # Arrange
            $silent = { }

            # Act
            $evidence = Get-ClientProtocolEvidence -OrganizationConfigCollection $silent `
                -CasMailboxPlanCollection $silent -CasMailboxCollection $silent

            # Assert
            ('collected={0}|failure={1}|{2}' -f $evidence.Collected, $evidence.FailureReason, (ConvertTo-CanonicalJson -InputObject $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|{"CasMailbox":[],"CasMailboxPlan":[],"OrganizationConfig":null}' `
                    -Because 'a tenant that holds no mailbox answers the third call with nothing, and that is an observation the evaluator decides rather than an infrastructure failure to hide the control behind'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = Get-ClientProtocolEvidence `
                -OrganizationConfigCollection { New-OrganizationConfigRecord -EwsEnabled $true } `
                -CasMailboxPlanCollection { New-CasMailboxPlanRecord } `
                -CasMailboxCollection { New-ClientAccessMailboxRecord -PopEnabled $true }

            # Act
            $act = { $evidence.Value['CasMailbox'] = @() }

            # Assert
            $act | Should -Throw `
                -Because 'raw evidence a caller can rewrite is not evidence of which mailboxes still speak a legacy protocol, it is evidence of which ones the caller wanted to speak one'
        }
    }

    Context 'Positive: one collection of all three sources is one record of exactly what the services returned' {

        It 'records all three observations under the control, source and commands the registry declares' {
            # Arrange
            $organization = { New-OrganizationConfigRecord -EwsEnabled $false -EwsAllowList @('Outlook-iOS-Android') }
            $plan = {
                New-CasMailboxPlanRecord -Identity 'ExchangeOnlineEnterprise'
                New-CasMailboxPlanRecord -Identity 'ExchangeOnlineDeskless' -PopEnabled $true
            }
            $mailbox = {
                New-ClientAccessMailboxRecord -Identity 'chief.executive@contoso.com'
                New-ClientAccessMailboxRecord -Identity 'scanner@contoso.com' -ImapEnabled $true -EwsAllowList @(' Scanner-Agent ')
            }
            $expected = 'EXO-009|ExchangeOnline|Get-OrganizationConfig; Get-CASMailboxPlan; Get-CASMailbox|collected=True|failure=|' +
            '{"CasMailbox":[{"ActiveSyncEnabled":true,"EwsAllowList":[],"EwsEnabled":false,"Identity":"chief.executive@contoso.com","ImapEnabled":false,"PopEnabled":false},' +
            '{"ActiveSyncEnabled":true,"EwsAllowList":[" Scanner-Agent "],"EwsEnabled":false,"Identity":"scanner@contoso.com","ImapEnabled":true,"PopEnabled":false}],' +
            '"CasMailboxPlan":[{"EwsAllowList":[],"EwsEnabled":false,"Identity":"ExchangeOnlineEnterprise","ImapEnabled":false,"OwaMailboxPolicy":"OwaMailboxPolicy-Default","PopEnabled":false},' +
            '{"EwsAllowList":[],"EwsEnabled":false,"Identity":"ExchangeOnlineDeskless","ImapEnabled":false,"OwaMailboxPolicy":"OwaMailboxPolicy-Default","PopEnabled":true}],' +
            '"OrganizationConfig":{"EwsAllowList":["Outlook-iOS-Android"],"EwsApplicationAccessPolicy":"EnforceAllowList","EwsEnabled":false}}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = Get-ClientProtocolEvidence -OrganizationConfigCollection $organization `
                -CasMailboxPlanCollection $plan -CasMailboxCollection $mailbox

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so a compliant plan has to survive collection beside the one that enables POP and a compliant mailbox beside the one that enables IMAP: a collector that filtered to the plans and mailboxes holding a legacy protocol would make a tenant nobody enumerated indistinguishable from a closed one, one that narrowed each entry to the members the control decides on would drop the identity every failure has to name and the untrimmed allow-list entry the evaluator has to normalize itself, and one that folded the three observations into a verdict would decide the control before any evaluator saw it'
        }
    }
}

Describe 'EXO-009-A2 client-protocol evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator EXO-009 is registered against' {
            # Arrange
            $registered = $script:ClientProtocolRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides EXO-009, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation to decide' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $absent = $null

            # Act
            $act = { Test-ClientProtocolControl -Evidence $absent -DesiredState (New-DesiredProtocolState) }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceRequired*' `
                -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-CASMailbox' `
                -Value ([pscustomobject]@{ Identity = 'scanner@contoso.com'; SmtpClientAuthenticationDisabled = $false })

            # Act
            $act = { Test-ClientProtocolControl -Evidence $foreign -DesiredState (New-DesiredProtocolState) }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' `
                -Because 'EXO-002 enumerates the same mailboxes for a different member, so a record that looks close enough decides this control from protocol settings nobody observed'
        }
    }

    Context 'Negative: the evaluator must be given the desired state to decide against' {

        It 'refuses a decision with no resolved desired protocol state' {
            # Arrange
            $unresolved = $null

            # Act
            $act = { Test-ClientProtocolControl -Evidence (New-ClientProtocolEvidenceRecord) -DesiredState $unresolved }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DesiredProtocolStateRequired*' `
                -Because 'an evaluator with no desired state decides the protocol surface against whatever it defaults to rather than against what the baseline resolved, and the default that flatters the tenant is the one nobody notices'
        }

        It "refuses a decision whose desired state resolves no '<_>' value" -ForEach $DesiredProtocolMember {
            # Arrange
            $partial = New-DesiredProtocolState
            $partial.PSObject.Properties.Remove($_)

            # Act
            $act = { Test-ClientProtocolControl -Evidence (New-ClientProtocolEvidenceRecord) -DesiredState $partial }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DesiredProtocolMemberRequired*' `
                -Because 'three protocols compared against the baseline and a fourth compared against nothing is reported as a fully compared tenant, and the protocol the resolution forgot is the one still open'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-ClientProtocolEvidence -OrganizationConfigCollection { New-CompliantOrganization } `
                -CasMailboxPlanCollection { @() } `
                -CasMailboxCollection { throw 'The operation was throttled and could not be completed.' }

            # Act
            $result = Test-ClientProtocolControl -Evidence $refused -DesiredState (New-DesiredProtocolState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a tenant the run never managed to read must cost the run its go-live, because the alternative is that a throttled mailbox enumeration is the cheapest way to pass this control'
        }
    }

    Context 'Negative: a record that carries only part of itself decides nothing about the rest' {

        It "decides a record carrying no '<_>' observation as an error" -ForEach $ClientProtocolObservation {
            # Arrange
            $observation = [ordered]@{}
            foreach ($name in $script:ObservationName) {
                if ($name -cne $_) { $observation[$name] = @() }
            }
            $partial = New-PartialClientProtocolEvidence -Payload $observation

            # Act
            $result = Test-ClientProtocolControl -Evidence $partial -DesiredState (New-DesiredProtocolState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=ClientProtocolEvidenceIncomplete: the record carries no '$_' observation." `
                    -Because 'an observation that is absent is not an observation of nothing, and read as one it reports a closed protocol surface from a source nobody read'
        }

        It "decides an observed organization configuration carrying no '<_>' member as an error" -ForEach $OrganizationDecidedMember {
            # Arrange
            $organization = New-CompliantOrganization
            $organization.PSObject.Properties.Remove($_)
            $incomplete = New-ClientProtocolEvidenceRecord -OrganizationConfig $organization

            # Act
            $result = Test-ClientProtocolControl -Evidence $incomplete -DesiredState (New-DesiredProtocolState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=ClientProtocolEvidenceIncomplete: the observed organization configuration carries no '$_' member." `
                    -Because 'an absent EWS switch read as off reports a closed tenant from a value nobody read, and an absent allow list read as empty reports that no application was exempted from a switch that may not even be on'
        }

        It "decides an observed mailbox plan carrying no '<_>' member as an error" -ForEach $ScopedDecidedMember {
            # Arrange
            $plan = New-CompliantPlan
            $plan.PSObject.Properties.Remove($_)
            $incomplete = New-ClientProtocolEvidenceRecord -CasMailboxPlan @($plan)

            # Act
            $result = Test-ClientProtocolControl -Evidence $incomplete -DesiredState (New-DesiredProtocolState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=ClientProtocolEvidenceIncomplete: an observed mailbox plan carries no '$_' member." `
                    -Because 'a plan with no protocol member cannot be told apart from one that has it switched off, and a plan with no identity cannot be named in the failure that would have it hardened'
        }

        It "decides an observed mailbox carrying no '<_>' member as an error" -ForEach $ScopedDecidedMember {
            # Arrange
            $mailbox = New-CompliantMailbox
            $mailbox.PSObject.Properties.Remove($_)
            $incomplete = New-ClientProtocolEvidenceRecord -CasMailbox @($mailbox)

            # Act
            $result = Test-ClientProtocolControl -Evidence $incomplete -DesiredState (New-DesiredProtocolState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=ClientProtocolEvidenceIncomplete: an observed mailbox carries no '$_' member." `
                    -Because 'the existing mailboxes are the half of this control nobody collects today, so an incomplete answer about them read as a compliant one restores exactly the gap the card exists to close'
        }
    }

    Context 'Negative: an organization that has not closed the tenant-wide protocol surface fails' {

        It 'fails an organization whose EWS state differs from the resolved desired state' {
            # Arrange
            $open = New-ClientProtocolEvidenceRecord -OrganizationConfig (New-CompliantOrganization -Override @{ EwsEnabled = $true })

            # Act
            $result = Test-ClientProtocolControl -Evidence $open -DesiredState (New-DesiredProtocolState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=LegacyProtocolOpen: the organization reports 'EwsEnabled' as 'True' where the baseline requires 'False'." `
                    -Because 'EWS is the protocol that reads a whole mailbox over one authenticated session, and an organization that leaves it on has granted that to every application the allow list does not stop'
        }

        It 'fails an organization EWS allow list holding an entry the baseline does not declare' {
            # Arrange
            $exempted = New-ClientProtocolEvidenceRecord -OrganizationConfig (New-CompliantOrganization -Override @{
                    EwsAllowList = @('Outlook-iOS-Android', 'Legacy-CRM')
                })

            # Act
            $result = Test-ClientProtocolControl -Evidence $exempted -DesiredState (New-DesiredProtocolState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=LegacyProtocolOpen: the EWS allow list of the organization holds 'legacy-crm' which the baseline does not declare." `
                    -Because 'a surplus dormant user-agent entry is historical configuration drift, not an exception to organization disablement'
        }

        It 'fails an organization EWS allow list that does not hold an entry the baseline declares' {
            # Arrange
            $narrowed = New-ClientProtocolEvidenceRecord -OrganizationConfig (New-CompliantOrganization -Override @{ EwsAllowList = @() })

            # Act
            $result = Test-ClientProtocolControl -Evidence $narrowed -DesiredState (New-DesiredProtocolState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=LegacyProtocolOpen: the EWS allow list of the organization does not hold 'outlook-ios-android'." `
                    -Because 'the allow list is exact desired state in both directions, and an approved application silently missing from it is a tenant nobody configured rather than one configured more tightly than asked'
        }
    }

    Context 'Negative: a mailbox plan that differs from the resolved desired state fails, naming the plan' {

        It "fails a mailbox plan whose '<Observed>' differs from the resolved desired state" -ForEach $ProtocolSwitchDrift {
            # Arrange
            $drifted = New-ClientProtocolEvidenceRecord -CasMailboxPlan @(
                New-CompliantPlan
                New-CompliantPlan -Override @{ Identity = 'ExchangeOnlineDeskless'; $Observed = $true }
            )

            # Act
            $result = Test-ClientProtocolControl -Evidence $drifted -DesiredState (New-DesiredProtocolState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly ("Fail|golive=False|reason=LegacyProtocolOpen: mailbox plan 'ExchangeOnlineDeskless' reports '$Observed' as '$Live' where the baseline requires '$Want'.") `
                    -Because 'a tenant holds a plan per licence and only one of them is ever hardened, so a control that decided the first plan would pass a tenant where every mailbox created under the second is born speaking a legacy protocol'
        }

        It 'fails a mailbox plan whose EWS allow list differs from the resolved desired state, naming the plan' {
            # Arrange
            $drifted = New-ClientProtocolEvidenceRecord -CasMailboxPlan @(
                New-CompliantPlan -Override @{ Identity = 'ExchangeOnlineDeskless'; EwsAllowList = @('Outlook-iOS-Android', 'Legacy-CRM') }
            )

            # Act
            $result = Test-ClientProtocolControl -Evidence $drifted -DesiredState (New-DesiredProtocolState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=LegacyProtocolOpen: the EWS allow list of mailbox plan 'ExchangeOnlineDeskless' holds 'legacy-crm' which the baseline does not declare." `
                    -Because 'the allow list is settable per plan as well as tenant-wide, so a plan-level exemption reopens EWS for every mailbox born under it while the organization switch still reads as closed'
        }
    }

    Context 'Negative: an existing mailbox that differs from the resolved desired state fails, naming the mailbox' {

        It "fails an existing mailbox whose '<Observed>' differs from the resolved desired state" -ForEach $ProtocolSwitchDrift {
            # Arrange
            $drifted = New-ClientProtocolEvidenceRecord -CasMailbox @(
                New-CompliantMailbox
                New-CompliantMailbox -Override @{ Identity = 'scanner@contoso.com'; $Observed = $true }
            )

            # Act
            $result = Test-ClientProtocolControl -Evidence $drifted -DesiredState (New-DesiredProtocolState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly ("Fail|golive=False|reason=LegacyProtocolOpen: mailbox 'scanner@contoso.com' reports '$Observed' as '$Live' where the baseline requires '$Want'.") `
                    -Because 'hardening the plan changes nothing for a mailbox that already exists, so this is the drift the shipping script cannot see at all and the reason a tenant with clean plans still hands a legacy protocol to every mailbox created before somebody cleaned them'
        }

        It 'fails an existing mailbox whose EWS allow list differs from the resolved desired state, naming the mailbox' {
            # Arrange
            $drifted = New-ClientProtocolEvidenceRecord -CasMailbox @(
                New-CompliantMailbox -Override @{ Identity = 'scanner@contoso.com'; EwsAllowList = @() }
            )

            # Act
            $result = Test-ClientProtocolControl -Evidence $drifted -DesiredState (New-DesiredProtocolState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=LegacyProtocolOpen: the EWS allow list of mailbox 'scanner@contoso.com' does not hold 'outlook-ios-android'." `
                    -Because 'a per-mailbox allow list overrides the tenant-wide one for that mailbox, so the allow list has to be decided on every mailbox rather than once on the organization'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-ClientProtocolControl `
                -Evidence (New-ClientProtocolEvidenceRecord -CasMailbox @(New-CompliantMailbox -Override @{ PopEnabled = $true })) `
                -DesiredState (New-DesiredProtocolState)

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act | Should -Throw -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: the organization, every plan and every existing mailbox holding the resolved desired state is one go-live-successful pass' {

        It 'passes a tenant whose organization, mailbox plans and existing mailboxes all hold the protocol state the baseline resolved' {
            # Arrange
            $restricted = New-ClientProtocolEvidenceRecord `
                -OrganizationConfig (New-CompliantOrganization -Override @{ EwsAllowList = @(' Outlook-iOS-Android ') }) `
                -CasMailboxPlan @(
                New-CompliantPlan
                New-CompliantPlan -Override @{ Identity = 'ExchangeOnlineDeskless'; EwsAllowList = @('OUTLOOK-IOS-ANDROID') }
            ) `
                -CasMailbox @(
                New-CompliantMailbox
                New-CompliantMailbox -Override @{ Identity = 'scanner@contoso.com'; EwsAllowList = @('outlook-ios-android', 'Outlook-iOS-Android') }
            )
            $expected = 'EXO-009|Pass|normalized=True|golive=True|reason=|evidence=Get-OrganizationConfig; Get-CASMailboxPlan; Get-CASMailbox:EXO-009'

            # Act
            $result = Test-ClientProtocolControl -Evidence $restricted -DesiredState (New-DesiredProtocolState)

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'all four values have to hold at once on all three scopes, proved here over a second mailbox plan and a second existing mailbox beside the first, whose allow lists differ from the baseline only in casing, in surrounding whitespace and in a repeated entry - none of which is drift, and a comparison that read any of them as drift would fail a correctly configured tenant; the verdict has to be one normalized go-live-successful pass naming the record it was decided from rather than a bare true'
        }
    }
}
