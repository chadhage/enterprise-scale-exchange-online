#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement is not installed and must never be imported. Both preset rule
    # cmdlets are reached only through the supplied collection seams, so every collection here is
    # a scriptblock returning canned rules or throwing a canned failure.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # Assigning before unrolling matters: the registry is returned as one read-only collection
    # deliberately protected from pipeline unrolling, so it is read by index rather than by pipe.
    $script:ControlRegistry = @(Get-BaselineControlRegistry)[0]
    $script:StrictPresetRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'MDO-002') { $entry }
        })[0]

    # The name Exchange Online gives the rule the Strict preset is applied through.
    $script:StrictRuleName = 'Strict Preset Security Policy'

    function New-StrictRule {
        [CmdletBinding()]
        param(
            [object]$Name = $script:StrictRuleName,

            [object]$State = 'Enabled',

            [object]$SentToMemberOf = @('priority-users@contoso.com'),

            [object]$SentTo = @(),

            [object]$RecipientDomainIs = @()
        )

        return [pscustomobject]@{
            Name              = $Name
            State             = $State
            SentToMemberOf    = $SentToMemberOf
            SentTo            = $SentTo
            RecipientDomainIs = $RecipientDomainIs
            Priority          = 0
        }
    }

    function New-StrictPresetEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [object]$EopRule,

            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [object]$AtpRule
        )

        return Get-StrictPresetEvidence `
            -EopRuleCollection { $EopRule }.GetNewClosure() `
            -AtpRuleCollection { $AtpRule }.GetNewClosure()
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

    # MDO-001: the Strict preset is targeted rather than scoped-and-excluded. It reaches the one
    # mail-enabled priority group the baseline resolves and nobody else, so the two remaining
    # targeting members are compared against nothing at all.
    $script:DesiredStrictPreset = [pscustomobject]@{
        enabled    = $true
        scopeGroup = 'priority-users@contoso.com'
    }

    # The declared Group comparison resolves a group to its primary SMTP address, which cannot be
    # done offline, so every test supplies the resolution as a seam. This one resolves the one
    # mail-enabled group the baseline names and passes an address through unchanged.
    $script:GroupResolver = {
        param($Value)

        if ($Value -like '*@*') { return [string]$Value }
        if ($Value -ceq 'Priority Users') { return 'priority-users@contoso.com' }

        return $null
    }

    function New-StrictRuleWithout {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Member
        )

        $rule = [ordered]@{
            Name              = $script:StrictRuleName
            State             = 'Enabled'
            SentToMemberOf    = @('priority-users@contoso.com')
            SentTo            = @()
            RecipientDomainIs = @()
        }

        $rule.Remove($Member)

        return [pscustomobject]$rule
    }

    function New-PartialStrictPresetEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'MDO-002' -Source 'ExchangeOnline' `
            -Command 'Get-EOPProtectionPolicyRule; Get-ATPProtectionPolicyRule' -Value $Payload
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

Describe 'MDO-003-A1 Strict preset collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector MDO-002 is registered against' {
            # Arrange
            $registered = $script:StrictPresetRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes the Strict preset, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: the collector must be given both service calls to make' {

        It 'refuses a collection with no EOP protection policy rule to read' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-StrictPresetEvidence -EopRuleCollection $noCollection -AtpRuleCollection { @() } }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EopProtectionPolicyRuleCollectionRequired*' `
                    -Because 'the EOP rule is what applies the Strict preset to a priority user at all, and a record assembled without reading it reports a protected population nobody looked up'
        }

        It 'refuses a collection with no ATP protection policy rule to read' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-StrictPresetEvidence -EopRuleCollection { @() } -AtpRuleCollection $noCollection }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'AtpProtectionPolicyRuleCollectionRequired*' `
                    -Because 'the EOP half and the ATP half of the preset are targeted by two separate rules, so a record carrying only the first reports Safe Links and Safe Attachments coverage for the priority users it never observed'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records an EOP collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The term Get-EOPProtectionPolicyRule is not recognized in this session.' }

            # Act
            $evidence = Get-StrictPresetEvidence -EopRuleCollection $refusing -AtpRuleCollection { @(New-StrictRule) }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'an exception here discards every other control in the run, and a refused command that is not recorded as refused reads downstream exactly like a preset rule that was read and found correctly targeted'
        }

        It 'records an ATP collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The operation was throttled and could not be completed.' }

            # Act
            $evidence = Get-StrictPresetEvidence -EopRuleCollection { @(New-StrictRule) } -AtpRuleCollection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'half an observation is not an observation of the preset, and a record that keeps the half that succeeded lets a throttled tenant decide which half of the preset the priority users are held to'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a tenant that holds no preset rule at all as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-StrictPresetEvidence -EopRuleCollection $empty -AtpRuleCollection $empty

            # Assert
            ('collected={0}|failure={1}|{2}' -f $evidence.Collected, $evidence.FailureReason, (ConvertTo-CanonicalJson -InputObject $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|{"ATPProtectionPolicyRule":[],"EOPProtectionPolicyRule":[]}' `
                    -Because 'a tenant that has never turned the Strict preset on is the exact finding this control exists to report, and calling it a collection failure hides that finding behind an infrastructure excuse'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = New-StrictPresetEvidence -EopRule @(New-StrictRule -State 'Disabled') -AtpRule @(New-StrictRule)

            # Act
            $act = { $evidence.Value['EOPProtectionPolicyRule'] = @() }

            # Assert
            $act |
                Should -Throw `
                    -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one run of both collections is one record of exactly what each returned' {

        It 'records both rule sets whole under their own names, under the control, source and commands the registry declares' {
            # Arrange
            $strictRule = New-StrictRule -Name ' Strict Preset Security Policy ' -State 'enabled' -SentToMemberOf @('Priority Users')
            $standardRule = New-StrictRule -Name 'Standard Preset Security Policy' -SentToMemberOf @() -RecipientDomainIs @('contoso.com')
            $expected = 'MDO-002|ExchangeOnline|Get-EOPProtectionPolicyRule; Get-ATPProtectionPolicyRule|collected=True|failure=|' +
            '{"ATPProtectionPolicyRule":[{"Name":"Strict Preset Security Policy","Priority":0,"RecipientDomainIs":[],' +
            '"SentTo":[],"SentToMemberOf":["priority-users@contoso.com"],"State":"Enabled"}],' +
            '"EOPProtectionPolicyRule":[{"Name":" Strict Preset Security Policy ","Priority":0,"RecipientDomainIs":[],' +
            '"SentTo":[],"SentToMemberOf":["Priority Users"],"State":"enabled"},' +
            '{"Name":"Standard Preset Security Policy","Priority":0,"RecipientDomainIs":["contoso.com"],' +
            '"SentTo":[],"SentToMemberOf":[],"State":"Enabled"}]}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = New-StrictPresetEvidence -EopRule @($strictRule, $standardRule) -AtpRule @(New-StrictRule)

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so both rule sets have to survive collection with their casing, their whitespace, their unresolved group display name and their unrelated sibling members intact, and the Standard preset rule sitting beside the Strict one has to survive too; a collector that filtered to the Strict rule or narrowed each rule to the members the control decides on would decide the targeting before the evaluator ever saw it'
        }
    }
}

Describe 'MDO-003-A2 Strict preset evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator MDO-002 is registered against' {
            # Arrange
            $registered = $script:StrictPresetRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides the Strict preset, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation, the group the baseline resolved and a way to resolve a group' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = { Test-StrictPresetControl -Evidence $noEvidence -DesiredState $script:DesiredStrictPreset -GroupResolver $script:GroupResolver }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceRequired*' `
                    -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'MDO-001' -Source 'ExchangeOnline' `
                -Command 'Get-EOPProtectionPolicyRule; Get-ATPProtectionPolicyRule' `
                -Value ([ordered]@{ EOPProtectionPolicyRule = @(New-StrictRule); ATPProtectionPolicyRule = @(New-StrictRule) })

            # Act
            $act = { Test-StrictPresetControl -Evidence $foreign -DesiredState $script:DesiredStrictPreset -GroupResolver $script:GroupResolver }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' `
                    -Because 'the Standard and the Strict preset are recorded by the same pair of commands under two controls with two desired states, so a record collected for one is exactly the record that must not decide the other'
        }

        It 'refuses a decision that names no resolved desired Strict preset state' {
            # Arrange
            $evidence = New-StrictPresetEvidence -EopRule @(New-StrictRule) -AtpRule @(New-StrictRule)

            # Act
            $act = { Test-StrictPresetControl -Evidence $evidence -DesiredState $null -GroupResolver $script:GroupResolver }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredStrictPresetStateRequired*' `
                    -Because 'an evaluator handed no desired state decides against whatever it defaults to rather than against what was approved'
        }

        It 'refuses a decision whose desired state resolves no priority group' {
            # Arrange
            $evidence = New-StrictPresetEvidence -EopRule @(New-StrictRule) -AtpRule @(New-StrictRule)
            $ungrouped = [pscustomobject]@{ enabled = $true }

            # Act
            $act = { Test-StrictPresetControl -Evidence $evidence -DesiredState $ungrouped -GroupResolver $script:GroupResolver }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredStrictPresetGroupRequired*' `
                    -Because 'the priority group is the entire target of the Strict preset, and comparing a tenant against no group at all passes exactly the tenant whose Strict rules reach nobody'
        }

        It 'refuses a decision with no way to resolve an observed group' {
            # Arrange
            $evidence = New-StrictPresetEvidence -EopRule @(New-StrictRule) -AtpRule @(New-StrictRule)

            # Act
            $act = { Test-StrictPresetControl -Evidence $evidence -DesiredState $script:DesiredStrictPreset -GroupResolver $null }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'StrictPresetGroupResolverRequired*' `
                    -Because 'Exchange Online reports the target as a display name while the baseline resolves it as a primary address, so comparing the two unresolved reads every correctly targeted tenant as drift'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-StrictPresetEvidence `
                -EopRuleCollection { throw 'The operation was throttled and could not be completed.' } `
                -AtpRuleCollection { @() }

            # Act
            $result = Test-StrictPresetControl -Evidence $refused -DesiredState $script:DesiredStrictPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a control the run never managed to observe must cost the run its go-live, because the alternative is that throttling the tenant is the cheapest way to pass it'
        }
    }

    Context 'Negative: a record that never observed a rule set decides nothing about it' {

        It 'decides a record carrying no <Observation> observation as an error' -ForEach @(
            @{ Observation = 'EOPProtectionPolicyRule'; Present = 'ATPProtectionPolicyRule' }
            @{ Observation = 'ATPProtectionPolicyRule'; Present = 'EOPProtectionPolicyRule' }
        ) {
            # Arrange
            $partial = New-PartialStrictPresetEvidence -Payload ([ordered]@{ $Present = @(New-StrictRule) })

            # Act
            $result = Test-StrictPresetControl -Evidence $partial -DesiredState $script:DesiredStrictPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=StrictPresetEvidenceIncomplete: the record carries no '$Observation' observation." `
                    -Because 'an absent rule set is not an observation that the tenant holds no such rule, and reading it as one decides half the preset from a command nobody ran'
        }

        It 'decides an observed rule carrying no <Member> member as an error' -ForEach @(
            @{ Member = 'Name' }
            @{ Member = 'State' }
            @{ Member = 'SentToMemberOf' }
            @{ Member = 'SentTo' }
            @{ Member = 'RecipientDomainIs' }
        ) {
            # Arrange
            $incomplete = New-StrictPresetEvidence -EopRule @(New-StrictRuleWithout -Member $Member) -AtpRule @(New-StrictRule)

            # Act
            $result = Test-StrictPresetControl -Evidence $incomplete -DesiredState $script:DesiredStrictPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=StrictPresetEvidenceIncomplete: an observed EOPProtectionPolicyRule carries no '$Member' member." `
                    -Because 'an absent target member read as empty reports a preset targeting nobody, which is indistinguishable from a rule the collector simply did not carry'
        }
    }

    Context 'Negative: a tenant that holds no Strict preset rule fails' {

        It 'fails a tenant whose <Observation> rules hold no Strict preset rule at all' -ForEach @(
            @{ Observation = 'EOPProtectionPolicyRule'; EopRule = @('standard'); AtpRule = @('strict') }
            @{ Observation = 'ATPProtectionPolicyRule'; EopRule = @('strict'); AtpRule = @() }
        ) {
            # Arrange
            # The comma keeps an empty rule set an empty array rather than letting it unroll to
            # nothing, which is the difference between a tenant holding no ATP rule and a caller
            # handing the collector no answer at all.
            $build = { param($Shape) , @(foreach ($item in $Shape) { if ($item -ceq 'strict') { New-StrictRule } else { New-StrictRule -Name 'Standard Preset Security Policy' } }) }
            $absent = New-StrictPresetEvidence -EopRule (& $build -Shape $EopRule) -AtpRule (& $build -Shape $AtpRule)

            # Act
            $result = Test-StrictPresetControl -Evidence $absent -DesiredState $script:DesiredStrictPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=StrictPresetDrift: the tenant holds no 'Strict Preset Security Policy' rule among the $Observation rules." `
                    -Because 'a tenant that never turned the Strict preset on is the default state of every tenant, so a control that reads a missing rule as anything other than a failure passes before anybody configures it'
        }
    }

    Context 'Negative: a Strict preset rule that is not enabled fails' {

        It 'fails a tenant whose <Observation> Strict rule is disabled, naming the rule and the state it holds' -ForEach @(
            @{ Observation = 'EOPProtectionPolicyRule'; DisableEop = $true }
            @{ Observation = 'ATPProtectionPolicyRule'; DisableEop = $false }
        ) {
            # Arrange
            $disabled = New-StrictPresetEvidence `
                -EopRule @(New-StrictRule -State $(if ($DisableEop) { 'Disabled' } else { 'Enabled' })) `
                -AtpRule @(New-StrictRule -State $(if ($DisableEop) { 'Enabled' } else { 'Disabled' }))

            # Act
            $result = Test-StrictPresetControl -Evidence $disabled -DesiredState $script:DesiredStrictPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=StrictPresetDrift: the $Observation rule 'Strict Preset Security Policy' is 'Disabled' where 'Enabled' is required." `
                    -Because 'a preset rule that exists but is switched off applies nothing to the priority users it names, and the two halves are switched independently, so a control that decides only the half it happens to read reports protection the tenant is not applying'
        }
    }

    Context 'Negative: a Strict preset rule targeting anything other than exactly the priority group fails' {

        It 'fails a rule that does not target the configured priority group' {
            # Arrange
            $untargeted = New-StrictPresetEvidence -EopRule @(New-StrictRule -SentToMemberOf @()) -AtpRule @(New-StrictRule)

            # Act
            $result = Test-StrictPresetControl -Evidence $untargeted -DesiredState $script:DesiredStrictPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=StrictPresetDrift: the EOPProtectionPolicyRule rule does not target 'SentToMemberOf' at 'priority-users@contoso.com'." `
                    -Because 'an enabled Strict rule that reaches nobody is the exact posture this control exists to catch, and a verdict that did not name the group leaves the operator nothing to act on'
        }

        It 'fails a rule that targets <Member> at a value the baseline never resolved' -ForEach @(
            @{ Member = 'SentToMemberOf'; Observed = @('priority-users@contoso.com', 'everyone@contoso.com'); Surplus = 'everyone@contoso.com' }
            @{ Member = 'SentTo'; Observed = @('contractor@contoso.com'); Surplus = 'contractor@contoso.com' }
            @{ Member = 'RecipientDomainIs'; Observed = @('contoso.com'); Surplus = 'contoso.com' }
        ) {
            # Arrange
            $argument = @{ $Member = $Observed }
            $widened = New-StrictPresetEvidence -EopRule @(New-StrictRule @argument) -AtpRule @(New-StrictRule)

            # Act
            $result = Test-StrictPresetControl -Evidence $widened -DesiredState $script:DesiredStrictPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=StrictPresetDrift: the EOPProtectionPolicyRule rule targets '$Member' at unapproved '$Surplus'." `
                    -Because 'the Strict preset is the most restrictive policy the tenant applies, so a rule stretched over a population nobody approved breaks mail for that population on an approval that was never given; the card requires exactly the priority group, not a superset of it'
        }

        It 'fails a tenant whose ATP rule alone targets the wrong population' {
            # Arrange
            $atpOnly = New-StrictPresetEvidence `
                -EopRule @(New-StrictRule) `
                -AtpRule @(New-StrictRule -SentToMemberOf @('everyone@contoso.com'))

            # Act
            $result = Test-StrictPresetControl -Evidence $atpOnly -DesiredState $script:DesiredStrictPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=StrictPresetDrift: the ATPProtectionPolicyRule rule does not target 'SentToMemberOf' at 'priority-users@contoso.com'; the ATPProtectionPolicyRule rule targets 'SentToMemberOf' at unapproved 'everyone@contoso.com'." `
                    -Because 'Safe Links and Safe Attachments are targeted by the ATP rule alone, so an evaluator that stops once the EOP rule agrees reports the priority users covered by a Strict policy that in fact reaches everybody but them'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-StrictPresetControl `
                -Evidence (New-StrictPresetEvidence -EopRule @(New-StrictRule -State 'Disabled') -AtpRule @(New-StrictRule)) `
                -DesiredState $script:DesiredStrictPreset -GroupResolver $script:GroupResolver

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act |
                Should -Throw `
                    -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: both Strict rules enabled and targeting exactly the priority group is one go-live-successful pass' {

        It 'passes a tenant whose Strict EOP and ATP rules are enabled and target exactly the priority group, ignoring the rules beside them' {
            # Arrange
            $strictRule = New-StrictRule -Name ' Strict Preset Security Policy ' -State 'enabled' `
                -SentToMemberOf @(' Priority Users ', 'Priority-Users@Contoso.com')
            $standardRule = New-StrictRule -Name 'Standard Preset Security Policy' -State 'Disabled' `
                -SentToMemberOf @('everyone@contoso.com') -SentTo @('ceo@contoso.com') -RecipientDomainIs @('contoso.com')
            $configured = New-StrictPresetEvidence -EopRule @($strictRule, $standardRule) -AtpRule @($standardRule, $strictRule)
            $expected = 'MDO-002|Pass|normalized=True|golive=True|reason=|evidence=Get-EOPProtectionPolicyRule; Get-ATPProtectionPolicyRule:MDO-002'

            # Act
            $result = Test-StrictPresetControl -Evidence $configured -DesiredState $script:DesiredStrictPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'the declared Group comparison trims, resolves a display name to its primary address, lowers the casing and collapses the duplicate that produces, so the tenant Exchange Online reports back in its own formatting is the same tenant the baseline asked for, and the Standard preset rule sitting beside the Strict one - disabled, aimed at everybody and exempting nothing - is a rule this control must leave entirely alone; the verdict has to be one normalized pass naming the record it was decided from rather than a bare true'
        }
    }
}
