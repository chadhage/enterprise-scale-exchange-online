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
    $script:ControlRegistry = @(Get-BaselineControlRegistry -Profile Historical)[0]
    $script:StandardPresetRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'MDO-001') { $entry }
        })[0]

    # The name Exchange Online gives the rule the Standard preset is applied through. A tenant
    # holds preset rules beside every custom rule it has ever created, so the name is what
    # separates the rule this control decides from the rules it must leave alone.
    $script:StandardRuleName = 'Standard Preset Security Policy'

    function New-PresetRule {
        [CmdletBinding()]
        param(
            [object]$Name = $script:StandardRuleName,

            [object]$State = 'Enabled',

            [object]$RecipientDomainIs = @('contoso.com'),

            [object]$ExceptIfSentToMemberOf = @('priority-users@contoso.com'),

            [object]$ExceptIfSentTo = @('secops@contoso.com')
        )

        return [pscustomobject]@{
            Name                   = $Name
            State                  = $State
            RecipientDomainIs      = $RecipientDomainIs
            ExceptIfSentToMemberOf = $ExceptIfSentToMemberOf
            ExceptIfSentTo         = $ExceptIfSentTo
            Priority               = 0
        }
    }

    function New-StandardPresetEvidence {
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

        return Get-StandardPresetEvidence `
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

    # MDO-001: the Standard preset scope the baseline resolves. `scope` is the prose name the
    # document gives the arrangement; the three collections below are what the rules are compared
    # against, member by member.
    $script:DesiredStandardPreset = [pscustomobject]@{
        enabled               = $true
        scope                 = 'AllRecipientsExceptStrictAndSecOps'
        sentToDomains         = @('contoso.com')
        excludedGroups        = @('priority-users@contoso.com')
        excludedSecOpsMailbox = @('secops@contoso.com')
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

    function New-PresetRuleWithout {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Member
        )

        $rule = [ordered]@{
            Name                   = $script:StandardRuleName
            State                  = 'Enabled'
            RecipientDomainIs      = @('contoso.com')
            ExceptIfSentToMemberOf = @('priority-users@contoso.com')
            ExceptIfSentTo         = @('secops@contoso.com')
        }

        $rule.Remove($Member)

        return [pscustomobject]$rule
    }

    function New-PartialStandardPresetEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'MDO-001' -Source 'ExchangeOnline' `
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

Describe 'MDO-002-A1 Standard preset collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector MDO-001 is registered against' {
            # Arrange
            $registered = $script:StandardPresetRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes the Standard preset, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: the collector must be given both service calls to make' {

        It 'refuses a collection with no EOP protection policy rule to read' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-StandardPresetEvidence -EopRuleCollection $noCollection -AtpRuleCollection { @() } }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EopProtectionPolicyRuleCollectionRequired*' `
                    -Because 'the EOP rule is what applies the Standard preset to a recipient at all, and a record assembled without reading it reports a preset scope nobody looked up'
        }

        It 'refuses a collection with no ATP protection policy rule to read' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-StandardPresetEvidence -EopRuleCollection { @() } -AtpRuleCollection $noCollection }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'AtpProtectionPolicyRuleCollectionRequired*' `
                    -Because 'the EOP half and the ATP half of the preset are scoped by two separate rules, so a record carrying only the first reports Safe Links and Safe Attachments coverage it never observed'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records an EOP collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The term Get-EOPProtectionPolicyRule is not recognized in this session.' }

            # Act
            $evidence = Get-StandardPresetEvidence -EopRuleCollection $refusing -AtpRuleCollection { @(New-PresetRule) }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'an exception here discards every other control in the run, and a refused command that is not recorded as refused reads downstream exactly like a preset rule that was read and found correctly scoped'
        }

        It 'records an ATP collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The operation was throttled and could not be completed.' }

            # Act
            $evidence = Get-StandardPresetEvidence -EopRuleCollection { @(New-PresetRule) } -AtpRuleCollection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'half an observation is not an observation of the preset, and a record that keeps the half that succeeded lets a throttled tenant decide which half of the preset the run is held to'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a tenant that holds no preset rule at all as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-StandardPresetEvidence -EopRuleCollection $empty -AtpRuleCollection $empty

            # Assert
            ('collected={0}|failure={1}|{2}' -f $evidence.Collected, $evidence.FailureReason, (ConvertTo-CanonicalJson -InputObject $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|{"ATPProtectionPolicyRule":[],"EOPProtectionPolicyRule":[]}' `
                    -Because 'a tenant that has never turned the Standard preset on is the exact finding this control exists to report, and calling it a collection failure hides that finding behind an infrastructure excuse'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = New-StandardPresetEvidence -EopRule @(New-PresetRule -State 'Disabled') -AtpRule @(New-PresetRule)

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
            $eopRule = New-PresetRule -Name ' Standard Preset Security Policy ' -State 'enabled' `
                -RecipientDomainIs @('Contoso.COM') -ExceptIfSentToMemberOf @('Priority-Users@contoso.com') -ExceptIfSentTo @('SMTP:SecOps@Contoso.com')
            $customRule = New-PresetRule -Name 'Marketing bulk exemption' -RecipientDomainIs @('fabrikam.example')
            $expected = 'MDO-001|ExchangeOnline|Get-EOPProtectionPolicyRule; Get-ATPProtectionPolicyRule|collected=True|failure=|' +
            '{"ATPProtectionPolicyRule":[{"ExceptIfSentTo":["secops@contoso.com"],"ExceptIfSentToMemberOf":["priority-users@contoso.com"],' +
            '"Name":"Standard Preset Security Policy","Priority":0,"RecipientDomainIs":["contoso.com"],"State":"Enabled"}],' +
            '"EOPProtectionPolicyRule":[{"ExceptIfSentTo":["SMTP:SecOps@Contoso.com"],"ExceptIfSentToMemberOf":["Priority-Users@contoso.com"],' +
            '"Name":" Standard Preset Security Policy ","Priority":0,"RecipientDomainIs":["Contoso.COM"],"State":"enabled"},' +
            '{"ExceptIfSentTo":["secops@contoso.com"],"ExceptIfSentToMemberOf":["priority-users@contoso.com"],' +
            '"Name":"Marketing bulk exemption","Priority":0,"RecipientDomainIs":["fabrikam.example"],"State":"Enabled"}]}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = New-StandardPresetEvidence -EopRule @($eopRule, $customRule) -AtpRule @(New-PresetRule)

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so both rule sets have to survive collection with their casing, their whitespace, their routing prefix and their unrelated sibling members intact, and the custom rule beside the preset rule has to survive too; a collector that filtered to the preset rule or narrowed each rule to the members the control decides on would decide the scope before the evaluator ever saw it'
        }
    }
}

Describe 'MDO-002-A2 Standard preset evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator MDO-001 is registered against' {
            # Arrange
            $registered = $script:StandardPresetRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides the Standard preset, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation, the scope the baseline resolved and a way to resolve a group' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = { Test-StandardPresetControl -Evidence $noEvidence -DesiredState $script:DesiredStandardPreset -GroupResolver $script:GroupResolver }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceRequired*' `
                    -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'MDO-002' -Source 'ExchangeOnline' -Command 'Get-EOPProtectionPolicyRule' -Value @(New-PresetRule)

            # Act
            $act = { Test-StandardPresetControl -Evidence $foreign -DesiredState $script:DesiredStandardPreset -GroupResolver $script:GroupResolver }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' `
                    -Because 'the Standard and Strict presets are scoped by rules of the same shape, so deciding one from the other reports a preset scope that was never looked at for this control'
        }

        It 'refuses a decision that names no resolved desired Standard preset state' {
            # Arrange
            $evidence = New-StandardPresetEvidence -EopRule @(New-PresetRule) -AtpRule @(New-PresetRule)

            # Act
            $act = { Test-StandardPresetControl -Evidence $evidence -DesiredState $null -GroupResolver $script:GroupResolver }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredStandardPresetStateRequired*' `
                    -Because 'the card demands the live scope exactly match the resolved desired state, and an evaluator handed no desired state decides against whatever it defaults to rather than against what was approved'
        }

        It 'refuses a decision whose desired state resolves no domain scope' {
            # Arrange
            $evidence = New-StandardPresetEvidence -EopRule @(New-PresetRule) -AtpRule @(New-PresetRule)
            $unscoped = [pscustomobject]@{ sentToDomains = @(); excludedGroups = @(); excludedSecOpsMailbox = @() }

            # Act
            $act = { Test-StandardPresetControl -Evidence $evidence -DesiredState $unscoped -GroupResolver $script:GroupResolver }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredStandardPresetScopeRequired*' `
                    -Because 'a preset scoped to no domain at all protects nobody, and comparing a tenant against an empty scope passes exactly the tenant that has turned the preset off for everyone'
        }

        It 'refuses a decision with no way to resolve an observed group' {
            # Arrange
            $evidence = New-StandardPresetEvidence -EopRule @(New-PresetRule) -AtpRule @(New-PresetRule)

            # Act
            $act = { Test-StandardPresetControl -Evidence $evidence -DesiredState $script:DesiredStandardPreset -GroupResolver $null }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'StandardPresetGroupResolverRequired*' `
                    -Because 'the declared Group comparison resolves a group to its primary SMTP address, and comparing an unresolved display name against a resolved address reads every correctly excluded group as drift'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-StandardPresetEvidence -EopRuleCollection { throw 'The operation was throttled and could not be completed.' } -AtpRuleCollection { @() }

            # Act
            $result = Test-StandardPresetControl -Evidence $refused -DesiredState $script:DesiredStandardPreset -GroupResolver $script:GroupResolver

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
            $partial = New-PartialStandardPresetEvidence -Payload ([ordered]@{ $Present = @(New-PresetRule) })

            # Act
            $result = Test-StandardPresetControl -Evidence $partial -DesiredState $script:DesiredStandardPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=StandardPresetEvidenceIncomplete: the record carries no '$Observation' observation." `
                    -Because 'an absent rule set is not an observation that the tenant holds no such rule, and reading it as one decides half the preset from a command nobody ran'
        }

        It 'decides an observed rule carrying no <Member> member as an error' -ForEach @(
            @{ Member = 'Name' }
            @{ Member = 'State' }
            @{ Member = 'RecipientDomainIs' }
            @{ Member = 'ExceptIfSentToMemberOf' }
            @{ Member = 'ExceptIfSentTo' }
        ) {
            # Arrange
            $incomplete = New-StandardPresetEvidence -EopRule @(New-PresetRuleWithout -Member $Member) -AtpRule @(New-PresetRule)

            # Act
            $result = Test-StandardPresetControl -Evidence $incomplete -DesiredState $script:DesiredStandardPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=StandardPresetEvidenceIncomplete: an observed EOPProtectionPolicyRule carries no '$Member' member." `
                    -Because 'an absent member read as empty reports a preset scoped to nothing and excluding nobody, which is indistinguishable from a rule the collector simply did not carry'
        }
    }

    Context 'Negative: a group the run cannot resolve is not a group the run may pass' {

        It 'decides an unresolvable observed group as an error' {
            # Arrange
            $unresolvable = New-StandardPresetEvidence `
                -EopRule @(New-PresetRule -ExceptIfSentToMemberOf @('Legacy Distribution List')) `
                -AtpRule @(New-PresetRule)

            # Act
            $result = Test-StandardPresetControl -Evidence $unresolvable -DesiredState $script:DesiredStandardPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvaluatorThrew:*UnresolvedCanonicalValue*' `
                    -Because 'a group nobody could resolve is an unknown exclusion, and treating an unknown exclusion as absent quietly passes a preset that exempts a population the run never identified'
        }
    }

    Context 'Negative: a tenant that holds no Standard preset rule fails' {

        It 'fails a tenant whose <Observation> rules hold no Standard preset rule at all' -ForEach @(
            @{ Observation = 'EOPProtectionPolicyRule'; EopRule = @('custom'); AtpRule = @('preset') }
            @{ Observation = 'ATPProtectionPolicyRule'; EopRule = @('preset'); AtpRule = @() }
        ) {
            # Arrange
            # The comma keeps an empty rule set an empty array rather than letting it unroll to
            # nothing, which is the difference between a tenant holding no ATP rule and a caller
            # handing the collector no answer at all.
            $build = { param($Shape) , @(foreach ($item in $Shape) { if ($item -ceq 'preset') { New-PresetRule } else { New-PresetRule -Name 'Marketing bulk exemption' } }) }
            $absent = New-StandardPresetEvidence -EopRule (& $build -Shape $EopRule) -AtpRule (& $build -Shape $AtpRule)

            # Act
            $result = Test-StandardPresetControl -Evidence $absent -DesiredState $script:DesiredStandardPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=StandardPresetDrift: the tenant holds no 'Standard Preset Security Policy' rule among the $Observation rules." `
                    -Because 'a tenant that never turned the preset on is the default state of every tenant, so a control that reads a missing rule as anything other than a failure passes before anybody configures it'
        }
    }

    Context 'Negative: a Standard preset rule that is not enabled fails' {

        It 'fails a tenant whose <Observation> Standard rule is disabled, naming the rule and the state it holds' -ForEach @(
            @{ Observation = 'EOPProtectionPolicyRule'; DisableEop = $true }
            @{ Observation = 'ATPProtectionPolicyRule'; DisableEop = $false }
        ) {
            # Arrange
            $disabled = New-StandardPresetEvidence `
                -EopRule @(New-PresetRule -State $(if ($DisableEop) { 'Disabled' } else { 'Enabled' })) `
                -AtpRule @(New-PresetRule -State $(if ($DisableEop) { 'Enabled' } else { 'Disabled' }))

            # Act
            $result = Test-StandardPresetControl -Evidence $disabled -DesiredState $script:DesiredStandardPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=StandardPresetDrift: the $Observation rule 'Standard Preset Security Policy' is 'Disabled' where 'Enabled' is required." `
                    -Because 'a preset rule that exists but is switched off applies nothing, and the two halves are switched independently, so a control that decides only the half it happens to read reports protection the tenant is not applying'
        }
    }

    Context 'Negative: a Standard preset rule scoped to anything other than the resolved desired state fails' {

        It 'fails a rule that does not scope <Member> to an approved value' -ForEach @(
            @{ Member = 'RecipientDomainIs'; Observed = @() ; Approved = 'contoso.com' }
            @{ Member = 'ExceptIfSentToMemberOf'; Observed = @(); Approved = 'priority-users@contoso.com' }
            @{ Member = 'ExceptIfSentTo'; Observed = @(); Approved = 'secops@contoso.com' }
        ) {
            # Arrange
            $argument = @{ $Member = $Observed }
            $narrowed = New-StandardPresetEvidence -EopRule @(New-PresetRule @argument) -AtpRule @(New-PresetRule)

            # Act
            $result = Test-StandardPresetControl -Evidence $narrowed -DesiredState $script:DesiredStandardPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=StandardPresetDrift: the EOPProtectionPolicyRule rule does not scope '$Member' to '$Approved'." `
                    -Because 'an approved domain the preset never reaches is an unprotected population, and an approved exclusion the preset never makes is a priority user or a SecOps mailbox the preset quietly re-covers; both are exactly what the card requires be matched'
        }

        It 'fails a rule that scopes <Member> to an unapproved value' -ForEach @(
            @{ Member = 'RecipientDomainIs'; Observed = @('contoso.com', 'fabrikam.example'); Unapproved = 'fabrikam.example' }
            @{ Member = 'ExceptIfSentToMemberOf'; Observed = @('priority-users@contoso.com', 'everyone@contoso.com'); Unapproved = 'everyone@contoso.com' }
            @{ Member = 'ExceptIfSentTo'; Observed = @('secops@contoso.com', 'ceo@contoso.com'); Unapproved = 'ceo@contoso.com' }
        ) {
            # Arrange
            $argument = @{ $Member = $Observed }
            $widened = New-StandardPresetEvidence -EopRule @(New-PresetRule @argument) -AtpRule @(New-PresetRule)

            # Act
            $result = Test-StandardPresetControl -Evidence $widened -DesiredState $script:DesiredStandardPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=StandardPresetDrift: the EOPProtectionPolicyRule rule scopes '$Member' to unapproved '$Unapproved'." `
                    -Because 'an exclusion nobody approved is a population the preset stops protecting, which is the whole mechanism this control exists to hold to the approved list; the card requires an exact match, not a superset'
        }

        It 'fails a tenant whose ATP rule alone is wrongly scoped' {
            # Arrange
            $atpOnly = New-StandardPresetEvidence `
                -EopRule @(New-PresetRule) `
                -AtpRule @(New-PresetRule -ExceptIfSentTo @('secops@contoso.com', 'ceo@contoso.com'))

            # Act
            $result = Test-StandardPresetControl -Evidence $atpOnly -DesiredState $script:DesiredStandardPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=StandardPresetDrift: the ATPProtectionPolicyRule rule scopes 'ExceptIfSentTo' to unapproved 'ceo@contoso.com'." `
                    -Because 'Safe Links and Safe Attachments are scoped by the ATP rule alone, so an evaluator that stops once the EOP rule agrees reports a chief executive protected against phishing links that the tenant has in fact exempted'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-StandardPresetControl `
                -Evidence (New-StandardPresetEvidence -EopRule @(New-PresetRule -State 'Disabled') -AtpRule @(New-PresetRule)) `
                -DesiredState $script:DesiredStandardPreset -GroupResolver $script:GroupResolver

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act |
                Should -Throw `
                    -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: both Standard rules enabled and scoped to exactly the resolved desired state is one go-live-successful pass' {

        It 'passes a tenant whose Standard EOP and ATP rules are enabled and exactly scoped, ignoring the custom rules beside them' {
            # Arrange
            $presetRule = New-PresetRule -Name ' Standard Preset Security Policy ' -State 'enabled' `
                -RecipientDomainIs @('Contoso.COM.', 'contoso.com') `
                -ExceptIfSentToMemberOf @('Priority Users') `
                -ExceptIfSentTo @('SMTP:SecOps@Contoso.com')
            $customRule = New-PresetRule -Name 'Marketing bulk exemption' -State 'Disabled' `
                -RecipientDomainIs @('fabrikam.example') `
                -ExceptIfSentToMemberOf @('everyone@contoso.com') `
                -ExceptIfSentTo @('ceo@contoso.com')
            $configured = New-StandardPresetEvidence -EopRule @($presetRule, $customRule) -AtpRule @($customRule, $presetRule)
            $expected = 'MDO-001|Pass|normalized=True|golive=True|reason=|evidence=Get-EOPProtectionPolicyRule; Get-ATPProtectionPolicyRule:MDO-001'

            # Act
            $result = Test-StandardPresetControl -Evidence $configured -DesiredState $script:DesiredStandardPreset -GroupResolver $script:GroupResolver

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'the declared comparisons trim, lower the casing, drop a trailing root label, strip an SMTP routing prefix, resolve a group to its primary address and collapse duplicates, so the tenant Exchange Online reports back in its own formatting is the same tenant the baseline asked for, and the custom rule scoped to another domain and exempting the chief executive is a rule this control must leave entirely alone; the verdict has to be one normalized pass naming the record it was decided from rather than a bare true'
        }
    }
}
