#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement is not installed and must never be imported. Get-ATPBuiltInProtectionRule
    # is reached only through the supplied collection seam, so every collection here is a scriptblock
    # returning canned rules or throwing a canned failure.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # Assigning before unrolling matters: the registry is returned as one read-only collection
    # deliberately protected from pipeline unrolling, so it is read by index rather than by pipe.
    $script:ControlRegistry = @(Get-BaselineControlRegistry)[0]
    $script:BuiltInProtectionRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'MDO-003') { $entry }
        })[0]

    # The name Exchange Online gives the one rule built-in protection is applied through.
    $script:BuiltInRuleName = 'ATP Built-In Protection Rule'

    function New-BuiltInRule {
        [CmdletBinding()]
        param(
            [object]$Name = $script:BuiltInRuleName,

            [object]$State = 'Enabled',

            [object]$ExceptIfSentTo = @(),

            [object]$ExceptIfSentToMemberOf = @(),

            [object]$ExceptIfRecipientDomainIs = @(),

            [object]$Priority = 0
        )

        return [pscustomobject]@{
            ExceptIfRecipientDomainIs = $ExceptIfRecipientDomainIs
            ExceptIfSentTo            = $ExceptIfSentTo
            ExceptIfSentToMemberOf    = $ExceptIfSentToMemberOf
            Name                      = $Name
            Priority                  = $Priority
            State                     = $State
        }
    }

    # MDO-001: the built-in protection state the baseline resolves. `exceptions` is the approved
    # exclusion register: each entry names the exclusion member it is granted on and the value, so
    # a mailbox approved by name never approves the whole domain it sits in.
    $script:DesiredBuiltInProtection = [pscustomobject]@{
        enabled    = $true
        exceptions = @(
            [pscustomobject]@{ exceptionType = 'Mailbox'; value = 'secops@contoso.com' }
            [pscustomobject]@{ exceptionType = 'Group'; value = 'phishsim-recipients@contoso.com' }
            [pscustomobject]@{ exceptionType = 'Domain'; value = 'lab.contoso.com' }
        )
    }

    # The declared Group comparison resolves a group to its primary SMTP address, which cannot be
    # done offline, so every test supplies the resolution as a seam. This one resolves the one
    # mail-enabled group the baseline names and passes an address through unchanged.
    $script:GroupResolver = {
        param($Value)

        if ($Value -like '*@*') { return [string]$Value }
        if ($Value -ceq 'Phishing Simulation Recipients') { return 'phishsim-recipients@contoso.com' }

        return $null
    }

    function New-ApprovedBuiltInRule {
        [CmdletBinding()]
        param(
            [object]$Name = $script:BuiltInRuleName,

            [object]$State = 'Enabled',

            [object]$ExceptIfSentTo = @('secops@contoso.com'),

            [object]$ExceptIfSentToMemberOf = @('phishsim-recipients@contoso.com'),

            [object]$ExceptIfRecipientDomainIs = @('lab.contoso.com')
        )

        return New-BuiltInRule -Name $Name -State $State -ExceptIfSentTo $ExceptIfSentTo `
            -ExceptIfSentToMemberOf $ExceptIfSentToMemberOf -ExceptIfRecipientDomainIs $ExceptIfRecipientDomainIs
    }

    function New-BuiltInRuleWithout {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Member
        )

        $rule = [ordered]@{
            ExceptIfRecipientDomainIs = @('lab.contoso.com')
            ExceptIfSentTo            = @('secops@contoso.com')
            ExceptIfSentToMemberOf    = @('phishsim-recipients@contoso.com')
            Name                      = $script:BuiltInRuleName
            State                     = 'Enabled'
        }

        $rule.Remove($Member)

        return [pscustomobject]$rule
    }

    function New-BuiltInProtectionEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [object]$Rule
        )

        return Get-BuiltInProtectionEvidence -RuleCollection { $Rule }.GetNewClosure()
    }

    function New-PartialBuiltInProtectionEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'MDO-003' -Source 'ExchangeOnline' `
            -Command 'Get-ATPBuiltInProtectionRule' -Value $Payload
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
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'MDO-004-A1 Built-in protection collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector MDO-003 is registered against' {
            # Arrange
            $registered = $script:BuiltInProtectionRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes built-in protection, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: the collector must be given the service call to make' {

        It 'refuses a collection with no built-in protection rule to read' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-BuiltInProtectionEvidence -RuleCollection $noCollection }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'BuiltInProtectionRuleCollectionRequired*' `
                    -Because 'the built-in protection rule is the only place the exclusions this control decides on are recorded, and a record assembled without reading it reports an exclusion set nobody looked up'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records a collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The term Get-ATPBuiltInProtectionRule is not recognized in this session.' }

            # Act
            $evidence = Get-BuiltInProtectionEvidence -RuleCollection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'an exception here discards every other control in the run, and a refused command that is not recorded as refused reads downstream exactly like a rule that was read and found carrying no exclusion'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a tenant that holds no built-in protection rule at all as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-BuiltInProtectionEvidence -RuleCollection $empty

            # Assert
            ('collected={0}|failure={1}|{2}' -f $evidence.Collected, $evidence.FailureReason, (ConvertTo-CanonicalJson -InputObject $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|{"ATPBuiltInProtectionRule":[]}' `
                    -Because 'a tenant whose built-in protection rule cannot be found is the exact finding this control exists to report, and calling it a collection failure hides that finding behind an infrastructure excuse'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = Get-BuiltInProtectionEvidence -RuleCollection { @(New-BuiltInRule -State 'Disabled') }

            # Act
            $act = { $evidence.Value['ATPBuiltInProtectionRule'] = @() }

            # Assert
            $act |
                Should -Throw `
                    -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one run of the collection is one record of exactly what the command returned' {

        It 'records every rule whole under its declared name, under the control, source and command the registry declares' {
            # Arrange
            $builtInRule = New-BuiltInRule -Name ' ATP Built-In Protection Rule ' -State 'enabled' `
                -ExceptIfSentTo @('SMTP:SecOps@Contoso.com') -ExceptIfSentToMemberOf @('Priority-Users@contoso.com') `
                -ExceptIfRecipientDomainIs @('Fabrikam.Example.')
            $customRule = New-BuiltInRule -Name 'Marketing bulk exemption' -Priority 1
            $expected = 'MDO-003|ExchangeOnline|Get-ATPBuiltInProtectionRule|collected=True|failure=|' +
            '{"ATPBuiltInProtectionRule":[' +
            '{"ExceptIfRecipientDomainIs":["Fabrikam.Example."],"ExceptIfSentTo":["SMTP:SecOps@Contoso.com"],' +
            '"ExceptIfSentToMemberOf":["Priority-Users@contoso.com"],"Name":" ATP Built-In Protection Rule ","Priority":0,"State":"enabled"},' +
            '{"ExceptIfRecipientDomainIs":[],"ExceptIfSentTo":[],"ExceptIfSentToMemberOf":[],' +
            '"Name":"Marketing bulk exemption","Priority":1,"State":"Enabled"}]}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = Get-BuiltInProtectionEvidence -RuleCollection { @($builtInRule, $customRule) }.GetNewClosure()

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so the rule has to survive collection with its casing, its whitespace, its routing prefix, its trailing root label and its unrelated sibling members intact, and any rule beside the built-in protection rule has to survive too; a collector that filtered to the built-in rule or narrowed it to the members the control decides on would decide the exclusion set before the evaluator ever saw it'
        }
    }
}

Describe 'MDO-004-A2 Built-in protection evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator MDO-003 is registered against' {
            # Arrange
            $registered = $script:BuiltInProtectionRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides built-in protection, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation, the exclusions the baseline approved and a way to resolve a group' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = { Test-BuiltInProtectionControl -Evidence $noEvidence -DesiredState $script:DesiredBuiltInProtection -GroupResolver $script:GroupResolver }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceRequired*' `
                    -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'MDO-001' -Source 'ExchangeOnline' `
                -Command 'Get-EOPProtectionPolicyRule' -Value @(New-ApprovedBuiltInRule)

            # Act
            $act = { Test-BuiltInProtectionControl -Evidence $foreign -DesiredState $script:DesiredBuiltInProtection -GroupResolver $script:GroupResolver }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' `
                    -Because 'the preset rules and the built-in protection rule carry the same exclusion members, so deciding one from the other reports an exclusion set that was never looked at for this control'
        }

        It 'refuses a decision that names no resolved desired built-in protection state' {
            # Arrange
            $evidence = New-BuiltInProtectionEvidence -Rule @(New-ApprovedBuiltInRule)

            # Act
            $act = { Test-BuiltInProtectionControl -Evidence $evidence -DesiredState $null -GroupResolver $script:GroupResolver }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredBuiltInProtectionStateRequired*' `
                    -Because 'the card demands every exclusion match the approved desired state, and an evaluator handed no desired state decides against whatever it defaults to rather than against what was approved'
        }

        It 'refuses a desired state that declares no approved exclusion register at all' {
            # Arrange
            $evidence = New-BuiltInProtectionEvidence -Rule @(New-ApprovedBuiltInRule)
            $unregistered = [pscustomobject]@{ enabled = $true }

            # Act
            $act = { Test-BuiltInProtectionControl -Evidence $evidence -DesiredState $unregistered -GroupResolver $script:GroupResolver }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredBuiltInProtectionExceptionsRequired*' `
                    -Because 'a baseline that approves no exclusion and a baseline that never declared the register read identically once the member is absent, and only one of them is a decision somebody made'
        }

        It 'refuses a decision with no way to resolve an observed group' {
            # Arrange
            $evidence = New-BuiltInProtectionEvidence -Rule @(New-ApprovedBuiltInRule)

            # Act
            $act = { Test-BuiltInProtectionControl -Evidence $evidence -DesiredState $script:DesiredBuiltInProtection -GroupResolver $null }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'BuiltInProtectionGroupResolverRequired*' `
                    -Because 'the declared Group comparison resolves a group to its primary SMTP address, and comparing an unresolved display name against a resolved address reads every approved exclusion as drift'
        }

        It 'refuses an approved exception granted on an exclusion member the contract does not declare' {
            # Arrange
            $evidence = New-BuiltInProtectionEvidence -Rule @(New-ApprovedBuiltInRule)
            $unknown = [pscustomobject]@{
                enabled    = $true
                exceptions = @([pscustomobject]@{ exceptionType = 'IpAddress'; value = '198.51.100.7' })
            }

            # Act
            $act = { Test-BuiltInProtectionControl -Evidence $evidence -DesiredState $unknown -GroupResolver $script:GroupResolver }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'UnknownBuiltInProtectionExceptionType*' `
                    -Because 'an approval granted on a member the rule has no such exclusion for is an approval that can never be matched, and silently dropping it would let the register claim an exemption the tenant is not actually holding'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-BuiltInProtectionEvidence -RuleCollection { throw 'The operation was throttled and could not be completed.' }

            # Act
            $result = Test-BuiltInProtectionControl -Evidence $refused -DesiredState $script:DesiredBuiltInProtection -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a control the run never managed to observe must cost the run its go-live, because the alternative is that throttling the tenant is the cheapest way to pass it'
        }
    }

    Context 'Negative: a record that never observed the rule decides nothing about it' {

        It 'decides a record carrying no built-in protection observation as an error' {
            # Arrange
            $partial = New-PartialBuiltInProtectionEvidence -Payload ([ordered]@{ ATPProtectionPolicyRule = @(New-ApprovedBuiltInRule) })

            # Act
            $result = Test-BuiltInProtectionControl -Evidence $partial -DesiredState $script:DesiredBuiltInProtection -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=BuiltInProtectionEvidenceIncomplete: the record carries no 'ATPBuiltInProtectionRule' observation." `
                    -Because 'an absent observation is not an observation that the tenant holds no built-in protection rule, and reading it as one decides the control from a command nobody ran'
        }

        It 'decides an observed rule carrying no <Member> member as an error' -ForEach @(
            @{ Member = 'Name' }
            @{ Member = 'State' }
            @{ Member = 'ExceptIfSentTo' }
            @{ Member = 'ExceptIfSentToMemberOf' }
            @{ Member = 'ExceptIfRecipientDomainIs' }
        ) {
            # Arrange
            $incomplete = New-BuiltInProtectionEvidence -Rule @(New-BuiltInRuleWithout -Member $Member)

            # Act
            $result = Test-BuiltInProtectionControl -Evidence $incomplete -DesiredState $script:DesiredBuiltInProtection -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=BuiltInProtectionEvidenceIncomplete: an observed ATPBuiltInProtectionRule carries no '$Member' member." `
                    -Because 'an absent exclusion member read as empty reports a rule excluding nobody, which is indistinguishable from a rule the collector simply did not carry'
        }
    }

    Context 'Negative: a group the run cannot resolve is not a group the run may pass' {

        It 'decides an unresolvable observed group as an error' {
            # Arrange
            $unresolvable = New-BuiltInProtectionEvidence -Rule @(New-ApprovedBuiltInRule -ExceptIfSentToMemberOf @('Legacy Distribution List'))

            # Act
            $result = Test-BuiltInProtectionControl -Evidence $unresolvable -DesiredState $script:DesiredBuiltInProtection -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvaluatorThrew:*UnresolvedCanonicalValue*' `
                    -Because 'a group nobody could resolve is an unknown exclusion, and treating an unknown exclusion as absent quietly passes a rule that exempts a population the run never identified'
        }
    }

    Context 'Negative: a tenant that holds no built-in protection rule fails' {

        It 'fails a tenant whose rules hold no built-in protection rule at all' {
            # Arrange
            $absent = New-BuiltInProtectionEvidence -Rule @(New-ApprovedBuiltInRule -Name 'Marketing bulk exemption')

            # Act
            $result = Test-BuiltInProtectionControl -Evidence $absent -DesiredState $script:DesiredBuiltInProtection -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=BuiltInProtectionDrift: the tenant holds no 'ATP Built-In Protection Rule'." `
                    -Because 'built-in protection is always-on, so a rule that cannot be found is a tenant nobody can prove anything about, and reading it as clean passes the control on the strength of a missing answer'
        }
    }

    Context 'Negative: a built-in protection rule that is not enabled fails' {

        It 'fails a tenant whose built-in protection rule is disabled, naming the state it holds' {
            # Arrange
            $disabled = New-BuiltInProtectionEvidence -Rule @(New-ApprovedBuiltInRule -State 'Disabled')

            # Act
            $result = Test-BuiltInProtectionControl -Evidence $disabled -DesiredState $script:DesiredBuiltInProtection -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=BuiltInProtectionDrift: the rule 'ATP Built-In Protection Rule' is 'Disabled' where 'Enabled' is required." `
                    -Because 'a built-in protection rule that exists but is switched off applies nothing, and the card requires the protection be enabled rather than merely present'
        }
    }

    Context 'Negative: an exclusion the baseline never approved fails' {

        It 'fails a rule excluding an unapproved value under <Member>' -ForEach @(
            @{ Member = 'ExceptIfSentTo'; Observed = @('secops@contoso.com', 'ceo@contoso.com'); Unapproved = 'ceo@contoso.com' }
            @{ Member = 'ExceptIfSentToMemberOf'; Observed = @('phishsim-recipients@contoso.com', 'everyone@contoso.com'); Unapproved = 'everyone@contoso.com' }
            @{ Member = 'ExceptIfRecipientDomainIs'; Observed = @('lab.contoso.com', 'fabrikam.example'); Unapproved = 'fabrikam.example' }
        ) {
            # Arrange
            $argument = @{ $Member = $Observed }
            $widened = New-BuiltInProtectionEvidence -Rule @(New-ApprovedBuiltInRule @argument)

            # Act
            $result = Test-BuiltInProtectionControl -Evidence $widened -DesiredState $script:DesiredBuiltInProtection -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=BuiltInProtectionDrift: the rule excludes unapproved '$Unapproved' under '$Member'." `
                    -Because 'an exclusion nobody approved is a population built-in protection stops reaching, which is the only thing about this always-on rule an operator can get wrong; the card requires an exact match, not a superset'
        }

        It 'fails a rule excluding a whole accepted domain even though a mailbox inside it is approved' {
            # Arrange
            $domainWide = New-BuiltInProtectionEvidence -Rule @(New-ApprovedBuiltInRule -ExceptIfRecipientDomainIs @('lab.contoso.com', 'contoso.com'))

            # Act
            $result = Test-BuiltInProtectionControl -Evidence $domainWide -DesiredState $script:DesiredBuiltInProtection -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=BuiltInProtectionDrift: the rule excludes unapproved 'contoso.com' under 'ExceptIfRecipientDomainIs'." `
                    -Because 'each approval is granted on the exclusion member it names, so approving the SecOps mailbox at contoso.com can never approve exempting every recipient in that domain - the broad exclusion the catalog forbids is exactly the one a bleeding register would hide'
        }

        It 'fails a rule that does not carry the approved exclusion <Member>' -ForEach @(
            @{ Member = 'ExceptIfSentTo'; Approved = 'secops@contoso.com' }
            @{ Member = 'ExceptIfSentToMemberOf'; Approved = 'phishsim-recipients@contoso.com' }
            @{ Member = 'ExceptIfRecipientDomainIs'; Approved = 'lab.contoso.com' }
        ) {
            # Arrange
            $argument = @{ $Member = @() }
            $narrowed = New-BuiltInProtectionEvidence -Rule @(New-ApprovedBuiltInRule @argument)

            # Act
            $result = Test-BuiltInProtectionControl -Evidence $narrowed -DesiredState $script:DesiredBuiltInProtection -GroupResolver $script:GroupResolver

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=BuiltInProtectionDrift: the rule does not exclude approved '$Approved' under '$Member'." `
                    -Because 'the card requires every exclusion match the approved desired state in both directions, and an approved exclusion the tenant is not applying means the register no longer describes the tenant it was approved for'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-BuiltInProtectionControl `
                -Evidence (New-BuiltInProtectionEvidence -Rule @(New-ApprovedBuiltInRule -State 'Disabled')) `
                -DesiredState $script:DesiredBuiltInProtection -GroupResolver $script:GroupResolver

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act |
                Should -Throw `
                    -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: an enabled rule carrying exactly the approved exclusions is one go-live-successful pass' {

        It 'passes a tenant whose built-in protection rule is enabled and exactly excluded, ignoring the custom rule beside it' {
            # Arrange
            $builtInRule = New-ApprovedBuiltInRule -Name ' ATP Built-In Protection Rule ' -State 'enabled' `
                -ExceptIfSentTo @('SMTP:SecOps@Contoso.com', 'secops@contoso.com') `
                -ExceptIfSentToMemberOf @('Phishing Simulation Recipients') `
                -ExceptIfRecipientDomainIs @('LAB.Contoso.COM.')
            $customRule = New-ApprovedBuiltInRule -Name 'Marketing bulk exemption' -State 'Disabled' `
                -ExceptIfSentTo @('ceo@contoso.com') -ExceptIfSentToMemberOf @('everyone@contoso.com') `
                -ExceptIfRecipientDomainIs @('contoso.com')
            $configured = New-BuiltInProtectionEvidence -Rule @($customRule, $builtInRule)
            $expected = 'MDO-003|Pass|normalized=True|golive=True|reason=|evidence=Get-ATPBuiltInProtectionRule:MDO-003'

            # Act
            $result = Test-BuiltInProtectionControl -Evidence $configured -DesiredState $script:DesiredBuiltInProtection -GroupResolver $script:GroupResolver

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'the declared comparisons trim, lower the casing, drop a trailing root label, strip an SMTP routing prefix, resolve a group to its primary address and collapse duplicates, so the tenant Exchange Online reports back in its own formatting is the same tenant the baseline approved, and the custom rule exempting the chief executive and an entire domain is a rule this control must leave entirely alone; the verdict has to be one normalized pass naming the record it was decided from rather than a bare true'
        }
    }
}
