#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph is not installed and must never be imported. The conditional access policies
    # are reached only through the supplied collection seam, so every collection here is a
    # scriptblock returning canned policies or throwing a canned failure, and no request leaves
    # this process.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # The registry is returned as one read-only collection deliberately protected from pipeline
    # unrolling, so the entry is read by index rather than by piping the collection.
    $script:ControlRegistry = @(Get-BaselineControlRegistry -Profile Historical)[0]
    $script:ConditionalAccessRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'EXO-003') { $entry }
        })[0]

    function New-ConditionalAccessPolicy {
        [CmdletBinding()]
        param(
            [string]$Id = '11111111-2222-3333-4444-555555555555',

            [string]$DisplayName = 'Block legacy authentication',

            [object]$State = 'enabled',

            [object]$ClientAppTypes = @('exchangeActiveSync', 'other'),

            [object]$IncludeUsers = @('All'),

            [object]$ExcludeUsers = @(),

            [object]$ExcludeGroups = @(),

            [object]$IncludeApplications = @('00000002-0000-0ff1-ce00-000000000000'),

            [object]$BuiltInControls = @('block'),

            # A member EXO-003 decides nothing about, so a collector that narrowed the payload to
            # the conditions the control reads is distinguishable from one that recorded what
            # Graph returned.
            [object]$CreatedDateTime = '2026-01-04T09:15:00Z'
        )

        return [pscustomobject]@{
            id              = $Id
            displayName     = $DisplayName
            state           = $State
            createdDateTime = $CreatedDateTime
            conditions      = [pscustomobject]@{
                clientAppTypes = $ClientAppTypes
                users          = [pscustomobject]@{
                    includeUsers  = $IncludeUsers
                    excludeUsers  = $ExcludeUsers
                    excludeGroups = $ExcludeGroups
                }
                applications   = [pscustomobject]@{
                    includeApplications = $IncludeApplications
                }
            }
            grantControls   = [pscustomobject]@{
                builtInControls = $BuiltInControls
            }
        }
    }

    function New-ConditionalAccessEvidenceRecord {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Policy
        )

        return Get-ConditionalAccessEvidence -Collection { $Policy }.GetNewClosure()
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

    $script:PolicyDisplayName = 'Block legacy authentication'
    $script:BreakGlassAccount = '0f4b1a2c-8d3e-4f5a-9b6c-7d8e9f0a1b2c'

    function New-PartialConditionalAccessEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'EXO-003' -Source 'MicrosoftGraph' `
            -Command 'GET /identity/conditionalAccess/policies' -Value $Payload
    }

    # Removes one leaf member from a freshly built fixture, so an evidence record can carry a
    # policy that never observed a member at all rather than one that observed it as empty.
    function Remove-PolicyMember {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Policy,

            [Parameter(Mandatory)]
            [string]$Path
        )

        $segment = @($Path -split '\.')
        $node = $Policy
        for ($index = 0; $index -lt $segment.Count - 1; $index++) {
            $node = $node.PSObject.Properties[$segment[$index]].Value
        }

        $node.PSObject.Properties.Remove($segment[-1])
        return $Policy
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

Describe 'EXO-003-A1 conditional-access collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector EXO-003 is registered against' {
            # Arrange
            $registered = $script:ConditionalAccessRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes EXO-003, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: the collector must be given a service call to make' {

        It 'refuses a collection with nothing to run' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-ConditionalAccessEvidence -Collection $noCollection }

            # Assert
            $act | Should -Throw -ExpectedMessage 'CollectionRequired*' -Because 'a record assembled without reaching Graph reports a legacy authentication posture nobody read from the tenant, which is exactly the standing of the Manual check this control replaces'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records a collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'GraphInsufficientPrivileges: the token carries no Policy.Read.All scope.' }

            # Act
            $evidence = Get-ConditionalAccessEvidence -Collection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'a consent gap, a throttled tenant and an expired token all arrive here as exceptions, and a refusal that is not recorded as a refusal reads downstream exactly like a tenant that was read and found to be blocking legacy authentication'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a collection that returned nothing as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-ConditionalAccessEvidence -Collection $empty

            # Assert
            ('collected={0}|failure={1}|observedAnything={2}' -f $evidence.Collected, $evidence.FailureReason, ($null -ne $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|observedAnything=False' `
                    -Because 'a tenant that has configured no conditional access policy at all answers with nothing, and that is the finding EXO-003 exists to fail on rather than an infrastructure excuse to hide it behind'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = New-ConditionalAccessEvidenceRecord -Policy (New-ConditionalAccessPolicy -State 'disabled')

            # Act
            $act = { $evidence.Value[0]['state'] = 'enabled' }

            # Assert
            $act | Should -Throw -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one collection of the conditional access policies is one record of exactly what Graph returned' {

        It 'records the policies Graph returned under the control, source and command the registry declares' {
            # Arrange
            $policy = @(
                New-ConditionalAccessPolicy
                New-ConditionalAccessPolicy -Id '99999999-8888-7777-6666-555555555555' -DisplayName 'Pilot - require MFA for admins' `
                    -State 'disabled' -ClientAppTypes @('browser') -IncludeApplications @('All') -BuiltInControls @('mfa') `
                    -CreatedDateTime '2025-11-20T17:40:00Z'
            )
            $expected = 'EXO-003|MicrosoftGraph|GET /identity/conditionalAccess/policies|collected=True|failure=|' +
            '[{"conditions":{"applications":{"includeApplications":["00000002-0000-0ff1-ce00-000000000000"]},"clientAppTypes":["exchangeActiveSync","other"],"users":{"excludeGroups":[],"excludeUsers":[],"includeUsers":["All"]}},"createdDateTime":"2026-01-04T09:15:00Z","displayName":"Block legacy authentication","grantControls":{"builtInControls":["block"]},"id":"11111111-2222-3333-4444-555555555555","state":"enabled"},' +
            '{"conditions":{"applications":{"includeApplications":["All"]},"clientAppTypes":["browser"],"users":{"excludeGroups":[],"excludeUsers":[],"includeUsers":["All"]}},"createdDateTime":"2025-11-20T17:40:00Z","displayName":"Pilot - require MFA for admins","grantControls":{"builtInControls":["mfa"]},"id":"99999999-8888-7777-6666-555555555555","state":"disabled"}]' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = New-ConditionalAccessEvidenceRecord -Policy $policy

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so both policies have to survive collection whole: a collector that filtered to the enabled policies would drop the disabled one and hide the fact that the tenant is running an unenforced pilot, one that narrowed the record to the policy the baseline names would leave the evaluator unable to report that no such policy exists among the ones that do, and one that narrowed each policy to the conditions the control reads would drop the creation time a reviewer dates the change by'
        }
    }
}

Describe 'EXO-003-A2 conditional-access evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator EXO-003 is registered against' {
            # Arrange
            $registered = $script:ConditionalAccessRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides EXO-003, and a control the run cannot decide is a control the go-live gate never hears about - which is exactly the standing the shipping script's Manual check leaves it in"
        }
    }

    Context 'Negative: the evaluator must be given an observation and the desired state the baseline resolved' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = {
                Test-ConditionalAccessControl -Evidence $noEvidence `
                    -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @()
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceRequired*' -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'EXO-005' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value ([pscustomobject]@{ ExternalPostmasterAddress = 'postmaster@contoso.com' })

            # Act
            $act = {
                Test-ConditionalAccessControl -Evidence $foreign `
                    -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @()
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' -Because 'deciding legacy authentication from another control record reports a posture that was never looked at'
        }

        It 'refuses a decision that names no resolved policy' {
            # Arrange
            $noPolicyName = ''

            # Act
            $act = {
                Test-ConditionalAccessControl -Evidence (New-ConditionalAccessEvidenceRecord -Policy (New-ConditionalAccessPolicy)) `
                    -PolicyDisplayName $noPolicyName -ApprovedExclusion @()
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'PolicyDisplayNameRequired*' -Because 'an evaluator that is not told which policy carries the block will take the first policy that happens to look like one, and a tenant can always be made to hold such a policy scoped to nobody'
        }

        It 'refuses a decision that names no resolved approved-exclusion list' {
            # Arrange
            $noApprovedExclusion = $null

            # Act
            $act = {
                Test-ConditionalAccessControl -Evidence (New-ConditionalAccessEvidenceRecord -Policy (New-ConditionalAccessPolicy)) `
                    -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion $noApprovedExclusion
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ApprovedExclusionRequired*' -Because 'an exclusion list the baseline resolved to nothing means no principal may be exempted, while one that was never resolved means nobody decided; reading the second as the first approves every exclusion the tenant happens to hold'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-ConditionalAccessEvidence -Collection { throw 'GraphThrottled: the request was throttled on every attempt.' }

            # Act
            $result = Test-ConditionalAccessControl -Evidence $refused `
                -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a control the run never managed to observe must cost the run its go-live, because the alternative is that withholding the Policy.Read.All consent is the cheapest way to pass it'
        }
    }

    Context 'Negative: a policy that carries only part of itself decides nothing about the rest' {

        It "decides a named policy carrying no '<_>' member as an error" -ForEach @(
            'state'
            'conditions.clientAppTypes'
            'conditions.users.includeUsers'
            'conditions.users.excludeUsers'
            'conditions.users.excludeGroups'
            'conditions.applications.includeApplications'
            'grantControls.builtInControls'
        ) {
            # Arrange
            $partial = New-PartialConditionalAccessEvidence -Payload @(Remove-PolicyMember -Policy (New-ConditionalAccessPolicy) -Path $_)

            # Act
            $result = Test-ConditionalAccessControl -Evidence $partial `
                -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=ConditionalAccessEvidenceIncomplete: the observed conditional access policy 'Block legacy authentication' carries no '$_' member." `
                    -Because 'an absent member is not a satisfied one, and every one of these read as satisfied reports that legacy authentication is blocked on the strength of something nobody observed'
        }
    }

    Context 'Negative: a tenant that is not blocking legacy authentication fails' {

        It 'fails a tenant that holds no conditional access policy at all' {
            # Arrange
            $nothing = Get-ConditionalAccessEvidence -Collection { }

            # Act
            $result = Test-ConditionalAccessControl -Evidence $nothing `
                -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=LegacyAuthenticationOpen: the tenant holds no conditional access policy.' `
                    -Because 'no conditional access policy at all is the default state of every tenant, so a control that reads it as anything other than a failure passes before anybody configures it'
        }

        It 'fails a tenant that holds policies but none the baseline names, naming the policy it looked for' {
            # Arrange
            $unrelated = New-ConditionalAccessEvidenceRecord -Policy @(
                New-ConditionalAccessPolicy -Id '99999999-8888-7777-6666-555555555555' -DisplayName 'Pilot - require MFA for admins'
            )

            # Act
            $result = Test-ConditionalAccessControl -Evidence $unrelated `
                -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=LegacyAuthenticationOpen: the tenant holds no conditional access policy named 'Block legacy authentication'." `
                    -Because 'a tenant with a full conditional access estate and no legacy authentication block in it is the common case, and a control that reports only that policies exist proves nothing about the one that closes this route'
        }

        It 'fails a named policy that is disabled' {
            # Arrange
            $disabled = New-ConditionalAccessEvidenceRecord -Policy (New-ConditionalAccessPolicy -State 'disabled')

            # Act
            $result = Test-ConditionalAccessControl -Evidence $disabled `
                -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=LegacyAuthenticationOpen: conditional access policy 'Block legacy authentication' is 'disabled' where 'enabled' is required." `
                    -Because 'a policy that exists and is switched off blocks exactly as much legacy authentication as no policy at all, while looking in an export exactly like one that is enforcing'
        }

        It 'fails a named policy that is report-only' {
            # Arrange
            $reportOnly = New-ConditionalAccessEvidenceRecord -Policy (New-ConditionalAccessPolicy -State 'enabledForReportingButNotEnforced')

            # Act
            $result = Test-ConditionalAccessControl -Evidence $reportOnly `
                -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=LegacyAuthenticationOpen: conditional access policy 'Block legacy authentication' is 'enabledForReportingButNotEnforced' where 'enabled' is required." `
                    -Because 'report-only is the state a policy is left in after a pilot nobody finished, it reads as enabled to every check that tests the state for truthiness, and it blocks nothing'
        }

        It 'fails a named policy that does not apply to all users' {
            # Arrange
            $narrowUsers = New-ConditionalAccessEvidenceRecord -Policy (New-ConditionalAccessPolicy -IncludeUsers @('3c2b1a09-8f7e-6d5c-4b3a-2a1b0c9d8e7f'))

            # Act
            $result = Test-ConditionalAccessControl -Evidence $narrowUsers `
                -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=LegacyAuthenticationOpen: conditional access policy 'Block legacy authentication' does not apply to all users." `
                    -Because 'a policy piloted against a single test account is enabled, blocking and enforcing, and protects one mailbox; the card demands correct scope precisely because the state alone cannot tell that apart from tenant-wide enforcement'
        }

        It 'fails a named policy that does not apply to Exchange Online' {
            # Arrange
            $otherApplication = New-ConditionalAccessEvidenceRecord -Policy (New-ConditionalAccessPolicy -IncludeApplications @('797f4846-ba00-4fd7-ba43-dac1f8f63013'))

            # Act
            $result = Test-ConditionalAccessControl -Evidence $otherApplication `
                -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=LegacyAuthenticationOpen: conditional access policy 'Block legacy authentication' does not apply to Exchange Online." `
                    -Because 'legacy authentication reaches the mailbox through the Exchange Online resource, so a block scoped to any other application leaves that route open however tenant-wide and enforcing it is'
        }

        It 'fails a named policy that does not cover a legacy client app type, naming the client it misses' {
            # Arrange
            $partialClient = New-ConditionalAccessEvidenceRecord -Policy (New-ConditionalAccessPolicy -ClientAppTypes @('other'))

            # Act
            $result = Test-ConditionalAccessControl -Evidence $partialClient `
                -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=LegacyAuthenticationOpen: conditional access policy 'Block legacy authentication' does not cover legacy client 'exchangeActiveSync'." `
                    -Because 'Graph splits legacy clients into two app types and blocking one of them leaves the other delivering mail exactly as before, so the failure has to name the client that is still getting through'
        }

        It 'fails a named policy that does not grant block' {
            # Arrange
            $notBlocking = New-ConditionalAccessEvidenceRecord -Policy (New-ConditionalAccessPolicy -BuiltInControls @('mfa'))

            # Act
            $result = Test-ConditionalAccessControl -Evidence $notBlocking `
                -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @()

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=LegacyAuthenticationOpen: conditional access policy 'Block legacy authentication' does not grant 'block'." `
                    -Because 'legacy clients cannot satisfy an interactive control, so a policy that requires multi-factor authentication of them rather than blocking them is the configuration that looks strictest and is the one most often left broken'
        }

        It 'fails a named policy that excludes a user the baseline does not approve, naming the user' {
            # Arrange
            $unapprovedUser = New-ConditionalAccessEvidenceRecord -Policy (
                New-ConditionalAccessPolicy -ExcludeUsers @('a1b2c3d4-e5f6-4708-9a0b-1c2d3e4f5a6b')
            )

            # Act
            $result = Test-ConditionalAccessControl -Evidence $unapprovedUser `
                -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @($script:BreakGlassAccount)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=LegacyAuthenticationOpen: conditional access policy 'Block legacy authentication' excludes 'a1b2c3d4-e5f6-4708-9a0b-1c2d3e4f5a6b' which the baseline does not approve." `
                    -Because 'an exclusion is a hole cut in a policy that otherwise reads as perfect, and the whole of this control past the enabled flag exists to report the holes; an unnamed one cannot be removed'
        }

        It 'fails a named policy that excludes a group the baseline does not approve, naming only the unapproved exclusion' {
            # Arrange
            $mixedExclusion = New-ConditionalAccessEvidenceRecord -Policy (
                New-ConditionalAccessPolicy -ExcludeUsers @($script:BreakGlassAccount) -ExcludeGroups @('7e6d5c4b-3a2b-41c0-9d8e-7f6a5b4c3d2e')
            )

            # Act
            $result = Test-ConditionalAccessControl -Evidence $mixedExclusion `
                -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @($script:BreakGlassAccount)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=LegacyAuthenticationOpen: conditional access policy 'Block legacy authentication' excludes '7e6d5c4b-3a2b-41c0-9d8e-7f6a5b4c3d2e' which the baseline does not approve." `
                    -Because 'a group exclusion exempts everyone somebody later adds to it and is the hole that grows on its own, and reporting the approved break-glass account alongside it would teach an operator to skim past both'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-ConditionalAccessControl `
                -Evidence (New-ConditionalAccessEvidenceRecord -Policy (New-ConditionalAccessPolicy -State 'disabled')) `
                -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @()

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act | Should -Throw -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: an enabled, correctly scoped, blocking policy with only approved exclusions is one go-live-successful pass' {

        It 'passes a tenant whose named policy is enabled, tenant-wide, scoped to Exchange Online, covers both legacy clients, grants block and excludes only approved principals' {
            # Arrange
            $compliant = New-ConditionalAccessEvidenceRecord -Policy @(
                New-ConditionalAccessPolicy -ExcludeUsers @($script:BreakGlassAccount)
                New-ConditionalAccessPolicy -Id '99999999-8888-7777-6666-555555555555' -DisplayName 'Pilot - require MFA for admins' `
                    -State 'disabled' -ClientAppTypes @('browser') -IncludeApplications @('All') -BuiltInControls @('mfa')
            )

            # Act
            $result = Test-ConditionalAccessControl -Evidence $compliant `
                -PolicyDisplayName $script:PolicyDisplayName -ApprovedExclusion @($script:BreakGlassAccount)

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly 'EXO-003|Pass|normalized=True|golive=True|reason=|evidence=GET /identity/conditionalAccess/policies:EXO-003' `
                    -Because 'all four clauses of the card are satisfied at once by exactly one tenant shape, and the unenforced pilot sitting beside the block proves the evaluator decides the policy the baseline named rather than the estate around it; the result carries the record it was decided from, so a reviewer can see which observation the pass rests on'
        }
    }
}
