#requires -Version 7.0

# Pester evaluates `-ForEach` during discovery, before any `BeforeAll` has run, so the five seams
# EXO-010 is observed through are declared here as well as inside `BeforeAll`. Each names the
# collector parameter that supplies it and the prefix its absence is refused with.
$RoleAssignmentSeam = @(
    @{ Parameter = 'RoleGroupCollection'; Prefix = 'RoleGroupCollectionRequired' }
    @{ Parameter = 'ManagementRoleAssignmentCollection'; Prefix = 'ManagementRoleAssignmentCollectionRequired' }
    @{ Parameter = 'ActivePimAssignmentCollection'; Prefix = 'ActivePimAssignmentCollectionRequired' }
    @{ Parameter = 'EligiblePimAssignmentCollection'; Prefix = 'EligiblePimAssignmentCollectionRequired' }
    @{ Parameter = 'AccessReviewCollection'; Prefix = 'AccessReviewCollectionRequired' }
)

# The five observations the record carries, and the desired-state arguments whose absence the
# evaluator refuses. Both are read during discovery, so both are declared outside `BeforeAll`.
$RoleAssignmentObservation = @('RoleGroup', 'ManagementRoleAssignment', 'ActivePimAssignment', 'EligiblePimAssignment', 'AccessReview')

$RoleAssignmentDesiredState = @(
    @{ Argument = 'PrivilegedRoleGroup'; Prefix = 'PrivilegedRoleGroupRequired'; Absent = @() }
    @{ Argument = 'ApprovedMember'; Prefix = 'ApprovedMemberRequired'; Absent = $null }
    @{ Argument = 'GovernedRole'; Prefix = 'GovernedRoleRequired'; Absent = @() }
    @{ Argument = 'MaximumReviewAgeDay'; Prefix = 'ReviewIntervalRequired'; Absent = 0 }
)

$RoleGroupDecidedMember = @('Name', 'Members')

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Neither ExchangeOnlineManagement nor Microsoft.Graph is installed, and neither is ever
    # imported. Every role group, management role assignment, PIM assignment and access review
    # below is a scriptblock returning canned records or throwing a canned failure, so no request
    # leaves this process and no credential is used.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # The registry is returned as one read-only collection deliberately protected from pipeline
    # unrolling, so the entry is read by index rather than by piping the collection.
    $script:ControlRegistry = @(Get-BaselineControlRegistry -Profile Historical)[0]
    $script:RoleAssignmentRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'EXO-010') { $entry }
        })[0]

    $script:SeamParameter = @(
        'RoleGroupCollection'
        'ManagementRoleAssignmentCollection'
        'ActivePimAssignmentCollection'
        'EligiblePimAssignmentCollection'
        'AccessReviewCollection'
    )

    # The discovery-time copy of this list is not in scope while a test runs, and a list that read
    # as empty would build a record carrying nothing and let every omission assert the same absence.
    $script:ObservationName = @(foreach ($name in $script:SeamParameter) { $name -replace 'Collection$' })

    function New-RoleAssignmentCollectionArgument {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{}
        )

        $argument = @{}
        foreach ($name in $script:SeamParameter) {
            $argument[$name] = { }
        }

        foreach ($name in @($Override.Keys)) {
            $argument[$name] = $Override[$name]
        }

        return $argument
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

    # The resolved desired state EXO-010 is decided against, and the instant it is decided at. The
    # clock is injected rather than read, so a review that is current today does not become stale
    # the day this suite is next run.
    $script:GovernedRoleId = '29232cdf-9323-42fd-ade2-1d097af3e4de'
    $script:UngovernedRoleId = '62e90394-69f5-4237-9190-012177145e10'
    $script:ApprovedPrincipal = 'break.glass@contoso.com'
    $script:StandingPrincipal = 'standing.admin@contoso.com'
    $script:ActivePrincipalId = 'b5d1f9a0-3c2e-4a77-9f81-6d0c4e2b8a13'
    $script:EligiblePrincipalId = 'c7e2a418-5b9d-4f60-8a31-2f4c6d9e1b05'
    $script:ReviewDisplayName = 'Exchange administrators quarterly review'
    $script:AsAtUtc = [datetime]::new(2026, 9, 17, 0, 0, 0, [System.DateTimeKind]::Utc)

    function New-RoleAssignmentDesiredState {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{}
        )

        $argument = @{
            PrivilegedRoleGroup = @('Organization Management')
            ApprovedMember      = @($script:ApprovedPrincipal)
            GovernedRole        = @($script:GovernedRoleId)
            MaximumReviewAgeDay = 90
            AsAtUtc             = $script:AsAtUtc
        }

        foreach ($name in @($Override.Keys)) {
            $argument[$name] = $Override[$name]
        }

        return $argument
    }

    function New-RoleGroup {
        [CmdletBinding()]
        param(
            [string]$Name = 'Organization Management',

            [object]$Members = @('break.glass@contoso.com')
        )

        return [pscustomobject]@{ Name = $Name; Members = $Members; WhenChangedUTC = '2026-02-11T08:00:00Z' }
    }

    function New-ManagementRoleAssignment {
        [CmdletBinding()]
        param(
            [string]$Role = 'Mailbox Import Export',

            [string]$RoleAssigneeName = 'Organization Management',

            [string]$RoleAssigneeType = 'RoleGroup'
        )

        return [pscustomobject]@{ Role = $Role; RoleAssigneeName = $RoleAssigneeName; RoleAssigneeType = $RoleAssigneeType; RecipientWriteScope = 'Organization' }
    }

    function New-ActivePimAssignment {
        [CmdletBinding()]
        param(
            [string]$RoleDefinitionId = '29232cdf-9323-42fd-ade2-1d097af3e4de',

            [string]$PrincipalId = 'b5d1f9a0-3c2e-4a77-9f81-6d0c4e2b8a13',

            [AllowNull()]
            [object]$EndDateTime = '2026-09-30T00:00:00Z'
        )

        return [pscustomobject]@{ principalId = $PrincipalId; roleDefinitionId = $RoleDefinitionId; endDateTime = $EndDateTime; memberType = 'Direct' }
    }

    function New-EligiblePimAssignment {
        [CmdletBinding()]
        param(
            [string]$RoleDefinitionId = '29232cdf-9323-42fd-ade2-1d097af3e4de',

            [string]$PrincipalId = 'c7e2a418-5b9d-4f60-8a31-2f4c6d9e1b05'
        )

        return [pscustomobject]@{ principalId = $PrincipalId; roleDefinitionId = $RoleDefinitionId; startDateTime = '2026-01-05T00:00:00Z' }
    }

    function New-AccessReview {
        [CmdletBinding()]
        param(
            [string]$ScopeRoleDefinitionId = '29232cdf-9323-42fd-ade2-1d097af3e4de',

            [AllowNull()]
            [object]$LastCompletedDateTime = '2026-08-20T00:00:00Z'
        )

        return [pscustomobject]@{
            displayName           = 'Exchange administrators quarterly review'
            scopeRoleDefinitionId = $ScopeRoleDefinitionId
            lastCompletedDateTime = $LastCompletedDateTime
            createdBy             = 'governance@contoso.com'
        }
    }

    # A tenant that satisfies every clause of EXO-010, with any one observation swapped out. Each
    # negative changes exactly the thing it is about, so a verdict it produces cannot be explained
    # by anything else in the fixture.
    function New-RoleAssignmentEvidenceRecord {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{}
        )

        $observed = @{
            RoleGroup                = @((New-RoleGroup), (New-RoleGroup -Name 'Help Desk' -Members @('service.desk@contoso.com')))
            ManagementRoleAssignment = @(New-ManagementRoleAssignment)
            ActivePimAssignment      = @(New-ActivePimAssignment)
            EligiblePimAssignment    = @(New-EligiblePimAssignment)
            AccessReview             = @(New-AccessReview)
        }

        foreach ($name in @($Override.Keys)) {
            $observed[$name] = $Override[$name]
        }

        $argument = @{}
        foreach ($name in $script:SeamParameter) {
            $entry = $observed[($name -replace 'Collection$')]
            # Emitted unwrapped: a service returns its records to the pipeline one at a time, and a
            # seam that wrote the collection as a single object would hand the collector a list
            # holding one list, which is a shape no Exchange or Graph call ever produces.
            $argument[$name] = { @($entry) }.GetNewClosure()
        }

        return Get-ExchangeRoleAssignmentEvidence @argument
    }

    function New-PartialRoleAssignmentEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'EXO-010' -Source 'ExchangeOnline,MicrosoftGraph' `
            -Command 'Get-RoleGroup; Get-ManagementRoleAssignment' -Value $Payload
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

        return '{0}|{1}|normalized={2}|golive={3}|reason={4}|evidence={5}' -f `
            $Result.ControlId,
        $Result.Status,
        $Result.Normalized,
        $Result.GoLiveSuccess,
        $Result.Reason,
        $Result.Evidence.ControlId
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXO-010-A1 RBAC and PIM collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector EXO-010 is registered against' {
            # Arrange
            $registered = $script:RoleAssignmentRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes EXO-010, and a collector that is named but not shipped leaves the control standing exactly where the shipping script leaves it, which is a status the result contract can never normalize"
        }
    }

    Context 'Negative: every one of the five sources must be given a service call to make' {

        It "refuses a collection with no '<Parameter>' to run" -ForEach $RoleAssignmentSeam {
            # Arrange
            $argument = New-RoleAssignmentCollectionArgument -Override @{ $Parameter = $null }

            # Act
            $act = { Get-ExchangeRoleAssignmentEvidence @argument }

            # Assert
            $act | Should -Throw -ExpectedMessage "$Prefix*" `
                -Because 'a record assembled from four of the five sources reports a privilege posture that silently excludes the fifth, and the missing one is always the one nobody thought to wire up'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It "records a refusal from '<Parameter>' as an uncollected observation instead of propagating it" -ForEach $RoleAssignmentSeam {
            # Arrange
            $argument = New-RoleAssignmentCollectionArgument -Override @{
                $Parameter = { throw 'InsufficientPrivileges: the caller holds no directory role to read this.' }
            }

            # Act
            $evidence = Get-ExchangeRoleAssignmentEvidence @argument

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'a consent gap, a throttled directory and an expired token all arrive here as exceptions, and a refusal that is not recorded as a refusal reads downstream exactly like a tenant that was read and found to hold no standing privilege'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a collection where every source returned nothing as collected' {
            # Arrange
            $argument = New-RoleAssignmentCollectionArgument

            # Act
            $evidence = Get-ExchangeRoleAssignmentEvidence @argument

            # Assert
            ('collected={0}|failure={1}|{2}' -f $evidence.Collected, $evidence.FailureReason, (ConvertTo-CanonicalJson -InputObject $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|{"AccessReview":[],"ActivePimAssignment":[],"EligiblePimAssignment":[],"ManagementRoleAssignment":[],"RoleGroup":[]}' `
                    -Because 'a tenant that has run no access review and holds no PIM assignment answers with nothing, and that is the finding EXO-010 exists to fail on rather than an infrastructure excuse to hide it behind'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $argument = New-RoleAssignmentCollectionArgument -Override @{
                RoleGroupCollection = { [pscustomobject]@{ Name = 'Organization Management'; Members = @('standing.admin@contoso.com') } }
            }
            $evidence = Get-ExchangeRoleAssignmentEvidence @argument

            # Act
            $act = { $evidence.Value['RoleGroup'] = @() }

            # Assert
            $act | Should -Throw -Because 'raw evidence a caller can rewrite is not evidence of who holds privilege, it is evidence of who the caller wanted to hold it'
        }
    }

    Context 'Positive: one collection of the five sources is one record of exactly what the services returned' {

        It 'records all five observations under the control, source and commands the registry declares' {
            # Arrange
            $argument = New-RoleAssignmentCollectionArgument -Override @{
                RoleGroupCollection                = {
                    [pscustomobject]@{ Name = 'Organization Management'; Members = @('standing.admin@contoso.com', 'break.glass@contoso.com'); WhenChangedUTC = '2026-02-11T08:00:00Z' }
                    [pscustomobject]@{ Name = 'Help Desk'; Members = @('service.desk@contoso.com'); WhenChangedUTC = '2025-12-03T14:30:00Z' }
                }
                ManagementRoleAssignmentCollection = {
                    [pscustomobject]@{ Role = 'Mailbox Import Export'; RoleAssigneeName = 'Organization Management'; RoleAssigneeType = 'RoleGroup'; RecipientWriteScope = 'Organization' }
                }
                ActivePimAssignmentCollection      = {
                    [pscustomobject]@{ principalId = 'b5d1f9a0-3c2e-4a77-9f81-6d0c4e2b8a13'; roleDefinitionId = '29232cdf-9323-42fd-ade2-1d097af3e4de'; endDateTime = '2026-09-30T00:00:00Z'; memberType = 'Direct' }
                }
                EligiblePimAssignmentCollection    = {
                    [pscustomobject]@{ principalId = 'c7e2a418-5b9d-4f60-8a31-2f4c6d9e1b05'; roleDefinitionId = '29232cdf-9323-42fd-ade2-1d097af3e4de'; startDateTime = '2026-01-05T00:00:00Z' }
                }
                AccessReviewCollection             = {
                    [pscustomobject]@{ displayName = 'Exchange administrators quarterly review'; scopeRoleDefinitionId = '29232cdf-9323-42fd-ade2-1d097af3e4de'; lastCompletedDateTime = '2026-08-20T00:00:00Z'; createdBy = 'governance@contoso.com' }
                }
            }
            $expected = 'EXO-010|ExchangeOnline,MicrosoftGraph|' +
            'Get-RoleGroup; Get-ManagementRoleAssignment; GET /roleManagement/directory/roleAssignmentScheduleInstances; GET /roleManagement/directory/roleEligibilityScheduleInstances; GET /identityGovernance/accessReviews/definitions' +
            '|collected=True|failure=|' +
            '{"AccessReview":[{"createdBy":"governance@contoso.com","displayName":"Exchange administrators quarterly review","lastCompletedDateTime":"2026-08-20T00:00:00Z","scopeRoleDefinitionId":"29232cdf-9323-42fd-ade2-1d097af3e4de"}],' +
            '"ActivePimAssignment":[{"endDateTime":"2026-09-30T00:00:00Z","memberType":"Direct","principalId":"b5d1f9a0-3c2e-4a77-9f81-6d0c4e2b8a13","roleDefinitionId":"29232cdf-9323-42fd-ade2-1d097af3e4de"}],' +
            '"EligiblePimAssignment":[{"principalId":"c7e2a418-5b9d-4f60-8a31-2f4c6d9e1b05","roleDefinitionId":"29232cdf-9323-42fd-ade2-1d097af3e4de","startDateTime":"2026-01-05T00:00:00Z"}],' +
            '"ManagementRoleAssignment":[{"RecipientWriteScope":"Organization","Role":"Mailbox Import Export","RoleAssigneeName":"Organization Management","RoleAssigneeType":"RoleGroup"}],' +
            '"RoleGroup":[{"Members":["standing.admin@contoso.com","break.glass@contoso.com"],"Name":"Organization Management","WhenChangedUTC":"2026-02-11T08:00:00Z"},' +
            '{"Members":["service.desk@contoso.com"],"Name":"Help Desk","WhenChangedUTC":"2025-12-03T14:30:00Z"}]}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = Get-ExchangeRoleAssignmentEvidence @argument

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so all five observations have to survive collection whole: a collector that filtered the role groups to the ones the baseline governs would drop the Help Desk group and hide the privilege somebody grants it next quarter, one that narrowed each record to the members the control decides on would drop the write scope, the member type and the review author a reviewer reconstructs the change from, and one that folded the five into a single privilege verdict would decide the control before any evaluator saw it'
        }
    }
}

Describe 'EXO-010-A2 RBAC and PIM evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator EXO-010 is registered against' {
            # Arrange
            $registered = $script:RoleAssignmentRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides EXO-010, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation and the desired state the baseline resolved' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $argument = New-RoleAssignmentDesiredState

            # Act
            $act = { Test-ExchangeRoleAssignmentControl -Evidence $null @argument }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceRequired*' `
                -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $foreign = New-BaselineEvidence -ControlId 'EXO-005' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value ([pscustomobject]@{ ExternalPostmasterAddress = 'postmaster@contoso.com' })

            # Act
            $act = { Test-ExchangeRoleAssignmentControl -Evidence $foreign @argument }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' `
                -Because 'deciding who holds privilege from another control record reports a posture that was never looked at'
        }

        It "refuses a decision that resolved no '<Argument>'" -ForEach $RoleAssignmentDesiredState {
            # Arrange
            $argument = New-RoleAssignmentDesiredState -Override @{ $Argument = $Absent }

            # Act
            $act = { Test-ExchangeRoleAssignmentControl -Evidence (New-RoleAssignmentEvidenceRecord) @argument }

            # Assert
            $act | Should -Throw -ExpectedMessage "$Prefix*" `
                -Because 'a desired state nobody resolved is not an empty desired state; read as one it either governs no role group, approves every member, governs no role or accepts a review of any age, and each of those is satisfied by every tenant'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $refused = Get-ExchangeRoleAssignmentEvidence -RoleGroupCollection { throw 'GraphThrottled: the request was throttled on every attempt.' } `
                -ManagementRoleAssignmentCollection { } -ActivePimAssignmentCollection { } `
                -EligiblePimAssignmentCollection { } -AccessReviewCollection { }

            # Act
            $result = Test-ExchangeRoleAssignmentControl -Evidence $refused @argument

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a privilege posture the run never managed to observe must cost the run its go-live, because the alternative is that withholding the directory read consent is the cheapest way to pass this control'
        }
    }

    Context 'Negative: a record that carries only part of itself decides nothing about the rest' {

        It "decides a record carrying no '<_>' observation as an error" -ForEach $RoleAssignmentObservation {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $observation = [ordered]@{}
            foreach ($name in $script:ObservationName) {
                if ($name -cne $_) { $observation[$name] = @() }
            }
            $partial = New-PartialRoleAssignmentEvidence -Payload $observation

            # Act
            $result = Test-ExchangeRoleAssignmentControl -Evidence $partial @argument

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=RoleAssignmentEvidenceIncomplete: the record carries no '$_' observation." `
                    -Because 'an observation that is absent is not an observation of nothing, and read as one it reports that nobody holds the privilege it was never asked about'
        }

        It "decides an observed role group carrying no '<_>' member as an error" -ForEach $RoleGroupDecidedMember {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $group = New-RoleGroup
            $group.PSObject.Properties.Remove($_)
            $incomplete = New-RoleAssignmentEvidenceRecord -Override @{ RoleGroup = @($group) }

            # Act
            $result = Test-ExchangeRoleAssignmentControl -Evidence $incomplete @argument

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=RoleAssignmentEvidenceIncomplete: an observed role group carries no '$_' member." `
                    -Because 'a group with no name cannot be matched against the groups the baseline governs and a group with no membership reads as a group nobody is in, so both absences let a privileged group pass by never being examined'
        }

        It 'decides a review reporting an unreadable completion time as an error' {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $unreadable = New-RoleAssignmentEvidenceRecord -Override @{
                AccessReview = @(New-AccessReview -LastCompletedDateTime 'last quarter')
            }

            # Act
            $result = Test-ExchangeRoleAssignmentControl -Evidence $unreadable @argument

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=RoleAssignmentEvidenceIncomplete: the access review 'Exchange administrators quarterly review' reports a completion time of 'last quarter' that cannot be read." `
                    -Because 'a completion time the run cannot read is a review age nobody knows, and treating it as current passes the one clause that proves anybody has looked'
        }
    }

    Context 'Negative: a tenant whose privilege is ungoverned fails' {

        It 'fails a privileged role group holding a member the baseline does not approve, naming the member' {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $standing = New-RoleAssignmentEvidenceRecord -Override @{
                RoleGroup = @(
                    New-RoleGroup -Members @($script:ApprovedPrincipal, $script:StandingPrincipal)
                    New-RoleGroup -Name 'Help Desk' -Members @('service.desk@contoso.com')
                )
            }

            # Act
            $result = Test-ExchangeRoleAssignmentControl -Evidence $standing @argument

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=PrivilegeUngoverned: privileged role group 'Organization Management' holds 'standing.admin@contoso.com' which the baseline does not approve." `
                    -Because 'standing membership of a privileged Exchange role group is the privilege PIM exists to remove, the approved break-glass account sitting beside it must not be reported as drift, and an unnamed surplus member cannot be removed'
        }

        It 'fails a management role assigned directly to a user rather than to a role group, naming the user and the role' {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $direct = New-RoleAssignmentEvidenceRecord -Override @{
                ManagementRoleAssignment = @(New-ManagementRoleAssignment -RoleAssigneeName $script:StandingPrincipal -RoleAssigneeType 'User')
            }

            # Act
            $result = Test-ExchangeRoleAssignmentControl -Evidence $direct @argument

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=PrivilegeUngoverned: management role 'Mailbox Import Export' is assigned directly to user 'standing.admin@contoso.com' rather than to a role group." `
                    -Because 'a role assigned straight to a user is held outside every role group the baseline governs and outside PIM entirely, so it survives every membership review and every elevation policy the tenant has'
        }

        It 'fails an active assignment that is permanent rather than time-bound, naming the principal and the role' {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $permanent = New-RoleAssignmentEvidenceRecord -Override @{
                ActivePimAssignment = @(New-ActivePimAssignment -EndDateTime $null)
            }

            # Act
            $result = Test-ExchangeRoleAssignmentControl -Evidence $permanent @argument

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=PrivilegeUngoverned: the active assignment of role '29232cdf-9323-42fd-ade2-1d097af3e4de' to 'b5d1f9a0-3c2e-4a77-9f81-6d0c4e2b8a13' is permanent rather than time-bound." `
                    -Because 'an active assignment with no end is standing privilege wearing the name of just-in-time access, and it reads in a PIM export exactly like an elevation that expires this afternoon'
        }

        It 'fails an eligible assignment for a role the baseline does not govern' {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $ungoverned = New-RoleAssignmentEvidenceRecord -Override @{
                EligiblePimAssignment = @(New-EligiblePimAssignment -RoleDefinitionId $script:UngovernedRoleId)
            }

            # Act
            $result = Test-ExchangeRoleAssignmentControl -Evidence $ungoverned @argument

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=PrivilegeUngoverned: the eligible assignment of role '62e90394-69f5-4237-9190-012177145e10' to 'c7e2a418-5b9d-4f60-8a31-2f4c6d9e1b05' is for a role the baseline does not govern." `
                    -Because 'eligibility for a role nobody declared is a path into privilege that no review of the declared roles will ever surface, and Global Administrator is reachable exactly this way'
        }

        It 'fails a governed role that carries no access review at all' {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $unreviewed = New-RoleAssignmentEvidenceRecord -Override @{ AccessReview = @() }

            # Act
            $result = Test-ExchangeRoleAssignmentControl -Evidence $unreviewed @argument

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=PrivilegeUngoverned: role '29232cdf-9323-42fd-ade2-1d097af3e4de' carries no access review." `
                    -Because 'a tenant that has never reviewed a governed role is the default state of every tenant, so a control that reads it as anything but a failure passes before anybody configures governance'
        }

        It 'fails an access review that has never completed' {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $started = New-RoleAssignmentEvidenceRecord -Override @{
                AccessReview = @(New-AccessReview -LastCompletedDateTime $null)
            }

            # Act
            $result = Test-ExchangeRoleAssignmentControl -Evidence $started @argument

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=PrivilegeUngoverned: the access review 'Exchange administrators quarterly review' for role '29232cdf-9323-42fd-ade2-1d097af3e4de' has never completed." `
                    -Because 'a review that exists and has never finished is the artifact an auditor is shown and the evidence that proves nothing, and it reads to every check that tests the review for existence exactly like a completed one'
        }

        It 'fails an access review whose completion is older than the resolved interval' {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $stale = New-RoleAssignmentEvidenceRecord -Override @{
                AccessReview = @(New-AccessReview -LastCompletedDateTime '2026-06-18T00:00:00Z')
            }

            # Act
            $result = Test-ExchangeRoleAssignmentControl -Evidence $stale @argument

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=PrivilegeUngoverned: the access review 'Exchange administrators quarterly review' for role '29232cdf-9323-42fd-ade2-1d097af3e4de' last completed on '2026-06-18T00:00:00Z', beyond the 90-day review interval." `
                    -Because 'a review completed once and never again is the usual shape of governance decay, and the card requires current evidence rather than evidence that a review once happened'
        }

        It 'does not report a review completed exactly on the interval boundary as drift' {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $boundary = New-RoleAssignmentEvidenceRecord -Override @{
                AccessReview = @(New-AccessReview -LastCompletedDateTime '2026-06-19T00:00:00Z')
                RoleGroup    = @(New-RoleGroup -Members @($script:ApprovedPrincipal, $script:StandingPrincipal))
            }

            # Act
            $result = Test-ExchangeRoleAssignmentControl -Evidence $boundary @argument

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=PrivilegeUngoverned: privileged role group 'Organization Management' holds 'standing.admin@contoso.com' which the baseline does not approve." `
                    -Because 'a ninety-day interval that rejects a review completed on its ninetieth day fails every tenant that reviews exactly on schedule, and this tenant is failing for a reason that has nothing to do with the review, so the reason proves the boundary was not counted as drift'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $result = Test-ExchangeRoleAssignmentControl @argument `
                -Evidence (New-RoleAssignmentEvidenceRecord -Override @{ AccessReview = @() })

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act | Should -Throw -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: approved membership, time-bound elevation, governed eligibility and a current review is one go-live-successful pass' {

        It 'passes a tenant whose privileged groups hold only approved members, whose roles are held through role groups, whose active assignment expires, whose eligibility is governed and whose governed role was reviewed inside the interval' {
            # Arrange
            $argument = New-RoleAssignmentDesiredState
            $governed = New-RoleAssignmentEvidenceRecord

            # Act
            $result = Test-ExchangeRoleAssignmentControl -Evidence $governed @argument

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly 'EXO-010|Pass|normalized=True|golive=True|reason=|evidence=EXO-010' `
                    -Because 'every clause of the card is satisfied at once by exactly one tenant shape, and the ungoverned Help Desk group sitting beside the governed one proves the evaluator holds the groups the baseline named to the approved list rather than every group it can see; the result carries the record it was decided from, so a reviewer can see which observation the pass rests on'
        }
    }
}
