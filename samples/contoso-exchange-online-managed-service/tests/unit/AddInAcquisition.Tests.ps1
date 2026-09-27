#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Every Exchange Online call EXO-012 depends on is reached only through a supplied collection
    # seam, so each collection here is a scriptblock returning a canned answer or throwing a canned
    # failure and no session and no request leaves this process.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # The registry is returned as one read-only collection deliberately protected from pipeline
    # unrolling, so the entry is read by index rather than by piping the collection.
    $script:ControlRegistry = @(Get-BaselineControlRegistry)[0]
    $script:AddInRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'EXO-012') { $entry }
        })[0]

    # A role assignment policy as `Get-RoleAssignmentPolicy` reports it. `Description` is carried
    # deliberately as a member EXO-012 decides nothing about, so a collector that narrowed the
    # answer to the members the control reads is distinguishable from one that recorded the answer.
    function New-RoleAssignmentPolicyRecord {
        [CmdletBinding()]
        param(
            [object]$Identity = 'Default Role Assignment Policy',

            [object]$IsDefault = $true,

            [object]$Description = 'The default role assignment policy.',

            [string[]]$Remove = @()
        )

        $policy = [ordered]@{
            Identity    = $Identity
            IsDefault   = $IsDefault
            Description = $Description
        }

        foreach ($member in $Remove) { $policy.Remove($member) }

        return [pscustomobject]$policy
    }

    # A management role assignment as `Get-ManagementRoleAssignment` reports it. `Name` and
    # `RoleAssigneeType` are carried as members EXO-012 decides nothing about.
    function New-ManagementRoleAssignmentRecord {
        [CmdletBinding()]
        param(
            [object]$Role = 'My Custom Apps',

            [object]$RoleAssignee = 'Default Role Assignment Policy',

            [object]$Name,

            [object]$RoleAssigneeType = 'RoleAssignmentPolicy',

            [string[]]$Remove = @()
        )

        if (-not $PSBoundParameters.ContainsKey('Name')) { $Name = '{0}-{1}' -f $Role, $RoleAssignee }

        $assignment = [ordered]@{
            Name             = $Name
            Role             = $Role
            RoleAssignee     = $RoleAssignee
            RoleAssigneeType = $RoleAssigneeType
        }

        foreach ($member in $Remove) { $assignment.Remove($member) }

        return [pscustomobject]$assignment
    }

    function New-AddInAcquisitionEvidence {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [AllowEmptyCollection()]
            [object[]]$Policy = @(),

            [AllowNull()]
            [AllowEmptyCollection()]
            [object[]]$Assignment = @()
        )

        return Get-AddInAcquisitionEvidence `
            -RoleAssignmentPolicyCollection { $Policy }.GetNewClosure() `
            -ManagementRoleAssignmentCollection { $Assignment }.GetNewClosure()
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

    # The baseline decides add-in acquisition with one switch under `protocolRestriction`, so the
    # desired state handed to the evaluator is that node.
    function New-AddInAcquisitionDesiredState {
        [CmdletBinding()]
        param(
            [object]$OutlookAddInsForUsers = $false,

            [string[]]$Remove = @()
        )

        $state = [ordered]@{
            outlookAddInsForUsers = $OutlookAddInsForUsers
        }

        foreach ($member in $Remove) { $state.Remove($member) }

        return [pscustomobject]$state
    }

    # A tenant that holds a default policy and hangs no add-in acquisition role off it, which is
    # what the shipped baseline asks for.
    function New-BaselineAddInAcquisitionEvidence {
        [CmdletBinding()]
        param(
            [object]$Policy,

            [object]$Assignment
        )

        if (-not $PSBoundParameters.ContainsKey('Policy')) { $Policy = @(New-RoleAssignmentPolicyRecord) }
        if (-not $PSBoundParameters.ContainsKey('Assignment')) { $Assignment = @(New-ManagementRoleAssignmentRecord -Role 'MyBaseOptions') }

        return New-AddInAcquisitionEvidence -Policy $Policy -Assignment $Assignment
    }

    function New-PartialAddInAcquisitionEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'EXO-012' -Source 'ExchangeOnline' `
            -Command 'Get-RoleAssignmentPolicy; Get-ManagementRoleAssignment' -Value $Payload
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

    # The three management roles that let a user acquire an add-in into their own mailbox.
    $script:AcquisitionRole = @('My Custom Apps', 'My Marketplace Apps', 'My ReadWriteMailboxApps')
    $script:DesiredAddInAcquisition = New-AddInAcquisitionDesiredState
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXO-012-A1 add-in acquisition collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector EXO-012 is registered against' {
            # Arrange
            $registered = $script:AddInRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes EXO-012, and a control the registry routes to a command nobody ships is a control that is never decided at all"
        }
    }

    Context 'Negative: both halves of the observation must be given a service call to make' {

        It 'refuses a run with no role assignment policy collection' {
            # Arrange
            $policy = $null

            # Act
            $act = { Get-AddInAcquisitionEvidence -RoleAssignmentPolicyCollection $policy -ManagementRoleAssignmentCollection { @() } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'RoleAssignmentPolicyCollectionRequired*' `
                -Because 'the assignments alone never say which policy is the default one, so a tenant with three policies is indistinguishable from a tenant whose default policy grants nothing'
        }

        It 'refuses a run with no management role assignment collection' {
            # Arrange
            $assignment = $null

            # Act
            $act = { Get-AddInAcquisitionEvidence -RoleAssignmentPolicyCollection { @() } -ManagementRoleAssignmentCollection $assignment }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ManagementRoleAssignmentCollectionRequired*' `
                -Because 'the policy is only a name until the assignments say which roles hang off it, so a policy list on its own reports nothing about what a user may install'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records a role assignment policy collection that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The term Get-RoleAssignmentPolicy is not recognized.' }

            # Act
            $evidence = Get-AddInAcquisitionEvidence -RoleAssignmentPolicyCollection $refusing -ManagementRoleAssignmentCollection { @() }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'a session that never answered proves nothing about which policy is the default, and a refusal that is not recorded as a refusal reads downstream exactly like a tenant that was queried and found clean'
        }

        It 'records a management role assignment collection that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The operation could not be performed because of a throttling policy.' }

            # Act
            $evidence = Get-AddInAcquisitionEvidence -RoleAssignmentPolicyCollection { @() } -ManagementRoleAssignmentCollection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'enumerating every management role assignment is the expensive half of this control, so throttling is the failure it will meet most often and the one it must never read as an absence of add-in roles'
        }
    }

    Context 'Negative: a tenant with nothing to report is an observation, not a failure' {

        It 'records collections that both returned nothing as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-AddInAcquisitionEvidence -RoleAssignmentPolicyCollection $empty -ManagementRoleAssignmentCollection $empty

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeExactly 'collected=True|failure=' `
                    -Because 'a tenant that returned no role assignment policy at all is a tenant that fails EXO-012, and calling that a collection failure hides a real finding behind an infrastructure excuse'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = New-AddInAcquisitionEvidence `
                -Policy @(New-RoleAssignmentPolicyRecord) `
                -Assignment @(New-ManagementRoleAssignmentRecord)

            # Act
            $act = { $evidence.Value['ManagementRoleAssignment'][0].Role = 'MyBaseOptions' }

            # Assert
            $act | Should -Throw -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one run of both collections is one record of exactly what each returned' {

        It 'records every policy and assignment the services returned under its own name, unfiltered and unreshaped' {
            # Arrange
            $policy = @(
                (New-RoleAssignmentPolicyRecord -Identity 'Default Role Assignment Policy' -IsDefault $true -Description 'The default role assignment policy.'),
                (New-RoleAssignmentPolicyRecord -Identity 'Restricted Recipients Policy' -IsDefault $false -Description 'No add-ins.')
            )
            $assignment = @(
                (New-ManagementRoleAssignmentRecord -Role 'My Custom Apps' -RoleAssignee 'Default Role Assignment Policy'),
                (New-ManagementRoleAssignmentRecord -Role 'MyBaseOptions' -RoleAssignee 'Default Role Assignment Policy'),
                (New-ManagementRoleAssignmentRecord -Role 'My Marketplace Apps' -RoleAssignee 'Restricted Recipients Policy')
            )
            $expected = 'EXO-012|ExchangeOnline|Get-RoleAssignmentPolicy; Get-ManagementRoleAssignment|collected=True|failure=|' +
            '{"ManagementRoleAssignment":[' +
            '{"Name":"My Custom Apps-Default Role Assignment Policy","Role":"My Custom Apps","RoleAssignee":"Default Role Assignment Policy","RoleAssigneeType":"RoleAssignmentPolicy"},' +
            '{"Name":"MyBaseOptions-Default Role Assignment Policy","Role":"MyBaseOptions","RoleAssignee":"Default Role Assignment Policy","RoleAssigneeType":"RoleAssignmentPolicy"},' +
            '{"Name":"My Marketplace Apps-Restricted Recipients Policy","Role":"My Marketplace Apps","RoleAssignee":"Restricted Recipients Policy","RoleAssigneeType":"RoleAssignmentPolicy"}],' +
            '"RoleAssignmentPolicy":[' +
            '{"Description":"The default role assignment policy.","Identity":"Default Role Assignment Policy","IsDefault":true},' +
            '{"Description":"No add-ins.","Identity":"Restricted Recipients Policy","IsDefault":false}]}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = New-AddInAcquisitionEvidence -Policy $policy -Assignment $assignment

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so the add-in role on the default policy, the harmless role beside it and the add-in role on a policy that is not the default all have to survive collection unchanged and stay separable from each other'
        }
    }
}

Describe 'EXO-012-A2 add-in acquisition evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator EXO-012 is registered against' {
            # Arrange
            $registered = $script:AddInRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides add-in acquisition, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation and the add-in acquisition state the baseline resolved' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = { Test-AddInAcquisitionControl -Evidence $noEvidence -DesiredState $script:DesiredAddInAcquisition }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceRequired*' `
                    -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'EXO-011' -Source 'ExchangeOnline' `
                -Command 'Get-RoleAssignmentPolicy; Get-ManagementRoleAssignment' `
                -Value ([ordered]@{
                    RoleAssignmentPolicy     = @(New-RoleAssignmentPolicyRecord)
                    ManagementRoleAssignment = @(New-ManagementRoleAssignmentRecord -Role 'MyBaseOptions')
                })

            # Act
            $act = { Test-AddInAcquisitionControl -Evidence $foreign -DesiredState $script:DesiredAddInAcquisition }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' `
                    -Because 'a record collected for one control is exactly the record that must not decide another, because the two carry two desired states'
        }

        It 'refuses a decision that names no resolved desired add-in acquisition state' {
            # Arrange
            $evidence = New-BaselineAddInAcquisitionEvidence

            # Act
            $act = { Test-AddInAcquisitionControl -Evidence $evidence -DesiredState $null }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredAddInAcquisitionStateRequired*' `
                    -Because 'an evaluator handed no desired state decides against whatever it defaults to rather than against what was approved, and the two answers here are exact opposites'
        }

        It 'refuses a desired state that declares no add-in acquisition decision' {
            # Arrange
            $evidence = New-BaselineAddInAcquisitionEvidence
            $undecided = New-AddInAcquisitionDesiredState -Remove @('outlookAddInsForUsers')

            # Act
            $act = { Test-AddInAcquisitionControl -Evidence $evidence -DesiredState $undecided }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredAddInAcquisitionDecisionRequired*' `
                    -Because 'whether users may acquire add-ins is a decision somebody made, and a baseline that never made it reads identically to a baseline that decided against it'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-AddInAcquisitionEvidence `
                -RoleAssignmentPolicyCollection { throw 'The operation could not be performed because of a throttling policy.' } `
                -ManagementRoleAssignmentCollection { @() }

            # Act
            $result = Test-AddInAcquisitionControl -Evidence $refused -DesiredState $script:DesiredAddInAcquisition

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'enumerating every management role assignment is the half of this control most likely to be throttled, and a throttled run read as a clean tenant makes throttling the cheapest way to pass'
        }
    }

    Context 'Negative: a record that never observed half the tenant decides nothing about it' {

        It 'decides a record carrying no <Observation> observation as an error' -ForEach @(
            @{ Observation = 'RoleAssignmentPolicy' }
            @{ Observation = 'ManagementRoleAssignment' }
        ) {
            # Arrange
            $payload = [ordered]@{
                RoleAssignmentPolicy     = @(New-RoleAssignmentPolicyRecord)
                ManagementRoleAssignment = @(New-ManagementRoleAssignmentRecord -Role 'MyBaseOptions')
            }
            $payload.Remove($Observation)
            $partial = New-PartialAddInAcquisitionEvidence -Payload $payload

            # Act
            $result = Test-AddInAcquisitionControl -Evidence $partial -DesiredState $script:DesiredAddInAcquisition

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=AddInAcquisitionEvidenceIncomplete: the record carries no '$Observation' observation." `
                    -Because 'neither command reports what a user may install on its own, so half a record read as a whole one decides the control from a command nobody ran'
        }

        It 'decides an observed role assignment policy carrying no <Member> member as an error' -ForEach @(
            @{ Member = 'Identity' }
            @{ Member = 'IsDefault' }
        ) {
            # Arrange
            $incomplete = New-BaselineAddInAcquisitionEvidence -Policy @(New-RoleAssignmentPolicyRecord -Remove @($Member))

            # Act
            $result = Test-AddInAcquisitionControl -Evidence $incomplete -DesiredState $script:DesiredAddInAcquisition

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=AddInAcquisitionEvidenceIncomplete: an observed RoleAssignmentPolicy carries no '$Member' member." `
                    -Because 'an absent identity leaves no policy for an assignment to hang off and an absent default flag read as false hides the one policy this control is about, and either read as a clean tenant is a finding about the collector rather than about the tenant'
        }

        It 'decides an observed management role assignment carrying no <Member> member as an error' -ForEach @(
            @{ Member = 'Role' }
            @{ Member = 'RoleAssignee' }
        ) {
            # Arrange
            $incomplete = New-BaselineAddInAcquisitionEvidence -Assignment @(New-ManagementRoleAssignmentRecord -Role 'MyBaseOptions' -Remove @($Member))

            # Act
            $result = Test-AddInAcquisitionControl -Evidence $incomplete -DesiredState $script:DesiredAddInAcquisition

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=AddInAcquisitionEvidenceIncomplete: an observed ManagementRoleAssignment carries no '$Member' member." `
                    -Because 'an assignment with no role names no grant and an assignment with no assignee names no policy, and an unreadable grant silently dropped is indistinguishable from a grant the tenant never made'
        }
    }

    Context 'Negative: a tenant whose default policy does not hold exactly the resolved roles fails' {

        It 'fails a tenant that observed no default role assignment policy at all' {
            # Arrange
            $undefaulted = New-BaselineAddInAcquisitionEvidence -Policy @(New-RoleAssignmentPolicyRecord -Identity 'Restricted Recipients Policy' -IsDefault $false)

            # Act
            $result = Test-AddInAcquisitionControl -Evidence $undefaulted -DesiredState $script:DesiredAddInAcquisition

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=AddInAcquisitionDrift: the tenant holds no default role assignment policy.' `
                    -Because 'the default policy is what every mailbox falls under without anybody choosing it, so a tenant where the control cannot find one has told this control nothing and passing it reports a restriction nobody proved'
        }

        It 'fails a default policy that holds <Role> while the baseline forbids user add-ins, naming the role' -ForEach @(
            @{ Role = 'My Custom Apps' }
            @{ Role = 'My Marketplace Apps' }
            @{ Role = 'My ReadWriteMailboxApps' }
        ) {
            # Arrange
            $granted = New-BaselineAddInAcquisitionEvidence -Assignment @(
                (New-ManagementRoleAssignmentRecord -Role 'MyBaseOptions')
                (New-ManagementRoleAssignmentRecord -Role $Role)
            )

            # Act
            $result = Test-AddInAcquisitionControl -Evidence $granted -DesiredState $script:DesiredAddInAcquisition

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=AddInAcquisitionDrift: the default role assignment policy holds user add-in acquisition role '$Role'." `
                    -Because 'each of the three roles grants a different way to side-load an add-in into a mailbox, so a verdict that did not name the one the tenant still holds sends the operator to clear all three and check nothing'
        }

        It 'fails a default policy that does not hold <Role> while the baseline permits user add-ins, naming the role' -ForEach @(
            @{ Role = 'My Custom Apps' }
            @{ Role = 'My Marketplace Apps' }
            @{ Role = 'My ReadWriteMailboxApps' }
        ) {
            # Arrange
            $permissive = New-AddInAcquisitionDesiredState -OutlookAddInsForUsers $true
            $partial = New-BaselineAddInAcquisitionEvidence -Assignment @(foreach ($held in $script:AcquisitionRole) {
                    if ($held -cne $Role) { New-ManagementRoleAssignmentRecord -Role $held }
                })

            # Act
            $result = Test-AddInAcquisitionControl -Evidence $partial -DesiredState $permissive

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=AddInAcquisitionDrift: the default role assignment policy does not hold user add-in acquisition role '$Role'." `
                    -Because 'the baseline resolves a role set rather than a ceiling, so a tenant more restricted than the state that was approved is still a tenant that is not the state that was approved, and drift is drift in both directions'
        }

        It 'fails a default policy holding an add-in acquisition role that differs only in casing and surrounding whitespace, naming the role as the baseline spells it' {
            # Arrange
            $spelled = New-BaselineAddInAcquisitionEvidence `
                -Policy @(New-RoleAssignmentPolicyRecord -Identity ' Default Role Assignment Policy ') `
                -Assignment @(New-ManagementRoleAssignmentRecord -Role '  my CUSTOM apps ' -RoleAssignee 'DEFAULT ROLE ASSIGNMENT POLICY')

            # Act
            $result = Test-AddInAcquisitionControl -Evidence $spelled -DesiredState $script:DesiredAddInAcquisition

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=AddInAcquisitionDrift: the default role assignment policy holds user add-in acquisition role 'My Custom Apps'." `
                    -Because 'Exchange Online returns role and assignee names in whatever casing and padding it stored them in, so a control that matched them literally would miss the grant entirely and report the tenant clean, and the operator has to be given the name the baseline uses rather than the tenant spelling'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-AddInAcquisitionControl `
                -Evidence (New-BaselineAddInAcquisitionEvidence -Assignment @(New-ManagementRoleAssignmentRecord -Role 'My Custom Apps')) `
                -DesiredState $script:DesiredAddInAcquisition

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act |
                Should -Throw `
                    -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: a default policy holding exactly the resolved add-in acquisition roles is one go-live-successful pass' {

        It 'passes a tenant whose default policy holds none of the three roles, ignoring the roles a policy that is not the default holds and the roles the default policy holds that acquire no add-in' {
            # Arrange
            $policy = @(
                (New-RoleAssignmentPolicyRecord -Identity ' Default Role Assignment Policy ' -IsDefault $true),
                (New-RoleAssignmentPolicyRecord -Identity 'Add-In Pilot Policy' -IsDefault $false -Description 'Pilot group.')
            )
            $assignment = @(
                (New-ManagementRoleAssignmentRecord -Role ' myBaseOptions ' -RoleAssignee 'DEFAULT ROLE ASSIGNMENT POLICY'),
                (New-ManagementRoleAssignmentRecord -Role 'MyContactInformation' -RoleAssignee ' default role assignment policy '),
                (New-ManagementRoleAssignmentRecord -Role 'My Custom Apps' -RoleAssignee 'Add-In Pilot Policy'),
                (New-ManagementRoleAssignmentRecord -Role 'My Marketplace Apps' -RoleAssignee 'Add-In Pilot Policy')
            )
            $compliant = New-BaselineAddInAcquisitionEvidence -Policy $policy -Assignment $assignment
            $expected = 'EXO-012|Pass|normalized=True|golive=True|reason=|evidence=Get-RoleAssignmentPolicy; Get-ManagementRoleAssignment:EXO-012'

            # Act
            $result = Test-AddInAcquisitionControl -Evidence $compliant -DesiredState $script:DesiredAddInAcquisition

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'the control decides one policy and three roles, so a pilot policy somebody deliberately assigned and an ordinary mailbox role hanging off the default policy are both out of scope rather than drift, the casing and padding Exchange Online reports identities back in is never drift either, and the verdict has to be one normalized pass naming the record it was decided from rather than a bare true'
        }
    }
}
