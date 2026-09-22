#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement is not installed and must never be imported. Every quarantine and
    # filter cmdlet is reached only through the supplied collection seams, so every collection here
    # is a scriptblock returning canned policies or throwing a canned failure.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # Assigning before unrolling matters: the registry is returned as one read-only collection
    # deliberately protected from pipeline unrolling, so it is read by index rather than by pipe.
    $script:ControlRegistry = @(Get-BaselineControlRegistry -Profile Historical)[0]
    $script:QuarantineRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'MDO-008') { $entry }
        })[0]

    function New-QuarantinePolicyObject {
        [CmdletBinding()]
        param(
            [object]$Name = 'AdminOnlyAccessPolicy',

            [object]$QuarantinePolicyType = 'QuarantinePolicy',

            [object]$EndUserQuarantinePermissionsValue = 0,

            [object]$EndUserSpamNotificationFrequency = '1.00:00:00',

            [object]$IncludeMessagesFromBlockedSenderAddress = $false,

            [string[]]$Remove = @()
        )

        $policy = [ordered]@{
            Name                                    = $Name
            QuarantinePolicyType                    = $QuarantinePolicyType
            EndUserQuarantinePermissionsValue       = $EndUserQuarantinePermissionsValue
            EndUserSpamNotificationFrequency        = $EndUserSpamNotificationFrequency
            IncludeMessagesFromBlockedSenderAddress = $IncludeMessagesFromBlockedSenderAddress
            ESNEnabled                              = $true
        }

        foreach ($member in $Remove) { $policy.Remove($member) }

        return [pscustomobject]$policy
    }

    function New-ContentFilterPolicyObject {
        [CmdletBinding()]
        param(
            [object]$Name = 'Default',

            [object]$HighConfidencePhishQuarantineTag = 'AdminOnlyAccessPolicy',

            [object]$PhishQuarantineTag = 'ContosoLimited',

            [object]$HighConfidenceSpamQuarantineTag = 'ContosoLimited',

            [object]$SpamQuarantineTag = 'ContosoLimited',

            [object]$BulkQuarantineTag = 'ContosoLimited',

            [object]$SpoofQuarantineTag = 'ContosoLimited',

            [string[]]$Remove = @()
        )

        $policy = [ordered]@{
            Name                             = $Name
            HighConfidencePhishQuarantineTag = $HighConfidencePhishQuarantineTag
            PhishQuarantineTag               = $PhishQuarantineTag
            HighConfidenceSpamQuarantineTag  = $HighConfidenceSpamQuarantineTag
            SpamQuarantineTag                = $SpamQuarantineTag
            BulkQuarantineTag                = $BulkQuarantineTag
            SpoofQuarantineTag               = $SpoofQuarantineTag
        }

        foreach ($member in $Remove) { $policy.Remove($member) }

        return [pscustomobject]$policy
    }

    function New-MalwareFilterPolicyObject {
        [CmdletBinding()]
        param(
            [object]$Name = 'Default',

            [object]$QuarantineTag = 'AdminOnlyAccessPolicy',

            [string[]]$Remove = @()
        )

        $policy = [ordered]@{
            Name          = $Name
            QuarantineTag = $QuarantineTag
        }

        foreach ($member in $Remove) { $policy.Remove($member) }

        return [pscustomobject]$policy
    }

    function New-QuarantineEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [object]$QuarantinePolicy,

            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [object]$ContentFilterPolicy,

            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [object]$MalwareFilterPolicy
        )

        return Get-QuarantinePolicyEvidence `
            -QuarantinePolicyCollection { $QuarantinePolicy }.GetNewClosure() `
            -ContentFilterPolicyCollection { $ContentFilterPolicy }.GetNewClosure() `
            -MalwareFilterPolicyCollection { $MalwareFilterPolicy }.GetNewClosure()
    }

    function New-QuarantinePolicySet {
        [CmdletBinding()]
        param(
            [object]$GlobalName = 'DefaultGlobalTag',

            [object]$GlobalType = 'GlobalQuarantinePolicy',

            [object]$GlobalFrequency = '1.00:00:00',

            [object]$GlobalBlockedSender = $false,

            [object]$AdminOnlyName = 'AdminOnlyAccessPolicy',

            [object]$AdminOnlyValue = 0,

            [object]$LimitedName = 'ContosoLimited',

            [object]$LimitedValue = 106,

            [string[]]$RemoveFromGlobal = @()
        )

        return @(
            New-QuarantinePolicyObject -Name $GlobalName -QuarantinePolicyType $GlobalType `
                -EndUserSpamNotificationFrequency $GlobalFrequency `
                -IncludeMessagesFromBlockedSenderAddress $GlobalBlockedSender -Remove $RemoveFromGlobal
            New-QuarantinePolicyObject -Name $AdminOnlyName -EndUserQuarantinePermissionsValue $AdminOnlyValue
            New-QuarantinePolicyObject -Name $LimitedName -EndUserQuarantinePermissionsValue $LimitedValue
        )
    }

    function New-QuarantineDesiredState {
        [CmdletBinding()]
        param(
            [object]$EndUserSpamNotificationFrequencyInDays = 1,

            [object]$IncludeMessagesFromBlockedSenderAddress = $false,

            [object]$HighRiskCategories = @('Malware', 'HighConfidencePhish'),

            [object]$CategoryPermissions,

            [string[]]$Remove = @()
        )

        if (-not $PSBoundParameters.ContainsKey('CategoryPermissions')) {
            $CategoryPermissions = @(
                [pscustomobject]@{ category = 'Malware'; accessLevel = 'AdminOnlyAccess' }
                [pscustomobject]@{ category = 'HighConfidencePhish'; accessLevel = 'AdminOnlyAccess' }
                [pscustomobject]@{ category = 'Phish'; accessLevel = 'LimitedAccess' }
                [pscustomobject]@{ category = 'HighConfidenceSpam'; accessLevel = 'LimitedAccess' }
                [pscustomobject]@{ category = 'Spam'; accessLevel = 'LimitedAccess' }
                [pscustomobject]@{ category = 'Bulk'; accessLevel = 'LimitedAccess' }
                [pscustomobject]@{ category = 'SpoofIntelligence'; accessLevel = 'LimitedAccess' }
            )
        }

        $state = [ordered]@{
            endUserAccessLevel                      = 'LimitedAccess'
            highRiskAccessLevel                     = 'AdminOnlyAccess'
            highRiskCategories                      = $HighRiskCategories
            endUserSpamNotificationFrequencyInDays  = $EndUserSpamNotificationFrequencyInDays
            includeMessagesFromBlockedSenderAddress = $IncludeMessagesFromBlockedSenderAddress
            categoryPermissions                     = $CategoryPermissions
        }

        foreach ($member in $Remove) { $state.Remove($member) }

        return [pscustomobject]$state
    }

    function New-BaselineQuarantineEvidence {
        [CmdletBinding()]
        param(
            [object]$QuarantinePolicy,

            [object]$ContentFilterPolicy,

            [object]$MalwareFilterPolicy
        )

        if (-not $PSBoundParameters.ContainsKey('QuarantinePolicy')) { $QuarantinePolicy = New-QuarantinePolicySet }
        if (-not $PSBoundParameters.ContainsKey('ContentFilterPolicy')) { $ContentFilterPolicy = @(New-ContentFilterPolicyObject) }
        if (-not $PSBoundParameters.ContainsKey('MalwareFilterPolicy')) { $MalwareFilterPolicy = @(New-MalwareFilterPolicyObject) }

        return New-QuarantineEvidence -QuarantinePolicy $QuarantinePolicy `
            -ContentFilterPolicy $ContentFilterPolicy -MalwareFilterPolicy $MalwareFilterPolicy
    }

    function New-PartialQuarantineEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'MDO-008' -Source 'ExchangeOnline' `
            -Command 'Get-QuarantinePolicy; Get-HostedContentFilterPolicy; Get-MalwareFilterPolicy' -Value $Payload
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

    $script:DesiredQuarantine = New-QuarantineDesiredState
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'MDO-007-A1 quarantine collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector MDO-008 is registered against' {
            # Arrange
            $registered = $script:QuarantineRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes quarantine behaviour, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: the collector must be given every service call to make' {

        It 'refuses a collection with no quarantine policy to read' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-QuarantinePolicyEvidence -QuarantinePolicyCollection $noCollection -ContentFilterPolicyCollection { @() } -MalwareFilterPolicyCollection { @() } }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'QuarantinePolicyCollectionRequired*' `
                    -Because 'the quarantine policies carry the notification cadence and every end-user permission, so a record assembled without them reports a quarantine nobody looked at'
        }

        It 'refuses a collection with no hosted content filter policy to read' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-QuarantinePolicyEvidence -QuarantinePolicyCollection { @() } -ContentFilterPolicyCollection $noCollection -MalwareFilterPolicyCollection { @() } }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'ContentFilterPolicyCollectionRequired*' `
                    -Because 'the permission a category actually gets is the permission of the quarantine policy the content filter points at, so the permissions alone say nothing about which category holds them'
        }

        It 'refuses a collection with no malware filter policy to read' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-QuarantinePolicyEvidence -QuarantinePolicyCollection { @() } -ContentFilterPolicyCollection { @() } -MalwareFilterPolicyCollection $noCollection }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'MalwareFilterPolicyCollectionRequired*' `
                    -Because 'malware is quarantined by the malware filter and not by the content filter, so a record without it is a record that cannot decide the one category the card names first'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records a quarantine policy collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The term Get-QuarantinePolicy is not recognized in this session.' }

            # Act
            $evidence = Get-QuarantinePolicyEvidence -QuarantinePolicyCollection $refusing -ContentFilterPolicyCollection { @(New-ContentFilterPolicyObject) } -MalwareFilterPolicyCollection { @(New-MalwareFilterPolicyObject) }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'an exception here discards every other control in the run, and a refused command that is not recorded as refused reads downstream exactly like a quarantine that was read and found correct'
        }

        It 'records a content filter collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The operation was throttled and could not be completed.' }

            # Act
            $evidence = Get-QuarantinePolicyEvidence -QuarantinePolicyCollection { @(New-QuarantinePolicyObject) } -ContentFilterPolicyCollection $refusing -MalwareFilterPolicyCollection { @(New-MalwareFilterPolicyObject) }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'a record that keeps the quarantine permissions but loses the mapping lets a throttled tenant be decided on permissions belonging to nobody in particular'
        }

        It 'records a malware filter collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The operation was throttled and could not be completed.' }

            # Act
            $evidence = Get-QuarantinePolicyEvidence -QuarantinePolicyCollection { @(New-QuarantinePolicyObject) } -ContentFilterPolicyCollection { @(New-ContentFilterPolicyObject) } -MalwareFilterPolicyCollection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'the six categories that did answer must never be allowed to stand in for the malware category that did not, because malware is the one the card holds to admin-only first'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a tenant that holds no policy at all as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-QuarantinePolicyEvidence -QuarantinePolicyCollection $empty -ContentFilterPolicyCollection $empty -MalwareFilterPolicyCollection $empty

            # Assert
            ('collected={0}|failure={1}|{2}' -f $evidence.Collected, $evidence.FailureReason, (ConvertTo-CanonicalJson -InputObject $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|{"HostedContentFilterPolicy":[],"MalwareFilterPolicy":[],"QuarantinePolicy":[]}' `
                    -Because 'a tenant that holds no quarantine policy at all is the exact finding this control exists to report, and calling it a collection failure hides that finding behind an infrastructure excuse'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = New-QuarantineEvidence -QuarantinePolicy @(New-QuarantinePolicyObject) -ContentFilterPolicy @(New-ContentFilterPolicyObject) -MalwareFilterPolicy @(New-MalwareFilterPolicyObject)

            # Act
            $act = { $evidence.Value['QuarantinePolicy'] = @() }

            # Assert
            $act |
                Should -Throw `
                    -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one run of all three collections is one record of exactly what each returned' {

        It 'records all three policy sets whole under their own names, under the control, source and commands the registry declares' {
            # Arrange
            $globalPolicy = New-QuarantinePolicyObject -Name ' DefaultGlobalTag ' -QuarantinePolicyType 'GlobalQuarantinePolicy' -EndUserSpamNotificationFrequency '4.00:00:00'
            $customPolicy = New-QuarantinePolicyObject -Name 'ContosoLimited' -EndUserQuarantinePermissionsValue 27
            $expected = 'MDO-008|ExchangeOnline|Get-QuarantinePolicy; Get-HostedContentFilterPolicy; Get-MalwareFilterPolicy|collected=True|failure=|' +
            '{"HostedContentFilterPolicy":[{"BulkQuarantineTag":"ContosoLimited","HighConfidencePhishQuarantineTag":"AdminOnlyAccessPolicy",' +
            '"HighConfidenceSpamQuarantineTag":"ContosoLimited","Name":"Default","PhishQuarantineTag":"ContosoLimited",' +
            '"SpamQuarantineTag":"ContosoLimited","SpoofQuarantineTag":"ContosoLimited"}],' +
            '"MalwareFilterPolicy":[{"Name":"Default","QuarantineTag":"AdminOnlyAccessPolicy"}],' +
            '"QuarantinePolicy":[{"ESNEnabled":true,"EndUserQuarantinePermissionsValue":0,"EndUserSpamNotificationFrequency":"4.00:00:00",' +
            '"IncludeMessagesFromBlockedSenderAddress":false,"Name":" DefaultGlobalTag ","QuarantinePolicyType":"GlobalQuarantinePolicy"},' +
            '{"ESNEnabled":true,"EndUserQuarantinePermissionsValue":27,"EndUserSpamNotificationFrequency":"1.00:00:00",' +
            '"IncludeMessagesFromBlockedSenderAddress":false,"Name":"ContosoLimited","QuarantinePolicyType":"QuarantinePolicy"}]}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = New-QuarantineEvidence -QuarantinePolicy @($globalPolicy, $customPolicy) -ContentFilterPolicy @(New-ContentFilterPolicyObject) -MalwareFilterPolicy @(New-MalwareFilterPolicyObject)

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so the wrong cadence, the whitespace around the global policy name, the custom policy sitting beside it and every member no decision reads all have to survive collection; a collector that filtered to the global policy or narrowed each policy to the members the control decides on would settle the cadence and the permissions before the evaluator ever saw them'
        }
    }
}

Describe 'MDO-007-A2 quarantine evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator MDO-008 is registered against' {
            # Arrange
            $registered = $script:QuarantineRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides quarantine behaviour, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation and the quarantine state the baseline resolved' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = { Test-QuarantinePolicyControl -Evidence $noEvidence -DesiredState $script:DesiredQuarantine }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceRequired*' `
                    -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'MDO-001' -Source 'ExchangeOnline' `
                -Command 'Get-QuarantinePolicy; Get-HostedContentFilterPolicy; Get-MalwareFilterPolicy' `
                -Value ([ordered]@{
                    QuarantinePolicy          = New-QuarantinePolicySet
                    HostedContentFilterPolicy = @(New-ContentFilterPolicyObject)
                    MalwareFilterPolicy       = @(New-MalwareFilterPolicyObject)
                })

            # Act
            $act = { Test-QuarantinePolicyControl -Evidence $foreign -DesiredState $script:DesiredQuarantine }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' `
                    -Because 'the same three commands feed more than one Defender control, so a record collected for one is exactly the record that must not decide the other'
        }

        It 'refuses a decision that names no resolved desired quarantine state' {
            # Arrange
            $evidence = New-BaselineQuarantineEvidence

            # Act
            $act = { Test-QuarantinePolicyControl -Evidence $evidence -DesiredState $null }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredQuarantineStateRequired*' `
                    -Because 'an evaluator handed no desired state decides against whatever it defaults to rather than against what was approved'
        }

        It 'refuses a desired state that declares no end-user notification cadence' {
            # Arrange
            $evidence = New-BaselineQuarantineEvidence
            $silent = New-QuarantineDesiredState -Remove @('endUserSpamNotificationFrequencyInDays')

            # Act
            $act = { Test-QuarantinePolicyControl -Evidence $evidence -DesiredState $silent }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredQuarantineNotificationCadenceRequired*' `
                    -Because 'the cadence is the whole reason a user ever learns a message was quarantined, and a baseline that declares none compares every tenant against nothing at all'
        }

        It 'refuses a desired cadence of <Declared>, which is not a positive whole number of days' -ForEach @(
            @{ Declared = 0 }
            @{ Declared = -1 }
            @{ Declared = 1.5 }
            @{ Declared = 'daily' }
        ) {
            # Arrange
            $evidence = New-BaselineQuarantineEvidence
            $unusable = New-QuarantineDesiredState -EndUserSpamNotificationFrequencyInDays $Declared

            # Act
            $act = { Test-QuarantinePolicyControl -Evidence $evidence -DesiredState $unusable }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredQuarantineNotificationCadenceInvalid*' `
                    -Because 'the card requires an exact cadence, and a declared cadence that is not a countable number of days cannot be compared exactly against anything the tenant reports'
        }

        It 'refuses a desired state that declares no blocked-sender decision' {
            # Arrange
            $evidence = New-BaselineQuarantineEvidence
            $undecided = New-QuarantineDesiredState -Remove @('includeMessagesFromBlockedSenderAddress')

            # Act
            $act = { Test-QuarantinePolicyControl -Evidence $evidence -DesiredState $undecided }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredQuarantineBlockedSenderDecisionRequired*' `
                    -Because 'including blocked senders in end-user notifications is a decision somebody makes, and a baseline that never made it reads identically to a baseline that decided against it'
        }

        It 'refuses a desired state that declares no category permission at all' -ForEach @(
            @{ Shape = 'absent' }
            @{ Shape = 'empty' }
        ) {
            # Arrange
            $evidence = New-BaselineQuarantineEvidence
            $unmapped = if ($Shape -ceq 'absent') {
                New-QuarantineDesiredState -Remove @('categoryPermissions')
            }
            else {
                New-QuarantineDesiredState -CategoryPermissions @()
            }

            # Act
            $act = { Test-QuarantinePolicyControl -Evidence $evidence -DesiredState $unmapped }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredQuarantineCategoryPermissionRequired*' `
                    -Because 'the category permissions are the entire comparison this control makes, and a tenant compared against none of them passes with every category on full end-user access'
        }

        It 'refuses a category permission naming no <Missing>' -ForEach @(
            @{ Missing = 'category'; Entry = [pscustomobject]@{ category = '  '; accessLevel = 'AdminOnlyAccess' } }
            @{ Missing = 'accessLevel'; Entry = [pscustomobject]@{ category = 'Malware'; accessLevel = '' } }
        ) {
            # Arrange
            $evidence = New-BaselineQuarantineEvidence
            $incomplete = New-QuarantineDesiredState -CategoryPermissions @($Entry)

            # Act
            $act = { Test-QuarantinePolicyControl -Evidence $evidence -DesiredState $incomplete }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredQuarantineCategoryPermissionIncomplete*' `
                    -Because 'a permission missing either half approves nothing, and reading it as a permission grants whatever the missing half happens to default to'
        }

        It 'refuses a desired state that declares no high-risk category' -ForEach @(
            @{ Shape = 'absent' }
            @{ Shape = 'empty' }
        ) {
            # Arrange
            $evidence = New-BaselineQuarantineEvidence
            $unranked = if ($Shape -ceq 'absent') {
                New-QuarantineDesiredState -Remove @('highRiskCategories')
            }
            else {
                New-QuarantineDesiredState -HighRiskCategories @()
            }

            # Act
            $act = { Test-QuarantinePolicyControl -Evidence $evidence -DesiredState $unranked }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredQuarantineHighRiskCategoryRequired*' `
                    -Because 'malware and high-confidence phishing being admin-only is the clause the card holds first, and a baseline that names no high-risk category has quietly dropped that clause'
        }

        It 'refuses a high-risk category no declared category permission covers' {
            # Arrange
            $evidence = New-BaselineQuarantineEvidence
            $uncovered = New-QuarantineDesiredState -HighRiskCategories @('Malware', 'HighConfidencePhish') -CategoryPermissions @(
                [pscustomobject]@{ category = 'Malware'; accessLevel = 'AdminOnlyAccess' }
            )

            # Act
            $act = { Test-QuarantinePolicyControl -Evidence $evidence -DesiredState $uncovered }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredQuarantineHighRiskCategoryUncovered*' `
                    -Because 'a category named high-risk and then never given a permission is a category this control would never look at, which is the one outcome naming it high-risk was supposed to prevent'
        }

        It 'refuses a high-risk category the baseline does not hold at admin-only access' {
            # Arrange
            $evidence = New-BaselineQuarantineEvidence
            $relaxed = New-QuarantineDesiredState -HighRiskCategories @('Malware') -CategoryPermissions @(
                [pscustomobject]@{ category = 'Malware'; accessLevel = 'LimitedAccess' }
            )

            # Act
            $act = { Test-QuarantinePolicyControl -Evidence $evidence -DesiredState $relaxed }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredQuarantineHighRiskAccessRequired*' `
                    -Because 'the card requires malware and high-confidence phishing to be admin-only, so a baseline that names one high-risk and then lets end users reach it is a baseline this control must refuse rather than faithfully enforce'
        }

        It 'refuses an access level the permission contract does not name' {
            # Arrange
            $evidence = New-BaselineQuarantineEvidence
            $invented = New-QuarantineDesiredState -HighRiskCategories @('Malware') -CategoryPermissions @(
                [pscustomobject]@{ category = 'Malware'; accessLevel = 'AdminOnlyAccess' }
                [pscustomobject]@{ category = 'Spam'; accessLevel = 'ReadOnlyAccess' }
            )

            # Act
            $act = { Test-QuarantinePolicyControl -Evidence $evidence -DesiredState $invented }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredQuarantineAccessLevelUnknown*' `
                    -Because 'Exchange Online reports end-user permissions as a bitmask rather than a name, so an access level with no declared value resolves to nothing and would silently compare every tenant as compliant'
        }

        It 'refuses a category the control can locate no quarantine tag for' {
            # Arrange
            $evidence = New-BaselineQuarantineEvidence
            $unlocatable = New-QuarantineDesiredState -HighRiskCategories @('Malware') -CategoryPermissions @(
                [pscustomobject]@{ category = 'Malware'; accessLevel = 'AdminOnlyAccess' }
                [pscustomobject]@{ category = 'Ransomware'; accessLevel = 'AdminOnlyAccess' }
            )

            # Act
            $act = { Test-QuarantinePolicyControl -Evidence $evidence -DesiredState $unlocatable }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredQuarantineCategoryUnmapped*' `
                    -Because 'a category with no filter member behind it is a category the tenant is never actually checked for, and skipping it silently reports coverage the run never looked for'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-QuarantinePolicyEvidence `
                -QuarantinePolicyCollection { throw 'The operation was throttled and could not be completed.' } `
                -ContentFilterPolicyCollection { @() } `
                -MalwareFilterPolicyCollection { @() }

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $refused -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a control the run never managed to observe must cost the run its go-live, because the alternative is that throttling the tenant is the cheapest way to pass it'
        }
    }

    Context 'Negative: a record that never observed a policy set decides nothing about it' {

        It 'decides a record carrying no <Observation> observation as an error' -ForEach @(
            @{ Observation = 'QuarantinePolicy' }
            @{ Observation = 'HostedContentFilterPolicy' }
            @{ Observation = 'MalwareFilterPolicy' }
        ) {
            # Arrange
            $payload = [ordered]@{
                QuarantinePolicy          = New-QuarantinePolicySet
                HostedContentFilterPolicy = @(New-ContentFilterPolicyObject)
                MalwareFilterPolicy       = @(New-MalwareFilterPolicyObject)
            }
            $payload.Remove($Observation)
            $partial = New-PartialQuarantineEvidence -Payload $payload

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $partial -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=QuarantineEvidenceIncomplete: the record carries no '$Observation' observation." `
                    -Because 'an absent policy set is not an observation that the tenant holds no such policy, and reading it as one decides a category from a command nobody ran'
        }

        It 'decides an observed quarantine policy carrying no <Member> member as an error' -ForEach @(
            @{ Member = 'Name' }
            @{ Member = 'QuarantinePolicyType' }
            @{ Member = 'EndUserQuarantinePermissionsValue' }
            @{ Member = 'EndUserSpamNotificationFrequency' }
            @{ Member = 'IncludeMessagesFromBlockedSenderAddress' }
        ) {
            # Arrange
            $incomplete = New-BaselineQuarantineEvidence -QuarantinePolicy (New-QuarantinePolicySet -RemoveFromGlobal @($Member))

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $incomplete -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=QuarantineEvidenceIncomplete: an observed QuarantinePolicy carries no '$Member' member." `
                    -Because 'an absent member read as its default reports a cadence, a permission or a policy type the collector never carried, which is indistinguishable from one the tenant actually holds'
        }

        It 'decides an observed <Observation> carrying no <Member> member for <Category> as an error' -ForEach @(
            @{ Observation = 'MalwareFilterPolicy'; Member = 'QuarantineTag'; Category = 'Malware' }
            @{ Observation = 'HostedContentFilterPolicy'; Member = 'HighConfidencePhishQuarantineTag'; Category = 'HighConfidencePhish' }
            @{ Observation = 'HostedContentFilterPolicy'; Member = 'PhishQuarantineTag'; Category = 'Phish' }
            @{ Observation = 'HostedContentFilterPolicy'; Member = 'HighConfidenceSpamQuarantineTag'; Category = 'HighConfidenceSpam' }
            @{ Observation = 'HostedContentFilterPolicy'; Member = 'SpamQuarantineTag'; Category = 'Spam' }
            @{ Observation = 'HostedContentFilterPolicy'; Member = 'BulkQuarantineTag'; Category = 'Bulk' }
            @{ Observation = 'HostedContentFilterPolicy'; Member = 'SpoofQuarantineTag'; Category = 'SpoofIntelligence' }
        ) {
            # Arrange
            $incomplete = if ($Observation -ceq 'MalwareFilterPolicy') {
                New-BaselineQuarantineEvidence -MalwareFilterPolicy @(New-MalwareFilterPolicyObject -Remove @($Member))
            }
            else {
                New-BaselineQuarantineEvidence -ContentFilterPolicy @(New-ContentFilterPolicyObject -Remove @($Member))
            }

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $incomplete -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=QuarantineEvidenceIncomplete: an observed $Observation carries no '$Member' member for '$Category'." `
                    -Because 'a missing tag member read as empty reports a category released under no quarantine policy at all, which is a finding about the collector rather than about the tenant'
        }
    }

    Context 'Negative: a tenant the record cannot describe unambiguously decides nothing' {

        It 'decides a record carrying two global quarantine policies as an error' {
            # Arrange
            $ambiguous = New-BaselineQuarantineEvidence -QuarantinePolicy @(
                New-QuarantinePolicyObject -Name 'DefaultGlobalTag' -QuarantinePolicyType 'GlobalQuarantinePolicy'
                New-QuarantinePolicyObject -Name 'SecondGlobalTag' -QuarantinePolicyType 'GlobalQuarantinePolicy'
            )

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $ambiguous -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Error|golive=False|reason=QuarantineEvidenceAmbiguous: the record carries 2 global quarantine policies where the tenant holds one.' `
                    -Because 'the global policy is the single tenant-wide object the cadence and the blocked-sender decision are read from, so picking one of two would pick the verdict by ordering'
        }

        It 'decides a record carrying two quarantine policies under one name as an error' {
            # Arrange
            $ambiguous = New-BaselineQuarantineEvidence -QuarantinePolicy @(
                New-QuarantinePolicyObject -Name 'ContosoLimited' -EndUserQuarantinePermissionsValue 106
                New-QuarantinePolicyObject -Name ' contosolimited ' -EndUserQuarantinePermissionsValue 236
            )

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $ambiguous -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=QuarantineEvidenceAmbiguous: the record carries two quarantine policies under the name 'contosolimited'." `
                    -Because 'every category is resolved to its permission by looking the tag name up, so two policies answering to one name resolve every category to whichever one the enumeration reached first'
        }

        It 'decides a notification cadence that is not a time span at all as an error' {
            # Arrange
            $unreadable = New-BaselineQuarantineEvidence -QuarantinePolicy (New-QuarantinePolicySet -GlobalFrequency 'EveryDay')

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $unreadable -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=QuarantineEvidenceNotRecognized: the global quarantine policy reports an end-user notification cadence of 'EveryDay', which is not a time span." `
                    -Because 'a cadence nobody can read is not a cadence that differs from the baseline, and reporting it as drift sends an operator to fix a tenant whose evidence is what actually broke'
        }
    }

    Context 'Negative: a tenant that holds no policy set at all fails, naming what is missing' {

        It 'fails a tenant that observed no <Missing>' -ForEach @(
            @{ Missing = 'global quarantine policy' }
            @{ Missing = 'hosted content filter policy' }
            @{ Missing = 'malware filter policy' }
        ) {
            # Arrange
            $argument = switch ($Missing) {
                'global quarantine policy' {
                    @{ QuarantinePolicy = @(
                            New-QuarantinePolicyObject -Name 'AdminOnlyAccessPolicy' -EndUserQuarantinePermissionsValue 0
                            New-QuarantinePolicyObject -Name 'ContosoLimited' -EndUserQuarantinePermissionsValue 106
                        )
                    }
                }
                'hosted content filter policy' { @{ ContentFilterPolicy = @() } }
                default { @{ MalwareFilterPolicy = @() } }
            }
            $bare = New-BaselineQuarantineEvidence @argument

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $bare -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=QuarantineDrift: the tenant holds no $Missing." `
                    -Because 'a policy set the tenant simply does not hold is the exact finding this control exists to report, and a verdict that did not name which one leaves the operator nothing to act on'
        }
    }

    Context 'Negative: a global quarantine policy that does not notify exactly as declared fails' {

        It 'fails a cadence of <Observed>, naming the cadence observed and the cadence required' -ForEach @(
            @{ Observed = '4.00:00:00' }
            @{ Observed = '7.00:00:00' }
            @{ Observed = '1.06:00:00' }
            @{ Observed = '00:00:00' }
        ) {
            # Arrange
            $drifted = New-BaselineQuarantineEvidence -QuarantinePolicy (New-QuarantinePolicySet -GlobalFrequency $Observed)

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $drifted -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=QuarantineDrift: the global quarantine policy notifies end users every '$Observed' where exactly 1 day is required." `
                    -Because 'the card requires an exact cadence, so a tenant that merely notifies at all - four days later, a week later, or six hours past the declared day - is not the tenant the baseline approved'
        }

        It 'fails a blocked-sender inclusion that differs from the baseline' {
            # Arrange
            $drifted = New-BaselineQuarantineEvidence -QuarantinePolicy (New-QuarantinePolicySet -GlobalBlockedSender $true)

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $drifted -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=QuarantineDrift: the global quarantine policy includes messages from blocked senders as 'True' where 'False' is required." `
                    -Because 'notifying end users about mail from senders they already blocked hands the blocked sender a delivery channel the user explicitly closed'
        }
    }

    Context 'Negative: a category that does not resolve to exactly the declared access level fails' {

        It 'fails a category whose quarantine tag names a policy the tenant does not hold, naming the category and the tag' {
            # Arrange
            $dangling = New-BaselineQuarantineEvidence -ContentFilterPolicy @(New-ContentFilterPolicyObject -PhishQuarantineTag 'ContosoRetired')

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $dangling -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=QuarantineDrift: the HostedContentFilterPolicy 'Default' releases 'Phish' under quarantine tag 'ContosoRetired', which the tenant does not hold." `
                    -Because 'a tag naming a policy that is not there resolves to no permission at all, and a control that skipped it would report a category as compliant precisely because it could not be checked'
        }

        It 'fails a category whose resolved permission value is not exactly the declared access level, naming the category, the value observed and the value required' {
            # Arrange
            $overPermissive = New-BaselineQuarantineEvidence -QuarantinePolicy (New-QuarantinePolicySet -LimitedValue 236)

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $overPermissive -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly ("Fail|golive=False|reason=QuarantineDrift: " +
                    "the HostedContentFilterPolicy 'Default' resolves 'Phish' to permission value '236' where 'LimitedAccess' requires '106'; " +
                    "the HostedContentFilterPolicy 'Default' resolves 'HighConfidenceSpam' to permission value '236' where 'LimitedAccess' requires '106'; " +
                    "the HostedContentFilterPolicy 'Default' resolves 'Spam' to permission value '236' where 'LimitedAccess' requires '106'; " +
                    "the HostedContentFilterPolicy 'Default' resolves 'Bulk' to permission value '236' where 'LimitedAccess' requires '106'; " +
                    "the HostedContentFilterPolicy 'Default' resolves 'SpoofIntelligence' to permission value '236' where 'LimitedAccess' requires '106'.") `
                    -Because 'the permission is a bitmask rather than a name, so a tenant whose limited-access policy has quietly been granted release and allow-sender reads as limited access to everybody who only checked the tag it points at'
        }

        It 'fails <Category> resolving to anything other than admin-only access, naming the category' -ForEach @(
            @{ Category = 'Malware' }
            @{ Category = 'HighConfidencePhish' }
        ) {
            # Arrange
            $reachable = if ($Category -ceq 'Malware') {
                New-BaselineQuarantineEvidence -MalwareFilterPolicy @(New-MalwareFilterPolicyObject -QuarantineTag 'ContosoLimited')
            }
            else {
                New-BaselineQuarantineEvidence -ContentFilterPolicy @(New-ContentFilterPolicyObject -HighConfidencePhishQuarantineTag 'ContosoLimited')
            }
            $observation = if ($Category -ceq 'Malware') { 'MalwareFilterPolicy' } else { 'HostedContentFilterPolicy' }

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $reachable -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=QuarantineDrift: the $observation 'Default' resolves high-risk '$Category' to permission value '106' where admin-only access requires '0'." `
                    -Because 'the card holds malware and high-confidence phishing admin-only first, so any end-user access to either is the one drift this control must never round down to a lesser finding'
        }

        It 'fails drift in one filter policy even when another filter policy is correct' {
            # Arrange
            $mixed = New-BaselineQuarantineEvidence -ContentFilterPolicy @(
                New-ContentFilterPolicyObject -Name 'Default'
                New-ContentFilterPolicyObject -Name 'Executives' -HighConfidencePhishQuarantineTag 'ContosoLimited'
            )

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $mixed -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=QuarantineDrift: the HostedContentFilterPolicy 'Executives' resolves high-risk 'HighConfidencePhish' to permission value '106' where admin-only access requires '0'." `
                    -Because 'every hosted content filter policy applies to some population, so an evaluator that stops once one policy agrees reports the whole tenant protected by a policy that reaches only part of it'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-QuarantinePolicyControl `
                -Evidence (New-BaselineQuarantineEvidence -QuarantinePolicy (New-QuarantinePolicySet -GlobalFrequency '7.00:00:00')) `
                -DesiredState $script:DesiredQuarantine

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act |
                Should -Throw `
                    -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: the declared cadence, the declared blocked-sender decision and every category at exactly its declared access level is one go-live-successful pass' {

        It 'passes a tenant whose global policy notifies exactly as declared and whose every filter policy maps every category to exactly its declared access level, with malware and high-confidence phishing admin-only' {
            # Arrange
            $policy = @(
                New-QuarantinePolicyObject -Name ' DefaultGlobalTag ' -QuarantinePolicyType ' globalquarantinepolicy ' `
                    -EndUserSpamNotificationFrequency '1.00:00:00' -IncludeMessagesFromBlockedSenderAddress $false
                New-QuarantinePolicyObject -Name ' AdminOnlyAccessPolicy ' -EndUserQuarantinePermissionsValue 0
                New-QuarantinePolicyObject -Name 'contosolimited' -EndUserQuarantinePermissionsValue 106
            )
            $contentFilter = @(
                New-ContentFilterPolicyObject -Name 'Default' -HighConfidencePhishQuarantineTag 'ADMINONLYACCESSPOLICY' `
                    -PhishQuarantineTag ' ContosoLimited ' -HighConfidenceSpamQuarantineTag 'ContosoLimited' `
                    -SpamQuarantineTag 'contosoLIMITED' -BulkQuarantineTag 'ContosoLimited ' -SpoofQuarantineTag ' contosolimited'
                New-ContentFilterPolicyObject -Name 'Executives'
            )
            $configured = New-BaselineQuarantineEvidence -QuarantinePolicy $policy -ContentFilterPolicy $contentFilter `
                -MalwareFilterPolicy @(New-MalwareFilterPolicyObject -QuarantineTag ' adminonlyaccesspolicy ')
            $expected = 'MDO-008|Pass|normalized=True|golive=True|reason=|evidence=Get-QuarantinePolicy; Get-HostedContentFilterPolicy; Get-MalwareFilterPolicy:MDO-008'

            # Act
            $result = Test-QuarantinePolicyControl -Evidence $configured -DesiredState $script:DesiredQuarantine

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'a quarantine tag is matched by name, and Exchange Online reports that name back in whatever casing and whitespace it was stored with, so a control that read those differences as drift would fail every correctly configured tenant; the second filter policy has to be read as well as the first, and the verdict has to be one normalized pass naming the record it was decided from rather than a bare true'
        }
    }
}
