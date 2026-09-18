#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement is not installed and must never be imported. Get-AtpPolicyForO365 is
    # reached only through the supplied collection seam, so every collection here is a scriptblock
    # returning a canned policy or throwing a canned failure.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # Assigning before unrolling matters: the registry is returned as one read-only collection
    # deliberately protected from pipeline unrolling, so it is read by index rather than by pipe.
    $script:ControlRegistry = @(Get-BaselineControlRegistry)[0]
    $script:SafeAttachmentsRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'MDO-004') { $entry }
        })[0]
    $script:SafeDocumentsRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'MDO-005') { $entry }
        })[0]

    function New-AtpPolicy {
        [CmdletBinding()]
        param(
            [object]$Name = 'Default',

            [object]$AllowSafeDocsOpen = $false,

            [object]$EnableATPForSPOTeamsODB = $true,

            [object]$EnableSafeDocs = $true
        )

        return [pscustomobject]@{
            AllowSafeDocsOpen       = $AllowSafeDocsOpen
            EnableATPForSPOTeamsODB = $EnableATPForSPOTeamsODB
            EnableSafeDocs          = $EnableSafeDocs
            Identity                = $Name
            Name                    = $Name
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

    # MDO-001: Safe Attachments for SharePoint, OneDrive and Teams is the one decision the baseline
    # resolves for this control, and it resolves to on.
    $script:DesiredSafeAttachments = [pscustomobject]@{ safeAttachmentsForSharePointOneDriveTeams = $true }

    function New-AtpPolicyWithout {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Member
        )

        $policy = [ordered]@{
            AllowSafeDocsOpen       = $false
            EnableATPForSPOTeamsODB = $true
            EnableSafeDocs          = $true
            Name                    = 'Default'
        }

        $policy.Remove($Member)

        return [pscustomobject]$policy
    }

    function New-SafeAttachmentsEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [object]$Policy
        )

        return Get-SafeAttachmentsEvidence -AtpPolicyCollection { $Policy }.GetNewClosure()
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

    # MDO-001: Safe Documents is two decisions - the scanner is on, and a user cannot open a file
    # it called malicious anyway - plus the service plan the entitlement must be verified against.
    $script:DesiredSafeDocuments = [pscustomobject]@{
        enabled             = $true
        allowBypass         = $false
        requiredServicePlan = 'SAFEDOCS'
        licenseRequired     = 'Microsoft 365 E5/A5/G5 or Microsoft Defender Suite'
    }

    # LIC-009: the shape `Test-BaselineSafeDocumentsPreflight` returns. The evaluator is handed one
    # of these rather than inferring entitlement from the observed policy, because an unlicensed
    # tenant and a licensed tenant that switched Safe Documents off report the same policy.
    $script:EntitlementReason = @{
        Pass        = "Safe Documents may be applied: the tenant holds an enabled 'SAFEDOCS' plan and all 2 licensing targets hold it enabled."
        NotEntitled = "Safe Documents is not applied: neither the tenant nor any of the 2 licensing targets holds an enabled 'SAFEDOCS' plan."
        Fail        = "Safe Documents preflight failed: the tenant 'SAFEDOCS' verdict is True while 1 of 2 licensing targets do not hold the plan enabled."
    }

    function New-EntitlementVerdict {
        [CmdletBinding()]
        param(
            [object]$Status = 'Pass',

            [object]$PlanName = 'SAFEDOCS'
        )

        return [pscustomobject]@{
            Source                  = 'BaselineSafeDocumentsPreflight'
            RequiredServicePlanName = $PlanName
            RequiredServicePlanId   = 'bf6f5520-59e3-4f82-974b-7dbbc4fd27c7'
            TenantEntitled          = ($Status -ceq 'Pass')
            Status                  = $Status
            MayApply                = ($Status -ceq 'Pass')
            Reason                  = $script:EntitlementReason[[string]$Status]
        }
    }

    function New-SafeDocumentsEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [object]$Policy
        )

        return Get-SafeDocumentsEvidence -AtpPolicyCollection { $Policy }.GetNewClosure()
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'MDO-006-A1 Safe Attachments collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector MDO-004 is registered against' {
            # Arrange
            $registered = $script:SafeAttachmentsRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes Safe Attachments for SharePoint, OneDrive and Teams, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: the collector must be given the service call to make' {

        It 'refuses a collection with no ATP policy to read' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-SafeAttachmentsEvidence -AtpPolicyCollection $noCollection }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'AtpPolicyCollectionRequired*' `
                    -Because 'the tenant ATP policy is the only place Safe Attachments for SharePoint, OneDrive and Teams is recorded, and a record assembled without reading it reports a file-protection posture nobody looked up'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records a collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The term Get-AtpPolicyForO365 is not recognized in this session.' }

            # Act
            $evidence = Get-SafeAttachmentsEvidence -AtpPolicyCollection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'an exception here discards every other control in the run, and a refused command that is not recorded as refused reads downstream exactly like a tenant that was read and found scanning its files'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a tenant that holds no ATP policy at all as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-SafeAttachmentsEvidence -AtpPolicyCollection $empty

            # Assert
            ('collected={0}|failure={1}|{2}' -f $evidence.Collected, $evidence.FailureReason, (ConvertTo-CanonicalJson -InputObject $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|{"AtpPolicyForO365":[]}' `
                    -Because 'a tenant whose ATP policy could not be found is the exact finding this control exists to report, and calling it a collection failure hides that finding behind an infrastructure excuse'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = Get-SafeAttachmentsEvidence -AtpPolicyCollection { @(New-AtpPolicy -EnableATPForSPOTeamsODB $false) }

            # Act
            $act = { $evidence.Value['AtpPolicyForO365'] = @() }

            # Assert
            $act |
                Should -Throw `
                    -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one run of the collection is one record of exactly what the command returned' {

        It 'records the policy whole under its declared name, under the control, source and command the registry declares' {
            # Arrange
            $policy = New-AtpPolicy -Name ' Default ' -EnableATPForSPOTeamsODB $false -EnableSafeDocs $false -AllowSafeDocsOpen $true
            $expected = 'MDO-004|ExchangeOnline|Get-AtpPolicyForO365|collected=True|failure=|' +
            '{"AtpPolicyForO365":[{"AllowSafeDocsOpen":true,"EnableATPForSPOTeamsODB":false,' +
            '"EnableSafeDocs":false,"Identity":" Default ","Name":" Default "}]}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = Get-SafeAttachmentsEvidence -AtpPolicyCollection { @($policy) }.GetNewClosure()

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so the policy has to survive collection with its whitespace and its Safe Documents siblings intact; a collector that narrowed the policy to the single member Safe Attachments is decided on would leave Safe Documents with no observation to be decided from at all'
        }
    }
}

Describe 'MDO-006-A2 Safe Attachments evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator MDO-004 is registered against' {
            # Arrange
            $registered = $script:SafeAttachmentsRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides Safe Attachments, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation and the state the baseline resolved' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = { Test-SafeAttachmentsControl -Evidence $noEvidence -DesiredState $script:DesiredSafeAttachments }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceRequired*' `
                    -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'MDO-005' -Source 'ExchangeOnline' `
                -Command 'Get-AtpPolicyForO365' -Value ([ordered]@{ AtpPolicyForO365 = @(New-AtpPolicy) })

            # Act
            $act = { Test-SafeAttachmentsControl -Evidence $foreign -DesiredState $script:DesiredSafeAttachments }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' `
                    -Because 'Safe Attachments and Safe Documents are recorded by the same command under two controls with two entitlements, so a record collected for one is exactly the record that must not decide the other'
        }

        It 'refuses a decision that names no resolved desired Safe Attachments state' {
            # Arrange
            $evidence = New-SafeAttachmentsEvidence -Policy @(New-AtpPolicy)

            # Act
            $act = { Test-SafeAttachmentsControl -Evidence $evidence -DesiredState $null }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredSafeAttachmentsStateRequired*' `
                    -Because 'an evaluator handed no desired state decides against whatever it defaults to rather than against what was approved'
        }

        It 'refuses a desired state that resolves no Safe Attachments decision at all' {
            # Arrange
            $evidence = New-SafeAttachmentsEvidence -Policy @(New-AtpPolicy)
            $undeclared = [pscustomobject]@{ zeroHourAutoPurge = $true }

            # Act
            $act = { Test-SafeAttachmentsControl -Evidence $evidence -DesiredState $undeclared }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredSafeAttachmentsDecisionRequired*' `
                    -Because 'a baseline that switched file scanning off and a baseline that never decided read identically once the member is absent, and only one of them is a decision somebody made'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-SafeAttachmentsEvidence -AtpPolicyCollection { throw 'The operation was throttled and could not be completed.' }

            # Act
            $result = Test-SafeAttachmentsControl -Evidence $refused -DesiredState $script:DesiredSafeAttachments

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a control the run never managed to observe must cost the run its go-live, because the alternative is that throttling the tenant is the cheapest way to pass it'
        }
    }

    Context 'Negative: a record that never observed the policy decides nothing about it' {

        It 'decides a record carrying no ATP policy observation as an error' {
            # Arrange
            $partial = New-BaselineEvidence -ControlId 'MDO-004' -Source 'ExchangeOnline' `
                -Command 'Get-AtpPolicyForO365' -Value ([ordered]@{ SafeAttachmentPolicy = @(New-AtpPolicy) })

            # Act
            $result = Test-SafeAttachmentsControl -Evidence $partial -DesiredState $script:DesiredSafeAttachments

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=SafeAttachmentsEvidenceIncomplete: the record carries no 'AtpPolicyForO365' observation." `
                    -Because 'an absent observation is not an observation that the tenant holds no ATP policy, and reading it as one decides the control from a command nobody ran'
        }

        It 'decides an observed policy carrying no EnableATPForSPOTeamsODB member as an error' {
            # Arrange
            $incomplete = New-SafeAttachmentsEvidence -Policy @(New-AtpPolicyWithout -Member 'EnableATPForSPOTeamsODB')

            # Act
            $result = Test-SafeAttachmentsControl -Evidence $incomplete -DesiredState $script:DesiredSafeAttachments

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=SafeAttachmentsEvidenceIncomplete: an observed AtpPolicyForO365 carries no 'EnableATPForSPOTeamsODB' member." `
                    -Because 'an absent switch read as off reports a tenant scanning nothing, which is indistinguishable from a policy the collector simply did not carry'
        }

        It 'decides more than one observed ATP policy as an error' {
            # Arrange
            $ambiguous = New-SafeAttachmentsEvidence -Policy @((New-AtpPolicy), (New-AtpPolicy -Name 'Legacy' -EnableATPForSPOTeamsODB $false))

            # Act
            $result = Test-SafeAttachmentsControl -Evidence $ambiguous -DesiredState $script:DesiredSafeAttachments

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Error|golive=False|reason=SafeAttachmentsEvidenceAmbiguous: the record carries 2 AtpPolicyForO365 observations where the tenant holds one.' `
                    -Because 'the ATP policy is one tenant-wide object, so two of them means the record is not what it claims to be, and deciding from whichever one happened to be first picks the verdict by ordering'
        }
    }

    Context 'Negative: a tenant whose observed Safe Attachments state is not the resolved state fails' {

        It 'fails a tenant that holds no ATP policy at all' {
            # Arrange
            $absent = New-SafeAttachmentsEvidence -Policy @()

            # Act
            $result = Test-SafeAttachmentsControl -Evidence $absent -DesiredState $script:DesiredSafeAttachments

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=SafeAttachmentsDrift: the tenant holds no ATP policy.' `
                    -Because 'a tenant with no ATP policy scans no file in SharePoint, OneDrive or Teams, which is the finding rather than an absence of one'
        }

        It 'fails a tenant whose Safe Attachments for SharePoint, OneDrive and Teams is switched off' {
            # Arrange
            $switchedOff = New-SafeAttachmentsEvidence -Policy @(New-AtpPolicy -EnableATPForSPOTeamsODB $false)

            # Act
            $result = Test-SafeAttachmentsControl -Evidence $switchedOff -DesiredState $script:DesiredSafeAttachments

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=SafeAttachmentsDrift: 'EnableATPForSPOTeamsODB' is 'False' where 'True' is required." `
                    -Because 'the switch being off is the whole control, and a verdict that did not name the observed state leaves the operator nothing to act on'
        }

        It 'fails a tenant that switched Safe Attachments on where the baseline resolved it off' {
            # Arrange
            $switchedOn = New-SafeAttachmentsEvidence -Policy @(New-AtpPolicy -EnableATPForSPOTeamsODB $true)
            $withheld = [pscustomobject]@{ safeAttachmentsForSharePointOneDriveTeams = $false }

            # Act
            $result = Test-SafeAttachmentsControl -Evidence $switchedOn -DesiredState $withheld

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=SafeAttachmentsDrift: 'EnableATPForSPOTeamsODB' is 'True' where 'False' is required." `
                    -Because 'the card requires the observed state match the desired state, and an evaluator that only ever checked the switch was on would report a tenant compliant with a baseline it never read'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-SafeAttachmentsControl `
                -Evidence (New-SafeAttachmentsEvidence -Policy @(New-AtpPolicy -EnableATPForSPOTeamsODB $false)) `
                -DesiredState $script:DesiredSafeAttachments

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act |
                Should -Throw `
                    -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: the observed state being exactly the resolved state is one go-live-successful pass' {

        It 'passes a tenant whose ATP policy holds exactly the Safe Attachments state the baseline resolved' {
            # Arrange
            $configured = New-SafeAttachmentsEvidence -Policy @(New-AtpPolicy -Name ' Default ' -EnableSafeDocs $false -AllowSafeDocsOpen $true)
            $expected = 'MDO-004|Pass|normalized=True|golive=True|reason=|evidence=Get-AtpPolicyForO365:MDO-004'

            # Act
            $result = Test-SafeAttachmentsControl -Evidence $configured -DesiredState $script:DesiredSafeAttachments

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'Safe Attachments is the one decision this control owns, so the Safe Documents members sharing the policy are MDO-005 drift rather than MDO-004 drift and this verdict must leave them entirely alone'
        }
    }
}

Describe 'MDO-006-A3 Safe Documents collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector MDO-005 is registered against' {
            # Arrange
            $registered = $script:SafeDocumentsRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes Safe Documents, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: the collector must be given the service call to make' {

        It 'refuses a collection with no ATP policy to read' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-SafeDocumentsEvidence -AtpPolicyCollection $noCollection }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'AtpPolicyCollectionRequired*' `
                    -Because 'the tenant ATP policy is the only place the Safe Documents switch and the bypass allowance are recorded, and a record assembled without reading it reports a posture nobody looked up'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records a collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The term Get-AtpPolicyForO365 is not recognized in this session.' }

            # Act
            $evidence = Get-SafeDocumentsEvidence -AtpPolicyCollection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'an exception here discards every other control in the run, and a refused command that is not recorded as refused reads downstream exactly like a tenant that was read and found blocking the bypass'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a tenant that holds no ATP policy at all as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-SafeDocumentsEvidence -AtpPolicyCollection $empty

            # Assert
            ('collected={0}|failure={1}|{2}' -f $evidence.Collected, $evidence.FailureReason, (ConvertTo-CanonicalJson -InputObject $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|{"AtpPolicyForO365":[]}' `
                    -Because 'a tenant whose ATP policy could not be found is the exact finding this control exists to report, and calling it a collection failure hides that finding behind an infrastructure excuse'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = Get-SafeDocumentsEvidence -AtpPolicyCollection { @(New-AtpPolicy -EnableSafeDocs $false) }

            # Act
            $act = { $evidence.Value['AtpPolicyForO365'] = @() }

            # Assert
            $act |
                Should -Throw `
                    -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one run of the collection is one record of exactly what the command returned' {

        It 'records the policy whole under its declared name, under the control, source and command the registry declares' {
            # Arrange
            $policy = New-AtpPolicy -Name ' Default ' -EnableATPForSPOTeamsODB $false -EnableSafeDocs $false -AllowSafeDocsOpen $true
            $expected = 'MDO-005|ExchangeOnline|Get-AtpPolicyForO365|collected=True|failure=|' +
            '{"AtpPolicyForO365":[{"AllowSafeDocsOpen":true,"EnableATPForSPOTeamsODB":false,' +
            '"EnableSafeDocs":false,"Identity":" Default ","Name":" Default "}]}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = Get-SafeDocumentsEvidence -AtpPolicyCollection { @($policy) }.GetNewClosure()

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'Safe Documents is a separately entitled control collected under its own record even though it shares a command with Safe Attachments, and the collector holds no opinion about the SAFEDOCS entitlement - a collector that skipped the call on an unentitled tenant would leave the control with no observation to report NotApplicable from'
        }
    }
}

Describe 'MDO-006-A4 Safe Documents evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator MDO-005 is registered against' {
            # Arrange
            $registered = $script:SafeDocumentsRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides Safe Documents, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation, the state the baseline resolved and an entitlement verdict somebody else reached' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = { Test-SafeDocumentsControl -Evidence $noEvidence -DesiredState $script:DesiredSafeDocuments -EntitlementVerdict (New-EntitlementVerdict) }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceRequired*' `
                    -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'MDO-004' -Source 'ExchangeOnline' `
                -Command 'Get-AtpPolicyForO365' -Value ([ordered]@{ AtpPolicyForO365 = @(New-AtpPolicy) })

            # Act
            $act = { Test-SafeDocumentsControl -Evidence $foreign -DesiredState $script:DesiredSafeDocuments -EntitlementVerdict (New-EntitlementVerdict) }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' `
                    -Because 'Safe Attachments and Safe Documents are recorded by the same command under two controls with two entitlements, so a record collected for one is exactly the record that must not decide the other'
        }

        It 'refuses a decision that names no resolved desired Safe Documents state' {
            # Arrange
            $evidence = New-SafeDocumentsEvidence -Policy @(New-AtpPolicy)

            # Act
            $act = { Test-SafeDocumentsControl -Evidence $evidence -DesiredState $null -EntitlementVerdict (New-EntitlementVerdict) }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredSafeDocumentsStateRequired*' `
                    -Because 'an evaluator handed no desired state decides against whatever it defaults to rather than against what was approved'
        }

        It 'refuses a desired state that declares no required service plan' {
            # Arrange
            $evidence = New-SafeDocumentsEvidence -Policy @(New-AtpPolicy)
            $unplanned = [pscustomobject]@{ enabled = $true; allowBypass = $false }

            # Act
            $act = { Test-SafeDocumentsControl -Evidence $evidence -DesiredState $unplanned -EntitlementVerdict (New-EntitlementVerdict) }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredSafeDocumentsServicePlanRequired*' `
                    -Because 'the plan the baseline declares is the only thing that makes an entitlement verdict checkable, and an evaluator that accepts any verdict at all accepts one reached on a plan that grants nothing'
        }

        It 'refuses a decision with no independently verified entitlement verdict' {
            # Arrange
            $evidence = New-SafeDocumentsEvidence -Policy @(New-AtpPolicy)

            # Act
            $act = { Test-SafeDocumentsControl -Evidence $evidence -DesiredState $script:DesiredSafeDocuments -EntitlementVerdict $null }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'SafeDocumentsEntitlementVerdictRequired*' `
                    -Because 'an unlicensed tenant and a licensed tenant that switched Safe Documents off report the same ATP policy, so an evaluator that inferred entitlement from the observation would report the first one as drift and the second one as absent capability, each time getting the other answer'
        }

        It 'refuses an entitlement verdict reached on a plan the baseline never declared' {
            # Arrange
            $evidence = New-SafeDocumentsEvidence -Policy @(New-AtpPolicy)
            $otherPlan = New-EntitlementVerdict -PlanName 'ATP_ENTERPRISE'

            # Act
            $act = { Test-SafeDocumentsControl -Evidence $evidence -DesiredState $script:DesiredSafeDocuments -EntitlementVerdict $otherPlan }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'SafeDocumentsEntitlementPlanMismatch*' `
                    -Because 'Defender for Office 365 Plan 2 entitles Safe Attachments and entitles Safe Documents to nobody, so a verdict cleared on that plan and read as this one passes Safe Documents on a licence that does not include it'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-SafeDocumentsEvidence -AtpPolicyCollection { throw 'The operation was throttled and could not be completed.' }

            # Act
            $result = Test-SafeDocumentsControl -Evidence $refused -DesiredState $script:DesiredSafeDocuments -EntitlementVerdict (New-EntitlementVerdict)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a control the run never managed to observe must cost the run its go-live, because the alternative is that throttling the tenant is the cheapest way to pass it'
        }
    }

    Context 'Negative: a record that never observed the policy decides nothing about it' {

        It 'decides a record carrying no ATP policy observation as an error' {
            # Arrange
            $partial = New-BaselineEvidence -ControlId 'MDO-005' -Source 'ExchangeOnline' `
                -Command 'Get-AtpPolicyForO365' -Value ([ordered]@{ SafeAttachmentPolicy = @(New-AtpPolicy) })

            # Act
            $result = Test-SafeDocumentsControl -Evidence $partial -DesiredState $script:DesiredSafeDocuments -EntitlementVerdict (New-EntitlementVerdict)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=SafeDocumentsEvidenceIncomplete: the record carries no 'AtpPolicyForO365' observation." `
                    -Because 'an absent observation is not an observation that the tenant holds no ATP policy, and reading it as one decides the control from a command nobody ran'
        }

        It 'decides an observed policy carrying no <Member> member as an error' -ForEach @(
            @{ Member = 'EnableSafeDocs' }
            @{ Member = 'AllowSafeDocsOpen' }
        ) {
            # Arrange
            $incomplete = New-SafeDocumentsEvidence -Policy @(New-AtpPolicyWithout -Member $Member)

            # Act
            $result = Test-SafeDocumentsControl -Evidence $incomplete -DesiredState $script:DesiredSafeDocuments -EntitlementVerdict (New-EntitlementVerdict)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=SafeDocumentsEvidenceIncomplete: an observed AtpPolicyForO365 carries no '$Member' member." `
                    -Because 'an absent switch read as off reports a tenant scanning nothing, and an absent bypass allowance read as false reports a block nobody configured; both are indistinguishable from a policy the collector simply did not carry'
        }
    }

    Context 'Negative: a tenant the entitlement verdict does not entitle is not a tenant this control decides' {

        It 'decides a tenant the verdict does not entitle as not applicable' {
            # Arrange
            $entitledLooking = New-SafeDocumentsEvidence -Policy @(New-AtpPolicy -EnableSafeDocs $true -AllowSafeDocsOpen $false)
            $unentitled = New-EntitlementVerdict -Status 'NotEntitled'

            # Act
            $result = Test-SafeDocumentsControl -Evidence $entitledLooking -DesiredState $script:DesiredSafeDocuments -EntitlementVerdict $unentitled

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "NotApplicable|golive=True|reason=SafeDocumentsNotEntitled: $($script:EntitlementReason['NotEntitled'])" `
                    -Because 'the verdict is supplied rather than inferred, so a policy that looks correctly configured cannot make an unlicensed tenant applicable; failing a tenant for not holding a capability it never bought is a finding about the invoice rather than about the configuration'
        }
    }

    Context 'Negative: an entitlement question nobody answered is never an entitled tenant' {

        It 'decides an entitlement verdict that failed rather than resolving as an error' {
            # Arrange
            $configured = New-SafeDocumentsEvidence -Policy @(New-AtpPolicy)
            $unresolved = New-EntitlementVerdict -Status 'Fail'

            # Act
            $result = Test-SafeDocumentsControl -Evidence $configured -DesiredState $script:DesiredSafeDocuments -EntitlementVerdict $unresolved

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=SafeDocumentsEntitlementUnresolved: $($script:EntitlementReason['Fail'])" `
                    -Because 'a preflight that disagreed with itself about who holds the plan answered neither entitled nor unentitled, and resolving that silence either way decides the control on a licensing question the run never settled'
        }
    }

    Context 'Negative: an entitled tenant whose observed Safe Documents state is not the resolved state fails' {

        It 'fails a tenant that holds no ATP policy at all' {
            # Arrange
            $absent = New-SafeDocumentsEvidence -Policy @()

            # Act
            $result = Test-SafeDocumentsControl -Evidence $absent -DesiredState $script:DesiredSafeDocuments -EntitlementVerdict (New-EntitlementVerdict)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=SafeDocumentsDrift: the tenant holds no ATP policy.' `
                    -Because 'an entitled tenant with no ATP policy scans no document it was paid up to scan, which is the finding rather than an absence of one'
        }

        It 'fails an entitled tenant whose Safe Documents scanner is switched off' {
            # Arrange
            $switchedOff = New-SafeDocumentsEvidence -Policy @(New-AtpPolicy -EnableSafeDocs $false)

            # Act
            $result = Test-SafeDocumentsControl -Evidence $switchedOff -DesiredState $script:DesiredSafeDocuments -EntitlementVerdict (New-EntitlementVerdict)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=SafeDocumentsDrift: 'EnableSafeDocs' is 'False' where 'True' is required." `
                    -Because 'an entitled tenant that never switched the scanner on is the most common Safe Documents finding there is, and a verdict that did not name the observed state leaves the operator nothing to act on'
        }

        It 'fails an entitled tenant that lets a user open a file Safe Documents called malicious' {
            # Arrange
            $bypassAllowed = New-SafeDocumentsEvidence -Policy @(New-AtpPolicy -AllowSafeDocsOpen $true)

            # Act
            $result = Test-SafeDocumentsControl -Evidence $bypassAllowed -DesiredState $script:DesiredSafeDocuments -EntitlementVerdict (New-EntitlementVerdict)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=SafeDocumentsDrift: 'AllowSafeDocsOpen' is 'True' where 'False' is required." `
                    -Because 'a scanner whose malicious verdict the user may click past protects nobody, so an evaluator that decided only whether Safe Documents was enabled would pass exactly the tenant that made the protection optional'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-SafeDocumentsControl `
                -Evidence (New-SafeDocumentsEvidence -Policy @(New-AtpPolicy -EnableSafeDocs $false)) `
                -DesiredState $script:DesiredSafeDocuments -EntitlementVerdict (New-EntitlementVerdict)

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act |
                Should -Throw `
                    -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: an independently entitled tenant holding exactly the resolved state is one go-live-successful pass' {

        It 'passes a tenant whose verified SAFEDOCS entitlement and observed ATP policy both match the baseline' {
            # Arrange
            $configured = New-SafeDocumentsEvidence -Policy @(New-AtpPolicy -Name ' Default ' -EnableATPForSPOTeamsODB $false -EnableSafeDocs $true -AllowSafeDocsOpen $false)
            $expected = 'MDO-005|Pass|normalized=True|golive=True|reason=|evidence=Get-AtpPolicyForO365:MDO-005'

            # Act
            $result = Test-SafeDocumentsControl -Evidence $configured -DesiredState $script:DesiredSafeDocuments -EntitlementVerdict (New-EntitlementVerdict)

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'Safe Documents is the two decisions this control owns and the entitlement is verified elsewhere, so the Safe Attachments member sharing the policy is MDO-004 drift rather than MDO-005 drift and this verdict must leave it entirely alone; the verdict has to be one normalized pass naming the record it was decided from rather than a bare true'
        }
    }
}
