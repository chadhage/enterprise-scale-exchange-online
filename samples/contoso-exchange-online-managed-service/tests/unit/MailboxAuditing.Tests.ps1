#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement is not installed and must never be imported. Both Exchange Online
    # commands EXO-006 depends on are reached only through a supplied collection seam, so each
    # collection here is a scriptblock returning a canned payload or throwing a canned failure.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # The registry is returned as one read-only collection deliberately protected from pipeline
    # unrolling, so the entry is read by index rather than by piping the collection.
    $script:ControlRegistry = @(Get-BaselineControlRegistry -Profile Historical)[0]
    $script:MailboxAuditingRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'EXO-006') { $entry }
        })[0]

    function New-OrganizationConfigRecord {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [bool]$AuditDisabled,

            [string]$Name = 'contoso.onmicrosoft.com'
        )

        return [pscustomobject]@{
            AuditDisabled = $AuditDisabled
            Name          = $Name
        }
    }

    function New-AuditBypassAssociationRecord {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Identity,

            [Parameter(Mandatory)]
            [bool]$AuditBypassEnabled
        )

        return [pscustomobject]@{
            AuditBypassEnabled = $AuditBypassEnabled
            Identity           = $Identity
        }
    }

    function New-MailboxAuditingEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$OrganizationConfig,

            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]]$Association
        )

        return Get-MailboxAuditingEvidence `
            -OrganizationConfigCollection { $OrganizationConfig }.GetNewClosure() `
            -AuditBypassAssociationCollection { $Association }.GetNewClosure()
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

    function New-PartialAuditingEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'EXO-006' -Source 'ExchangeOnline' `
            -Command 'Get-OrganizationConfig; Get-MailboxAuditBypassAssociation' -Value $Payload
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

Describe 'EXO-006-A1 mailbox-auditing collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector EXO-006 is registered against' {
            # Arrange
            $registered = $script:MailboxAuditingRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes EXO-006, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: both halves of the control must be given a service call to make' {

        It 'refuses a run with no organization configuration collection' {
            # Arrange
            $organization = $null

            # Act
            $act = {
                Get-MailboxAuditingEvidence -OrganizationConfigCollection $organization `
                    -AuditBypassAssociationCollection { @() }
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OrganizationConfigCollectionRequired*' -Because 'a record that never read the organization configuration cannot say whether auditing is switched on at all, which is the first half of the control'
        }

        It 'refuses a run with no audit bypass association collection' {
            # Arrange
            $association = $null

            # Act
            $act = {
                Get-MailboxAuditingEvidence -OrganizationConfigCollection { New-OrganizationConfigRecord -AuditDisabled $false } `
                    -AuditBypassAssociationCollection $association
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'AuditBypassAssociationCollectionRequired*' -Because 'an enabled bypass exempts a mailbox from auditing while the organization setting still reads as enabled, so a record with no bypass view reports auditing on for mailboxes that are not being audited'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records an organization configuration collection that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The term Get-OrganizationConfig is not recognized in this session.' }

            # Act
            $evidence = Get-MailboxAuditingEvidence -OrganizationConfigCollection $refusing `
                -AuditBypassAssociationCollection { @() }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'a command that never answered proves nothing about auditing, and a record that hides the refusal reads downstream exactly like a tenant that was checked and found compliant'
        }

        It 'records an audit bypass association collection that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The operation was throttled and could not be completed.' }

            # Act
            $evidence = Get-MailboxAuditingEvidence -OrganizationConfigCollection { New-OrganizationConfigRecord -AuditDisabled $false } `
                -AuditBypassAssociationCollection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'enumerating bypass associations across a large tenant is the call most likely to be throttled, so the failure this control will meet most often must be the one it refuses to read as half a pass'
        }
    }

    Context 'Negative: a tenant with no bypass associations is an observation, not a failed collection' {

        It 'records collections that returned nothing as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-MailboxAuditingEvidence -OrganizationConfigCollection $empty `
                -AuditBypassAssociationCollection $empty

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeExactly 'collected=True|failure=' `
                    -Because 'a tenant that holds no bypass association at all is the tenant this control is trying to reach, and calling that a collection failure turns the compliant outcome into an infrastructure error'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = New-MailboxAuditingEvidence `
                -OrganizationConfig (New-OrganizationConfigRecord -AuditDisabled $true) `
                -Association @(New-AuditBypassAssociationRecord -Identity 'svc-journal@contoso.com' -AuditBypassEnabled $true)

            # Act
            $act = { $evidence.Value['MailboxAuditBypassAssociation'][0].AuditBypassEnabled = $false }

            # Assert
            $act | Should -Throw -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one run of both collections is one record of exactly what each returned' {

        It 'records the organization configuration and every association the services returned under its own name, unfiltered and unreshaped' {
            # Arrange
            $organizationConfig = New-OrganizationConfigRecord -AuditDisabled $true
            $association = @(
                (New-AuditBypassAssociationRecord -Identity 'svc-archive@contoso.com' -AuditBypassEnabled $false),
                (New-AuditBypassAssociationRecord -Identity 'svc-journal@contoso.com' -AuditBypassEnabled $true)
            )
            $expected = 'EXO-006|ExchangeOnline|Get-OrganizationConfig; Get-MailboxAuditBypassAssociation|collected=True|failure=|' +
            '{"MailboxAuditBypassAssociation":' +
            '[{"AuditBypassEnabled":false,"Identity":"svc-archive@contoso.com"},' +
            '{"AuditBypassEnabled":true,"Identity":"svc-journal@contoso.com"}],' +
            '"OrganizationConfig":{"AuditDisabled":true,"Name":"contoso.onmicrosoft.com"}}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = New-MailboxAuditingEvidence -OrganizationConfig $organizationConfig -Association $association

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so the disabled association has to survive collection alongside the enabled one; a collector that filtered to the enabled bypasses would satisfy every other assertion in this file while quietly deciding which associations the evaluator is allowed to see'
        }
    }
}

Describe 'EXO-006-A2 mailbox-auditing evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator EXO-006 is registered against' {
            # Arrange
            $registered = $script:MailboxAuditingRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides EXO-006, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation of this tenant' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = { Test-MailboxAuditingControl -Evidence $noEvidence }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceRequired*' -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one, and this is the control that decides whether anything a compromised mailbox does is recorded at all'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'EXO-005' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value ([pscustomobject]@{ ExternalPostmasterAddress = 'postmaster@contoso.com' })

            # Act
            $act = { Test-MailboxAuditingControl -Evidence $foreign }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' -Because 'deciding the auditing control from another control record reports an auditing posture that was never looked at'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-MailboxAuditingEvidence -OrganizationConfigCollection { New-OrganizationConfigRecord -AuditDisabled $false } `
                -AuditBypassAssociationCollection { throw 'The operation was throttled and could not be completed.' }

            # Act
            $result = Test-MailboxAuditingControl -Evidence $refused

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a control the run never managed to observe must cost the run its go-live, because the alternative is that throttling the bypass enumeration is the cheapest way to pass the auditing control'
        }
    }

    Context 'Negative: a record that carries only part of the tenant decides nothing about the rest' {

        It 'decides a record carrying no organization configuration observation as an error' {
            # Arrange
            $partial = New-PartialAuditingEvidence -Payload ([ordered]@{ MailboxAuditBypassAssociation = @() })

            # Act
            $result = Test-MailboxAuditingControl -Evidence $partial

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=MailboxAuditingEvidenceIncomplete: the record carries no 'OrganizationConfig' observation." `
                    -Because 'an absent observation is not an observation of nothing, and reading it as one lets a record that never asked whether auditing is on report that it is'
        }

        It 'decides a record carrying no audit bypass association observation as an error' {
            # Arrange
            $partial = New-PartialAuditingEvidence -Payload ([ordered]@{ OrganizationConfig = (New-OrganizationConfigRecord -AuditDisabled $false) })

            # Act
            $result = Test-MailboxAuditingControl -Evidence $partial

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=MailboxAuditingEvidenceIncomplete: the record carries no 'MailboxAuditBypassAssociation' observation." `
                    -Because 'the bypass view is the half the shipping script never collected, so a record without it must not be decidable; that omission is exactly how a tenant with every interesting mailbox exempted has been passing this control'
        }

        It 'decides an organization configuration carrying no auditing member as an error' {
            # Arrange
            $partial = New-PartialAuditingEvidence -Payload ([ordered]@{
                    OrganizationConfig            = ([pscustomobject]@{ Name = 'contoso.onmicrosoft.com' })
                    MailboxAuditBypassAssociation = @()
                })

            # Act
            $result = Test-MailboxAuditingControl -Evidence $partial

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=MailboxAuditingEvidenceIncomplete: the observed organization configuration carries no 'AuditDisabled' member." `
                    -Because 'an absent member read as false says auditing is enabled on the strength of a member nobody observed, which is the most flattering possible reading of an incomplete answer'
        }
    }

    Context 'Negative: a tenant whose mail is not being audited fails' {

        It 'fails an organization that has auditing disabled' {
            # Arrange
            $disabled = New-MailboxAuditingEvidence -OrganizationConfig (New-OrganizationConfigRecord -AuditDisabled $true) -Association @()

            # Act
            $result = Test-MailboxAuditingControl -Evidence $disabled

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=MailboxAuditingGap: organization-wide mailbox auditing is disabled.' `
                    -Because 'auditing switched off organization-wide means no mailbox action is recorded anywhere, and an investigation after the fact has nothing to read'
        }

        It 'fails a tenant holding enabled audit bypass associations, naming every bypassed identity and no other' {
            # Arrange
            $bypassed = New-MailboxAuditingEvidence `
                -OrganizationConfig (New-OrganizationConfigRecord -AuditDisabled $false) `
                -Association @(
                (New-AuditBypassAssociationRecord -Identity 'exec@contoso.com' -AuditBypassEnabled $true),
                (New-AuditBypassAssociationRecord -Identity 'svc-archive@contoso.com' -AuditBypassEnabled $false),
                (New-AuditBypassAssociationRecord -Identity 'svc-journal@contoso.com' -AuditBypassEnabled $true)
            )

            # Act
            $result = Test-MailboxAuditingControl -Evidence $bypassed

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=MailboxAuditingGap: audit bypass is enabled for 'exec@contoso.com', 'svc-journal@contoso.com'." `
                    -Because 'an enabled bypass exempts that mailbox from auditing while the organization setting still reads as enabled, so this is the gap the card exists to close; the failure has to name which identities are exempt and must not name the association that exists but is switched off, because an operator who is told a compliant association is a finding stops believing the findings'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-MailboxAuditingControl -Evidence (New-MailboxAuditingEvidence -OrganizationConfig (New-OrganizationConfigRecord -AuditDisabled $true) -Association @())

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act | Should -Throw -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: auditing on with no mailbox exempted from it is one go-live-successful pass' {

        It 'passes a tenant that audits organization-wide and holds no association whose bypass is enabled' {
            # Arrange
            $audited = New-MailboxAuditingEvidence `
                -OrganizationConfig (New-OrganizationConfigRecord -AuditDisabled $false) `
                -Association @(New-AuditBypassAssociationRecord -Identity 'svc-archive@contoso.com' -AuditBypassEnabled $false)
            $expected = 'EXO-006|Pass|normalized=True|golive=True|reason=|evidence=Get-OrganizationConfig; Get-MailboxAuditBypassAssociation:EXO-006'

            # Act
            $result = Test-MailboxAuditingControl -Evidence $audited

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'both halves of the control have to hold at once: auditing switched on and no mailbox exempted from it, proved here over a tenant that carries an association whose bypass is switched off, because an evaluator that failed on the mere existence of an association would fail every tenant that has ever created one; and the verdict has to be one normalized go-live-successful pass naming the record it was decided from rather than a bare true'
        }
    }
}
