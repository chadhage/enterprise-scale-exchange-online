#requires -Version 7.0

# Pester evaluates `-ForEach` during discovery, before any `BeforeAll` has run, so the five members
# EXO-008 decides each remote domain by are declared here. Each entry carries the name Exchange
# Online reports the member under, the name the baseline resolves it under, a live value that
# differs from the baseline, and how both values read in the failure the operator is handed.
$RemoteDomainDecidedMember = @(
    @{ Observed = 'AutoForwardEnabled'; Desired = 'autoForwardEnabled'; Drift = $true; Live = 'True'; Want = 'False' }
    @{ Observed = 'AutoReplyEnabled'; Desired = 'autoReplyEnabled'; Drift = $true; Live = 'True'; Want = 'False' }
    @{ Observed = 'AllowedOOFType'; Desired = 'allowedOOFType'; Drift = 'External'; Live = 'External'; Want = 'InternalLegacy' }
    @{ Observed = 'DeliveryReportEnabled'; Desired = 'deliveryReportEnabled'; Drift = $true; Live = 'True'; Want = 'False' }
    @{ Observed = 'NDREnabled'; Desired = 'nonDeliveryReportEnabled'; Drift = $true; Live = 'True'; Want = 'False' }
)

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement is not installed and must never be imported. `Get-RemoteDomain` is
    # reached only through the supplied collection seam, so every collection here is a scriptblock
    # returning canned remote domains or throwing a canned failure.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # The registry is returned as one read-only collection deliberately protected from pipeline
    # unrolling, so the entry is read by index rather than by piping the collection.
    $script:ControlRegistry = @(Get-BaselineControlRegistry)[0]
    $script:RemoteDomainRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'EXO-008') { $entry }
        })[0]

    function New-RemoteDomainRecord {
        [CmdletBinding()]
        param(
            [string]$Identity = 'Default',

            [string]$DomainName = '*',

            [object]$AutoForwardEnabled = $false,

            [object]$AutoReplyEnabled = $false,

            [object]$AllowedOOFType = 'None',

            [object]$DeliveryReportEnabled = $false,

            [object]$NDREnabled = $false,

            # A member EXO-008 decides nothing about, so a collector that narrowed the payload to
            # the five decided members is distinguishable from one that recorded what was returned.
            [object]$TrustedMailOutboundEnabled = $false
        )

        return [pscustomobject]@{
            Identity                   = $Identity
            DomainName                 = $DomainName
            AutoForwardEnabled         = $AutoForwardEnabled
            AutoReplyEnabled           = $AutoReplyEnabled
            AllowedOOFType             = $AllowedOOFType
            DeliveryReportEnabled      = $DeliveryReportEnabled
            NDREnabled                 = $NDREnabled
            TrustedMailOutboundEnabled = $TrustedMailOutboundEnabled
        }
    }

    function New-RemoteDomainEvidenceRecord {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$RemoteDomain
        )

        return Get-RemoteDomainEvidence -Collection { $RemoteDomain }.GetNewClosure()
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

    # The desired remote-domain state the baseline resolves, as `remoteDomainDefault` declares it.
    function New-DesiredRemoteDomainState {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{}
        )

        $state = [pscustomobject][ordered]@{
            autoForwardEnabled       = $false
            autoReplyEnabled         = $false
            allowedOOFType           = 'InternalLegacy'
            deliveryReportEnabled    = $false
            nonDeliveryReportEnabled = $false
        }

        foreach ($name in $Override.Keys) {
            $state.PSObject.Properties[$name].Value = $Override[$name]
        }

        return $state
    }

    # A tenant that satisfies EXO-008, with exactly one thing changed per negative, so a verdict a
    # negative produces cannot be explained by anything else in the fixture.
    function New-CompliantRemoteDomainEvidence {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{},

            [string]$Identity = 'Default'
        )

        $argument = @{ Identity = $Identity; AllowedOOFType = 'InternalLegacy' }
        foreach ($name in $Override.Keys) { $argument[$name] = $Override[$name] }

        return New-RemoteDomainEvidenceRecord -RemoteDomain @(New-RemoteDomainRecord @argument)
    }

    function New-PartialRemoteDomainEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'EXO-008' -Source 'ExchangeOnline' -Command 'Get-RemoteDomain' -Value $Payload
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

Describe 'EXO-008-A1 remote-domain collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector EXO-008 is registered against' {
            # Arrange
            $registered = $script:RemoteDomainRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes EXO-008, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: the collector must be given a service call to make' {

        It 'refuses a collection with nothing to run' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-RemoteDomainEvidence -Collection $noCollection }

            # Assert
            $act | Should -Throw -ExpectedMessage 'CollectionRequired*' -Because 'a record assembled without reaching the remote domains reports a forwarding and out-of-office posture nobody read from the tenant'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records a collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The term Get-RemoteDomain is not recognized in this session.' }

            # Act
            $evidence = Get-RemoteDomainEvidence -Collection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'an exception here discards every other control in the run, and a refused command that is not recorded as refused reads downstream exactly like a tenant whose remote domains were read and found compliant'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a collection that returned nothing as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-RemoteDomainEvidence -Collection $empty

            # Assert
            ('collected={0}|failure={1}|observedAnything={2}' -f $evidence.Collected, $evidence.FailureReason, ($null -ne $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|observedAnything=False' `
                    -Because 'a tenant that answers with no remote domain at all is the finding EXO-008 exists to fail on rather than an infrastructure excuse to hide it behind'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = New-RemoteDomainEvidenceRecord -RemoteDomain (New-RemoteDomainRecord -AutoForwardEnabled $true)

            # Act
            $act = { $evidence.Value[0]['AutoForwardEnabled'] = $false }

            # Assert
            $act | Should -Throw -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one collection of the remote domains is one record of exactly what it returned' {

        It 'records the remote domains the service returned under the control, source and command the registry declares' {
            # Arrange
            $remoteDomain = @(
                New-RemoteDomainRecord -Identity 'Default' -DomainName '*' `
                    -AutoForwardEnabled $true -AutoReplyEnabled $false -AllowedOOFType 'External' `
                    -DeliveryReportEnabled $true -NDREnabled $true -TrustedMailOutboundEnabled $false
                New-RemoteDomainRecord -Identity 'Fabrikam' -DomainName 'fabrikam.example' `
                    -AutoForwardEnabled $false -AutoReplyEnabled $true -AllowedOOFType 'None' `
                    -DeliveryReportEnabled $false -NDREnabled $false -TrustedMailOutboundEnabled $true
            )
            $expected = 'EXO-008|ExchangeOnline|Get-RemoteDomain|collected=True|failure=|' +
            '[{"AllowedOOFType":"External","AutoForwardEnabled":true,"AutoReplyEnabled":false,"DeliveryReportEnabled":true,"DomainName":"*","Identity":"Default","NDREnabled":true,"TrustedMailOutboundEnabled":false},' +
            '{"AllowedOOFType":"None","AutoForwardEnabled":false,"AutoReplyEnabled":true,"DeliveryReportEnabled":false,"DomainName":"fabrikam.example","Identity":"Fabrikam","NDREnabled":false,"TrustedMailOutboundEnabled":true}]' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = New-RemoteDomainEvidenceRecord -RemoteDomain $remoteDomain

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so both remote domains have to survive collection with every member the service returned: a collector that narrowed the payload to the default domain would drop the non-default domain whose auto-reply is switched on, one that filtered to the five members the control decides on would drop the outbound trust member, and either reshaping decides the control before the evaluator ever sees it'
        }
    }
}

Describe 'EXO-008-A2 remote-domain evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator EXO-008 is registered against' {
            # Arrange
            $registered = $script:RemoteDomainRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides EXO-008, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation to decide' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $absent = $null

            # Act
            $act = { Test-RemoteDomainControl -Evidence $absent -DesiredState (New-DesiredRemoteDomainState) }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceRequired*' `
                -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'EXO-001' -Source 'ExchangeOnline' -Command 'Get-AcceptedDomain' `
                -Value ([pscustomobject]@{ DomainName = 'contoso.com' })

            # Act
            $act = { Test-RemoteDomainControl -Evidence $foreign -DesiredState (New-DesiredRemoteDomainState) }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' `
                -Because 'a record collected for a different control names different domains for different reasons, so a record that looks close enough decides this control from members nobody observed'
        }
    }

    Context 'Negative: the evaluator must be given the desired state to decide against' {

        It 'refuses a decision with no resolved desired remote-domain state' {
            # Arrange
            $unresolved = $null

            # Act
            $act = { Test-RemoteDomainControl -Evidence (New-CompliantRemoteDomainEvidence) -DesiredState $unresolved }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DesiredRemoteDomainStateRequired*' `
                -Because 'an evaluator with no desired state decides the five values against whatever it defaults to rather than against what the baseline resolved, and the default that flatters the tenant is the one nobody notices'
        }

        It "refuses a decision whose desired state resolves no '<Desired>' value" -ForEach $RemoteDomainDecidedMember {
            # Arrange
            $partial = New-DesiredRemoteDomainState
            $partial.PSObject.Properties.Remove($Desired)

            # Act
            $act = { Test-RemoteDomainControl -Evidence (New-CompliantRemoteDomainEvidence) -DesiredState $partial }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DesiredRemoteDomainMemberRequired*' `
                -Because 'four of five values decided against the baseline and the fifth decided against nothing is reported as a fully compared domain, and the uncompared value is always the one the resolution forgot'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-RemoteDomainEvidence -Collection { throw 'The operation was throttled and could not be completed.' }

            # Act
            $result = Test-RemoteDomainControl -Evidence $refused -DesiredState (New-DesiredRemoteDomainState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a tenant the run never managed to read must cost the run its go-live, because the alternative is that a refused remote-domain enumeration is the cheapest way to pass this control'
        }
    }

    Context 'Negative: a domain that carries only part of itself decides nothing about the rest' {

        It "decides an observed remote domain carrying no '<Observed>' member as an error" -ForEach $RemoteDomainDecidedMember {
            # Arrange
            $domain = New-RemoteDomainRecord -Identity 'Default' -AllowedOOFType 'InternalLegacy'
            $domain.PSObject.Properties.Remove($Observed)
            $incomplete = New-RemoteDomainEvidenceRecord -RemoteDomain @($domain)

            # Act
            $result = Test-RemoteDomainControl -Evidence $incomplete -DesiredState (New-DesiredRemoteDomainState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=RemoteDomainEvidenceIncomplete: an observed remote domain carries no '$Observed' member." `
                    -Because 'an absent member is not a member observed to be off, and read as off it reports a hardened domain on the strength of a value nobody read'
        }
    }

    Context 'Negative: a tenant that holds no remote domain at all fails' {

        It 'fails a tenant that observed no remote domain' {
            # Arrange
            $empty = Get-RemoteDomainEvidence -Collection { }

            # Act
            $result = Test-RemoteDomainControl -Evidence $empty -DesiredState (New-DesiredRemoteDomainState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=RemoteDomainDrift: the tenant holds no remote domain at all.' `
                    -Because 'a tenant with no remote domain has nothing enforcing the auto-forward, auto-reply and out-of-office posture this control exists to prove, and an empty answer folded into a pass is the finding hidden behind the absence of anything to find'
        }
    }

    Context 'Negative: any one of the five values differing from the resolved desired state fails' {

        It "fails a remote domain whose '<Observed>' differs from the resolved desired state" -ForEach $RemoteDomainDecidedMember {
            # Arrange
            $drifted = New-CompliantRemoteDomainEvidence -Override @{ $Observed = $Drift }

            # Act
            $result = Test-RemoteDomainControl -Evidence $drifted -DesiredState (New-DesiredRemoteDomainState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly ("Fail|golive=False|reason=RemoteDomainDrift: remote domain 'Default' reports '$Observed' as '$Live' where the baseline requires '$Want'." ) `
                    -Because 'all five are decided or the ones that are not are the ones the tenant drifts on, and an operator handed a failure that does not name the domain, the member, the value it holds and the value it must hold has to go and find all four before they can act on it'
        }

        It 'fails a non-default remote domain that differs while the default domain agrees' {
            # Arrange
            $override = New-RemoteDomainEvidenceRecord -RemoteDomain @(
                New-RemoteDomainRecord -Identity 'Default' -DomainName '*' -AllowedOOFType 'InternalLegacy'
                New-RemoteDomainRecord -Identity 'Fabrikam' -DomainName 'fabrikam.example' -AllowedOOFType 'InternalLegacy' -AutoForwardEnabled $true
            )

            # Act
            $result = Test-RemoteDomainControl -Evidence $override -DesiredState (New-DesiredRemoteDomainState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=RemoteDomainDrift: remote domain 'Fabrikam' reports 'AutoForwardEnabled' as 'True' where the baseline requires 'False'." `
                    -Because 'a non-default remote domain overrides the default for exactly the addresses it covers, so a control that decided only the default domain would pass a tenant that opened automatic forwarding to the one partner domain somebody created it for'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-RemoteDomainControl `
                -Evidence (New-CompliantRemoteDomainEvidence -Override @{ AutoForwardEnabled = $true }) `
                -DesiredState (New-DesiredRemoteDomainState)

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act | Should -Throw -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: five values equal to the resolved desired state on every observed domain is one go-live-successful pass' {

        It 'passes a tenant whose every remote domain holds all five values the baseline resolved' {
            # Arrange
            $hardened = New-RemoteDomainEvidenceRecord -RemoteDomain @(
                New-RemoteDomainRecord -Identity 'Default' -DomainName '*' -AllowedOOFType 'InternalLegacy' -TrustedMailOutboundEnabled $true
                New-RemoteDomainRecord -Identity 'Fabrikam' -DomainName 'fabrikam.example' -AllowedOOFType ' internallegacy ' -TrustedMailOutboundEnabled $false
            )
            $expected = 'EXO-008|Pass|normalized=True|golive=True|reason=|evidence=Get-RemoteDomain:EXO-008'

            # Act
            $result = Test-RemoteDomainControl -Evidence $hardened -DesiredState (New-DesiredRemoteDomainState)

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'all five values have to hold at once on every domain the tenant returned, proved here over a non-default domain beside the default one, whose out-of-office type differs from the baseline only in casing and surrounding whitespace - which is not drift - and which carries an outbound trust member the control decides nothing about; the verdict has to be one normalized go-live-successful pass naming the record it was decided from rather than a bare true'
        }
    }
}
