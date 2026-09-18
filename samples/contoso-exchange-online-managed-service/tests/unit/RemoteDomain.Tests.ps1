#requires -Version 7.0

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
