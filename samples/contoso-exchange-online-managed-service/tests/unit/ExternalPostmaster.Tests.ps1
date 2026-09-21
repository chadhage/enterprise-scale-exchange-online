#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement is not installed and must never be imported. `Get-TransportConfig`
    # is reached only through the supplied collection seam, so every collection here is a
    # scriptblock returning a canned transport configuration or throwing a canned failure.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # Assigning before unrolling matters: the registry is returned as one read-only collection
    # deliberately protected from pipeline unrolling, so it is read by index rather than by pipe.
    $script:ControlRegistry = @(Get-BaselineControlRegistry -Profile Historical)[0]
    $script:ExternalPostmasterRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'EXO-005') { $entry }
        })[0]

    function New-TransportConfigRecord {
        [CmdletBinding()]
        param(
            # A typed [string] would convert an unset member to an empty string, which is a
            # different observation from a tenant that carries no postmaster member at all.
            [object]$ExternalPostmasterAddress = $null,

            [bool]$SmtpClientAuthenticationDisabled = $true
        )

        return [pscustomobject]@{
            ExternalPostmasterAddress        = $ExternalPostmasterAddress
            SmtpClientAuthenticationDisabled = $SmtpClientAuthenticationDisabled
        }
    }

    function New-ExternalPostmasterEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$TransportConfig
        )

        return Get-ExternalPostmasterEvidence -Collection { $TransportConfig }.GetNewClosure()
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

    $script:ExpectedPostmasterAddress = 'postmaster@contoso.com'

    function New-PartialPostmasterEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'EXO-005' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value $Payload
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

Describe 'EXO-005-A1 external-postmaster collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector EXO-005 is registered against' {
            # Arrange
            $registered = $script:ExternalPostmasterRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes EXO-005, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: the collector must be given a service call to make' {

        It 'refuses a collection with nothing to run' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-ExternalPostmasterEvidence -Collection $noCollection }

            # Assert
            $act | Should -Throw -ExpectedMessage 'CollectionRequired*' -Because 'a record assembled without reaching the transport configuration reports a postmaster address nobody read from the tenant'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records a collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The term Get-TransportConfig is not recognized in this session.' }

            # Act
            $evidence = Get-ExternalPostmasterEvidence -Collection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'an exception here discards every other control in the run, and a refused command that is not recorded as refused reads downstream exactly like a transport configuration that was read and found correct'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a collection that returned nothing as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-ExternalPostmasterEvidence -Collection $empty

            # Assert
            ('collected={0}|failure={1}|observedAnything={2}' -f $evidence.Collected, $evidence.FailureReason, ($null -ne $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|observedAnything=False' `
                    -Because 'a transport configuration that answered with nothing is a real finding EXO-005 has to fail on, and calling it a collection failure hides that finding behind an infrastructure excuse'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = New-ExternalPostmasterEvidence -TransportConfig (New-TransportConfigRecord -ExternalPostmasterAddress 'wrong@fabrikam.example')

            # Act
            $act = { $evidence.Value['ExternalPostmasterAddress'] = 'postmaster@contoso.com' }

            # Assert
            $act | Should -Throw -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one collection of the transport configuration is one record of exactly what it returned' {

        It 'records the transport configuration the service returned under the control, source and command the registry declares' {
            # Arrange
            $transportConfig = New-TransportConfigRecord -ExternalPostmasterAddress 'SMTP:Postmaster@Contoso.com ' -SmtpClientAuthenticationDisabled $false
            $expected = 'EXO-005|ExchangeOnline|Get-TransportConfig|collected=True|failure=|' +
            '{"ExternalPostmasterAddress":"SMTP:Postmaster@Contoso.com ","SmtpClientAuthenticationDisabled":false}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = New-ExternalPostmasterEvidence -TransportConfig $transportConfig

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so the address has to survive collection with its prefix, its casing and its trailing space intact and its unrelated sibling member has to survive alongside it; a collector that narrowed the payload to the postmaster member or normalized it on the way in would decide half the control before the evaluator ever saw it'
        }
    }
}

Describe 'EXO-005-A2 external-postmaster evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator EXO-005 is registered against' {
            # Arrange
            $registered = $script:ExternalPostmasterRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides EXO-005, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation and the address the baseline resolved' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = { Test-ExternalPostmasterControl -Evidence $noEvidence -ExpectedAddress $script:ExpectedPostmasterAddress }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceRequired*' -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'EXO-001' -Source 'ExchangeOnline' -Command 'Get-AcceptedDomain' -Value @([pscustomobject]@{ DomainName = 'contoso.com'; DomainType = 'Authoritative' })

            # Act
            $act = { Test-ExternalPostmasterControl -Evidence $foreign -ExpectedAddress $script:ExpectedPostmasterAddress }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' -Because 'deciding the postmaster control from another control record reports a transport configuration that was never looked at'
        }

        It 'refuses a decision that names no resolved desired address' {
            # Arrange
            $evidence = New-ExternalPostmasterEvidence -TransportConfig (New-TransportConfigRecord -ExternalPostmasterAddress 'postmaster@contoso.com')

            # Act
            $act = { Test-ExternalPostmasterControl -Evidence $evidence -ExpectedAddress '  ' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ExpectedPostmasterAddressRequired*' -Because 'the card demands the live address exactly equal the resolved desired state, and an evaluator handed no desired state either passes every address or fails every address; both are decided by the absence of configuration rather than by the tenant'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-ExternalPostmasterEvidence -Collection { throw 'The operation was throttled and could not be completed.' }

            # Act
            $result = Test-ExternalPostmasterControl -Evidence $refused -ExpectedAddress $script:ExpectedPostmasterAddress

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a control the run never managed to observe must cost the run its go-live, because the alternative is that throttling the tenant is the cheapest way to pass it'
        }
    }

    Context 'Negative: a record that never observed the postmaster member decides nothing about it' {

        It 'decides a record carrying no external postmaster member as an error' {
            # Arrange
            $partial = New-PartialPostmasterEvidence -Payload ([pscustomobject]@{ SmtpClientAuthenticationDisabled = $true })

            # Act
            $result = Test-ExternalPostmasterControl -Evidence $partial -ExpectedAddress $script:ExpectedPostmasterAddress

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=ExternalPostmasterEvidenceIncomplete: the record carries no 'ExternalPostmasterAddress' observation." `
                    -Because 'an absent member is not an observation that the address is unset, and reading it as one turns a transport configuration nobody looked at into a reportable finding about a tenant'
        }

        It 'decides a record that observed no transport configuration at all as an error' {
            # Arrange
            $nothing = Get-ExternalPostmasterEvidence -Collection { }

            # Act
            $result = Test-ExternalPostmasterControl -Evidence $nothing -ExpectedAddress $script:ExpectedPostmasterAddress

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=ExternalPostmasterEvidenceIncomplete: the record carries no 'ExternalPostmasterAddress' observation." `
                    -Because 'a command that answered with nothing observed no address, and a run that cannot distinguish that from a tenant whose address is unset will report whichever of the two is more convenient'
        }
    }

    Context 'Negative: a tenant whose live address is not the resolved desired address fails' {

        It 'fails a tenant that has set no external postmaster address' {
            # Arrange
            $unset = New-ExternalPostmasterEvidence -TransportConfig (New-TransportConfigRecord -ExternalPostmasterAddress '')

            # Act
            $result = Test-ExternalPostmasterControl -Evidence $unset -ExpectedAddress $script:ExpectedPostmasterAddress

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ExternalPostmasterDrift: the tenant has set no external postmaster address where 'postmaster@contoso.com' is required." `
                    -Because 'an unset address is the default state of every tenant, so a control that reads it as anything other than a failure is a control that passes before anybody configures it'
        }

        It 'fails a tenant whose live address differs from the resolved desired address, naming both' {
            # Arrange
            $drifted = New-ExternalPostmasterEvidence -TransportConfig (New-TransportConfigRecord -ExternalPostmasterAddress 'postmaster@fabrikam.example')

            # Act
            $result = Test-ExternalPostmasterControl -Evidence $drifted -ExpectedAddress $script:ExpectedPostmasterAddress

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ExternalPostmasterDrift: the tenant sets the external postmaster address to 'postmaster@fabrikam.example' where 'postmaster@contoso.com' is required." `
                    -Because 'a failure that does not name the live address alongside the desired one tells an operator that something is wrong without telling them what the tenant actually sends non-delivery reports from, which is the one fact the control exists to establish'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-ExternalPostmasterControl `
                -Evidence (New-ExternalPostmasterEvidence -TransportConfig (New-TransportConfigRecord -ExternalPostmasterAddress 'postmaster@fabrikam.example')) `
                -ExpectedAddress $script:ExpectedPostmasterAddress

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act | Should -Throw -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: a live address equal to the resolved desired state is one go-live-successful pass' {

        It 'passes a tenant whose live address equals the resolved desired address under the declared SMTP comparison' {
            # Arrange
            $configured = New-ExternalPostmasterEvidence -TransportConfig (New-TransportConfigRecord -ExternalPostmasterAddress ' SMTP:PostMaster@Contoso.COM ')
            $expected = 'EXO-005|Pass|normalized=True|golive=True|reason=|evidence=Get-TransportConfig:EXO-005'

            # Act
            $result = Test-ExternalPostmasterControl -Evidence $configured -ExpectedAddress $script:ExpectedPostmasterAddress

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'the declared SMTP address comparison trims, strips the routing prefix and lowers the casing, so the tenant that Exchange Online reports back in its own formatting is the same tenant the baseline asked for; a comparison that read any of those three as drift would fail a correctly configured tenant, and the verdict has to be one normalized pass naming the record it was decided from rather than a bare true'
        }
    }
}
