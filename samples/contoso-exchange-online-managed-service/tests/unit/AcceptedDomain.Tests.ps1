#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph and ExchangeOnlineManagement are not installed and must never be imported.
    # `Get-AcceptedDomain` is reached only through the supplied collection seam, so every
    # collection here is a scriptblock returning a canned payload or throwing a canned failure.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # Assigning before unrolling matters: the registry is returned as one read-only collection
    # deliberately protected from pipeline unrolling, so piping it would filter the collection
    # itself rather than the entries inside it, and every member read afterwards would answer for
    # all forty-three controls at once.
    $script:ControlRegistry = @(Get-BaselineControlRegistry)[0]
    $script:AcceptedDomainRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'EXO-001') { $entry }
        })[0]
    function New-AcceptedDomainCollection {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]]$Domain
        )

        return { $Domain }.GetNewClosure()
    }

    function New-AcceptedDomainRecord {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$DomainName,

            [Parameter(Mandatory)]
            [string]$DomainType
        )

        return [pscustomobject]@{
            Name       = $DomainName
            DomainName = $DomainName
            DomainType = $DomainType
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

    function New-AcceptedDomainEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]]$Domain
        )

        return Get-AcceptedDomainEvidence -Collection (New-AcceptedDomainCollection -Domain $Domain)
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

Describe 'EXO-001-A1 accepted-domain collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector EXO-001 is registered against' {
            # Arrange
            $registered = $script:AcceptedDomainRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes EXO-001, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: the collector must be given a service call to make' {

        It 'refuses a collection with nothing to run' {
            # Arrange
            $noCollection = $null

            # Act
            $result = { Get-AcceptedDomainEvidence -Collection $noCollection }

            # Assert
            $result | Should -Throw -ExpectedMessage 'CollectionRequired*' -Because 'a collector that reaches no service records an observation of a tenant it never looked at'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records a collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The term Get-AcceptedDomain is not recognized in this session.' }

            # Act
            $evidence = Get-AcceptedDomainEvidence -Collection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'an exception here discards every other control in the run, and a refused command that is not recorded as refused reads downstream exactly like a command that found nothing wrong'
        }
    }

    Context 'Negative: a tenant that holds no accepted domain is an observation, not a failure' {

        It 'records a collection that returned nothing as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-AcceptedDomainEvidence -Collection $empty

            # Assert
            ('collected={0}|observedAnything={1}' -f $evidence.Collected, ($null -ne $evidence.Value)) |
                Should -BeExactly 'collected=True|observedAnything=False' `
                    -Because 'a tenant holding no accepted domain is a tenant that fails EXO-001, and calling that a collection failure hides a real finding behind an infrastructure excuse'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = Get-AcceptedDomainEvidence -Collection (New-AcceptedDomainCollection -Domain @(New-AcceptedDomainRecord -DomainName 'contoso.com' -DomainType 'InternalRelay'))

            # Act
            $act = { $evidence.Value[0].DomainType = 'Authoritative' }

            # Assert
            $act | Should -Throw -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one collection of the accepted domains is one record of exactly what was returned' {

        It 'records every domain the service returned, unfiltered and unreshaped' {
            # Arrange
            $collection = New-AcceptedDomainCollection -Domain @(
                (New-AcceptedDomainRecord -DomainName 'contoso.com' -DomainType 'Authoritative'),
                (New-AcceptedDomainRecord -DomainName 'fabrikam.example' -DomainType 'InternalRelay')
            )
            $expected = 'EXO-001|ExchangeOnline|Get-AcceptedDomain|collected=True|failure=|' +
            '[{"DomainName":"contoso.com","DomainType":"Authoritative","Name":"contoso.com"},' +
            '{"DomainName":"fabrikam.example","DomainType":"InternalRelay","Name":"fabrikam.example"}]' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = Get-AcceptedDomainEvidence -Collection $collection

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so a domain the evaluator will fail on has to survive collection unchanged'
        }
    }
}

Describe 'EXO-001-A2 accepted-domain evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator EXO-001 is registered against' {
            # Arrange
            $registered = $script:AcceptedDomainRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides EXO-001, and an evaluator that is named but not shipped is a control nobody decides"
        }
    }

    Context 'Negative: the evaluator must be given a record it can decide and a state to decide against' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $result = { Test-AcceptedDomainControl -Evidence $noEvidence -ExpectedDomain @('contoso.com') }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EvidenceRequired*' -Because 'a verdict reached over no observation is a verdict about nothing, and it counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value ([pscustomobject]@{ SmtpClientAuthenticationDisabled = $true })

            # Act
            $result = { Test-AcceptedDomainControl -Evidence $foreign -ExpectedDomain @('contoso.com') }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' -Because 'deciding one control from another control''s observation reports a tenant state that was never looked at'
        }

        It 'refuses a decision that expects no domain at all' {
            # Arrange
            $evidence = New-AcceptedDomainEvidence -Domain @(New-AcceptedDomainRecord -DomainName 'contoso.com' -DomainType 'InternalRelay')

            # Act
            $result = { Test-AcceptedDomainControl -Evidence $evidence -ExpectedDomain @() }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ExpectedDomainRequired*' -Because 'a control that expects no domain is satisfied by every tenant, including one that holds no authoritative domain at all'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-AcceptedDomainEvidence -Collection { throw 'The remote session was disconnected.' }

            # Act
            $result = Test-AcceptedDomainControl -Evidence $refused -ExpectedDomain @('contoso.com')

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeLike 'EXO-001|Error|normalized=True|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a control the run never managed to observe must cost the run its go-live, because the alternative is that disconnecting the session is the cheapest way to pass'
        }
    }

    Context 'Negative: a tenant that does not hold an expected domain fails' {

        It 'fails a tenant that holds no accepted domain at all' {
            # Arrange
            $empty = Get-AcceptedDomainEvidence -Collection { }

            # Act
            $result = Test-AcceptedDomainControl -Evidence $empty -ExpectedDomain @('contoso.com')

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly "EXO-001|Fail|normalized=True|golive=False|reason=AcceptedDomainDrift: the tenant holds no accepted domain for 'contoso.com'.|evidence=Get-AcceptedDomain:EXO-001" `
                    -Because 'an observation of nothing is an observation, and reading it as agreement means a tenant with no mail domain at all passes the accepted-domain control'
        }

        It 'fails a tenant that holds only some of the expected domains' {
            # Arrange
            $evidence = New-AcceptedDomainEvidence -Domain @(New-AcceptedDomainRecord -DomainName 'contoso.com' -DomainType 'Authoritative')

            # Act
            $result = Test-AcceptedDomainControl -Evidence $evidence -ExpectedDomain @('contoso.com', 'fabrikam.example')

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly "EXO-001|Fail|normalized=True|golive=False|reason=AcceptedDomainDrift: the tenant holds no accepted domain for 'fabrikam.example'.|evidence=Get-AcceptedDomain:EXO-001" `
                    -Because 'a domain the baseline claims the tenant owns but the tenant does not accept is mail the organization believes it receives and does not'
        }
    }

    Context 'Negative: a domain that is accepted on any other terms fails' {

        It 'fails a domain the tenant accepts as an internal relay' {
            # Arrange
            $evidence = New-AcceptedDomainEvidence -Domain @(New-AcceptedDomainRecord -DomainName 'contoso.com' -DomainType 'InternalRelay')

            # Act
            $result = Test-AcceptedDomainControl -Evidence $evidence -ExpectedDomain @('contoso.com')

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly "EXO-001|Fail|normalized=True|golive=False|reason=AcceptedDomainDrift: 'contoso.com' is 'InternalRelay' where exactly 'Authoritative' is required.|evidence=Get-AcceptedDomain:EXO-001" `
                    -Because 'an internal relay domain forwards mail for recipients Exchange Online cannot verify, which is the backscatter path the control exists to close'
        }

        It 'fails a domain whose type differs from Authoritative only in case' {
            # Arrange
            $evidence = New-AcceptedDomainEvidence -Domain @(New-AcceptedDomainRecord -DomainName 'contoso.com' -DomainType 'authoritative')

            # Act
            $result = Test-AcceptedDomainControl -Evidence $evidence -ExpectedDomain @('contoso.com')

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly "EXO-001|Fail|normalized=True|golive=False|reason=AcceptedDomainDrift: 'contoso.com' is 'authoritative' where exactly 'Authoritative' is required.|evidence=Get-AcceptedDomain:EXO-001" `
                    -Because 'the card requires the type to be exactly Authoritative, and a comparison loose enough to accept a different casing is loose enough to stop proving which value the service actually returned'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $evidence = New-AcceptedDomainEvidence -Domain @(New-AcceptedDomainRecord -DomainName 'contoso.com' -DomainType 'InternalRelay')
            $result = Test-AcceptedDomainControl -Evidence $evidence -ExpectedDomain @('contoso.com')

            # Act
            $act = { $result.Status = 'Pass' }

            # Assert
            $act | Should -Throw -Because 'a verdict a caller can rewrite turns a failing control into a passing one without changing anything in the tenant'
        }
    }

    Context 'Positive: every expected domain held on exactly Authoritative terms is the only pass' {

        It 'passes a tenant holding every expected domain as Authoritative' {
            # Arrange
            $evidence = New-AcceptedDomainEvidence -Domain @(
                (New-AcceptedDomainRecord -DomainName 'Contoso.com' -DomainType 'Authoritative'),
                (New-AcceptedDomainRecord -DomainName 'fabrikam.example' -DomainType 'Authoritative')
            )

            # Act
            $result = Test-AcceptedDomainControl -Evidence $evidence -ExpectedDomain @(' contoso.com ', 'FABRIKAM.example.')

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly 'EXO-001|Pass|normalized=True|golive=True|reason=|evidence=Get-AcceptedDomain:EXO-001' `
                    -Because 'casing, surrounding whitespace and a trailing root dot are all the same domain, so formatting must never read as drift while the type stays an exact comparison'
        }
    }
}
