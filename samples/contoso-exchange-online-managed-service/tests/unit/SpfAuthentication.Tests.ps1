#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-SpfAnswer {
        param(
            [string]$Domain,
            [object]$Authoritative = $true,
            [object[]]$Records = @('v=spf1 ip4:192.0.2.0/24 -all'),
            [int]$TTL = 3600
        )

        [pscustomobject]@{
            Domain        = $Domain
            Authoritative = $Authoritative
            Records       = $Records
            TTL           = $TTL
        }
    }

    function New-SpfEvidence {
        param(
            [string[]]$SendingDomain = @('contoso.com'),
            [object[]]$Answer = @((New-SpfAnswer -Domain 'contoso.com'))
        )

        Get-SpfEvidence -SendingDomain $SendingDomain -TxtRecordCollection { param($Domain) $Answer }.GetNewClosure()
    }

    function New-SpfRecord {
        param(
            [string[]]$SendingDomain = @('contoso.com'),
            [object[]]$Answer = @((New-SpfAnswer -Domain 'contoso.com'))
        )

        New-BaselineEvidence -ControlId 'AUTH-002' -Source 'Dns' -Command 'Resolve-DnsName -Type TXT' -Value ([ordered]@{
                SendingDomains = $SendingDomain
                TxtAnswers     = $Answer
            })
    }

    function Get-SpfFold {
        param([object]$Result)
        '{0}|golive={1}|reason={2}' -f $Result.Status, $Result.GoLiveSuccess, $Result.Reason
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'AUTH-002 SPF authentication' {
    Context 'Negative: the registered SPF surface must be shipped and callable' {
        It 'exports the SPF collector' {
            # Arrange
            $registered = (@(Get-BaselineControlRegistry -Profile Historical)[0] | Where-Object ControlId -CEQ 'AUTH-002').Collector

            # Act
            $command = @(Get-Command -Module ExchangeOnlineBaseline.Common -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $command.Count | Should -Be 1
        }

        It 'exports the SPF evaluator' {
            # Arrange
            $registered = (@(Get-BaselineControlRegistry -Profile Historical)[0] | Where-Object ControlId -CEQ 'AUTH-002').Evaluator

            # Act
            $command = @(Get-Command -Module ExchangeOnlineBaseline.Common -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $command.Count | Should -Be 1
        }

        It 'refuses collection without any sending domain' {
            # Arrange
            $domains = @()

            # Act
            $act = { Get-SpfEvidence -SendingDomain $domains -TxtRecordCollection { @() } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'SpfSendingDomainRequired*'
        }

        It 'refuses collection without an authoritative TXT seam' {
            # Arrange
            $collector = $null

            # Act
            $act = { Get-SpfEvidence -SendingDomain @('contoso.com') -TxtRecordCollection $collector }

            # Assert
            $act | Should -Throw -ExpectedMessage 'SpfTxtRecordCollectionRequired*'
        }

        It 'records a TXT dependency failure as uncollected evidence' {
            # Arrange
            $refusing = { param($Domain) throw "authoritative DNS refused $Domain" }

            # Act
            $evidence = Get-SpfEvidence -SendingDomain @('contoso.com') -TxtRecordCollection $refusing

            # Assert
            ('{0}|{1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'False|CollectionFailed:*authoritative DNS refused contoso.com*'
        }

        It 'passes every sending domain to the injected TXT seam and retains its raw answers' {
            # Arrange
            $seen = [System.Collections.Generic.List[string]]::new()
            $answer = @(
                New-SpfAnswer -Domain 'contoso.com' -Records @('v=spf1 include:_spf.example.net ~all', 'site-verification=abc') -TTL 91
                New-SpfAnswer -Domain 'fabrikam.com' -Authoritative $false -Records @('v=spf1 +all') -TTL 92
            )
            $collector = { param($Domain) foreach ($name in $Domain) { $seen.Add($name) }; $answer }.GetNewClosure()

            # Act
            $evidence = Get-SpfEvidence -SendingDomain @('contoso.com', 'fabrikam.com') -TxtRecordCollection $collector

            # Assert
            ($seen -join ',') | Should -BeExactly 'contoso.com,fabrikam.com'
            (ConvertTo-CanonicalJson -InputObject $evidence.Value) | Should -BeExactly '{"SendingDomains":["contoso.com","fabrikam.com"],"TxtAnswers":[{"Authoritative":true,"Domain":"contoso.com","Records":["v=spf1 include:_spf.example.net ~all","site-verification=abc"],"TTL":91},{"Authoritative":false,"Domain":"fabrikam.com","Records":["v=spf1 +all"],"TTL":92}]}'
        }
    }

    Context 'Negative: every sending domain needs one authoritative, syntactically valid SPF policy' {
        It 'fails when a sending domain has no SPF record' {
            # Arrange
            $evidence = New-SpfRecord -Answer @((New-SpfAnswer -Domain 'contoso.com' -Records @('site-verification=abc')))

            # Act
            $result = Test-SpfControl -Evidence $evidence

            # Assert
            (Get-SpfFold $result) | Should -BeExactly "Fail|golive=False|reason=SpfRecordAbsent: sending domain 'contoso.com' publishes no SPF record."
        }

        It 'fails when a sending domain publishes duplicate SPF records' {
            # Arrange
            $evidence = New-SpfRecord -Answer @((New-SpfAnswer -Domain 'contoso.com' -Records @('v=spf1 ip4:192.0.2.1 -all', 'v=spf1 mx -all')))

            # Act
            $result = Test-SpfControl -Evidence $evidence

            # Assert
            (Get-SpfFold $result) | Should -BeExactly "Fail|golive=False|reason=SpfRecordDuplicate: domain 'contoso.com' publishes 2 SPF records; exactly one is required."
        }

        It 'fails a malformed SPF mechanism' {
            # Arrange
            $evidence = New-SpfRecord -Answer @((New-SpfAnswer -Domain 'contoso.com' -Records @('v=spf1 include -all')))

            # Act
            $result = Test-SpfControl -Evidence $evidence

            # Assert
            (Get-SpfFold $result) | Should -BeExactly "Fail|golive=False|reason=SpfMechanismMalformed: domain 'contoso.com' contains malformed SPF term 'include'."
        }

        It 'returns an error for a non-authoritative TXT answer' {
            # Arrange
            $evidence = New-SpfRecord -Answer @((New-SpfAnswer -Domain 'contoso.com' -Authoritative $false))

            # Act
            $result = Test-SpfControl -Evidence $evidence

            # Assert
            (Get-SpfFold $result) | Should -BeExactly "Error|golive=False|reason=SpfEvidenceNonAuthoritative: TXT evidence for domain 'contoso.com' is not authoritative."
        }

        It 'fails a broad pass-all terminal policy' {
            # Arrange
            $evidence = New-SpfRecord -Answer @((New-SpfAnswer -Domain 'contoso.com' -Records @('v=spf1 +all')))

            # Act
            $result = Test-SpfControl -Evidence $evidence

            # Assert
            (Get-SpfFold $result) | Should -BeExactly "Fail|golive=False|reason=SpfTerminalPolicyBroad: domain 'contoso.com' ends in '+all', which authorizes every sender."
        }

        It 'fails a soft-fail terminal policy' {
            # Arrange
            $evidence = New-SpfRecord -Answer @((New-SpfAnswer -Domain 'contoso.com' -Records @('v=spf1 ~all')))

            # Act
            $result = Test-SpfControl -Evidence $evidence

            # Assert
            (Get-SpfFold $result) | Should -BeExactly "Fail|golive=False|reason=SpfTerminalPolicySoft: domain 'contoso.com' ends in '~all' rather than exact '-all'."
        }

        It 'fails any terminal policy other than exact minus-all' {
            # Arrange
            $evidence = New-SpfRecord -Answer @((New-SpfAnswer -Domain 'contoso.com' -Records @('v=spf1 ?all')))

            # Act
            $result = Test-SpfControl -Evidence $evidence

            # Assert
            (Get-SpfFold $result) | Should -BeExactly "Fail|golive=False|reason=SpfTerminalPolicyNotExact: domain 'contoso.com' ends in '?all' rather than exact '-all'."
        }

        It 'fails when exact minus-all is not the terminal term' {
            # Arrange
            $evidence = New-SpfRecord -Answer @((New-SpfAnswer -Domain 'contoso.com' -Records @('v=spf1 -all ip4:192.0.2.1')))

            # Act
            $result = Test-SpfControl -Evidence $evidence

            # Assert
            (Get-SpfFold $result) | Should -BeExactly "Fail|golive=False|reason=SpfTerminalPolicyNotExact: domain 'contoso.com' does not terminate in exact '-all'."
        }
    }

    Context 'Negative: include and redirect graphs are evaluated only from injected evidence' {
        It 'fails when an included domain is absent from the injected TXT answers' {
            # Arrange
            $evidence = New-SpfRecord -Answer @((New-SpfAnswer -Domain 'contoso.com' -Records @('v=spf1 include:_spf.example.net -all')))

            # Act
            $result = Test-SpfControl -Evidence $evidence

            # Assert
            (Get-SpfFold $result) | Should -BeExactly "Fail|golive=False|reason=SpfDependencyAbsent: domain 'contoso.com' includes '_spf.example.net', but no injected TXT evidence exists for that domain."
        }

        It 'fails an include loop' {
            # Arrange
            $evidence = New-SpfRecord -Answer @(
                (New-SpfAnswer -Domain 'contoso.com' -Records @('v=spf1 include:_spf.example.net -all'))
                (New-SpfAnswer -Domain '_spf.example.net' -Records @('v=spf1 include:contoso.com -all'))
            )

            # Act
            $result = Test-SpfControl -Evidence $evidence

            # Assert
            (Get-SpfFold $result) | Should -BeExactly 'Fail|golive=False|reason=SpfDependencyLoop: SPF evaluation encountered loop contoso.com -> _spf.example.net -> contoso.com.'
        }

        It 'fails a redirect loop' {
            # Arrange
            $evidence = New-SpfRecord -Answer @(
                (New-SpfAnswer -Domain 'contoso.com' -Records @('v=spf1 redirect=_spf.example.net'))
                (New-SpfAnswer -Domain '_spf.example.net' -Records @('v=spf1 redirect=contoso.com'))
            )

            # Act
            $result = Test-SpfControl -Evidence $evidence

            # Assert
            (Get-SpfFold $result) | Should -BeExactly 'Fail|golive=False|reason=SpfDependencyLoop: SPF evaluation encountered loop contoso.com -> _spf.example.net -> contoso.com.'
        }

        It 'fails when SPF processing exceeds ten DNS-causing terms' {
            # Arrange
            $terms = 1..11 | ForEach-Object { "include:_spf$_.example.net" }
            $answers = @((New-SpfAnswer -Domain 'contoso.com' -Records @("v=spf1 $($terms -join ' ') -all")))
            $answers += 1..11 | ForEach-Object { New-SpfAnswer -Domain "_spf$_.example.net" }
            $evidence = New-SpfRecord -Answer $answers

            # Act
            $result = Test-SpfControl -Evidence $evidence

            # Assert
            (Get-SpfFold $result) | Should -BeExactly "Fail|golive=False|reason=SpfLookupLimitExceeded: sending domain 'contoso.com' requires more than 10 DNS lookups."
        }
    }

    Context 'Positive: one complete all-domain injected SPF graph passes' {
        It 'passes every sending domain through authoritative include and redirect evidence with exact minus-all termination' {
            # Arrange
            $answers = @(
                (New-SpfAnswer -Domain 'contoso.com' -Records @('site-verification=abc', 'v=spf1 ip4:192.0.2.0/24 include:_spf.contoso.net -all'))
                (New-SpfAnswer -Domain '_spf.contoso.net' -Records @('v=spf1 a mx -all'))
                (New-SpfAnswer -Domain 'fabrikam.com' -Records @('v=spf1 redirect=_spf.fabrikam.net'))
                (New-SpfAnswer -Domain '_spf.fabrikam.net' -Records @('v=spf1 ip6:2001:db8::/32 -all'))
            )
            $evidence = New-SpfEvidence -SendingDomain @('CONTOSO.COM.', 'fabrikam.com') -Answer $answers

            # Act
            $result = Test-SpfControl -Evidence $evidence

            # Assert
            ('{0}|{1}|{2}|{3}' -f $result.ControlId, $result.Status, $result.Normalized, $result.GoLiveSuccess) |
                Should -BeExactly 'AUTH-002|Pass|True|True'
        }
    }
}
