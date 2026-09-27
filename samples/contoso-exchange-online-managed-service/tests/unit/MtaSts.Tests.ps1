#requires -Version 7.0

# Pester evaluates `-ForEach` during discovery, before any `BeforeAll` has run, so the observations
# EXO-011 is decided from, the members each observed answer is decided by, and the ways a published
# policy can fall short are declared here.
$MtaStsObservation = @('MtaStsRecord', 'MtaStsPolicy', 'TlsRptRecord', 'MxRecord')

$DesiredTransportMember = @('mtaStsMode', 'mtaStsMaxAgeSeconds', 'tlsRptAddress')

$TxtDecidedMember = @('Authoritative', 'Strings')

$MxDecidedMember = @('Authoritative', 'NameExchange')

$PolicyDecidedMember = @('Scheme', 'TlsValidated', 'StatusCode', 'ContentType', 'Content')

$AuthoritativeAnswer = @(
    @{ Observation = 'MtaStsRecord'; Builder = 'New-CompliantDiscoveryRecord'; Noun = 'MTA-STS discovery' }
    @{ Observation = 'TlsRptRecord'; Builder = 'New-CompliantTlsRptRecord'; Noun = 'TLS-RPT' }
    @{ Observation = 'MxRecord'; Builder = 'New-CompliantMxAnswer'; Noun = 'MX' }
)

$PolicyDirective = @('version', 'mode', 'mx', 'max_age')

$PolicyDirectiveDrift = @(
    @{ Directive = 'mode'; Live = 'testing'; Want = 'enforce' }
    @{ Directive = 'max_age'; Live = '86400'; Want = '604800' }
)

$EndpointDefect = @(
    @{ Member = 'Scheme'; Live = 'http'; Finding = "the MTA-STS policy endpoint was reached over 'http' rather than 'https'" }
    @{ Member = 'TlsValidated'; Live = $false; Finding = 'the MTA-STS policy endpoint did not present a TLS chain that validated' }
    @{ Member = 'StatusCode'; Live = 404; Finding = "the MTA-STS policy endpoint answered with status '404' rather than '200'" }
    @{ Member = 'ContentType'; Live = 'text/html'; Finding = "the MTA-STS policy endpoint answered with media type 'text/html' rather than 'text/plain'" }
)

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Every DNS lookup and every policy fetch EXO-011 depends on is reached only through a supplied
    # collection seam, so each collection here is a scriptblock returning a canned answer or
    # throwing a canned failure and no query and no request leaves this process.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # The registry is returned as one read-only collection deliberately protected from pipeline
    # unrolling, so the entry is read by index rather than by piping the collection.
    $script:ControlRegistry = @(Get-BaselineControlRegistry)[0]
    $script:MtaStsRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'EXO-011') { $entry }
        })[0]

    # A DNS TXT answer as the seam reports it: whether the answering server was authoritative for
    # the zone, and the character strings the record holds. `TTL` is carried deliberately as a
    # member EXO-011 decides nothing about, so a collector that narrowed the answer to the members
    # the control reads is distinguishable from one that recorded the answer.
    function New-TxtAnswer {
        [CmdletBinding()]
        param(
            [string]$Name = '_mta-sts.contoso.com',

            [object]$Authoritative = $true,

            [object]$Strings = @('v=STSv1; id=20260916T000000Z'),

            [object]$TTL = 3600
        )

        return [pscustomobject]@{
            Name          = $Name
            Authoritative = $Authoritative
            Strings       = $Strings
            TTL           = $TTL
        }
    }

    function New-MxAnswer {
        [CmdletBinding()]
        param(
            [string]$Name = 'contoso.com',

            [object]$Authoritative = $true,

            [object]$NameExchange = @('contoso-com.mail.protection.outlook.com'),

            [object]$TTL = 3600
        )

        return [pscustomobject]@{
            Name          = $Name
            Authoritative = $Authoritative
            NameExchange  = $NameExchange
            TTL           = $TTL
        }
    }

    # The MTA-STS policy document, as RFC 8461 declares it. The directives are built rather than
    # written out at each negative so one of them can be changed or dropped in isolation.
    function New-MtaStsPolicyDocument {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{},

            [string[]]$Remove = @()
        )

        $directive = [ordered]@{
            version = 'STSv1'
            mode    = 'enforce'
            mx      = @('contoso-com.mail.protection.outlook.com')
            max_age = '604800'
        }

        foreach ($name in $Override.Keys) { $directive[$name] = $Override[$name] }

        $line = @(
            foreach ($name in @($directive.Keys)) {
                if ($name -cin $Remove) { continue }
                foreach ($value in @($directive[$name])) { '{0}: {1}' -f $name, $value }
            }
        )

        return ($line -join "`n")
    }

    # The HTTPS fetch of the policy endpoint, as the seam reports it: the scheme it was reached
    # over, whether the TLS chain validated, the status and media type the endpoint answered with,
    # and the document body. `Uri` is carried as a member EXO-011 decides nothing about.
    function New-PolicyFetch {
        [CmdletBinding()]
        param(
            [object]$Scheme = 'https',

            [object]$TlsValidated = $true,

            [object]$StatusCode = 200,

            [object]$ContentType = 'text/plain',

            [object]$Content,

            [object]$Uri = 'https://mta-sts.contoso.com/.well-known/mta-sts.txt'
        )

        if (-not $PSBoundParameters.ContainsKey('Content')) { $Content = New-MtaStsPolicyDocument }

        return [pscustomobject]@{
            Scheme       = $Scheme
            TlsValidated = $TlsValidated
            StatusCode   = $StatusCode
            ContentType  = $ContentType
            Content      = $Content
            Uri          = $Uri
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

    # The discovery-time copy of this list is not in scope while a test runs, and a list that read
    # as empty would let every omission assert the same absence.
    $script:ObservationName = @('MtaStsRecord', 'MtaStsPolicy', 'TlsRptRecord', 'MxRecord')

    function New-CompliantDiscoveryRecord {
        [CmdletBinding()]
        param([hashtable]$Override = @{})

        $argument = @{ Name = '_mta-sts.contoso.com'; Strings = @('v=STSv1; id=20260916T000000Z') }
        foreach ($name in $Override.Keys) { $argument[$name] = $Override[$name] }

        return New-TxtAnswer @argument
    }

    function New-CompliantTlsRptRecord {
        [CmdletBinding()]
        param([hashtable]$Override = @{})

        $argument = @{ Name = '_smtp._tls.contoso.com'; Strings = @('v=TLSRPTv1; rua=mailto:tlsrpt@contoso.com') }
        foreach ($name in $Override.Keys) { $argument[$name] = $Override[$name] }

        return New-TxtAnswer @argument
    }

    function New-CompliantMxAnswer {
        [CmdletBinding()]
        param([hashtable]$Override = @{})

        $argument = @{}
        foreach ($name in $Override.Keys) { $argument[$name] = $Override[$name] }

        return New-MxAnswer @argument
    }

    function New-CompliantPolicyFetch {
        [CmdletBinding()]
        param([hashtable]$Override = @{})

        $argument = @{}
        foreach ($name in $Override.Keys) { $argument[$name] = $Override[$name] }

        return New-PolicyFetch @argument
    }

    # The transport-security state the baseline resolves, as `transportSecurity` declares it.
    function New-DesiredTransportSecurityState {
        [CmdletBinding()]
        param([hashtable]$Override = @{})

        $state = [pscustomobject][ordered]@{
            mtaStsMode          = 'enforce'
            mtaStsMaxAgeSeconds = 604800
            tlsRptAddress       = 'mailto:tlsrpt@contoso.com'
        }

        foreach ($name in $Override.Keys) {
            $state.PSObject.Properties[$name].Value = $Override[$name]
        }

        return $state
    }

    # A domain that satisfies EXO-011, with exactly one thing changed per negative, so a verdict a
    # negative produces cannot be explained by anything else in the fixture.
    function New-MtaStsEvidenceRecord {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [object]$MtaStsRecord,

            [AllowNull()]
            [object]$MtaStsPolicy,

            [AllowNull()]
            [object]$TlsRptRecord,

            [AllowNull()]
            [object]$MxRecord
        )

        if (-not $PSBoundParameters.ContainsKey('MtaStsRecord')) { $MtaStsRecord = New-CompliantDiscoveryRecord }
        if (-not $PSBoundParameters.ContainsKey('MtaStsPolicy')) { $MtaStsPolicy = New-CompliantPolicyFetch }
        if (-not $PSBoundParameters.ContainsKey('TlsRptRecord')) { $TlsRptRecord = New-CompliantTlsRptRecord }
        if (-not $PSBoundParameters.ContainsKey('MxRecord')) { $MxRecord = New-CompliantMxAnswer }

        return Get-MtaStsEvidence `
            -MtaStsRecordCollection { $MtaStsRecord }.GetNewClosure() `
            -MtaStsPolicyCollection { $MtaStsPolicy }.GetNewClosure() `
            -TlsRptRecordCollection { $TlsRptRecord }.GetNewClosure() `
            -MxRecordCollection { $MxRecord }.GetNewClosure()
    }

    function New-PartialMtaStsEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'EXO-011' -Source 'Dns' `
            -Command 'Resolve-DnsName -Type TXT _mta-sts; Invoke-WebRequest mta-sts.txt; Resolve-DnsName -Type TXT _smtp._tls; Resolve-DnsName -Type MX' `
            -Value $Payload
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

Describe 'EXO-011-A1 MTA-STS and TLS-RPT collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector EXO-011 is registered against' {
            # Arrange
            $registered = $script:MtaStsRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes EXO-011, and both shipping scripts answer this control with a literal 'Manual' today, which is the one status a go-live gate can never act on"
        }
    }

    Context 'Negative: every source the control is decided from must be given a call to make' {

        It 'refuses a run with no MTA-STS discovery lookup' {
            # Arrange
            $discovery = $null

            # Act
            $act = {
                Get-MtaStsEvidence -MtaStsRecordCollection $discovery -MtaStsPolicyCollection { New-PolicyFetch } `
                    -TlsRptRecordCollection { New-TxtAnswer } -MxRecordCollection { New-MxAnswer }
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MtaStsRecordCollectionRequired*' `
                -Because 'the discovery record is what tells a sending server a policy exists at all, so a domain serving a perfect policy document nobody is told to fetch enforces nothing'
        }

        It 'refuses a run with no policy fetch' {
            # Arrange
            $policy = $null

            # Act
            $act = {
                Get-MtaStsEvidence -MtaStsRecordCollection { New-TxtAnswer } -MtaStsPolicyCollection $policy `
                    -TlsRptRecordCollection { New-TxtAnswer } -MxRecordCollection { New-MxAnswer }
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MtaStsPolicyCollectionRequired*' `
                -Because 'the discovery record carries a policy id and nothing else, so the mode, the maximum age and the MX hosts the policy actually commits the domain to are only readable from the document itself'
        }

        It 'refuses a run with no TLS-RPT lookup' {
            # Arrange
            $tlsRpt = $null

            # Act
            $act = {
                Get-MtaStsEvidence -MtaStsRecordCollection { New-TxtAnswer } -MtaStsPolicyCollection { New-PolicyFetch } `
                    -TlsRptRecordCollection $tlsRpt -MxRecordCollection { New-MxAnswer }
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'TlsRptRecordCollectionRequired*' `
                -Because 'a policy in enforce mode silently drops mail whose TLS negotiation fails, and the TLS report is the only thing that tells anybody it is happening'
        }

        It 'refuses a run with no MX lookup' {
            # Arrange
            $mx = $null

            # Act
            $act = {
                Get-MtaStsEvidence -MtaStsRecordCollection { New-TxtAnswer } -MtaStsPolicyCollection { New-PolicyFetch } `
                    -TlsRptRecordCollection { New-TxtAnswer } -MxRecordCollection $mx
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MxRecordCollectionRequired*' `
                -Because 'a policy that does not name every published MX host makes mail to the hosts it omits undeliverable the moment the mode reaches enforce, so the published hosts have to be read from DNS rather than assumed from the policy'
        }
    }

    Context 'Negative: a source that refused is never an observation' {

        It 'records a discovery lookup that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'DNS name does not exist.' }

            # Act
            $evidence = Get-MtaStsEvidence -MtaStsRecordCollection $refusing -MtaStsPolicyCollection { New-PolicyFetch } `
                -TlsRptRecordCollection { New-TxtAnswer } -MxRecordCollection { New-MxAnswer }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'a resolver that never answered proves nothing about what the zone publishes, and a refusal that is not recorded as a refusal reads downstream exactly like a domain that was queried and found compliant'
        }

        It 'records a policy fetch that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The remote certificate is invalid according to the validation procedure.' }

            # Act
            $evidence = Get-MtaStsEvidence -MtaStsRecordCollection { New-TxtAnswer } -MtaStsPolicyCollection $refusing `
                -TlsRptRecordCollection { New-TxtAnswer } -MxRecordCollection { New-MxAnswer }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'the policy endpoint is the one source here that is an ordinary web host somebody else operates, so it is the one that expires a certificate quietly, and a fetch that threw recorded as a whole observation reports an enforced domain from a document nobody read'
        }

        It 'records a TLS-RPT lookup that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The DNS operation timed out.' }

            # Act
            $evidence = Get-MtaStsEvidence -MtaStsRecordCollection { New-TxtAnswer } -MtaStsPolicyCollection { New-PolicyFetch } `
                -TlsRptRecordCollection $refusing -MxRecordCollection { New-MxAnswer }

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'a record assembled from three of the four sources reports a transport posture that silently excludes the fourth, and the excluded one always reads as compliant'
        }

        It 'records an MX lookup that threw as an uncollected observation' {
            # Arrange
            $refusing = { throw 'The server was unable to process the request.' }

            # Act
            $evidence = Get-MtaStsEvidence -MtaStsRecordCollection { New-TxtAnswer } -MtaStsPolicyCollection { New-PolicyFetch } `
                -TlsRptRecordCollection { New-TxtAnswer } -MxRecordCollection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'MX coverage is the only finding here that can stop mail arriving rather than merely leave it unprotected, so an unread MX answer taken as full coverage is the most expensive silent pass this control can produce'
        }
    }

    Context 'Negative: a domain that published nothing is an observation, not a failed collection' {

        It 'records a collection where all four sources returned nothing as collected' {
            # Arrange
            $silent = { }

            # Act
            $evidence = Get-MtaStsEvidence -MtaStsRecordCollection $silent -MtaStsPolicyCollection $silent `
                -TlsRptRecordCollection $silent -MxRecordCollection $silent

            # Assert
            ('collected={0}|failure={1}|{2}' -f $evidence.Collected, $evidence.FailureReason, (ConvertTo-CanonicalJson -InputObject $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|{"MtaStsPolicy":null,"MtaStsRecord":null,"MxRecord":null,"TlsRptRecord":null}' `
                    -Because 'a domain that has published no MTA-STS at all answers every one of these with nothing, and that is the commonest observation this control decides rather than an infrastructure failure to hide the control behind'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = Get-MtaStsEvidence `
                -MtaStsRecordCollection { New-TxtAnswer -Authoritative $false } `
                -MtaStsPolicyCollection { New-PolicyFetch -StatusCode 404 } `
                -TlsRptRecordCollection { New-TxtAnswer -Strings @() } `
                -MxRecordCollection { New-MxAnswer -NameExchange @() }

            # Act
            $act = { $evidence.Value['MtaStsPolicy'] = $null }

            # Assert
            $act | Should -Throw `
                -Because 'raw evidence a caller can rewrite is not evidence of what the domain publishes, it is evidence of what the caller wanted it to publish'
        }
    }

    Context 'Positive: one collection of all four sources is one record of exactly what they returned' {

        It 'records all four observations under the control, source and commands the registry declares' {
            # Arrange
            $discovery = { New-TxtAnswer -Name '_mta-sts.contoso.com' -Strings @('v=STSv1; id=20260916T000000Z') }
            $policy = { New-PolicyFetch -Content "version: STSv1`nmode: testing`nmx: contoso-com.mail.protection.outlook.com`nmax_age: 604800" }
            $tlsRpt = { New-TxtAnswer -Name '_smtp._tls.contoso.com' -Strings @('v=TLSRPTv1; rua=mailto:tlsrpt@contoso.com') }
            $mx = { New-MxAnswer -NameExchange @('contoso-com.mail.protection.outlook.com', 'contoso-com-v2.mail.protection.outlook.com') }
            $expected = 'EXO-011|Dns|Resolve-DnsName -Type TXT _mta-sts; Invoke-WebRequest mta-sts.txt; Resolve-DnsName -Type TXT _smtp._tls; Resolve-DnsName -Type MX|collected=True|failure=|' +
            '{"MtaStsPolicy":{"Content":"version: STSv1\nmode: testing\nmx: contoso-com.mail.protection.outlook.com\nmax_age: 604800",' +
            '"ContentType":"text/plain","Scheme":"https","StatusCode":200,"TlsValidated":true,"Uri":"https://mta-sts.contoso.com/.well-known/mta-sts.txt"},' +
            '"MtaStsRecord":{"Authoritative":true,"Name":"_mta-sts.contoso.com","Strings":["v=STSv1; id=20260916T000000Z"],"TTL":3600},' +
            '"MxRecord":{"Authoritative":true,"Name":"contoso.com","NameExchange":["contoso-com.mail.protection.outlook.com","contoso-com-v2.mail.protection.outlook.com"],"TTL":3600},' +
            '"TlsRptRecord":{"Authoritative":true,"Name":"_smtp._tls.contoso.com","Strings":["v=TLSRPTv1; rua=mailto:tlsrpt@contoso.com"],"TTL":3600}}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = Get-MtaStsEvidence -MtaStsRecordCollection $discovery -MtaStsPolicyCollection $policy `
                -TlsRptRecordCollection $tlsRpt -MxRecordCollection $mx

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so the policy document survives collection as the text the endpoint served rather than as parsed directives, a second published MX host survives beside the one the policy names, and a policy in testing mode survives at all: a collector that parsed the document would decide the syntax before any evaluator saw it, one that narrowed each answer to the members the control reads would drop the authoritative flag the evaluator needs to know the answer is worth anything, and one that folded the four observations into a verdict would decide the control in the collector'
        }
    }
}

Describe 'EXO-011-A2 MTA-STS and TLS-RPT evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator EXO-011 is registered against' {
            # Arrange
            $registered = $script:MtaStsRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides EXO-011, and until it ships the control is answered with a literal 'Manual', which the go-live gate cannot tell apart from nobody having looked"
        }
    }

    Context 'Negative: the evaluator must be given an observation to decide' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $absent = $null

            # Act
            $act = { Test-MtaStsControl -Evidence $absent -DesiredState (New-DesiredTransportSecurityState) }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceRequired*' `
                -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'AUTH-003' -Source 'Dns' -Command 'Resolve-DnsName -Type TXT _dmarc' `
                -Value ([pscustomobject]@{ Name = '_dmarc.contoso.com'; Strings = @('v=DMARC1; p=reject') })

            # Act
            $act = { Test-MtaStsControl -Evidence $foreign -DesiredState (New-DesiredTransportSecurityState) }

            # Assert
            $act | Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' `
                -Because 'every DNS control in this solution collects a TXT answer shaped exactly like this one, so a record that looks close enough decides transport security from a policy nobody looked up'
        }
    }

    Context 'Negative: the evaluator must be given the desired state to decide against' {

        It 'refuses a decision with no resolved desired transport-security state' {
            # Arrange
            $unresolved = $null

            # Act
            $act = { Test-MtaStsControl -Evidence (New-MtaStsEvidenceRecord) -DesiredState $unresolved }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DesiredTransportSecurityStateRequired*' `
                -Because 'an evaluator with no desired state decides the published policy against whatever it defaults to rather than against what the baseline resolved, and a default of testing mode passes every domain that never finished the rollout'
        }

        It "refuses a decision whose desired state resolves no '<_>' value" -ForEach $DesiredTransportMember {
            # Arrange
            $partial = New-DesiredTransportSecurityState
            $partial.PSObject.Properties.Remove($_)

            # Act
            $act = { Test-MtaStsControl -Evidence (New-MtaStsEvidenceRecord) -DesiredState $partial }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DesiredTransportSecurityMemberRequired*' `
                -Because 'two values compared against the baseline and a third compared against nothing is reported as a fully decided domain, and the TLS-RPT destination in particular resolves from an admin-supplied parameter, so an unresolved one is the likeliest of the three'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-MtaStsEvidence -MtaStsRecordCollection { New-CompliantDiscoveryRecord } `
                -MtaStsPolicyCollection { throw 'The remote certificate is invalid according to the validation procedure.' } `
                -TlsRptRecordCollection { New-CompliantTlsRptRecord } `
                -MxRecordCollection { New-CompliantMxAnswer }

            # Act
            $result = Test-MtaStsControl -Evidence $refused -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a domain the run never managed to read must cost the run its go-live, because the alternative is that an expired certificate on the policy host is the cheapest way to pass this control'
        }
    }

    Context 'Negative: a record that carries only part of itself decides nothing about the rest' {

        It "decides a record carrying no '<_>' observation as an error" -ForEach $MtaStsObservation {
            # Arrange
            $observation = [ordered]@{}
            foreach ($name in $script:ObservationName) {
                if ($name -cne $_) { $observation[$name] = $null }
            }
            $partial = New-PartialMtaStsEvidence -Payload $observation

            # Act
            $result = Test-MtaStsControl -Evidence $partial -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=MtaStsEvidenceIncomplete: the record carries no '$_' observation." `
                    -Because 'an observation that is absent is not an observation of nothing, and read as one it decides transport security from a source nobody read'
        }

        It "decides an observed MTA-STS discovery record carrying no '<_>' member as an error" -ForEach $TxtDecidedMember {
            # Arrange
            $discovery = New-CompliantDiscoveryRecord
            $discovery.PSObject.Properties.Remove($_)
            $incomplete = New-MtaStsEvidenceRecord -MtaStsRecord $discovery

            # Act
            $result = Test-MtaStsControl -Evidence $incomplete -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=MtaStsEvidenceIncomplete: the observed MTA-STS discovery record carries no '$_' member." `
                    -Because 'an absent set of character strings read as an empty answer reports a domain that published nothing, and an absent authoritative flag read as true reports a cached answer as proof of what the zone holds'
        }

        It "decides an observed TLS-RPT record carrying no '<_>' member as an error" -ForEach $TxtDecidedMember {
            # Arrange
            $tlsRpt = New-CompliantTlsRptRecord
            $tlsRpt.PSObject.Properties.Remove($_)
            $incomplete = New-MtaStsEvidenceRecord -TlsRptRecord $tlsRpt

            # Act
            $result = Test-MtaStsControl -Evidence $incomplete -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=MtaStsEvidenceIncomplete: the observed TLS-RPT record carries no '$_' member." `
                    -Because 'the TLS report is the only thing that says a negotiation failed, so an incomplete answer about it read as a compliant one is how an enforcing domain drops mail with nobody watching'
        }

        It "decides an observed MX answer carrying no '<_>' member as an error" -ForEach $MxDecidedMember {
            # Arrange
            $mx = New-CompliantMxAnswer
            $mx.PSObject.Properties.Remove($_)
            $incomplete = New-MtaStsEvidenceRecord -MxRecord $mx

            # Act
            $result = Test-MtaStsControl -Evidence $incomplete -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=MtaStsEvidenceIncomplete: the observed MX answer carries no '$_' member." `
                    -Because 'an absent list of exchange hosts read as an empty one makes any policy cover every host it was never asked about, which is the reading that turns enforce mode into lost mail'
        }

        It "decides an observed MTA-STS policy fetch carrying no '<_>' member as an error" -ForEach $PolicyDecidedMember {
            # Arrange
            $policy = New-CompliantPolicyFetch
            $policy.PSObject.Properties.Remove($_)
            $incomplete = New-MtaStsEvidenceRecord -MtaStsPolicy $policy

            # Act
            $result = Test-MtaStsControl -Evidence $incomplete -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=MtaStsEvidenceIncomplete: the observed MTA-STS policy fetch carries no '$_' member." `
                    -Because 'a fetch whose scheme, TLS outcome, status or media type was never recorded read as the compliant one reports an enforced domain from a transport nobody checked, and an absent document read as empty reports a policy that declares nothing as one that declares everything'
        }
    }

    Context 'Negative: an answer that was not authoritative proves nothing about the zone' {

        It 'decides a <Noun> answer that was not authoritative as an error' -ForEach $AuthoritativeAnswer {
            # Arrange
            $argument = @{ $Observation = (& $Builder -Override @{ Authoritative = $false }) }
            $cached = New-MtaStsEvidenceRecord @argument

            # Act
            $result = Test-MtaStsControl -Evidence $cached -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=MtaStsEvidenceInconclusive: the $Noun answer was not authoritative for the zone." `
                    -Because 'a recursive resolver answers from a cache that can outlive the record by the whole of its time to live, so a non-authoritative answer decides todays posture from yesterdays zone - and the direction it is wrong in is always the flattering one, because the record that was just withdrawn is the one still cached'
        }
    }

    Context 'Negative: a policy endpoint that is not a trustworthy HTTPS resource fails' {

        It "fails a policy endpoint whose '<Member>' is not what a policy fetch requires" -ForEach $EndpointDefect {
            # Arrange
            $defective = New-MtaStsEvidenceRecord -MtaStsPolicy (New-CompliantPolicyFetch -Override @{ $Member = $Live })

            # Act
            $result = Test-MtaStsControl -Evidence $defective -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=TransportSecurityUnenforced: $Finding." `
                    -Because 'a sending server refuses a policy it could not fetch over authenticated HTTPS, so a document that is correct in every word but served over plain HTTP, behind an invalid chain, under a redirect or as HTML commits the domain to nothing at all'
        }
    }

    Context 'Negative: a policy document that does not say what it must fails' {

        It "fails a policy that declares no '<_>'" -ForEach $PolicyDirective {
            # Arrange
            $silent = New-MtaStsEvidenceRecord -MtaStsPolicy (New-CompliantPolicyFetch -Override @{
                    Content = (New-MtaStsPolicyDocument -Remove @($_))
                })

            # Act
            $result = Test-MtaStsControl -Evidence $silent -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=TransportSecurityUnenforced: the MTA-STS policy declares no '$_'." `
                    -Because 'RFC 8461 requires all four, and a sending server that cannot parse one of them discards the whole policy rather than applying the rest, so a document missing a single directive is indistinguishable to a sender from a domain that published no policy'
        }

        It 'fails a policy whose version is not the one the standard declares' {
            # Arrange
            $future = New-MtaStsEvidenceRecord -MtaStsPolicy (New-CompliantPolicyFetch -Override @{
                    Content = (New-MtaStsPolicyDocument -Override @{ version = 'STSv2' })
                })

            # Act
            $result = Test-MtaStsControl -Evidence $future -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=TransportSecurityUnenforced: the MTA-STS policy declares 'version' as 'STSv2' where the standard requires 'STSv1'." `
                    -Because 'the version is the first thing a sender reads and the whole document is discarded on an unrecognized one, so a typed version string is a policy nobody applies while every other directive in it reads as correct'
        }

        It "fails a policy whose '<Directive>' differs from the resolved desired state" -ForEach $PolicyDirectiveDrift {
            # Arrange
            $drifted = New-MtaStsEvidenceRecord -MtaStsPolicy (New-CompliantPolicyFetch -Override @{
                    Content = (New-MtaStsPolicyDocument -Override @{ $Directive = $Live })
                })

            # Act
            $result = Test-MtaStsControl -Evidence $drifted -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=TransportSecurityUnenforced: the MTA-STS policy declares '$Directive' as '$Live' where the baseline requires '$Want'." `
                    -Because 'the runbook tells an operator to start in testing mode and move to enforce only after reviewing reports, so a domain left in testing is the commonest outcome of a correctly followed rollout and reports a published policy that downgrades silently on every attack it exists to stop; a maximum age far below the resolved one leaves the cached policy expiring between deliveries, which has the same effect for a sender that has not spoken to the domain lately'
        }
    }

    Context 'Negative: a policy that does not cover what the domain publishes fails' {

        It 'fails a published MX host no policy MX pattern covers, naming the host' {
            # Arrange
            $uncovered = New-MtaStsEvidenceRecord -MxRecord (New-CompliantMxAnswer -Override @{
                    NameExchange = @('contoso-com.mail.protection.outlook.com', 'legacy-relay.contoso.com')
                })

            # Act
            $result = Test-MtaStsControl -Evidence $uncovered -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=TransportSecurityUnenforced: the MTA-STS policy does not cover published MX host 'legacy-relay.contoso.com'." `
                    -Because 'this is the only finding in the control that stops mail arriving rather than merely leaving it unprotected: the moment the mode reaches enforce, a sender that resolves the uncovered host refuses to deliver to it, and the operator who added the relay is never the operator who edited the policy'
        }

        It 'fails a domain that publishes no MX host at all' {
            # Arrange
            $unreachable = New-MtaStsEvidenceRecord -MxRecord (New-CompliantMxAnswer -Override @{ NameExchange = @() })

            # Act
            $result = Test-MtaStsControl -Evidence $unreachable -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=TransportSecurityUnenforced: the domain publishes no MX host at all.' `
                    -Because 'an empty answer is the one input that makes every coverage comparison vacuously true, so a control that decided coverage by iterating the published hosts would report full coverage for a domain that publishes none'
        }
    }

    Context 'Negative: a discovery record that does not announce the policy fails' {

        It 'fails a domain that publishes no MTA-STS discovery record' {
            # Arrange
            $unannounced = New-MtaStsEvidenceRecord -MtaStsRecord (New-CompliantDiscoveryRecord -Override @{ Strings = @() })

            # Act
            $result = Test-MtaStsControl -Evidence $unannounced -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=TransportSecurityUnenforced: the domain publishes no MTA-STS discovery record.' `
                    -Because 'a sender never fetches a policy it was not told about, so a perfect document served from a perfect endpoint enforces nothing for a domain whose discovery record was never published'
        }

        It 'fails a discovery record whose version is not the one the standard declares' {
            # Arrange
            $future = New-MtaStsEvidenceRecord -MtaStsRecord (New-CompliantDiscoveryRecord -Override @{
                    Strings = @('v=STSv2; id=20260916T000000Z')
                })

            # Act
            $result = Test-MtaStsControl -Evidence $future -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=TransportSecurityUnenforced: the MTA-STS discovery record declares 'v=STSv2' where the standard requires 'v=STSv1'." `
                    -Because 'the version tag is what distinguishes this TXT record from every other one at the same name, and a sender that does not recognize it treats the domain as having no policy'
        }

        It 'fails a discovery record that carries no policy id' {
            # Arrange
            $idless = New-MtaStsEvidenceRecord -MtaStsRecord (New-CompliantDiscoveryRecord -Override @{
                    Strings = @('v=STSv1;')
                })

            # Act
            $result = Test-MtaStsControl -Evidence $idless -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=TransportSecurityUnenforced: the MTA-STS discovery record carries no policy id.' `
                    -Because 'the id is the only signal a sender has that the document changed, so a record without one leaves every sender holding the policy it cached up to the maximum age - which means an MX host added today is uncovered for a week after the document was corrected'
        }
    }

    Context 'Negative: a TLS-RPT record that reports nowhere the baseline approved fails' {

        It 'fails a domain that publishes no TLS-RPT record' {
            # Arrange
            $unreported = New-MtaStsEvidenceRecord -TlsRptRecord (New-CompliantTlsRptRecord -Override @{ Strings = @() })

            # Act
            $result = Test-MtaStsControl -Evidence $unreported -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=TransportSecurityUnenforced: the domain publishes no TLS-RPT record.' `
                    -Because 'enforce mode converts a downgrade attack from silently readable mail into silently undelivered mail, and the TLS report is the only place either outcome is ever visible'
        }

        It 'fails a TLS-RPT record whose version is not the one the standard declares' {
            # Arrange
            $future = New-MtaStsEvidenceRecord -TlsRptRecord (New-CompliantTlsRptRecord -Override @{
                    Strings = @('v=TLSRPTv2; rua=mailto:tlsrpt@contoso.com')
                })

            # Act
            $result = Test-MtaStsControl -Evidence $future -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=TransportSecurityUnenforced: the TLS-RPT record declares 'v=TLSRPTv2' where the standard requires 'v=TLSRPTv1'." `
                    -Because 'a record a sender does not recognize is a record a sender does not report to, and the destination inside it reads as perfectly correct to anybody checking by eye'
        }

        It 'fails a TLS-RPT record whose destination differs from the resolved desired state' {
            # Arrange
            $misdirected = New-MtaStsEvidenceRecord -TlsRptRecord (New-CompliantTlsRptRecord -Override @{
                    Strings = @('v=TLSRPTv1; rua=mailto:postmaster@contoso.com')
                })

            # Act
            $result = Test-MtaStsControl -Evidence $misdirected -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=TransportSecurityUnenforced: the TLS-RPT record reports its destination as 'mailto:postmaster@contoso.com' where the baseline requires 'mailto:tlsrpt@contoso.com'." `
                    -Because 'a report delivered to an address nobody monitors is indistinguishable from a report nobody sent, so the destination is exact desired state rather than a presence check - and the address the baseline resolves is the monitored one somebody agreed to watch'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-MtaStsControl `
                -Evidence (New-MtaStsEvidenceRecord -MtaStsPolicy (New-CompliantPolicyFetch -Override @{
                        Content = (New-MtaStsPolicyDocument -Override @{ mode = 'testing' })
                    })) `
                -DesiredState (New-DesiredTransportSecurityState)

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act | Should -Throw -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: an announced, fetchable, enforcing policy that covers every published host and reports to the approved destination is one go-live-successful pass' {

        It 'passes a domain whose discovery record, policy document, MX coverage and TLS-RPT destination all hold what the baseline resolved' {
            # Arrange
            $published = New-MtaStsEvidenceRecord `
                -MtaStsRecord (New-CompliantDiscoveryRecord -Override @{ Strings = @(' V=STSv1; ID=20260916T000000Z ') }) `
                -MtaStsPolicy (New-CompliantPolicyFetch -Override @{
                    ContentType = 'text/plain; charset=utf-8'
                    Content     = "Version: STSv1`r`n  MODE:  ENFORCE  `r`nmx: *.mail.protection.outlook.com`r`nMax_Age: 604800`r`n"
                }) `
                -TlsRptRecord (New-CompliantTlsRptRecord -Override @{ Strings = @('v=TLSRPTv1; ru', 'a=MailTo:TlsRpt@contoso.com ') }) `
                -MxRecord (New-CompliantMxAnswer -Override @{
                    NameExchange = @('CONTOSO-COM.Mail.Protection.Outlook.Com', 'contoso-com-v2.mail.protection.outlook.com.')
                })
            $expected = 'EXO-011|Pass|normalized=True|golive=True|reason=|evidence=EXO-011'

            # Act
            $result = Test-MtaStsControl -Evidence $published -DesiredState (New-DesiredTransportSecurityState)

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'everything a real domain reports back that is not drift has to survive at once: a media type carrying a charset parameter, policy keys in mixed case separated by carriage returns with a trailing blank line, a mode and a maximum age padded with whitespace, a wildcard MX pattern covering both published hosts, a host reported in mixed case, a second host reported with the trailing root label DNS actually returns, a discovery record whose tag and id are upper-cased and padded, and a TLS-RPT destination split across two character strings because the answer was longer than one - a comparison that read any of these as drift would fail a correctly configured domain, and the verdict has to be one normalized go-live-successful pass naming the record it was decided from rather than a bare true'
        }
    }
}
