#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph and ExchangeOnlineManagement are not installed and must never be imported.
    # Collection reaches the service only through the supplied seam, so every collection here is
    # a scriptblock that returns a canned payload or throws a canned failure.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:TransportConfigCollection = {
        [pscustomobject]@{
            Identity                         = 'contoso.onmicrosoft.com'
            SmtpClientAuthenticationDisabled = $true
            AcceptedDomain                   = @('contoso.com')
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
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EVD-001-A3 evidence collector' {

    Context 'Negative: the caller must name the control, the source, the command and the collection' {

        It 'refuses a collection with no control identifier' {
            # Arrange
            $noControl = $null

            # Act
            $result = { Get-BaselineEvidence -ControlId $noControl -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $script:TransportConfigCollection }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlIdRequired*' -Because 'a record that names no control can be counted against no control, so the control it was collected for would simply go unevaluated'
        }

        It 'refuses a collection whose control identifier is blank' {
            # Arrange
            $blankControl = '  '

            # Act
            $result = { Get-BaselineEvidence -ControlId $blankControl -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $script:TransportConfigCollection }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlIdRequired*' -Because 'whitespace names no control any more than nothing does'
        }

        It 'refuses a collection with no source' {
            # Arrange
            $noSource = $null

            # Act
            $result = { Get-BaselineEvidence -ControlId 'EXO-002' -Source $noSource -Command 'Get-TransportConfig' -Collection $script:TransportConfigCollection }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EvidenceSourceRequired*' -Because 'a reviewer who cannot tell whether a value came from Exchange Online or from Graph cannot reproduce the observation'
        }

        It 'refuses a collection whose source is blank' {
            # Arrange
            $blankSource = ' '

            # Act
            $result = { Get-BaselineEvidence -ControlId 'EXO-002' -Source $blankSource -Command 'Get-TransportConfig' -Collection $script:TransportConfigCollection }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EvidenceSourceRequired*' -Because 'a blank source is an unnamed source'
        }

        It 'refuses a collection with no command name' {
            # Arrange
            $noCommand = $null

            # Act
            $result = { Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command $noCommand -Collection $script:TransportConfigCollection }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EvidenceCommandRequired*' -Because 'evidence nobody can re-run is an assertion rather than an observation'
        }

        It 'refuses a collection whose command name is blank' {
            # Arrange
            $blankCommand = '   '

            # Act
            $result = { Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command $blankCommand -Collection $script:TransportConfigCollection }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EvidenceCommandRequired*' -Because 'a blank command name is an unnamed command'
        }

        It 'refuses a collection with nothing to run' {
            # Arrange
            $noCollection = $null

            # Act
            $result = { Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $noCollection }

            # Assert
            $result | Should -Throw -ExpectedMessage 'CollectionRequired*' -Because 'a collector with nothing to run would record a value it never observed'
        }
    }

    Context 'Negative: a collection that failed is recorded as a failure, never as an observation' {

        It 'does not report a collection that threw as a successful one' {
            # Arrange
            $refused = { throw 'AccessDenied: the connection is not authorized to run Get-TransportConfig.' }

            # Act
            $evidence = Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $refused

            # Assert
            $evidence.Collected | Should -BeFalse -Because 'a command that was refused observed nothing, and a record that claims otherwise lets an unobserved control read as compliant'
        }

        It 'does not record a collection that threw without naming its failure' {
            # Arrange
            $refused = { throw 'AccessDenied: the connection is not authorized to run Get-TransportConfig.' }

            # Act
            $evidence = Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $refused

            # Assert
            $evidence.FailureReason | Should -BeLike '*AccessDenied*not authorized*' -Because 'a failure nobody can explain cannot be distinguished from a transient one and will be retried forever or dismissed'
        }

        It 'does not record a collected value for a collection that threw' {
            # Arrange
            $refusedAfterOutput = {
                [pscustomobject]@{ SmtpClientAuthenticationDisabled = $true }
                throw 'AccessDenied: the connection is not authorized to run Get-TransportConfig.'
            }

            # Act
            $evidence = Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $refusedAfterOutput

            # Assert
            $evidence.Value | Should -BeNullOrEmpty -Because 'a partial result from a command that then failed is an incomplete view of the tenant, and a control decided on a partial view is decided on nothing'
        }

        It 'does not let a collection that threw abort the run' {
            # Arrange
            $refused = { throw 'AccessDenied: the connection is not authorized to run Get-TransportConfig.' }

            # Act
            $result = { Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $refused }

            # Assert
            $result | Should -Not -Throw -Because 'one refused command must cost one control, not discard every other control collected in the same run'
        }

        It 'does not report a collection that returned nothing as a failed one' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-BaselineEvidence -ControlId 'EXO-013' -Source 'ExchangeOnline' -Command 'Get-InboxRule' -Collection $empty

            # Assert
            $evidence.Collected | Should -BeTrue -Because 'a tenant that genuinely holds no forwarding rule is an observation a control can pass on, and folding it into failure would make the compliant tenant indistinguishable from the unreachable one'
        }
    }

    Context 'Negative: the payload is recorded as the service returned it' {

        It 'does not keep only the first item of a collection that returned many' {
            # Arrange
            $many = {
                [pscustomobject]@{ Name = 'Default'; PopEnabled = $false }
                [pscustomobject]@{ Name = 'ExchangeOnlineEnterprise'; PopEnabled = $true }
            }

            # Act
            $evidence = Get-BaselineEvidence -ControlId 'EXO-009' -Source 'ExchangeOnline' -Command 'Get-CASMailboxPlan' -Collection $many

            # Assert
            @($evidence.Value).Count | Should -Be 2 -Because 'a control that must hold for every mailbox plan cannot be decided from the first plan alone, and the plan that violates it is rarely the first'
        }

        It 'does not fold a single-item collection into a scalar' {
            # Arrange
            $single = { , @([pscustomobject]@{ Name = 'Default'; PopEnabled = $true }) }

            # Act
            $evidence = Get-BaselineEvidence -ControlId 'EXO-009' -Source 'ExchangeOnline' -Command 'Get-CASMailboxPlan' -Collection $single

            # Assert
            # The comma keeps the pipeline from unrolling the one-item collection before Should sees it,
            # so this asserts the shape the collector recorded rather than the shape the pipe produced.
            , $evidence.Value | Should -BeOfType ([System.Collections.IList]) -Because 'a tenant that happens to hold one plan today would otherwise change the shape of the evidence, and an evaluator written against a collection would silently stop working'
        }

        It 'does not admit a payload that already carries a control verdict' {
            # Arrange
            $deciding = { [pscustomobject]@{ Status = 'Pass'; Normalized = $true; GoLiveSuccess = $true; Reason = 'looks fine' } }

            # Act
            $result = { Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $deciding }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EvidenceCarriesVerdict*' -Because 'a collector that returns a verdict has already decided the control, and a decision nobody can re-derive from raw state is exactly what this separation removes'
        }
    }

    Context 'Negative: the record cannot be edited after it is collected' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $script:TransportConfigCollection

            # Act
            $act = { $evidence.Command = 'Get-OrganizationConfig' }

            # Assert
            $act | Should -Throw -Because 'a record whose command can be rewritten after the fact cannot prove which command produced the value beside it'
        }

        It 'returns a record whose payload rejects mutation' {
            # Arrange
            $evidence = Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $script:TransportConfigCollection

            # Act
            $act = { $evidence.Value.SmtpClientAuthenticationDisabled = $false }

            # Assert
            $act | Should -Throw -Because 'observed state that can be edited between collection and evaluation is not evidence of anything'
        }
    }

    Context 'Negative: collection happens once, through the seam, and nowhere else' {

        AfterEach {
            Remove-Item -Path 'function:global:Connect-ExchangeOnline', 'function:global:Get-TransportConfig', 'function:global:Connect-MgGraph', 'function:global:Get-MgSubscribedSku' -ErrorAction SilentlyContinue
        }

        It 'does not invoke the supplied collection more than once' {
            # Arrange
            $script:CollectionInvocation = 0
            $counting = { $script:CollectionInvocation++; [pscustomobject]@{ SmtpClientAuthenticationDisabled = $true } }

            # Act
            $null = Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $counting

            # Assert
            $script:CollectionInvocation | Should -Be 1 -Because 'a command run twice can return two different tenants, and the record would name a state that never existed at either moment'
        }

        It 'does not hand the supplied collection any argument' {
            # Arrange
            $script:CollectionArgument = $null
            $capturing = { $script:CollectionArgument = $args.Count; [pscustomobject]@{ SmtpClientAuthenticationDisabled = $true } }

            # Act
            $null = Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $capturing

            # Assert
            $script:CollectionArgument | Should -Be 0 -Because 'a collection handed a control identifier or a desired state is a collection that can shape what it returns to the answer the caller wanted'
        }

        It 'does not reach a live service command of its own' {
            # Arrange
            $script:CollectorCommandInvocation = [System.Collections.Generic.List[string]]::new()
            function global:Connect-ExchangeOnline { $script:CollectorCommandInvocation.Add('Connect-ExchangeOnline') }
            function global:Get-TransportConfig { $script:CollectorCommandInvocation.Add('Get-TransportConfig') }
            function global:Connect-MgGraph { $script:CollectorCommandInvocation.Add('Connect-MgGraph') }
            function global:Get-MgSubscribedSku { $script:CollectorCommandInvocation.Add('Get-MgSubscribedSku') }

            # Act
            $null = Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $script:TransportConfigCollection

            # Assert
            $script:CollectorCommandInvocation | Should -BeNullOrEmpty -Because 'a collector that connects or queries on its own reaches a tenant the caller never authorized and never sees'
        }
    }

    Context 'Positive: one collection yields one immutable raw record' {

        It 'returns exactly one immutable record naming its control, its source and its command and carrying the returned payload verbatim' {
            # Arrange
            $collection = $script:TransportConfigCollection

            # Act
            $evidence = @(Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $collection)

            # Assert
            '{0}|{1}' -f $evidence.Count, (Get-EvidenceFold -Evidence $evidence[0]) |
                Should -BeExactly ('1|EXO-002|ExchangeOnline|Get-TransportConfig|collected=True|failure=|{"AcceptedDomain":["contoso.com"],"Identity":"contoso.onmicrosoft.com","SmtpClientAuthenticationDisabled":true}|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value') `
                -Because 'evidence is only reviewable when one collection produces one record that names what was asked, of whom, and by which command, and carries back exactly what the service returned and nothing the collector decided'
        }
    }
}
