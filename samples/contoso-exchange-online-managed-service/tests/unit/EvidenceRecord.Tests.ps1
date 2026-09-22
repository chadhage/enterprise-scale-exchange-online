#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph and ExchangeOnlineManagement are not installed and must never be imported.
    # Every payload below is canned exactly as the service cmdlet named on the record would have
    # returned it, because collection is the only thing under test here.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # A representative raw payload: nested objects, a nested collection, and a member named Status
    # that belongs to the service object rather than to any verdict.
    function New-TransportConfigPayload {
        [CmdletBinding()]
        param()

        return [pscustomobject]@{
            Identity                       = 'contoso.onmicrosoft.com'
            SmtpClientAuthenticationDisabled = $true
            ExternalPostmasterAddress      = 'postmaster@contoso.com'
            Status                         = 'Healthy'
            Journaling                     = [pscustomobject]@{
                Recipient = 'journal@contoso.com'
                Enabled   = $false
            }
            AcceptedDomain                 = @('contoso.com', 'contoso.onmicrosoft.com')
        }
    }

    # An object that carries the three members a control result carries. Raw evidence that already
    # holds a verdict is not raw evidence; it is an evaluation that skipped the record.
    function New-VerdictShapedPayload {
        [CmdletBinding()]
        param()

        return [pscustomobject]@{
            ControlId     = 'EXO-002'
            Status        = 'Pass'
            Normalized    = $true
            GoLiveSuccess = $true
            Reason        = 'SMTP AUTH is disabled tenant-wide.'
        }
    }

    function Get-EvidenceFold {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Evidence
        )

        # Key order is not part of the record contract, so the member set is folded ordinally.
        $memberName = [string[]]@($Evidence.Keys)
        [System.Array]::Sort($memberName, [System.StringComparer]::Ordinal)
        $memberName = $memberName -join ','

        return '{0}|{1}|{2}|{3}|collected={4}|reason={5}|members={6}|payload={7}' -f `
            $Evidence.ControlId,
        $Evidence.Source,
        $Evidence.Command,
        $Evidence.CollectedAtUtc.ToString('o'),
        $Evidence.Collected,
        $(if ($null -eq $Evidence.FailureReason) { '<none>' } else { $Evidence.FailureReason }),
        $memberName,
        (ConvertTo-CanonicalJson -InputObject $Evidence.Value)
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EVD-001-A1 raw evidence collection record' {

    Context 'Negative: a record must name what was collected and how' {

        It 'refuses a record with no control identifier' {
            # Arrange
            $noControl = $null

            # Act
            $record = { New-BaselineEvidence -ControlId $noControl -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value (New-TransportConfigPayload) }

            # Assert
            $record | Should -Throw -ExpectedMessage 'ControlIdRequired*' -Because 'evidence that names no control cannot be matched to the control it is meant to decide'
        }

        It 'refuses a record whose control identifier is blank' {
            # Arrange
            $blankControl = '   '

            # Act
            $record = { New-BaselineEvidence -ControlId $blankControl -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value (New-TransportConfigPayload) }

            # Assert
            $record | Should -Throw -ExpectedMessage 'ControlIdRequired*' -Because 'whitespace names no control any more than nothing does'
        }

        It 'refuses a record with no source' {
            # Arrange
            $noSource = $null

            # Act
            $record = { New-BaselineEvidence -ControlId 'EXO-002' -Source $noSource -Command 'Get-TransportConfig' -Value (New-TransportConfigPayload) }

            # Assert
            $record | Should -Throw -ExpectedMessage 'EvidenceSourceRequired*' -Because 'evidence whose origin is unrecorded cannot be reproduced or challenged'
        }

        It 'refuses a record whose source is blank' {
            # Arrange
            $blankSource = ''

            # Act
            $record = { New-BaselineEvidence -ControlId 'EXO-002' -Source $blankSource -Command 'Get-TransportConfig' -Value (New-TransportConfigPayload) }

            # Assert
            $record | Should -Throw -ExpectedMessage 'EvidenceSourceRequired*' -Because 'an empty origin is an unrecorded origin'
        }

        It 'refuses a record with no collection command' {
            # Arrange
            $noCommand = $null

            # Act
            $record = { New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command $noCommand -Value (New-TransportConfigPayload) }

            # Assert
            $record | Should -Throw -ExpectedMessage 'EvidenceCommandRequired*' -Because 'the command that produced a payload is the only thing that makes the payload auditable'
        }

        It 'refuses a record whose collection command is blank' {
            # Arrange
            $blankCommand = '  '

            # Act
            $record = { New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command $blankCommand -Value (New-TransportConfigPayload) }

            # Assert
            $record | Should -Throw -ExpectedMessage 'EvidenceCommandRequired*' -Because 'whitespace records no command'
        }

        It 'refuses a record that was never given a collected value' {
            # Arrange
            $unsuppliedValue = @{ ControlId = 'EXO-002'; Source = 'ExchangeOnline'; Command = 'Get-TransportConfig' }

            # Act
            $record = { New-BaselineEvidence @unsuppliedValue }

            # Assert
            $record | Should -Throw -ExpectedMessage 'EvidenceValueRequired*' -Because 'a value that was never supplied cannot be told from a service that genuinely returned nothing'
        }

        It 'refuses a collection time that is not UTC' {
            # Arrange
            $localTime = [datetime]::new(2026, 9, 17, 9, 30, 0, [System.DateTimeKind]::Local)

            # Act
            $record = { New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value (New-TransportConfigPayload) -CollectedAtUtc $localTime }

            # Assert
            $record | Should -Throw -ExpectedMessage 'CollectionTimeNotUtc*' -Because 'evidence age decides a go-live, and an ambiguous clock makes age unknowable'
        }
    }

    Context 'Negative: a failed collection is never a silent one' {

        It 'does not report a failed collection as a successful one' {
            # Arrange
            $reason = 'Get-TransportConfig was refused: the connection is not authorized.'

            # Act
            $record = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value $null -Failed -FailureReason $reason

            # Assert
            $record.Collected | Should -BeFalse -Because 'a collection that failed must never be indistinguishable from one that returned nothing'
        }

        It 'refuses a failed collection that names no reason' {
            # Arrange
            $unexplained = @{ ControlId = 'EXO-002'; Source = 'ExchangeOnline'; Command = 'Get-TransportConfig'; Value = $null; Failed = $true }

            # Act
            $record = { New-BaselineEvidence @unexplained }

            # Assert
            $record | Should -Throw -ExpectedMessage 'FailureReasonRequired*' -Because 'an unexplained failure cannot be triaged and will be read as an empty result'
        }

        It 'refuses a successful collection that names a failure reason' {
            # Arrange
            $contradiction = @{ ControlId = 'EXO-002'; Source = 'ExchangeOnline'; Command = 'Get-TransportConfig'; Value = (New-TransportConfigPayload); FailureReason = 'Get-TransportConfig timed out.' }

            # Act
            $record = { New-BaselineEvidence @contradiction }

            # Assert
            $record | Should -Throw -ExpectedMessage 'FailureReasonUnexpected*' -Because 'a record that both succeeded and failed lets a reader pick the answer they prefer'
        }
    }

    Context 'Negative: raw evidence carries no verdict' {

        It 'refuses a control result as the collected value' {
            # Arrange
            $alreadyDecided = New-ControlResult -ControlId 'EXO-002' -Status 'Pass'

            # Act
            $record = { New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value $alreadyDecided }

            # Assert
            $record | Should -Throw -ExpectedMessage 'EvidenceCarriesVerdict*' -Because 'a collector that returns a decision has evaluated, which is exactly the mixing this card removes'
        }

        It 'refuses a collected value that carries a status, a normalized verdict and a go-live verdict' {
            # Arrange
            $verdictShaped = New-VerdictShapedPayload

            # Act
            $record = { New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value $verdictShaped }

            # Assert
            $record | Should -Throw -ExpectedMessage 'EvidenceCarriesVerdict*' -Because 'the verdict shape is refused on its members, so hand-building one evades nothing'
        }

        It 'refuses a collected collection whose element carries a verdict' {
            # Arrange
            $mixedPayload = @((New-TransportConfigPayload), (New-VerdictShapedPayload))

            # Act
            $record = { New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value $mixedPayload }

            # Assert
            $record | Should -Throw -ExpectedMessage 'EvidenceCarriesVerdict*' -Because 'a verdict smuggled into one element of a payload is still a verdict in the evidence'
        }

        It 'does not admit a payload member merely because the service named it Status' {
            # Arrange
            $servicePayload = New-TransportConfigPayload

            # Act
            $record = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value $servicePayload

            # Assert
            $record.Value.Status | Should -BeExactly 'Healthy' -Because 'Status is an ordinary member on real service objects, so the refusal must key on the whole verdict shape, not on one name'
        }
    }

    Context 'Negative: a record cannot be edited after it is taken' {

        It 'rejects assignment to an existing member' {
            # Arrange
            $record = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value (New-TransportConfigPayload)

            # Act
            $act = { $record.Source = 'Invented' }

            # Assert
            $act | Should -Throw -Because 'evidence an operator can rewrite after the fact proves nothing about the tenant'
        }

        It 'rejects assignment of a new member' {
            # Arrange
            $record = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value (New-TransportConfigPayload)

            # Act
            $act = { $record.Verdict = 'Pass' }

            # Assert
            $act | Should -Throw -Because 'a member added after collection is a claim the collector never made'
        }

        It 'rejects assignment to the collected value' {
            # Arrange
            $record = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value (New-TransportConfigPayload)

            # Act
            $act = { $record.Value = 'replaced' }

            # Assert
            $act | Should -Throw -Because 'the payload is the evidence, so replacing it wholesale is the cheapest possible forgery'
        }

        It 'rejects assignment to a nested payload member' {
            # Arrange
            $record = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value (New-TransportConfigPayload)

            # Act
            $act = { $record.Value.SmtpClientAuthenticationDisabled = $false }

            # Assert
            $act | Should -Throw -Because 'freezing only the envelope leaves the observed state editable, which is the state that decides the control'
        }

        It 'rejects assignment to a member nested two levels inside the payload' {
            # Arrange
            $record = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value (New-TransportConfigPayload)

            # Act
            $act = { $record.Value.Journaling.Enabled = $true }

            # Assert
            $act | Should -Throw -Because 'immutability that stops at the first level is not immutability'
        }

        It 'rejects assignment to a nested collection element' {
            # Arrange
            $record = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value (New-TransportConfigPayload)

            # Act
            $act = { $record.Value.AcceptedDomain[0] = 'attacker.example' }

            # Assert
            $act | Should -Throw -Because 'a collection whose elements can be swapped records whatever the last writer wanted'
        }

        It 'does not hand back the mutable payload instance the collector returned' {
            # Arrange
            $payload = New-TransportConfigPayload

            # Act
            $record = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value $payload

            # Assert
            [object]::ReferenceEquals($record.Value, $payload) | Should -BeFalse -Because 'sharing the instance leaves the caller holding a live handle onto frozen evidence'
        }
    }

    Context 'Negative: the payload is recorded as it was returned' {

        It 'does not fold a single-element payload into a scalar' {
            # Arrange
            $singleElement = @((New-TransportConfigPayload))

            # Act
            $record = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value $singleElement

            # Assert
            $record.Value.Count | Should -Be 1 -Because 'a tenant holding exactly one connector must not be recorded as a tenant holding a connector-shaped object'
        }

        It 'does not discard a payload the service returned as empty' {
            # Arrange
            $emptyResult = @()

            # Act
            $record = New-BaselineEvidence -ControlId 'PP-005' -Source 'ExchangeOnline' -Command 'Get-InboundConnector' -Value $emptyResult

            # Assert
            $record.Collected | Should -BeTrue -Because 'an empty result is a successful observation of absence, which is precisely what PP-005 needs'
        }
    }

    Context 'Negative: collection records what it was handed and reaches nothing' {

        # The stubs are global, so cleanup must survive an Act that throws; otherwise a failing run
        # leaks them into the session and every later test resolves them instead of failing.
        AfterEach {
            Remove-Item -Path 'function:global:Connect-ExchangeOnline', 'function:global:Get-TransportConfig', 'function:global:Connect-MgGraph', 'function:global:Get-MgSubscribedSku' -ErrorAction SilentlyContinue
        }

        It 'records the payload it was handed without collecting any of its own' {
            # Arrange
            $script:EvidenceCommandInvocation = [System.Collections.Generic.List[string]]::new()
            function global:Connect-ExchangeOnline { $script:EvidenceCommandInvocation.Add('Connect-ExchangeOnline') }
            function global:Get-TransportConfig { $script:EvidenceCommandInvocation.Add('Get-TransportConfig') }
            function global:Connect-MgGraph { $script:EvidenceCommandInvocation.Add('Connect-MgGraph') }
            function global:Get-MgSubscribedSku { $script:EvidenceCommandInvocation.Add('Get-MgSubscribedSku') }

            # Act
            $null = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value (New-TransportConfigPayload)

            # Assert
            $script:EvidenceCommandInvocation | Should -BeNullOrEmpty -Because 'the record names the command that was run elsewhere; running it here would make the record its own witness'
        }
    }

    Context 'Positive: a collected payload becomes one immutable, verdict-free record' {

        It 'names its control, source, command and collection time and carries the payload verbatim' {
            # Arrange
            $collectedAt = [datetime]::new(2026, 9, 17, 4, 5, 6, [System.DateTimeKind]::Utc)
            $payload = New-TransportConfigPayload
            $expectedPayloadText = ConvertTo-CanonicalJson -InputObject $payload

            # Act
            $record = New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value $payload -CollectedAtUtc $collectedAt

            # Assert
            Get-EvidenceFold -Evidence $record |
                Should -BeExactly ("EXO-002|ExchangeOnline|Get-TransportConfig|2026-09-17T04:05:06.0000000Z|collected=True|reason=<none>|" +
                    "members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value|payload=$expectedPayloadText") -Because 'a raw evidence record is exactly the payload, the control it belongs to, and how and when it was obtained, and nothing that resembles a decision'
        }
    }
}
