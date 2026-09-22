#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph and ExchangeOnlineManagement are not installed and must never be imported.
    # Evaluation is a pure decision over a record that was collected elsewhere, so every record
    # here is built by the shipped collector from a canned payload.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-TransportConfigEvidence {
        [CmdletBinding()]
        param(
            [string]$ControlId = 'EXO-002',
            [bool]$SmtpClientAuthenticationDisabled = $true,
            [switch]$Failed
        )

        if ($Failed) {
            return New-BaselineEvidence -ControlId $ControlId -Source 'ExchangeOnline' -Command 'Get-TransportConfig' `
                -Value $null -Failed -FailureReason 'Get-TransportConfig was refused: the connection is not authorized.' `
                -CollectedAtUtc ([datetime]::new(2026, 9, 17, 4, 5, 6, [System.DateTimeKind]::Utc))
        }

        $payload = [pscustomobject]@{
            Identity                         = 'contoso.onmicrosoft.com'
            SmtpClientAuthenticationDisabled = $SmtpClientAuthenticationDisabled
            AcceptedDomain                   = @('contoso.com')
        }

        return New-BaselineEvidence -ControlId $ControlId -Source 'ExchangeOnline' -Command 'Get-TransportConfig' `
            -Value $payload -CollectedAtUtc ([datetime]::new(2026, 9, 17, 4, 5, 6, [System.DateTimeKind]::Utc))
    }

    # The shipped evaluator shape: one verdict over the record it was handed, and nothing else.
    $script:SmtpAuthEvaluator = {
        param($Evidence)

        if ($Evidence.Value.SmtpClientAuthenticationDisabled) {
            [pscustomobject]@{ Status = 'Pass'; Reason = 'SMTP AUTH is disabled tenant-wide.' }
        }
        else {
            [pscustomobject]@{ Status = 'Fail'; Reason = 'SMTP AUTH is enabled tenant-wide.' }
        }
    }

    function Get-ResultFold {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Result
        )

        $memberName = [string[]]@($Result.Keys)
        [System.Array]::Sort($memberName, [System.StringComparer]::Ordinal)

        return '{0}|{1}|normalized={2}|golive={3}|{4}|evidence={5}:{6}|members={7}' -f `
            $Result.ControlId,
        $Result.Status,
        $Result.Normalized,
        $Result.GoLiveSuccess,
        $Result.Reason,
        $Result.Evidence.Command,
        (ConvertTo-CanonicalJson -InputObject $Result.Evidence.Value),
        ($memberName -join ',')
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EVD-001-A2 normalized control evaluation result' {

    Context 'Negative: the caller must supply a control, a record and an evaluator' {

        It 'refuses an evaluation with no control identifier' {
            # Arrange
            $noControl = $null

            # Act
            $result = { Test-BaselineControl -ControlId $noControl -Evidence (New-TransportConfigEvidence) -Evaluator $script:SmtpAuthEvaluator }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlIdRequired*' -Because 'a verdict that names no control cannot be counted against the catalog'
        }

        It 'refuses an evaluation whose control identifier is blank' {
            # Arrange
            $blankControl = '  '

            # Act
            $result = { Test-BaselineControl -ControlId $blankControl -Evidence (New-TransportConfigEvidence) -Evaluator $script:SmtpAuthEvaluator }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlIdRequired*' -Because 'whitespace names no control any more than nothing does'
        }

        It 'refuses an evaluation with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $result = { Test-BaselineControl -ControlId 'EXO-002' -Evidence $noEvidence -Evaluator $script:SmtpAuthEvaluator }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EvidenceRequired*' -Because 'an evaluator with no record would have to collect its own, which is the mixing this card removes'
        }

        It 'refuses evidence that is not a baseline evidence record' {
            # Arrange
            $rawPayload = [pscustomobject]@{ SmtpClientAuthenticationDisabled = $true }

            # Act
            $result = { Test-BaselineControl -ControlId 'EXO-002' -Evidence $rawPayload -Evaluator $script:SmtpAuthEvaluator }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EvidenceNotRecognized*' -Because 'a bare payload carries no source, no command and no collection time, so a verdict over it is unauditable'
        }

        It 'refuses an evidence record that does not declare whether collection succeeded' {
            # Arrange
            $incomplete = [pscustomobject]@{
                ControlId      = 'EXO-002'
                Source         = 'ExchangeOnline'
                Command        = 'Get-TransportConfig'
                Value          = [pscustomobject]@{ SmtpClientAuthenticationDisabled = $true }
                CollectedAtUtc = [datetime]::new(2026, 9, 17, 4, 5, 6, [System.DateTimeKind]::Utc)
            }

            # Act
            $result = { Test-BaselineControl -ControlId 'EXO-002' -Evidence $incomplete -Evaluator $script:SmtpAuthEvaluator }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EvidenceNotRecognized*' -Because 'a record that never says whether it was collected lets a failed collection be read as an empty one'
        }

        It 'refuses an evaluation with no evaluator' {
            # Arrange
            $noEvaluator = $null

            # Act
            $result = { Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence) -Evaluator $noEvaluator }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EvaluatorRequired*' -Because 'without an evaluator there is no decision to normalize'
        }

        It 'refuses evidence that was collected for a different control' {
            # Arrange
            $otherControl = New-TransportConfigEvidence -ControlId 'EXO-005'

            # Act
            $result = { Test-BaselineControl -ControlId 'EXO-002' -Evidence $otherControl -Evaluator $script:SmtpAuthEvaluator }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EvidenceControlMismatch*EXO-002*EXO-005*' -Because 'deciding one control on another control''s record is how a green board comes to mean nothing'
        }
    }

    Context 'Negative: a misbehaving evaluator is an error, never a pass' {

        It 'does not pass a control whose evaluator returned no verdict' {
            # Arrange
            $silent = { param($Evidence) }

            # Act
            $result = Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence) -Evaluator $silent

            # Assert
            '{0}:{1}:{2}' -f $result.Status, $result.GoLiveSuccess, $result.Reason |
                Should -BeLike 'Error:False:*EvaluatorReturnedNoVerdict*' -Because 'silence is not agreement, and a control nobody decided must never clear a go-live'
        }

        It 'does not pass a control whose evaluator returned more than one verdict' {
            # Arrange
            $indecisive = {
                param($Evidence)
                [pscustomobject]@{ Status = 'Pass'; Reason = 'first' }
                [pscustomobject]@{ Status = 'Fail'; Reason = 'second' }
            }

            # Act
            $result = Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence) -Evaluator $indecisive

            # Assert
            '{0}:{1}:{2}' -f $result.Status, $result.GoLiveSuccess, $result.Reason |
                Should -BeLike 'Error:False:*EvaluatorReturnedMultipleVerdicts*' -Because 'two verdicts mean nobody knows which one the control holds, and picking the first would silently prefer the kinder one'
        }

        It 'does not pass a control whose evaluator returned a verdict with no status' {
            # Arrange
            $statusless = { param($Evidence) [pscustomobject]@{ Reason = 'looks fine' } }

            # Act
            $result = Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence) -Evaluator $statusless

            # Assert
            '{0}:{1}:{2}' -f $result.Status, $result.GoLiveSuccess, $result.Reason |
                Should -BeLike 'Error:False:*EvaluatorVerdictMissingStatus*' -Because 'a verdict with no status is prose, and prose cannot gate a deployment'
        }

        It 'does not pass a control whose evaluator returned a status the result contract does not declare' {
            # Arrange
            $invented = { param($Evidence) [pscustomobject]@{ Status = 'ProbablyFine'; Reason = 'invented status' } }

            # Act
            $result = Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence) -Evaluator $invented

            # Assert
            '{0}:{1}:{2}' -f $result.Status, $result.GoLiveSuccess, $result.Reason |
                Should -BeLike 'Error:False:*ProbablyFine*' -Because 'an undeclared status would be counted by no gate at all and would therefore never block anything'
        }

        It 'does not pass a control whose evaluator returned a failing status with no reason' {
            # Arrange
            $unexplained = { param($Evidence) [pscustomobject]@{ Status = 'Fail' } }

            # Act
            $result = Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence) -Evaluator $unexplained

            # Assert
            '{0}:{1}:{2}' -f $result.Status, $result.GoLiveSuccess, $result.Reason |
                Should -BeLike 'Error:False:*EvaluatorReasonMissing*' -Because 'a failure nobody can explain cannot be remediated and will be dismissed as noise'
        }

        It 'does not accept a verdict that names a different control' {
            # Arrange
            $misattributed = { param($Evidence) [pscustomobject]@{ ControlId = 'EXO-005'; Status = 'Pass'; Reason = 'wrong control' } }

            # Act
            $result = Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence) -Evaluator $misattributed

            # Assert
            '{0}:{1}:{2}' -f $result.Status, $result.GoLiveSuccess, $result.Reason |
                Should -BeLike 'Error:False:*EvaluatorControlMismatch*EXO-005*' -Because 'a verdict filed against the wrong control leaves the right one unevaluated and the wrong one falsely green'
        }

        It 'does not pass a control whose evaluator threw' {
            # Arrange
            $broken = { param($Evidence) throw 'NullReferenceInEvaluator: the payload member was absent.' }

            # Act
            $result = Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence) -Evaluator $broken

            # Assert
            '{0}:{1}:{2}' -f $result.Status, $result.GoLiveSuccess, $result.Reason |
                Should -BeLike 'Error:False:*NullReferenceInEvaluator*' -Because 'an evaluator that crashed proved nothing, and its crash must be reported rather than swallowed'
        }

        It 'does not let a broken evaluator abort the evaluation of every other control' {
            # Arrange
            $broken = { param($Evidence) throw 'NullReferenceInEvaluator: the payload member was absent.' }

            # Act
            $result = { Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence) -Evaluator $broken }

            # Assert
            $result | Should -Not -Throw -Because 'one defective evaluator must degrade one control, not discard the whole evidence run'
        }
    }

    Context 'Negative: a failed collection can never be decided' {

        It 'does not pass a control whose evidence failed to collect' {
            # Arrange
            $uncollected = New-TransportConfigEvidence -Failed

            # Act
            $result = Test-BaselineControl -ControlId 'EXO-002' -Evidence $uncollected -Evaluator $script:SmtpAuthEvaluator

            # Assert
            '{0}:{1}:{2}' -f $result.Status, $result.GoLiveSuccess, $result.Reason |
                Should -BeLike 'Error:False:*not authorized*' -Because 'a control whose state was never observed is unknown, and unknown must fail closed rather than read as compliant'
        }

        It 'does not run the evaluator over a record whose collection failed' {
            # Arrange
            $script:EvaluatorInvocation = 0
            $counting = { param($Evidence) $script:EvaluatorInvocation++; [pscustomobject]@{ Status = 'Pass' } }

            # Act
            $null = Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence -Failed) -Evaluator $counting

            # Assert
            $script:EvaluatorInvocation | Should -Be 0 -Because 'handing a null payload to an evaluator invites it to decide on absence, which is how a failed collection becomes a pass'
        }
    }

    Context 'Negative: a result cannot be edited and must carry what decided it' {

        It 'rejects assignment to the status' {
            # Arrange
            $result = Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence) -Evaluator $script:SmtpAuthEvaluator

            # Act
            $act = { $result.Status = 'Pass' }

            # Assert
            $act | Should -Throw -Because 'a verdict an operator can overwrite is an opinion, not evidence'
        }

        It 'rejects assignment to the reason' {
            # Arrange
            $result = Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence -SmtpClientAuthenticationDisabled $false) -Evaluator $script:SmtpAuthEvaluator

            # Act
            $act = { $result.Reason = 'nothing to see here' }

            # Assert
            $act | Should -Throw -Because 'rewriting why a control failed is how a failure is made to look like an accepted risk'
        }

        It 'does not return a result that omits the evidence it was decided from' {
            # Arrange
            $evidence = New-TransportConfigEvidence

            # Act
            $result = Test-BaselineControl -ControlId 'EXO-002' -Evidence $evidence -Evaluator $script:SmtpAuthEvaluator

            # Assert
            $result.Evidence.Command | Should -BeExactly 'Get-TransportConfig' -Because 'a verdict that does not carry its record cannot be re-examined by anyone who did not run the collection'
        }

        It 'does not carry the evidence back in a mutable form' {
            # Arrange
            $result = Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence) -Evaluator $script:SmtpAuthEvaluator

            # Act
            $act = { $result.Evidence.Value.SmtpClientAuthenticationDisabled = $false }

            # Assert
            $act | Should -Throw -Because 'evidence that thaws on its way into a result is evidence that can be edited after the verdict'
        }
    }

    Context 'Negative: evaluation decides on the record alone and reaches nothing' {

        AfterEach {
            Remove-Item -Path 'function:global:Connect-ExchangeOnline', 'function:global:Get-TransportConfig', 'function:global:Connect-MgGraph', 'function:global:Get-MgSubscribedSku' -ErrorAction SilentlyContinue
        }

        It 'hands the evaluator the evidence record and nothing else' {
            # Arrange
            $script:EvaluatorArgument = $null
            $capturing = { param($Evidence) $script:EvaluatorArgument = $args.Count; [pscustomobject]@{ Status = 'Pass' } }

            # Act
            $null = Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence) -Evaluator $capturing

            # Assert
            $script:EvaluatorArgument | Should -Be 0 -Because 'an evaluator handed a connection, a seam or a credential is an evaluator that can collect, and one that can collect will'
        }

        It 'decides the control without reaching any live service command' {
            # Arrange
            $script:EvaluationCommandInvocation = [System.Collections.Generic.List[string]]::new()
            function global:Connect-ExchangeOnline { $script:EvaluationCommandInvocation.Add('Connect-ExchangeOnline') }
            function global:Get-TransportConfig { $script:EvaluationCommandInvocation.Add('Get-TransportConfig') }
            function global:Connect-MgGraph { $script:EvaluationCommandInvocation.Add('Connect-MgGraph') }
            function global:Get-MgSubscribedSku { $script:EvaluationCommandInvocation.Add('Get-MgSubscribedSku') }

            # Act
            $null = Test-BaselineControl -ControlId 'EXO-002' -Evidence (New-TransportConfigEvidence) -Evaluator $script:SmtpAuthEvaluator

            # Assert
            $script:EvaluationCommandInvocation | Should -BeNullOrEmpty -Because 'evaluation is a decision over a record that was already collected, so a live call here would be a second, unrecorded collection'
        }
    }

    Context 'Positive: one record and one evaluator yield one normalized result' {

        It 'returns exactly one normalized control result naming the control, its status, its reason and the evidence it was decided from' {
            # Arrange
            $evidence = New-TransportConfigEvidence

            # Act
            $result = @(Test-BaselineControl -ControlId 'EXO-002' -Evidence $evidence -Evaluator $script:SmtpAuthEvaluator)

            # Assert
            '{0}|{1}' -f $result.Count, (Get-ResultFold -Result $result[0]) |
                Should -BeExactly ('1|EXO-002|Pass|normalized=True|golive=True|SMTP AUTH is disabled tenant-wide.|evidence=Get-TransportConfig:{"AcceptedDomain":["contoso.com"],"Identity":"contoso.onmicrosoft.com","SmtpClientAuthenticationDisabled":true}|members=ControlId,EvaluatedAtUtc,Evidence,GoLiveSuccess,Normalized,Reason,Status') `
                -Because 'a control evaluation is only usable downstream when one record and one evaluator produce one result that names the control, normalizes its status, explains it, and carries the record it was decided from verbatim'
        }
    }
}
