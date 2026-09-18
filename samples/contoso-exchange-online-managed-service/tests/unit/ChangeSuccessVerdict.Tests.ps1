#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ChangeId = 'CHG0044556'
    $script:PostChangeEvidence = 'postchange-CHG0044556.json'

    function New-Step {
        param(
            [string]$Id,
            [string]$State = 'Succeeded',
            [string]$Fault = '',
            [string[]]$DependsOn = @()
        )

        return [pscustomobject]@{
            Id        = $Id
            Command   = 'Set-RemoteDomain'
            Identity  = 'Fabrikam'
            State     = $State
            Fault     = $Fault
            DependsOn = @($DependsOn)
        }
    }

    function New-Application {
        param([object[]]$Step)

        $plan = @($Step | ForEach-Object {
                [ordered]@{ OperationId = $_.Id; Command = $_.Command; Identity = $_.Identity; DependsOn = @($_.DependsOn) }
            })

        $journal = New-BaselineMutationJournal -Operation @($Step | ForEach-Object {
                [ordered]@{ OperationId = $_.Id; Command = $_.Command; Identity = $_.Identity; State = $_.State; Fault = $_.Fault }
            })

        return Resolve-BaselinePartialApplication -ChangeId $script:ChangeId -Operation $plan -Journal $journal
    }

    # Every declared mutation landed - the only run a success verdict may admit.
    function New-CleanApplication {
        return New-Application -Step @(
            (New-Step -Id 'op-1')
            (New-Step -Id 'op-2' -DependsOn @('op-1'))
        )
    }

    function New-PostChange {
        param(
            [bool]$Permitted = $true,
            [string[]]$Finding = @(),
            [string]$Evidence = $script:PostChangeEvidence
        )

        return [ordered]@{
            Permitted = $Permitted
            Finding   = @($Finding)
            Evidence  = $Evidence
        }
    }

    function Format-Refusal {
        param([object]$Verdict, [string]$Prefix)

        return '{0}|{1}' -f $Verdict['Successful'], [bool](@($Verdict['Finding']) | Where-Object { $_ -like "$Prefix*" })
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-006-A2 change success verdict' {

    Context 'Negative: the run the verdict was asked about is not one it can read' {

        It 'refuses a verdict asked for without a partial-application record' {
            # Arrange
            $postChange = New-PostChange

            # Act
            $act = { Test-BaselineChangeSuccess -Application $null -PostChange $postChange }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeSuccessApplicationNotSupplied*' -Because 'a verdict decided from no record of what the run did is a verdict about nothing'
        }
    }

    Context 'Negative: a run that did not finish is still reported successful' {

        It 'does not report a run carrying a failed operation successful' {
            # Arrange
            $application = New-Application -Step @(
                (New-Step -Id 'op-1')
                (New-Step -Id 'op-2' -State 'Failed' -Fault 'RemoteDomainNotFound' -DependsOn @('op-1'))
            )

            # Act
            $verdict = Test-BaselineChangeSuccess -Application $application -PostChange (New-PostChange)

            # Assert
            (Format-Refusal -Verdict $verdict -Prefix 'ChangeOperationFailed') |
                Should -BeExactly 'False|True' -Because 'a run that reports success while one of its mutations threw hands the operator a tenant nobody configured'
        }

        It 'does not report a run carrying a halted operation successful' {
            # Arrange
            $application = New-Application -Step @(
                (New-Step -Id 'op-1' -State 'Failed' -Fault 'RemoteDomainNotFound')
                (New-Step -Id 'op-2' -State 'Pending' -DependsOn @('op-1'))
            )

            # Act
            $verdict = Test-BaselineChangeSuccess -Application $application -PostChange (New-PostChange)

            # Assert
            (Format-Refusal -Verdict $verdict -Prefix 'ChangeOperationHalted') |
                Should -BeExactly 'False|True' -Because 'an operation stopped behind a failure is a change the baseline still owes, and a success verdict closes the change with it unmade'
        }

        It 'does not report a run carrying an outstanding operation successful' {
            # Arrange
            $application = New-Application -Step @(
                (New-Step -Id 'op-1')
                (New-Step -Id 'op-2' -State 'Pending')
            )

            # Act
            $verdict = Test-BaselineChangeSuccess -Application $application -PostChange (New-PostChange)

            # Assert
            (Format-Refusal -Verdict $verdict -Prefix 'ChangeOperationOutstanding') |
                Should -BeExactly 'False|True' -Because 'a mutation the run never reached is not a mutation that succeeded, and only the record separates the two'
        }
    }

    Context 'Negative: the post-change evidence never admitted the run' {

        It 'does not report a run whose post-change decision refused successful' {
            # Arrange
            $postChange = New-PostChange -Permitted $false -Finding @('ControlNotPassed: MDO-003 was decided Fail.')

            # Act
            $verdict = Test-BaselineChangeSuccess -Application (New-CleanApplication) -PostChange $postChange

            # Assert
            (Format-Refusal -Verdict $verdict -Prefix 'PostChangeRefused') |
                Should -BeExactly 'False|True' -Because 'every mutation returning is not the same as the tenant ending up compliant, and only the post-change decision can tell them apart'
        }

        It 'does not report a run handed no post-change decision successful' {
            # Arrange
            $application = New-CleanApplication

            # Act
            $verdict = Test-BaselineChangeSuccess -Application $application -PostChange $null

            # Assert
            (Format-Refusal -Verdict $verdict -Prefix 'PostChangeDecisionNotSupplied') |
                Should -BeExactly 'False|True' -Because 'a run that reports success before anything looked at the tenant afterwards is reporting its own intentions'
        }

        It 'does not treat a post-change decision that decided nothing as one that passed' {
            # Arrange
            $postChange = [ordered]@{ Finding = @(); Evidence = $script:PostChangeEvidence }

            # Act
            $verdict = Test-BaselineChangeSuccess -Application (New-CleanApplication) -PostChange $postChange

            # Assert
            (Format-Refusal -Verdict $verdict -Prefix 'PostChangeDecidedNothing') |
                Should -BeExactly 'False|True' -Because 'a decision that reached no conclusion is silence, and reading silence as consent is how a failed verification becomes a successful change'
        }

        It 'does not report a run whose post-change decision names no evidence successful' {
            # Arrange
            $postChange = New-PostChange -Evidence '   '

            # Act
            $verdict = Test-BaselineChangeSuccess -Application (New-CleanApplication) -PostChange $postChange

            # Assert
            (Format-Refusal -Verdict $verdict -Prefix 'PostChangeEvidenceNotNamed') |
                Should -BeExactly 'False|True' -Because 'a decision nobody can trace back to the observations behind it is an assertion, and an audit cannot re-decide it'
        }
    }

    Context 'Negative: the refusal does not say everything it refused on' {

        It 'does not omit any reason a run was refused' {
            # Arrange
            $application = New-Application -Step @(
                (New-Step -Id 'op-1' -State 'Failed' -Fault 'RemoteDomainNotFound')
                (New-Step -Id 'op-2' -State 'Pending' -DependsOn @('op-1'))
                (New-Step -Id 'op-3' -State 'Pending')
            )
            $postChange = New-PostChange -Permitted $false -Finding @('ControlNotPassed: MDO-003 was decided Fail.')

            # Act
            $verdict = Test-BaselineChangeSuccess -Application $application -PostChange $postChange

            # Assert
            (@('ChangeOperationFailed', 'ChangeOperationHalted', 'ChangeOperationOutstanding', 'PostChangeRefused') |
                    ForEach-Object { $prefix = $_; [bool](@($verdict['Finding']) | Where-Object { $_ -like "$prefix*" }) }) -join ',' |
                Should -BeExactly 'True,True,True,True' -Because 'an operator handed one blocker at a time has to rerun the whole change to learn what else was already wrong'
        }

        It 'does not admit a verdict a caller can edit after the fact' {
            # Arrange
            $verdict = Test-BaselineChangeSuccess -Application (New-CleanApplication) -PostChange (New-PostChange)

            # Act
            $act = { $verdict['Successful'] = $true }

            # Assert
            $act | Should -Throw -Because 'a verdict a caller can rewrite is a verdict nobody decided'
        }
    }

    Context 'Positive: a run whose every mutation landed and whose post-change evidence admitted it' {

        It 'reports success and names the post-change evidence it was decided from' {
            # Arrange
            $application = New-CleanApplication

            # Act
            $verdict = Test-BaselineChangeSuccess -Application $application -PostChange (New-PostChange)

            # Assert
            '{0}|{1}|{2}|{3}' -f $verdict['Successful'], $verdict['ChangeId'], $verdict['PostChangeEvidence'], @($verdict['Finding']).Count |
                Should -BeExactly "True|$script:ChangeId|$script:PostChangeEvidence|0" -Because 'the only run that may be called successful is one where every declared mutation landed and the tenant was observed afterwards to have accepted them'
        }
    }
}
