#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:DeploymentScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-007-A3 the shipped deployment script changes the tenant only under a plan it can account for' {

    Context 'Positive: every mutation the script can reach is declared, captured, journalled, reversible and evidenced' {

        It 'reports the shipped deployment script planned with no finding' {
            # Arrange
            $expected = 'planned'

            # Act
            $plan = Test-BaselineDeploymentMutationPlan -ScriptPath $script:DeploymentScriptPath

            # Assert
            $(if ([bool]$plan['Planned']) { $expected } else { @($plan['Finding']) -join ' ' }) |
                Should -BeExactly $expected -Because 'a mutation the plan never declared is applied outside the change that was approved, a mutation whose prior state nobody captured cannot be put back, and a run that leaves no pre-change, apply, rollback and post-change record has changed a tenant nobody can audit or reverse'
        }
    }
}
