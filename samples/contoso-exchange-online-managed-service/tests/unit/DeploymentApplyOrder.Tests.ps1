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

Describe 'SAFE-007-A2 the shipped deployment script applies in the one order an apply can be refused in' {

    Context 'Positive: the gate decides before the run connects and before every mutation the script carries' {

        It 'reports the shipped deployment script ordered with no finding' {
            # Arrange
            $expected = 'ordered'

            # Act
            $order = Test-BaselineDeploymentApplyOrder -ScriptPath $script:DeploymentScriptPath

            # Assert
            $(if ([bool]$order['Ordered']) { $expected } else { @($order['Finding']) -join ' ' }) |
                Should -BeExactly $expected -Because 'the gate is the only thing that can refuse an apply, and a gate reached after the credential is spent or after the first mutation lands can refuse nothing that has not already happened'
        }
    }
}
