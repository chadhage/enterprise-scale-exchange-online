#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:EvidenceScript = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'

    function Import-RegistryExecutionFunction {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:EvidenceScript, [ref]$tokens, [ref]$errors)
        $definition = @($ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq 'Invoke-BaselineControlRegistryExecution'
                }, $true))

        if ($definition.Count -ne 1) {
            throw "RegistryExecutionEngineMissing: expected one Invoke-BaselineControlRegistryExecution definition and found $($definition.Count)."
        }

        Set-Item -Path 'Function:\global:Invoke-BaselineControlRegistryExecution' -Value $definition[0].Body.GetScriptBlock()
    }

    function New-RegistryEntry {
        param(
            [string]$ControlId = 'EXO-001',
            [string]$Collector = 'Get-SyntheticEvidence',
            [string]$Evaluator = 'Test-SyntheticControl'
        )

        [pscustomobject]@{
            ControlId = $ControlId
            Collector = $Collector
            Evaluator = $Evaluator
        }
    }

    function Invoke-RegistryExecutionSubject {
        param(
            [AllowNull()]
            [object[]]$Registry,
            [string[]]$ExpectedControlId = @('EXO-001'),
            [scriptblock]$CommandResolver = { param($Name) { $Name } },
            [scriptblock]$CollectorArgumentResolver = { param($Entry) @{} },
            [scriptblock]$EvaluatorArgumentResolver = { param($Entry, $Evidence) @{ Evidence = $Evidence } }
        )

        Import-RegistryExecutionFunction
        Invoke-BaselineControlRegistryExecution -Registry $Registry -ExpectedControlId $ExpectedControlId `
            -CommandResolver $CommandResolver -CollectorArgumentResolver $CollectorArgumentResolver `
            -EvaluatorArgumentResolver $EvaluatorArgumentResolver
    }
}

AfterAll {
    Remove-Item -Path 'Function:\global:Invoke-BaselineControlRegistryExecution' -ErrorAction SilentlyContinue
}

Describe 'EVD-007 complete control registry execution engine' {
    Context 'Negative: the applicable registry must be complete and unambiguous before execution' {
        It 'refuses an empty applicable registry' {
            # Arrange
            $registry = @()

            # Act
            $result = { Invoke-RegistryExecutionSubject -Registry $registry }

            # Assert
            $result | Should -Throw -ExpectedMessage 'RegistryExecutionRegistryRequired*'
        }

        It 'refuses an applicable control missing from the registry' {
            # Arrange
            $registry = @(New-RegistryEntry -ControlId 'EXO-001')
            $expected = @('EXO-001', 'EXO-002')

            # Act
            $result = { Invoke-RegistryExecutionSubject -Registry $registry -ExpectedControlId $expected }

            # Assert
            $result | Should -Throw -ExpectedMessage 'RegistryExecutionControlMissing*EXO-002*'
        }

        It 'refuses a control registered more than once' {
            # Arrange
            $registry = @(
                (New-RegistryEntry -ControlId 'EXO-001')
                (New-RegistryEntry -ControlId 'EXO-001')
            )

            # Act
            $result = { Invoke-RegistryExecutionSubject -Registry $registry }

            # Assert
            $result | Should -Throw -ExpectedMessage 'RegistryExecutionControlDuplicated*EXO-001*'
        }

        It 'refuses a registry control outside the applicable control set' {
            # Arrange
            $registry = @(
                (New-RegistryEntry -ControlId 'EXO-001')
                (New-RegistryEntry -ControlId 'EXO-999')
            )

            # Act
            $result = { Invoke-RegistryExecutionSubject -Registry $registry }

            # Assert
            $result | Should -Throw -ExpectedMessage 'RegistryExecutionControlUnknown*EXO-999*'
        }
    }

    Context 'Negative: every declared collector and evaluator must resolve before execution' {
        It 'refuses an unresolved registered collector without invoking any command' {
            # Arrange
            $script:invocationCount = 0
            $registry = @(New-RegistryEntry -Collector 'Get-MissingEvidence')
            $resolver = {
                param($Name)
                if ($Name -ceq 'Get-MissingEvidence') { return $null }
                { $script:invocationCount++ }
            }

            # Act
            $result = { Invoke-RegistryExecutionSubject -Registry $registry -CommandResolver $resolver }

            # Assert
            $result | Should -Throw -ExpectedMessage 'RegistryExecutionCollectorUnresolved*EXO-001*Get-MissingEvidence*'
            $script:invocationCount | Should -Be 0
        }

        It 'refuses an unresolved registered evaluator without invoking any command' {
            # Arrange
            $script:invocationCount = 0
            $registry = @(New-RegistryEntry -Evaluator 'Test-MissingControl')
            $resolver = {
                param($Name)
                if ($Name -ceq 'Test-MissingControl') { return $null }
                { $script:invocationCount++ }
            }

            # Act
            $result = { Invoke-RegistryExecutionSubject -Registry $registry -CommandResolver $resolver }

            # Assert
            $result | Should -Throw -ExpectedMessage 'RegistryExecutionEvaluatorUnresolved*EXO-001*Test-MissingControl*'
            $script:invocationCount | Should -Be 0
        }
    }

    Context 'Positive: the complete applicable registry executes through its declarations' {
        It 'invokes every registered collector and evaluator exactly once' {
            # Arrange
            $script:invocation = @{}
            $registry = @(
                (New-RegistryEntry -ControlId 'EXO-001' -Collector 'Get-FirstEvidence' -Evaluator 'Test-FirstControl')
                (New-RegistryEntry -ControlId 'EXO-002' -Collector 'Get-SecondEvidence' -Evaluator 'Test-SecondControl')
            )
            $resolver = {
                param($Name)
                switch ($Name) {
                    'Get-FirstEvidence' { return { $script:invocation['Get-FirstEvidence']++; [pscustomobject]@{ Marker = 'first' } } }
                    'Test-FirstControl' { return { param($Evidence) $script:invocation['Test-FirstControl']++; [pscustomobject]@{ ControlId = 'EXO-001'; Status = 'Pass'; Marker = $Evidence.Marker } } }
                    'Get-SecondEvidence' { return { $script:invocation['Get-SecondEvidence']++; [pscustomobject]@{ Marker = 'second' } } }
                    'Test-SecondControl' { return { param($Evidence) $script:invocation['Test-SecondControl']++; [pscustomobject]@{ ControlId = 'EXO-002'; Status = 'Pass'; Marker = $Evidence.Marker } } }
                }
            }

            # Act
            $result = @(Invoke-RegistryExecutionSubject -Registry $registry -ExpectedControlId @('EXO-001', 'EXO-002') -CommandResolver $resolver)

            # Assert
            @($script:invocation.Keys | Sort-Object | ForEach-Object { "$_=$($script:invocation[$_])" }) -join '|' |
                Should -BeExactly 'Get-FirstEvidence=1|Get-SecondEvidence=1|Test-FirstControl=1|Test-SecondControl=1'
            @($result | ForEach-Object { "$($_.Entry.ControlId):$($_.Evidence.Marker):$($_.Result.ControlId):$($_.Result.Status)" }) -join '|' |
                Should -BeExactly 'EXO-001:first:EXO-001:Pass|EXO-002:second:EXO-002:Pass'
        }
    }
}
