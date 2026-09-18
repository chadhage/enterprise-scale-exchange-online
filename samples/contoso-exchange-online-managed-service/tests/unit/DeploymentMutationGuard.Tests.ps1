#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:DeployScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-005-A3 the shipped deployment script guards every tenant mutation' {

    Context 'Negative: the script is not there to be guarded' {

        It 'ships a deployment script to report on' {
            # Arrange
            $path = $script:DeployScriptPath

            # Act
            $present = Test-Path -LiteralPath $path -PathType Leaf

            # Assert
            $present | Should -BeTrue -Because 'a guard report over a script that is not shipped clears nothing'
        }
    }

    Context 'Negative: the script claims a decision it never asks for' {

        It 'calls $PSCmdlet.ShouldProcess at least once' {
            # Arrange
            $text = Get-Content -LiteralPath $script:DeployScriptPath -Raw

            # Act
            $callCount = ([regex]::Matches($text, [regex]::Escape('$PSCmdlet.ShouldProcess'))).Count

            # Assert
            $callCount | Should -BeGreaterThan 0 -Because 'a script declaring SupportsShouldProcess while calling ShouldProcess nowhere silently ignores -WhatIf and -Confirm on every tenant mutation'
        }

        It 'declares SupportsShouldProcess' {
            # Arrange
            $text = Get-Content -LiteralPath $script:DeployScriptPath -Raw

            # Act
            $declared = $text -match 'SupportsShouldProcess'

            # Assert
            $declared | Should -BeTrue -Because 'a script that mutates a tenant without declaring SupportsShouldProcess cannot be run with -WhatIf at all'
        }
    }

    Context 'Negative: the report is empty for the wrong reason' {

        It 'finds tenant mutation sites in the script' {
            # Arrange
            $report = Get-BaselineMutationGuardReport -ScriptPath $script:DeployScriptPath

            # Act
            $siteCount = @($report.MutationSite).Count

            # Assert
            $siteCount | Should -BeGreaterThan 0 -Because 'a deployment script the analyzer finds no mutations in is an analyzer that would clear anything, not a script that changes nothing'
        }
    }

    Context 'Positive: every tenant mutation the script can reach sits under a decision' {

        It 'reports no unguarded mutation site' {
            # Arrange
            $expected = 'no unguarded mutation site'

            # Act
            $unguarded = @((Get-BaselineMutationGuardReport -ScriptPath $script:DeployScriptPath).UnguardedSite)

            # Assert
            $(if ($unguarded.Count -eq 0) { $expected } else { ($unguarded | ForEach-Object { '{0}@{1}' -f $_.Command, $_.Line }) -join ', ' }) |
                Should -BeExactly $expected -Because 'a tenant-mutating cmdlet reachable without a ShouldProcess decision ignores -WhatIf and -Confirm and changes the tenant anyway'
        }
    }
}
