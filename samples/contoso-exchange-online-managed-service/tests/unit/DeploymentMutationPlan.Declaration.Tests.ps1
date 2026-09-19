#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:FixtureRoot = $TestDrive

    # The declaration form every fixture is built in, and the one the shipped script is held to: a
    # script-level `$MutationPlan` assigned an array of ordered hashtables, each naming the
    # operation, the command it runs and the object it runs against.
    function New-PlanEntry {
        param(
            [string]$OperationId = 'op-transport',
            [string]$Command = 'Set-TransportConfig',
            [string]$Identity = 'Default',
            [string[]]$Omit = @()
        )

        $member = [ordered]@{
            OperationId = $OperationId
            Command     = $Command
            Identity    = $Identity
        }
        foreach ($name in $Omit) { $member.Remove($name) }

        $pair = @(foreach ($name in $member.Keys) { "{0} = '{1}'" -f $name, $member[$name] }) -join '; '
        return ('    [ordered]@{{ {0} }}' -f $pair)
    }

    function New-PlanFixture {
        param(
            [string[]]$Entry = @((New-PlanEntry)),
            [switch]$OmitPlan,
            [string[]]$MutationCommand = @('Set-TransportConfig'),
            [switch]$IncludeNonTenantCommand
        )

        $plan = if ($OmitPlan) { '' } else { "`$MutationPlan = @(`n$($Entry -join ",`n")`n)" }

        $mutation = @(
            foreach ($name in $MutationCommand) {
                "if (`$PSCmdlet.ShouldProcess('Default', '$name')) {`n    $name -Identity 'Default'`n}"
            }
        ) -join "`n`n"

        # Commands a bare mutating-verb match would demand a plan entry for and the analyzer does
        # not: three allowlisted non-tenant commands and one function the script defines itself.
        $noise = if ($IncludeNonTenantCommand) {
            @'
function Set-LocalHelper {
    param([string]$Name)
}

New-Item -Path $ArtifactRoot -ItemType Directory -Force | Out-Null
Set-Variable -Name 'attempt' -Value 1
Set-Content -LiteralPath (Join-Path $ArtifactRoot 'outcome.json') -Value '{}'
Set-LocalHelper -Name 'noise'
'@
        }
        else { '' }

        $text = @"
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string]`$ParameterPath,

    [string]`$ArtifactRoot,

    [switch]`$Apply
)

Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'

$plan

Connect-ExchangeOnline -ShowBanner:`$false

$noise

$mutation
"@

        $path = Join-Path $script:FixtureRoot ('mutation-plan-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $path -Value $text -Encoding utf8
        return $path
    }

    function Format-PlanRefusal {
        param([object]$Report, [string]$Code)

        return '{0}|{1}' -f $Report['Planned'], [bool](@($Report['Finding']) | Where-Object { $_ -like "$Code*" })
    }

    function Select-PlanFinding {
        param([object]$Report, [string]$Code)

        return @(@($Report['Finding']) | Where-Object { $_ -like "$Code*" })
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-007-A3 the shipped mutation plan declares every mutation it can reach' {

    Context 'Negative: there is no script to read a mutation plan out of' {

        It 'does not report a planned run for a script path naming no file' {
            # Arrange
            $missingPath = Join-Path $script:FixtureRoot ('absent-{0}.ps1' -f [guid]::NewGuid().ToString('N'))

            # Act
            $report = Test-BaselineDeploymentMutationPlan -ScriptPath $missingPath

            # Assert
            (Format-PlanRefusal -Report $report -Code 'MutationPlanScriptNotFound') |
                Should -BeExactly 'False|True' -Because 'a plan report over a script that was never shipped declares a plan for mutations nobody can run'
        }
    }

    Context 'Negative: the script declares no mutation plan at all' {

        It 'does not report a planned run for a script assigning no mutation plan' {
            # Arrange
            $scriptPath = New-PlanFixture -OmitPlan -MutationCommand @('Set-TransportConfig', 'Set-OrganizationConfig')

            # Act
            $report = Test-BaselineDeploymentMutationPlan -ScriptPath $scriptPath

            # Assert
            (Format-PlanRefusal -Report $report -Code 'MutationPlanScriptNotDeclared') |
                Should -BeExactly 'False|True' -Because 'a script that mutates a tenant while declaring no plan has nothing to journal, capture state against or roll back, so every change it makes is unaccounted for'
        }
    }

    Context 'Negative: a mutation the script can reach is not in the plan' {

        It 'does not report a planned run for a reachable tenant mutation the plan omits' {
            # Arrange
            $scriptPath = New-PlanFixture `
                -Entry @((New-PlanEntry -OperationId 'op-transport' -Command 'Set-TransportConfig' -Identity 'Default')) `
                -MutationCommand @('Set-TransportConfig', 'Set-OrganizationConfig')

            # Act
            $report = Test-BaselineDeploymentMutationPlan -ScriptPath $scriptPath

            # Assert
            $omitted = Select-PlanFinding -Report $report -Code 'MutationPlanOperationNotDeclared'
            ('{0}|{1}|{2}' -f $report['Planned'], ($omitted.Count -gt 0), (@($omitted -match 'Set-OrganizationConfig').Count -gt 0)) |
                Should -BeExactly 'False|True|True' -Because 'a tenant mutation absent from the plan is applied outside the change that was previewed and approved, and a finding that cannot name it tells nobody which mutation to declare'
        }

        It 'does not demand a plan entry for a command that mutates no tenant' {
            # Arrange
            $scriptPath = New-PlanFixture `
                -Entry @((New-PlanEntry -OperationId 'op-transport' -Command 'Set-TransportConfig' -Identity 'Default')) `
                -MutationCommand @('Set-TransportConfig') `
                -IncludeNonTenantCommand

            # Act
            $report = Test-BaselineDeploymentMutationPlan -ScriptPath $scriptPath

            # Assert
            $omitted = Select-PlanFinding -Report $report -Code 'MutationPlanOperationNotDeclared'
            (@(foreach ($name in @('New-Item', 'Set-Variable', 'Set-Content', 'Set-LocalHelper')) {
                        '{0}={1}' -f $name, (@($omitted -match $name).Count -gt 0)
                    }) -join ',') |
                Should -BeExactly 'New-Item=False,Set-Variable=False,Set-Content=False,Set-LocalHelper=False' -Because 'a plan check that matches mutating verbs itself rather than reusing the mutation analyzer demands plan entries for local helpers and file-system calls, and a report full of mutations that are not mutations is one nobody reads'
        }
    }

    Context 'Negative: a declared operation does not say what it changes' {

        It 'does not report a planned run for an operation naming no command' {
            # Arrange
            $scriptPath = New-PlanFixture `
                -Entry @((New-PlanEntry -OperationId 'op-transport' -Omit @('Command'))) `
                -MutationCommand @('Set-TransportConfig')

            # Act
            $report = Test-BaselineDeploymentMutationPlan -ScriptPath $scriptPath

            # Assert
            (Format-PlanRefusal -Report $report -Code 'MutationPlanOperationCommandNotNamed') |
                Should -BeExactly 'False|True' -Because 'an operation that names no command cannot be matched to the mutation it covers, so it clears every mutation and none of them'
        }

        It 'does not report a planned run for an operation naming no identity' {
            # Arrange
            $scriptPath = New-PlanFixture `
                -Entry @((New-PlanEntry -OperationId 'op-transport' -Omit @('Identity'))) `
                -MutationCommand @('Set-TransportConfig')

            # Act
            $report = Test-BaselineDeploymentMutationPlan -ScriptPath $scriptPath

            # Assert
            (Format-PlanRefusal -Report $report -Code 'MutationPlanOperationIdentityNotNamed') |
                Should -BeExactly 'False|True' -Because 'an operation that names no identity does not say which object it changes, so its prior state cannot be captured and its change cannot be rolled back'
        }
    }
}
