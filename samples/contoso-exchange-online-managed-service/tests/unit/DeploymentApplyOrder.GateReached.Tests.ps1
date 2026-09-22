#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # Synthetic scripts only. The shipped script is never written to, and nothing here connects
    # to a tenant: every fixture is parsed as text and judged on its shape alone.
    function New-FixtureScript {
        param([string]$Path, [string]$Text)

        Set-Content -LiteralPath $Path -Value $Text -Encoding utf8
        return $Path
    }

    function Format-ApplyOrder {
        param([object]$Node, [string]$Prefix)

        return '{0}|{1}' -f $Node['Ordered'], [bool](@($Node['Finding']) | Where-Object { $_ -like "$Prefix*" })
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-007-A2 shipped deployment script reaches the apply gate' {

    Context 'Negative: the run never asks the gate whether it may apply' {

        It 'does not call a script ordered when it never reaches the apply prerequisite gate' {
            # Arrange
            $path = New-FixtureScript -Path (Join-Path $TestDrive 'gate-never-reached.ps1') -Text @'
param(
    [string]$ConfigurationPath,
    [switch]$Apply
)

$context = Get-BaselineContext -ConfigurationPath $ConfigurationPath

if ($Apply) {
    Set-TransportConfig -Identity 'Default' -Confirm:$false
}
'@

            # Act
            $node = Test-BaselineDeploymentApplyOrder -ScriptPath $path

            # Assert
            (Format-ApplyOrder -Node $node -Prefix 'ApplyOrderGateNotReached') |
                Should -BeExactly 'False|True' -Because 'a run that mutates a tenant without ever consulting the apply prerequisite gate has no gate, only a gate function nobody calls'
        }
    }

    Context 'Negative: the gate is reached on a run that was never asked to apply' {

        It 'does not call a script ordered when the gate is not governed by its own apply switch' {
            # Arrange
            $path = New-FixtureScript -Path (Join-Path $TestDrive 'gate-outside-apply-switch.ps1') -Text @'
param(
    [string]$ConfigurationPath,
    [string]$PreviewPath,
    [string]$ApprovalPath,
    [string]$ArtifactRoot,
    [switch]$Apply
)

$decision = Test-BaselineApplyPrerequisite -Apply:$Apply -PreviewPath $PreviewPath -ApprovalPath $ApprovalPath -ArtifactRoot $ArtifactRoot

if (-not $decision.Permitted) {
    throw ('ApplyRefused: {0}' -f (@($decision.Finding) -join '; '))
}

if ($Apply) {
    Set-TransportConfig -Identity 'Default' -Confirm:$false
}
'@

            # Act
            $node = Test-BaselineDeploymentApplyOrder -ScriptPath $path

            # Assert
            (Format-ApplyOrder -Node $node -Prefix 'ApplyOrderGateNotUnderApplySwitch') |
                Should -BeExactly 'False|True' -Because 'a gate reached outside the apply switch refuses audit runs that change nothing and proves nothing about the apply run that does'
        }
    }

    Context 'Negative: the gate refuses and the run continues anyway' {

        It 'does not call a script ordered when a refusing decision does not terminate the run' {
            # Arrange
            $path = New-FixtureScript -Path (Join-Path $TestDrive 'gate-refusal-ignored.ps1') -Text @'
param(
    [string]$ConfigurationPath,
    [string]$PreviewPath,
    [string]$ApprovalPath,
    [string]$ArtifactRoot,
    [switch]$Apply
)

if ($Apply) {
    $decision = Test-BaselineApplyPrerequisite -Apply -PreviewPath $PreviewPath -ApprovalPath $ApprovalPath -ArtifactRoot $ArtifactRoot

    if (-not $decision.Permitted) {
        Write-Warning ('apply prerequisite refused: {0}' -f (@($decision.Finding) -join '; '))
    }

    Set-TransportConfig -Identity 'Default' -Confirm:$false
}
'@

            # Act
            $node = Test-BaselineDeploymentApplyOrder -ScriptPath $path

            # Assert
            (Format-ApplyOrder -Node $node -Prefix 'ApplyOrderGateRefusalNotEnforced') |
                Should -BeExactly 'False|True' -Because 'a refusal the run only warns about is a refusal that changed the tenant anyway, and a gate whose No is advisory is not a gate'
        }
    }
}
