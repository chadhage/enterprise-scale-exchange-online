#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:FixtureRoot = $TestDrive

    # Every declaration parameter an apply run needs before it can name what it was reviewed
    # against. Each negative is this fixture with exactly one declaration removed.
    $script:DeclaredParameter = [ordered]@{
        ParameterPath = '    [Parameter(Mandatory)]
    [string]$ParameterPath'
        PreviewPath   = '    [string]$PreviewPath'
        ApprovalPath  = '    [string]$ApprovalPath'
        ChangeId      = '    [string]$ChangeId'
        ArtifactRoot  = '    [string]$ArtifactRoot'
        Apply         = '    [switch]$Apply'
    }

    function New-DeploymentFixture {
        param([string]$OmitParameter)

        $declaration = @(
            foreach ($name in $script:DeclaredParameter.Keys) {
                if ($name -eq $OmitParameter) { continue }
                [string]$script:DeclaredParameter[$name]
            }
        ) -join ",`n`n"

        $text = @"
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
$declaration
)

Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'

Connect-ExchangeOnline -ShowBanner:`$false

if (`$PSCmdlet.ShouldProcess('Default', 'Set transport config')) {
    Set-TransportConfig -Identity 'Default'
}
"@

        $path = Join-Path $script:FixtureRoot ('apply-order-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $path -Value $text -Encoding utf8
        return $path
    }

    function Format-Refusal {
        param([object]$Report, [string]$Code)

        return '{0}|{1}' -f $Report['Ordered'], [bool](@($Report['Finding']) | Where-Object { $_ -like "$Code*" })
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-007-A2 shipped deployment script declares what an apply needs' {

    Context 'Negative: there is no script to read the apply order out of' {

        It 'does not report an ordered apply for a script path naming no file' {
            # Arrange
            $missingPath = Join-Path $script:FixtureRoot ('absent-{0}.ps1' -f [guid]::NewGuid().ToString('N'))

            # Act
            $report = Test-BaselineDeploymentApplyOrder -ScriptPath $missingPath

            # Assert
            (Format-Refusal -Report $report -Code 'ApplyOrderScriptNotFound') |
                Should -BeExactly 'False|True' -Because 'an order report over a script that was never shipped clears an apply path nobody can run'
        }
    }

    Context 'Negative: the script cannot name the change it is applying' {

        It 'does not report an ordered apply for a script declaring no preview path parameter' {
            # Arrange
            $scriptPath = New-DeploymentFixture -OmitParameter 'PreviewPath'

            # Act
            $report = Test-BaselineDeploymentApplyOrder -ScriptPath $scriptPath

            # Assert
            (Format-Refusal -Report $report -Code 'ApplyOrderParameterPreviewPathNotDeclared') |
                Should -BeExactly 'False|True' -Because 'a script with no way to be handed the reviewed plan applies whatever the configuration happens to say at run time'
        }

        It 'does not report an ordered apply for a script declaring no approval path parameter' {
            # Arrange
            $scriptPath = New-DeploymentFixture -OmitParameter 'ApprovalPath'

            # Act
            $report = Test-BaselineDeploymentApplyOrder -ScriptPath $scriptPath

            # Assert
            (Format-Refusal -Report $report -Code 'ApplyOrderParameterApprovalPathNotDeclared') |
                Should -BeExactly 'False|True' -Because 'a script with no way to be handed an approval cannot be told that anyone agreed to the change it is about to make'
        }

        It 'does not report an ordered apply for a script declaring no change identifier parameter' {
            # Arrange
            $scriptPath = New-DeploymentFixture -OmitParameter 'ChangeId'

            # Act
            $report = Test-BaselineDeploymentApplyOrder -ScriptPath $scriptPath

            # Assert
            (Format-Refusal -Report $report -Code 'ApplyOrderParameterChangeIdNotDeclared') |
                Should -BeExactly 'False|True' -Because 'a tenant mutation that carries no change identifier cannot be tied back to the change record that authorised it'
        }

        It 'does not report an ordered apply for a script declaring no artifact root parameter' {
            # Arrange
            $scriptPath = New-DeploymentFixture -OmitParameter 'ArtifactRoot'

            # Act
            $report = Test-BaselineDeploymentApplyOrder -ScriptPath $scriptPath

            # Assert
            (Format-Refusal -Report $report -Code 'ApplyOrderParameterArtifactRootNotDeclared') |
                Should -BeExactly 'False|True' -Because 'a run with nowhere to write its preview, approval and outcome leaves no evidence that the apply ever happened'
        }
    }
}
