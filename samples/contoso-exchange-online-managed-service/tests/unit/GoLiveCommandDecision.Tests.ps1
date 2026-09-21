BeforeAll {
    $script:CommandPath = Join-Path $PSScriptRoot '..\..\scripts\Test-ExchangeOnlineBaseline.ps1'
    $script:RequiredBinding = @(
        'Envelope',
        'CatalogPath',
        'ExpectedTenantId',
        'ExpectedDeploymentProfile',
        'ExpectedConfigurationHash',
        'RiskAcceptance',
        'MaximumEvidenceAge',
        'RequestedBy',
        'Signature',
        'TargetEntitlement'
    )

    function Get-GoLiveDecisionBlock {
        param([Parameter(Mandatory)][string]$Path)

        $token = $null
        $parseError = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$token, [ref]$parseError)
        if ($parseError.Count -gt 0) {
            throw "FixtureParseFailed: $($parseError[0].Message)"
        }

        $assignment = @($ast.EndBlock.Statements | Where-Object {
            $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $_.Left.VariablePath.UserPath -ceq 'goLiveDecision'
        })
        $conditional = @($ast.EndBlock.Statements | Where-Object {
            $_ -is [System.Management.Automation.Language.IfStatementAst] -and
            $_.Extent.Text -match '\$GoLive\b' -and
            $_.Extent.Text -match '\bTest-BaselineGoLive\b'
        })

        if ($assignment.Count -ne 1 -or $conditional.Count -ne 1) {
            return '$goLiveDecision = $null'
        }

        return $assignment[0].Extent.Text + [Environment]::NewLine + $conditional[0].Extent.Text
    }

    function New-GoLiveArguments {
        return @{
            Envelope                  = [pscustomobject]@{ Id = 'envelope-sentinel' }
            CatalogPath               = 'catalog-sentinel.json'
            ExpectedTenantId          = '11111111-1111-1111-1111-111111111111'
            ExpectedDeploymentProfile = 'MicrosoftNative'
            ExpectedConfigurationHash = ('a' * 64)
            RiskAcceptance            = @([pscustomobject]@{ Id = 'acceptance-sentinel' })
            MaximumEvidenceAge        = [timespan]::FromHours(12)
            RequestedBy               = 'operator@contoso.example'
            Signature                 = [pscustomobject]@{ CmsVerified = $true; Id = 'signature-sentinel' }
            TargetEntitlement         = [pscustomobject]@{ Id = 'entitlement-sentinel' }
        }
    }

    function Measure-GoLiveDecisionBlock {
        param(
            [Parameter(Mandatory)][string]$Source,
            [Parameter(Mandatory)][hashtable]$Arguments
        )

        $token = $null
        $parseError = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($Source, [ref]$token, [ref]$parseError)
        if ($parseError.Count -gt 0) {
            return [pscustomobject]@{ Violations = @("Parse:$($parseError[0].Message)") }
        }

        $inputCommand = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -cne 'Test-BaselineGoLive'
        }, $true))
        if ($inputCommand.Count -gt 0) {
            return [pscustomobject]@{ Violations = @("InputReread:$($inputCommand[0].GetCommandName())") }
        }

        $harness = @'
param([bool]$GoLive, [hashtable]$goLiveInput)
$script:gateCalls = [System.Collections.Generic.List[object]]::new()
function Test-BaselineGoLive {
    param(
        $Envelope,
        $CatalogPath,
        $ExpectedTenantId,
        $ExpectedDeploymentProfile,
        $ExpectedConfigurationHash,
        $RiskAcceptance,
        $MaximumEvidenceAge,
        $RequestedBy,
        $Signature,
        $TargetEntitlement
    )
    $call = @{}
    foreach ($name in $PSBoundParameters.Keys) { $call[$name] = $PSBoundParameters[$name] }
    $decision = [pscustomobject]@{ Permitted = $true; Call = $script:gateCalls.Count + 1 }
    $script:gateCalls.Add([pscustomobject]@{ Binding = $call; Decision = $decision })
    return $decision
}
__SOURCE__
[pscustomobject]@{ Decision = $goLiveDecision; Call = @($script:gateCalls) }
'@
        $scriptBlock = [scriptblock]::Create($harness.Replace('__SOURCE__', $Source))
        $live = & $scriptBlock $true $Arguments
        $ordinary = & $scriptBlock $false $Arguments
        $violation = [System.Collections.Generic.List[string]]::new()

        if (@($live.Call).Count -ne 1) {
            $violation.Add("GoLiveInvocationCount:$(@($live.Call).Count)")
        }
        else {
            foreach ($name in $script:RequiredBinding) {
                if (-not $live.Call[0].Binding.ContainsKey($name)) {
                    $violation.Add("Binding:$name")
                    continue
                }

                $expected = $Arguments[$name]
                $actual = $live.Call[0].Binding[$name]
                if ($name -in @('Envelope', 'RiskAcceptance', 'Signature', 'TargetEntitlement')) {
                    if (-not [object]::ReferenceEquals($expected, $actual)) {
                        $violation.Add("Binding:$name")
                    }
                }
                elseif ($actual -ne $expected) {
                    $violation.Add("Binding:$name")
                }
            }

            if (-not [object]::ReferenceEquals($live.Decision, $live.Call[0].Decision)) {
                $violation.Add('Decision:Discarded')
            }
        }

        if (@($ordinary.Call).Count -ne 0) {
            $violation.Add("NonGoLiveInvocationCount:$(@($ordinary.Call).Count)")
        }
        if ($null -ne $ordinary.Decision) {
            $violation.Add('NonGoLiveDecision:NotNull')
        }

        return [pscustomobject]@{ Violations = @($violation) }
    }

    function New-WiringFixture {
        param(
            [string]$Prefix = '',
            [string]$Invocation = 'Test-BaselineGoLive @goLiveInput',
            [switch]$Unconditional,
            [switch]$DiscardDecision,
            [switch]$Duplicate
        )

        $call = if ($DiscardDecision) { '$null = ' + $Invocation } else { '$goLiveDecision = ' + $Invocation }
        if ($Duplicate) { $call += [Environment]::NewLine + '    ' + $call }
        if ($Unconditional) {
            return "$Prefix`n`$goLiveDecision = `$null`n$call"
        }

        return "$Prefix`n`$goLiveDecision = `$null`nif (`$GoLive) {`n    $call`n}"
    }
}

Describe 'GATE-006 evidence-command go-live decision wiring' {
    Context 'negative invocation contracts' {
        It 'refuses a decision block that never invokes the gate' {
            # Arrange
            $source = '$goLiveDecision = $null'

            # Act
            $result = Measure-GoLiveDecisionBlock -Source $source -Arguments (New-GoLiveArguments)

            # Assert
            $result.Violations | Should -Contain 'GoLiveInvocationCount:0'
        }

        It 'refuses a go-live request that invokes the gate more than once' {
            # Arrange
            $source = New-WiringFixture -Duplicate

            # Act
            $result = Measure-GoLiveDecisionBlock -Source $source -Arguments (New-GoLiveArguments)

            # Assert
            $result.Violations | Should -Contain 'GoLiveInvocationCount:2'
        }

        It 'refuses ordinary collection that invokes the go-live gate' {
            # Arrange
            $source = New-WiringFixture -Unconditional

            # Act
            $result = Measure-GoLiveDecisionBlock -Source $source -Arguments (New-GoLiveArguments)

            # Assert
            $result.Violations | Should -Contain 'NonGoLiveInvocationCount:1'
        }

        It 'refuses a gate decision that is discarded' {
            # Arrange
            $source = New-WiringFixture -DiscardDecision

            # Act
            $result = Measure-GoLiveDecisionBlock -Source $source -Arguments (New-GoLiveArguments)

            # Assert
            $result.Violations | Should -Contain 'Decision:Discarded'
        }

        It 'refuses an invocation block that rereads materialized input' {
            # Arrange
            $source = New-WiringFixture -Prefix '$null = Get-Content -LiteralPath $RiskAcceptancePath'

            # Act
            $result = Measure-GoLiveDecisionBlock -Source $source -Arguments (New-GoLiveArguments)

            # Assert
            $result.Violations | Should -Contain 'InputReread:Get-Content'
        }

        It 'refuses an invocation omitting <_>' -ForEach @(
            'Envelope',
            'CatalogPath',
            'ExpectedTenantId',
            'ExpectedDeploymentProfile',
            'ExpectedConfigurationHash',
            'RiskAcceptance',
            'MaximumEvidenceAge',
            'RequestedBy',
            'Signature',
            'TargetEntitlement'
        ) {
            # Arrange
            $arguments = New-GoLiveArguments
            $null = $arguments.Remove($_)
            $source = New-WiringFixture

            # Act
            $result = Measure-GoLiveDecisionBlock -Source $source -Arguments $arguments

            # Assert
            $result.Violations | Should -Contain "Binding:$_"
        }
    }

    Context 'complete invocation contract' {
        It 'passes every materialized binding exactly once only for a public go-live request' {
            # Arrange
            $source = Get-GoLiveDecisionBlock -Path $script:CommandPath

            # Act
            $result = Measure-GoLiveDecisionBlock -Source $source -Arguments (New-GoLiveArguments)

            # Assert
            $result.Violations | Should -BeNullOrEmpty
        }
    }
}
