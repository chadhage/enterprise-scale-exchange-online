#requires -Version 7.0

# The fault outcomes the shipped script can only reach by naming them off the contract itself.
# `Compliance` and `Approval` are absent on purpose: those two are decided by the run-outcome seam,
# and a script that can name them itself is a script that can resolve them itself. `Collection` is
# absent because the seam reaches it too - a control decided `Error` is a collection fault - so its
# own handler is asserted by fault separation rather than by reachability.
$DirectFaultOutcome = @('Configuration', 'Connection', 'Internal')

# The three regions whose faults an automation caller acts on differently from a defect in this
# tool: a configuration it can fix, a connection it can retry, a collection it can rerun.
$SeparableRegion = @('Configuration', 'Connection', 'Collection')

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:EvidenceScriptPath = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # Running the evidence command would require an Exchange Online and a Graph session, so which
    # exits it can produce is decided from the shipped script's syntax tree instead.
    # Microsoft.Graph and ExchangeOnlineManagement are not installed and are never imported here.

    function Get-ExitCodeOutcomeName {
        [CmdletBinding()]
        param([Parameter(Mandatory)][object]$Contract)

        if ($Contract -is [System.Collections.IDictionary]) { return @(foreach ($key in $Contract.Keys) { [string]$key }) }

        return @($Contract.PSObject.Properties | Where-Object { $_.MemberType -ne 'Method' } | ForEach-Object { $_.Name })
    }

    function Get-ExitExpression {
        [CmdletBinding()]
        param([Parameter(Mandatory)][System.Management.Automation.Language.ExitStatementAst]$Exit)

        $pipeline = $Exit.Pipeline
        if ($null -eq $pipeline) { return $null }

        if ($pipeline -is [System.Management.Automation.Language.PipelineAst] -and
            $pipeline.PipelineElements.Count -eq 1 -and
            $pipeline.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) {
            return $pipeline.PipelineElements[0].Expression
        }

        return $pipeline
    }

    function Get-ContractMemberName {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Scope,
            [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Variable
        )

        $access = @($Scope.FindAll({ param($node) $node -is [System.Management.Automation.Language.MemberExpressionAst] }, $true))

        return @(foreach ($member in $access) {
                if ($member.Expression -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }
                if ($member.Expression.VariablePath.UserPath -notin $Variable) { continue }
                if ($member.Member -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { continue }
                $member.Member.Value
            })
    }

    function Get-ScriptExitResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyString()]
            [string]$ScriptPath
        )

        $result = [ordered]@{
            Satisfied  = $false
            Reason     = $null
            Violations = @()
        }

        if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
            $result.Reason = 'EvidenceCommandPathNotSupplied'
            return [pscustomobject]$result
        }

        if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
            $result.Reason = 'EvidenceCommandMissing'
            return [pscustomobject]$result
        }

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)

        if (@($errors).Count -gt 0) {
            $result.Reason = 'EvidenceCommandUnparsable'
            $result.Violations = @(@($errors) | ForEach-Object { $_.Message })
            return [pscustomobject]$result
        }

        $declaredOutcome = Get-ExitCodeOutcomeName -Contract (Get-BaselineExitCodeContract)

        $contractVariable = [System.Collections.Generic.List[string]]::new()
        $seamVariable = [System.Collections.Generic.List[string]]::new()

        foreach ($assignment in @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))) {
            if ($assignment.Left -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }

            $name = $assignment.Left.VariablePath.UserPath
            $source = $assignment.Right.Extent.Text
            if ($source -match 'Get-BaselineExitCodeContract') { $contractVariable.Add($name) }
            if ($source -match 'Get-BaselineRunOutcome') { $seamVariable.Add($name) }
        }

        $exitStatement = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ExitStatementAst] }, $true))
        if ($exitStatement.Count -eq 0) {
            $result.Reason = 'EvidenceCommandDeclaresNoExit'
            return [pscustomobject]$result
        }

        $literal = [System.Collections.Generic.List[string]]::new()
        $undeclared = [System.Collections.Generic.List[string]]::new()
        $unresolved = [System.Collections.Generic.List[string]]::new()
        $exitedFromSeam = $false

        foreach ($statement in $exitStatement) {
            $expression = Get-ExitExpression -Exit $statement

            if ($null -eq $expression) {
                $unresolved.Add($statement.Extent.Text)
                continue
            }

            if ($expression -is [System.Management.Automation.Language.ConstantExpressionAst]) {
                $literal.Add($statement.Extent.Text)
                continue
            }

            if ($expression -isnot [System.Management.Automation.Language.MemberExpressionAst] -or
                $expression.Expression -isnot [System.Management.Automation.Language.VariableExpressionAst] -or
                $expression.Member -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $unresolved.Add($statement.Extent.Text)
                continue
            }

            $variable = $expression.Expression.VariablePath.UserPath
            $member = $expression.Member.Value

            if ($variable -in $contractVariable) {
                if ($member -notin $declaredOutcome) { $undeclared.Add($statement.Extent.Text) }
                continue
            }

            if ($variable -in $seamVariable -and $member -eq 'ExitCode') {
                $exitedFromSeam = $true
                continue
            }

            $unresolved.Add($statement.Extent.Text)
        }

        if ($literal.Count -gt 0) {
            $result.Reason = 'ExitCodeLiteral'
            $result.Violations = @($literal)
            return [pscustomobject]$result
        }

        if ($undeclared.Count -gt 0) {
            $result.Reason = 'ExitCodeNotDeclared'
            $result.Violations = @($undeclared)
            return [pscustomobject]$result
        }

        if ($unresolved.Count -gt 0) {
            $result.Reason = 'ExitCodeUnresolved'
            $result.Violations = @($unresolved)
            return [pscustomobject]$result
        }

        # A fault outcome is reachable when the script names it off the contract. `Compliance` and
        # `Approval` are reachable only through the seam, which is the whole point: the script is
        # not permitted to decide either one for itself.
        $named = @(Get-ContractMemberName -Scope $ast -Variable @($contractVariable))
        $reachable = [System.Collections.Generic.List[string]]::new()
        foreach ($outcome in $named) { if ($outcome -notin $reachable) { $reachable.Add($outcome) } }
        if ($exitedFromSeam) {
            foreach ($outcome in @('Success', 'Collection', 'Compliance', 'Approval')) {
                if ($outcome -notin $reachable) { $reachable.Add($outcome) }
            }
        }

        $unreachable = @(@('Configuration', 'Connection', 'Collection', 'Compliance', 'Approval', 'Internal') | Where-Object { $_ -notin $reachable })
        if ($unreachable.Count -gt 0) {
            $result.Reason = 'OutcomeUnreachable'
            $result.Violations = @($unreachable)
            return [pscustomobject]$result
        }

        if (-not $exitedFromSeam -or 'Compliance' -in $named) {
            $result.Reason = 'ComplianceNotFromSeam'
            $result.Violations = @($exitStatement | ForEach-Object { $_.Extent.Text })
            return [pscustomobject]$result
        }

        $handler = @($ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.CatchClauseAst] -or
                    $node -is [System.Management.Automation.Language.TrapStatementAst]
                }, $true))

        $handled = @(foreach ($clause in $handler) {
                , @(Get-ContractMemberName -Scope $clause -Variable @($contractVariable))
            })

        $conflated = [System.Collections.Generic.List[string]]::new()
        foreach ($region in @('Configuration', 'Connection', 'Collection')) {
            $alone = @($handled | Where-Object { $region -in $_ -and 'Internal' -notin $_ })
            if ($alone.Count -eq 0) { $conflated.Add($region) }
        }

        $internalOwn = @($handled | Where-Object {
                $clause = $_
                'Internal' -in $clause -and @(@('Configuration', 'Connection', 'Collection') | Where-Object { $_ -in $clause }).Count -eq 0
            })
        if ($internalOwn.Count -eq 0) { $conflated.Add('Internal') }

        if ($conflated.Count -gt 0) {
            $result.Reason = 'FaultNotSeparated'
            $result.Violations = @($conflated)
            return [pscustomobject]$result
        }

        $result.Satisfied = $true
        $result.Reason = 'EvidenceCommandExitContractSatisfied'
        return [pscustomobject]$result
    }

    function New-ExitFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Root,

            [string[]]$Omit = @(),
            [string]$Conflate,

            [switch]$LiteralExit,
            [switch]$UndeclaredOutcome,
            [switch]$UnresolvedExit,
            [switch]$NoSeamExit,
            [switch]$DecidesComplianceItself
        )

        $scriptDirectory = Join-Path $Root ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $scriptDirectory -Force | Out-Null
        $path = Join-Path $scriptDirectory 'Test-ExchangeOnlineBaseline.ps1'

        $region = [ordered]@{
            Configuration = 'Get-BaselineContext -ParameterPath $ParameterPath'
            Connection    = 'Connect-ExchangeOnline -ShowBanner:$false'
            Collection    = 'Get-AcceptedDomain -Identity contoso.com'
        }

        $line = [System.Collections.Generic.List[string]]::new()
        $line.Add('#requires -Version 7.0')
        $line.Add('param([string]$ParameterPath)')
        $line.Add('')
        $line.Add('$exitCode = Get-BaselineExitCodeContract')
        $line.Add('')

        if ('Internal' -notin $Omit -and -not $Conflate) {
            $line.Add('trap {')
            $line.Add('    Write-Error $_')
            $line.Add('    exit $exitCode.Internal')
            $line.Add('}')
            $line.Add('')
        }

        foreach ($name in @($region.Keys)) {
            if ($name -in $Omit) { continue }

            $member = if ($UndeclaredOutcome -and $name -eq 'Configuration') { 'Catastrophe' } else { $name }

            $line.Add('try {')
            $line.Add('    ' + $region[$name])
            $line.Add('}')
            $line.Add('catch {')
            $line.Add('    Write-Error $_')
            if ($Conflate -eq $name) {
                $line.Add('    if ($_.Exception -is [System.IO.IOException]) { exit $exitCode.' + $member + ' }')
                $line.Add('    exit $exitCode.Internal')
            }
            else {
                $line.Add('    exit $exitCode.' + $member)
            }
            $line.Add('}')
            $line.Add('')
        }

        if ($LiteralExit) { $line.Add('if ($false) { exit 1 }') }
        if ($UnresolvedExit) { $line.Add('if ($false) { exit $legacyFailureCode }') }
        if ($DecidesComplianceItself) { $line.Add('if ($false) { exit $exitCode.Compliance }') }

        $line.Add('$outcome = Get-BaselineRunOutcome -Check @() -GoLive $null')
        if (-not $NoSeamExit) { $line.Add('exit $outcome.ExitCode') }

        Set-Content -LiteralPath $path -Value ($line -join [Environment]::NewLine) -Encoding utf8
        return $path
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GATE-004-A3 the evidence command resolves every exit from the contract' {

    BeforeAll {
        $script:FixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('evidence-exit-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:FixtureRoot -Force | Out-Null
    }

    AfterAll {
        Remove-Item -LiteralPath $script:FixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    Context 'Negative: a command that is not there is a command no exit contract governs' {

        It 'ships the evidence command the exit contract governs' {
            # Arrange
            $path = $script:EvidenceScriptPath

            # Act
            $present = Test-Path -LiteralPath $path -PathType Leaf

            # Assert
            $present | Should -BeTrue -Because 'an exit contract asserted against a command nobody ships governs nothing'
        }

        It 'refuses a run it was handed no path to read' {
            # Arrange
            $path = ''

            # Act
            $verdict = Get-ScriptExitResult -ScriptPath $path

            # Assert
            $verdict.Reason | Should -BeExactly 'EvidenceCommandPathNotSupplied' -Because 'a check handed no command to read reports on nothing and calls it satisfied'
        }

        It 'refuses a path that names no file' {
            # Arrange
            $path = Join-Path $script:FixtureRoot 'Test-NoSuchCommand.ps1'

            # Act
            $verdict = Get-ScriptExitResult -ScriptPath $path

            # Assert
            $verdict.Reason | Should -BeExactly 'EvidenceCommandMissing' -Because 'a command that is not on disk cannot be the command whose exits were proved'
        }
    }

    Context 'Negative: an exit the contract did not resolve is an exit nothing downstream was told to expect' {

        It 'refuses a literal exit code' {
            # Arrange
            $path = New-ExitFixture -Root $script:FixtureRoot -LiteralExit

            # Act
            $verdict = Get-ScriptExitResult -ScriptPath $path

            # Assert
            $verdict.Reason | Should -BeExactly 'ExitCodeLiteral' -Because 'a hardcoded exit is the one thing that drifts from the contract without anybody editing the contract'
        }

        It 'refuses an exit naming an outcome the contract never declared' {
            # Arrange
            $path = New-ExitFixture -Root $script:FixtureRoot -UndeclaredOutcome

            # Act
            $verdict = Get-ScriptExitResult -ScriptPath $path

            # Assert
            $verdict.Reason | Should -BeExactly 'ExitCodeNotDeclared' -Because 'a member the contract never declared resolves to nothing, and an exit of nothing is an exit of zero'
        }

        It 'refuses an exit resolved from something that is not the contract' {
            # Arrange
            $path = New-ExitFixture -Root $script:FixtureRoot -UnresolvedExit

            # Act
            $verdict = Get-ScriptExitResult -ScriptPath $path

            # Assert
            $verdict.Reason | Should -BeExactly 'ExitCodeUnresolved' -Because 'a code carried in some other variable is a second contract nobody maintains'
        }
    }

    Context 'Negative: a fault class the command cannot reach is a fault class the caller never sees' {

        It 'refuses a command that cannot reach the <_> outcome' -ForEach $DirectFaultOutcome {
            # Arrange
            $path = New-ExitFixture -Root $script:FixtureRoot -Omit @($_)

            # Act
            $verdict = Get-ScriptExitResult -ScriptPath $path

            # Assert
            ('{0}:{1}' -f $verdict.Reason, ($verdict.Violations -join ',')) |
                Should -BeExactly ('OutcomeUnreachable:{0}' -f $_) -Because "a caller that can never be told '$_' has to guess that fault class from a code meaning something else"
        }

        It 'refuses a command that exits nothing through the run-outcome seam' {
            # Arrange
            $path = New-ExitFixture -Root $script:FixtureRoot -NoSeamExit

            # Act
            $verdict = Get-ScriptExitResult -ScriptPath $path

            # Assert
            ('{0}:{1}' -f $verdict.Reason, ($verdict.Violations -join ',')) |
                Should -BeExactly 'OutcomeUnreachable:Compliance,Approval' -Because 'a command that never exits from the seam can report a compliance gap and an ungranted approval only as success'
        }
    }

    Context 'Negative: a compliance exit the command decides for itself is a gate the command can open' {

        It 'refuses a command that resolves the compliance exit itself' {
            # Arrange
            $path = New-ExitFixture -Root $script:FixtureRoot -DecidesComplianceItself

            # Act
            $verdict = Get-ScriptExitResult -ScriptPath $path

            # Assert
            $verdict.Reason | Should -BeExactly 'ComplianceNotFromSeam' -Because 'a command that decides its own compliance exit is exactly the defect that shipped a correct gate exiting zero'
        }
    }

    Context 'Negative: a fault this tool caused and a fault the tenant caused are not the same answer' {

        It 'refuses a command that conflates a <_> fault with an internal one' -ForEach $SeparableRegion {
            # Arrange
            $path = New-ExitFixture -Root $script:FixtureRoot -Conflate $_

            # Act
            $verdict = Get-ScriptExitResult -ScriptPath $path

            # Assert
            $verdict.Violations | Should -Contain $_ -Because "a '$_' fault reported as a defect in this tool sends the caller to the wrong owner"
        }
    }

    Context 'Positive: the shipped evidence command resolves every exit from the contract' {

        It 'resolves every exit from the contract and reaches all six fault outcomes' {
            # Arrange
            $path = $script:EvidenceScriptPath

            # Act
            $verdict = Get-ScriptExitResult -ScriptPath $path

            # Assert
            ('Satisfied={0}:Reason={1}:Violations={2}' -f $verdict.Satisfied, $verdict.Reason, ($verdict.Violations -join ',')) |
                Should -BeExactly 'Satisfied=True:Reason=EvidenceCommandExitContractSatisfied:Violations=' -Because 'a gate is only enforced by the command that ships, not by the library it could have called'
        }
    }
}
