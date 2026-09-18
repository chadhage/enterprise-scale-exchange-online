#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:EvidenceScriptPath = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'

    # Running the evidence command would require an Exchange Online and a Graph session, so the
    # parameter surface is decided from the shipped script's syntax tree instead. Microsoft.Graph
    # and ExchangeOnlineManagement are not installed and are never imported here.

    # GATE-001: the parameters a go-live decision cannot be reached without. The type is named
    # beside each one because a switch the operator cannot omit, a maximum age that is really a
    # string and an expected hash that accepts any object each read exactly like the parameter the
    # card asks for while proving something else.
    $script:GoLiveParameterContract = @(
        [pscustomobject]@{ Name = 'GoLive'; Type = [System.Management.Automation.SwitchParameter] }
        [pscustomobject]@{ Name = 'RiskAcceptancePath'; Type = [string] }
        [pscustomobject]@{ Name = 'MaximumEvidenceAge'; Type = [timespan] }
        [pscustomobject]@{ Name = 'ExpectedConfigurationHash'; Type = [string] }
    )

    function Test-ParameterMandatory {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [System.Management.Automation.Language.ParameterAst]$Parameter
        )

        foreach ($attribute in @($Parameter.Attributes | Where-Object { $_ -is [System.Management.Automation.Language.AttributeAst] })) {
            if ($attribute.TypeName.Name -notin @('Parameter', 'ParameterAttribute')) { continue }

            foreach ($named in @($attribute.NamedArguments)) {
                if ($named.ArgumentName -ne 'Mandatory') { continue }
                if ($named.ExpressionOmitted -or $named.Argument.Extent.Text -match '^\$true$') { return $true }
            }
        }

        return $false
    }

    function Get-GoLiveParameterResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyString()]
            [string]$ScriptPath,

            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [object[]]$Contract
        )

        $result = [ordered]@{
            Satisfied  = $false
            Reason     = $null
            Violations = @()
        }

        if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
            $result.Reason = 'EvidenceCommandMissing'
            return [pscustomobject]$result
        }

        if ($null -eq $Contract) {
            $result.Reason = 'ContractNotSupplied'
            return [pscustomobject]$result
        }

        if (@($Contract).Count -eq 0) {
            $result.Reason = 'ContractDeclaresNoParameter'
            return [pscustomobject]$result
        }

        foreach ($entry in @($Contract)) {
            if ([string]::IsNullOrWhiteSpace([string]$entry.Name)) {
                $result.Reason = 'ContractParameterUnnamed'
                return [pscustomobject]$result
            }

            if ($null -eq $entry.Type -or $entry.Type -isnot [type]) {
                $result.Reason = 'ContractParameterUntyped'
                $result.Violations = @([string]$entry.Name)
                return [pscustomobject]$result
            }
        }

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)

        # The command's own surface is its top-level parameter block. A parameter declared inside a
        # nested function is not something an automation caller can ever supply.
        if ($null -eq $ast.ParamBlock) {
            $result.Reason = 'ParameterBlockMissing'
            return [pscustomobject]$result
        }

        $declared = @($ast.ParamBlock.Parameters)

        $missing = [System.Collections.Generic.List[string]]::new()
        $untyped = [System.Collections.Generic.List[string]]::new()
        $mismatched = [System.Collections.Generic.List[string]]::new()
        $mandatory = [System.Collections.Generic.List[string]]::new()

        foreach ($entry in @($Contract)) {
            $name = [string]$entry.Name
            $parameter = @($declared | Where-Object { $_.Name.VariablePath.UserPath -eq $name })

            if ($parameter.Count -eq 0) {
                $missing.Add($name)
                continue
            }

            $constraint = @($parameter[0].Attributes | Where-Object { $_ -is [System.Management.Automation.Language.TypeConstraintAst] })
            if ($constraint.Count -eq 0) {
                $untyped.Add($name)
                continue
            }

            if ($parameter[0].StaticType -ne $entry.Type) {
                $mismatched.Add(("{0}: declared '{1}', required '{2}'" -f $name, $parameter[0].StaticType.FullName, $entry.Type.FullName))
                continue
            }

            if (Test-ParameterMandatory -Parameter $parameter[0]) {
                $mandatory.Add($name)
            }
        }

        if ($missing.Count -gt 0) {
            $result.Reason = 'ParameterMissing'
            $result.Violations = @($missing)
            return [pscustomobject]$result
        }

        if ($untyped.Count -gt 0) {
            $result.Reason = 'ParameterUntyped'
            $result.Violations = @($untyped)
            return [pscustomobject]$result
        }

        if ($mismatched.Count -gt 0) {
            $result.Reason = 'ParameterTypeMismatch'
            $result.Violations = @($mismatched)
            return [pscustomobject]$result
        }

        # A go-live parameter the operator cannot omit turns every ordinary evidence run into a
        # go-live decision, which is how a gate stops being opt-in and starts being ignored.
        if ($mandatory.Count -gt 0) {
            $result.Reason = 'ParameterMandatory'
            $result.Violations = @($mandatory)
            return [pscustomobject]$result
        }

        $result.Satisfied = $true
        $result.Reason = 'GoLiveParameterSurfaceSatisfied'
        return [pscustomobject]$result
    }

    function New-GoLiveParameterFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Root,

            [string[]]$Omit = @(),
            [hashtable]$Declaration = @{},

            [switch]$NoParameterBlock,
            [switch]$LowerCaseNames,
            [switch]$NestedOnly,
            [switch]$ExtraParameter
        )

        $scriptDirectory = Join-Path $Root ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $scriptDirectory -Force | Out-Null
        $path = Join-Path $scriptDirectory 'Test-ExchangeOnlineBaseline.ps1'

        $default = [ordered]@{
            GoLive                    = '[switch]$GoLive'
            RiskAcceptancePath        = '[string]$RiskAcceptancePath'
            MaximumEvidenceAge        = '[timespan]$MaximumEvidenceAge'
            ExpectedConfigurationHash = '[string]$ExpectedConfigurationHash'
        }

        if ($LowerCaseNames) {
            $default['GoLive'] = '[switch]$golive'
            $default['RiskAcceptancePath'] = '[string]$riskacceptancepath'
        }

        foreach ($name in $Declaration.Keys) { $default[$name] = $Declaration[$name] }
        foreach ($name in $Omit) { $default.Remove($name) }

        $entry = [System.Collections.Generic.List[string]]::new()
        $entry.Add('[Parameter(Mandatory)]' + [Environment]::NewLine + '    [string]$ParameterPath')
        foreach ($name in $default.Keys) { $entry.Add($default[$name]) }
        if ($ExtraParameter) { $entry.Add('[switch]$SkipConnection') }

        $line = [System.Collections.Generic.List[string]]::new()
        $line.Add('#requires -Version 7.0')

        if ($NestedOnly) {
            $line.Add('param(')
            $line.Add('    [Parameter(Mandatory)]')
            $line.Add('    [string]$ParameterPath')
            $line.Add(')')
            $line.Add('')
            $line.Add('function Invoke-Gate {')
            $line.Add('    param(')
            $line.Add('        [switch]$GoLive,')
            $line.Add('        [string]$RiskAcceptancePath,')
            $line.Add('        [timespan]$MaximumEvidenceAge,')
            $line.Add('        [string]$ExpectedConfigurationHash')
            $line.Add('    )')
            $line.Add('}')
        }
        elseif ($NoParameterBlock) {
            $line.Add('$ParameterPath = $args[0]')
        }
        else {
            $line.Add('[CmdletBinding()]')
            $line.Add('param(')
            $line.Add('    ' + ($entry -join (',' + [Environment]::NewLine + '    ')))
            $line.Add(')')
        }

        $line.Add('')
        $line.Add('Set-StrictMode -Version Latest')

        Set-Content -LiteralPath $path -Value ($line -join [Environment]::NewLine) -Encoding utf8
        return $path
    }
}

Describe 'GATE-001-A go-live parameter surface' {
    BeforeAll {
        $script:FixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('golive-parameters-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:FixtureRoot -Force | Out-Null
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:FixtureRoot) {
            Remove-Item -LiteralPath $script:FixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'the surface cannot be decided' {
        It 'refuses a check that is handed no path to read' {
            # Arrange
            $contract = $script:GoLiveParameterContract

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath '' -Contract $contract

            # Assert
            $result.Reason | Should -BeExactly 'EvidenceCommandMissing' -Because 'a surface nobody named cannot be proved to carry anything'
        }

        It 'refuses a path that names no file' {
            # Arrange
            $absent = Join-Path $script:FixtureRoot 'no-such-command.ps1'

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $absent -Contract $script:GoLiveParameterContract

            # Assert
            $result.Reason | Should -BeExactly 'EvidenceCommandMissing' -Because 'a command that does not exist declares no parameter'
        }

        It 'refuses a check that is handed no parameter contract' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $null

            # Assert
            $result.Reason | Should -BeExactly 'ContractNotSupplied' -Because 'a check with no contract behind it demands nothing'
        }

        It 'refuses a contract that declares no parameter' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract @()

            # Assert
            $result.Reason | Should -BeExactly 'ContractDeclaresNoParameter' -Because 'an empty contract is satisfied by every command ever written'
        }

        It 'refuses a contract entry that names no parameter' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot
            $contract = @([pscustomobject]@{ Name = ''; Type = [string] })

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $contract

            # Assert
            $result.Reason | Should -BeExactly 'ContractParameterUnnamed' -Because 'a required parameter with no name can never be looked for'
        }

        It 'refuses a contract entry that names no type' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot
            $contract = @([pscustomobject]@{ Name = 'GoLive'; Type = $null })

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $contract

            # Assert
            $result.Violations | Should -Be @('GoLive') -Because 'an untyped demand accepts the parameter in any shape at all'
        }
    }

    Context 'the command declares no surface' {
        It 'refuses a command that declares no parameter block at all' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot -NoParameterBlock

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $script:GoLiveParameterContract

            # Assert
            $result.Reason | Should -BeExactly 'ParameterBlockMissing' -Because 'a command with no parameter block accepts no go-live request'
        }

        It 'refuses go-live parameters declared only inside a nested function' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot -NestedOnly

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $script:GoLiveParameterContract

            # Assert
            $result.Reason | Should -BeExactly 'ParameterMissing' -Because 'a parameter an automation caller cannot supply is not the command surface'
        }
    }

    Context 'a declared parameter is absent' {
        It 'names GoLive when it is absent' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot -Omit 'GoLive'

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $script:GoLiveParameterContract

            # Assert
            $result.Violations | Should -Be @('GoLive') -Because 'without the switch there is no way to ask for a gated run'
        }

        It 'names RiskAcceptancePath when it is absent' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot -Omit 'RiskAcceptancePath'

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $script:GoLiveParameterContract

            # Assert
            $result.Violations | Should -Be @('RiskAcceptancePath') -Because 'an approved exception nobody can supply is an exception nobody can honour'
        }

        It 'names MaximumEvidenceAge when it is absent' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot -Omit 'MaximumEvidenceAge'

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $script:GoLiveParameterContract

            # Assert
            $result.Violations | Should -Be @('MaximumEvidenceAge') -Because 'evidence with no declared shelf life never goes stale'
        }

        It 'names ExpectedConfigurationHash when it is absent' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot -Omit 'ExpectedConfigurationHash'

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $script:GoLiveParameterContract

            # Assert
            $result.Violations | Should -Be @('ExpectedConfigurationHash') -Because 'a run nobody can bind to a configuration proves nothing about that configuration'
        }

        It 'names every absent go-live parameter at once' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot -Omit @('GoLive', 'MaximumEvidenceAge')

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $script:GoLiveParameterContract

            # Assert
            $result.Violations | Should -Be @('GoLive', 'MaximumEvidenceAge') -Because 'reporting one absence at a time hides how far the surface is from the contract'
        }
    }

    Context 'a declared parameter is the wrong shape' {
        It 'refuses GoLive declared as a bool rather than a switch' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot -Declaration @{ GoLive = '[bool]$GoLive' }

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $script:GoLiveParameterContract

            # Assert
            $result.Violations | Should -Be @("GoLive: declared 'System.Boolean', required 'System.Management.Automation.SwitchParameter'") -Because 'a bool the caller must supply a value for is not an opt-in switch'
        }

        It 'refuses MaximumEvidenceAge declared as a string rather than a time span' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot -Declaration @{ MaximumEvidenceAge = '[string]$MaximumEvidenceAge' }

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $script:GoLiveParameterContract

            # Assert
            $result.Violations | Should -Be @("MaximumEvidenceAge: declared 'System.String', required 'System.TimeSpan'") -Because 'an age the command has to parse itself is an age it can misparse into forever'
        }

        It 'separates a parameter with no type constraint at all from a mismatched one' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot -Declaration @{ ExpectedConfigurationHash = '$ExpectedConfigurationHash' }

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $script:GoLiveParameterContract

            # Assert
            $result.Reason | Should -BeExactly 'ParameterUntyped' -Because 'an untyped parameter accepts every object ever passed to it, which is a different defect from the wrong type'
        }

        It 'refuses a go-live parameter declared mandatory' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot -Declaration @{
                RiskAcceptancePath = '[Parameter(Mandatory)]' + [Environment]::NewLine + '    [string]$RiskAcceptancePath'
            }

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $script:GoLiveParameterContract

            # Assert
            $result.Violations | Should -Be @('RiskAcceptancePath') -Because 'a mandatory gate parameter makes every ordinary evidence run demand it'
        }
    }

    Context 'the surface is read as the shell reads it' {
        It 'does not report a parameter differing only in casing as missing' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot -LowerCaseNames

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $script:GoLiveParameterContract

            # Assert
            $result.Satisfied | Should -BeTrue -Because 'PowerShell binds parameters without regard to casing, so a casing difference breaks no caller'
        }

        It 'does not report a parameter the contract never named as drift' {
            # Arrange
            $path = New-GoLiveParameterFixture -Root $script:FixtureRoot -ExtraParameter

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $path -Contract $script:GoLiveParameterContract

            # Assert
            $result.Satisfied | Should -BeTrue -Because 'the contract is a floor on the go-live surface, not a ceiling on the command'
        }
    }

    Context 'the shipped evidence command' {
        It 'declares every go-live parameter at the type the contract names, none of them mandatory' {
            # Arrange
            $contract = $script:GoLiveParameterContract

            # Act
            $result = Get-GoLiveParameterResult -ScriptPath $script:EvidenceScriptPath -Contract $contract

            # Assert
            $result.Satisfied | Should -BeTrue -Because "the shipped evidence command must accept a go-live request, but reported '$($result.Reason)' for '$($result.Violations -join "', '")'"
        }
    }
}
