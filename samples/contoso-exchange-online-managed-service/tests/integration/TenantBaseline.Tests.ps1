#requires -Version 7.0

BeforeAll {
    $script:ShippedTestRoot = Split-Path -Parent $PSScriptRoot
    $script:ScenarioFileName = 'TenantBaseline.Tests.ps1'

    # The two modules the integration suite may never require. Neither is installed here, and an
    # integration scenario that needs one is a scenario nobody can run offline.
    $script:TenantModule = @('Microsoft.Graph', 'ExchangeOnlineManagement')
    $script:TenantConnectCommand = @('Connect-MgGraph', 'Connect-ExchangeOnline', 'Connect-IPPSSession')
    $script:PlantedNamePattern = '(?i)(password|secret|token|apikey|credential)'

    function Test-TenantModuleName {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyString()]
            [string]$Name
        )

        if ([string]::IsNullOrWhiteSpace($Name)) { return $false }

        foreach ($module in $script:TenantModule) {
            if ($Name -eq $module -or $Name -like "$module.*") { return $true }
        }

        return $false
    }

    function Get-IntegrationOfflineFinding {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        $lexeme = $null
        $parseFault = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Resolve-Path -LiteralPath $Path).ProviderPath, [ref]$lexeme, [ref]$parseFault)

        if (@($parseFault).Count -gt 0) { return @('IntegrationSuiteNotParsable') }

        $code = [System.Collections.Generic.List[string]]::new()

        if ($null -ne $ast.ScriptRequirements) {
            foreach ($required in @($ast.ScriptRequirements.RequiredModules)) {
                if (Test-TenantModuleName -Name ([string]$required.Name)) {
                    $code.Add('IntegrationSuiteRequiresTenantModule')
                }
            }
        }

        foreach ($command in @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))) {
            $name = [string]$command.GetCommandName()

            if ($script:TenantConnectCommand -contains $name) { $code.Add('IntegrationSuiteConnectsToTenant') }
            if ($name -eq 'ConvertTo-SecureString') { $code.Add('IntegrationSuiteCarriesSecret') }

            foreach ($element in @($command.CommandElements)) {
                if ($element -is [System.Management.Automation.Language.CommandParameterAst] -and $element.ParameterName -eq 'Apply') {
                    $code.Add('IntegrationSuiteAppliesChange')
                }

                if ($name -ne 'Import-Module') { continue }
                if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst] -and (Test-TenantModuleName -Name $element.Value)) {
                    $code.Add('IntegrationSuiteImportsTenantModule')
                }
            }
        }

        foreach ($assignment in @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))) {
            $target = $assignment.Left
            if ($target -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }
            if ([string]$target.VariablePath.UserPath -notmatch $script:PlantedNamePattern) { continue }

            $assigned = $assignment.Right
            if ($assigned -is [System.Management.Automation.Language.CommandExpressionAst] -and
                $assigned.Expression -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $code.Add('IntegrationSuiteCarriesSecret')
            }
        }

        return @($code)
    }

    function Get-TestLayoutResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyString()]
            [string]$TestRoot
        )

        $finding = [System.Collections.Generic.List[string]]::new()

        if ([string]::IsNullOrWhiteSpace($TestRoot) -or -not (Test-Path -LiteralPath $TestRoot -PathType Container)) {
            return [pscustomobject]@{ Satisfied = $false; Finding = @('TestRootNotFound') }
        }

        $unitRoot = Join-Path $TestRoot 'unit'
        if (-not (Test-Path -LiteralPath $unitRoot -PathType Container)) {
            $finding.Add('UnitSuiteNotFound')
        }
        elseif (@(Get-ChildItem -LiteralPath $unitRoot -Filter '*.Tests.ps1' -File -Recurse).Count -eq 0) {
            $finding.Add('UnitSuiteEmpty')
        }

        $integrationRoot = Join-Path $TestRoot 'integration'
        if (-not (Test-Path -LiteralPath $integrationRoot -PathType Container)) {
            $finding.Add('IntegrationSuiteNotFound')
        }
        else {
            if (-not (Test-Path -LiteralPath (Join-Path $integrationRoot $script:ScenarioFileName) -PathType Leaf)) {
                $finding.Add('IntegrationScenarioFileNotFound')
            }

            foreach ($file in @(Get-ChildItem -LiteralPath $integrationRoot -Filter '*.Tests.ps1' -File -Recurse)) {
                foreach ($code in @(Get-IntegrationOfflineFinding -Path $file.FullName)) { $finding.Add($code) }
            }
        }

        $fixtureRoot = Join-Path $TestRoot 'fixtures'
        if (-not (Test-Path -LiteralPath $fixtureRoot -PathType Container)) {
            $finding.Add('FixtureRootNotFound')
        }
        else {
            if (@(Get-ChildItem -LiteralPath $fixtureRoot -File).Count -gt 0) { $finding.Add('FixtureNotGrouped') }

            $group = @(Get-ChildItem -LiteralPath $fixtureRoot -Directory)
            if ($group.Count -eq 0) { $finding.Add('FixtureGroupNotFound') }

            foreach ($entry in $group) {
                if (@(Get-ChildItem -LiteralPath $entry.FullName -File -Recurse).Count -eq 0) { $finding.Add('FixtureGroupEmpty') }
            }
        }

        $distinct = @($finding | Select-Object -Unique)
        return [pscustomobject]@{ Satisfied = ($distinct.Count -eq 0); Finding = $distinct }
    }

    function New-LayoutFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Root,

            [switch]$OmitUnitSuite,
            [switch]$EmptyUnitSuite,
            [switch]$OmitIntegrationSuite,
            [switch]$OmitScenarioFile,
            [switch]$UnparsableScenario,
            [switch]$RequireTenantModule,
            [switch]$ImportTenantModule,
            [switch]$ConnectToTenant,
            [switch]$ApplyChange,
            [switch]$CarryPlantedSecret,
            [switch]$OmitFixtureRoot,
            [switch]$OmitFixtureGroup,
            [switch]$LooseFixture,
            [switch]$EmptyFixtureGroup
        )

        $testRoot = Join-Path $Root ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

        if (-not $OmitUnitSuite) {
            $unitRoot = Join-Path $testRoot 'unit'
            New-Item -ItemType Directory -Path $unitRoot -Force | Out-Null

            if (-not $EmptyUnitSuite) {
                Set-Content -LiteralPath (Join-Path $unitRoot 'Fixture.Tests.ps1') `
                    -Value 'Describe ''fixture'' { It ''passes'' { $true | Should -BeTrue } }' -Encoding utf8
            }
        }

        if (-not $OmitIntegrationSuite) {
            $integrationRoot = Join-Path $testRoot 'integration'
            New-Item -ItemType Directory -Path $integrationRoot -Force | Out-Null

            $line = [System.Collections.Generic.List[string]]::new()
            if ($RequireTenantModule) { $line.Add('#requires -Modules Microsoft.Graph.Authentication') }
            $line.Add('BeforeAll {')
            if ($ImportTenantModule) { $line.Add('    Import-Module -Name ''ExchangeOnlineManagement'' -Force') }
            if ($CarryPlantedSecret) { $line.Add('    $script:tenantPassword = ''PlantedNotReal''') }
            $line.Add('}')
            $line.Add('Describe ''scenario'' {')
            $line.Add('    It ''runs'' {')
            if ($ConnectToTenant) { $line.Add('        Connect-MgGraph -Scopes ''Directory.Read.All''') }
            if ($ApplyChange) { $line.Add('        & $script:DeploymentScriptPath -Apply') }
            $line.Add('        $true | Should -BeTrue')
            $line.Add('    }')
            $line.Add('}')
            if ($UnparsableScenario) { $line.Add('function {') }

            if (-not $OmitScenarioFile) {
                Set-Content -LiteralPath (Join-Path $integrationRoot $script:ScenarioFileName) `
                    -Value ($line -join [Environment]::NewLine) -Encoding utf8
            }
        }

        if (-not $OmitFixtureRoot) {
            $fixtureRoot = Join-Path $testRoot 'fixtures'
            New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null

            if (-not $OmitFixtureGroup) {
                $groupRoot = Join-Path $fixtureRoot 'com002'
                New-Item -ItemType Directory -Path $groupRoot -Force | Out-Null

                if (-not $EmptyFixtureGroup) {
                    Set-Content -LiteralPath (Join-Path $groupRoot 'parameters.complete.json') -Value '{}' -Encoding utf8
                }
            }

            if ($LooseFixture) {
                Set-Content -LiteralPath (Join-Path $fixtureRoot 'parameters.loose.json') -Value '{}' -Encoding utf8
            }
        }

        return $testRoot
    }
}

Describe 'TST-001 the test layout the integration suite is authored into' {

    Context 'Negative: the root does not describe a suite at all' {

        It 'reports TestRootNotFound when the test root names nothing' {
            # Arrange
            $missingRoot = ''

            # Act
            $result = Get-TestLayoutResult -TestRoot $missingRoot

            # Assert
            $result.Finding | Should -Contain 'TestRootNotFound' -Because 'a layout resolved from a path that names no directory is a layout nobody can add a scenario to'
        }

        It 'reports UnitSuiteNotFound when there is no unit suite' {
            # Arrange
            $layoutRoot = New-LayoutFixture -Root $TestDrive -OmitUnitSuite

            # Act
            $result = Get-TestLayoutResult -TestRoot $layoutRoot

            # Assert
            $result.Finding | Should -Contain 'UnitSuiteNotFound' -Because 'integration scenarios that no unit suite backs are the only place a defect can be caught, and by then it is already in a tenant'
        }

        It 'reports UnitSuiteEmpty when the unit suite holds no tests' {
            # Arrange
            $layoutRoot = New-LayoutFixture -Root $TestDrive -EmptyUnitSuite

            # Act
            $result = Get-TestLayoutResult -TestRoot $layoutRoot

            # Assert
            $result.Finding | Should -Contain 'UnitSuiteEmpty' -Because 'a unit directory carrying no test file is a directory, not a suite, and satisfies the layout without asserting anything'
        }
    }

    Context 'Negative: the integration suite has nowhere to put a scenario' {

        It 'reports IntegrationSuiteNotFound when there is no integration suite' {
            # Arrange
            $layoutRoot = New-LayoutFixture -Root $TestDrive -OmitIntegrationSuite

            # Act
            $result = Get-TestLayoutResult -TestRoot $layoutRoot

            # Assert
            $result.Finding | Should -Contain 'IntegrationSuiteNotFound' -Because 'the matrix scenarios are required to live under this suite, so with no suite there is no path for them to be authored into'
        }

        It 'reports IntegrationScenarioFileNotFound when the scenario file is absent' {
            # Arrange
            $layoutRoot = New-LayoutFixture -Root $TestDrive -OmitScenarioFile

            # Act
            $result = Get-TestLayoutResult -TestRoot $layoutRoot

            # Assert
            $result.Finding | Should -Contain 'IntegrationScenarioFileNotFound' -Because 'the ten matrix scenarios are required at this exact path, and a suite without it sends them somewhere nothing holds them to an offline seam'
        }

        It 'reports IntegrationSuiteNotParsable when a scenario file does not parse' {
            # Arrange
            $layoutRoot = New-LayoutFixture -Root $TestDrive -UnparsableScenario

            # Act
            $result = Get-TestLayoutResult -TestRoot $layoutRoot

            # Assert
            $result.Finding | Should -Contain 'IntegrationSuiteNotParsable' -Because 'a scenario file that does not parse cannot be read for what it reaches for, so every offline guarantee below is unenforced on it'
        }
    }

    Context 'Negative: the integration suite reaches for a live tenant' {

        It 'reports IntegrationSuiteRequiresTenantModule when a scenario requires a tenant module' {
            # Arrange
            $layoutRoot = New-LayoutFixture -Root $TestDrive -RequireTenantModule

            # Act
            $result = Get-TestLayoutResult -TestRoot $layoutRoot

            # Assert
            $result.Finding | Should -Contain 'IntegrationSuiteRequiresTenantModule' -Because 'a scenario that requires Microsoft.Graph or ExchangeOnlineManagement cannot be discovered where neither is installed, so it silently never runs'
        }

        It 'reports IntegrationSuiteImportsTenantModule when a scenario imports a tenant module' {
            # Arrange
            $layoutRoot = New-LayoutFixture -Root $TestDrive -ImportTenantModule

            # Act
            $result = Get-TestLayoutResult -TestRoot $layoutRoot

            # Assert
            $result.Finding | Should -Contain 'IntegrationSuiteImportsTenantModule' -Because 'importing the real tenant module is how a mocked seam quietly becomes a live one'
        }

        It 'reports IntegrationSuiteConnectsToTenant when a scenario opens a tenant connection' {
            # Arrange
            $layoutRoot = New-LayoutFixture -Root $TestDrive -ConnectToTenant

            # Act
            $result = Get-TestLayoutResult -TestRoot $layoutRoot

            # Assert
            $result.Finding | Should -Contain 'IntegrationSuiteConnectsToTenant' -Because 'a scenario that calls a connect command has left the injectable seam and is talking to whichever tenant the runner happens to be signed in to'
        }

        It 'reports IntegrationSuiteAppliesChange when a scenario passes the apply switch' {
            # Arrange
            $layoutRoot = New-LayoutFixture -Root $TestDrive -ApplyChange

            # Act
            $result = Get-TestLayoutResult -TestRoot $layoutRoot

            # Assert
            $result.Finding | Should -Contain 'IntegrationSuiteAppliesChange' -Because 'an apply run started by the test suite mutates a tenant nobody previewed or approved the change against'
        }

        It 'reports IntegrationSuiteCarriesSecret when a scenario carries a literal secret' {
            # Arrange
            $layoutRoot = New-LayoutFixture -Root $TestDrive -CarryPlantedSecret

            # Act
            $result = Get-TestLayoutResult -TestRoot $layoutRoot

            # Assert
            $result.Finding | Should -Contain 'IntegrationSuiteCarriesSecret' -Because 'a credential literal in a committed test is a published credential, whether or not the test ever uses it'
        }
    }

    Context 'Negative: the fixtures are not grouped by the collector they feed' {

        It 'reports FixtureRootNotFound when there is no fixture root' {
            # Arrange
            $layoutRoot = New-LayoutFixture -Root $TestDrive -OmitFixtureRoot

            # Act
            $result = Get-TestLayoutResult -TestRoot $layoutRoot

            # Assert
            $result.Finding | Should -Contain 'FixtureRootNotFound' -Because 'with no fixture root every scenario inlines its own tenant shape and no two scenarios are measured against the same one'
        }

        It 'reports FixtureGroupNotFound when the fixture root holds no group' {
            # Arrange
            $layoutRoot = New-LayoutFixture -Root $TestDrive -OmitFixtureGroup

            # Act
            $result = Get-TestLayoutResult -TestRoot $layoutRoot

            # Assert
            $result.Finding | Should -Contain 'FixtureGroupNotFound' -Because 'an ungrouped fixture root is a flat bag in which nothing says which collector a fixture belongs to'
        }

        It 'reports FixtureNotGrouped when a fixture sits loose at the fixture root' {
            # Arrange
            $layoutRoot = New-LayoutFixture -Root $TestDrive -LooseFixture

            # Act
            $result = Get-TestLayoutResult -TestRoot $layoutRoot

            # Assert
            $result.Finding | Should -Contain 'FixtureNotGrouped' -Because 'a loose fixture is owned by no collector, so nothing fails when the collector it was written for stops reading it'
        }

        It 'reports FixtureGroupEmpty when a fixture group holds no fixture' {
            # Arrange
            $layoutRoot = New-LayoutFixture -Root $TestDrive -EmptyFixtureGroup

            # Act
            $result = Get-TestLayoutResult -TestRoot $layoutRoot

            # Assert
            $result.Finding | Should -Contain 'FixtureGroupEmpty' -Because 'an empty group satisfies the grouping rule while supplying nothing, which is the grouping made ceremonial'
        }
    }

    Context 'Positive: the shipped layout holds the scenarios offline' {

        It 'resolves the shipped test tree as a layout the matrix scenarios can be authored into without a tenant' {
            # Arrange
            $shippedRoot = $script:ShippedTestRoot

            # Act
            $result = Get-TestLayoutResult -TestRoot $shippedRoot

            # Assert
            $result.Satisfied | Should -BeTrue -Because "the shipped layout must carry a unit suite, this scenario file, grouped fixtures and an integration suite that requires no tenant module, opens no connection, applies nothing and carries no secret, yet it reported $($result.Finding -join ', ')"
        }
    }
}
