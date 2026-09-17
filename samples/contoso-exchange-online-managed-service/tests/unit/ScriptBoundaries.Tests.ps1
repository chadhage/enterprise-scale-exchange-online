#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:DeploymentScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'
    $script:EvidenceScriptPath = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'
    $script:UnitTestDirectory = $PSScriptRoot

    # Verbs that change state, paired with the nouns that are local to the host rather than the tenant.
    $script:MutatingVerbs = @('Set', 'New', 'Remove', 'Enable', 'Disable', 'Update', 'Add', 'Clear', 'Reset', 'Restore', 'Rename', 'Move')
    $script:LocalNouns = @(
        'Item', 'ItemProperty', 'Content', 'ChildItem', 'Variable', 'Alias', 'Module', 'Object',
        'Member', 'StrictMode', 'Location', 'TimeSpan', 'Guid', 'TemporaryFile', 'PSBreakpoint'
    )
    $script:SharedModuleName = 'ExchangeOnlineBaseline.Common.psm1'

    function Get-TenantMutatingCommand {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)

        $localFunctions = @(
            $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
                ForEach-Object { $_.Name }
        )

        $commandNames = @(
            $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } |
                Where-Object { $_ }
        )

        $verbPattern = '^(?<verb>{0})-(?<noun>[A-Za-z0-9]+)$' -f ($script:MutatingVerbs -join '|')
        $mutating = [System.Collections.Generic.List[string]]::new()

        foreach ($name in $commandNames) {
            if ($name -notmatch $verbPattern) { continue }
            if ($Matches['noun'] -in $script:LocalNouns) { continue }
            if ($name -in $localFunctions) { continue }
            $mutating.Add($name)
        }

        return @($mutating | Sort-Object -Unique)
    }

    function Test-SharedModuleConsumption {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        $content = Get-Content -LiteralPath $Path -Raw
        return [bool]($content -match ('Import-Module[^\r\n]*{0}' -f [regex]::Escape($script:SharedModuleName)))
    }

    function Get-ScriptBoundaryResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$DeploymentScriptPath,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$EvidenceScriptPath,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$UnitTestDirectory
        )

        $result = [ordered]@{
            Satisfied  = $false
            Reason     = $null
            Violations = @()
        }

        if ([string]::IsNullOrWhiteSpace($DeploymentScriptPath) -or -not (Test-Path -LiteralPath $DeploymentScriptPath -PathType Leaf)) {
            $result.Reason = 'DeploymentScriptMissing'
            return [pscustomobject]$result
        }

        if ([string]::IsNullOrWhiteSpace($EvidenceScriptPath) -or -not (Test-Path -LiteralPath $EvidenceScriptPath -PathType Leaf)) {
            $result.Reason = 'EvidenceScriptMissing'
            return [pscustomobject]$result
        }

        $evidenceMutations = Get-TenantMutatingCommand -Path $EvidenceScriptPath
        if ($evidenceMutations.Count -gt 0) {
            $result.Reason = 'MutationOutsideDeployment'
            $result.Violations = $evidenceMutations
            return [pscustomobject]$result
        }

        $deploymentMutations = Get-TenantMutatingCommand -Path $DeploymentScriptPath
        if ($deploymentMutations.Count -eq 0) {
            $result.Reason = 'MutationOwnershipAbsent'
            return [pscustomobject]$result
        }

        if (-not (Test-SharedModuleConsumption -Path $DeploymentScriptPath)) {
            $result.Reason = 'DeploymentModuleNotImported'
            return [pscustomobject]$result
        }

        if (-not (Test-SharedModuleConsumption -Path $EvidenceScriptPath)) {
            $result.Reason = 'EvidenceModuleNotImported'
            return [pscustomobject]$result
        }

        $consumingTests = @()
        if (-not [string]::IsNullOrWhiteSpace($UnitTestDirectory) -and (Test-Path -LiteralPath $UnitTestDirectory -PathType Container)) {
            $consumingTests = @(
                Get-ChildItem -LiteralPath $UnitTestDirectory -Filter '*.Tests.ps1' -File |
                    Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match [regex]::Escape($script:SharedModuleName) }
            )
        }

        if ($consumingTests.Count -eq 0) {
            $result.Reason = 'UnitTestsModuleNotConsumed'
            return [pscustomobject]$result
        }

        $result.Satisfied = $true
        $result.Reason = 'BoundariesSatisfied'
        return [pscustomobject]$result
    }

    function New-BoundaryFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Root,

            [switch]$OmitDeploymentScript,
            [switch]$OmitEvidenceScript,
            [switch]$MutateInEvidenceScript,
            [switch]$RemoveDeploymentMutation,
            [switch]$OmitDeploymentImport,
            [switch]$OmitEvidenceImport,
            [switch]$OmitUnitTestConsumption
        )

        $fixtureRoot = Join-Path $Root ([guid]::NewGuid().ToString('N'))
        $scriptDirectory = Join-Path $fixtureRoot 'scripts'
        $unitDirectory = Join-Path $fixtureRoot 'tests/unit'
        New-Item -ItemType Directory -Path $scriptDirectory -Force | Out-Null
        New-Item -ItemType Directory -Path $unitDirectory -Force | Out-Null

        $importLine = 'Import-Module (Join-Path $PSScriptRoot ''ExchangeOnlineBaseline.Common.psm1'') -Force'

        $deploymentLines = [System.Collections.Generic.List[string]]::new()
        if (-not $OmitDeploymentImport) { $deploymentLines.Add($importLine) }
        $deploymentLines.Add('Set-StrictMode -Version Latest')
        $deploymentLines.Add('function Set-OrganizationControls { param($State) }')
        if (-not $RemoveDeploymentMutation) {
            $deploymentLines.Add('Set-TransportConfig -SmtpClientAuthenticationDisabled $true')
        }
        $deploymentLines.Add('Set-OrganizationControls -State $null')

        $evidenceLines = [System.Collections.Generic.List[string]]::new()
        if (-not $OmitEvidenceImport) { $evidenceLines.Add($importLine) }
        $evidenceLines.Add('Set-StrictMode -Version Latest')
        $evidenceLines.Add('function Add-Check { param($Name) }')
        $evidenceLines.Add('$transport = Get-TransportConfig')
        $evidenceLines.Add('New-Item -ItemType Directory -Path $PSScriptRoot -Force | Out-Null')
        $evidenceLines.Add('Add-Check -Name ''EXO-002''')
        if ($MutateInEvidenceScript) {
            $evidenceLines.Add('Set-TransportConfig -SmtpClientAuthenticationDisabled $true')
        }

        $deploymentPath = Join-Path $scriptDirectory 'Deploy-ExchangeOnlineBaseline.ps1'
        $evidencePath = Join-Path $scriptDirectory 'Test-ExchangeOnlineBaseline.ps1'

        if (-not $OmitDeploymentScript) {
            Set-Content -LiteralPath $deploymentPath -Value ($deploymentLines -join [Environment]::NewLine) -Encoding utf8
        }

        if (-not $OmitEvidenceScript) {
            Set-Content -LiteralPath $evidencePath -Value ($evidenceLines -join [Environment]::NewLine) -Encoding utf8
        }

        $unitTestLines = [System.Collections.Generic.List[string]]::new()
        if (-not $OmitUnitTestConsumption) {
            $unitTestLines.Add('$modulePath = Join-Path $PSScriptRoot ''ExchangeOnlineBaseline.Common.psm1''')
        }
        $unitTestLines.Add('Describe ''fixture'' { It ''passes'' { $true | Should -BeTrue } }')
        Set-Content -LiteralPath (Join-Path $unitDirectory 'Fixture.Tests.ps1') -Value ($unitTestLines -join [Environment]::NewLine) -Encoding utf8

        return [pscustomobject]@{
            DeploymentScriptPath = $deploymentPath
            EvidenceScriptPath   = $evidencePath
            UnitTestDirectory    = $unitDirectory
        }
    }
}

Describe 'ARC-002-A script responsibility boundaries' {

    Context 'Negative: boundaries are not satisfied' {

        It 'reports DeploymentScriptMissing when the deployment script is absent' {
            # Arrange
            $fixture = New-BoundaryFixture -Root $TestDrive -OmitDeploymentScript

            # Act
            $result = Get-ScriptBoundaryResult -DeploymentScriptPath $fixture.DeploymentScriptPath -EvidenceScriptPath $fixture.EvidenceScriptPath -UnitTestDirectory $fixture.UnitTestDirectory

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an absent deployment script cannot own tenant mutation'
            $result.Reason | Should -Be 'DeploymentScriptMissing'
        }

        It 'reports EvidenceScriptMissing when the evidence script is absent' {
            # Arrange
            $fixture = New-BoundaryFixture -Root $TestDrive -OmitEvidenceScript

            # Act
            $result = Get-ScriptBoundaryResult -DeploymentScriptPath $fixture.DeploymentScriptPath -EvidenceScriptPath $fixture.EvidenceScriptPath -UnitTestDirectory $fixture.UnitTestDirectory

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an absent evidence script cannot perform read-only collection'
            $result.Reason | Should -Be 'EvidenceScriptMissing'
        }

        It 'reports MutationOutsideDeployment when the evidence script mutates the tenant' {
            # Arrange
            $fixture = New-BoundaryFixture -Root $TestDrive -MutateInEvidenceScript

            # Act
            $result = Get-ScriptBoundaryResult -DeploymentScriptPath $fixture.DeploymentScriptPath -EvidenceScriptPath $fixture.EvidenceScriptPath -UnitTestDirectory $fixture.UnitTestDirectory

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'evidence collection must stay read-only'
            $result.Reason | Should -Be 'MutationOutsideDeployment'
            $result.Violations | Should -Be @('Set-TransportConfig')
        }

        It 'reports MutationOwnershipAbsent when the deployment script performs no tenant mutation' {
            # Arrange
            $fixture = New-BoundaryFixture -Root $TestDrive -RemoveDeploymentMutation

            # Act
            $result = Get-ScriptBoundaryResult -DeploymentScriptPath $fixture.DeploymentScriptPath -EvidenceScriptPath $fixture.EvidenceScriptPath -UnitTestDirectory $fixture.UnitTestDirectory

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'the deployment script must remain the owner of tenant mutation'
            $result.Reason | Should -Be 'MutationOwnershipAbsent'
        }

        It 'reports DeploymentModuleNotImported when the deployment script does not consume the shared module' {
            # Arrange
            $fixture = New-BoundaryFixture -Root $TestDrive -OmitDeploymentImport

            # Act
            $result = Get-ScriptBoundaryResult -DeploymentScriptPath $fixture.DeploymentScriptPath -EvidenceScriptPath $fixture.EvidenceScriptPath -UnitTestDirectory $fixture.UnitTestDirectory

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'both entry scripts must consume the shared module'
            $result.Reason | Should -Be 'DeploymentModuleNotImported'
        }

        It 'reports EvidenceModuleNotImported when the evidence script does not consume the shared module' {
            # Arrange
            $fixture = New-BoundaryFixture -Root $TestDrive -OmitEvidenceImport

            # Act
            $result = Get-ScriptBoundaryResult -DeploymentScriptPath $fixture.DeploymentScriptPath -EvidenceScriptPath $fixture.EvidenceScriptPath -UnitTestDirectory $fixture.UnitTestDirectory

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'both entry scripts must consume the shared module'
            $result.Reason | Should -Be 'EvidenceModuleNotImported'
        }

        It 'reports UnitTestsModuleNotConsumed when no unit test references the shared module' {
            # Arrange
            $fixture = New-BoundaryFixture -Root $TestDrive -OmitUnitTestConsumption

            # Act
            $result = Get-ScriptBoundaryResult -DeploymentScriptPath $fixture.DeploymentScriptPath -EvidenceScriptPath $fixture.EvidenceScriptPath -UnitTestDirectory $fixture.UnitTestDirectory

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'unit tests must consume the shared module'
            $result.Reason | Should -Be 'UnitTestsModuleNotConsumed'
        }
    }

    Context 'Positive: boundaries are satisfied' {

        It 'keeps tenant mutation in the deployment script while both scripts and unit tests consume the shared module' {
            # Arrange
            $deploymentPath = $script:DeploymentScriptPath
            $evidencePath = $script:EvidenceScriptPath
            $unitDirectory = $script:UnitTestDirectory

            # Act
            $result = Get-ScriptBoundaryResult -DeploymentScriptPath $deploymentPath -EvidenceScriptPath $evidencePath -UnitTestDirectory $unitDirectory

            # Assert
            $result.Satisfied | Should -BeTrue -Because "boundary violation: $($result.Reason) $($result.Violations -join ', ')"
        }
    }
}
