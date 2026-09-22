#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:EvidenceScriptPath = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'
    $script:DeploymentScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:SharedModuleName = 'ExchangeOnlineBaseline.Common.psm1'

    # COM-007 requires both entry scripts to draw their configuration from one shared function, so
    # neither can drift from the other's resolved object or canonical hash.
    $script:SharedContextFunction = 'Get-BaselineContext'

    $script:ModuleOwnedCapability = @(
        [pscustomobject]@{
            Capability  = 'ConfigurationResolution'
            NamePattern = '(?i)(resolve|resolved).*(config|configuration)'
            BodyPattern = '__ADMIN_REQUIRED'
        }
        [pscustomobject]@{
            Capability  = 'ConfigurationValidation'
            NamePattern = '(?i)^(assert|validate|test)-.*(config|configuration|baseline|desiredstate)'
            BodyPattern = '(?i)\bTest-Json\b'
        }
        [pscustomobject]@{
            Capability  = 'ConfigurationHashing'
            NamePattern = '(?i)hash'
            BodyPattern = '(?i)\b(SHA256|HashData|Get-FileHash)\b'
        }
        [pscustomobject]@{
            Capability  = 'NormalizedComparison'
            NamePattern = '(?i)^compare-'
            BodyPattern = '(?i)\bCompare-Object\b'
        }
        [pscustomobject]@{
            Capability  = 'EntitlementDecision'
            NamePattern = '(?i)(entitle|applicab|riskacceptance|controlresult)'
            BodyPattern = '(?i)licensing\.(messaging|compliance)Tier'
        }
    )

    $script:MutatingVerbs = @('Set', 'New', 'Remove', 'Enable', 'Disable', 'Update', 'Add', 'Clear', 'Reset', 'Restore', 'Rename', 'Move')
    $script:LocalNouns = @(
        'Item', 'ItemProperty', 'Content', 'ChildItem', 'Variable', 'Alias', 'Module', 'Object',
        'Member', 'StrictMode', 'Location', 'TimeSpan', 'Guid', 'TemporaryFile', 'PSBreakpoint'
    )

    # The boundary is tenant mutation. The shared module reaches no service of its own, so a
    # `New-` verb it exports builds a local record and is read against the manifest rather than
    # restated here, so an added export cannot silently become an unreviewed exemption.
    $script:SharedModuleCommand = @(
        [string[]](Import-PowerShellDataFile -LiteralPath (Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psd1')).FunctionsToExport
    )

    function Get-ScriptAst {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        $tokens = $null
        $errors = $null
        return [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    }

    function Get-InvokedCommandName {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [System.Management.Automation.Language.Ast]$Ast
        )

        return @(
            $Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } |
                Where-Object { $_ }
        )
    }

    function Get-TenantMutatingCommand {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [System.Management.Automation.Language.Ast]$Ast
        )

        $localFunctions = @(
            $Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
                ForEach-Object { $_.Name }
        )

        $verbPattern = '^(?<verb>{0})-(?<noun>[A-Za-z0-9]+)$' -f ($script:MutatingVerbs -join '|')
        $mutating = [System.Collections.Generic.List[string]]::new()

        foreach ($name in (Get-InvokedCommandName -Ast $Ast)) {
            if ($name -notmatch $verbPattern) { continue }
            if ($Matches['noun'] -in $script:LocalNouns) { continue }
            if ($name -in $localFunctions) { continue }
            if ($name -in $script:SharedModuleCommand) { continue }
            $mutating.Add($name)
        }

        return @($mutating | Sort-Object -Unique)
    }

    function Get-DuplicateModuleHelper {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [System.Management.Automation.Language.Ast]$Ast
        )

        $duplicates = [System.Collections.Generic.List[string]]::new()

        $functions = @(
            $Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
        )

        foreach ($function in $functions) {
            $body = $function.Body.Extent.Text

            foreach ($capability in $script:ModuleOwnedCapability) {
                if ($function.Name -notmatch $capability.NamePattern -and $body -notmatch $capability.BodyPattern) { continue }
                $duplicates.Add(('{0}:{1}' -f $function.Name, $capability.Capability))
            }
        }

        return @($duplicates | Sort-Object -Unique)
    }

    function Get-EvidenceMigrationResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$EvidenceScriptPath,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$DeploymentScriptPath,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$ModulePath
        )

        $result = [ordered]@{
            Satisfied  = $false
            Reason     = $null
            Violations = @()
        }

        if ([string]::IsNullOrWhiteSpace($EvidenceScriptPath) -or -not (Test-Path -LiteralPath $EvidenceScriptPath -PathType Leaf)) {
            $result.Reason = 'EvidenceScriptMissing'
            return [pscustomobject]$result
        }

        if ([string]::IsNullOrWhiteSpace($DeploymentScriptPath) -or -not (Test-Path -LiteralPath $DeploymentScriptPath -PathType Leaf)) {
            $result.Reason = 'DeploymentScriptMissing'
            return [pscustomobject]$result
        }

        if ([string]::IsNullOrWhiteSpace($ModulePath) -or -not (Test-Path -LiteralPath $ModulePath -PathType Leaf)) {
            $result.Reason = 'SharedModuleMissing'
            return [pscustomobject]$result
        }

        $evidenceContent = Get-Content -LiteralPath $EvidenceScriptPath -Raw
        if ($evidenceContent -notmatch ('Import-Module[^\r\n]*{0}' -f [regex]::Escape($script:SharedModuleName))) {
            $result.Reason = 'SharedModuleNotImported'
            return [pscustomobject]$result
        }

        $evidenceAst = Get-ScriptAst -Path $EvidenceScriptPath

        $duplicates = Get-DuplicateModuleHelper -Ast $evidenceAst
        if ($duplicates.Count -gt 0) {
            $result.Reason = 'DuplicateModuleHelper'
            $result.Violations = $duplicates
            return [pscustomobject]$result
        }

        # The known placeholder defect: the evidence script parsed the baseline and the parameter
        # file itself, so it evaluated unresolved administrator inputs as if they were desired state.
        if ($evidenceContent -match 'Get-Content[^\r\n]*\$ConfigurationPath') {
            $result.Reason = 'RawConfigurationRead'
            return [pscustomobject]$result
        }

        if ($evidenceContent -match 'Get-Content[^\r\n]*\$ParameterPath') {
            $result.Reason = 'RawParameterRead'
            return [pscustomobject]$result
        }

        if ($script:SharedContextFunction -notin (Get-InvokedCommandName -Ast $evidenceAst)) {
            $result.Reason = 'EvidenceContextNotDelegated'
            $result.Violations = @($script:SharedContextFunction)
            return [pscustomobject]$result
        }

        $deploymentAst = Get-ScriptAst -Path $DeploymentScriptPath
        if ($script:SharedContextFunction -notin (Get-InvokedCommandName -Ast $deploymentAst)) {
            $result.Reason = 'DeploymentContextNotShared'
            $result.Violations = @($script:SharedContextFunction)
            return [pscustomobject]$result
        }

        $mutations = Get-TenantMutatingCommand -Ast $evidenceAst
        if ($mutations.Count -gt 0) {
            $result.Reason = 'MutationInEvidenceScript'
            $result.Violations = $mutations
            return [pscustomobject]$result
        }

        $result.Satisfied = $true
        $result.Reason = 'EvidenceMigrationSatisfied'
        $result.Violations = @()
        return [pscustomobject]$result
    }

    function New-EvidenceMigrationFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Root,

            [switch]$OmitEvidenceScript,
            [switch]$OmitDeploymentScript,
            [switch]$OmitSharedModule,
            [switch]$OmitEvidenceImport,
            [switch]$ReadRawConfiguration,
            [switch]$ReadRawParameter,
            [switch]$OmitEvidenceContextCall,
            [switch]$OmitDeploymentContextCall,
            [switch]$MutateInEvidenceScript,

            [string]$InjectHelperName,
            [string]$InjectHelperBody
        )

        $fixtureRoot = Join-Path $Root ([guid]::NewGuid().ToString('N'))
        $scriptDirectory = Join-Path $fixtureRoot 'scripts'
        New-Item -ItemType Directory -Path $scriptDirectory -Force | Out-Null

        $modulePath = Join-Path $scriptDirectory $script:SharedModuleName
        if (-not $OmitSharedModule) {
            Set-Content -LiteralPath $modulePath -Value 'function Get-BaselineContext { }' -Encoding utf8
        }

        $importLine = 'Import-Module (Join-Path $PSScriptRoot ''ExchangeOnlineBaseline.Common.psm1'') -Force'
        $contextLine = '$context = Get-BaselineContext -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath -SchemaPath $SchemaPath'

        $evidenceLines = [System.Collections.Generic.List[string]]::new()
        if (-not $OmitEvidenceImport) { $evidenceLines.Add($importLine) }
        $evidenceLines.Add('Set-StrictMode -Version Latest')
        $evidenceLines.Add('function Add-Check { param($Name) $Name }')

        if ($PSBoundParameters.ContainsKey('InjectHelperName') -or $PSBoundParameters.ContainsKey('InjectHelperBody')) {
            $helperName = if ($PSBoundParameters.ContainsKey('InjectHelperName')) { $InjectHelperName } else { 'Get-LocalHelper' }
            $helperBody = if ($PSBoundParameters.ContainsKey('InjectHelperBody')) { $InjectHelperBody } else { '$Value' }
            $evidenceLines.Add(('function {0} {{ param($Value) {1} }}' -f $helperName, $helperBody))
        }

        if ($ReadRawConfiguration) {
            $evidenceLines.Add('$baseline = Get-Content -Path $ConfigurationPath -Raw | ConvertFrom-Json')
        }
        if ($ReadRawParameter) {
            $evidenceLines.Add('$supplied = Get-Content -Path $ParameterPath -Raw | ConvertFrom-Json')
        }
        if (-not $OmitEvidenceContextCall) { $evidenceLines.Add($contextLine) }
        $evidenceLines.Add('$transport = Get-TransportConfig')
        $evidenceLines.Add('New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null')
        if ($MutateInEvidenceScript) {
            $evidenceLines.Add('Set-TransportConfig -SmtpClientAuthenticationDisabled $true')
        }
        $evidenceLines.Add('Add-Check -Name ''EXO-002''')

        $deploymentLines = [System.Collections.Generic.List[string]]::new()
        $deploymentLines.Add($importLine)
        $deploymentLines.Add('Set-StrictMode -Version Latest')
        if (-not $OmitDeploymentContextCall) { $deploymentLines.Add($contextLine) }
        $deploymentLines.Add('Set-TransportConfig -SmtpClientAuthenticationDisabled $true')

        $evidencePath = Join-Path $scriptDirectory 'Test-ExchangeOnlineBaseline.ps1'
        $deploymentPath = Join-Path $scriptDirectory 'Deploy-ExchangeOnlineBaseline.ps1'

        if (-not $OmitEvidenceScript) {
            Set-Content -LiteralPath $evidencePath -Value ($evidenceLines -join [Environment]::NewLine) -Encoding utf8
        }
        if (-not $OmitDeploymentScript) {
            Set-Content -LiteralPath $deploymentPath -Value ($deploymentLines -join [Environment]::NewLine) -Encoding utf8
        }

        return [pscustomobject]@{
            EvidenceScriptPath   = $evidencePath
            DeploymentScriptPath = $deploymentPath
            ModulePath           = $modulePath
        }
    }
}

Describe 'COM-007-A1 evidence entry script migration and single configuration source' {

    Context 'Negative: the evidence script is not drawing from the shared configuration source' {

        It 'reports EvidenceScriptMissing when the evidence script is absent' {
            # Arrange
            $fixture = New-EvidenceMigrationFixture -Root $TestDrive -OmitEvidenceScript

            # Act
            $result = Get-EvidenceMigrationResult -EvidenceScriptPath $fixture.EvidenceScriptPath -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an absent evidence script cannot have been migrated'
            $result.Reason | Should -Be 'EvidenceScriptMissing'
        }

        It 'reports DeploymentScriptMissing when the deployment script is absent' {
            # Arrange
            $fixture = New-EvidenceMigrationFixture -Root $TestDrive -OmitDeploymentScript

            # Act
            $result = Get-EvidenceMigrationResult -EvidenceScriptPath $fixture.EvidenceScriptPath -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'parity has no counterpart without the deployment script'
            $result.Reason | Should -Be 'DeploymentScriptMissing'
        }

        It 'reports SharedModuleMissing when the shared module is absent' {
            # Arrange
            $fixture = New-EvidenceMigrationFixture -Root $TestDrive -OmitSharedModule

            # Act
            $result = Get-EvidenceMigrationResult -EvidenceScriptPath $fixture.EvidenceScriptPath -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'there is no shared source without the shared module'
            $result.Reason | Should -Be 'SharedModuleMissing'
        }

        It 'reports SharedModuleNotImported when the evidence script does not import the shared module' {
            # Arrange
            $fixture = New-EvidenceMigrationFixture -Root $TestDrive -OmitEvidenceImport

            # Act
            $result = Get-EvidenceMigrationResult -EvidenceScriptPath $fixture.EvidenceScriptPath -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'the evidence script must consume the shared module'
            $result.Reason | Should -Be 'SharedModuleNotImported'
        }

        It 'reports DuplicateModuleHelper when a local helper name claims configuration resolution' {
            # Arrange
            $fixture = New-EvidenceMigrationFixture -Root $TestDrive -InjectHelperName 'ConvertTo-ResolvedConfiguration'

            # Act
            $result = Get-EvidenceMigrationResult -EvidenceScriptPath $fixture.EvidenceScriptPath -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'configuration resolution belongs to the shared module'
            $result.Reason | Should -Be 'DuplicateModuleHelper'
        }

        It 'reports DuplicateModuleHelper when a local helper body substitutes administrator placeholders' {
            # Arrange
            $fixture = New-EvidenceMigrationFixture -Root $TestDrive -InjectHelperName 'Get-LocalTemplate' -InjectHelperBody '$Value -replace ''__ADMIN_REQUIRED:PRIMARY__'', ''contoso.com'''

            # Act
            $result = Get-EvidenceMigrationResult -EvidenceScriptPath $fixture.EvidenceScriptPath -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'placeholder substitution is the shared module resolution implementation'
            $result.Reason | Should -Be 'DuplicateModuleHelper'
        }

        It 'reports DuplicateModuleHelper when a local helper name claims an entitlement decision' {
            # Arrange
            $fixture = New-EvidenceMigrationFixture -Root $TestDrive -InjectHelperName 'Get-Entitlement'

            # Act
            $result = Get-EvidenceMigrationResult -EvidenceScriptPath $fixture.EvidenceScriptPath -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'entitlement decisions belong to the shared module'
            $result.Reason | Should -Be 'DuplicateModuleHelper'
        }

        It 'names the duplicate helper and the capability it claims' {
            # Arrange
            $fixture = New-EvidenceMigrationFixture -Root $TestDrive -InjectHelperName 'Get-Entitlement'

            # Act
            $result = Get-EvidenceMigrationResult -EvidenceScriptPath $fixture.EvidenceScriptPath -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Violations | Should -Contain 'Get-Entitlement:EntitlementDecision'
        }

        It 'reports RawConfigurationRead when the evidence script parses the baseline file itself' {
            # Arrange
            $fixture = New-EvidenceMigrationFixture -Root $TestDrive -ReadRawConfiguration

            # Act
            $result = Get-EvidenceMigrationResult -EvidenceScriptPath $fixture.EvidenceScriptPath -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'reading the raw baseline evaluates unresolved administrator placeholders as desired state'
            $result.Reason | Should -Be 'RawConfigurationRead'
        }

        It 'reports RawParameterRead when the evidence script parses the parameter file itself' {
            # Arrange
            $fixture = New-EvidenceMigrationFixture -Root $TestDrive -ReadRawParameter

            # Act
            $result = Get-EvidenceMigrationResult -EvidenceScriptPath $fixture.EvidenceScriptPath -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'administrator inputs must reach evidence through the resolved configuration, not a second parse'
            $result.Reason | Should -Be 'RawParameterRead'
        }

        It 'reports EvidenceContextNotDelegated when the evidence script never builds the shared context' {
            # Arrange
            $fixture = New-EvidenceMigrationFixture -Root $TestDrive -OmitEvidenceContextCall

            # Act
            $result = Get-EvidenceMigrationResult -EvidenceScriptPath $fixture.EvidenceScriptPath -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'importing the module is not enough; the configuration must come from the shared context'
            $result.Reason | Should -Be 'EvidenceContextNotDelegated'
        }

        It 'reports DeploymentContextNotShared when the deployment script builds its configuration another way' {
            # Arrange
            $fixture = New-EvidenceMigrationFixture -Root $TestDrive -OmitDeploymentContextCall

            # Act
            $result = Get-EvidenceMigrationResult -EvidenceScriptPath $fixture.EvidenceScriptPath -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'two different configuration sources cannot be proved to agree'
            $result.Reason | Should -Be 'DeploymentContextNotShared'
        }

        It 'reports MutationInEvidenceScript when the evidence script mutates the tenant' {
            # Arrange
            $fixture = New-EvidenceMigrationFixture -Root $TestDrive -MutateInEvidenceScript

            # Act
            $result = Get-EvidenceMigrationResult -EvidenceScriptPath $fixture.EvidenceScriptPath -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'evidence collection must stay read-only'
            $result.Reason | Should -Be 'MutationInEvidenceScript'
        }
    }

    Context 'Positive: both shipped entry scripts draw from one shared configuration source' {

        It 'imports the shared module, defines no module-owned helper, never parses the baseline or parameter file itself, shares the context function with deployment, and stays read-only' {
            # Arrange
            $evidenceScriptPath = $script:EvidenceScriptPath
            $deploymentScriptPath = $script:DeploymentScriptPath
            $modulePath = $script:ModulePath

            # Act
            $result = Get-EvidenceMigrationResult -EvidenceScriptPath $evidenceScriptPath -DeploymentScriptPath $deploymentScriptPath -ModulePath $modulePath

            # Assert
            $result.Satisfied | Should -BeTrue -Because "the evidence script must satisfy COM-007 but reported '$($result.Reason)' for '$($result.Violations -join ', ')'"
            $result.Reason | Should -Be 'EvidenceMigrationSatisfied'
        }
    }
}
