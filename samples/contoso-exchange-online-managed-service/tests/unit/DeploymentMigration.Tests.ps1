#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:DeploymentScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:SharedModuleName = 'ExchangeOnlineBaseline.Common.psm1'

    # COM-006 forbids the deployment entry script from owning any capability ARC-001 assigned to the
    # shared module. A helper is a duplicate when its name claims the capability or when its body
    # carries the implementation marker of that capability.
    $script:ModuleOwnedCapability = @(
        [pscustomobject]@{
            Capability     = 'ConfigurationResolution'
            NamePattern    = '(?i)(resolve|resolved).*(config|configuration)'
            BodyPattern    = '__ADMIN_REQUIRED'
            ModuleFunction = 'Resolve-BaselineConfiguration'
        }
        [pscustomobject]@{
            Capability     = 'ConfigurationValidation'
            NamePattern    = '(?i)^(assert|validate|test)-.*(config|configuration|baseline|desiredstate)'
            BodyPattern    = '(?i)\bTest-Json\b'
            ModuleFunction = 'Assert-BaselineConfiguration'
        }
        [pscustomobject]@{
            Capability     = 'ConfigurationHashing'
            NamePattern    = '(?i)hash'
            BodyPattern    = '(?i)\b(SHA256|HashData|Get-FileHash)\b'
            ModuleFunction = 'Get-BaselineConfigurationHash'
        }
        [pscustomobject]@{
            Capability     = 'NormalizedComparison'
            NamePattern    = '(?i)^compare-'
            BodyPattern    = '(?i)\bCompare-Object\b'
            ModuleFunction = 'Compare-NormalizedCollection'
        }
        [pscustomobject]@{
            Capability     = 'EntitlementDecision'
            NamePattern    = '(?i)(entitle|applicab|riskacceptance|controlresult)'
            BodyPattern    = '(?i)licensing\.(messaging|compliance)Tier'
            ModuleFunction = 'Get-ControlApplicability'
        }
    )

    # The shared module must perform resolution and validation on behalf of the deployment script,
    # either by direct invocation or through the one shared context function COM-007 introduced.
    $script:DelegatedModuleFunction = @(
        [pscustomobject]@{ Name = 'Resolve-BaselineConfiguration'; Reason = 'ResolutionNotDelegated' }
        [pscustomobject]@{ Name = 'Assert-BaselineConfiguration'; Reason = 'ValidationNotDelegated' }
    )

    $script:SharedContextFunction = 'Get-BaselineContext'

    $script:MutatingVerbs = @('Set', 'New', 'Remove', 'Enable', 'Disable', 'Update', 'Add', 'Clear', 'Reset', 'Restore', 'Rename', 'Move')
    $script:LocalNouns = @(
        'Item', 'ItemProperty', 'Content', 'ChildItem', 'Variable', 'Alias', 'Module', 'Object',
        'Member', 'StrictMode', 'Location', 'TimeSpan', 'Guid', 'TemporaryFile', 'PSBreakpoint'
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

        $commandNames = @(
            $Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
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

    function Get-SharedContextCapability {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ModulePath
        )

        $context = @(
            (Get-ScriptAst -Path $ModulePath).FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
                Where-Object { $_.Name -eq $script:SharedContextFunction }
        )

        if ($context.Count -eq 0) { return @() }

        return @(
            $context[0].Body.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } |
                Where-Object { $_ } |
                Sort-Object -Unique
        )
    }

    function Get-DuplicateModuleHelper {
        param(
            [Parameter(Mandatory)]
            [System.Management.Automation.Language.Ast]$Ast
        )

        $duplicates = [System.Collections.Generic.List[object]]::new()

        $functions = @(
            $Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
        )

        foreach ($function in $functions) {
            $body = $function.Body.Extent.Text

            foreach ($capability in $script:ModuleOwnedCapability) {
                $nameClaims = $function.Name -match $capability.NamePattern
                $bodyClaims = $body -match $capability.BodyPattern

                if (-not $nameClaims -and -not $bodyClaims) { continue }

                $duplicates.Add([pscustomobject]@{
                        Function       = $function.Name
                        Capability     = $capability.Capability
                        ModuleFunction = $capability.ModuleFunction
                        Evidence       = if ($nameClaims) { 'Name' } else { 'Body' }
                    })
            }
        }

        return @($duplicates)
    }

    function Get-DeploymentMigrationResult {
        [CmdletBinding()]
        param(
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

        if ([string]::IsNullOrWhiteSpace($DeploymentScriptPath) -or -not (Test-Path -LiteralPath $DeploymentScriptPath -PathType Leaf)) {
            $result.Reason = 'DeploymentScriptMissing'
            return [pscustomobject]$result
        }

        if ([string]::IsNullOrWhiteSpace($ModulePath) -or -not (Test-Path -LiteralPath $ModulePath -PathType Leaf)) {
            $result.Reason = 'SharedModuleMissing'
            return [pscustomobject]$result
        }

        $content = Get-Content -LiteralPath $DeploymentScriptPath -Raw
        if ($content -notmatch ('Import-Module[^\r\n]*{0}' -f [regex]::Escape($script:SharedModuleName))) {
            $result.Reason = 'SharedModuleNotImported'
            return [pscustomobject]$result
        }

        $ast = Get-ScriptAst -Path $DeploymentScriptPath

        $duplicates = Get-DuplicateModuleHelper -Ast $ast
        if ($duplicates.Count -gt 0) {
            $result.Reason = 'DuplicateModuleHelper'
            $result.Violations = @($duplicates | ForEach-Object { '{0}:{1}' -f $_.Function, $_.Capability } | Sort-Object -Unique)
            return [pscustomobject]$result
        }

        $commandNames = @(
            $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } |
                Where-Object { $_ }
        )

        $contextCapability = @()
        if ($script:SharedContextFunction -in $commandNames) {
            $contextCapability = Get-SharedContextCapability -ModulePath $ModulePath
        }

        foreach ($delegated in $script:DelegatedModuleFunction) {
            if ($delegated.Name -in $commandNames) { continue }
            if ($delegated.Name -in $contextCapability) { continue }

            $result.Reason = $delegated.Reason
            $result.Violations = @($delegated.Name)
            return [pscustomobject]$result
        }

        $mutations = Get-TenantMutatingCommand -Ast $ast
        if ($mutations.Count -eq 0) {
            $result.Reason = 'MutationOwnershipAbsent'
            return [pscustomobject]$result
        }

        $result.Satisfied = $true
        $result.Reason = 'DeploymentMigrationSatisfied'
        $result.Violations = @()
        return [pscustomobject]$result
    }

    function New-DeploymentMigrationFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Root,

            [switch]$OmitDeploymentScript,
            [switch]$OmitSharedModule,
            [switch]$OmitImport,
            [switch]$OmitResolutionCall,
            [switch]$OmitValidationCall,
            [switch]$RemoveMutation,
            [switch]$UseSharedContext,
            [switch]$ContextOmitsResolution,
            [switch]$ContextOmitsValidation,

            [string]$InjectHelperName,
            [string]$InjectHelperBody
        )

        $fixtureRoot = Join-Path $Root ([guid]::NewGuid().ToString('N'))
        $scriptDirectory = Join-Path $fixtureRoot 'scripts'
        New-Item -ItemType Directory -Path $scriptDirectory -Force | Out-Null

        $modulePath = Join-Path $scriptDirectory $script:SharedModuleName
        if (-not $OmitSharedModule) {
            $contextBody = [System.Collections.Generic.List[string]]::new()
            if (-not $ContextOmitsResolution) { $contextBody.Add('$resolution = Resolve-BaselineConfiguration -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath') }
            if (-not $ContextOmitsValidation) { $contextBody.Add('$validation = Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $SchemaPath') }

            $moduleLines = @(
                'function Resolve-BaselineConfiguration { }'
                'function Assert-BaselineConfiguration { }'
                ('function Get-BaselineContext {{ {0} }}' -f ($contextBody -join '; '))
            )
            Set-Content -LiteralPath $modulePath -Value ($moduleLines -join [Environment]::NewLine) -Encoding utf8
        }

        $lines = [System.Collections.Generic.List[string]]::new()
        if (-not $OmitImport) {
            $lines.Add('Import-Module (Join-Path $PSScriptRoot ''ExchangeOnlineBaseline.Common.psm1'') -Force')
        }
        $lines.Add('Set-StrictMode -Version Latest')
        $lines.Add('function Add-Outcome { param($Control) $Control }')
        $lines.Add('function Set-OrganizationControls { param($State) $State }')

        if ($PSBoundParameters.ContainsKey('InjectHelperName') -or $PSBoundParameters.ContainsKey('InjectHelperBody')) {
            $helperName = if ($PSBoundParameters.ContainsKey('InjectHelperName')) { $InjectHelperName } else { 'Get-LocalHelper' }
            $helperBody = if ($PSBoundParameters.ContainsKey('InjectHelperBody')) { $InjectHelperBody } else { '$Value' }
            $lines.Add(('function {0} {{ param($Value) {1} }}' -f $helperName, $helperBody))
        }

        if ($UseSharedContext) {
            $lines.Add('$context = Get-BaselineContext -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath -SchemaPath $SchemaPath')
            $lines.Add('$validated = $context.Configuration')
        }
        else {
            if (-not $OmitResolutionCall) {
                $lines.Add('$resolution = Resolve-BaselineConfiguration -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath')
            }
            if (-not $OmitValidationCall) {
                $lines.Add('$validated = Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $SchemaPath')
            }
        }
        if (-not $RemoveMutation) {
            $lines.Add('Set-TransportConfig -SmtpClientAuthenticationDisabled $true')
        }
        $lines.Add('Set-OrganizationControls -State $validated')
        $lines.Add('Add-Outcome -Control ''EXO-002''')

        $deploymentPath = Join-Path $scriptDirectory 'Deploy-ExchangeOnlineBaseline.ps1'
        if (-not $OmitDeploymentScript) {
            Set-Content -LiteralPath $deploymentPath -Value ($lines -join [Environment]::NewLine) -Encoding utf8
        }

        return [pscustomobject]@{
            DeploymentScriptPath = $deploymentPath
            ModulePath           = $modulePath
        }
    }
}

Describe 'COM-006-A deployment entry script migration' {

    Context 'Negative: the deployment script has not been migrated' {

        It 'reports DeploymentScriptMissing when the deployment script is absent' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -OmitDeploymentScript

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an absent deployment script cannot have been migrated'
            $result.Reason | Should -Be 'DeploymentScriptMissing'
        }

        It 'reports SharedModuleMissing when the shared module is absent' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -OmitSharedModule

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'there is nothing to migrate to when the shared module is absent'
            $result.Reason | Should -Be 'SharedModuleMissing'
        }

        It 'reports SharedModuleNotImported when the deployment script does not import the shared module' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -OmitImport

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'the deployment script must consume the shared module'
            $result.Reason | Should -Be 'SharedModuleNotImported'
        }

        It 'reports DuplicateModuleHelper when a local helper name claims configuration resolution' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -InjectHelperName 'ConvertTo-ResolvedConfiguration'

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'configuration resolution belongs to the shared module'
            $result.Reason | Should -Be 'DuplicateModuleHelper'
        }

        It 'reports DuplicateModuleHelper when a local helper body substitutes administrator placeholders' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -InjectHelperName 'Get-LocalTemplate' -InjectHelperBody '$Value -replace ''__ADMIN_REQUIRED:PRIMARY__'', ''contoso.com'''

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'placeholder substitution is the shared module resolution implementation'
            $result.Reason | Should -Be 'DuplicateModuleHelper'
        }

        It 'reports DuplicateModuleHelper when a local helper name claims configuration validation' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -InjectHelperName 'Assert-Configuration'

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'configuration validation belongs to the shared module'
            $result.Reason | Should -Be 'DuplicateModuleHelper'
        }

        It 'reports DuplicateModuleHelper when a local helper body validates against a schema' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -InjectHelperName 'Get-LocalVerdict' -InjectHelperBody 'Test-Json -Json $Value -SchemaFile $SchemaPath'

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'schema validation is the shared module validation implementation'
            $result.Reason | Should -Be 'DuplicateModuleHelper'
        }

        It 'reports DuplicateModuleHelper when a local helper name claims configuration hashing' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -InjectHelperName 'Get-ConfigurationHash'

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'configuration hashing belongs to the shared module'
            $result.Reason | Should -Be 'DuplicateModuleHelper'
        }

        It 'reports DuplicateModuleHelper when a local helper body computes a digest' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -InjectHelperName 'Get-LocalIdentity' -InjectHelperBody '[System.Security.Cryptography.SHA256]::HashData($Value)'

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'digest computation is the shared module hashing implementation'
            $result.Reason | Should -Be 'DuplicateModuleHelper'
        }

        It 'reports DuplicateModuleHelper when a local helper name claims collection comparison' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -InjectHelperName 'Compare-AllowList'

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'normalized comparison belongs to the shared module'
            $result.Reason | Should -Be 'DuplicateModuleHelper'
        }

        It 'reports DuplicateModuleHelper when a local helper body compares collections' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -InjectHelperName 'Get-LocalDelta' -InjectHelperBody 'Compare-Object -ReferenceObject $Value -DifferenceObject $Value'

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'collection comparison is the shared module comparison implementation'
            $result.Reason | Should -Be 'DuplicateModuleHelper'
        }

        It 'reports DuplicateModuleHelper when a local helper name claims an entitlement decision' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -InjectHelperName 'Get-Entitlement'

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'entitlement decisions belong to the shared module'
            $result.Reason | Should -Be 'DuplicateModuleHelper'
        }

        It 'reports DuplicateModuleHelper when a local helper body derives entitlement from licensing tiers' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -InjectHelperName 'Get-LocalPlan' -InjectHelperBody 'Get-ConfigValue $Value ''licensing.messagingTier'''

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'deriving entitlement from declared tiers is the shared module decision implementation'
            $result.Reason | Should -Be 'DuplicateModuleHelper'
        }

        It 'names the duplicate helper and the capability it claims' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -InjectHelperName 'Get-Entitlement'

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Violations | Should -Contain 'Get-Entitlement:EntitlementDecision'
        }

        It 'reports ResolutionNotDelegated when the deployment script never calls the shared resolution function' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -OmitResolutionCall

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'importing the module is not enough; resolution must be delegated to it'
            $result.Reason | Should -Be 'ResolutionNotDelegated'
        }

        It 'reports ResolutionNotDelegated when the script delegates through a shared context that never resolves' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -UseSharedContext -ContextOmitsResolution

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'calling the context is only delegation when the context performs the resolution'
            $result.Reason | Should -Be 'ResolutionNotDelegated'
        }

        It 'reports ValidationNotDelegated when the script delegates through a shared context that never validates' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -UseSharedContext -ContextOmitsValidation

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'calling the context is only delegation when the context performs the validation'
            $result.Reason | Should -Be 'ValidationNotDelegated'
        }

        It 'reports ValidationNotDelegated when the deployment script never calls the shared validation function' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -OmitValidationCall

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'importing the module is not enough; validation must be delegated to it'
            $result.Reason | Should -Be 'ValidationNotDelegated'
        }

        It 'reports MutationOwnershipAbsent when the deployment script no longer mutates the tenant' {
            # Arrange
            $fixture = New-DeploymentMigrationFixture -Root $TestDrive -RemoveMutation

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $fixture.DeploymentScriptPath -ModulePath $fixture.ModulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'migration must not move tenant mutation out of the deployment script'
            $result.Reason | Should -Be 'MutationOwnershipAbsent'
        }
    }

    Context 'Positive: the shipped deployment script is migrated' {

        It 'imports the shared module, defines no module-owned helper, delegates resolution and validation, and still owns tenant mutation' {
            # Arrange
            $deploymentScriptPath = $script:DeploymentScriptPath
            $modulePath = $script:ModulePath

            # Act
            $result = Get-DeploymentMigrationResult -DeploymentScriptPath $deploymentScriptPath -ModulePath $modulePath

            # Assert
            $result.Satisfied | Should -BeTrue -Because "the deployment script must satisfy COM-006 but reported '$($result.Reason)' for '$($result.Violations -join ', ')'"
            $result.Reason | Should -Be 'DeploymentMigrationSatisfied'
        }
    }
}
