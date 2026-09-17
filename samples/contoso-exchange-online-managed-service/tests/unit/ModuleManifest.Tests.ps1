#requires -Version 7.0

# Discovery-scope copy so the per-function negative cases can be expanded by -ForEach.
$RequiredPublicFunctions = @(
    'Resolve-BaselineConfiguration'
    'Assert-BaselineConfiguration'
    'ConvertTo-CanonicalJson'
    'Get-BaselineConfigurationHash'
    'Compare-NormalizedCollection'
    'Get-ControlApplicability'
    'Test-RiskAcceptance'
    'New-ControlResult'
)

BeforeAll {
    $script:RequiredPublicFunctions = @(
        'Resolve-BaselineConfiguration'
        'Assert-BaselineConfiguration'
        'ConvertTo-CanonicalJson'
        'Get-BaselineConfigurationHash'
        'Compare-NormalizedCollection'
        'Get-ControlApplicability'
        'Test-RiskAcceptance'
        'New-ControlResult'
    )

    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:CommonManifestPath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psd1'

    function Get-ModuleManifestResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$ManifestPath,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$ModulePath
        )

        $result = [ordered]@{
            Satisfied        = $false
            Reason           = $null
            DeclaredFunction = @()
            ModuleFunction   = @()
        }

        if ([string]::IsNullOrWhiteSpace($ManifestPath) -or -not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
            $result.Reason = 'ManifestFileMissing'
            return [pscustomobject]$result
        }

        $manifest = $null
        try {
            $manifest = Import-PowerShellDataFile -LiteralPath $ManifestPath -ErrorAction Stop
        }
        catch {
            $result.Reason = 'ManifestUnreadable'
            return [pscustomobject]$result
        }

        if (-not $manifest.ContainsKey('RootModule') -or [string]::IsNullOrWhiteSpace([string]$manifest['RootModule'])) {
            $result.Reason = 'RootModuleMissing'
            return [pscustomobject]$result
        }

        if ((Split-Path -Leaf ([string]$manifest['RootModule'])) -ne (Split-Path -Leaf $ModulePath)) {
            $result.Reason = 'RootModuleMismatch'
            return [pscustomobject]$result
        }

        $declared = @()
        if ($manifest.ContainsKey('FunctionsToExport')) {
            $declared = @($manifest['FunctionsToExport'])
        }

        if (-not $manifest.ContainsKey('FunctionsToExport') -or $declared.Count -eq 0 -or ($declared | Where-Object { $_ -match '\*' })) {
            $result.Reason = 'WildcardFunctionExport'
            return [pscustomobject]$result
        }

        $result.DeclaredFunction = $declared

        $module = $null
        try {
            $module = Import-Module -Name $ModulePath -Force -PassThru -DisableNameChecking -ErrorAction Stop
        }
        catch {
            $result.Reason = 'ModuleUnreadable'
            return [pscustomobject]$result
        }

        try {
            $exported = @($module.ExportedFunctions.Keys)
            $result.ModuleFunction = $exported

            if (@($script:RequiredPublicFunctions | Where-Object { $_ -notin $declared }).Count -gt 0) {
                $result.Reason = 'RequiredFunctionNotDeclared'
                return [pscustomobject]$result
            }

            if (@($declared | Where-Object { $_ -notin $exported }).Count -gt 0) {
                $result.Reason = 'DeclaredFunctionNotInModule'
                return [pscustomobject]$result
            }

            if (@($exported | Where-Object { $_ -notin $declared }).Count -gt 0) {
                $result.Reason = 'ModuleFunctionNotDeclared'
                return [pscustomobject]$result
            }

            $result.Satisfied = $true
            $result.Reason = 'ManifestSatisfied'
        }
        finally {
            Remove-Module -ModuleInfo $module -Force -ErrorAction SilentlyContinue
        }

        return [pscustomobject]$result
    }

    function New-StubModuleFile {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Directory,

            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [string[]]$Export
        )

        $path = Join-Path $Directory ('Stub-{0}.psm1' -f [guid]::NewGuid().ToString('N'))
        $lines = [System.Collections.Generic.List[string]]::new()
        foreach ($name in $Export) {
            $lines.Add("function $name { }")
        }
        $quoted = ($Export | ForEach-Object { "'$_'" }) -join ', '
        $lines.Add("Export-ModuleMember -Function @($quoted)")

        Set-Content -LiteralPath $path -Value ($lines -join [Environment]::NewLine) -Encoding utf8
        return $path
    }

    function New-StubManifestFile {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Directory,

            [string]$RootModule,

            [AllowEmptyCollection()]
            [string[]]$FunctionsToExport,

            [switch]$OmitFunctionsToExport,

            [switch]$WildcardExport
        )

        $path = Join-Path $Directory ('Stub-{0}.psd1' -f [guid]::NewGuid().ToString('N'))
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add('@{')
        $lines.Add("    ModuleVersion = '1.0.0'")
        $lines.Add("    GUID = '$([guid]::NewGuid().ToString())'")
        $lines.Add("    Author = 'Pester stub'")
        if (-not [string]::IsNullOrWhiteSpace($RootModule)) {
            $lines.Add("    RootModule = '$RootModule'")
        }
        if ($WildcardExport) {
            $lines.Add("    FunctionsToExport = '*'")
        }
        elseif (-not $OmitFunctionsToExport) {
            $quoted = ($FunctionsToExport | ForEach-Object { "'$_'" }) -join ', '
            $lines.Add("    FunctionsToExport = @($quoted)")
        }
        $lines.Add('}')

        Set-Content -LiteralPath $path -Value ($lines -join [Environment]::NewLine) -Encoding utf8
        return $path
    }
}

Describe 'COM-001-A module manifest and public API contract' {

    Context 'Negative: the manifest does not declare the public API' {

        It 'reports ManifestFileMissing when the manifest is absent' {
            # Arrange
            $modulePath = New-StubModuleFile -Directory $TestDrive -Export $script:RequiredPublicFunctions
            $absentManifest = Join-Path $TestDrive 'Absent.psd1'

            # Act
            $result = Get-ModuleManifestResult -ManifestPath $absentManifest -ModulePath $modulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an absent manifest declares no public API'
            $result.Reason | Should -Be 'ManifestFileMissing'
        }

        It 'reports ManifestUnreadable when the manifest is not a valid data file' {
            # Arrange
            $modulePath = New-StubModuleFile -Directory $TestDrive -Export $script:RequiredPublicFunctions
            $brokenManifest = Join-Path $TestDrive ('Broken-{0}.psd1' -f [guid]::NewGuid().ToString('N'))
            Set-Content -LiteralPath $brokenManifest -Value '@{ ModuleVersion = ' -Encoding utf8

            # Act
            $result = Get-ModuleManifestResult -ManifestPath $brokenManifest -ModulePath $modulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an unreadable manifest cannot be trusted to declare exports'
            $result.Reason | Should -Be 'ManifestUnreadable'
        }

        It 'reports RootModuleMissing when the manifest declares no root module' {
            # Arrange
            $modulePath = New-StubModuleFile -Directory $TestDrive -Export $script:RequiredPublicFunctions
            $manifestPath = New-StubManifestFile -Directory $TestDrive -FunctionsToExport $script:RequiredPublicFunctions

            # Act
            $result = Get-ModuleManifestResult -ManifestPath $manifestPath -ModulePath $modulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a manifest without a root module exports no implementation'
            $result.Reason | Should -Be 'RootModuleMissing'
        }

        It 'reports RootModuleMismatch when the manifest points at another module file' {
            # Arrange
            $modulePath = New-StubModuleFile -Directory $TestDrive -Export $script:RequiredPublicFunctions
            $manifestPath = New-StubManifestFile -Directory $TestDrive -RootModule 'SomeOther.psm1' -FunctionsToExport $script:RequiredPublicFunctions

            # Act
            $result = Get-ModuleManifestResult -ManifestPath $manifestPath -ModulePath $modulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'the manifest must bind to the shared module it ships beside'
            $result.Reason | Should -Be 'RootModuleMismatch'
        }

        It 'reports WildcardFunctionExport when the manifest omits FunctionsToExport' {
            # Arrange
            $modulePath = New-StubModuleFile -Directory $TestDrive -Export $script:RequiredPublicFunctions
            $manifestPath = New-StubManifestFile -Directory $TestDrive -RootModule (Split-Path -Leaf $modulePath) -OmitFunctionsToExport

            # Act
            $result = Get-ModuleManifestResult -ManifestPath $manifestPath -ModulePath $modulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an omitted export list exports every function implicitly'
            $result.Reason | Should -Be 'WildcardFunctionExport'
        }

        It 'reports WildcardFunctionExport when the manifest exports by wildcard' {
            # Arrange
            $modulePath = New-StubModuleFile -Directory $TestDrive -Export $script:RequiredPublicFunctions
            $manifestPath = New-StubManifestFile -Directory $TestDrive -RootModule (Split-Path -Leaf $modulePath) -WildcardExport

            # Act
            $result = Get-ModuleManifestResult -ManifestPath $manifestPath -ModulePath $modulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'the public API must be explicit, not a wildcard'
            $result.Reason | Should -Be 'WildcardFunctionExport'
        }

        It "reports RequiredFunctionNotDeclared when '<_>' is not declared" -ForEach $RequiredPublicFunctions {
            # Arrange
            $omitted = $_
            $modulePath = New-StubModuleFile -Directory $TestDrive -Export $script:RequiredPublicFunctions
            $manifestPath = New-StubManifestFile -Directory $TestDrive -RootModule (Split-Path -Leaf $modulePath) -FunctionsToExport @($script:RequiredPublicFunctions | Where-Object { $_ -ne $omitted })

            # Act
            $result = Get-ModuleManifestResult -ManifestPath $manifestPath -ModulePath $modulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because "the public API requires $omitted to be declared"
            $result.Reason | Should -Be 'RequiredFunctionNotDeclared'
        }

        It 'reports DeclaredFunctionNotInModule when the manifest declares an export the module does not define' {
            # Arrange
            $modulePath = New-StubModuleFile -Directory $TestDrive -Export $script:RequiredPublicFunctions
            $manifestPath = New-StubManifestFile -Directory $TestDrive -RootModule (Split-Path -Leaf $modulePath) -FunctionsToExport (@($script:RequiredPublicFunctions) + 'Get-PhantomCapability')

            # Act
            $result = Get-ModuleManifestResult -ManifestPath $manifestPath -ModulePath $modulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a declared export that does not exist is a broken public API'
            $result.Reason | Should -Be 'DeclaredFunctionNotInModule'
        }

        It 'reports ModuleFunctionNotDeclared when the module exports a function the manifest omits' {
            # Arrange
            $modulePath = New-StubModuleFile -Directory $TestDrive -Export (@($script:RequiredPublicFunctions) + 'Get-UndeclaredCapability')
            $manifestPath = New-StubManifestFile -Directory $TestDrive -RootModule (Split-Path -Leaf $modulePath) -FunctionsToExport $script:RequiredPublicFunctions

            # Act
            $result = Get-ModuleManifestResult -ManifestPath $manifestPath -ModulePath $modulePath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'the manifest must match the module it ships beside'
            $result.Reason | Should -Be 'ModuleFunctionNotDeclared'
        }
    }

    Context 'Positive: the manifest declares the public API' {

        It 'declares exactly the functions the shared module exports' {
            # Arrange
            $manifestPath = $script:CommonManifestPath
            $modulePath = $script:CommonModulePath

            # Act
            $result = Get-ModuleManifestResult -ManifestPath $manifestPath -ModulePath $modulePath

            # Assert
            $result.Satisfied | Should -BeTrue -Because "the manifest contract reported $($result.Reason)"
        }
    }
}
