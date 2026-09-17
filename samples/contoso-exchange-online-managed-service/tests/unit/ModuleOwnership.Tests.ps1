#requires -Version 7.0

# Discovery-scope copy so the per-capability negative cases can be expanded by -ForEach.
$RequiredCapabilities = @(
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
    $script:RequiredCapabilities = @(
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

    function Get-ModuleOwnershipResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$Path
        )

        $result = [ordered]@{
            Satisfied           = $false
            Reason              = $null
            MissingCapabilities = @($script:RequiredCapabilities)
        }

        if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            $result.Reason = 'ModuleFileMissing'
            return [pscustomobject]$result
        }

        $module = $null
        try {
            $module = Import-Module -Name $Path -Force -PassThru -DisableNameChecking -ErrorAction Stop
        }
        catch {
            $result.Reason = 'ModuleImportFailed'
            return [pscustomobject]$result
        }

        try {
            $exported = @($module.ExportedFunctions.Keys) + @($module.ExportedCmdlets.Keys) + @($module.ExportedAliases.Keys)
            $missing = @($script:RequiredCapabilities | Where-Object { $_ -notin $exported })

            $result.MissingCapabilities = $missing
            $result.Satisfied = ($missing.Count -eq 0)
            $result.Reason = if ($result.Satisfied) { 'OwnershipSatisfied' } else { 'CapabilityNotExported' }
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
}

Describe 'ARC-001-A shared module ownership contract' {

    Context 'Negative: ownership is not satisfied' {

        It 'reports ModuleFileMissing when the module file is absent' {
            # Arrange
            $absentPath = Join-Path $TestDrive 'ExchangeOnlineBaseline.Common.psm1'

            # Act
            $result = Get-ModuleOwnershipResult -Path $absentPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an absent module cannot own any capability'
            $result.Reason | Should -Be 'ModuleFileMissing'
        }

        It 'reports ModuleImportFailed when the module cannot be imported' {
            # Arrange
            $brokenPath = Join-Path $TestDrive ('Broken-{0}.psm1' -f [guid]::NewGuid().ToString('N'))
            Set-Content -LiteralPath $brokenPath -Value "throw 'module import is intentionally broken'" -Encoding utf8

            # Act
            $result = Get-ModuleOwnershipResult -Path $brokenPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a module that fails to import cannot own any capability'
            $result.Reason | Should -Be 'ModuleImportFailed'
        }

        It "reports CapabilityNotExported when '<_>' is not exported" -ForEach $RequiredCapabilities {
            # Arrange
            $capability = $_
            $stubPath = New-StubModuleFile -Directory $TestDrive -Export @($script:RequiredCapabilities | Where-Object { $_ -ne $capability })

            # Act
            $result = Get-ModuleOwnershipResult -Path $stubPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because "ownership requires $capability to be exported"
            $result.Reason | Should -Be 'CapabilityNotExported'
            $result.MissingCapabilities | Should -Be @($capability)
        }
    }

    Context 'Positive: ownership is satisfied' {

        It 'exports the full required capability set from the shared module' {
            # Arrange
            $modulePath = $script:CommonModulePath

            # Act
            $result = Get-ModuleOwnershipResult -Path $modulePath

            # Assert
            $result.Satisfied | Should -BeTrue -Because "missing capabilities: $($result.MissingCapabilities -join ', ')"
        }
    }
}
