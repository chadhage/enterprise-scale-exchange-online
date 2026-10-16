[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$tools = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'tools.psd1')
if ($PSVersionTable.PSVersion -lt [version]$tools.MinimumPowerShellVersion) {
    throw "PowerShell $($tools.MinimumPowerShellVersion) or later is required."
}
$moduleRoot = Join-Path $PSScriptRoot '..\..\.artifacts\modules'
$null = New-Item -ItemType Directory -Path $moduleRoot -Force
$env:PSModulePath = $moduleRoot + [IO.Path]::PathSeparator + $env:PSModulePath
foreach ($name in 'Pester', 'PSScriptAnalyzer') {
    if (-not (Get-Module -ListAvailable -Name $name | Where-Object Version -EQ ([version]$tools[$name]))) {
        Save-Module -Name $name -RequiredVersion $tools[$name] -Path $moduleRoot -Repository PSGallery -ErrorAction Stop
    }
    Import-Module $name -RequiredVersion $tools[$name] -Force -ErrorAction Stop
}
if ($env:GITHUB_ENV) {
    "PSModulePath=$($env:PSModulePath)" | Add-Content -LiteralPath $env:GITHUB_ENV
}
