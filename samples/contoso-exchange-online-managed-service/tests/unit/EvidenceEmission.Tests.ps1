#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:EvidenceScriptPath = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:CommonManifestPath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psd1'

    # Running the evidence script would require an Exchange Online and a Graph session, so the
    # emission is decided from the shipped script's syntax tree instead. Microsoft.Graph and
    # ExchangeOnlineManagement are not installed and are never imported here.
    $script:EnvelopeBuilder = 'New-BaselineEvidenceEnvelope'
    $script:ArtifactWriter = @('Set-Content', 'Out-File')

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

    function Get-HashtableKeyName {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [System.Management.Automation.Language.Ast]$Ast
        )

        return @(
            $Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.HashtableAst] }, $true) |
                ForEach-Object { $_.KeyValuePairs } |
                ForEach-Object { $_.Item1.Extent.Text.Trim([char[]]@("'", '"')) }
        )
    }

    # The envelope members are read from the builder rather than restated here, because a restated
    # list stops naming the envelope the moment somebody edits only one of the two.
    function Get-EnvelopeMemberName {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ModulePath
        )

        $builderName = $script:EnvelopeBuilder
        $builder = @(
            (Get-ScriptAst -Path $ModulePath).FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $builderName
                }, $true)
        )

        if ($builder.Count -eq 0) {
            return @()
        }

        $record = @(
            $builder[0].Body.FindAll({ param($node) $node -is [System.Management.Automation.Language.HashtableAst] }, $true) |
                Sort-Object { $_.KeyValuePairs.Count } -Descending
        )

        return @($record[0].KeyValuePairs | ForEach-Object { $_.Item1.Extent.Text.Trim([char[]]@("'", '"')) })
    }

    function Get-EvidenceEmissionResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$ScriptPath,

            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [string[]]$ExportedCommand,

            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [string[]]$EnvelopeMember
        )

        $result = [ordered]@{
            Satisfied  = $false
            Reason     = $null
            Violations = @()
        }

        if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
            $result.Reason = 'EvidenceScriptMissing'
            return [pscustomobject]$result
        }

        if (@($ExportedCommand) -cnotcontains $script:EnvelopeBuilder) {
            $result.Reason = 'EnvelopeBuilderNotExported'
            return [pscustomobject]$result
        }

        $builderName = $script:EnvelopeBuilder
        $writerName = $script:ArtifactWriter
        $ast = Get-ScriptAst -Path $ScriptPath

        $build = @(
            $ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                    @($node.Right.FindAll({
                                param($call)
                                $call -is [System.Management.Automation.Language.CommandAst] -and $call.GetCommandName() -ceq $builderName
                            }, $true)).Count -gt 0
                }, $true)
        )

        if ($build.Count -eq 0) {
            $result.Reason = 'EnvelopeNeverBuilt'
            return [pscustomobject]$result
        }

        $envelopeVariable = @(
            $build |
                Where-Object { $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] } |
                ForEach-Object { $_.Left.VariablePath.UserPath }
        )

        # A write with no variable behind it names no artifact, which is the same unprovable
        # publication as writing an object the builder never produced.
        $write = @(
            $ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.PipelineAst] -and
                    @($node.PipelineElements |
                            Where-Object { $_ -is [System.Management.Automation.Language.CommandAst] -and $_.GetCommandName() -cin $writerName }).Count -gt 0
                }, $true)
        )

        $artifactVariable = ''
        $writeOffset = [int]::MaxValue
        if ($write.Count -gt 0) {
            $written = @(
                $write[0].PipelineElements[0].FindAll({
                        param($node) $node -is [System.Management.Automation.Language.VariableExpressionAst]
                    }, $true)
            )
            if ($written.Count -gt 0) {
                $artifactVariable = $written[0].VariablePath.UserPath
            }
            $writeOffset = $write[0].Extent.StartOffset
        }

        if ($envelopeVariable -cnotcontains $artifactVariable) {
            $result.Reason = 'ArtifactNotEnvelope'
            $result.Violations = @($artifactVariable)
            return [pscustomobject]$result
        }

        $buildOffset = @($build | ForEach-Object { $_.Extent.StartOffset } | Sort-Object)[0]
        if ($buildOffset -gt $writeOffset) {
            $result.Reason = 'EnvelopeBuiltAfterWrite'
            return [pscustomobject]$result
        }

        $handRolled = @(Get-HashtableKeyName -Ast $ast | Where-Object { $_ -in @($EnvelopeMember) } | Sort-Object -Unique)
        if ($handRolled.Count -gt 0) {
            $result.Reason = 'EnvelopeMemberHandRolled'
            $result.Violations = $handRolled
            return [pscustomobject]$result
        }

        $result.Satisfied = $true
        $result.Reason = 'EvidenceEmissionSatisfied'
        return [pscustomobject]$result
    }

    function New-EmissionFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Root,

            [switch]$OmitScript,
            [switch]$NeverBuild,
            [switch]$WriteOtherArtifact,
            [switch]$BuildAfterWrite,
            [switch]$HandRollMember
        )

        $scriptDirectory = Join-Path $Root ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $scriptDirectory -Force | Out-Null
        $path = Join-Path $scriptDirectory 'Test-ExchangeOnlineBaseline.ps1'

        $build = '$envelope = New-BaselineEvidenceEnvelope -Context $context -TenantId $tenantId -OrganizationName $organizationName -ParameterPath $ParameterPath -Evidence $record -Check $verdict'
        $write = '$envelope | ConvertTo-Json -Depth 20 | Set-Content -Path $resultPath -Encoding utf8'
        $rival = '$result = [ordered]@{ observed = $record; decided = $verdict }'
        $rivalWrite = '$result | ConvertTo-Json -Depth 20 | Set-Content -Path $resultPath -Encoding utf8'

        $line = [System.Collections.Generic.List[string]]::new()
        $line.Add('Import-Module (Join-Path $PSScriptRoot ''ExchangeOnlineBaseline.Common.psm1'') -Force')

        if ($NeverBuild) {
            $line.Add($rival)
            $line.Add($rivalWrite)
        }
        elseif ($WriteOtherArtifact) {
            $line.Add($build)
            $line.Add($rival)
            $line.Add($rivalWrite)
        }
        elseif ($BuildAfterWrite) {
            $line.Add($write)
            $line.Add($build)
        }
        elseif ($HandRollMember) {
            $line.Add('$restated = [ordered]@{ ConfigurationHash = $hash; TenantId = $tenantId }')
            $line.Add($build)
            $line.Add($write)
        }
        else {
            $line.Add($build)
            $line.Add($write)
        }

        if (-not $OmitScript) {
            Set-Content -LiteralPath $path -Value ($line -join [Environment]::NewLine) -Encoding utf8
        }

        return $path
    }

    $script:ExportedCommand = @([string[]](Import-PowerShellDataFile -LiteralPath $script:CommonManifestPath).FunctionsToExport)
    $script:EnvelopeMember = @(Get-EnvelopeMemberName -ModulePath $script:CommonModulePath)
}

Describe 'EVD-004-A3 evidence entry script emits the envelope' {

    Context 'Negative: the emission cannot be decided' {

        It 'reports EvidenceScriptMissing when the evidence script is absent' {
            # Arrange
            $path = New-EmissionFixture -Root $TestDrive -OmitScript

            # Act
            $result = Get-EvidenceEmissionResult -ScriptPath $path -ExportedCommand $script:ExportedCommand -EnvelopeMember $script:EnvelopeMember

            # Assert
            ('{0}|{1}' -f $result.Satisfied, $result.Reason) |
                Should -BeExactly 'False|EvidenceScriptMissing' `
                    -Because 'a script that does not exist emits no evidence at all, and a run that produced no artifact must not read as a run that produced a clean one'
        }

        It 'reports EnvelopeBuilderNotExported when the module does not publish the builder' {
            # Arrange
            $path = New-EmissionFixture -Root $TestDrive
            $withoutBuilder = @($script:ExportedCommand | Where-Object { $_ -cne 'New-BaselineEvidenceEnvelope' })

            # Act
            $result = Get-EvidenceEmissionResult -ScriptPath $path -ExportedCommand $withoutBuilder -EnvelopeMember $script:EnvelopeMember

            # Assert
            ('{0}|{1}' -f $result.Satisfied, $result.Reason) |
                Should -BeExactly 'False|EnvelopeBuilderNotExported' `
                    -Because 'a script calling a builder the module does not export fails only at run time, in the tenant, after collection has already happened'
        }
    }

    Context 'Negative: the script must build the envelope it publishes' {

        It 'reports EnvelopeNeverBuilt when the script assembles its artifact without the builder' {
            # Arrange
            $path = New-EmissionFixture -Root $TestDrive -NeverBuild

            # Act
            $result = Get-EvidenceEmissionResult -ScriptPath $path -ExportedCommand $script:ExportedCommand -EnvelopeMember $script:EnvelopeMember

            # Assert
            ('{0}|{1}' -f $result.Satisfied, $result.Reason) |
                Should -BeExactly 'False|EnvelopeNeverBuilt' `
                    -Because 'an artifact that never passed through the builder was never held to any of the builder guards, so it can omit the tenant, the profile or the hash and still be published'
        }

        It 'reports ArtifactNotEnvelope when the script writes something it did not build with the builder' {
            # Arrange
            $path = New-EmissionFixture -Root $TestDrive -WriteOtherArtifact

            # Act
            $result = Get-EvidenceEmissionResult -ScriptPath $path -ExportedCommand $script:ExportedCommand -EnvelopeMember $script:EnvelopeMember

            # Assert
            ('{0}|{1}' -f $result.Satisfied, $result.Reason) |
                Should -BeExactly 'False|ArtifactNotEnvelope' `
                    -Because 'building a validated envelope and then publishing a different object is indistinguishable, to every reader, from never validating anything'
        }

        It 'reports EnvelopeBuiltAfterWrite when the artifact is written before the envelope exists' {
            # Arrange
            $path = New-EmissionFixture -Root $TestDrive -BuildAfterWrite

            # Act
            $result = Get-EvidenceEmissionResult -ScriptPath $path -ExportedCommand $script:ExportedCommand -EnvelopeMember $script:EnvelopeMember

            # Assert
            ('{0}|{1}' -f $result.Satisfied, $result.Reason) |
                Should -BeExactly 'False|EnvelopeBuiltAfterWrite' `
                    -Because 'an envelope built after the file is written cannot have been the thing written, so the builder guards run over an artifact nobody will ever read'
        }

        It 'reports EnvelopeMemberHandRolled when the script restates an envelope member itself' {
            # Arrange
            $path = New-EmissionFixture -Root $TestDrive -HandRollMember

            # Act
            $result = Get-EvidenceEmissionResult -ScriptPath $path -ExportedCommand $script:ExportedCommand -EnvelopeMember $script:EnvelopeMember

            # Assert
            ('{0}|{1}' -f $result.Satisfied, $result.Reason) |
                Should -BeExactly 'False|EnvelopeMemberHandRolled' `
                    -Because 'a second copy of an envelope fact inside the script is a second source of truth, and the two disagree the first time only one of them is maintained'
        }
    }

    Context 'Positive: the shipped evidence script publishes exactly the envelope it built' {

        It 'builds the envelope through the exported builder and writes that envelope as its evidence artifact' {
            # Arrange
            $expected = 'True|EvidenceEmissionSatisfied|'

            # Act
            $result = Get-EvidenceEmissionResult -ScriptPath $script:EvidenceScriptPath -ExportedCommand $script:ExportedCommand -EnvelopeMember $script:EnvelopeMember

            # Assert
            ('{0}|{1}|{2}' -f $result.Satisfied, $result.Reason, (@($result.Violations) -join ',')) |
                Should -BeExactly $expected `
                    -Because 'the evidence artifact is the only thing a reviewer ever sees, so the guards the builder enforces are worth nothing unless the shipped script publishes the builder output itself'
        }
    }
}
