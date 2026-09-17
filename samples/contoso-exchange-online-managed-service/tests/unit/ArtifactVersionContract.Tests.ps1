#requires -Version 7.0

# Discovery-scope copy so the per-artifact negative cases can be expanded by -ForEach.
$VersionedArtifacts = @('Configuration', 'Evidence', 'Preview', 'Approval', 'Rollback', 'Exception')

BeforeAll {
    $script:VersionedArtifacts = @('Configuration', 'Evidence', 'Preview', 'Approval', 'Rollback', 'Exception')
    $script:SemanticVersionPattern = '^\d+\.\d+\.\d+$'

    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    function Get-ArtifactVersionVerdict {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            $Contract
        )

        $verdict = [ordered]@{
            Satisfied  = $false
            Reason     = $null
            Violations = @()
        }

        if ($null -eq $Contract) {
            $verdict.Reason = 'ContractMissing'
            return [pscustomobject]$verdict
        }

        foreach ($property in @('BaselineVersion', 'Artifact')) {
            if ($null -eq $Contract.PSObject.Properties[$property]) {
                $verdict.Reason = 'ContractMissing'
                $verdict.Violations = @($property)
                return [pscustomobject]$verdict
            }
        }

        if ([string]::IsNullOrWhiteSpace($Contract.BaselineVersion)) {
            $verdict.Reason = 'BaselineVersionMissing'
            return [pscustomobject]$verdict
        }

        $artifacts = @($Contract.Artifact)
        $declaredNames = @($artifacts | ForEach-Object { $_.Artifact })

        $missingArtifacts = @($script:VersionedArtifacts | Where-Object { $_ -notin $declaredNames })
        if ($missingArtifacts.Count -gt 0) {
            $verdict.Reason = 'ArtifactContractMissing'
            $verdict.Violations = $missingArtifacts
            return [pscustomobject]$verdict
        }

        $unknownArtifacts = @($declaredNames | Where-Object { $_ -notin $script:VersionedArtifacts })
        if ($unknownArtifacts.Count -gt 0) {
            $verdict.Reason = 'UnknownArtifactContract'
            $verdict.Violations = $unknownArtifacts
            return [pscustomobject]$verdict
        }

        $withoutVersion = @($artifacts | Where-Object { [string]::IsNullOrWhiteSpace($_.SchemaVersion) } | ForEach-Object { $_.Artifact })
        if ($withoutVersion.Count -gt 0) {
            $verdict.Reason = 'SchemaVersionMissing'
            $verdict.Violations = $withoutVersion
            return [pscustomobject]$verdict
        }

        $nonSemantic = @($artifacts | Where-Object { $_.SchemaVersion -notmatch $script:SemanticVersionPattern } | ForEach-Object { $_.Artifact })
        if ($nonSemantic.Count -gt 0) {
            $verdict.Reason = 'SchemaVersionNotSemantic'
            $verdict.Violations = $nonSemantic
            return [pscustomobject]$verdict
        }

        $coupled = @($artifacts | Where-Object { $_.VersionSource -eq 'Baseline' } | ForEach-Object { $_.Artifact })
        if ($coupled.Count -gt 0) {
            $verdict.Reason = 'ArtifactVersionCoupledToBaseline'
            $verdict.Violations = $coupled
            return [pscustomobject]$verdict
        }

        $verdict.Satisfied = $true
        $verdict.Reason = 'ArtifactVersionContractSatisfied'
        return [pscustomobject]$verdict
    }

    function New-ArtifactVersionFixture {
        [CmdletBinding()]
        param(
            [AllowEmptyString()]
            [string]$BaselineVersion = '1.0.0',
            [string]$OmitArtifact,
            [string]$AddArtifact,
            [string]$WithoutSchemaVersionArtifact,
            [string]$NonSemanticArtifact,
            [string]$BaselineSourcedArtifact
        )

        $artifacts = [System.Collections.Generic.List[object]]::new()
        foreach ($name in $script:VersionedArtifacts) {
            if ($name -eq $OmitArtifact) { continue }

            $schemaVersion = '1.0.0'
            if ($name -eq $WithoutSchemaVersionArtifact) { $schemaVersion = '' }
            elseif ($name -eq $NonSemanticArtifact) { $schemaVersion = 'v1' }

            $artifacts.Add([pscustomobject]@{
                    Artifact      = $name
                    SchemaVersion = $schemaVersion
                    VersionSource = if ($name -eq $BaselineSourcedArtifact) { 'Baseline' } else { 'ArtifactSchema' }
                })
        }

        if ($AddArtifact) {
            $artifacts.Add([pscustomobject]@{
                    Artifact      = $AddArtifact
                    SchemaVersion = '1.0.0'
                    VersionSource = 'ArtifactSchema'
                })
        }

        return [pscustomobject]@{
            BaselineVersion = $BaselineVersion
            Artifact        = @($artifacts)
        }
    }
}

Describe 'DES-004-A independent artifact version contract' {

    Context 'Negative: the contract is not satisfied' {

        It 'reports ContractMissing when no contract is published' {
            # Arrange
            $contract = $null

            # Act
            $verdict = Get-ArtifactVersionVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'an absent contract versions nothing'
            $verdict.Reason | Should -Be 'ContractMissing'
        }

        It 'reports BaselineVersionMissing when the baseline version is not declared' {
            # Arrange
            $contract = New-ArtifactVersionFixture -BaselineVersion ''

            # Act
            $verdict = Get-ArtifactVersionVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'independence is only meaningful against a declared baseline version'
            $verdict.Reason | Should -Be 'BaselineVersionMissing'
        }

        It "reports ArtifactContractMissing when '<_>' has no versioned contract" -ForEach $VersionedArtifacts {
            # Arrange
            $artifact = $_
            $contract = New-ArtifactVersionFixture -OmitArtifact $artifact

            # Act
            $verdict = Get-ArtifactVersionVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because "$artifact requires its own versioned contract"
            $verdict.Reason | Should -Be 'ArtifactContractMissing'
            $verdict.Violations | Should -Be @($artifact)
        }

        It 'reports UnknownArtifactContract when an undeclared artifact is versioned' {
            # Arrange
            $contract = New-ArtifactVersionFixture -AddArtifact 'Scratch'

            # Act
            $verdict = Get-ArtifactVersionVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'only the declared artifacts carry versioned contracts'
            $verdict.Reason | Should -Be 'UnknownArtifactContract'
            $verdict.Violations | Should -Be @('Scratch')
        }

        It 'reports SchemaVersionMissing when an artifact declares no schema version' {
            # Arrange
            $contract = New-ArtifactVersionFixture -WithoutSchemaVersionArtifact 'Evidence'

            # Act
            $verdict = Get-ArtifactVersionVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'every artifact contract carries its own schema version'
            $verdict.Reason | Should -Be 'SchemaVersionMissing'
            $verdict.Violations | Should -Be @('Evidence')
        }

        It 'reports SchemaVersionNotSemantic when an artifact schema version is not semantic' {
            # Arrange
            $contract = New-ArtifactVersionFixture -NonSemanticArtifact 'Preview'

            # Act
            $verdict = Get-ArtifactVersionVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'artifact schema versions must be comparable'
            $verdict.Reason | Should -Be 'SchemaVersionNotSemantic'
            $verdict.Violations | Should -Be @('Preview')
        }

        It 'reports ArtifactVersionCoupledToBaseline when an artifact version is sourced from the baseline' {
            # Arrange
            $contract = New-ArtifactVersionFixture -BaselineSourcedArtifact 'Approval'

            # Act
            $verdict = Get-ArtifactVersionVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'artifact contracts version independently from the baseline'
            $verdict.Reason | Should -Be 'ArtifactVersionCoupledToBaseline'
            $verdict.Violations | Should -Be @('Approval')
        }
    }

    Context 'Positive: the contract is satisfied' {

        It 'versions configuration, evidence, preview, approval, rollback, and exception contracts independently from the baseline' {
            # Arrange
            Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking
            $contract = Get-ArtifactVersionContract

            # Act
            $verdict = Get-ArtifactVersionVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeTrue -Because "contract violation: $($verdict.Reason) $($verdict.Violations -join ', ')"
        }
    }
}
