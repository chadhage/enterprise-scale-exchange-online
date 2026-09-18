#requires -Version 7.0

# Discovery-scope copy so the per-artifact negative cases can be expanded by -ForEach.
$ChangeArtifacts = @('Preview', 'Approval', 'PreChange', 'Apply', 'Rollback', 'PostChange')

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # Named here rather than read off the contract, so a contract that quietly drops an artifact is
    # a failure rather than a smaller expectation.
    $script:ChangeArtifacts = @('Preview', 'Approval', 'PreChange', 'Apply', 'Rollback', 'PostChange')

    # A rollback anyone has to hand-translate before running is not a rollback, so that artifact is
    # the one executable in the set and every other artifact is machine-readable state.
    $script:ExpectedFormat = @{
        Preview    = 'Json'
        Approval   = 'Json'
        PreChange  = 'Json'
        Apply      = 'Json'
        Rollback   = 'PowerShell'
        PostChange = 'Json'
    }

    $script:FormatExtension = @{ Json = '.json'; PowerShell = '.ps1' }

    function Get-ChangeArtifactVerdict {
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

        $member = Get-ContractMemberName -Contract $Contract

        if ('Artifact' -notin $member) {
            $verdict.Reason = 'ArtifactSetMissing'
            return [pscustomobject]$verdict
        }

        if ('ChangeIdentifierPattern' -notin $member -or 'ChangeIdentifierPlaceholder' -notin $member -or
            [string]::IsNullOrWhiteSpace([string]$Contract.ChangeIdentifierPattern) -or
            [string]::IsNullOrWhiteSpace([string]$Contract.ChangeIdentifierPlaceholder)) {
            $verdict.Reason = 'ChangeIdentifierPatternMissing'
            return [pscustomobject]$verdict
        }

        $placeholder = [string]$Contract.ChangeIdentifierPlaceholder
        $artifacts = @($Contract.Artifact)
        $declaredNames = @($artifacts | ForEach-Object { [string]$_.Artifact })

        $missing = @($script:ChangeArtifacts | Where-Object { $_ -notin $declaredNames })
        if ($missing.Count -gt 0) {
            $verdict.Reason = 'ArtifactNotDeclared'
            $verdict.Violations = $missing
            return [pscustomobject]$verdict
        }

        $unknown = @($declaredNames | Where-Object { $_ -notin $script:ChangeArtifacts })
        if ($unknown.Count -gt 0) {
            $verdict.Reason = 'UnknownArtifactDeclared'
            $verdict.Violations = $unknown
            return [pscustomobject]$verdict
        }

        $withoutTemplate = @($artifacts | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.FileNameTemplate) } | ForEach-Object { [string]$_.Artifact })
        if ($withoutTemplate.Count -gt 0) {
            $verdict.Reason = 'FileNameTemplateMissing'
            $verdict.Violations = $withoutTemplate
            return [pscustomobject]$verdict
        }

        $withoutPlaceholder = @($artifacts | Where-Object { [string]$_.FileNameTemplate -notlike "*$placeholder*" } | ForEach-Object { [string]$_.Artifact })
        if ($withoutPlaceholder.Count -gt 0) {
            $verdict.Reason = 'ChangeIdentifierPlaceholderMissing'
            $verdict.Violations = $withoutPlaceholder
            return [pscustomobject]$verdict
        }

        $wrongStem = @(
            $artifacts |
                Where-Object { [string]$_.FileNameTemplate -notlike ('{0}-{1}*' -f ([string]$_.Artifact).ToLowerInvariant(), $placeholder) } |
                ForEach-Object { [string]$_.Artifact }
        )
        if ($wrongStem.Count -gt 0) {
            $verdict.Reason = 'FileNameStemMismatch'
            $verdict.Violations = $wrongStem
            return [pscustomobject]$verdict
        }

        $wrongFormat = @(
            $artifacts |
                Where-Object { [string]$_.Format -ne $script:ExpectedFormat[[string]$_.Artifact] } |
                ForEach-Object { [string]$_.Artifact }
        )
        if ($wrongFormat.Count -gt 0) {
            $verdict.Reason = 'ArtifactFormatMismatch'
            $verdict.Violations = $wrongFormat
            return [pscustomobject]$verdict
        }

        $wrongExtension = @(
            $artifacts |
                Where-Object { [System.IO.Path]::GetExtension([string]$_.FileNameTemplate) -ne $script:FormatExtension[[string]$_.Format] } |
                ForEach-Object { [string]$_.Artifact }
        )
        if ($wrongExtension.Count -gt 0) {
            $verdict.Reason = 'FileNameExtensionMismatch'
            $verdict.Violations = $wrongExtension
            return [pscustomobject]$verdict
        }

        $sequence = @($artifacts | ForEach-Object { [int]$_.Sequence })
        if (@($sequence | Select-Object -Unique).Count -ne $sequence.Count) {
            $verdict.Reason = 'SequenceDuplicated'
            $verdict.Violations = @($sequence | Group-Object | Where-Object Count -gt 1 | ForEach-Object { $_.Name })
            return [pscustomobject]$verdict
        }

        $expectedSequence = 1..$script:ChangeArtifacts.Count
        if (@(Compare-Object -ReferenceObject $expectedSequence -DifferenceObject ($sequence | Sort-Object)).Count -gt 0) {
            $verdict.Reason = 'SequenceNotContiguous'
            $verdict.Violations = @($sequence | Sort-Object | ForEach-Object { [string]$_ })
            return [pscustomobject]$verdict
        }

        $optional = @($artifacts | Where-Object { -not [bool]$_.Required } | ForEach-Object { [string]$_.Artifact })
        if ($optional.Count -gt 0) {
            $verdict.Reason = 'ArtifactOptional'
            $verdict.Violations = $optional
            return [pscustomobject]$verdict
        }

        $verdict.Satisfied = $true
        $verdict.Reason = 'ChangeArtifactContractSatisfied'
        return [pscustomobject]$verdict
    }

    function Get-ContractMemberName {
        [CmdletBinding()]
        param([Parameter(Mandatory)][object]$Contract)

        if ($Contract -is [System.Collections.IDictionary]) { return @($Contract.Keys | ForEach-Object { [string]$_ }) }

        return @($Contract.PSObject.Properties | Where-Object { $_.MemberType -ne 'Method' } | ForEach-Object { $_.Name })
    }

    function New-ChangeArtifactFixture {
        [CmdletBinding()]
        param(
            [string]$OmitArtifact,
            [string]$AddArtifact,
            [string]$WithoutTemplateArtifact,
            [string]$WithoutPlaceholderArtifact,
            [string]$WrongStemArtifact,
            [string]$WrongFormatArtifact,
            [string]$WrongExtensionArtifact,
            [string]$OptionalArtifact,
            [switch]$OmitArtifactSet,
            [switch]$OmitIdentifierPattern,
            [switch]$DuplicateSequence,
            [switch]$BreakSequence
        )

        $placeholder = '<id>'
        $artifacts = [System.Collections.Generic.List[object]]::new()
        $sequence = 0

        foreach ($name in $script:ChangeArtifacts) {
            if ($name -eq $OmitArtifact) { continue }

            $sequence++
            $format = $script:ExpectedFormat[$name]
            if ($name -eq $WrongFormatArtifact) {
                $format = if ($format -eq 'Json') { 'PowerShell' } else { 'Json' }
            }

            $stem = $name.ToLowerInvariant()
            $extension = $script:FormatExtension[$script:ExpectedFormat[$name]]
            $template = '{0}-{1}{2}' -f $stem, $placeholder, $extension
            if ($name -eq $WithoutTemplateArtifact) { $template = '' }
            elseif ($name -eq $WithoutPlaceholderArtifact) { $template = '{0}{1}' -f $stem, $extension }
            elseif ($name -eq $WrongStemArtifact) { $template = 'plan-{0}{1}' -f $placeholder, $extension }
            elseif ($name -eq $WrongExtensionArtifact) { $template = '{0}-{1}.txt' -f $stem, $placeholder }

            $declaredSequence = $sequence
            if ($DuplicateSequence -and $name -eq 'Apply') { $declaredSequence = 1 }
            elseif ($BreakSequence -and $name -eq 'PostChange') { $declaredSequence = 9 }

            $artifacts.Add([pscustomobject]@{
                    Artifact         = $name
                    FileNameTemplate = $template
                    Format           = $format
                    Sequence         = $declaredSequence
                    Required         = ($name -ne $OptionalArtifact)
                })
        }

        if ($AddArtifact) {
            $artifacts.Add([pscustomobject]@{
                    Artifact         = $AddArtifact
                    FileNameTemplate = ('{0}-{1}.json' -f $AddArtifact.ToLowerInvariant(), $placeholder)
                    Format           = 'Json'
                    Sequence         = ++$sequence
                    Required         = $true
                })
        }

        $fixture = [ordered]@{}
        if (-not $OmitIdentifierPattern) {
            $fixture['ChangeIdentifierPattern'] = '^[A-Za-z0-9][A-Za-z0-9-]{0,63}$'
            $fixture['ChangeIdentifierPlaceholder'] = $placeholder
        }
        if (-not $OmitArtifactSet) {
            $fixture['Artifact'] = @($artifacts)
        }

        return [pscustomobject]$fixture
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-001-A1 the change artifact contract' {

    Context 'Negative: the contract does not declare the artifact set' {

        It 'reports ContractMissing when no contract is published' {
            # Arrange
            $contract = $null

            # Act
            $verdict = Get-ChangeArtifactVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'a change nobody declared artifacts for leaves nothing behind to audit'
            $verdict.Reason | Should -Be 'ContractMissing'
        }

        It 'reports ArtifactSetMissing when the contract declares no artifacts' {
            # Arrange
            $contract = New-ChangeArtifactFixture -OmitArtifactSet

            # Act
            $verdict = Get-ChangeArtifactVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'a contract naming no artifact emits nothing'
            $verdict.Reason | Should -Be 'ArtifactSetMissing'
        }

        It 'reports ChangeIdentifierPatternMissing when the contract declares no change identifier pattern' {
            # Arrange
            $contract = New-ChangeArtifactFixture -OmitIdentifierPattern

            # Act
            $verdict = Get-ChangeArtifactVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'artifacts named after an unconstrained identifier can be written anywhere'
            $verdict.Reason | Should -Be 'ChangeIdentifierPatternMissing'
        }

        It "reports ArtifactNotDeclared when '<_>' is not in the set" -ForEach $ChangeArtifacts {
            # Arrange
            $artifact = $_
            $contract = New-ChangeArtifactFixture -OmitArtifact $artifact

            # Act
            $verdict = Get-ChangeArtifactVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because "$artifact is one of the six a change has to leave behind"
            $verdict.Reason | Should -Be 'ArtifactNotDeclared'
            $verdict.Violations | Should -Be @($artifact)
        }

        It 'reports UnknownArtifactDeclared when an artifact outside the set is declared' {
            # Arrange
            $contract = New-ChangeArtifactFixture -AddArtifact 'Scratch'

            # Act
            $verdict = Get-ChangeArtifactVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'an artifact nothing reads is an artifact nobody reviews'
            $verdict.Reason | Should -Be 'UnknownArtifactDeclared'
            $verdict.Violations | Should -Be @('Scratch')
        }
    }

    Context 'Negative: an artifact does not declare the file it emits' {

        It 'reports FileNameTemplateMissing when an artifact declares no file name' {
            # Arrange
            $contract = New-ChangeArtifactFixture -WithoutTemplateArtifact 'Approval'

            # Act
            $verdict = Get-ChangeArtifactVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'an artifact with no declared file name is one every run can name differently'
            $verdict.Reason | Should -Be 'FileNameTemplateMissing'
            $verdict.Violations | Should -Be @('Approval')
        }

        It 'reports ChangeIdentifierPlaceholderMissing when a file name does not carry the change identifier' {
            # Arrange
            $contract = New-ChangeArtifactFixture -WithoutPlaceholderArtifact 'Preview'

            # Act
            $verdict = Get-ChangeArtifactVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'a fixed file name means the second change overwrites the first change evidence'
            $verdict.Reason | Should -Be 'ChangeIdentifierPlaceholderMissing'
            $verdict.Violations | Should -Be @('Preview')
        }

        It 'reports FileNameStemMismatch when a file name is not built from the artifact name' {
            # Arrange
            $contract = New-ChangeArtifactFixture -WrongStemArtifact 'PreChange'

            # Act
            $verdict = Get-ChangeArtifactVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'an artifact file nobody can identify from its name is one nobody finds'
            $verdict.Reason | Should -Be 'FileNameStemMismatch'
            $verdict.Violations | Should -Be @('PreChange')
        }

        It "reports ArtifactFormatMismatch when '<_>' declares the wrong format" -ForEach $ChangeArtifacts {
            # Arrange
            $artifact = $_
            $contract = New-ChangeArtifactFixture -WrongFormatArtifact $artifact

            # Act
            $verdict = Get-ChangeArtifactVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'the rollback is the one artifact that has to run, and the rest have to be read by machine'
            $verdict.Reason | Should -Be 'ArtifactFormatMismatch'
            $verdict.Violations | Should -Be @($artifact)
        }

        It 'reports FileNameExtensionMismatch when a file name extension does not match its declared format' {
            # Arrange
            $contract = New-ChangeArtifactFixture -WrongExtensionArtifact 'Apply'

            # Act
            $verdict = Get-ChangeArtifactVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'a file whose extension disagrees with its format is opened by the wrong tool'
            $verdict.Reason | Should -Be 'FileNameExtensionMismatch'
            $verdict.Violations | Should -Be @('Apply')
        }
    }

    Context 'Negative: the set does not order or require the artifacts' {

        It 'reports SequenceDuplicated when two artifacts claim the same position' {
            # Arrange
            $contract = New-ChangeArtifactFixture -DuplicateSequence

            # Act
            $verdict = Get-ChangeArtifactVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'two artifacts at one position leave the order of the change undecided'
            $verdict.Reason | Should -Be 'SequenceDuplicated'
        }

        It 'reports SequenceNotContiguous when the order skips a position' {
            # Arrange
            $contract = New-ChangeArtifactFixture -BreakSequence

            # Act
            $verdict = Get-ChangeArtifactVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'a gap in the order is a stage of the change nothing accounts for'
            $verdict.Reason | Should -Be 'SequenceNotContiguous'
        }

        It "reports ArtifactOptional when '<_>' is declared optional" -ForEach $ChangeArtifacts {
            # Arrange
            $artifact = $_
            $contract = New-ChangeArtifactFixture -OptionalArtifact $artifact

            # Act
            $verdict = Get-ChangeArtifactVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'an artifact a run may skip is an artifact no audit can rely on'
            $verdict.Reason | Should -Be 'ArtifactOptional'
            $verdict.Violations | Should -Be @($artifact)
        }
    }

    Context 'Negative: the contract is not something a caller can rewrite' {

        It 'refuses assignment to the declared artifact set' {
            # Arrange
            $contract = Get-BaselineChangeArtifactContract

            # Act
            $act = { $contract.Artifact = @() }

            # Assert
            $act | Should -Throw -Because 'a contract a caller can edit at runtime is a contract that says whatever the caller needs it to say'
        }
    }

    Context 'Positive: the contract declares the whole change artifact set' {

        It 'declares preview, approval, pre-change, apply, rollback, and post-change artifacts in change order' {
            # Arrange
            $expected = $script:ChangeArtifacts

            # Act
            $contract = Get-BaselineChangeArtifactContract

            # Assert
            ('Verdict={0}:Order={1}:Names={2}' -f
                (Get-ChangeArtifactVerdict -Contract $contract).Reason,
                ((@($contract.Artifact) | Sort-Object { [int]$_.Sequence } | ForEach-Object { [string]$_.Artifact }) -join ','),
                ((@($contract.Artifact) | Sort-Object { [int]$_.Sequence } | ForEach-Object { [string]$_.FileNameTemplate }) -join ',')) |
                Should -BeExactly ('Verdict=ChangeArtifactContractSatisfied:Order={0}:Names=preview-<id>.json,approval-<id>.json,prechange-<id>.json,apply-<id>.json,rollback-<id>.ps1,postchange-<id>.json' -f ($expected -join ',')) -Because 'a change that cannot produce all six in order is a change nobody can reconstruct afterwards'
        }
    }
}
