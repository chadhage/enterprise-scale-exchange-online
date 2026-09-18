#requires -Version 7.0

# Discovery-scope copies so the per-case negatives can be expanded by -ForEach.
$RejectedChangeIdentifier = @(
    @{ Case = 'null'; Value = $null }
    @{ Case = 'empty'; Value = '' }
    @{ Case = 'whitespace'; Value = '   ' }
    @{ Case = 'a directory separator'; Value = 'evidence/CHG0012345' }
    @{ Case = 'a parent-directory segment'; Value = '..' }
)

$RejectedArtifactName = @(
    @{ Case = 'null'; Value = $null }
    @{ Case = 'empty'; Value = '' }
    @{ Case = 'whitespace'; Value = '   ' }
    @{ Case = 'an artifact the contract never declared'; Value = 'Journal' }
    @{ Case = 'an artifact named in the wrong case'; Value = 'preview' }
)

$RejectedRoot = @(
    @{ Case = 'null'; Value = $null }
    @{ Case = 'empty'; Value = '' }
    @{ Case = 'whitespace'; Value = '   ' }
)

$JsonArtifact = @('Preview', 'Approval', 'PreChange', 'Apply', 'PostChange')

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ChangeId = 'CHG0012345'
    $script:RollbackText = "#requires -Version 7.0`nSet-TransportConfig -Identity 'Default' -SmtpClientAuthenticationDisabled `$false`n"

    # A fresh directory per case, so one case cannot see another case's emission.
    function New-EmissionRoot {
        $path = Join-Path ([System.IO.Path]::GetTempPath()) ('change-emission-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        return $path
    }

    $script:SampleContent = [ordered]@{
        changeId  = 'CHG0012345'
        tenant    = 'contoso.onmicrosoft.com'
        operation = @(
            [ordered]@{ command = 'Set-TransportConfig'; identity = 'Default' }
        )
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-001-A3 change artifact emission' {

    Context 'Negative: an emission the caller did not fully describe' {

        It 'refuses a change identifier that is <Case>' -ForEach $RejectedChangeIdentifier {
            # Arrange
            $root = New-EmissionRoot

            # Act
            $act = { Write-BaselineChangeArtifact -ChangeId $Value -Artifact 'Preview' -Root $root -Content $script:SampleContent }

            # Assert
            $act | Should -Throw -Because 'an artifact file named from an unchecked identifier is a write to wherever that identifier points'
        }

        It 'refuses an artifact name that is <Case>' -ForEach $RejectedArtifactName {
            # Arrange
            $root = New-EmissionRoot

            # Act
            $act = { Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact $Value -Root $root -Content $script:SampleContent }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeArtifactNotDeclared*' -Because 'an artifact the contract never declared is a file no audit knows to read'
        }

        It 'refuses a destination root that is <Case>' -ForEach $RejectedRoot {
            # Arrange
            $artifact = 'Preview'

            # Act
            $act = { Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact $artifact -Root $Value -Content $script:SampleContent }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeArtifactRootNotSupplied*' -Because 'an artifact written to no stated directory is written to whatever the process happened to be sitting in'
        }

        It 'refuses content that is null' {
            # Arrange
            $root = New-EmissionRoot

            # Act
            $act = { Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact 'Preview' -Root $root -Content $null }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeArtifactContentNotSupplied*' -Because 'an empty artifact is an artifact that records the change never happened'
        }

        It 'refuses rollback content that is not executable text' {
            # Arrange
            $root = New-EmissionRoot

            # Act
            $act = { Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact 'Rollback' -Root $root -Content $script:SampleContent }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeArtifactContentNotExecutable*' -Because 'a rollback that is a document rather than a script is a rollback nobody can run'
        }
    }

    Context 'Negative: the artifact does not land where the set resolved it' {

        It 'writes the <_> artifact to the path the set resolved and to nowhere else' -ForEach $JsonArtifact {
            # Arrange
            $artifact = $_
            $root = New-EmissionRoot
            $expected = [string]((New-BaselineChangeArtifactSet -ChangeId $script:ChangeId -Root $root) | Where-Object { [string]$_.Artifact -eq $artifact }).Path

            # Act
            Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact $artifact -Root $root -Content $script:SampleContent | Out-Null

            # Assert
            (@(Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object { $_.FullName }) -join ',') |
                Should -BeExactly $expected -Because 'an artifact written anywhere but its resolved path is an artifact the audit never finds'
        }

        It 'creates the destination root when the run has not written to it yet' {
            # Arrange
            $root = Join-Path ([System.IO.Path]::GetTempPath()) ('change-emission-' + [guid]::NewGuid().ToString('N'))

            # Act
            $record = Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact 'Preview' -Root $root -Content $script:SampleContent

            # Assert
            (Test-Path -LiteralPath $record.Path -PathType Leaf) | Should -BeTrue -Because 'a writer that requires the directory to already exist loses the first artifact of every change'
        }

        It 'reports only a path it actually wrote' {
            # Arrange
            $root = New-EmissionRoot

            # Act
            $record = Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact 'Apply' -Root $root -Content $script:SampleContent

            # Assert
            (Test-Path -LiteralPath ([string]$record.Path) -PathType Leaf) | Should -BeTrue -Because 'a reported path with no file behind it is an artifact reference that fails at the audit, not at the run'
        }
    }

    Context 'Negative: the bytes on disk are not the artifact the caller handed over' {

        It 'writes the <_> artifact as the canonical JSON of the content' -ForEach $JsonArtifact {
            # Arrange
            $artifact = $_
            $root = New-EmissionRoot
            $expected = ConvertTo-CanonicalJson -InputObject $script:SampleContent

            # Act
            $record = Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact $artifact -Root $root -Content $script:SampleContent

            # Assert
            [System.IO.File]::ReadAllText([string]$record.Path) |
                Should -BeExactly $expected -Because 'an artifact whose text depends on how PowerShell felt like serializing it cannot be compared across two runs'
        }

        It 'writes the rollback artifact as exactly the executable text it was handed' {
            # Arrange
            $root = New-EmissionRoot

            # Act
            $record = Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact 'Rollback' -Root $root -Content $script:RollbackText

            # Assert
            [System.IO.File]::ReadAllText([string]$record.Path) |
                Should -BeExactly $script:RollbackText -Because 'a rollback the writer reformatted is a script nobody reviewed'
        }

        It 'writes the artifact without a byte-order mark' {
            # Arrange
            $root = New-EmissionRoot

            # Act
            $record = Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact 'Preview' -Root $root -Content $script:SampleContent

            # Assert
            (@([System.IO.File]::ReadAllBytes([string]$record.Path)) | Select-Object -First 3) -join ',' |
                Should -Not -BeExactly '239,187,191' -Because 'a mark in front of the first byte changes the hash of an artifact whose text never changed'
        }

        It 'reports the hash of the bytes it wrote' {
            # Arrange
            $root = New-EmissionRoot

            # Act
            $record = Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact 'Preview' -Root $root -Content $script:SampleContent

            # Assert
            [string]$record.Hash |
                Should -BeExactly ([string](Get-FileHash -LiteralPath ([string]$record.Path) -Algorithm SHA256).Hash).ToLowerInvariant() -Because 'a hash taken over something other than the file is a seal that proves nothing about the file'
        }
    }

    Context 'Negative: a second emission overwrites the first' {

        It 'refuses to emit an artifact the change has already emitted' {
            # Arrange
            $root = New-EmissionRoot
            Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact 'Preview' -Root $root -Content $script:SampleContent | Out-Null

            # Act
            $act = { Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact 'Preview' -Root $root -Content $script:SampleContent }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeArtifactAlreadyEmitted*' -Because 'a change that can rewrite its own preview is a change whose approved plan is whatever it last wrote'
        }

        It 'leaves the first emission intact when a second is refused' {
            # Arrange
            $root = New-EmissionRoot
            $first = Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact 'Preview' -Root $root -Content $script:SampleContent

            # Act
            try { Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact 'Preview' -Root $root -Content ([ordered]@{ changeId = 'other' }) } catch { }

            # Assert
            ([string](Get-FileHash -LiteralPath ([string]$first.Path) -Algorithm SHA256).Hash).ToLowerInvariant() |
                Should -BeExactly ([string]$first.Hash) -Because 'a refusal that still truncated the file has destroyed the artifact it was protecting'
        }
    }

    Context 'Negative: the emitted record is not fixed' {

        It 'refuses assignment to the emitted path' {
            # Arrange
            $root = New-EmissionRoot
            $record = Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact 'Preview' -Root $root -Content $script:SampleContent

            # Act
            $act = { $record.Path = 'somewhere-else.json' }

            # Assert
            $act | Should -Throw -Because 'a record a caller can rewrite reports whatever the caller wanted written'
        }

        It 'refuses assignment to the emitted hash' {
            # Arrange
            $root = New-EmissionRoot
            $record = Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact 'Preview' -Root $root -Content $script:SampleContent

            # Act
            $act = { $record.Hash = '0' }

            # Assert
            $act | Should -Throw -Because 'a seal a caller can replace is not a seal'
        }
    }

    Context 'Positive: one artifact is emitted to its resolved path under its own seal' {

        It 'emits the preview to its resolved path and reports that path with the hash of what it wrote' {
            # Arrange
            $root = New-EmissionRoot
            $expectedPath = [string]((New-BaselineChangeArtifactSet -ChangeId $script:ChangeId -Root $root) | Where-Object { [string]$_.Artifact -eq 'Preview' }).Path

            # Act
            $record = Write-BaselineChangeArtifact -ChangeId $script:ChangeId -Artifact 'Preview' -Root $root -Content $script:SampleContent

            # Assert
            '{0}|{1}|{2}' -f $record.Artifact, $record.Path, $record.Hash |
                Should -BeExactly ('{0}|{1}|{2}' -f 'Preview', $expectedPath, ([string](Get-FileHash -LiteralPath $expectedPath -Algorithm SHA256).Hash).ToLowerInvariant()) -Because 'a change that cannot show the file it wrote and the seal over it has left no evidence of itself'
        }
    }
}
