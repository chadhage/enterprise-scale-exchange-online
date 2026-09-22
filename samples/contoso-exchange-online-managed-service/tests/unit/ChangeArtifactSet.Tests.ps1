#requires -Version 7.0

# Discovery-scope copies so the per-case negatives can be expanded by -ForEach.
$RejectedChangeIdentifier = @(
    @{ Case = 'null'; Value = $null }
    @{ Case = 'empty'; Value = '' }
    @{ Case = 'whitespace'; Value = '   ' }
    @{ Case = 'forward slash'; Value = 'evidence/CHG0012345' }
    @{ Case = 'back slash'; Value = 'evidence\CHG0012345' }
    @{ Case = 'parent directory'; Value = '..' }
    @{ Case = 'parent directory segment'; Value = '..CHG0012345' }
    @{ Case = 'drive qualifier'; Value = 'C:CHG0012345' }
    @{ Case = 'asterisk wildcard'; Value = 'CHG*' }
    @{ Case = 'question mark wildcard'; Value = 'CHG?12345' }
    @{ Case = 'embedded space'; Value = 'CHG 0012345' }
    @{ Case = 'underscore'; Value = 'CHG_0012345' }
    @{ Case = 'dot'; Value = 'CHG.0012345' }
    @{ Case = 'leading hyphen'; Value = '-CHG0012345' }
    @{ Case = 'over the permitted length'; Value = ('C' * 65) }
)

$ChangeArtifacts = @('Preview', 'Approval', 'PreChange', 'Apply', 'Rollback', 'PostChange')

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ChangeId = 'CHG0012345'

    # Named here rather than read off the contract, so a resolver that renames a file is a failure
    # rather than a smaller expectation.
    $script:ExpectedFileName = @(
        'preview-CHG0012345.json'
        'approval-CHG0012345.json'
        'prechange-CHG0012345.json'
        'apply-CHG0012345.json'
        'rollback-CHG0012345.ps1'
        'postchange-CHG0012345.json'
    )
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-001-A2 change artifact set resolution' {

    Context 'Negative: an identifier that is not a change identifier names no artifact set' {

        It 'refuses a change identifier that is <Case>' -ForEach $RejectedChangeIdentifier {
            # Arrange
            $candidate = $Value

            # Act
            $act = { New-BaselineChangeArtifactSet -ChangeId $candidate }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeIdentifierNotRecognized*' -Because 'an artifact file name built from an unchecked identifier is a write to wherever that identifier points'
        }
    }

    Context 'Negative: the resolved set does not account for every artifact' {

        It 'resolves exactly one entry per declared artifact' {
            # Arrange
            $declared = @((Get-BaselineChangeArtifactContract).Artifact | ForEach-Object { [string]$_.Artifact })

            # Act
            $resolved = @((New-BaselineChangeArtifactSet -ChangeId $script:ChangeId) | ForEach-Object { [string]$_.Artifact })

            # Assert
            ($resolved -join ',') | Should -BeExactly ($declared -join ',') -Because 'an artifact the resolver never names is an artifact no run is ever asked to write'
        }

        It 'orders the entries by the sequence the contract declares' {
            # Arrange
            $contract = Get-BaselineChangeArtifactContract
            $expected = @($contract.Artifact | Sort-Object { [int]$_.Sequence } | ForEach-Object { [string]$_.Artifact })

            # Act
            $resolved = @((New-BaselineChangeArtifactSet -ChangeId $script:ChangeId) | ForEach-Object { [string]$_.Artifact })

            # Assert
            ($resolved -join ',') | Should -BeExactly ($expected -join ',') -Because 'artifacts written out of change order describe a change that never happened in that order'
        }
    }

    Context 'Negative: a resolved file name is not the contract template carrying the identifier' {

        It "names the '<_>' artifact from its own template" -ForEach $ChangeArtifacts {
            # Arrange
            $artifact = $_
            $template = [string]((@((Get-BaselineChangeArtifactContract).Artifact) | Where-Object { [string]$_.Artifact -eq $artifact }).FileNameTemplate)

            # Act
            $fileName = [string](((New-BaselineChangeArtifactSet -ChangeId $script:ChangeId) | Where-Object { [string]$_.Artifact -eq $artifact }).FileName)

            # Assert
            $fileName | Should -BeExactly $template.Replace('<id>', $script:ChangeId) -Because 'a file name the contract did not declare is an artifact nothing downstream knows to read'
        }

        It 'leaves no change identifier placeholder unsubstituted' {
            # Arrange
            $placeholder = [string]((Get-BaselineChangeArtifactContract).ChangeIdentifierPlaceholder)

            # Act
            $unsubstituted = @((New-BaselineChangeArtifactSet -ChangeId $script:ChangeId) | Where-Object { [string]$_.FileName -like "*$placeholder*" } | ForEach-Object { [string]$_.Artifact })

            # Assert
            ($unsubstituted -join ',') | Should -BeExactly '' -Because 'a literal placeholder on disk is every change writing over the same file'
        }
    }

    Context 'Negative: the resolved set ignores where it was asked to write' {

        It 'joins a supplied root directory to every entry' {
            # Arrange
            $root = Join-Path ([System.IO.Path]::GetTempPath()) 'baseline-change-evidence'

            # Act
            $unrooted = @((New-BaselineChangeArtifactSet -ChangeId $script:ChangeId -Root $root) | Where-Object { [string]$_.Path -ne (Join-Path $root ([string]$_.FileName)) } | ForEach-Object { [string]$_.Artifact })

            # Assert
            ($unrooted -join ',') | Should -BeExactly '' -Because 'an artifact written somewhere other than the directory the run was given is an artifact the audit never finds'
        }

        It 'resolves the path to the bare file name when no root is supplied' {
            # Arrange
            $expected = $script:ExpectedFileName

            # Act
            $path = @((New-BaselineChangeArtifactSet -ChangeId $script:ChangeId) | ForEach-Object { [string]$_.Path })

            # Assert
            ($path -join ',') | Should -BeExactly ($expected -join ',') -Because 'a resolver that invents a directory of its own writes where nobody asked it to'
        }
    }

    Context 'Negative: the resolved set is not stable or not fixed' {

        It 'resolves one identifier to one set' {
            # Arrange
            $changeId = $script:ChangeId

            # Act
            $distinct = @(1, 2 | ForEach-Object { (@((New-BaselineChangeArtifactSet -ChangeId $changeId) | ForEach-Object { '{0}={1}' -f $_.Artifact, $_.FileName })) -join ';' } | Select-Object -Unique)

            # Assert
            $distinct.Count | Should -Be 1 -Because 'two runs of one change that disagree on the file names leave two half-recorded changes'
        }

        It 'refuses assignment to a resolved file name' {
            # Arrange
            $set = New-BaselineChangeArtifactSet -ChangeId $script:ChangeId

            # Act
            $act = { $set[0].FileName = 'preview.json' }

            # Assert
            $act | Should -Throw -Because 'a set a caller can rewrite after resolution is a set that names whatever the caller writes'
        }

        It 'refuses assignment to a resolved entry' {
            # Arrange
            $set = New-BaselineChangeArtifactSet -ChangeId $script:ChangeId

            # Act
            $act = { $set[0] = $null }

            # Assert
            $act | Should -Throw -Because 'an entry a caller can drop is an artifact the run stops producing'
        }
    }

    Context 'Positive: one change identifier resolves the whole artifact set' {

        It 'resolves preview, approval, pre-change, apply, rollback, and post-change file names in change order' {
            # Arrange
            $expected = $script:ExpectedFileName

            # Act
            $set = New-BaselineChangeArtifactSet -ChangeId $script:ChangeId

            # Assert
            (@($set) | ForEach-Object { [string]$_.FileName }) -join ',' |
                Should -BeExactly ($expected -join ',') -Because 'a change that cannot name all six files for its own identifier cannot be reconstructed from disk'
        }
    }
}
