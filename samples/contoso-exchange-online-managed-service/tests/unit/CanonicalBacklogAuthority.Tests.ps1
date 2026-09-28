#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:ValidatorPath = Join-Path $script:SampleRoot 'scripts' 'Test-CanonicalBacklogAuthority.ps1'

    function New-BacklogAuthorityFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Name,

            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [AllowEmptyString()]
            [string[]]$BacklogLine,

            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [AllowEmptyString()]
            [string[]]$KanbanLine
        )

        $root = Join-Path $TestDrive $Name
        $githubRoot = Join-Path $root '.github'
        $null = New-Item -ItemType Directory -Path $githubRoot -Force

        $backlogPath = Join-Path $githubRoot 'backlog.md'
        $kanbanPath = Join-Path $githubRoot 'kanban.md'
        Set-Content -LiteralPath $backlogPath -Value $BacklogLine -Encoding utf8
        Set-Content -LiteralPath $kanbanPath -Value $KanbanLine -Encoding utf8

        return [pscustomobject]@{
            BacklogPath = $backlogPath
            KanbanPath  = $kanbanPath
        }
    }

    function New-CanonicalBacklogLine {
        return @(
            '# Exchange Online Remediation Backlog'
            ''
            'Canonical generation: 285. Updated: 2026-09-27. Executable cards: 90; To Do 50, In Progress 1, Done 39; 24 summary parents excluded.'
        )
    }

    function New-HistoricalKanbanLine {
        return @(
            '# Exchange Online Hardening Kanban'
            ''
            '> **Historical compatibility view — not a canonical status authority.** Current executable status, ranks, dependencies, counts and release eligibility are owned exclusively by [the canonical remediation backlog](backlog.md).'
            ''
            'Board updated: 2026-09-27 (generation 284 historical snapshot)'
            '| Bucket | Count |'
            '| --- | ---: |'
            '| To Do | 36 |'
            '| In Progress | 0 |'
            '| Done | 193 |'
            'Executable cards: 229; summary parents excluded: 1. Board revision: 284.'
        )
    }
}

Describe 'EXR-018-A01 canonical backlog authority validator' {

    Context 'Negative: canonical authority is ambiguous or absent' {

        It 'rejects multiple files claiming canonical status authority' {
            # Arrange
            $fixture = New-BacklogAuthorityFixture -Name 'multiple-authorities' `
                -BacklogLine (New-CanonicalBacklogLine) `
                -KanbanLine @(
                    '# Exchange Online Hardening Kanban'
                    ''
                    'Canonical generation: 285. Updated: 2026-09-27. Executable cards: 229; To Do 36, In Progress 0, Done 193.'
                    ''
                    'This board is the canonical status authority for current card status and counts.'
                )

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $fixture.BacklogPath -KanbanPath $fixture.KanbanPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'CanonicalAuthorityMultiple*' -Because 'two writable boards cannot independently own current generation, counts, and status'
        }

        It 'rejects inputs in which no file claims canonical status authority' {
            # Arrange
            $fixture = New-BacklogAuthorityFixture -Name 'no-authority' `
                -BacklogLine @(
                    '# Exchange Online Remediation Notes'
                    ''
                    'Generated planning notes for generation 285; this file is not a status authority.'
                ) `
                -KanbanLine @(
                    '# Exchange Online Hardening Kanban'
                    ''
                    '> **Historical compatibility view — not a canonical status authority.** See [the remediation notes](backlog.md).'
                )

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $fixture.BacklogPath -KanbanPath $fixture.KanbanPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'CanonicalAuthorityMissing*' -Because 'generated notes and a historical view provide no canonical current-status source'
        }
    }

    Context 'Negative: legacy authority metadata is unsafe' {

        It 'rejects an unarchived writable legacy authority' {
            # Arrange
            $fixture = New-BacklogAuthorityFixture -Name 'writable-legacy' `
                -BacklogLine (New-CanonicalBacklogLine) `
                -KanbanLine @(
                    '# Exchange Online Hardening Kanban'
                    ''
                    '> **Legacy compatibility board.** Current entries remain writable and may be updated independently from [the canonical remediation backlog](backlog.md).'
                    ''
                    'Board updated: 2026-09-27 (generation 284)'
                )

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $fixture.BacklogPath -KanbanPath $fixture.KanbanPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'LegacyAuthorityWritable*' -Because 'a legacy status source must be explicitly historical, generated, or read-only'
        }

        It 'rejects a historical view whose canonical identity does not match the declared canonical backlog' {
            # Arrange
            $fixture = New-BacklogAuthorityFixture -Name 'identity-mismatch' `
                -BacklogLine (New-CanonicalBacklogLine) `
                -KanbanLine @(
                    '# Exchange Online Hardening Kanban'
                    ''
                    '> **Historical compatibility view — not a canonical status authority.** Current status is owned exclusively by [a different canonical backlog](release-backlog.md).'
                    ''
                    'Board updated: 2026-09-27 (generation 284 historical snapshot)'
                )

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $fixture.BacklogPath -KanbanPath $fixture.KanbanPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'CanonicalIdentityMismatch*' -Because 'every derived or historical view must link to the same canonical backlog identity'
        }

        It 'rejects a historical legacy view that claims independent current generation, count, or status authority' {
            # Arrange
            $fixture = New-BacklogAuthorityFixture -Name 'independent-current-claim' `
                -BacklogLine (New-CanonicalBacklogLine) `
                -KanbanLine @(
                    '# Exchange Online Hardening Kanban'
                    ''
                    '> **Historical compatibility view.** Linked to [the canonical remediation backlog](backlog.md).'
                    ''
                    'Current generation: 285.'
                    'Current executable counts: To Do 36, In Progress 0, Done 193.'
                    'This legacy board independently governs current card status.'
                )

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $fixture.BacklogPath -KanbanPath $fixture.KanbanPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'LegacyIndependentAuthorityClaim*' -Because 'a historical view may preserve old metadata but cannot claim current generation, counts, or status authority'
        }
    }

    Context 'Positive: one canonical authority with a derived legacy view' {

        It 'accepts backlog.md as canonical when every other supplied board is historical, generated, or read-only and linked to it' {
            # Arrange
            $fixture = New-BacklogAuthorityFixture -Name 'single-canonical-authority' `
                -BacklogLine (New-CanonicalBacklogLine) `
                -KanbanLine (New-HistoricalKanbanLine)

            # Act
            $result = & $script:ValidatorPath -BacklogPath $fixture.BacklogPath -KanbanPath $fixture.KanbanPath

            # Assert
            $result.AuthorityCount | Should -Be 1
            $result.CanonicalPath | Should -Be $fixture.BacklogPath
            $result.LegacyMode | Should -Be 'HistoricalGeneratedOrReadOnly'
        }
    }
}
