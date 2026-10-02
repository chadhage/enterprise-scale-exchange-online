#requires -Version 7.0

[CmdletBinding()]
param(
    [string]$BacklogPath = (Join-Path $PSScriptRoot 'backlog.md'),
    [string]$CohortsPath = (Join-Path $PSScriptRoot 'cohorts.md'),
    [string]$KanbanPath = (Join-Path $PSScriptRoot 'kanban.md')
)

$ErrorActionPreference = 'Stop'

function Assert-Board {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "DispatchBoardInvalid: $Message"
    }
}

function Get-Generation {
    param([string]$Content, [string]$Pattern, [string]$Name)
    $match = [regex]::Match($Content, $Pattern)
    Assert-Board $match.Success "$Name generation is missing."
    [int]$match.Groups['generation'].Value
}

function Get-CanonicalCards {
    param([string]$Content)

    $start = [regex]::Match($Content, '(?m)^## Force-Ranked Work[ \t]*\r?$')
    Assert-Board $start.Success 'Force-Ranked Work is missing.'
    $tail = $Content.Substring($start.Index + $start.Length)
    $next = [regex]::Match($tail, '(?m)^## [^\r\n]+\r?$')
    $canonical = if ($next.Success) { $tail.Substring(0, $next.Index) } else { $tail }
    $headings = [regex]::Matches($canonical, '(?m)^### (?<id>(?:EXR|REG)-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)[ \t]*\r?$')
    $cards = [System.Collections.Generic.List[object]]::new()

    for ($index = 0; $index -lt $headings.Count; $index++) {
        $heading = $headings[$index]
        $end = if ($index + 1 -lt $headings.Count) { $headings[$index + 1].Index } else { $canonical.Length }
        $bodyStart = $heading.Index + $heading.Length
        $body = $canonical.Substring($bodyStart, $end - $bodyStart)
        $rank = [regex]::Match($body, '(?im)^Rank\s+(?<rank>[^\r\n]+?)\r?$')
        $definition = if ($rank.Success) { $body.Substring($rank.Index) } else { $body }
        $statuses = @([regex]::Matches(
                $definition,
                '(?im)^\s*-\s*[^\r\n]*?\bStatus\s*:\s*(?<status>To Do|In Progress|Done)\b'
            ) | ForEach-Object { $_.Groups['status'].Value })
        $isSummary = (
            $body -match '(?im)^(?:Non-executable summary|Parent summary)\b' -or
            $body -match '(?im)^\s*-\s*[^\r\n]*\bStatus\s*:\s*excluded summary\b' -or
            (-not $rank.Success -and $statuses.Count -eq 0)
        )
        $dependencies = @()
        if (-not $isSummary) {
            Assert-Board ($statuses.Count -eq 1) "$($heading.Groups['id'].Value) must have exactly one status."
            $dependencyLine = [regex]::Match(
                $definition,
                '(?im)^\s*-\s*Dependencies\s*:\s*(?<dependencies>.*?)(?=\.\s+Owner\s*:|\r?$)'
            )
            Assert-Board $dependencyLine.Success "$($heading.Groups['id'].Value) dependencies are missing."
            $dependencies = @([regex]::Matches(
                    $dependencyLine.Groups['dependencies'].Value,
                    '\b(?:EXR|REG)-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*\b'
                ) | ForEach-Object { $_.Value } | Select-Object -Unique)
        }
        $cards.Add([pscustomobject]@{
                Id           = $heading.Groups['id'].Value
                Rank         = if ($rank.Success) { $rank.Groups['rank'].Value.Trim() } else { $null }
                Status       = if ($statuses.Count) { $statuses[0] } else { $null }
                IsSummary    = $isSummary
                Dependencies = $dependencies
            })
    }
    $cards
}

function Get-MarkdownTableRows {
    param([string]$Content, [string]$Heading, [string]$FirstColumn)

    $start = [regex]::Match($Content, "(?m)^## $([regex]::Escape($Heading))[ \t]*\r?$")
    Assert-Board $start.Success "$Heading is missing."
    $tail = $Content.Substring($start.Index + $start.Length)
    $next = [regex]::Match($tail, '(?m)^## [^\r\n]+\r?$')
    $section = if ($next.Success) { $tail.Substring(0, $next.Index) } else { $tail }
    @([regex]::Matches(
            $section,
            "(?m)^\|\s*``(?<$FirstColumn>[^``]+)``\s*\|\s*(?<c2>.*?)\s*\|\s*``(?<profile>[^``]+)``\s*\|\s*(?<reservation>.*?)\s*\|\s*(?<readonly>.*?)\s*\|\s*(?<validation>.*?)\s*\|\s*$"
        ) | ForEach-Object {
            [pscustomobject]@{
                Id          = $_.Groups[$FirstColumn].Value
                Dependency  = $_.Groups['c2'].Value
                Profile     = $_.Groups['profile'].Value
                Reservation = $_.Groups['reservation'].Value
                ReadOnly    = $_.Groups['readonly'].Value
                Validation  = $_.Groups['validation'].Value
            }
        })
}

$backlog = Get-Content -LiteralPath $BacklogPath -Raw
$cohorts = Get-Content -LiteralPath $CohortsPath -Raw
$kanban = Get-Content -LiteralPath $KanbanPath -Raw

$backlogGeneration = Get-Generation $backlog '(?im)^Canonical generation\s*:\s*(?<generation>\d+)\b' 'backlog'
$cohortGeneration = Get-Generation $cohorts '(?im)^Allocation generation\s*:\s*(?<generation>\d+)\b' 'cohorts'
$kanbanGeneration = Get-Generation $kanban '(?im)^Allocation generation mirrored\s*:\s*(?<generation>\d+)\b' 'kanban'
Assert-Board ($backlogGeneration -ge 605) 'generation must be at least 605.'
Assert-Board ($backlogGeneration -eq $cohortGeneration -and $backlogGeneration -eq $kanbanGeneration) 'generation disagreement.'

$cards = @(Get-CanonicalCards $backlog)
$duplicates = @($cards | Group-Object Id | Where-Object Count -gt 1)
Assert-Board ($duplicates.Count -eq 0) "duplicate active IDs: $($duplicates.Name -join ', ')."
$executables = @($cards | Where-Object { -not $_.IsSummary })
$summaries = @($cards | Where-Object IsSummary)
$todo = @($executables | Where-Object Status -eq 'To Do')
$inProgress = @($executables | Where-Object Status -eq 'In Progress')
$done = @($executables | Where-Object Status -eq 'Done')
Assert-Board ($executables.Count -eq 104) "expected 104 executable cards, found $($executables.Count)."
Assert-Board ($summaries.Count -eq 28) "expected 28 summary parents, found $($summaries.Count)."
Assert-Board ($todo.Count -eq 47 -and $inProgress.Count -eq 0 -and $done.Count -eq 57) "expected 47/0/57 buckets, found $($todo.Count)/$($inProgress.Count)/$($done.Count)."
Assert-Board (@($todo | Where-Object Id -ceq 'REG-001').Count -eq 1) 'REG-001 must be safely requeued To Do.'
Assert-Board (($done | Where-Object Id -eq 'EXR-010-A12-L01-F02').Count -eq 1) 'F02 must be Done.'
Assert-Board (($done | Where-Object Id -eq 'EXR-018-A01').Count -eq 1) 'EXR-018-A01 must be Done.'
$c01 = @($cards | Where-Object Id -ceq 'EXR-010-A12-L01-C01')
Assert-Board ($c01.Count -eq 1) 'C01 unique canonical ID is missing.'
Assert-Board ($c01[0].Rank -ceq '23.6 - Final canonical acceptance/Done transition.') 'C01 rank must be exactly 23.6.'
Assert-Board ($c01[0].Status -ceq 'Done') 'C01 must be Done.'
Assert-Board ($c01[0].Dependencies.Count -eq 1 -and $c01[0].Dependencies[0] -ceq 'EXR-010-A12-L01-F02') 'C01 must depend exactly on F02.'

$allIds = @{} 
foreach ($card in $cards) { $allIds[$card.Id] = $true }
$unknownDependencies = @(
    foreach ($card in $executables) {
        foreach ($dependency in $card.Dependencies) {
            if (-not $allIds.ContainsKey($dependency)) { "$($card.Id)->$dependency" }
        }
    }
)
Assert-Board ($unknownDependencies.Count -eq 0) "unknown active dependencies: $($unknownDependencies -join ', ')."

$profileStart = [regex]::Match($backlog, '(?m)^## Canonical dispatch profiles[ \t]*\r?$')
Assert-Board $profileStart.Success 'dispatch profiles are missing.'
$profileTail = $backlog.Substring($profileStart.Index + $profileStart.Length)
$profileEnd = [regex]::Match($profileTail, '(?m)^## [^\r\n]+\r?$')
$profileSection = $profileTail.Substring(0, $profileEnd.Index)
$profiles = @{}
foreach ($match in [regex]::Matches(
        $profileSection,
        '(?m)^\|\s*`(?<name>[A-Z0-9-]+)`\s*\|\s*(?<envelope>.+?)\s*\|\s*(?<validation>.+?)\s*\|\s*(?<expected>.+?)\s*\|\s*(?<evidence>.+?)\s*\|\s*(?<integration>.+?)\s*\|\s*(?<abort>.+?)\s*\|\s*(?<handoff>.+?)\s*\|\s*$'
    )) {
    $profiles[$match.Groups['name'].Value] = $match
}
Assert-Board ($profiles.Count -ge 1) 'no dispatch profiles resolved.'

$manifest = @(Get-MarkdownTableRows $backlog 'Canonical To Do dispatch manifest' 'card')
$manifestDuplicates = @($manifest | Group-Object Id | Where-Object Count -gt 1)
Assert-Board ($manifestDuplicates.Count -eq 0) "duplicate manifest IDs: $($manifestDuplicates.Name -join ', ')."
Assert-Board ($manifest.Count -eq 47) "expected 47 manifest entries, found $($manifest.Count)."
$unfinishedIds = @(($todo.Id + $inProgress.Id) | Sort-Object)
$manifestIds = @($manifest.Id | Sort-Object)
Assert-Board (($unfinishedIds -join "`n") -ceq ($manifestIds -join "`n")) 'manifest IDs do not exactly match unfinished executable IDs.'

foreach ($entry in $manifest) {
    Assert-Board $profiles.ContainsKey($entry.Profile) "$($entry.Id) profile $($entry.Profile) does not resolve."
    foreach ($field in 'Dependency', 'Reservation', 'ReadOnly', 'Validation') {
        Assert-Board (-not [string]::IsNullOrWhiteSpace($entry.$field)) "$($entry.Id) field $field is empty."
    }
    Assert-Board ($entry.Dependency -match '`(?:READY|WAIT-DEP|WAIT-EXT|WAIT-SUITE|CLAIMED:[^`]+)') "$($entry.Id) eligibility or claim binding is missing."
    Assert-Board ($entry.Validation -match 'F=' -and $entry.Validation -match 'A=') "$($entry.Id) focused/affected binding is incomplete."
    $profile = $profiles[$entry.Profile]
    foreach ($field in 'envelope', 'validation', 'expected', 'evidence', 'integration', 'abort', 'handoff') {
        Assert-Board (-not [string]::IsNullOrWhiteSpace($profile.Groups[$field].Value)) "$($entry.Id) resolved profile field $field is empty."
    }
}

function Normalize-Reservation {
    param([string]$Value)
    $trimmed = $Value.Trim().Trim('`').Replace('\', '/')
    if ($trimmed -match '^(?:DISCOVER:|evidence root only$|approval evidence only$)') { return $null }
    $trimmed
}

$eligible = @($manifest | Where-Object Dependency -match '`READY`')
Assert-Board ($eligible.Id -notcontains 'EXR-018-A01') 'Done card EXR-018-A01 must not remain pull-ready.'
$expectedReady = @(
    foreach ($area in 'A01', 'A02', 'A03', 'A04') {
        foreach ($unit in 'D01', 'D02', 'D03', 'D04') {
            "EXR-012-$area-$unit"
        }
    }
)
$claimedDiscovery = @()
$expectedUnclaimedReady = @($expectedReady | Where-Object { $_ -cnotin $claimedDiscovery })
Assert-Board ($eligible.Count -eq 16) "Platinum three-card release must restore exactly 16 unclaimed READY cards, found $($eligible.Count)."
Assert-Board (@($expectedUnclaimedReady | Where-Object { $_ -cnotin $eligible.Id }).Count -eq 0) 'The sixteen unclaimed EXR-012 documentation children must remain in the READY bank.'
Assert-Board ($inProgress.Count -eq 0) 'No REG-001 role may remain active after the generation-679 release.'
foreach ($parentId in 'EXR-012-A01', 'EXR-012-A02', 'EXR-012-A03', 'EXR-012-A04') {
    $parent = @($cards | Where-Object Id -ceq $parentId)
    Assert-Board ($parent.Count -eq 1 -and $parent[0].IsSummary) "$parentId must be an excluded aggregate summary."
}
foreach ($entry in $eligible) {
    $card = @($cards | Where-Object Id -ceq $entry.Id)
    Assert-Board ($card.Count -eq 1) "$($entry.Id) canonical card is missing."
    $unfinished = @($card[0].Dependencies | Where-Object {
            $dependency = $_
            @($cards | Where-Object { $_.Id -ceq $dependency -and $_.Status -ceq 'Done' }).Count -ne 1
        })
    Assert-Board ($unfinished.Count -eq 0) "$($entry.Id) is READY with unfinished dependencies: $($unfinished -join ', ')."
    Assert-Board ($entry.Reservation -match '^`DISCOVER:') "$($entry.Id) must remain discovery-gated until exact writable paths are frozen."
}
$a02 = @($manifest | Where-Object Id -eq 'EXR-018-A02')
Assert-Board ($a02.Count -eq 1 -and $a02[0].Dependency -match '`WAIT-EXT`') 'EXR-018-A02 must remain externally gated after A01 completion.'
$reservations = @(
    foreach ($entry in $eligible) {
        foreach ($raw in $entry.Reservation -split '\s*;\s*') {
            $normalized = Normalize-Reservation $raw
            if ($normalized) { [pscustomobject]@{ Card = $entry.Id; Path = $normalized } }
        }
    }
)
$conflicts = [System.Collections.Generic.List[string]]::new()
for ($left = 0; $left -lt $reservations.Count; $left++) {
    for ($right = $left + 1; $right -lt $reservations.Count; $right++) {
        if ($reservations[$left].Card -eq $reservations[$right].Card) { continue }
        $a = $reservations[$left].Path.TrimEnd('/')
        $b = $reservations[$right].Path.TrimEnd('/')
        if ($a -eq $b -or $a.StartsWith("$b/") -or $b.StartsWith("$a/")) {
            $conflicts.Add("$($reservations[$left].Card):$a <> $($reservations[$right].Card):$b")
        }
    }
}
Assert-Board ($conflicts.Count -eq 0) "eligible reservation conflicts: $($conflicts -join '; ')."

$generationPattern = [regex]::Escape([string]$backlogGeneration)
Assert-Board ($backlogGeneration -eq 679) 'REG-001 Purple release generation must be 679.'
Assert-Board ($backlog -match 'Generation 679 Purple REG-001 affected NACK, release, and safe requeue') 'Generation-679 backlog release is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 679 Purple REG-001 Affected NACK, Release And Requeue\r?$') 'Generation-679 registry release is missing.'
Assert-Board ($backlog -match '4,751' -and $backlog -match '1,542' -and $backlog -match '62 failed containers') 'Generation-679 affected NACK counts are missing.'
Assert-Board ($backlog -match 'Generation 678 Purple REG-001 post-run correction NACK and independent verification grant') 'Generation-678 backlog grant is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 678 Purple REG-001 Post-Run NACK And C3 Verification\r?$') 'Generation-678 registry grant is missing.'
Assert-Board ($cohorts -match 'root-canonical/Kanban/g678/preserve-g677-NACK-and-grant-C3-fresh-verification') 'Generation-678 C3 verification ACK is missing.'
Assert-Board ($backlog -match 'Generation 677 Purple REG-001 accepted red and ApprovedException repair grant') 'Generation-677 backlog grant is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 677 Purple REG-001 Accepted Red And C2 Repair\r?$') 'Generation-677 registry grant is missing.'
Assert-Board ($cohorts -match 'root-canonical/Kanban/g677/accept-red-and-grant-C2-approved-exception-repair') 'Generation-677 C2 repair ACK is missing.'
Assert-Board ($backlog -match 'Generation 676 Purple REG-001 C2 repair checkpoint and C1 fixture-prerequisite grant') 'Generation-676 backlog grant is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 676 Purple REG-001 C2 Checkpoint And C1 Fixture Grant\r?$') 'Generation-676 registry grant is missing.'
Assert-Board ($cohorts -match 'root-canonical/Kanban/g676/preserve-C2-repair-and-grant-C1-fixture-prerequisites') 'Generation-676 C1 fixture ACK is missing.'
Assert-Board ($backlog -match 'Generation 675 Purple REG-001 fixture acceptance and C2 evidence-creation grant') 'Generation-675 backlog grant is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 675 Purple REG-001 Fixture Acceptance And C2 Repair\r?$') 'Generation-675 registry grant is missing.'
Assert-Board ($cohorts -match 'root-canonical/Kanban/g675/accept-C1-fixture-and-grant-C2-evidence-creation-repair') 'Generation-675 C2 repair ACK is missing.'
Assert-Board ($backlog -match 'Generation 674 Purple REG-001 intended-red NACK and bounded fixture repair') 'Generation-674 backlog NACK is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 674 Purple REG-001 Intended-Red NACK And Fixture Repair\r?$') 'Generation-674 registry NACK is missing.'
Assert-Board ($cohorts -match 'root-canonical/Kanban/g674/nack-C1-container-and-grant-bounded-fixture-alignment') 'Generation-674 bounded repair ACK is missing.'
Assert-Board ($backlog -match 'Generation 673 four-cohort atomic allocation and Purple REG-001 claim') 'Generation-673 backlog claim record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 673 Four-Cohort Atomic Allocation And Purple REG-001 Claim\r?$') 'Generation-673 registry claim record is missing.'
Assert-Board ($cohorts -match 'root-canonical/Kanban/g673/atomic-four-cohort-claim-REG-001-Purple') 'Generation-673 ACK is missing.'
Assert-Board ($cohorts -match 'REG-001/Purple/g673/a03edfa70d5f48788b8e2f3a9b234afb') 'Generation-673 claim token is missing.'
Assert-Board ($cohorts -match 'dispatch/REG-001/Purple/Coworker-1/g673') 'Generation-673 branch binding is missing.'
Assert-Board ($cohorts -match 'exchange-online-protection-dispatch-REG-001-Purple-Coworker-1-g673') 'Generation-673 worktree binding is missing.'
foreach ($role in 1..3) {
    Assert-Board ($cohorts -match "\.artifacts/dispatch/REG-001/g673/Purple/Coworker-$role/") "Purple Coworker-$role evidence root is missing."
}
Assert-Board ($cohorts -match 'Silver retains D02 documentation queue affinity') 'Silver queue affinity is missing.'
Assert-Board ($cohorts -match 'Platinum g665 branch/worktree/evidence remain immutable read-only history') 'Platinum g665 supersession is missing.'
Assert-Board ($backlog -match 'Generation 672 REG-001 focused NACK, release, and safe requeue') 'Generation-672 backlog release record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 672 REG-001 Focused NACK, Release And Safe Requeue\r?$') 'Generation-672 registry release record is missing.'
Assert-Board ($backlog -match '67/69' -and $backlog -match 'full affected suite was correctly withheld') 'Generation-672 focused NACK evidence is missing.'
Assert-Board ($cohorts -match 'REG-001 returns In Progress -> To Do/unassigned as `WAIT-SUITE`') 'Generation-672 release disposition is missing.'
Assert-Board ($backlog -match 'Generation 671 REG-001 verifier NACK and ApprovedException repair grant') 'Generation-671 backlog NACK record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 671 REG-001 Verifier NACK And ApprovedException Repair Grant\r?$') 'Generation-671 registry NACK record is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g671/grant-REG-001-approved-exception-repair-to-Coworker-2') 'Generation-671 backlog repair ACK is missing.'
Assert-Board ($cohorts -match 'Platinum-root-coordinator/Kanban/g671/grant-REG-001-approved-exception-repair-to-Coworker-2') 'Generation-671 registry repair ACK is missing.'
Assert-Board ($backlog -match 'Generation 670 REG-001 independent-verification handoff') 'Generation-670 backlog handoff record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 670 REG-001 Independent Verification Handoff\r?$') 'Generation-670 registry handoff record is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g670/grant-REG-001-independent-focused-and-affected-to-Coworker-3') 'Generation-670 backlog verifier ACK is missing.'
Assert-Board ($cohorts -match 'Platinum-root-coordinator/Kanban/g670/grant-REG-001-independent-focused-and-affected-to-Coworker-3') 'Generation-670 registry verifier ACK is missing.'
Assert-Board ($backlog -match 'Generation 669 REG-001 five-failure repair barrier') 'Generation-669 backlog barrier record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 669 REG-001 Five-Failure Repair Barrier\r?$') 'Generation-669 registry barrier record is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g669/grant-REG-001-five-contract-repair-to-Coworker-2') 'Generation-669 backlog barrier ACK is missing.'
Assert-Board ($cohorts -match 'Platinum-root-coordinator/Kanban/g669/grant-REG-001-five-contract-repair-to-Coworker-2') 'Generation-669 registry barrier ACK is missing.'
Assert-Board ($backlog -match 'Generation 668 REG-001 Common-module repair barrier') 'Generation-668 backlog barrier record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 668 REG-001 Common-Module Repair Barrier\r?$') 'Generation-668 registry barrier record is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g668/grant-REG-001-common-normalization-repair-to-Coworker-2') 'Generation-668 backlog barrier ACK is missing.'
Assert-Board ($cohorts -match 'Platinum-root-coordinator/Kanban/g668/grant-REG-001-common-normalization-repair-to-Coworker-2') 'Generation-668 registry barrier ACK is missing.'
Assert-Board ($backlog -match 'Generation 667 REG-001 entrypoint repair barrier') 'Generation-667 backlog barrier record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 667 REG-001 Entrypoint Repair Barrier\r?$') 'Generation-667 registry barrier record is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g667/grant-REG-001-entrypoint-repair-to-Coworker-2') 'Generation-667 backlog barrier ACK is missing.'
Assert-Board ($cohorts -match 'Platinum-root-coordinator/Kanban/g667/grant-REG-001-entrypoint-repair-to-Coworker-2') 'Generation-667 registry barrier ACK is missing.'
Assert-Board ($backlog -match 'Generation 666 REG-001 C1-to-C2 barrier') 'Generation-666 backlog barrier record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 666 REG-001 C1-To-C2 Fixture Barrier\r?$') 'Generation-666 registry barrier record is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g666/handoff-REG-001-test-fixture-to-Coworker-2') 'Generation-666 backlog barrier ACK is missing.'
Assert-Board ($cohorts -match 'Platinum-root-coordinator/Kanban/g666/handoff-REG-001-test-fixture-to-Coworker-2') 'Generation-666 registry barrier ACK is missing.'
Assert-Board ($backlog -match 'Generation 665 foundational allocation and claim') 'Generation-665 backlog allocation record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 665 Root Atomic REG-001 Allocation And Claim\r?$') 'Generation-665 registry allocation record is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g665/claim-REG-001') 'REG-001 backlog claim ACK is missing.'
Assert-Board ($cohorts -match 'Platinum-root-coordinator/Kanban/g665/claim-REG-001') 'REG-001 registry claim ACK is missing.'
Assert-Board ($cohorts -match 'Platinum/Coworker-1' -and $cohorts -match 'Platinum/Coworker-2' -and $cohorts -match 'Platinum/Coworker-3') 'Exact Platinum Coworker roles are missing.'
Assert-Board ($backlog -match 'syntactically READY' -and $backlog -match 'acceptance-unsafe') 'Syntactic and acceptance-safe readiness are not distinguished.'
Assert-Board ($backlog -match 'No waiver, narrowing, baseline subtraction') 'REG-001 fail-closed no-waiver contract is missing.'
Assert-Board ($backlog -match 'Generation 664 Platinum three-card review NACK, release, and safe requeue') 'Platinum generation-664 backlog release record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 664 Platinum Three-Card Review NACK, Release And Requeue\r?$') 'Platinum generation-664 registry release record is missing.'
Assert-Board ($backlog -match '5,476' -and $backlog -match '5,469' -and $backlog -match '5,463') 'Platinum generation-664 affected result counts are missing.'
Assert-Board ($backlog -match 'Generation 663 Platinum independent-review handoff') 'Platinum generation-663 backlog review record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 663 Platinum Independent-Review Handoff\r?$') 'Platinum generation-663 registry review record is missing.'
foreach ($reviewAck in @(
        'review-EXR-012-A01-D01-by-Coworker-3',
        'review-EXR-012-A01-D02-by-Coworker-1',
        'review-EXR-012-A01-D03-by-Coworker-2'
    )) {
    Assert-Board ($backlog -match [regex]::Escape("Platinum-root-coordinator/Kanban/g663/$reviewAck")) "$reviewAck backlog ACK is missing."
    Assert-Board ($cohorts -match [regex]::Escape("Platinum-root-coordinator/Kanban/g663/$reviewAck")) "$reviewAck registry ACK is missing."
}
Assert-Board ($backlog -match 'Generation 662 Platinum three-card atomic claim') 'Platinum generation-662 backlog claim record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 662 Platinum Atomic Three-Card Claim\r?$') 'Platinum generation-662 registry claim record is missing.'
foreach ($claimedId in $claimedDiscovery) {
    Assert-Board ($backlog -match [regex]::Escape("Platinum-root-coordinator/Kanban/g662/claim-$claimedId")) "$claimedId backlog ACK is missing."
    Assert-Board ($cohorts -match [regex]::Escape("Platinum-root-coordinator/Kanban/g662/claim-$claimedId")) "$claimedId registry ACK is missing."
}
Assert-Board ($backlog -match 'Generation 661 Platinum D01 affected NACK, release, and safe requeue') 'Platinum D01 generation-661 release record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 661 Platinum D01 Affected NACK, Release And Requeue\r?$') 'Platinum D01 generation-661 registry release is missing.'
Assert-Board ($backlog -match '5,477' -and $backlog -match '833' -and $backlog -match 'one failed container') 'Platinum D01 generation-661 affected counts are missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g644/claim-EXR-012-A01-D01') 'Platinum D01 backlog ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g645/repair-EXR-012-A01-D01-C1-tests') 'Platinum D01 repair ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g646/repair-EXR-012-A01-D01-C1-proof-and-raw-evidence') 'Platinum D01 proof/evidence repair ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g647/accept-red-and-handoff-EXR-012-A01-D01-C2-readme') 'Platinum D01 accepted-red handoff ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g648/accept-EXR-012-A01-D01-C2-and-grant-C3-fresh-verification') 'Platinum D01 C3 verification ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g649/nack-EXR-012-A01-D01-C3-and-grant-C1-crlf-parser-repair') 'Platinum D01 parser-repair ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g650/accept-EXR-012-A01-D01-C1-crlf-parser-repair-and-grant-C3-fresh-verification') 'Platinum D01 fresh-verification ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g651/nack-EXR-012-A01-D01-C3-and-grant-C1-read-only-diagnosis') 'Platinum D01 read-only diagnosis ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g652/accept-diagnosis-and-grant-C1-test-helper-cardinality-repair') 'Platinum D01 test-helper repair ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g653/accept-C1-test-helper-cardinality-repair-and-grant-C3-fresh-verification') 'Platinum D01 fresh C3 verification ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g654/nack-EXR-012-A01-D01-C3-diff-identity-and-grant-C1-read-only-diagnosis') 'Platinum D01 diff-identity diagnosis ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g655/accept-C1-diff-representation-diagnosis-and-grant-C3-fresh-verification') 'Platinum D01 resolved-diff fresh verification ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g656/preserve-g655-nack-retire-whole-diff-digest-and-grant-C3-fresh-verification') 'Platinum D01 retired-diff fresh verification ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g657/nack-EXR-012-A01-D01-g656-affected-and-grant-C1-read-only-failure-cluster-diagnosis') 'Platinum D01 affected-failure diagnosis ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g658/nack-C1-g657-all-baseline-classification-and-grant-bounded-preserved-evidence-repair') 'Platinum D01 classification-repair ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g659/nack-C1-g658-contradictory-member-rationales-and-grant-bounded-causal-reconciliation') 'Platinum D01 causal-reconciliation ACK is missing.'
Assert-Board ($backlog -match 'Platinum-root-coordinator/Kanban/g660/accept-C1-g659-causal-reconciliation-preserve-affected-NACK-and-require-baseline-disposition') 'Platinum D01 baseline-disposition ACK is missing.'
Assert-Board ($backlog -match '67DD4AA706B461866BF3108ACCFCDA1E65A3D23F78CBC592BA6A2616A74585E5') 'Platinum D01 g659 reconciliation digest is missing.'
Assert-Board ($backlog -match 'No command, test, edit, implementation attempt') 'Platinum D01 zero-command boundary is missing.'
Assert-Board ($backlog -match '3B7CB0EE4B77DDEE1FB212510DBDC3B6AB54086900F934693763370E123A119B') 'Platinum D01 g658 packet digest is missing.'
Assert-Board ($cohorts -match '\.artifacts/dispatch/EXR-012-A01-D01/g644/Platinum/Coworker-1/diagnosis-g659/causal-reconciliation\.json') 'Platinum C1 generation-659 reconciliation path is missing.'
Assert-Board ($backlog -match '181A1D700782508DA94DDC0F46CCCCD404010D4605AF1BADAF1231810E7D4330') 'Platinum D01 g657 enumeration packet digest is missing.'
Assert-Board ($backlog -match '835 harness/shared-state-contamination tests plus one failed container' -and $backlog -match '2 pre-existing-baseline tests') 'Platinum D01 preliminary repaired classification is missing.'
Assert-Board ($cohorts -match '\.artifacts/dispatch/EXR-012-A01-D01/g644/Platinum/Coworker-1/diagnosis-g658/classification-repair\.json') 'Platinum C1 generation-658 repair path is missing.'
Assert-Board ($backlog -match 'B6410494CB24F45AA5A2FD0C903383A4D319B929F591AB6B20293E7C94DB27AD') 'Platinum D01 g656 affected NACK packet digest is missing.'
Assert-Board ($backlog -match '5,473' -and $backlog -match '837' -and $backlog -match 'one failed container') 'Platinum D01 affected NACK counts are missing.'
Assert-Board ($cohorts -match '\.artifacts/dispatch/EXR-012-A01-D01/g644/Platinum/Coworker-1/diagnosis-g657/affected-root-clusters\.json') 'Platinum C1 generation-657 diagnosis packet path is missing.'
Assert-Board ($backlog -match 'FE87A4BA0AE3FC5EDCFE7DB932CE2D931D45D83967BF38C76FA0F38B7A15F15B') 'Platinum D01 g655 NACK evidence digest is missing.'
Assert-Board ($backlog -match 'Whole no-index output byte counts/digests are formally retired as non-authoritative acceptance gates') 'Platinum D01 whole-diff retirement decision is missing.'
Assert-Board ($backlog -match 'samples/contoso-exchange-online-managed-service/README\.md' -and $backlog -match 'samples/contoso-exchange-online-managed-service/tests/unit/ReadmeOperatorEntry\.Tests\.ps1') 'Platinum D01 authoritative changed-path inventory is missing.'
Assert-Board ($backlog -match 'git diff --check') 'Platinum D01 authoritative diff-check gate is missing.'
Assert-Board ($cohorts -match '\.artifacts/dispatch/EXR-012-A01-D01/g644/Platinum/Coworker-3/verification-g656/') 'Platinum C3 generation-656 evidence root is missing.'
Assert-Board ($backlog -match '93930DAB6101FA6601DF750B4755146A506911CA3190C508704D1F83EE59E08F') 'Platinum D01 diff diagnosis packet digest is missing.'
Assert-Board ($backlog -match 'F6B68709840A49521D881AB216D6D88D5ACB23AD2A8F60FD67AB4E0CB2215A04' -and $backlog -match '22,835 bytes') 'Platinum D01 PowerShell diff representation is missing.'
Assert-Board ($backlog -match '63C9A2E7A0AB328B2C789BEC17D04E9986A76EECFF2EA10D1D453922B7F061D0' -and $backlog -match '22,836 bytes') 'Platinum D01 raw Git diff representation is missing.'
Assert-Board ($cohorts -match '\.artifacts/dispatch/EXR-012-A01-D01/g644/Platinum/Coworker-3/verification-g655/') 'Platinum C3 generation-655 evidence root is missing.'
Assert-Board ($backlog -match '18/18' -and $backlog -match '6,310/6,310') 'Platinum D01 focused and affected verification contract is missing.'
Assert-Board ($cohorts -match 'EXR-012-A01-D01/Platinum/g644/4ed34a64d8124e12910989424f1449d3') 'Platinum D01 claim token is missing.'
Assert-Board ($cohorts -match 'dispatch/EXR-012-A01-D01/Platinum/Coworker-1/g644') 'Platinum D01 branch reservation is missing.'
Assert-Board ($cohorts -match 'exchange-online-protection-dispatch-EXR-012-A01-D01-Platinum-Coworker-1-g644') 'Platinum D01 worktree reservation is missing.'
foreach ($role in 1..3) {
    Assert-Board ($cohorts -match "\.artifacts/dispatch/EXR-012-A01-D01/g644/Platinum/Coworker-$role/") "Platinum Coworker-$role evidence root is missing."
}
Assert-Board ($backlog -match "(?m)^Board readiness: \*\*BOARD READY — generation $generationPattern\*\*") 'backlog readiness declaration is missing or stale.'
Assert-Board ($cohorts -match "(?m)^Allocation readiness: \*\*BOARD READY — generation $generationPattern\*\*") 'cohort readiness declaration is missing or stale.'
Assert-Board ($kanban -match "(?m)^Allocation generation mirrored: $generationPattern[ \t]*\r?$" -and $kanban -match "(?m)^Canonical executable cards: 104; canonical summary parents excluded: 28\. Compatibility generation: $generationPattern\. ") 'kanban generation is missing or stale.'
Assert-Board ($backlog -match '(?m)^\d+\. \*\*READY-bank replenishment\.\*\* After every claim, completion, requeue, dependency transition, external-gate transition, or reservation change, the canonical writer recomputes eligibility and targets at least sixteen unclaimed READY cards\.') 'canonical READY-bank replenishment contract is missing.'
Assert-Board ($cohorts -match '(?m)^8\. After every claim, completion, requeue, dependency transition, external-gate transition or reservation change, the canonical writer recomputes eligibility and targets at least sixteen unclaimed READY cards\.') 'allocation READY-bank replenishment contract is missing.'
Assert-Board ($backlog -match '(?m)^Generation 614 Purple C01 final candidate: \*\*Canonical decision: ACCEPT `EXR-010-A12-L01-C01` as Done\.\*\*') 'C01 canonical decision record is missing.'
Assert-Board ($backlog -match '(?m)^Generation 615 Purple C01 acceptance and release: the canonical writer accepts the generation-614 candidate ') 'C01 canonical release record is missing.'
Assert-Board ($backlog -match '(?m)^Generation 612 Purple C01 rejection: the structurally coherent candidate is REJECTED because C2''s green validator was invocation 3 after two failed implementation-debug invocations, violating the explicit no-retry contract\.') 'C01 generation-612 rejection record is missing.'
Assert-Board ($backlog -match '(?m)^Generation 613 Purple C01 fresh attempt: ACK `Purple-20260930T224006Z-e7a0834/Kanban/g613/fresh-zero-retry-C01` ') 'C01 generation-613 fresh-attempt grant is missing.'
Assert-Board ($cohorts -match '(?m)^- \*\*Generation authority:\*\* session `Purple-20260930T224006Z-e7a0834` proposes generation 614 ') 'C01 generation authority record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 613 Purple C01 Fresh Zero-Retry Grant\r?$') 'C01 generation-613 registry grant is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 612 Purple C01 Candidate Rejection\r?$') 'C01 generation-612 registry rejection is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 615 Purple C01 Acceptance And Release\r?$') 'C01 generation-615 registry release is missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-09-30 / compatibility synchronization to generation 614:\*\* canonical decision ACCEPT marks `EXR-010-A12-L01-C01` Done ') 'C01 compatibility activity record is missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-09-30 / compatibility synchronization to generation 615:\*\* accepted the generation-614 C01 candidate ') 'C01 compatibility release activity is missing.'
Assert-Board ($backlog -match '(?m)^- Generation 614 accepted candidate evidence: canonical decision ACCEPT;') 'C01 accepted candidate evidence is missing from its canonical card section.'
Assert-Board ($backlog -match '(?m)^\d+\. \*\*One-card swarm WIP and isolation\.\*\* Each cohort owns at most one In Progress card and binds exactly three logical roles: test author, implementation owner and independent verifier\.') 'canonical one-card swarm contract is missing.'
Assert-Board ($backlog -match '(?m)^\d+\. \*\*Exact-role barrier behavior\.\*\* The test author freezes negative-first evidence before the implementation owner receives writable ownership') 'canonical exact-role barrier contract is missing.'
Assert-Board ($cohorts -match '(?m)^4\. A cohort swarms one In Progress card with exactly three logical Coworker roles: test author, implementation owner and independent verifier\.') 'allocation one-card swarm contract is missing.'
Assert-Board ($backlog -match '(?m)^Generation 618 four-cohort allocation and Purple D01 claim: ') 'generation-618 backlog claim record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 618 Four-Cohort Allocation And Purple D01 Claim\r?$') 'generation-618 registry claim is missing.'
Assert-Board ($cohorts -match [regex]::Escape('EXR-012-A01-D01/Purple/g618/56c2a84b94b34c03846814657ca5202d')) 'Purple D01 token is missing.'
Assert-Board ($cohorts -match [regex]::Escape('samples/contoso-exchange-online-managed-service/tests/unit/ReadmeOperatorEntry.Tests.ps1') -and $cohorts -match [regex]::Escape('samples/contoso-exchange-online-managed-service/README.md')) 'Purple D01 exact reservations are missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-09-30 / compatibility synchronization to generation 618:\*\*') 'generation-618 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 619 Purple D01 C1-to-C2 barrier: ') 'generation-619 backlog handoff is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 619 Purple D01 C1-To-C2 Barrier\r?$') 'generation-619 registry handoff is missing.'
Assert-Board ($cohorts -match [regex]::Escape('532912196F8F26E87575B1DD49A38B242457E5641DB447529C776A01632103FB')) 'frozen D01 test hash is missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-09-30 / compatibility synchronization to generation 619:\*\*') 'generation-619 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 620 Purple D01 C2 quiescence and C3 verification grant: ') 'generation-620 backlog verification grant is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 620 Purple D01 C3 Verification Grant\r?$') 'generation-620 registry verification grant is missing.'
Assert-Board ($cohorts -match '5464 passed / 838 failed / 6302 total') 'C2 affected failure identity is missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 620:\*\*') 'generation-620 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 621 Purple D01 canonical rejection and safe requeue: ') 'generation-621 backlog rejection is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 621 Purple D01 Rejection, Release And Requeue\r?$') 'generation-621 registry release is missing.'
Assert-Board ($cohorts -match [regex]::Escape('81C4C8351F7552A6D9FBD467830C38AAAC70691981DDFF58E1A225E888C0FE8C')) 'C3 review packet identity is missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 621:\*\*') 'generation-621 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 622 Silver, Gold and White read-only discovery claims: ') 'generation-622 backlog claim record is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 622 Silver, Gold And White Read-Only Discovery Claims\r?$') 'generation-622 registry claim is missing.'
foreach ($token in @(
        'EXR-012-A01-D02/Silver/g622/29331ed087fc73dafffe59e4edee64cf',
        'EXR-012-A01-D03/Gold/g622/ca09bfa8fe4e5ddef1804a3088ddd02c',
        'EXR-012-A01-D04/White/g622/639d631231be61cdccf48a0f3067f11c'
    )) {
    Assert-Board ($cohorts -match [regex]::Escape($token)) "generation-622 claim token is missing: $token"
}
Assert-Board ($cohorts -match 'No documentation, product, test, or shared-governance path is writable') 'generation-622 zero-write reservation is missing.'
Assert-Board ($cohorts -match [regex]::Escape('.artifacts/kanban/EXR-012-A01-D02/g622/Silver/') -and
    $cohorts -match [regex]::Escape('.artifacts/kanban/EXR-012-A01-D03/g622/Gold/') -and
    $cohorts -match [regex]::Escape('.artifacts/kanban/EXR-012-A01-D04/g622/White/')) 'generation-622 evidence roots are incomplete.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 622:\*\*') 'generation-622 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 623 discovery reconciliation and White conflict hold: ') 'generation-623 backlog reconciliation is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 623 Discovery Reconciliation And White Conflict Hold\r?$') 'generation-623 registry reconciliation is missing.'
Assert-Board ($cohorts -match [regex]::Escape('Purple-20260930T233031Z-e7a0834/Kanban/g623/accept-D04-discovery-hold-implementation-conflict')) 'generation-623 White conflict-hold ACK is missing.'
Assert-Board ($cohorts -match [regex]::Escape('1969BC87779BD409EA9BBF1EB4D56C7F91F74E8BD531ACC1848E0030DDC6BBE1')) 'preserved D01 README conflict identity is missing.'
Assert-Board ($cohorts -match 'do not issue an implementation token, evidence root, or writable reservation') 'generation-623 fail-closed implementation disposition is missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 623:\*\*') 'generation-623 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 624 White D04 release and requeue: ') 'generation-624 backlog release is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 624 White D04 Release And Requeue\r?$') 'generation-624 registry release is missing.'
Assert-Board ($cohorts -match [regex]::Escape('Purple-20260930T233031Z-e7a0834/Kanban/g624/release-requeue-D04-conflict')) 'generation-624 release ACK is missing.'
Assert-Board ($cohorts -match 'No implementation token, evidence root, or writable path exists') 'generation-624 zero-authority disposition is missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 624:\*\*') 'generation-624 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 625 four-cohort A02 discovery claims: ') 'generation-625 backlog claim transaction is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 625 Four-Cohort A02 Read-Only Discovery Claims\r?$') 'generation-625 registry claim transaction is missing.'
foreach ($token in @(
        'EXR-012-A02-D01/Purple/g625/b8aa995802ae4d6eb1e458c6026b0724',
        'EXR-012-A02-D02/Silver/g625/a01ddbcadc764ae795955cf868f82051',
        'EXR-012-A02-D03/Gold/g625/41236ec6e61542058c7462919f3acf55',
        'EXR-012-A02-D04/White/g625/b8c875dadd4f4f8eae018980bfb30483'
    )) {
    Assert-Board ($cohorts -match [regex]::Escape($token)) "generation-625 token is missing: $token"
}
Assert-Board ($cohorts -match 'No implementation path is writable') 'generation-625 zero-write discovery boundary is missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 625:\*\*') 'generation-625 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 626 exact discovery authority and Silver conditional freeze: ') 'generation-626 authority clarification is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 626 Exact Discovery Authority And Session Binding\r?$') 'generation-626 registry authority is missing.'
foreach ($operation in @(
        'DISCOVER-FREEZE:runbooks',
        'DISCOVER-FREEZE:control-catalog',
        'DISCOVER-FREEZE:value-authority',
        'DISCOVER-FREEZE:set-verify-output'
    )) {
    Assert-Board ($cohorts -match [regex]::Escape($operation)) "generation-626 exact operation is missing: $operation"
}
Assert-Board ($cohorts -match [regex]::Escape('C:/Users/chhage/repos/sony/GISC/exchange-online-protection/.github/')) 'generation-626 primary canonical authority path is missing.'
Assert-Board ($cohorts -match 'may write only `.artifacts/kanban/EXR-012-A02-D01/g625/Purple/`' -and
    $cohorts -match 'may write only `.artifacts/kanban/EXR-012-A02-D02/g625/Silver/`' -and
    $cohorts -match 'may write only `.artifacts/kanban/EXR-012-A02-D03/g625/Gold/`' -and
    $cohorts -match 'may write only `.artifacts/kanban/EXR-012-A02-D04/g625/White/`') 'generation-626 evidence-output grants are incomplete.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 626:\*\*') 'generation-626 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 627 A02 discovery reconciliation and Gold identity correction: ') 'generation-627 backlog reconciliation is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 627 A02 Discovery Reconciliation And Gold Identity Correction\r?$') 'generation-627 registry reconciliation is missing.'
Assert-Board ($cohorts -match [regex]::Escape('Gold/Coworker-1') -and
    $cohorts -match [regex]::Escape('Gold/Coworker-2') -and
    $cohorts -match [regex]::Escape('Gold/Coworker-3')) 'generation-627 Gold runtime identities are incomplete.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 627:\*\*') 'generation-627 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 628 Gold D03 discovery acceptance and requeue: ') 'generation-628 backlog release is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 628 Gold D03 Discovery Acceptance And Requeue\r?$') 'generation-628 registry release is missing.'
Assert-Board ($cohorts -match [regex]::Escape('5EC8B79B1859D707903A666BDCEC61E380888C2E2DE0B9A21B3FC7DD20E46A2E')) 'generation-628 Gold independent review identity is missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 628:\*\*') 'generation-628 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 629 four-cohort A03 discovery claims: ') 'generation-629 backlog transaction is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 629 Four-Cohort A03 Read-Only Discovery Claims\r?$') 'generation-629 registry transaction is missing.'
foreach ($token in @(
        'EXR-012-A03-D01/Purple/g629/1feb532cdf354e6e860d5f2df039898d',
        'EXR-012-A03-D02/Silver/g629/368637ba80bd4ebab169cbb38d4ed85d',
        'EXR-012-A03-D03/Gold/g629/4ea7eff026f44448b39a7d547e3dca08',
        'EXR-012-A03-D04/White/g629/f1642377206d4944b6e16157050bc41b'
    )) {
    Assert-Board ($cohorts -match [regex]::Escape($token)) "generation-629 token is missing: $token"
}
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 629:\*\*') 'generation-629 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 630 A03 partial reconciliation and White operational correction: ') 'generation-630 backlog reconciliation is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 630 A03 Partial Reconciliation And White Operational Correction\r?$') 'generation-630 registry reconciliation is missing.'
Assert-Board ($cohorts -match [regex]::Escape('White/2026-10-01T02:22:14.785Z')) 'generation-630 White session binding is missing.'
Assert-Board ($cohorts -match [regex]::Escape('Purple-g628/Kanban/g630/continue-EXR-012-A03-D04')) 'generation-630 Purple ACK is missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 630:\*\*') 'generation-630 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 631 White D04 lease renewal and evidence partition: ') 'generation-631 backlog renewal is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 631 White D04 Lease Renewal And Evidence Partition\r?$') 'generation-631 registry renewal is missing.'
Assert-Board ($cohorts -match [regex]::Escape('Purple-g628/Kanban/g631/renew-EXR-012-A03-D04')) 'generation-631 renewal ACK is missing.'
foreach ($root in @(
        '.artifacts/kanban/EXR-012-A03-D04/g629/White/Coworker-1/',
        '.artifacts/kanban/EXR-012-A03-D04/g629/White/Coworker-2/',
        '.artifacts/kanban/EXR-012-A03-D04/g629/White/Coworker-3/'
    )) {
    Assert-Board ($cohorts -match [regex]::Escape($root)) "generation-631 evidence partition is missing: $root"
}
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 631:\*\*') 'generation-631 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 632 White D04 blocked discovery acceptance and requeue: ') 'generation-632 backlog release is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 632 White D04 Blocked Discovery Acceptance And Requeue\r?$') 'generation-632 registry release is missing.'
Assert-Board ($cohorts -match [regex]::Escape('7DF8FFD8107F36BA196947B54FA535007DA5867DB78A3886117123C41157DDB1')) 'generation-632 independent result identity is missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 632:\*\*') 'generation-632 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 633 four-cohort A04 discovery claims: ') 'generation-633 backlog transaction is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 633 Four-Cohort A04 Read-Only Discovery Claims\r?$') 'generation-633 registry transaction is missing.'
foreach ($operation in @(
        'DISCOVER-FREEZE:evidence-viewer',
        'DISCOVER-FREEZE:exclusions-denominator',
        'DISCOVER-FREEZE:status-semantics',
        'DISCOVER-FREEZE:raid-source-claims'
    )) {
    Assert-Board ($cohorts -match [regex]::Escape($operation)) "generation-633 operation is missing: $operation"
}
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 633:\*\*') 'generation-633 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 634 A04 discovery reconciliation and full release: ') 'generation-634 backlog reconciliation is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 634 A04 Discovery Reconciliation And Full Release\r?$') 'generation-634 registry reconciliation is missing.'
Assert-Board ($cohorts -match [regex]::Escape('C2B7C814FF5D15E3B0070A2E0F3BDB7D43A329754C396BAA5E8811389D74C6')) 'generation-634 Purple review identity is missing.'
Assert-Board ($cohorts -match [regex]::Escape('3AE376548E37EE53BC713DB79497D497F0D793CBE44D6FEC38CD52223D24F636')) 'generation-634 White review identity is missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 634:\*\*') 'generation-634 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 635 D03 canonical adjudication NACK: ') 'generation-635 backlog adjudication is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 635 D03 Canonical Adjudication NACK\r?$') 'generation-635 registry adjudication is missing.'
Assert-Board ($cohorts -match [regex]::Escape('Purple-20261001T090114-0400-g634-d03')) 'generation-635 coordinator binding is missing.'
Assert-Board ($cohorts -match 'exactly three acceptance-aligned negatives and exactly one positive') 'generation-635 future test inventory requirement is missing.'
Assert-Board ($cohorts -match 'No Pester run was authorized') 'generation-635 intended-red NACK is missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 635:\*\*') 'generation-635 compatibility activity is missing.'
Assert-Board ($backlog -match '(?m)^Generation 636 D03 White concurrence: ') 'generation-636 backlog concurrence is missing.'
Assert-Board ($cohorts -match '(?m)^### Generation 636 D03 White Read-Only Concurrence\r?$') 'generation-636 registry concurrence is missing.'
Assert-Board ($cohorts -match [regex]::Escape('White-20261001T130114Z-g634')) 'generation-636 White reviewer identity is missing.'
Assert-Board ($cohorts -match [regex]::Escape('1FCFF4000C06706308703A8377576192FD32640AF4EBDB8264A226FE9E1CA846')) 'generation-636 preserved review identity is missing.'
Assert-Board ($cohorts -match 'affected `Total=B\+4`') 'generation-636 affected denominator requirement is missing.'
Assert-Board ($kanban -match '(?m)^- \*\*2026-10-01 / compatibility synchronization to generation 636:\*\*') 'generation-636 compatibility activity is missing.'

[pscustomobject]@{
    Generation                   = $backlogGeneration
    Executable                   = $executables.Count
    ToDo                        = $todo.Count
    InProgress                  = $inProgress.Count
    Done                        = $done.Count
    SummaryParents              = $summaries.Count
    ManifestEntries             = $manifest.Count
    Profiles                    = $profiles.Count
    PullReady                   = $eligible.Count
    UnknownDependencyReferences = $unknownDependencies.Count
    EligibleReservationConflicts = $conflicts.Count
    Result                       = 'BOARD READY'
}
