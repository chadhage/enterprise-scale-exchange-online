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
    $headings = [regex]::Matches($canonical, '(?m)^### (?<id>EXR-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)[ \t]*\r?$')
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
                    '\bEXR-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*\b'
                ) | ForEach-Object { $_.Value } | Select-Object -Unique)
        }
        $cards.Add([pscustomobject]@{
                Id           = $heading.Groups['id'].Value
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
Assert-Board ($executables.Count -eq 91) "expected 91 executable cards, found $($executables.Count)."
Assert-Board ($summaries.Count -eq 24) "expected 24 summary parents, found $($summaries.Count)."
Assert-Board ($todo.Count -eq 35 -and $inProgress.Count -eq 0 -and $done.Count -eq 56) "expected 35/0/56 buckets, found $($todo.Count)/$($inProgress.Count)/$($done.Count)."
Assert-Board (($done | Where-Object Id -eq 'EXR-010-A12-L01-F02').Count -eq 1) 'F02 must be Done.'
Assert-Board (($done | Where-Object Id -eq 'EXR-018-A01').Count -eq 1) 'EXR-018-A01 must be Done.'

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
Assert-Board ($manifest.Count -eq 35) "expected 35 manifest entries, found $($manifest.Count)."
$todoIds = @($todo.Id | Sort-Object)
$manifestIds = @($manifest.Id | Sort-Object)
Assert-Board (($todoIds -join "`n") -ceq ($manifestIds -join "`n")) 'manifest IDs do not exactly match To Do IDs.'

foreach ($entry in $manifest) {
    Assert-Board $profiles.ContainsKey($entry.Profile) "$($entry.Id) profile $($entry.Profile) does not resolve."
    foreach ($field in 'Dependency', 'Reservation', 'ReadOnly', 'Validation') {
        Assert-Board (-not [string]::IsNullOrWhiteSpace($entry.$field)) "$($entry.Id) field $field is empty."
    }
    Assert-Board ($entry.Dependency -match '`(?:READY|WAIT-DEP|WAIT-EXT|WAIT-F02)') "$($entry.Id) eligibility is missing."
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
Assert-Board ($eligible.Count -eq 1 -and $eligible[0].Id -eq 'EXR-010-A12-L01-C01') 'C01 must be the sole pull-ready card after F02 acceptance.'
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
Assert-Board ($backlog -match "(?m)^Board readiness: \*\*BOARD READY — generation $generationPattern\*\*") 'backlog readiness declaration is missing or stale.'
Assert-Board ($cohorts -match "(?m)^Allocation readiness: \*\*BOARD READY — generation $generationPattern\*\*") 'cohort readiness declaration is missing or stale.'
Assert-Board ($backlog -match '(?m)^\d+\. \*\*Worker-slot WIP and isolation\.\*\* Each coworker owns at most one In Progress implementation card, so a three-worker cohort may hold up to three nonconflicting cards; there is no unrelated global one-card gate\.') 'canonical worker-slot WIP contract is missing.'
Assert-Board ($backlog -match '(?m)^\d+\. \*\*Idle pull behavior\.\*\* When a coworker becomes idle, the steward immediately reruns the dependency-ready query') 'canonical idle-coworker pull contract is missing.'
Assert-Board ($cohorts -match '(?m)^4\. Each Coworker holds at most one In Progress implementation card; a three-Coworker cohort may therefore hold up to three nonconflicting cards\.') 'allocation worker-slot contract is missing.'

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
