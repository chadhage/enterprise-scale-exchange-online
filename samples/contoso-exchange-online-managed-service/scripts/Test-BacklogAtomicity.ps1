#requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$BacklogPath
)

$content = Get-Content -LiteralPath $BacklogPath -Raw -ErrorAction Stop

function Get-CardField {
    param(
        [Parameter(Mandatory)][string]$Body,
        [Parameter(Mandatory)][string]$Label
    )

    @([regex]::Matches(
            $Body,
            "(?im)^\s*-\s*$([regex]::Escape($Label))\s*:\s*(?<value>.*\S)\s*$"
        ) | ForEach-Object { $_.Groups['value'].Value.Trim() })
}

function Throw-AtomicError {
    param(
        [Parameter(Mandatory)][string]$Message,
        [hashtable]$Discovery
    )

    $exception = [System.InvalidOperationException]::new($Message)
    if ($Discovery) {
        foreach ($entry in $Discovery.GetEnumerator()) {
            $exception.Data[$entry.Key] = $entry.Value
        }
    }
    throw $exception
}

$forceRankedHeading = [regex]::Match(
    $content,
    '(?m)^## Force-Ranked Work[ \t]*\r?$'
)
if (-not $forceRankedHeading.Success) {
    Throw-AtomicError -Message 'AtomicFieldMissing:ForceRankedWork: canonical Force-Ranked Work is absent.'
}

$canonicalStart = $forceRankedHeading.Index + $forceRankedHeading.Length
$canonicalTail = $content.Substring($canonicalStart)
$nextLevelTwo = [regex]::Match($canonicalTail, '(?m)^## [^\r\n]+\r?$')
$canonical = if ($nextLevelTwo.Success) {
    $canonicalTail.Substring(0, $nextLevelTwo.Index)
}
else {
    $canonicalTail
}

# Only exact level-three headings in the canonical Force-Ranked Work section can
# create cards.  Generation overrides, inventories, audit prose, links, and
# historical text therefore cannot manufacture current card identities.
$headingPattern = '(?m)^###(?<suffix>[^\r\n]*)\r?$'
$headingMatches = [regex]::Matches($canonical, $headingPattern)
$sections = [System.Collections.Generic.List[object]]::new()

for ($index = 0; $index -lt $headingMatches.Count; $index++) {
    $heading = $headingMatches[$index]
    $end = if ($index + 1 -lt $headingMatches.Count) {
        $headingMatches[$index + 1].Index
    }
    else {
        $canonical.Length
    }

    $suffix = $heading.Groups['suffix'].Value.Trim()
    $id = if ($suffix -match '^(EXR-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)$') {
        $Matches[1]
    }
    else {
        $null
    }
    $bodyStart = $heading.Index + $heading.Length
    $sections.Add([pscustomobject]@{
            Id     = $id
            Suffix = $suffix
            Body   = $canonical.Substring($bodyStart, $end - $bodyStart)
        })
}

$missingIdentity = $sections | Where-Object {
    -not $_.Id -and (
        $_.Body -match '(?im)^Rank\s+\S' -or
        $_.Body -match '(?im)^(?:Non-executable summary|Parent summary)\b' -or
        $_.Body -match '(?im)^\s*-\s*[^\r\n]*\bStatus\s*:\s*(?:To Do|In Progress|Done|excluded summary)\b'
    )
} | Select-Object -First 1
if ($missingIdentity) {
    Throw-AtomicError -Message 'AtomicFieldMissing:Id: an executable or summary card heading has no canonical ID.'
}

$cardSections = @($sections | Where-Object Id)
$duplicate = $cardSections |
    Group-Object Id |
    Where-Object Count -gt 1 |
    Select-Object -First 1
if ($duplicate) {
    Throw-AtomicError -Message "AtomicCardIdDuplicate:$($duplicate.Name): canonical card IDs must be unique."
}

$cards = @($cardSections | ForEach-Object {
        $body = $_.Body
        $summaryMarker = [regex]::Match(
            $body,
            '(?im)^(?:Non-executable summary|Parent summary)\b'
        )
        $excludedStatus = [regex]::Match(
            $body,
            '(?im)^\s*-\s*[^\r\n]*\bStatus\s*:\s*excluded summary\b'
        )
        $rank = [regex]::Match($body, '(?im)^Rank\s+(?<value>[^\r\n]+?)\r?$')

        # The definition begins at its anchored Rank declaration.  Earlier
        # generation/audit bullets are provenance, not current card fields.
        $definition = if ($rank.Success) {
            $body.Substring($rank.Index)
        }
        else {
            $body
        }
        $statuses = @([regex]::Matches(
                $definition,
                '(?im)^\s*-\s*[^\r\n]*?\bStatus\s*:\s*(?<status>To Do|In Progress|Done)\b'
            ) | ForEach-Object { $_.Groups['status'].Value })

        $isSummary = $summaryMarker.Success -or $excludedStatus.Success -or
            (-not $rank.Success -and $statuses.Count -eq 0)
        [pscustomobject]@{
            Id         = $_.Id
            Body       = $body
            Definition = $definition
            Rank       = if ($rank.Success) { $rank.Groups['value'].Value.Trim() } else { $null }
            Statuses   = $statuses
            IsSummary  = $isSummary
            Fields     = @{}
        }
    })

$leafSummary = $cards | Where-Object {
    if (-not $_.IsSummary -or $_.Id -notmatch '-A\d+$') {
        return $false
    }
    $prefix = "$($_.Id)-"
    -not ($cards | Where-Object { $_.Id.StartsWith($prefix, [System.StringComparison]::Ordinal) })
} | Select-Object -First 1
if ($leafSummary) {
    Throw-AtomicError -Message "ExecutableLeafSummaryOnly:$($leafSummary.Id): an atomic leaf cannot be summary-only."
}

$executables = @($cards | Where-Object { -not $_.IsSummary })
$summaries = @($cards | Where-Object IsSummary)

foreach ($card in $executables) {
    if ($card.Statuses.Count -eq 0) {
        Throw-AtomicError -Message "AtomicFieldMissing:Status:$($card.Id): required field 'Status' is absent."
    }
    if ($card.Statuses.Count -ne 1) {
        Throw-AtomicError -Message "AtomicStatusMultiple:$($card.Id): exactly one current executable status is required."
    }
    if (-not $card.Rank) {
        Throw-AtomicError -Message "AtomicFieldMissing:Rank:$($card.Id): required field 'Rank' is absent."
    }
    $card.Fields.Status = $card.Statuses
    $card.Fields.Rank = @($card.Rank)
}

$canonicalHeader = [regex]::Match(
    $content,
    '(?im)^Canonical generation\s*:\s*(?<generation>\d+)\..*?Executable cards\s*:\s*(?<executable>\d+)\s*;\s*To Do\s+(?<todo>\d+)\s*,\s*In Progress\s+(?<inprogress>\d+)\s*,\s*Done\s+(?<done>\d+)\s*;\s*(?<summary>\d+)\s+summary parents excluded\.?\s*$'
)
if (-not $canonicalHeader.Success) {
    Throw-AtomicError -Message 'AtomicFieldMissing:CanonicalHeader: canonical executable and bucket inventory is absent.'
}

$declaredExecutableCount = [int]$canonicalHeader.Groups['executable'].Value
$declaredSummaryCount = [int]$canonicalHeader.Groups['summary'].Value
$declaredToDoCount = [int]$canonicalHeader.Groups['todo'].Value
$declaredInProgressCount = [int]$canonicalHeader.Groups['inprogress'].Value
$declaredDoneCount = [int]$canonicalHeader.Groups['done'].Value

if ($declaredExecutableCount -ne $executables.Count) {
    $summaryId = if ($summaries.Count) { $summaries[0].Id } else { 'unknown' }
    Throw-AtomicError -Message "SummaryCountedAsExecutable:${summaryId}: declared executable count includes or omits a summary parent."
}
if ($declaredSummaryCount -ne $summaries.Count) {
    Throw-AtomicError -Message "SummaryCountMismatch:$declaredSummaryCount/$($summaries.Count): declared and discovered summary counts differ."
}
if (($declaredToDoCount + $declaredInProgressCount + $declaredDoneCount) -ne $declaredExecutableCount) {
    Throw-AtomicError -Message 'ExecutableBucketCountMismatch: canonical status buckets do not reconcile to the executable count.'
}

$discovery = @{
    DiscoverySucceeded = $true
    ExecutableCount    = $executables.Count
    SummaryCount       = $summaries.Count
    ToDoCount          = $declaredToDoCount
    InProgressCount    = $declaredInProgressCount
    DoneCount          = $declaredDoneCount
}

# Missing-field inventory is deliberately evaluated after complete production
# discovery, so a real unresolved gap remains an error without being confused
# with parser failure.
$inventoryHeading = [regex]::Match(
    $content,
    '(?m)^### Missing-Field Inventory[ \t]*\r?$'
)
if (-not $inventoryHeading.Success) {
    Throw-AtomicError -Message 'AtomicFieldMissing:MissingFieldInventory: canonical inventory is absent.' -Discovery $discovery
}
$inventoryTail = $content.Substring($inventoryHeading.Index + $inventoryHeading.Length)
$inventoryEnd = [regex]::Match($inventoryTail, '(?m)^#{2,3} [^\r\n]+\r?$')
$inventoryBody = if ($inventoryEnd.Success) {
    $inventoryTail.Substring(0, $inventoryEnd.Index)
}
else {
    $inventoryTail
}
$inventoryRows = [regex]::Matches(
    $inventoryBody,
    '(?im)^\|\s*(?<card>EXR-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)\s*\|\s*(?<detail>[^|]+?)\s*\|\s*$'
)
$executableById = @{}
foreach ($card in $executables) {
    $executableById[$card.Id] = $card
}
foreach ($row in $inventoryRows) {
    $inventoryId = $row.Groups['card'].Value
    if (-not $executableById.ContainsKey($inventoryId)) {
        Throw-AtomicError -Message "MissingFieldInventoryCardUnknown:${inventoryId}: inventory must reference a current executable card." -Discovery $discovery
    }
    Throw-AtomicError -Message "MissingFieldInventoryUnresolved:${inventoryId}: required information remains unresolved." -Discovery $discovery
}

$requiredFields = [ordered]@{
    Dependencies        = 'Dependencies'
    Accountability      = 'Accountable owner or external gate'
    Surface             = 'Bounded writable/read-only surface'
    NegativeCases       = 'Explicit negative cases'
    PositiveCase        = 'Positive behavioral case'
    FocusedVerification = 'Focused command and count'
    AffectedValidation  = 'Affected validation'
    ReviewerEvidence    = 'Required reviewer and evidence root'
    ClosureEvidence     = 'Closure evidence'
}

foreach ($card in $executables) {
    $dependencyMatch = [regex]::Match(
        $card.Definition,
        '(?im)^\s*-\s*Dependencies\s*:\s*(?<value>.*?)(?=\.\s+Owner\s*:|\r?$)'
    )
    if (-not $dependencyMatch.Success) {
        Throw-AtomicError -Message "AtomicFieldMissing:Dependencies:$($card.Id): required field 'Dependencies' is absent." -Discovery $discovery
    }
    $card.Fields.Dependencies = @($dependencyMatch.Groups['value'].Value.Trim())

    $ownerMatch = [regex]::Match(
        $card.Definition,
        '(?im)^\s*-\s*[^\r\n]*?\bOwner\s*:\s*(?<value>.*?)(?=\.\s+Workstream\s*:|\r?$)'
    )
    if (-not $ownerMatch.Success) {
        Throw-AtomicError -Message "AtomicFieldMissing:Accountability:$($card.Id): required field 'Accountable owner or external gate' is absent." -Discovery $discovery
    }
    $card.Fields.Accountability = @($ownerMatch.Groups['value'].Value.Trim())

    foreach ($entry in $requiredFields.GetEnumerator()) {
        if ($entry.Key -in @('Dependencies', 'Accountability')) {
            continue
        }
        $values = @(Get-CardField -Body $card.Definition -Label $entry.Value)
        if ($values.Count -eq 0) {
            Throw-AtomicError -Message "AtomicFieldMissing:$($entry.Key):$($card.Id): required field '$($entry.Value)' is absent." -Discovery $discovery
        }
        $card.Fields[$entry.Key] = $values
    }

    if ($card.Fields.PositiveCase.Count -ne 1) {
        Throw-AtomicError -Message "PositiveCaseMultiple:$($card.Id): exactly one positive behavioral declaration is required." -Discovery $discovery
    }

    $focused = $card.Fields.FocusedVerification[0]
    if ($focused -notmatch '(?i)\bexpected\s+\d+\b' -or
        $focused -notmatch '(?i)\bdeterministic red discovery\s*:') {
        Throw-AtomicError -Message "FocusedVerificationIncomplete:$($card.Id): exact expected count and deterministic red-discovery contract are required." -Discovery $discovery
    }
}

$edges = @{}
foreach ($card in $executables) {
    $dependencies = @(
        $card.Fields.Dependencies[0] -split '\s*[,;]\s*' |
        ForEach-Object { $_.Trim().TrimEnd('.') } |
        Where-Object { $_ -and $_ -notmatch '^(?i:none)$' }
    )
    $edges[$card.Id] = $dependencies

    foreach ($dependency in $dependencies) {
        if ($dependency -eq $card.Id) {
            Throw-AtomicError -Message "DependencyUnsafe:$($card.Id): an executable card cannot depend on itself." -Discovery $discovery
        }
        if (-not $executableById.ContainsKey($dependency)) {
            Throw-AtomicError -Message "DependencyUnknown:$($card.Id):${dependency}: dependency does not identify a current executable card." -Discovery $discovery
        }
    }
}

$visitState = @{}
$visitPath = [System.Collections.Generic.List[string]]::new()
function Test-DependencyCycle {
    param([Parameter(Mandatory)][string]$Id)

    $visitState[$Id] = 'Visiting'
    $visitPath.Add($Id)
    foreach ($dependency in $edges[$Id]) {
        if ($visitState[$dependency] -eq 'Visiting') {
            $start = $visitPath.IndexOf($dependency)
            $cycle = @($visitPath[$start..($visitPath.Count - 1)]) + $dependency
            Throw-AtomicError -Message "DependencyCycle:$($cycle -join '->'): executable dependencies must be acyclic." -Discovery $discovery
        }
        if ($visitState[$dependency] -ne 'Visited') {
            Test-DependencyCycle -Id $dependency
        }
    }
    $visitPath.RemoveAt($visitPath.Count - 1)
    $visitState[$Id] = 'Visited'
}

foreach ($card in $executables) {
    if ($visitState[$card.Id] -ne 'Visited') {
        Test-DependencyCycle -Id $card.Id
    }
}

$historicalSection = [regex]::Match($content, '(?ims)^##\s+Historical\b(?<body>.*)$')
if ($historicalSection.Success -and
    $historicalSection.Groups['body'].Value -match 'EXR-[A-Za-z0-9-]+') {
    Throw-AtomicError -Message "HistoricalMetadataParsedAsCurrent:$($Matches[0]): historical prose cannot contribute current card metadata." -Discovery $discovery
}

[pscustomobject]@{
    CanonicalGeneration = [int]$canonicalHeader.Groups['generation'].Value
    ExecutableCount     = $executables.Count
    SummaryCount        = $summaries.Count
    ToDoCount           = $declaredToDoCount
    InProgressCount     = $declaredInProgressCount
    DoneCount           = $declaredDoneCount
    DiscoverySucceeded  = $true
    InventoryResolved   = $true
    DependenciesAcyclic = $true
}
