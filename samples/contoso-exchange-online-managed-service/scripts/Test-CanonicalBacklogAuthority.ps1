#requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ [IO.Path]::GetFileName($_) -eq 'backlog.md' })]
    [string]$BacklogPath,

    [Parameter(Mandatory)]
    [ValidateScript({ [IO.Path]::GetFileName($_) -eq 'kanban.md' })]
    [string]$KanbanPath
)

$backlog = Get-Content -LiteralPath $BacklogPath -Raw -ErrorAction Stop
$kanban = Get-Content -LiteralPath $KanbanPath -Raw -ErrorAction Stop

$backlogClaimsAuthority = $backlog -match '(?im)^\s*Canonical generation\s*:'
$kanbanClaimsAuthority = (
    $kanban -match '(?im)^\s*Canonical generation\s*:' -or
    $kanban -match '(?i)(?<!not a )canonical status authority for current'
)
$authorityCount = @($backlogClaimsAuthority, $kanbanClaimsAuthority).Where({ $_ }).Count

if ($authorityCount -gt 1) {
    throw 'CanonicalAuthorityMultiple: more than one supplied file claims current status authority.'
}

if ($authorityCount -eq 0) {
    throw 'CanonicalAuthorityMissing: no supplied file claims current status authority.'
}

$legacyIsNonWritable = $kanban -match '(?i)\b(historical|generated|read-only)\b'
$legacyClaimsWritable = $kanban -match '(?i)\b(writable|updated independently)\b'
if (-not $legacyIsNonWritable -or $legacyClaimsWritable) {
    throw 'LegacyAuthorityWritable: the legacy board is not explicitly historical, generated, or read-only.'
}

$canonicalLinks = [regex]::Matches($kanban, '(?i)\[[^\]]+\]\((?<target>[^)]+)\)')
$linksToCanonicalBacklog = @($canonicalLinks).Where({
        $_.Groups['target'].Value.Trim() -eq 'backlog.md'
    }).Count -gt 0
if (-not $linksToCanonicalBacklog) {
    throw 'CanonicalIdentityMismatch: the legacy board does not identify backlog.md as canonical.'
}

$legacyClaimsCurrentAuthority = (
    $kanban -match '(?im)^\s*Current generation\s*:' -or
    $kanban -match '(?im)^\s*Current executable counts\s*:' -or
    $kanban -match '(?i)\bindependently governs current card status\b'
)
if ($legacyClaimsCurrentAuthority) {
    throw 'LegacyIndependentAuthorityClaim: a legacy view claims independent current generation, count, or status authority.'
}

[pscustomobject]@{
    CanonicalPath = $BacklogPath
    LegacyPath    = $KanbanPath
    AuthorityCount = $authorityCount
    LegacyMode    = 'HistoricalGeneratedOrReadOnly'
}
