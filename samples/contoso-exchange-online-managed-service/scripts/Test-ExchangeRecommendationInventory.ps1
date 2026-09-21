[CmdletBinding()]
param(
    [System.Collections.IDictionary]$Document,
    [string]$InventoryPath = (Join-Path $PSScriptRoot '../config/exchange-recommendations.v1.json'),
    [datetime]$AsOfUtc = [datetime]::UtcNow
)

$ErrorActionPreference = 'Stop'
$sampleRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$codes = [System.Collections.Generic.List[string]]::new()
if ($null -eq $Document) {
    try { $Document = Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json -AsHashtable }
    catch { return [pscustomobject]@{ Valid = $false; Codes = @('UnreadableInventory'); ReleaseReady = $false } }
}
$manifest = Get-Content (Join-Path $sampleRoot 'config/exchange-only.manifest.v1.json') -Raw | ConvertFrom-Json -AsHashtable
Import-Module (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psd1') -ErrorAction Stop
$registry = Get-BaselineControlRegistry -Profile ExchangeOnly
$moduleText = Get-Content (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psm1') -Raw
$tokens = $null
$parseErrors = $null
$moduleAst = [System.Management.Automation.Language.Parser]::ParseInput($moduleText, [ref]$tokens, [ref]$parseErrors)
$functionNames = @($moduleAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
$commandNames = @($moduleAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
$rawCommandNames = @([regex]::Matches($moduleText, '-Command\s+([A-Za-z]+-[A-Za-z0-9]+)') | ForEach-Object { $_.Groups[1].Value })
$knownCommands = @($functionNames) + @($commandNames) + @($rawCommandNames)
$raidText = Get-Content (Join-Path $sampleRoot '../../.github/RAID.md') -Raw
$backlogText = Get-Content (Join-Path $sampleRoot '../../.github/backlog.md') -Raw

if ($Document.Profile -cne $manifest.Profile -or $Document.ManifestVersion -cne $manifest.Version -or $Document.Version -cne '1.0.0') { $codes.Add('ManifestBindingMismatch') }
if ($Document.Claim -cne 'DeclaredExchangeManifest' -or $Document.ExternalReadiness -cne 'Unverified') { $codes.Add('UnsupportedClaim') }
$serialized = $Document | ConvertTo-Json -Depth 30
if ($serialized -match '(?i)100\s*%|fully\s+compliant|all\s+Microsoft\s+(365\s+)?recommendations|Microsoft.certified|universal.compliance') { $codes.Add('UnsupportedClaim') }
$cadence = 0
if (-not [int]::TryParse([string]$Document.ReviewCadenceDays, [ref]$cadence) -or $cadence -lt 1 -or $cadence -gt 90) { $codes.Add('InvalidReviewCadence'); $cadence = 90 }
if ([string]::IsNullOrWhiteSpace($Document.ReviewOwner)) { $codes.Add('MissingField') }
foreach ($record in @($Document) + @($Document.Sources)) {
    $reviewed = [datetime]::MinValue
    if (-not [datetime]::TryParseExact([string]$record.ReviewedOn, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$reviewed) -or $reviewed.Date -gt $AsOfUtc.Date) { $codes.Add('InvalidReviewDate') }
    elseif (($AsOfUtc.Date - $reviewed.Date).TotalDays -gt $cadence) { $codes.Add('StaleSource') }
}
$sourceIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$sourceUrls = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($source in @($Document.Sources)) {
    if (-not $sourceIds.Add([string]$source.Id)) { $codes.Add('DuplicateSource') }
    if (-not $sourceUrls.Add([string]$source.Url)) { $codes.Add('DuplicateSourceUrl') }
    $sourceUri = $null
    if (-not [uri]::TryCreate([string]$source.Url, [UriKind]::Absolute, [ref]$sourceUri) -or $sourceUri.Scheme -cne 'https' -or $sourceUri.Host -cnotin @('learn.microsoft.com','techcommunity.microsoft.com') -or $sourceUri.UserInfo -or $sourceUri.AbsolutePath -eq '/') { $codes.Add('UnsupportedSource') }
    if ([string]::IsNullOrWhiteSpace($source.Id) -or @($source.Sections | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) { $codes.Add('MissingField') }
}
$mapped = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($row in @($Document.Mappings) + @($Document.Assessments)) {
    foreach ($field in @('SourceId','Section','License','Setting','Reason')) {
        if ($field -eq 'Reason' -and $row.Contains('ControlId')) { continue }
        if ([string]::IsNullOrWhiteSpace([string]$row[$field])) { $codes.Add('MissingField') }
    }
    $source = @($Document.Sources | Where-Object { $_.Id -ceq $row.SourceId })
    if ($source.Count -ne 1) { $codes.Add('DanglingSource') }
    elseif ($row.Section -cnotin $source[0].Sections) { $codes.Add('DanglingSection') }
    if ($row.Basis -cnotin @('MicrosoftRecommendation','MicrosoftCapabilityLocalPolicy','LocalChoice')) { $codes.Add('UnsupportedBasis') }
    if ($row.Applicability -cne 'Applicable') { $codes.Add('UnsupportedApplicability') }
    if (@($row.Commands | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) { $codes.Add('MissingCommand') }
}
foreach ($row in @($Document.Mappings)) {
    if (-not $mapped.Add([string]$row.ControlId)) { $codes.Add('DuplicateMapping') }
    if ($row.ControlId -cnotin $manifest.ControlId) { $codes.Add('DanglingControl') }
    $entry = @($registry | Where-Object { $_.ControlId -ceq $row.ControlId })
    if ($row.Evaluator -cnotin $functionNames) { $codes.Add('DanglingEvaluator') }
    if ($entry.Count -eq 1) {
        if ($row.Evaluator -cne $entry[0].Evaluator) { $codes.Add('EvaluatorBindingMismatch') }
        if ($row.Evidence -cne $entry[0].EvidencePath) { $codes.Add('EvidenceBindingMismatch') }
    }
    foreach ($command in @($row.Commands)) {
        if ($command -cnotin $knownCommands) { $codes.Add('DanglingCommand') }
    }
    if ([string]::IsNullOrWhiteSpace($row.Limit)) { $codes.Add('MissingField') }
    try {
        $runbookPath = [IO.Path]::GetFullPath((Join-Path $sampleRoot ([string]$row.Runbook)))
        if (-not $runbookPath.StartsWith($sampleRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $runbookPath -PathType Leaf) -or [string]::IsNullOrWhiteSpace($row.RunbookSection)) { $codes.Add('DanglingRunbook') }
        else {
            $runbook = Get-Content -LiteralPath $runbookPath -Raw
            if ($runbook -cnotmatch ('(?m)^#{1,6} ' + [regex]::Escape($row.RunbookSection) + '\r?$')) { $codes.Add('DanglingRunbook') }
        }
    } catch { $codes.Add('DanglingRunbook') }
}
foreach ($control in $manifest.ControlId) { if (-not $mapped.Contains($control)) { $codes.Add('MissingMapping') } }
$proposalIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$ranks = [System.Collections.Generic.HashSet[int]]::new()
foreach ($proposal in @($Document.Proposals)) {
    if (-not $proposalIds.Add([string]$proposal.Id)) { $codes.Add('DuplicateProposal') }
    $rank = 0
    if (-not [int]::TryParse([string]$proposal.Rank, [ref]$rank) -or $rank -lt 1) { $codes.Add('InvalidRank') }
    elseif (-not $ranks.Add($rank)) { $codes.Add('DuplicateRank') }
    foreach ($field in @('Id','Title','Owner')) { if ([string]::IsNullOrWhiteSpace($proposal[$field])) { $codes.Add('MissingField') } }
    if ($proposal.Status -cne 'Proposed') { $codes.Add('UnsupportedClaim') }
    if (@($proposal.Acceptance | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -lt 2) { $codes.Add('MissingAcceptance') }
    if ($proposal.ExistingCard -and $backlogText -cnotmatch ('(?m)^### ' + [regex]::Escape($proposal.ExistingCard) + '\r?$')) { $codes.Add('DanglingChildReference') }
}
$assessmentIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$areas = @('SharingDelegation','Protocols','MailboxAccess','Domains','Protection','Auditing','ExchangeGovernance')
foreach ($assessment in @($Document.Assessments)) {
    if ([string]::IsNullOrWhiteSpace($assessment.Id)) { $codes.Add('MissingField') }
    if ($assessment.Area -cnotin $areas) { $codes.Add('UnknownAssessmentArea') }
    if (-not $assessmentIds.Add([string]$assessment.Id)) { $codes.Add('DuplicateAssessment') }
    if ($assessment.Coverage -cnotin @('Gap','Partial')) { $codes.Add('UnsupportedCoverage') }
    if (-not $proposalIds.Contains([string]$assessment.Proposal)) { $codes.Add('UntrackedGap') }
    foreach ($field in @('Evaluator','Evidence','Runbook')) {
        if ([string]::IsNullOrWhiteSpace($assessment[$field])) { $codes.Add('MissingField') }
        elseif ($assessment[$field] -cne 'Unimplemented') { $codes.Add('UnsupportedCoverage') }
    }
}
foreach ($proposal in @($Document.Proposals)) {
    if ($proposal.Id -cnotin @($Document.Assessments | ForEach-Object { $_.Proposal })) { $codes.Add('DanglingProposal') }
}
foreach ($area in $areas) {
    if ($area -cnotin @($Document.Assessments | ForEach-Object { $_.Area })) { $codes.Add('MissingAssessmentArea') }
}
$expectedExclusions = @(@($manifest.Exclusion) + @($manifest.ExternalCheck) | ForEach-Object { $_.ControlId })
$excluded = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($exclusion in @($Document.Exclusions)) {
    foreach ($control in @($exclusion.ControlId)) {
        if (-not $excluded.Add([string]$control)) { $codes.Add('DuplicateExclusion') }
        if ($control -cnotin $expectedExclusions) { $codes.Add('UnsupportedExclusion') }
        $declaredExclusion = @(@($manifest.Exclusion) + @($manifest.ExternalCheck) | Where-Object { $control -cin $_.ControlId })
        if ($declaredExclusion.Count -eq 1 -and $exclusion.Reference -cne $declaredExclusion[0].Reference) { $codes.Add('ExternalBindingMismatch') }
    }
    if ([string]::IsNullOrWhiteSpace($exclusion.Reason)) { $codes.Add('ExclusionReasonRequired') }
    if ([string]::IsNullOrWhiteSpace($exclusion.ExternalOwner)) { $codes.Add('ExternalOwnerRequired') }
    if ([string]::IsNullOrWhiteSpace($exclusion.Reference) -or $raidText -cnotmatch ('\| ' + [regex]::Escape($exclusion.Reference) + ' \|')) { $codes.Add('DanglingExternalReference') }
    if ($exclusion.Status -cne 'Unverified') { $codes.Add('UnsupportedClaim') }
}
foreach ($control in $expectedExclusions) { if (-not $excluded.Contains($control)) { $codes.Add('MissingExclusion') } }
[pscustomobject]@{
    Valid = $codes.Count -eq 0
    Codes = @($codes | Sort-Object -Unique)
    Scope = 'DeclaredExchangeManifest'
    ManifestCount = @($manifest.ControlId).Count
    MappedCount = $mapped.Count
    ProposedGapCount = @($Document.Proposals).Count
    ExternalReadiness = 'Unverified'
    ReleaseReady = $false
}