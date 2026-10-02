#requires -Version 7.5
<#
.SYNOPSIS
Writes a Markdown summary of everything one approved Exchange Online change left behind.

.DESCRIPTION
Reads the change artifacts (preview, approval, prechange, apply, rollback, postchange) and the evidence
envelope written by Test-ExchangeOnlineBaseline.ps1, then writes evidence-report-<ChangeId>.md into the
artifact folder. The report lists every artifact with its SHA-256 hash, the approved operations and their
outcome, evidence status counts, every check that did not pass, exclusions, and external readiness.

The script is read-only for the tenant: it never connects to Exchange Online. The report is a summary for
the change ticket; it is not a go-live approval.

.EXAMPLE
./scripts/New-ExchangeChangeEvidenceReport.ps1 -ArtifactRoot $change.ArtifactRoot -ChangeId $change.ChangeId
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ArtifactRoot,
    [Parameter(Mandatory)][string]$ChangeId,
    [string]$EvidencePath,
    [string]$OutputPath,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('InformationAction')) { $InformationPreference = 'Continue' }

if ($ChangeId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,63}\z') {
    throw "ChangeIdentifierNotRecognized: '$($ChangeId)' is not a change identifier; use letters, digits and hyphens only (for example CHG-1001)."
}
if (-not (Test-Path -LiteralPath $ArtifactRoot -PathType Container)) {
    throw "ArtifactRootMissing: '$($ArtifactRoot)' does not exist. Pass the same -ArtifactRoot you used for Preview and Apply (`$change.ArtifactRoot)."
}
$ArtifactRoot = (Resolve-Path -LiteralPath $ArtifactRoot).ProviderPath
if ([string]::IsNullOrWhiteSpace($EvidencePath)) { $EvidencePath = Join-Path $ArtifactRoot 'evidence/exchange-online-evidence.json' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $ArtifactRoot "evidence-report-$($ChangeId).md" }

if (-not (Test-Path -LiteralPath $EvidencePath -PathType Leaf)) {
    throw ("EvidenceMissing: '$($EvidencePath)' was not found. Collect evidence first:`n" +
        "  ./scripts/Test-ExchangeOnlineBaseline.ps1 -ParameterPath `$change.ParameterPath -ConfigurationPath `$change.ConfigurationPath -OutputPath (Join-Path `$change.ArtifactRoot 'evidence')`n" +
        'The collector confirms the signed-in account and tenant before it reads anything.')
}

function Read-JsonFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label)
    try {
        Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100 -DateKind String
    }
    catch {
        throw "$($Label)Unreadable: '$($Path)' is not readable JSON ($($_.Exception.Message)). Do not edit change artifacts by hand; rerun the stage that wrote it."
    }
}

function Get-RecordValue {
    param([object]$Node, [string]$Name)
    if ($null -ne $Node -and $Node.PSObject.Properties[$Name]) { $Node.$Name } else { $null }
}

function Format-Cell {
    param([object]$Value)
    $text = if ($null -eq $Value) { '' } elseif ($Value -is [array]) { ($Value | ForEach-Object { [string]$_ }) -join ', ' } else { [string]$Value }
    $text = ($text -replace '\r?\n', ' ' -replace '\|', '\|').Trim()
    if ([string]::IsNullOrEmpty($text)) { '-' } else { $text }
}

$evidence = Read-JsonFile -Path $EvidencePath -Label 'Evidence'

$artifactSpec = @(
    @{ Artifact = 'Preview'; Name = "preview-$($ChangeId).json" }
    @{ Artifact = 'Approval'; Name = "approval-$($ChangeId).json" }
    @{ Artifact = 'PreChange'; Name = "prechange-$($ChangeId).json" }
    @{ Artifact = 'Apply'; Name = "apply-$($ChangeId).json" }
    @{ Artifact = 'Rollback'; Name = "rollback-$($ChangeId).ps1" }
    @{ Artifact = 'PostChange'; Name = "postchange-$($ChangeId).json" }
)
$artifacts = foreach ($spec in $artifactSpec) {
    $path = Join-Path $ArtifactRoot $spec.Name
    $present = Test-Path -LiteralPath $path -PathType Leaf
    [pscustomobject]@{
        Artifact  = $spec.Artifact
        Name      = $spec.Name
        Path      = $path
        Present   = $present
        Sha256    = $(if ($present) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() } else { '' })
        Modified  = $(if ($present) { (Get-Item -LiteralPath $path).LastWriteTimeUtc.ToString('u') } else { '' })
    }
}
$documents = @{}
foreach ($artifact in $artifacts | Where-Object { $_.Present -and $_.Name.EndsWith('.json') }) {
    $documents[$artifact.Artifact] = Read-JsonFile -Path $artifact.Path -Label $artifact.Artifact
}
$missing = @($artifacts | Where-Object { -not $_.Present } | ForEach-Object Artifact)

$preview = $documents['Preview']
$approval = $documents['Approval']
$apply = $documents['Apply']
$post = $documents['PostChange']
$applyStatus = [string](Get-RecordValue $apply 'Status')
$postStatus = [string](Get-RecordValue $post 'Status')

$checks = @(Get-RecordValue $evidence 'Check' | Where-Object { $null -ne $_ })
$noEvidenceChecks = $checks.Count -eq 0
$statusOrder = 'Pass', 'Fail', 'Error', 'Manual', 'ApprovedException', 'NotEntitled'
$statusCount = [ordered]@{}
foreach ($status in $statusOrder) { $statusCount[$status] = 0 }
foreach ($check in $checks) {
    $status = [string](Get-RecordValue $check 'Status')
    if (-not $statusCount.Contains($status)) { $statusCount[$status] = 0 }
    $statusCount[$status]++
}
$needsAttention = @($checks | Where-Object { [string](Get-RecordValue $_ 'Status') -ne 'Pass' })

# Evidence only counts for this change when it was collected for the previewed tenant, profile and configuration.
$normalizeHash = { param($Value) ([string]$Value -replace '(?i)^sha256:', '').Trim().ToLowerInvariant() }
$binding = @(
    [pscustomobject]@{ Field = 'Tenant'; Preview = [string](Get-RecordValue $preview 'Tenant'); Evidence = [string](Get-RecordValue $evidence 'TenantId'); Compare = { param($a, $b) $a.Trim() -eq $b.Trim() } }
    [pscustomobject]@{ Field = 'DeploymentProfile'; Preview = [string](Get-RecordValue $preview 'DeploymentProfile'); Evidence = [string](Get-RecordValue $evidence 'DeploymentProfile'); Compare = { param($a, $b) $a -ceq $b } }
    [pscustomobject]@{ Field = 'ConfigurationHash'; Preview = [string](Get-RecordValue $preview 'ConfigurationHash'); Evidence = [string](Get-RecordValue $evidence 'ConfigurationHash'); Compare = { param($a, $b) (& $normalizeHash $a) -ceq (& $normalizeHash $b) } }
    [pscustomobject]@{ Field = 'CollectedAfterApply'; Preview = [string](Get-RecordValue $apply 'CompletedOn'); Evidence = [string](Get-RecordValue $evidence 'CollectedAtUtc'); Compare = {
            param($a, $b)
            $style = [Globalization.DateTimeStyles]::AssumeUniversal
            $applied = [datetimeoffset]::MinValue; $collected = [datetimeoffset]::MinValue
            [datetimeoffset]::TryParse($a, [Globalization.CultureInfo]::InvariantCulture, $style, [ref]$applied) -and
            [datetimeoffset]::TryParse($b, [Globalization.CultureInfo]::InvariantCulture, $style, [ref]$collected) -and
            $collected -ge $applied
        } }
) | ForEach-Object {
    $match = -not [string]::IsNullOrWhiteSpace($_.Preview) -and -not [string]::IsNullOrWhiteSpace($_.Evidence) -and (& $_.Compare $_.Preview $_.Evidence)
    [pscustomobject]@{ Field = $_.Field; Preview = $_.Preview; Evidence = $_.Evidence; Match = [bool]$match }
}
$bindingMismatch = @($binding | Where-Object { -not $_.Match } | ForEach-Object Field)

# Approval, apply and post-change only count when they were written for this change and this frozen preview.
$previewSha256 = [string]($artifacts | Where-Object Artifact -EQ 'Preview' | ForEach-Object Sha256)
$previewTenant = ([string](Get-RecordValue $preview 'Tenant')).Trim()
$previewConfiguration = & $normalizeHash (Get-RecordValue $preview 'ConfigurationHash')
$artifactMismatch = @(
    if ($null -ne $preview -and [string](Get-RecordValue $preview 'ChangeId') -cne $ChangeId) { 'Preview ChangeId' }
    foreach ($name in 'Approval', 'Apply', 'PostChange') {
        $document = $documents[$name]
        if ($null -eq $document -or $null -eq $preview) { continue }
        if ([string](Get-RecordValue $document 'ChangeId') -cne $ChangeId) { "$($name) ChangeId" }
        $documentTenant = ([string](Get-RecordValue $document 'Tenant')).Trim()
        if ([string]::IsNullOrEmpty($documentTenant) -or $documentTenant -ne $previewTenant) { "$($name) Tenant" }
        if ([string](Get-RecordValue $document 'PreviewHash') -cne $previewSha256) { "$($name) PreviewHash" }
        if ($name -ne 'Approval') {
            $documentConfiguration = & $normalizeHash (Get-RecordValue $document 'ConfigurationHash')
            if ([string]::IsNullOrEmpty($documentConfiguration) -or $documentConfiguration -cne $previewConfiguration) { "$($name) ConfigurationHash" }
        }
    }
)

$complete = $missing.Count -eq 0 -and $applyStatus -eq 'Succeeded' -and $postStatus -eq 'Succeeded' -and
    -not $noEvidenceChecks -and $bindingMismatch.Count -eq 0 -and $artifactMismatch.Count -eq 0
$overall = if (-not $complete) { 'INCOMPLETE' }
elseif (($statusCount['Fail'] + $statusCount['Error']) -gt 0) { 'APPLIED - CONTROLS NEED ATTENTION' }
else { 'APPLIED - EVIDENCE COLLECTED' }

$md = [System.Text.StringBuilder]::new()
function Add-Line { param([string]$Text = '') $null = $md.AppendLine($Text) }

Add-Line "# Exchange Online change evidence report: $($ChangeId)"
Add-Line
Add-Line "**Outcome: $($overall)**"
Add-Line
Add-Line '> This report summarises the change record and the collected evidence. It is not a go-live approval and does not turn unverified readiness into Pass.'
Add-Line
Add-Line '## Summary'
Add-Line
Add-Line '| Item | Value |'
Add-Line '| --- | --- |'
Add-Line "| Change | $(Format-Cell $ChangeId) |"
Add-Line "| Tenant | $(Format-Cell (Get-RecordValue $preview 'Tenant')) |"
Add-Line "| Scope | $(Format-Cell (Get-RecordValue $preview 'Scope')) |"
Add-Line "| Preview generated | $(Format-Cell (Get-RecordValue $preview 'GeneratedOn')) |"
Add-Line "| Approved by | $(Format-Cell (Get-RecordValue $approval 'ApprovalIdentity')) |"
Add-Line "| Approved at | $(Format-Cell (Get-RecordValue $approval 'ApprovalTimeUtc')) |"
Add-Line "| Apply status | $(Format-Cell $applyStatus) |"
Add-Line "| Apply completed | $(Format-Cell (Get-RecordValue $apply 'CompletedOn')) |"
Add-Line "| Post-change status | $(Format-Cell $postStatus) |"
Add-Line "| Evidence collected | $(Format-Cell (Get-RecordValue $evidence 'CollectedAtUtc')) |"
Add-Line "| Configuration hash | $(Format-Cell (Get-RecordValue $preview 'ConfigurationHash')) |"
Add-Line "| Manifest hash | $(Format-Cell (Get-RecordValue $evidence 'ManifestHash')) |"
Add-Line "| Report written | $([datetimeoffset]::UtcNow.ToString('u')) |"
Add-Line

Add-Line '## Evidence binding'
Add-Line
Add-Line '| Field | Change record | Evidence | Match |'
Add-Line '| --- | --- | --- | --- |'
foreach ($row in $binding) {
    Add-Line "| $($row.Field) | $(Format-Cell $row.Preview) | $(Format-Cell $row.Evidence) | $(if ($row.Match) { 'Yes' } else { '**No**' }) |"
}
Add-Line
if ($bindingMismatch.Count -gt 0) {
    Add-Line "The evidence does not belong to this change ($($bindingMismatch -join ', ') differ, are missing, or were collected before apply completed). Recollect evidence after apply with this change's parameter and configuration files."
    Add-Line
}

Add-Line '## Change artifacts'
Add-Line
Add-Line '| Artifact | File | Status | SHA-256 | Modified (UTC) |'
Add-Line '| --- | --- | --- | --- | --- |'
foreach ($artifact in $artifacts) {
    $state = if ($artifact.Present) { 'Present' } else { '**Missing**' }
    Add-Line "| $($artifact.Artifact) | ``$($artifact.Name)`` | $($state) | $(Format-Cell $artifact.Sha256) | $(Format-Cell $artifact.Modified) |"
}
Add-Line "| Evidence | ``$([IO.Path]::GetRelativePath($ArtifactRoot, $EvidencePath))`` | Present | $((Get-FileHash -LiteralPath $EvidencePath -Algorithm SHA256).Hash.ToLowerInvariant()) | $((Get-Item -LiteralPath $EvidencePath).LastWriteTimeUtc.ToString('u')) |"
Add-Line
if ($missing.Count -gt 0) {
    Add-Line "Missing artifacts: $($missing -join ', '). Every change leaves all six; find them before closing the ticket."
    Add-Line
}
if ($artifactMismatch.Count -gt 0) {
    Add-Line "These artifact fields do not belong to this change: $($artifactMismatch -join ', '). Each file must name this change and tenant and carry this preview's SHA-256. Do not rename or edit change artifacts; use the files the stages wrote for this change."
    Add-Line
}

Add-Line '## Operations'
Add-Line
$operations = @(Get-RecordValue $preview 'Operation' | Where-Object { $null -ne $_ })
if ($operations.Count -eq 0) {
    Add-Line 'No preview operations were found.'
}
else {
    $stateById = @{}
    foreach ($entry in @(Get-RecordValue $apply 'Operation' | Where-Object { $null -ne $_ })) {
        $stateById[[string](Get-RecordValue $entry 'OperationId')] = [string](Get-RecordValue $entry 'State')
    }
    Add-Line '| # | Command | Identity | Result |'
    Add-Line '| --- | --- | --- | --- |'
    foreach ($operation in $operations | Sort-Object { [int](Get-RecordValue $_ 'Sequence') }) {
        $result = $stateById[[string](Get-RecordValue $operation 'OperationId')]
        if ([string]::IsNullOrEmpty($result)) { $result = 'Not applied' }
        Add-Line "| $(Format-Cell (Get-RecordValue $operation 'Sequence')) | ``$(Format-Cell (Get-RecordValue $operation 'Command'))`` | $(Format-Cell (Get-RecordValue $operation 'Identity')) | $(Format-Cell $result) |"
    }
}
Add-Line

Add-Line '## Evidence results'
Add-Line
Add-Line '| Status | Count |'
Add-Line '| --- | --- |'
foreach ($status in $statusCount.Keys) { Add-Line "| $($status) | $($statusCount[$status]) |" }
Add-Line
if ($noEvidenceChecks) {
    Add-Line 'No evidence checks were found; evidence collection is incomplete.'
}
elseif ($needsAttention.Count -eq 0) {
    Add-Line 'Every check passed.'
}
else {
    Add-Line '### Checks that did not pass'
    Add-Line
    Add-Line '| Control | Status | Reason |'
    Add-Line '| --- | --- | --- |'
    foreach ($check in $needsAttention) {
        Add-Line "| $(Format-Cell (Get-RecordValue $check 'ControlId')) | $(Format-Cell (Get-RecordValue $check 'Status')) | $(Format-Cell (Get-RecordValue $check 'Reason')) |"
    }
}
Add-Line

foreach ($section in @(
        @{ Title = 'External readiness'; Name = 'ExternalReadiness' }
        @{ Title = 'Exclusions'; Name = 'Exclusion' }
    )) {
    $items = @(Get-RecordValue $evidence $section.Name | Where-Object { $null -ne $_ })
    if ($items.Count -eq 0) { continue }
    Add-Line "## $($section.Title)"
    Add-Line
    $columns = @($items | ForEach-Object { $_.PSObject.Properties.Name } | Where-Object { $_ -notin 'Evidence', 'Detail' } | Select-Object -Unique)
    Add-Line "| $($columns -join ' | ') |"
    Add-Line "| $(($columns | ForEach-Object { '---' }) -join ' | ') |"
    foreach ($item in $items) {
        Add-Line "| $(($columns | ForEach-Object { Format-Cell (Get-RecordValue $item $_) }) -join ' | ') |"
    }
    Add-Line
}

Add-Line '## Next actions'
Add-Line
if ($missing.Count -gt 0) { Add-Line "- Locate or regenerate the missing artifacts: $($missing -join ', ')." }
if ($artifactMismatch.Count -gt 0) { Add-Line "- Replace the artifacts that belong to another change or preview: $($artifactMismatch -join ', ')." }
if ($bindingMismatch.Count -gt 0) { Add-Line "- Recollect evidence after apply for this change; $($bindingMismatch -join ', ') do not match the change record." }
if ($applyStatus -ne 'Succeeded' -or $postStatus -ne 'Succeeded') { Add-Line '- Apply or post-change did not report Succeeded. Follow your recovery decision before closing.' }
if ($noEvidenceChecks) { Add-Line '- Recollect evidence that includes the expected control check records; an empty check collection is not a passing result.' }
if ($needsAttention.Count -gt 0) { Add-Line "- Assign an owner to each of the $($needsAttention.Count) checks that did not pass." }
Add-Line '- Attach this report and the whole artifact folder to the change ticket.'
Add-Line '- Disconnect: `Disconnect-ExchangeOnline -Confirm:$false`.'

$outputDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($OutputPath))
$null = New-Item -ItemType Directory -Path $outputDirectory -Force
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath), $md.ToString(), [Text.UTF8Encoding]::new($false))

$color = if ($overall -eq 'APPLIED - EVIDENCE COLLECTED') { $PSStyle.Foreground.Green } elseif ($complete) { $PSStyle.Foreground.Yellow } else { $PSStyle.Foreground.Red }
Write-Information "$($color)$($overall)$($PSStyle.Reset)"
Write-Information "  Artifacts present: $(6 - $missing.Count) of 6$(if ($missing.Count) { " (missing: $($missing -join ', '))" })"
if ($bindingMismatch.Count -gt 0) { Write-Information "  Evidence binding: $($bindingMismatch -join ', ') do not match the change record" }
if ($artifactMismatch.Count -gt 0) { Write-Information "  Artifact binding: $($artifactMismatch -join ', ') belong to another change or preview" }
Write-Information "  Evidence: $(($statusCount.Keys | Where-Object { $statusCount[$_] -gt 0 } | ForEach-Object { "$($_) $($statusCount[$_])" }) -join ', ')"
if ($noEvidenceChecks) { Write-Information '  Evidence checks: none found; collection is incomplete' }
Write-Information "  Report: $([IO.Path]::GetFullPath($OutputPath))"

if ($PassThru) {
    [pscustomobject]@{
        Path            = [IO.Path]::GetFullPath($OutputPath)
        Outcome         = $overall
        Complete        = $complete
        MissingArtifact = $missing
        BindingMismatch = $bindingMismatch
        ArtifactMismatch = $artifactMismatch
        EvidenceCheckCount = $checks.Count
        StatusCount     = [pscustomobject]$statusCount
    }
}
