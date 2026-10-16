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

$artifactSpec = @(
    @{ Artifact = 'Preview'; Name = "preview-$($ChangeId).json" }
    @{ Artifact = 'Approval'; Name = "approval-$($ChangeId).json" }
    @{ Artifact = 'PreChange'; Name = "prechange-$($ChangeId).json" }
    @{ Artifact = 'Apply'; Name = "apply-$($ChangeId).json" }
    @{ Artifact = 'Rollback'; Name = "rollback-$($ChangeId).ps1" }
    @{ Artifact = 'PostChange'; Name = "postchange-$($ChangeId).json" }
)
$rollbackResultName = "rollback-result-$ChangeId.json"
$rollbackResultPath = Join-Path $ArtifactRoot $rollbackResultName
$rollbackIndexName = "rollback-$ChangeId.lock"
$rollbackIndexPath = Join-Path $ArtifactRoot $rollbackIndexName
$rollbackResultPresent = Test-Path -LiteralPath $rollbackResultPath -PathType Leaf
$rollbackIndexPresent = Test-Path -LiteralPath $rollbackIndexPath -PathType Leaf
$rollbackAttemptFiles = @(Get-ChildItem -LiteralPath $ArtifactRoot -File -Filter "rollback-attempt-$ChangeId-*.json" -ErrorAction SilentlyContinue)
$optionalRollbackSpec = @()
if ($rollbackResultPresent) {
    $optionalRollbackSpec += @{ Artifact = 'RollbackResult'; Name = $rollbackResultName }
}
if ($rollbackIndexPresent) {
    $optionalRollbackSpec += @{ Artifact = 'RollbackAttemptIndex'; Name = $rollbackIndexName }
}
foreach ($attemptFile in $rollbackAttemptFiles) {
    $optionalRollbackSpec += @{ Artifact = 'RollbackAttempt'; Name = $attemptFile.Name }
}
$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
$pathComparison = if ([IO.Path]::DirectorySeparatorChar -eq '\') {
    [StringComparison]::OrdinalIgnoreCase
} else {
    [StringComparison]::Ordinal
}
$protectedPaths = @($EvidencePath) + @($artifactSpec | ForEach-Object { Join-Path $ArtifactRoot $_.Name }) +
    @($rollbackResultPath, $rollbackIndexPath) + @($rollbackAttemptFiles | ForEach-Object FullName)
foreach ($protectedPath in $protectedPaths) {
    if ([string]::Equals($outputFullPath, [IO.Path]::GetFullPath($protectedPath), $pathComparison)) {
        throw "EvidenceReportOutputPathCollision: OutputPath '$outputFullPath' resolves to a change artifact or evidence input '$protectedPath'; choose a separate report path."
    }
}

if (-not (Test-Path -LiteralPath $EvidencePath -PathType Leaf)) {
    throw ("EvidenceMissing: '$($EvidencePath)' was not found. Collect evidence first:`n" +
        "  ./scripts/Test-ExchangeOnlineBaseline.ps1 -ParameterPath `$change.ParameterPath -ConfigurationPath `$change.ConfigurationPath -OutputPath (Join-Path `$change.ArtifactRoot 'evidence')`n" +
        'The collector confirms the signed-in account and tenant before it reads anything.')
}

function Assert-UniqueJsonPropertyNames {
    param([Parameter(Mandatory)][System.Text.Json.JsonElement]$Element)
    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                throw "JSON object contains duplicate property '$($property.Name)' (case-insensitive)."
            }
            Assert-UniqueJsonPropertyNames -Element $property.Value
        }
    }
    elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            Assert-UniqueJsonPropertyNames -Element $item
        }
    }
}

function Read-JsonFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label)
    try {
        $raw = Get-Content -LiteralPath $Path -Raw
        $options = [System.Text.Json.JsonDocumentOptions]::new()
        $options.MaxDepth = 100
        $jsonDocument = [System.Text.Json.JsonDocument]::Parse($raw, $options)
        try {
            Assert-UniqueJsonPropertyNames -Element $jsonDocument.RootElement
        }
        finally {
            $jsonDocument.Dispose()
        }
        $raw | ConvertFrom-Json -AsHashtable -NoEnumerate -Depth 100 -DateKind String
    }
    catch {
        throw "$($Label)Unreadable: '$($Path)' is not readable JSON ($($_.Exception.Message)). Do not edit change artifacts by hand; rerun the stage that wrote it."
    }
}

$script:documentMismatch = [Collections.Generic.List[string]]::new()
function Read-JsonDocument {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label)
    try {
        $document = Read-JsonFile -Path $Path -Label $Label
    }
    catch {
        $script:documentMismatch.Add($_.Exception.Message)
        return $null
    }
    if ($document -isnot [System.Collections.IDictionary]) {
        $script:documentMismatch.Add("$($Label)Invalid: JSON root must be an object.")
        return $null
    }
    $document
}

function Get-RecordValue {
    param([object]$Node, [string]$Name)
    if ($Node -is [System.Collections.IDictionary]) {
        if ($Node.Contains($Name)) { $Node[$Name] }
    }
    elseif ($null -ne $Node -and $Node.PSObject.Properties[$Name]) {
        $Node.$Name
    }
}

function Get-TrimmedRecordValue {
    param([object]$Node, [string]$Name)
    $value = Get-RecordValue $Node $Name
    if ($null -eq $value) { return '' }
    ([string]$value).Trim()
}

function Format-Cell {
    param([object]$Value)
    $text = if ($null -eq $Value) { '' } elseif ($Value -is [array]) { ($Value | ForEach-Object { [string]$_ }) -join ', ' } else { [string]$Value }
    $text = ($text -replace '\r?\n', ' ' -replace '\|', '\|').Trim()
    if ([string]::IsNullOrEmpty($text)) { '-' } else { $text }
}

$evidence = Read-JsonDocument -Path $EvidencePath -Label 'Evidence'
$manifest = Read-JsonFile -Path (Join-Path $PSScriptRoot '../config/exchange-only.manifest.v1.json') -Label 'Evidence manifest'
if ($manifest -isnot [System.Collections.IDictionary]) { throw 'EvidenceManifestInvalid: the shipped manifest root must be a JSON object.' }
Import-Module (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psm1') `
    -Function @('ConvertTo-CanonicalJson', 'Get-BaselineRollbackRecoveryState') -ErrorAction Stop
$manifestHash = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson -InputObject $manifest))
    )
).ToLowerInvariant()
$expectedControlIds = @(Get-RecordValue $manifest 'ControlId' | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
if ($expectedControlIds.Count -eq 0 -or @($expectedControlIds | Select-Object -Unique).Count -ne $expectedControlIds.Count) {
    throw 'EvidenceManifestInvalid: the shipped ExchangeOnly manifest must contain unique control identifiers.'
}

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
$artifacts = @($artifacts)
foreach ($spec in $optionalRollbackSpec) {
    $path = Join-Path $ArtifactRoot $spec.Name
    $artifacts += [pscustomobject]@{
        Artifact = $spec.Artifact
        Name = $spec.Name
        Path = $path
        Present = $true
        Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        Modified = (Get-Item -LiteralPath $path).LastWriteTimeUtc.ToString('u')
    }
}
$requiredArtifactNames = @($artifactSpec | ForEach-Object Artifact)
$documents = @{}
foreach ($artifact in $artifacts | Where-Object { $_.Present -and $_.Artifact -in @('Preview', 'Approval', 'PreChange', 'Apply', 'PostChange') }) {
    $document = Read-JsonDocument -Path $artifact.Path -Label $artifact.Artifact
    if ($null -ne $document) { $documents[$artifact.Artifact] = $document }
}
$missing = @($artifacts | Where-Object { -not $_.Present -and $_.Artifact -in $requiredArtifactNames } | ForEach-Object Artifact)
$rollbackResult = $null
$rollbackReadError = ''
if ($rollbackResultPresent) {
    try {
        $rollbackResult = Read-JsonFile -Path $rollbackResultPath -Label 'RollbackResult'
    }
    catch {
        $rollbackReadError = $_.Exception.Message
    }
}

$preview = $documents['Preview']
$approval = $documents['Approval']
$prechange = $documents['PreChange']
$apply = $documents['Apply']
$post = $documents['PostChange']
$applyStatus = [string](Get-RecordValue $apply 'Status')
$postStatus = [string](Get-RecordValue $post 'Status')

$checks = @(Get-RecordValue $evidence 'Check' | Where-Object { $null -ne $_ })
$noEvidenceChecks = $checks.Count -eq 0
$expectedControlIdSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$expectedControlIds | ForEach-Object { $null = $expectedControlIdSet.Add($_) }
$observedControlIdSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$checkMismatch = @()
foreach ($check in $checks) {
    $controlId = [string](Get-RecordValue $check 'ControlId')
    if ([string]::IsNullOrWhiteSpace($controlId)) {
        $checkMismatch += 'Evidence check has no ControlId'
    }
    elseif (-not $expectedControlIdSet.Contains($controlId)) {
        $checkMismatch += "Unexpected evidence control '$controlId'"
    }
    elseif (-not $observedControlIdSet.Add($controlId)) {
        $checkMismatch += "Duplicate evidence control '$controlId'"
    }
}
foreach ($controlId in $expectedControlIds) {
    if (-not $observedControlIdSet.Contains($controlId)) {
        $checkMismatch += "Missing evidence control '$controlId'"
    }
}
$statusOrder = 'Pass', 'Fail', 'Error', 'Manual', 'ApprovedException', 'NotApplicable', 'NotEntitled', 'Unverified'
$statusCount = [ordered]@{}
foreach ($status in $statusOrder) { $statusCount[$status] = 0 }
foreach ($check in $checks) {
    $status = [string](Get-RecordValue $check 'Status')
    if (-not $statusCount.Contains($status)) { $statusCount[$status] = 0 }
    $statusCount[$status]++
}
$acceptedEvidenceStatuses = @('Pass', 'ApprovedException', 'NotApplicable')
$needsAttention = @($checks | Where-Object { [string](Get-RecordValue $_ 'Status') -cnotin $acceptedEvidenceStatuses })

# Evidence only counts for this change when it was collected for the previewed tenant, profile and configuration.
$normalizeHash = { param($Value) ([string]$Value -replace '(?i)^sha256:', '').Trim().ToLowerInvariant() }
$binding = @(
    [pscustomobject]@{ Field = 'Tenant'; Preview = [string](Get-RecordValue $preview 'Tenant'); Evidence = [string](Get-RecordValue $evidence 'TenantId'); Compare = { param($a, $b) $a.Trim() -eq $b.Trim() } }
    [pscustomobject]@{ Field = 'DeploymentProfile'; Preview = [string](Get-RecordValue $preview 'DeploymentProfile'); Evidence = [string](Get-RecordValue $evidence 'DeploymentProfile'); Compare = { param($a, $b) $a -ceq $b } }
    [pscustomobject]@{ Field = 'ConfigurationHash'; Preview = [string](Get-RecordValue $preview 'ConfigurationHash'); Evidence = [string](Get-RecordValue $evidence 'ConfigurationHash'); Compare = { param($a, $b) (& $normalizeHash $a) -ceq (& $normalizeHash $b) } }
    [pscustomobject]@{ Field = 'ManifestHash'; Preview = $manifestHash; Evidence = [string](Get-RecordValue $evidence 'ManifestHash'); Compare = { param($a, $b) $a.Trim() -ieq $b.Trim() } }
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
$previewTenantValue = Get-RecordValue $preview 'Tenant'
$previewTenant = if ($null -eq $previewTenantValue) { '' } else { ([string]$previewTenantValue).Trim() }
$previewConfiguration = & $normalizeHash (Get-RecordValue $preview 'ConfigurationHash')
$operations = @(Get-RecordValue $preview 'Operation' | Where-Object { $null -ne $_ })
$captureById = @{}
foreach ($entry in @(Get-RecordValue $prechange 'Entry' | Where-Object { $null -ne $_ })) {
    $operationId = [string](Get-RecordValue $entry 'OperationId')
    $exists = Get-RecordValue $entry 'Exists'
    if (-not [string]::IsNullOrWhiteSpace($operationId) -and -not $captureById.ContainsKey($operationId) -and $exists -is [bool]) {
        $captureById[$operationId] = [ordered]@{
            Exists = $exists
            Value = Get-RecordValue $entry 'Value'
        }
    }
}
$rollbackErrors = [Collections.Generic.List[string]]::new()
$applyConfiguration = & $normalizeHash (Get-RecordValue $apply 'ConfigurationHash')
$applyJournalIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$applyJournalValid = $null -ne $apply
foreach ($applyOperation in @(Get-RecordValue $apply 'Operation' | Where-Object { $null -ne $_ })) {
    $operationId = [string](Get-RecordValue $applyOperation 'OperationId')
    $approvedOperation = @($operations | Where-Object { [string](Get-RecordValue $_ 'OperationId') -ceq $operationId })
    $operationState = [string](Get-RecordValue $applyOperation 'State')
    $operationProgress = [string](Get-RecordValue $applyOperation 'Progress')
    if ([string]::IsNullOrWhiteSpace($operationId) -or $approvedOperation.Count -ne 1 -or
        -not $applyJournalIds.Add($operationId) -or
        [string](Get-RecordValue $applyOperation 'Command') -cne [string](Get-RecordValue $approvedOperation[0] 'Command') -or
        [string](Get-RecordValue $applyOperation 'Identity') -cne [string](Get-RecordValue $approvedOperation[0] 'Identity') -or
        [int](Get-RecordValue $applyOperation 'Sequence') -ne [int](Get-RecordValue $approvedOperation[0] 'Sequence') -or
        $operationState -cnotin @('Succeeded', 'Unchanged', 'Failed') -or
        $operationProgress -cnotin @('', 'Removed', 'Created') -or
        ($operationState -ceq 'Failed' -and [string]::IsNullOrWhiteSpace([string](Get-RecordValue $applyOperation 'Fault')))) {
        $applyJournalValid = $false
    }
}
if ($applyStatus -ceq 'Succeeded' -and $applyJournalIds.Count -ne $operations.Count) { $applyJournalValid = $false }
$applyReceiptBound = $null -ne $apply -and $applyJournalValid -and
    $applyStatus -cin @('Succeeded', 'Failed') -and
    ($applyStatus -cne 'Failed' -or -not [string]::IsNullOrWhiteSpace([string](Get-RecordValue $apply 'Fault'))) -and
    [string](Get-RecordValue $apply 'ChangeId') -ceq $ChangeId -and
    [string](Get-RecordValue $apply 'Tenant') -ceq $previewTenant -and
    [string](Get-RecordValue $apply 'DeploymentProfile') -ceq 'ExchangeOnly' -and
    [string](Get-RecordValue $apply 'PreviewHash') -ceq $previewSha256 -and
    -not [string]::IsNullOrWhiteSpace($previewSha256) -and
    $applyConfiguration -ceq $previewConfiguration
if (-not [string]::IsNullOrWhiteSpace($rollbackReadError)) { $rollbackErrors.Add($rollbackReadError) }
$rollbackAttempts = @()
if ($rollbackIndexPresent -or $rollbackAttemptFiles.Count -gt 0) {
    try {
        $rollbackRecovery = Get-BaselineRollbackRecoveryState -ArtifactRoot $ArtifactRoot -ChangeId $ChangeId `
            -Tenant $previewTenant -PreviewHash $previewSha256 `
            -ConfigurationHash ([string](Get-RecordValue $preview 'ConfigurationHash')) -Approved $operations
        $rollbackAttempts = @($rollbackRecovery.Attempts)
    }
    catch {
        $rollbackErrors.Add($_.Exception.Message)
    }
}
$rollbackReceiptValid = $false
$rollbackCompleted = [datetimeoffset]::MinValue
if ($rollbackResultPresent -and $rollbackResult -isnot [System.Collections.IDictionary] -and [string]::IsNullOrWhiteSpace($rollbackReadError)) {
    $rollbackErrors.Add('RollbackResultInvalid: the rollback result root must be a JSON object.')
}
elseif ($null -ne $rollbackResult) {
    $rollbackResultMismatch = @()
    if ([string](Get-RecordValue $rollbackResult 'ChangeId') -cne $ChangeId) { $rollbackResultMismatch += 'ChangeId' }
    $rollbackTenant = Get-TrimmedRecordValue $rollbackResult 'Tenant'
    if ([string]::IsNullOrWhiteSpace($rollbackTenant) -or $rollbackTenant -cne $previewTenant) { $rollbackResultMismatch += 'Tenant' }
    if ([string](Get-RecordValue $rollbackResult 'DeploymentProfile') -cne 'ExchangeOnly') { $rollbackResultMismatch += 'DeploymentProfile' }
    if ($previewSha256 -notmatch '^[0-9a-f]{64}$' -or [string](Get-RecordValue $rollbackResult 'PreviewHash') -cne $previewSha256) { $rollbackResultMismatch += 'PreviewHash' }
    $rollbackConfiguration = & $normalizeHash (Get-RecordValue $rollbackResult 'ConfigurationHash')
    if ([string]::IsNullOrWhiteSpace($rollbackConfiguration) -or $rollbackConfiguration -cne $previewConfiguration) { $rollbackResultMismatch += 'ConfigurationHash' }
    if ([string](Get-RecordValue $rollbackResult 'Status') -cne 'Succeeded') { $rollbackResultMismatch += 'Status' }
    if (-not [string]::IsNullOrWhiteSpace([string](Get-RecordValue $rollbackResult 'Fault'))) { $rollbackResultMismatch += 'Fault' }
    $dateStyles = [Globalization.DateTimeStyles]::AssumeUniversal
    if (-not [datetimeoffset]::TryParse(
            [string](Get-RecordValue $rollbackResult 'CompletedOn'),
            [Globalization.CultureInfo]::InvariantCulture,
            $dateStyles,
            [ref]$rollbackCompleted
        )) {
        $rollbackResultMismatch += 'CompletedOn'
    }
    $rollbackOperations = @(Get-RecordValue $rollbackResult 'Operation' | Where-Object { $null -ne $_ })
    $rollbackOperationIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    if ($operations.Count -eq 0) { $rollbackResultMismatch += 'Operation coverage' }
    foreach ($rollbackOperation in $rollbackOperations) {
        $operationId = [string](Get-RecordValue $rollbackOperation 'OperationId')
        $approvedOperation = @($operations | Where-Object { [string](Get-RecordValue $_ 'OperationId') -ceq $operationId })
        if ([string]::IsNullOrWhiteSpace($operationId) -or $approvedOperation.Count -ne 1 -or
            -not $rollbackOperationIds.Add($operationId)) {
            $rollbackResultMismatch += 'Operation coverage'
            continue
        }
        $operationState = [string](Get-RecordValue $rollbackOperation 'State')
        $captureState = $captureById[$operationId]
        $afterState = Get-RecordValue $approvedOperation[0] 'After'
        $afterExists = Get-RecordValue $afterState 'Exists'
        $captureMatchesAfter = $false
        if ($null -eq $captureState -or $afterExists -isnot [bool]) {
            $rollbackResultMismatch += "Operation '$operationId' recovery state"
        }
        else {
            $approvedAfterState = [ordered]@{
                Exists = $afterExists
                Value = Get-RecordValue $afterState 'Value'
            }
            $captureMatchesAfter = (ConvertTo-CanonicalJson -InputObject $captureState) -ceq
                (ConvertTo-CanonicalJson -InputObject $approvedAfterState)
        }
        $applyJournalMatch = @((Get-RecordValue $apply 'Operation') | Where-Object {
                [string](Get-RecordValue $_ 'OperationId') -ceq $operationId
            })
        $applyOmittedAfterFailure = $applyReceiptBound -and $applyStatus -ceq 'Failed' -and $applyJournalMatch.Count -eq 0
        if ($operationState -ceq 'NotChangedByApply') {
            if (-not [string]::IsNullOrWhiteSpace([string](Get-RecordValue $rollbackOperation 'Fault'))) {
                $rollbackResultMismatch += "Operation '$operationId' Fault"
            }
            if (-not $captureMatchesAfter -and -not $applyOmittedAfterFailure) {
                $rollbackResultMismatch += "Operation '$operationId' NotChangedByApply contradicts the PreChange capture and Apply receipt"
            }
            continue
        }
        if ($operationState -cnotin @('Succeeded', 'Unchanged') -or
            [string](Get-RecordValue $rollbackOperation 'Command') -cne [string](Get-RecordValue $approvedOperation[0] 'Command') -or
            [string](Get-RecordValue $rollbackOperation 'Identity') -cne [string](Get-RecordValue $approvedOperation[0] 'Identity') -or
            [int](Get-RecordValue $rollbackOperation 'Sequence') -ne [int](Get-RecordValue $approvedOperation[0] 'Sequence') -or
            -not [string]::IsNullOrWhiteSpace([string](Get-RecordValue $rollbackOperation 'Fault'))) {
            $rollbackResultMismatch += "Operation '$operationId' journal"
        }
        if ($operationState -cin @('Succeeded', 'Unchanged') -and $captureMatchesAfter) {
            $rollbackResultMismatch += "Operation '$operationId' reports restoration although PreChange already matched the approved After state"
        }
        elseif ($operationState -cin @('Succeeded', 'Unchanged') -and $applyOmittedAfterFailure) {
            $rollbackResultMismatch += "Operation '$operationId' reports restoration although the bound failed Apply receipt omits it"
        }
    }
    foreach ($operation in $operations) {
        $operationId = [string](Get-RecordValue $operation 'OperationId')
        if ([string]::IsNullOrWhiteSpace($operationId) -or -not $rollbackOperationIds.Contains($operationId)) {
            $rollbackResultMismatch += 'Operation coverage'
        }
    }
    if ($rollbackResultMismatch.Count -gt 0) {
        foreach ($mismatch in @($rollbackResultMismatch | Select-Object -Unique)) {
            $rollbackErrors.Add("RollbackResultMismatch: $mismatch")
        }
    }
    else {
        $rollbackReceiptValid = $true
    }
}
if ($rollbackReceiptValid -and $null -ne $apply) {
    $applyCompleted = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse(
            [string](Get-RecordValue $apply 'CompletedOn'),
            [Globalization.CultureInfo]::InvariantCulture,
            $dateStyles,
            [ref]$applyCompleted
        ) -and $rollbackCompleted -lt $applyCompleted) {
        $rollbackErrors.Add('RollbackResultMismatch: CompletedOn predates the Apply receipt.')
    }
}
if ($rollbackReceiptValid) {
    foreach ($attempt in $rollbackAttempts) {
        $attemptCompleted = [datetimeoffset]::MinValue
        if (-not [datetimeoffset]::TryParse(
                [string](Get-RecordValue $attempt.Document 'CompletedOn'),
                [Globalization.CultureInfo]::InvariantCulture,
                $dateStyles,
                [ref]$attemptCompleted
            ) -or $attemptCompleted -ge $rollbackCompleted) {
            $rollbackErrors.Add('ChangeRollbackReceiptMismatch: a failed rollback attempt completed at or after the successful rollback result.')
            break
        }
    }
}
$rollbackMismatch = @($rollbackErrors.ToArray())
$rollbackStatus = if ($rollbackMismatch.Count -gt 0) { 'Invalid or incomplete' }
elseif ($rollbackReceiptValid) { 'Succeeded' }
elseif ($rollbackAttempts.Count -gt 0) { 'Failed attempts' }
else { 'Not performed' }
$rollbackOutcome = if ($rollbackMismatch.Count -gt 0) { 'RECOVERY INCOMPLETE' }
elseif ($rollbackReceiptValid) { 'ROLLED BACK' }
elseif ($rollbackAttempts.Count -gt 0) { 'RECOVERY INCOMPLETE' }
else { '' }
$preChangeMismatch = @()
if ($null -ne $prechange) {
    if ([string](Get-RecordValue $prechange 'ChangeId') -cne $ChangeId) { $preChangeMismatch += 'PreChange ChangeId' }
    $captureTenant = Get-TrimmedRecordValue $prechange 'Tenant'
    if ([string]::IsNullOrEmpty($captureTenant) -or $captureTenant -cne $previewTenant) { $preChangeMismatch += 'PreChange Tenant' }
    if ([string](Get-RecordValue $prechange 'Algorithm') -cne 'SHA256') { $preChangeMismatch += 'PreChange Algorithm' }
    $captureEntries = @(Get-RecordValue $prechange 'Entry' | Where-Object { $null -ne $_ })
    if ($captureEntries.Count -eq 0) {
        $preChangeMismatch += 'PreChange Entry'
    }
    else {
        $captureHash = [System.Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData(
                [System.Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-CanonicalJson -InputObject $captureEntries))
            )
        ).ToLowerInvariant()
        $sealedCaptureHash = [string](Get-RecordValue $prechange 'Hash')
        if ([string]::IsNullOrWhiteSpace($sealedCaptureHash) -or $sealedCaptureHash -cne $captureHash) {
            $preChangeMismatch += 'PreChange Hash'
        }
        $capturedIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($entry in $captureEntries) {
            $operationId = [string](Get-RecordValue $entry 'OperationId')
            if ([string]::IsNullOrWhiteSpace($operationId) -or -not $capturedIds.Add($operationId)) {
                $preChangeMismatch += 'PreChange Operations'
                break
            }
        }
        $previewIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($operation in $operations) {
            $operationId = [string](Get-RecordValue $operation 'OperationId')
            if (-not [string]::IsNullOrWhiteSpace($operationId)) { $null = $previewIds.Add($operationId) }
        }
        if ($capturedIds.Count -ne $previewIds.Count -or @($capturedIds | Where-Object { -not $previewIds.Contains($_) }).Count -gt 0) {
            $preChangeMismatch += 'PreChange Operations'
        }
    }
}
if ($rollbackReceiptValid -and $preChangeMismatch.Count -gt 0) {
    $rollbackErrors.Add('RollbackResultMismatch: the sealed PreChange capture is invalid for this approved change.')
    $rollbackMismatch = @($rollbackErrors.ToArray())
    $rollbackStatus = 'Invalid or incomplete'
    $rollbackOutcome = 'RECOVERY INCOMPLETE'
}
$applyOperations = @(Get-RecordValue $apply 'Operation' | Where-Object { $null -ne $_ })
$previewOperationIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$stateById = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
$operationMismatch = @()
if ($operations.Count -eq 0) {
    $operationMismatch += 'Preview contains no operations'
}
foreach ($operation in $operations) {
    $operationId = [string](Get-RecordValue $operation 'OperationId')
    if ([string]::IsNullOrWhiteSpace($operationId)) {
        $operationMismatch += 'Preview operation has no OperationId'
    }
    elseif (-not $previewOperationIds.Add($operationId)) {
        $operationMismatch += "Preview contains duplicate operation '$operationId'"
    }
}
foreach ($entry in $applyOperations) {
    $operationId = [string](Get-RecordValue $entry 'OperationId')
    if ([string]::IsNullOrWhiteSpace($operationId)) {
        $operationMismatch += 'Apply result has no OperationId'
        continue
    }
    if (-not $previewOperationIds.Contains($operationId)) {
        $operationMismatch += "Apply contains unexpected operation '$operationId'"
        continue
    }
    if ($stateById.ContainsKey($operationId)) {
        $operationMismatch += "Apply contains duplicate results for '$operationId'"
        $stateById[$operationId] = 'Duplicate results'
        continue
    }
    $stateById[$operationId] = [string](Get-RecordValue $entry 'State')
}
foreach ($operation in $operations) {
    $operationId = [string](Get-RecordValue $operation 'OperationId')
    if ([string]::IsNullOrWhiteSpace($operationId) -or -not $stateById.ContainsKey($operationId)) {
        if (-not [string]::IsNullOrWhiteSpace($operationId)) {
            $operationMismatch += "Apply has no result for '$operationId'"
        }
        continue
    }
    if ($stateById[$operationId] -cnotin @('Succeeded', 'Unchanged', 'Duplicate results')) {
        $operationMismatch += "Apply result for '$operationId' is not Succeeded or Unchanged"
    }
}
$artifactMismatch = @(
    if ($null -ne $preview -and [string](Get-RecordValue $preview 'ChangeId') -cne $ChangeId) { 'Preview ChangeId' }
    foreach ($name in 'Approval', 'Apply', 'PostChange') {
        $document = $documents[$name]
        if ($null -eq $document -or $null -eq $preview) { continue }
        if ([string](Get-RecordValue $document 'ChangeId') -cne $ChangeId) { "$($name) ChangeId" }
        $documentTenant = Get-TrimmedRecordValue $document 'Tenant'
        if ([string]::IsNullOrEmpty($documentTenant) -or $documentTenant -ne $previewTenant) { "$($name) Tenant" }
        if ([string](Get-RecordValue $document 'PreviewHash') -cne $previewSha256) { "$($name) PreviewHash" }
        if ($name -ne 'Approval') {
            $documentConfiguration = & $normalizeHash (Get-RecordValue $document 'ConfigurationHash')
            if ([string]::IsNullOrEmpty($documentConfiguration) -or $documentConfiguration -cne $previewConfiguration) { "$($name) ConfigurationHash" }
        }
    }
)

$complete = $missing.Count -eq 0 -and $documentMismatch.Count -eq 0 -and $applyStatus -eq 'Succeeded' -and $postStatus -eq 'Succeeded' -and
    -not $noEvidenceChecks -and $checkMismatch.Count -eq 0 -and $bindingMismatch.Count -eq 0 -and $artifactMismatch.Count -eq 0 -and
    $preChangeMismatch.Count -eq 0 -and $operationMismatch.Count -eq 0
$overall = if ($rollbackOutcome) { $rollbackOutcome }
elseif (-not $complete) { 'INCOMPLETE' }
elseif ($needsAttention.Count -gt 0) { 'APPLIED - CONTROLS NEED ATTENTION' }
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
Add-Line "| Rollback status | $(Format-Cell $rollbackStatus) |"
Add-Line "| Failed rollback attempts | $(Format-Cell $rollbackAttempts.Count) |"
Add-Line "| Rollback completed | $(Format-Cell (Get-RecordValue $rollbackResult 'CompletedOn')) |"
Add-Line "| Evidence collected | $(Format-Cell (Get-RecordValue $evidence 'CollectedAtUtc')) |"
Add-Line "| Configuration hash | $(Format-Cell (Get-RecordValue $preview 'ConfigurationHash')) |"
Add-Line "| Manifest hash | $(Format-Cell (Get-RecordValue $evidence 'ManifestHash')) |"
Add-Line "| Report written | $([datetimeoffset]::UtcNow.ToString('u')) |"
Add-Line

if ($rollbackMismatch.Count -gt 0) {
    Add-Line '## Recovery'
    Add-Line
    Add-Line 'Rollback was attempted but could not be confirmed. Do not treat the change as applied or restored.'
    foreach ($mismatch in $rollbackMismatch) { Add-Line "- $($mismatch)" }
    Add-Line
}
elseif ($rollbackOutcome -eq 'ROLLED BACK') {
    Add-Line '## Recovery'
    Add-Line
    Add-Line "A successful rollback receipt was validated at $(Format-Cell (Get-RecordValue $rollbackResult 'CompletedOn')); $($rollbackAttempts.Count) earlier failed attempt(s) were validated."
    Add-Line 'The evidence records below are retained for audit and do not establish the current tenant state after rollback.'
    Add-Line
}
elseif ($rollbackAttempts.Count -gt 0) {
    Add-Line '## Recovery'
    Add-Line
    Add-Line "Validated $($rollbackAttempts.Count) failed rollback attempt(s), but no successful rollback result exists."
    foreach ($attempt in $rollbackAttempts) {
        Add-Line "- $($attempt.Name): $([string](Get-RecordValue $attempt.Document 'Fault'))"
    }
    Add-Line
}

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
if ($checkMismatch.Count -gt 0) {
    Add-Line "Evidence control coverage does not match the ExchangeOnly manifest: $($checkMismatch -join '; '). Recollect the complete evidence set."
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
if ($documentMismatch.Count -gt 0) {
    Add-Line "These JSON documents are unreadable or do not have an object root: $($documentMismatch -join '; '). Rerun the stage that wrote each document; do not edit change artifacts by hand."
    Add-Line
}
if ($artifactMismatch.Count -gt 0) {
    Add-Line "These artifact fields do not belong to this change: $($artifactMismatch -join ', '). Each file must name this change and tenant and carry this preview's SHA-256. Do not rename or edit change artifacts; use the files the stages wrote for this change."
    Add-Line
}
if ($preChangeMismatch.Count -gt 0) {
    Add-Line "The PreChange recovery capture is invalid for this change: $($preChangeMismatch -join ', '). Use the sealed capture written by Apply; do not edit or rename recovery artifacts."
    Add-Line
}
if ($operationMismatch.Count -gt 0) {
    Add-Line "Apply operation results do not match the preview: $($operationMismatch -join '; ')."
    Add-Line
}

Add-Line '## Apply operations'
Add-Line
if ($operations.Count -eq 0) {
    Add-Line 'No preview operations were found.'
}
else {
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
if ($rollbackOutcome -eq 'ROLLED BACK') {
    Add-Line 'Evidence outcomes are retained for audit; they are not a current-state assessment after rollback.'
    Add-Line
}
Add-Line '| Status | Count |'
Add-Line '| --- | --- |'
foreach ($status in $statusCount.Keys) { Add-Line "| $($status) | $($statusCount[$status]) |" }
Add-Line
if ($noEvidenceChecks) {
    Add-Line 'No evidence checks were found; evidence collection is incomplete.'
}
elseif ($needsAttention.Count -eq 0) {
    Add-Line 'No unresolved checks; all results are Pass, ApprovedException, or NotApplicable.'
}
else {
    Add-Line '### Checks that need attention'
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
    $columns = @($items | ForEach-Object {
            if ($_ -is [System.Collections.IDictionary]) { $_.Keys } else { $_.PSObject.Properties.Name }
        } | Where-Object { $_ -notin 'Evidence', 'Detail' } | Select-Object -Unique)
    Add-Line "| $($columns -join ' | ') |"
    Add-Line "| $(($columns | ForEach-Object { '---' }) -join ' | ') |"
    foreach ($item in $items) {
        Add-Line "| $(($columns | ForEach-Object { Format-Cell (Get-RecordValue $item $_) }) -join ' | ') |"
    }
    Add-Line
}

Add-Line '## Next actions'
Add-Line
if ($rollbackOutcome -eq 'ROLLED BACK') {
    Add-Line '- The rollback receipt confirms restoration; do not use pre-rollback evidence to describe current tenant state.'
}
elseif ($rollbackOutcome -eq 'RECOVERY INCOMPLETE') {
    Add-Line '- Stop and verify the tenant state with the recovery owner; do not mark the change applied or restored.'
}
else {
    if ($missing.Count -gt 0) { Add-Line "- Locate or regenerate the missing artifacts: $($missing -join ', ')." }
    if ($documentMismatch.Count -gt 0) { Add-Line '- Rerun the stages that wrote unreadable or non-object JSON documents; do not edit artifacts by hand.' }
    if ($artifactMismatch.Count -gt 0) { Add-Line "- Replace the artifacts that belong to another change or preview: $($artifactMismatch -join ', ')." }
    if ($preChangeMismatch.Count -gt 0) { Add-Line '- Restore the original sealed PreChange capture from this Apply; do not edit or substitute it.' }
    if ($operationMismatch.Count -gt 0) { Add-Line '- Regenerate or correct the Apply receipt so it contains exactly one successful result for every preview operation.' }
    if ($bindingMismatch.Count -gt 0) { Add-Line "- Recollect evidence after apply for this change; $($bindingMismatch -join ', ') do not match the change record." }
    if ($applyStatus -ne 'Succeeded' -or $postStatus -ne 'Succeeded') { Add-Line '- Apply or post-change did not report Succeeded. Follow your recovery decision before closing.' }
    if ($noEvidenceChecks) { Add-Line '- Recollect evidence that includes the expected control check records; an empty check collection is not a passing result.' }
    if ($checkMismatch.Count -gt 0) { Add-Line '- Recollect evidence with exactly one result for every control in the shipped ExchangeOnly manifest.' }
    if ($needsAttention.Count -gt 0) { Add-Line "- Resolve or assign an owner to each of the $($needsAttention.Count) unresolved checks." }
}
Add-Line '- Attach this report and the whole artifact folder to the change ticket.'
Add-Line '- Disconnect: `Disconnect-ExchangeOnline -Confirm:$false`.'

$outputDirectory = Split-Path -Parent $outputFullPath
$null = New-Item -ItemType Directory -Path $outputDirectory -Force
[IO.File]::WriteAllText($outputFullPath, $md.ToString(), [Text.UTF8Encoding]::new($false))

$color = if ($overall -eq 'APPLIED - EVIDENCE COLLECTED') { $PSStyle.Foreground.Green }
elseif ($overall -eq 'ROLLED BACK' -or ($complete -and $overall -ne 'RECOVERY INCOMPLETE')) { $PSStyle.Foreground.Yellow }
else { $PSStyle.Foreground.Red }
Write-Information "$($color)$($overall)$($PSStyle.Reset)"
Write-Information "  Artifacts present: $(6 - $missing.Count) of 6$(if ($missing.Count) { " (missing: $($missing -join ', '))" })"
Write-Information "  Rollback: $rollbackStatus; failed attempts: $($rollbackAttempts.Count)"
if ($rollbackMismatch.Count -gt 0) { Write-Information "  Recovery findings: $($rollbackMismatch -join '; ')" }
if ($bindingMismatch.Count -gt 0) { Write-Information "  Evidence binding: $($bindingMismatch -join ', ') do not match the change record" }
if ($checkMismatch.Count -gt 0) { Write-Information "  Evidence control coverage: $($checkMismatch.Count) manifest mismatch(es)" }
if ($artifactMismatch.Count -gt 0) { Write-Information "  Artifact binding: $($artifactMismatch -join ', ') belong to another change or preview" }
Write-Information "  Evidence: $(($statusCount.Keys | Where-Object { $statusCount[$_] -gt 0 } | ForEach-Object { "$($_) $($statusCount[$_])" }) -join ', ')"
if ($noEvidenceChecks) { Write-Information '  Evidence checks: none found; collection is incomplete' }
Write-Information "  Report: $outputFullPath"

if ($PassThru) {
    [pscustomobject]@{
        Path            = $outputFullPath
        Outcome         = $overall
        Complete        = $complete
        RollbackStatus  = $rollbackStatus
        RollbackAttemptCount = $rollbackAttempts.Count
        RollbackMismatch = $rollbackMismatch
        RollbackCompletedOn = Get-RecordValue $rollbackResult 'CompletedOn'
        MissingArtifact = $missing
        BindingMismatch = $bindingMismatch
        CheckMismatch = $checkMismatch
        ArtifactMismatch = $artifactMismatch
        DocumentMismatch = $documentMismatch.ToArray()
        OperationMismatch = $operationMismatch
        PreChangeMismatch = $preChangeMismatch
        EvidenceCheckCount = $checks.Count
        StatusCount     = [pscustomobject]$statusCount
    }
}
