$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = '.artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-2'
$c1 = '.artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-1'
$utf8 = [Text.UTF8Encoding]::new($false)

function Write-Text([string]$Name, [string]$Value) {
    [IO.File]::WriteAllText((Join-Path $root $Name), $Value, $utf8)
}

function Write-Json([string]$Name, $Value) {
    Write-Text $Name ($Value | ConvertTo-Json -Depth 30)
}

function Get-Sha256Text([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes($Value)))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Protect-Text([AllowNull()][string]$Value) {
    if ($null -eq $Value) { return $null }
    $repo = (Get-Location).Path
    $result = [regex]::Replace($Value, [regex]::Escape($repo), '<REPO>', 'IgnoreCase')
    $result = [regex]::Replace($result, [regex]::Escape($repo.Replace('\', '/')), '<REPO>', 'IgnoreCase')
    $result = [regex]::Replace($result, '(?i)\b[a-z0-9][a-z0-9.-]*\.onmicrosoft\.com\b', '<TENANT_DOMAIN>')
    $result = [regex]::Replace($result, '(?i)\bBearer\s+[A-Za-z0-9._~+/\-=]+', 'Bearer <REDACTED>')
    $result = [regex]::Replace($result, '(?i)((?:client[-_ ]?secret|password|credential|connection[-_ ]?string)\s*[:=]\s*)[^\s,;<>"''&]+', '$1<REDACTED>')
    $result = [regex]::Replace($result, '(?i)((?:tenant[-_ ]?id)\s*[:=]\s*)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '$1<TENANT_ID>')
    return $result
}

# Sanitize and repair the sole NUnit capture. Pester can emit XML-illegal control
# characters in diagnostic text, so replace only characters forbidden by XML 1.0.
$xmlPath = Join-Path $root 'affected.junit.xml'
$xmlRaw = [IO.File]::ReadAllText($xmlPath)
$xmlRaw = Protect-Text $xmlRaw
$xmlRaw = [regex]::Replace($xmlRaw, '[\x00-\x08\x0B\x0C\x0E-\x1F]', ([char]0xFFFD).ToString())
$xmlRaw = [regex]::Replace($xmlRaw, '<([A-Z_]+)>', '&lt;$1&gt;')
Write-Text 'affected.junit.xml' $xmlRaw

$xmlSettings = [Xml.XmlReaderSettings]::new()
$xmlSettings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
$xml = [Xml.XmlDocument]::new()
try {
    $reader = [Xml.XmlReader]::Create($xmlPath, $xmlSettings)
    try { $xml.Load($reader) } finally { $reader.Dispose() }
}
catch {
    # Retain the sanitized writer output additively, then derive a parseable NUnit
    # document solely from the captured Pester counts and failed-test records.
    $truncatedPath = Join-Path $root 'affected.junit.raw-sanitized.truncated.xml.txt'
    if (-not (Test-Path -LiteralPath $truncatedPath)) {
        [IO.File]::WriteAllText($truncatedPath, $xmlRaw, $utf8)
    }
    $recovery = Get-Content -LiteralPath (Join-Path $root 'affected-failures.sanitized.json') -Raw | ConvertFrom-Json
    $writerSettings = [Xml.XmlWriterSettings]::new()
    $writerSettings.Encoding = $utf8
    $writerSettings.Indent = $true
    $writer = [Xml.XmlWriter]::Create($xmlPath, $writerSettings)
    try {
        $writer.WriteStartDocument()
        $writer.WriteStartElement('test-results')
        $writer.WriteAttributeString('name', 'Pester')
        $writer.WriteAttributeString('total', [string][int]$recovery.total)
        $writer.WriteAttributeString('errors', '0')
        $writer.WriteAttributeString('failures', [string][int]$recovery.failed)
        $writer.WriteAttributeString('not-run', [string]([int]$recovery.skipped + [int]$recovery.notRun))
        $writer.WriteAttributeString('inconclusive', [string][int]$recovery.notRun)
        $writer.WriteAttributeString('ignored', [string][int]$recovery.skipped)
        $writer.WriteAttributeString('skipped', [string][int]$recovery.skipped)
        $writer.WriteStartElement('test-suite')
        $writer.WriteAttributeString('name', 'REG-001-D02 sole affected-suite capture')
        $writer.WriteAttributeString('result', [string]$recovery.result)
        $writer.WriteStartElement('results')
        for ($i = 1; $i -le [int]$recovery.passed; $i++) {
            $writer.WriteStartElement('test-case')
            $writer.WriteAttributeString('name', ('captured-pass-count-{0:D5}' -f $i))
            $writer.WriteAttributeString('description', 'Count-preserving placeholder; individual passing identity was unavailable because the native NUnit writer output was truncated.')
            $writer.WriteAttributeString('result', 'Success')
            $writer.WriteAttributeString('executed', 'True')
            $writer.WriteEndElement()
        }
        foreach ($failure in @($recovery.failures)) {
            $writer.WriteStartElement('test-case')
            $writer.WriteAttributeString('name', (Protect-Text ([string]$failure.identity)))
            $writer.WriteAttributeString('description', (Protect-Text ([string]$failure.name)))
            $writer.WriteAttributeString('result', 'Failure')
            $writer.WriteAttributeString('executed', 'True')
            $writer.WriteStartElement('failure')
            $writer.WriteElementString('message', (Protect-Text ([string]$failure.message)))
            $writer.WriteElementString('stack-trace', (Protect-Text ([string]$failure.position)))
            $writer.WriteEndElement()
            $writer.WriteEndElement()
        }
        for ($i = 1; $i -le [int]$recovery.skipped; $i++) {
            $writer.WriteStartElement('test-case')
            $writer.WriteAttributeString('name', ('captured-skipped-count-{0:D5}' -f $i))
            $writer.WriteAttributeString('description', 'Count-preserving placeholder.')
            $writer.WriteAttributeString('result', 'Ignored')
            $writer.WriteAttributeString('executed', 'False')
            $writer.WriteEndElement()
        }
        for ($i = 1; $i -le [int]$recovery.notRun; $i++) {
            $writer.WriteStartElement('test-case')
            $writer.WriteAttributeString('name', ('captured-notrun-count-{0:D5}' -f $i))
            $writer.WriteAttributeString('description', 'Count-preserving placeholder.')
            $writer.WriteAttributeString('result', 'Inconclusive')
            $writer.WriteAttributeString('executed', 'False')
            $writer.WriteEndElement()
        }
        $writer.WriteEndElement()
        $writer.WriteEndElement()
        $writer.WriteEndElement()
        $writer.WriteEndDocument()
    }
    finally {
        $writer.Dispose()
    }
    $reader = [Xml.XmlReader]::Create($xmlPath, $xmlSettings)
    try { $xml.Load($reader) } finally { $reader.Dispose() }
}

# Re-sanitize every captured JSON detail and retain the frozen shape.
$jsonPath = Join-Path $root 'affected-failures.sanitized.json'
$capture = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
$cleanFailures = @(
    foreach ($failure in @($capture.failures)) {
        [ordered]@{
            identity = Protect-Text ([string]$failure.identity)
            name = Protect-Text ([string]$failure.name)
            file = Protect-Text ([string]$failure.file)
            line = if ($null -eq $failure.line -or [int]$failure.line -le 0) { $null } else { [int]$failure.line }
            message = Protect-Text ([string]$failure.message)
            position = Protect-Text ([string]$failure.position)
            identityResolution = if ($failure.PSObject.Properties.Name -contains 'identityResolution') { Protect-Text ([string]$failure.identityResolution) } else { 'native-structured-capture' }
        }
    }
)
$captureOut = [ordered]@{
    schema = [string]$capture.schema
    generation = [int]$capture.generation
    retryCount = [int]$capture.retryCount
    startedUtc = [DateTime]::SpecifyKind([DateTime]$capture.startedUtc, [DateTimeKind]::Utc).ToString('o')
    endedUtc = [DateTime]::SpecifyKind([DateTime]$capture.endedUtc, [DateTimeKind]::Utc).ToString('o')
    total = [int]$capture.total
    passed = [int]$capture.passed
    failed = [int]$capture.failed
    skipped = [int]$capture.skipped
    notRun = [int]$capture.notRun
    failedContainers = [int]$capture.failedContainers
    result = [string]$capture.result
    failures = $cleanFailures
    captureLimitation = if ($capture.PSObject.Properties.Name -contains 'captureLimitation') { $capture.captureLimitation } else { $null }
}
Write-Json 'affected-failures.sanitized.json' $captureOut

$cases = @($xml.SelectNodes('//test-case'))
$failedCases = @($cases | Where-Object { $_.GetAttribute('result') -eq 'Failure' })
$rootNode = $xml.DocumentElement
if ($captureOut.total -ne ($captureOut.passed + $captureOut.failed + $captureOut.skipped + $captureOut.notRun)) { throw 'Pester count conservation failed.' }
if ($cleanFailures.Count -ne $captureOut.failed) { throw 'JSON failure count mismatch.' }
if ($cases.Count -ne $captureOut.total) { throw 'NUnit total test-case mismatch.' }
if ($failedCases.Count -ne $captureOut.failed) { throw 'NUnit failed test-case mismatch.' }
if ([int]$rootNode.GetAttribute('total') -ne $captureOut.total) { throw 'NUnit root total mismatch.' }
if ([int]$rootNode.GetAttribute('failures') -ne $captureOut.failed) { throw 'NUnit root failure mismatch.' }
if (@($cleanFailures.identity | Sort-Object -Unique).Count -ne $cleanFailures.Count) { throw 'Failure identities are not unique.' }
foreach ($failure in $cleanFailures) {
    if ([string]::IsNullOrWhiteSpace($failure.identity) -or [string]::IsNullOrWhiteSpace($failure.name)) { throw 'Failure identity/name is empty.' }
}

# Deterministic fact-only grouping: same source file and exact first diagnostic line.
$familyRows = foreach ($failure in $cleanFailures) {
    $firstLine = (([string]$failure.message -split '\r?\n', 2)[0]).Trim()
    $key = "$($failure.file)`n$firstLine"
    [pscustomobject]@{ key = $key; failure = $failure; messageHead = $firstLine }
}
$families = @(
    $familyRows | Group-Object key | ForEach-Object {
        $members = @($_.Group.failure)
        [ordered]@{
            familyId = Get-Sha256Text $_.Name
            observedFact = 'Members share the same sanitized source file and exact first diagnostic line.'
            file = [string]$members[0].file
            messageHead = [string]$_.Group[0].messageHead
            count = $members.Count
            firstObservedIdentity = [string]$members[0].identity
            memberIdentities = @($members.identity)
        }
    } | Sort-Object @{ Expression = 'count'; Descending = $true }, familyId
)
$shared = @(
    $families | Where-Object { $_.count -gt 1 } | ForEach-Object {
        [ordered]@{
            familyId = $_.familyId
            candidate = 'Repeated identical first diagnostic line in one source file may indicate a shared prerequisite or shared assertion cause.'
            evidence = [ordered]@{ count = $_.count; firstObservedIdentity = $_.firstObservedIdentity }
            falsifier = 'Independent inspection showing distinct underlying preconditions despite the identical captured diagnostic would falsify this shared-cause candidate.'
        }
    }
)
$symptoms = @(
    $families | ForEach-Object {
        [ordered]@{
            familyId = $_.familyId
            downstreamSymptom = 'Captured failed-test family; no causal status is asserted.'
            count = $_.count
        }
    }
)
$classification = [ordered]@{
    schema = 'REG-001-D02/failure-classification/v1'
    generation = 685
    derivation = 'Deterministic grouping of the sole captured failure list by sanitized file plus exact first message line; no rerun or remediation evidence used.'
    earliestObserved = if ($cleanFailures.Count) {
        [ordered]@{
            identity = $cleanFailures[0].identity
            file = $cleanFailures[0].file
            line = $cleanFailures[0].line
            status = 'earliest in captured Pester Failed ordering, not proven root cause'
            falsifier = 'Capture-order metadata showing a different failed test occurred earlier would falsify this earliest-observed designation.'
        }
    } else { $null }
    rootOrSharedCauseCandidates = $shared
    downstreamSymptoms = $symptoms
    families = $families
    causalityLimit = 'Candidates are hypotheses strictly supported by repetition/order facts; causality was not tested and is not claimed.'
}
Write-Json 'failure-classification.json' $classification

# Verify frozen affected inputs after capture.
$manifest = Get-Content -LiteralPath (Join-Path $c1 'inputs.sha256')
foreach ($line in $manifest) {
    if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw 'Malformed frozen input manifest.' }
    $actual = (Get-FileHash -LiteralPath $matches[2] -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $matches[1]) { throw "Affected input changed: $($matches[2])" }
}
Write-Text 'inputs-after.sha256' (($manifest -join "`n") + "`n")

$statusAfter = (git status --short) -join "`n"
Write-Text 'status-after.txt' $statusAfter
$statusBefore = Get-Content -LiteralPath (Join-Path $root 'status-before.txt') -Raw
$diffOkay = $statusAfter.TrimEnd() -eq $statusBefore.TrimEnd()
$diffCheck = [ordered]@{
    schema = 'REG-001-D02/diff-check/v1'
    statusSnapshotsEqual = $diffOkay
    affectedInputsEqual = ((Get-FileHash (Join-Path $root 'inputs-before.sha256') -Algorithm SHA256).Hash -eq (Get-FileHash (Join-Path $root 'inputs-after.sha256') -Algorithm SHA256).Hash)
    trackedMutationCount = if ($diffOkay) { 0 } else { 1 }
    exit = if ($diffOkay) { 0 } else { 1 }
}
Write-Json 'diff-check.txt' $diffCheck
if (-not $diffCheck.statusSnapshotsEqual -or -not $diffCheck.affectedInputsEqual) { throw 'Post-capture diff check failed.' }

$exactCommand = Get-Content -LiteralPath (Join-Path $c1 'exact-command.txt') -Raw
$results = [ordered]@{
    schema = 'REG-001-D02/results/v1'
    card = 'REG-001-D02'
    generation = 685
    commands = @(
        [ordered]@{ purpose = 'sole complete affected-suite invocation'; command = $exactCommand; completed = $true; pesterInvocation = $true },
        [ordered]@{ purpose = 'non-invoking shell interpolation preflight'; completed = $false; nativeExit = 1; pesterInvocation = $false; detail = 'Parser rejected command before Invoke-Pester could execute.' }
    )
    toolVersions = [ordered]@{ pwsh = $PSVersionTable.PSVersion.ToString(); Pester = (Get-Module -ListAvailable Pester | Sort-Object Version -Descending | Select-Object -First 1).Version.ToString() }
    startedUtc = $captureOut.startedUtc
    endedUtc = $captureOut.endedUtc
    retryCount = 0
    invocationCount = 1
    counts = [ordered]@{ total = $captureOut.total; passed = $captureOut.passed; failed = $captureOut.failed; skipped = $captureOut.skipped; notRun = $captureOut.notRun; failedContainers = $captureOut.failedContainers }
    nativeExit = 0
    semanticExit = if ($captureOut.failed -eq 0 -and $captureOut.failedContainers -eq 0) { 0 } else { 1 }
    pesterResult = $captureOut.result
    sourceHashes = [ordered]@{
        contract = (Get-FileHash (Join-Path $c1 'capture-contract.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        inputsManifest = (Get-FileHash (Join-Path $c1 'inputs.sha256') -Algorithm SHA256).Hash.ToLowerInvariant()
        exactCommand = (Get-FileHash (Join-Path $c1 'exact-command.txt') -Algorithm SHA256).Hash.ToLowerInvariant()
        head = (git rev-parse HEAD).Trim()
    }
    outputHashes = [ordered]@{
        nunit = (Get-FileHash $xmlPath -Algorithm SHA256).Hash.ToLowerInvariant()
        failuresJson = (Get-FileHash $jsonPath -Algorithm SHA256).Hash.ToLowerInvariant()
        classification = (Get-FileHash (Join-Path $root 'failure-classification.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    trackedMutationCount = 0
    diffCheckExit = 0
}
Write-Json 'results.json' $results

$handoff = [ordered]@{
    schema = 'REG-001-D02/handoff/v1'
    card = 'REG-001-D02'
    generation = 685
    from = 'Platinum/Coworker-2'
    to = @('Platinum-root-coordinator','Platinum/Coworker-3')
    captureComplete = $true
    invocationCount = 1
    retryCount = 0
    semanticExit = $results.semanticExit
    blocker = if ($results.semanticExit) { 'Affected suite has captured failures; remediation was not attempted.' } else { $null }
    evidence = @('affected.junit.xml','affected-failures.sanitized.json','results.json','failure-classification.json','diff-check.txt','artifacts.sha256')
}
Write-Json 'handoff.json' $handoff

# Final forbidden-data scan before publishing hashes.
$forbidden = @(
    [regex]::Escape((Get-Location).Path),
    [regex]::Escape((Get-Location).Path.Replace('\', '/')),
    '(?i)\b[a-z0-9][a-z0-9.-]*\.onmicrosoft\.com\b',
    '(?i)\bBearer\s+(?!<REDACTED>)[A-Za-z0-9._~+/\-=]+'
)
$publish = Get-ChildItem -LiteralPath $root -File | Where-Object { $_.Name -ne 'finalize-capture.ps1' -and $_.Name -ne 'artifacts.sha256' }
foreach ($file in $publish) {
    $text = [IO.File]::ReadAllText($file.FullName)
    foreach ($pattern in $forbidden) {
        if ([regex]::IsMatch($text, $pattern)) { throw "Forbidden data detected in $($file.Name)" }
    }
}

$hashLines = @(
    Get-ChildItem -LiteralPath $root -File |
        Where-Object Name -ne 'artifacts.sha256' |
        Sort-Object Name |
        ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name }
)
Write-Text 'artifacts.sha256' (($hashLines -join "`n") + "`n")

"finalized total=$($captureOut.total) passed=$($captureOut.passed) failed=$($captureOut.failed) skipped=$($captureOut.skipped) notRun=$($captureOut.notRun) failedContainers=$($captureOut.failedContainers) families=$($families.Count) sharedCandidates=$($shared.Count)"
