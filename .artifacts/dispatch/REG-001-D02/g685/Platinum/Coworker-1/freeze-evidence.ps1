$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$evidenceRoot = Join-Path (Get-Location) '.artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-1'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$writeText = {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, $utf8NoBom)
}
$writeJson = {
    param([string]$Path, $Value)
    & $writeText $Path ($Value | ConvertTo-Json -Depth 20)
}
$sha256Text = {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($sha.ComputeHash($utf8NoBom.GetBytes($Text)))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

New-Item -ItemType Directory -Force -Path $evidenceRoot | Out-Null

$backlogLine = Select-String -LiteralPath '.github/backlog.md' -Pattern '^- Exact command, owned solely by Platinum/Coworker-2' |
    Select-Object -First 1 -ExpandProperty Line
if (-not $backlogLine) { throw 'Canonical REG-001-D02 command line was not found.' }
$tick = [char]96
$commandStart = $backlogLine.IndexOf("$tick" + 'pwsh -NoProfile -Command ')
$commandEnd = $backlogLine.LastIndexOf($tick)
if ($commandStart -lt 0 -or $commandEnd -le $commandStart) { throw 'Canonical command delimiters were not found.' }
$exactCommand = $backlogLine.Substring($commandStart + 1, $commandEnd - $commandStart - 1)
$exactCommandHash = & $sha256Text $exactCommand
& $writeText (Join-Path $evidenceRoot 'exact-command.txt') $exactCommand

$head = (git rev-parse HEAD).Trim()
$branch = (git branch --show-current).Trim()
$pwshVersion = $PSVersionTable.PSVersion.ToString()
$pesterVersion = (Get-Module -ListAvailable Pester | Sort-Object Version -Descending | Select-Object -First 1).Version.ToString()
$tokenHash = 'fdcdbabd876d6eb8b76dd30ff9819e1eeea9009903c984e8ff8ae8922574c3bc'

$claim = [ordered]@{
    schema = 'REG-001-D02/claim/v1'
    card = 'REG-001-D02'
    generation = 685
    cohort = 'Platinum'
    role = 'Coworker-1'
    responsibility = 'diagnostic assertion/capture-contract owner'
    phase = 1
    run = 'Platinum-20261002T135932Z-g684-resume'
    ack = 'Platinum-root-coordinator/Kanban/g685/add-claim-REG-001-D02-retry-zero-capture'
    tokenSha256 = $tokenHash
    repositoryHead = $head
    branchObservedReadOnly = $branch
    writableRoot = '.artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-1/'
    captureOwner = 'Platinum/Coworker-2'
    verifier = 'Platinum/Coworker-3'
    invocationAllowance = [ordered]@{ pesterInvocations = 1; retryCount = 0; owner = 'Platinum/Coworker-2' }
    trackedPathsWritable = @()
    prohibitions = @(
        'C1 must not invoke Pester',
        'No tracked mutation',
        'No board, registry, governance, product, documentation, or test edit',
        'No live, network, credential, provisioning, destructive, remediation, branch, worktree, commit, or push action'
    )
    canonicalCommandSha256 = $exactCommandHash
}
& $writeJson (Join-Path $evidenceRoot 'claim.json') $claim

$contract = [ordered]@{
    schema = 'REG-001-D02/capture-contract/v1'
    card = 'REG-001-D02'
    generation = 685
    canonicalCommand = [ordered]@{
        file = 'exact-command.txt'
        sha256 = $exactCommandHash
        invocationOwner = 'Platinum/Coworker-2'
        invocationCount = 1
        retryCount = 0
        pesterPath = 'samples/contoso-exchange-online-managed-service/tests'
        outputVerbosity = 'Detailed'
        pesterPassThru = $true
        pesterRunExit = $false
        nunitOutput = '.artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-2/affected.junit.xml'
        jsonOutput = '.artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-2/affected-failures.sanitized.json'
    }
    frozenEnvironment = [ordered]@{
        head = $head
        pwsh = $pwshVersion
        pester = $pesterVersion
        trackedAffectedInputManifest = 'inputs.sha256'
        allTrackedStateManifest = 'tracked-state-before.sha256'
        statusSnapshot = 'status-before.txt'
    }
    requiredCaptureArtifacts = @(
        'affected.junit.xml',
        'affected-failures.sanitized.json',
        'results.json',
        'status-before.txt',
        'status-after.txt',
        'diff-check.txt',
        'inputs-before.sha256',
        'inputs-after.sha256',
        'artifacts.sha256'
    )
    affectedJson = [ordered]@{
        schema = 'REG-001-D02/v1'
        requiredTopLevel = @('schema','generation','retryCount','startedUtc','endedUtc','total','passed','failed','skipped','notRun','failedContainers','result','failures')
        constants = [ordered]@{ generation = 685; retryCount = 0 }
        time = [ordered]@{
            startedUtc = 'nonempty ISO-8601 UTC with Z designator'
            endedUtc = 'nonempty ISO-8601 UTC with Z designator'
            ordering = 'endedUtc >= startedUtc'
        }
        integerFields = @('total','passed','failed','skipped','notRun','failedContainers','retryCount')
        conservation = @(
            'total = passed + failed + skipped + notRun',
            'failures.Count = failed',
            'failedContainers equals Pester FailedContainers.Count',
            'failed equals NUnit failed test-case count',
            'total equals NUnit total test-case count under the same Pester invocation'
        )
        failedTestRequiredFields = @('identity','name','file','line','message','position')
        failedTestAssertions = @(
            'exactly one JSON entry exists for every Pester failed test',
            'identity is nonempty and unique within failures',
            'name is nonempty',
            'file is repo-relative or begins with <REPO> and contains no absolute repository path',
            'line is a positive integer when available, otherwise a JSON null is explicit',
            'message and position keys always exist; available detail is nonempty',
            'identity/name/file/line/message/position map one-to-one to the corresponding failed NUnit/Pester test'
        )
    }
    nunitXml = [ordered]@{
        format = 'NUnitXml'
        parseable = $true
        requiredAssertions = @(
            'XML parser loads without recovery or parse error',
            'test-case totals and outcomes reconcile to JSON total/passed/failed/skipped/notRun',
            'failed test-case count equals JSON failed and JSON failures.Count',
            'failed-container count is retained separately in JSON and results.json',
            'each failed test-case has one corresponding JSON identity/detail record'
        )
    }
    resultsJson = [ordered]@{
        requiredFields = @(
            'schema','card','generation','commands','toolVersions','startedUtc','endedUtc',
            'retryCount','invocationCount','counts','nativeExit','semanticExit','pesterResult',
            'sourceHashes','outputHashes','trackedMutationCount','diffCheckExit'
        )
        countsRequired = @('total','passed','failed','skipped','notRun','failedContainers')
        exitContract = [ordered]@{
            nativeExit = 'integer process exit from the sole pwsh capture process'
            semanticExit = 'integer derived from Pester result/counts; 0 only when no failed tests or failed containers, otherwise nonzero'
            pesterResult = 'exact string from Pester Run result'
            note = 'Run.Exit=false means nativeExit and semanticExit are distinct and both are mandatory'
        }
        toolVersionsRequired = @('pwsh','Pester')
        sourceHashes = 'Must byte-match C1 inputs.sha256 before and after capture.'
    }
    sanitization = [ordered]@{
        appliesTo = @('affected.junit.xml','affected-failures.sanitized.json','results.json','status-before.txt','status-after.txt','diff-check.txt')
        forbidden = @(
            'absolute repository root or any case/slash variant',
            'credentials, passwords, client secrets, bearer values, private keys, or connection strings',
            'allocation token literal or captured authentication/session token',
            'tenant IDs or tenant-identifying domains such as *.onmicrosoft.com',
            'unsanitized live output'
        )
        allowedPathForms = @('repository-relative path','<REPO>-prefixed sanitized path')
        responseToDetection = 'Stop handling; quarantine outside canonical evidence pending sanitization; do not publish contaminated bytes.'
    }
    immutability = [ordered]@{
        beforeAfterTrackedHashesEqual = $true
        inputsBeforeAfterEqual = $true
        trackedMutationCount = 0
        noNewTrackedMutation = $true
        diffCheckExit = 0
        preservePreExistingWorkingTreeState = $true
    }
    acceptanceAssertions = @(
        'exact command SHA-256 equals frozen canonicalCommand.sha256',
        'one and only one Pester invocation by C2; retryCount=0',
        'both XML and JSON parse successfully',
        'total=passed+failed+skipped+notRun',
        'failures.Count=failed=NUnit failed test-case count',
        'failedContainers is present and reconciles to the Pester result',
        'each failure preserves identity/name/file/line/message/position with sanitization',
        'start/end UTC, tool versions, native exit, semantic exit, source hashes, and output hashes are retained',
        'no secrets, tenant identifiers, allocation/auth tokens, or absolute repository paths occur',
        'all tracked hashes remain stable and there are zero new tracked mutations'
    )
}
& $writeJson (Join-Path $evidenceRoot 'capture-contract.json') $contract

$affectedTracked = @(git ls-files 'samples/contoso-exchange-online-managed-service/**') | Sort-Object
$affectedHashLines = foreach ($relative in $affectedTracked) {
    $hash = (Get-FileHash -LiteralPath $relative -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $($relative.Replace('\','/'))"
}
& $writeText (Join-Path $evidenceRoot 'inputs.sha256') (($affectedHashLines -join "`n") + "`n")

$allTracked = @(git ls-files) | Sort-Object
$allTrackedHashLines = foreach ($relative in $allTracked) {
    $hash = (Get-FileHash -LiteralPath $relative -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $($relative.Replace('\','/'))"
}
& $writeText (Join-Path $evidenceRoot 'tracked-state-before.sha256') (($allTrackedHashLines -join "`n") + "`n")

$status = @(git status --short) -join "`n"
& $writeText (Join-Path $evidenceRoot 'status-before.txt') ($status + "`n")

$commands = [ordered]@{
    schema = 'REG-001-D02/commands/v1'
    note = 'No command in this packet invokes Pester. View-tool reads are not shell invocations.'
    commands = @(
        "Get-ChildItem -Force | Select-Object Name,Mode; Get-ChildItem -Recurse -File -Force | Where-Object { `$_.Name -match 'manifest|REG-001-D02' -or `$_.FullName -match 'REG-001-D02' } | Select-Object -ExpandProperty FullName",
        "git status --short; git ls-files | Select-String -Pattern 'manifest|\.psd1`$|Pester|Tests|tests' | ForEach-Object { `$_.Line }",
        "Select-String -Path .github\backlog.md,.github\cohorts.md,.github\kanban.md -Pattern 'REG-001-D02' -Context 3,8 | ForEach-Object { `"--- `$(`$_.Path):`$(`$_.LineNumber)`"; `$_.Context.PreContext; `$_.Line; `$_.Context.PostContext }",
        "Get-ChildItem .artifacts\dispatch -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { `$_.Name -in @('claim.json','inputs.sha256','results.json','handoff.json') } | Select-Object -Last 20 -ExpandProperty FullName",
        "Select-String -Path .github\*.md,.github\*.ps1 -Pattern 'Invoke-Pester.*affected|affected command|repository-standard|NUnitXml|OutputFormat|CI.ps1' -Context 2,3 | Select-Object -First 100 | ForEach-Object { `"--- `$(`$_.Path):`$(`$_.LineNumber)`"; `$_.Context.PreContext; `$_.Line; `$_.Context.PostContext }",
        "Get-ChildItem samples\contoso-exchange-online-managed-service\tests -Force | Select-Object Name,Mode; Get-ChildItem samples\contoso-exchange-online-managed-service -File -Force | Select-Object Name",
        "Select-String -Path .github\backlog.md,.github\cohorts.md -Pattern '^\| REG-001-D02 |REG-001-D02.*(?:Invoke-Pester|Path|C1|C2|C3|Platinum)|Platinum.*REG-001-D02' | ForEach-Object { `"`$(`$_.Path):`$(`$_.LineNumber): `$(`$_.Line)`" }",
        "Get-ChildItem .artifacts\dispatch -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { `$_.FullName -match 'REG-001-D0[01]|REG-001' } | Select-Object FullName,Length | Format-Table -AutoSize | Out-String -Width 400",
        "Select-String -Path .github\backlog.md,.github\cohorts.md -Pattern 'NUnitXml|OutputFormat|affected\.xml|affected\.json|Invoke-Pester -Path ''samples/contoso-exchange-online-managed-service/tests''' | ForEach-Object { `"`$(`$_.Path):`$(`$_.LineNumber): `$(`$_.Line)`" } | Select-Object -Last 30",
        "`$files = @('.github/backlog.md','.github/cohorts.md','.github/kanban.md','.github/validate-dispatch-board.ps1'); foreach (`$f in `$files) { `$h=(Get-FileHash -Algorithm SHA256 `$f).Hash.ToLowerInvariant(); `"`$h  `$f`" }; git status --porcelain=v1",
        "`$head=git rev-parse HEAD; `$branch=git branch --show-current; `$ps=`$PSVersionTable.PSVersion.ToString(); `$pester=(Get-Module -ListAvailable Pester | Sort-Object Version -Descending | Select-Object -First 1).Version.ToString(); `"HEAD=`$head``nBRANCH=`$branch``nPWSH=`$ps``nPESTER=`$pester`"; git diff --name-only; git ls-files --others --exclude-standard",
        "`$root=(Get-Location).Path; `$tracked=@(git ls-files); `"tracked=`$(`$tracked.Count)`"; `"tests=`$(@(`$tracked | Where-Object { `$_ -like 'samples/contoso-exchange-online-managed-service/tests/*' }).Count)`"; `"sources=`$(@(`$tracked | Where-Object { `$_ -like 'samples/contoso-exchange-online-managed-service/*' }).Count)`"",
        "pwsh -NoProfile -File .artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-1/freeze-evidence.ps1",
        "pwsh -NoProfile -Command `"`$ErrorActionPreference='Stop'; `$root='.artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-1'; Get-ChildItem `$root -File | Sort-Object Name | ForEach-Object { '`{0}  {1}' -f (Get-FileHash `$_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), `$_.Name }; Get-Content (Join-Path `$root 'claim.json') -Raw | ConvertFrom-Json | Out-Null; Get-Content (Join-Path `$root 'capture-contract.json') -Raw | ConvertFrom-Json | Out-Null; if ((git diff --name-only -- . ':!.artifacts') -join '|' -ne '.github/backlog.md|.github/cohorts.md|.github/kanban.md|.github/validate-dispatch-board.ps1') { throw 'Unexpected tracked mutation set' }`"",
        "pwsh -NoProfile -File .artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-1/freeze-evidence.ps1",
        "pwsh -NoProfile -Command `"`$ErrorActionPreference='Stop'; `$root='.artifacts/dispatch/REG-001-D02/g685/Platinum/Coworker-1'; Get-ChildItem `$root -File | Sort-Object Name | ForEach-Object { '`{0}  {1}' -f (Get-FileHash `$_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), `$_.Name }; Get-Content (Join-Path `$root 'claim.json') -Raw | ConvertFrom-Json | Out-Null; Get-Content (Join-Path `$root 'capture-contract.json') -Raw | ConvertFrom-Json | Out-Null; if ((git diff --name-only -- . ':!.artifacts') -join '|' -ne '.github/backlog.md|.github/cohorts.md|.github/kanban.md|.github/validate-dispatch-board.ps1') { throw 'Unexpected tracked mutation set' }`""
    )
}
& $writeJson (Join-Path $evidenceRoot 'commands-executed.json') $commands

$summary = [ordered]@{
    schema = 'REG-001-D02/freeze-summary/v1'
    frozenAtUtc = [DateTime]::UtcNow.ToString('o')
    head = $head
    pwsh = $pwshVersion
    pester = $pesterVersion
    affectedTrackedInputCount = $affectedTracked.Count
    allTrackedFileCount = $allTracked.Count
    exactCommandSha256 = $exactCommandHash
    pesterInvocationsByC1 = 0
    expectedC2PesterInvocations = 1
    retryCount = 0
}
& $writeJson (Join-Path $evidenceRoot 'freeze-summary.json') $summary

$artifactLines = Get-ChildItem -LiteralPath $evidenceRoot -File |
    Where-Object Name -ne 'artifacts.sha256' |
    Sort-Object Name |
    ForEach-Object {
        '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name
    }
& $writeText (Join-Path $evidenceRoot 'artifacts.sha256') (($artifactLines -join "`n") + "`n")
