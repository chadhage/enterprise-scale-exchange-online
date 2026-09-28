#requires -Version 7.0

$RequiredAtomicFields = @(
    @{ Name = 'Status'; Label = 'Status'; Expected = 'AtomicFieldMissing:Status*' }
    @{ Name = 'Rank'; Label = 'Rank'; Expected = 'AtomicFieldMissing:Rank*' }
    @{ Name = 'Dependencies'; Label = 'Dependencies'; Expected = 'AtomicFieldMissing:Dependencies*' }
    @{ Name = 'Accountability'; Label = 'Accountable owner or external gate'; Expected = 'AtomicFieldMissing:Accountability*' }
    @{ Name = 'Surface'; Label = 'Bounded writable/read-only surface'; Expected = 'AtomicFieldMissing:Surface*' }
    @{ Name = 'NegativeCases'; Label = 'Explicit negative cases'; Expected = 'AtomicFieldMissing:NegativeCases*' }
    @{ Name = 'PositiveCase'; Label = 'Positive behavioral case'; Expected = 'AtomicFieldMissing:PositiveCase*' }
    @{ Name = 'FocusedVerification'; Label = 'Focused command and count'; Expected = 'AtomicFieldMissing:FocusedVerification*' }
    @{ Name = 'AffectedValidation'; Label = 'Affected validation'; Expected = 'AtomicFieldMissing:AffectedValidation*' }
    @{ Name = 'ReviewerEvidence'; Label = 'Required reviewer and evidence root'; Expected = 'AtomicFieldMissing:ReviewerEvidence*' }
    @{ Name = 'ClosureEvidence'; Label = 'Closure evidence'; Expected = 'AtomicFieldMissing:ClosureEvidence*' }
)

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:ValidatorPath = Join-Path $script:SampleRoot 'scripts' 'Test-BacklogAtomicity.ps1'
    $script:ActualBacklogPath = Join-Path (Split-Path -Parent (Split-Path -Parent $script:SampleRoot)) '.github' 'backlog.md'

    function New-BacklogAtomicityFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Name,

            [string]$OmitField,

            [switch]$OmitId,

            [switch]$DuplicateId,

            [switch]$UnresolvedInventory,

            [switch]$CountSummaryAsExecutable,

            [switch]$MakeLeafSummaryOnly,

            [switch]$UnsafeDependencies,

            [switch]$MultiplePositiveDeclarations,

            [switch]$WeakFocusedVerification,

            [switch]$UnknownDependency,

            [switch]$DependencyCycle,

            [switch]$UnknownInventoryCard,

            [switch]$HistoricalMetadata
        )

        $field = [ordered]@{
            Status = 'To Do'
            Rank = '900.1'
            Dependencies = if ($UnsafeDependencies) {
                'EXR-900-A01'
            }
            elseif ($UnknownDependency) {
                'EXR-999-A01'
            }
            elseif ($DependencyCycle) {
                'EXR-900-A02'
            }
            else {
                'None'
            }
            'Accountable owner or external gate' = 'Owner: Cohort Fixture'
            'Bounded writable/read-only surface' = 'Writable: tests/unit/BacklogAtomicity.Tests.ps1; read-only: .github/backlog.md'
            'Explicit negative cases' = 'missing input; malformed card; unsafe dependency'
            'Positive behavioral case' = 'exactly one frozen canonical fixture'
            'Focused command and count' = if ($WeakFocusedVerification) {
                "Invoke-Pester -Path 'tests/unit/BacklogAtomicity.Tests.ps1'"
            }
            else {
                "Invoke-Pester -Path 'tests/unit/BacklogAtomicity.Tests.ps1'; expected 1; deterministic red discovery: validator absent"
            }
            'Affected validation' = 'focused unit validation followed by the offline affected suite'
            'Required reviewer and evidence root' = 'Reviewer: Independent Fixture Reviewer; root: evidence/exr-900-a01'
            'Closure evidence' = 'field report, counts, exits, hashes, and diff identity'
        }

        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add('# Exchange Online Remediation Backlog')
        $lines.Add('')
        $executableCount = if ($CountSummaryAsExecutable -or $DependencyCycle) { 2 } else { 1 }
        $lines.Add("Canonical generation: 900. Updated: 2026-09-27. Executable cards: $executableCount; To Do $executableCount, In Progress 0, Done 0; 1 summary parents excluded.")
        $lines.Add('')
        $lines.Add('### Missing-Field Inventory')
        $lines.Add('')
        $lines.Add('| Card | Exact missing information |')
        $lines.Add('| --- | --- |')
        if ($UnresolvedInventory) {
            $lines.Add('| EXR-900-A01 | Required reviewer identity remains unresolved. |')
        }
        elseif ($UnknownInventoryCard) {
            $lines.Add('| EXR-999-A01 | Required field remains unresolved for an unknown or non-executable card. |')
        }
        else {
            $lines.Add('| None | None; every executable card is complete. |')
        }
        $lines.Add('')
        $lines.Add('## Force-Ranked Work')
        $lines.Add('')
        $lines.Add('### EXR-900')
        $lines.Add('')
        $lines.Add('Parent summary - Frozen production-format fixture.')
        $lines.Add('')
        $lines.Add('- Dependencies: terminal leaf EXR-900-A01. Owner: unassigned summary. Workstream: Fixture. Updated: 2026-09-27. Status: excluded summary.')
        $lines.Add('')
        $lines.Add($(if ($OmitId) { '###' } else { '### EXR-900-A01' }))
        $lines.Add('')
        if ($MakeLeafSummaryOnly) {
            $lines.Add('Non-executable summary - Atomic leaf incorrectly marked as a summary.')
        }
        elseif ($OmitField -eq 'Rank') {
            $lines.Add('Atomic executable production-format fixture leaf with its rank omitted.')
        }
        else {
            $lines.Add('Rank 900.1 - Atomic executable production-format fixture leaf.')
        }
        $lines.Add('')

        $metadata = [System.Collections.Generic.List[string]]::new()
        if ($OmitField -ne 'Dependencies') {
            $metadata.Add("Dependencies: $($field.Dependencies)")
        }
        if ($OmitField -ne 'Accountable owner or external gate') {
            $metadata.Add('Owner: Cohort Fixture')
        }
        $metadata.Add('Workstream: Fixture')
        $metadata.Add('Updated: 2026-09-27')
        if ($OmitField -ne 'Status') {
            $metadata.Add("Status: $($field.Status)")
        }
        $lines.Add("- $($metadata -join '. ').")

        foreach ($entry in $field.GetEnumerator()) {
            if ($entry.Key -eq $OmitField -or
                $entry.Key -in @('Status', 'Rank', 'Dependencies', 'Accountable owner or external gate')) {
                continue
            }
            $lines.Add("- $($entry.Key): $($entry.Value)")
            if ($MultiplePositiveDeclarations -and $entry.Key -eq 'Positive behavioral case') {
                $lines.Add('- Positive behavioral case: a second declaration that violates single-positive scope')
            }
        }

        if ($DependencyCycle) {
            $lines.Add('')
            $lines.Add('### EXR-900-A02')
            $lines.Add('')
            $lines.Add('Rank 900.2 - Second executable production-format fixture leaf for a non-self dependency cycle.')
            $lines.Add('')
            $lines.Add('- Dependencies: EXR-900-A01. Owner: Cohort Fixture. Workstream: Fixture. Updated: 2026-09-27. Status: To Do.')
            $lines.Add('- Accountable owner or external gate: Owner: Cohort Fixture')
            $lines.Add('- Bounded writable/read-only surface: Writable: tests/unit/BacklogAtomicity.Tests.ps1; read-only: .github/backlog.md')
            $lines.Add('- Explicit negative cases: dependency cycle')
            $lines.Add('- Positive behavioral case: exactly one frozen canonical fixture')
            $lines.Add("- Focused command and count: Invoke-Pester -Path 'tests/unit/BacklogAtomicity.Tests.ps1'; expected 1; deterministic red discovery: validator absent")
            $lines.Add('- Affected validation: focused unit validation followed by the offline affected suite')
            $lines.Add('- Required reviewer and evidence root: Reviewer: Independent Fixture Reviewer; root: evidence/exr-900-a02')
            $lines.Add('- Closure evidence: field report, counts, exits, hashes, and diff identity')
        }

        if ($DuplicateId) {
            $lines.Add('')
            $lines.Add('### EXR-900-A01')
            $lines.Add('')
            $lines.Add('Parent summary - Duplicate identity that must not be accepted.')
            $lines.Add('')
            $lines.Add('- Dependencies: terminal leaf EXR-900-A01. Owner: unassigned summary. Workstream: Fixture. Updated: 2026-09-27. Status: excluded summary.')
        }

        if ($HistoricalMetadata) {
            $lines.Add('')
            $lines.Add('## Historical generation/prose')
            $lines.Add('')
            $lines.Add('Historical generation: 899. Executable cards: 77; To Do 77, In Progress 0, Done 0.')
            $lines.Add('Archived prose only: ### EXR-899-A77 - Card type: Executable - Status: To Do.')
        }

        $path = Join-Path $TestDrive "$Name.md"
        Set-Content -LiteralPath $path -Value $lines -Encoding utf8
        return $path
    }
}

Describe 'EXR-018-A02 canonical backlog atomicity validator' {

    Context 'Negative: a required atomic-card field is absent' {

        It "rejects an executable card missing <Name>" -ForEach $RequiredAtomicFields {
            # Arrange
            $backlogPath = New-BacklogAtomicityFixture -Name "missing-$Name" -OmitField $Label

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $backlogPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage $Expected -Because "every executable card requires the $Name field"
        }

        It 'rejects an executable card whose heading omits its required ID' {
            # Arrange
            $backlogPath = New-BacklogAtomicityFixture -Name 'missing-id' -OmitId

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $backlogPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'AtomicFieldMissing:Id*' -Because 'every executable card requires an explicit canonical ID'
        }
    }

    Context 'Negative: canonical card identity and inventory are unresolved' {

        It 'rejects duplicate canonical card IDs' {
            # Arrange
            $backlogPath = New-BacklogAtomicityFixture -Name 'duplicate-id' -DuplicateId

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $backlogPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'AtomicCardIdDuplicate:EXR-900-A01*' -Because 'canonical executable and summary identities must be unique'
        }

        It 'rejects a Missing-Field Inventory entry that remains unresolved' {
            # Arrange
            $backlogPath = New-BacklogAtomicityFixture -Name 'unresolved-inventory' -UnresolvedInventory

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $backlogPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MissingFieldInventoryUnresolved:EXR-900-A01*' -Because 'an execution-ready card cannot retain unresolved required information'
        }

        It 'rejects a Missing-Field Inventory row naming an unknown or non-executable card' {
            # Arrange
            $backlogPath = New-BacklogAtomicityFixture -Name 'unknown-inventory-card' -UnknownInventoryCard

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $backlogPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MissingFieldInventoryCardUnknown:EXR-999-A01*' -Because 'inventory rows must resolve to a current executable card'
        }
    }

    Context 'Negative: executable and summary classification is inconsistent' {

        It 'rejects an executable count that includes a summary parent' {
            # Arrange
            $backlogPath = New-BacklogAtomicityFixture -Name 'summary-counted' -CountSummaryAsExecutable

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $backlogPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'SummaryCountedAsExecutable:EXR-900*' -Because 'summary parents must be excluded from executable totals'
        }

        It 'rejects an executable leaf classified as summary-only' {
            # Arrange
            $backlogPath = New-BacklogAtomicityFixture -Name 'leaf-summary-only' -MakeLeafSummaryOnly

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $backlogPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ExecutableLeafSummaryOnly:EXR-900-A01*' -Because 'an atomic leaf cannot evade executable validation by being labelled as a summary'
        }

        It 'rejects multiple positive behavioral declarations for one executable unit' {
            # Arrange
            $backlogPath = New-BacklogAtomicityFixture -Name 'multiple-positive-declarations' -MultiplePositiveDeclarations

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $backlogPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'PositiveCaseMultiple:EXR-900-A01*' -Because 'each executable unit must declare exactly one positive behavior'
        }

        It 'rejects focused verification lacking an exact count and deterministic red-discovery contract' {
            # Arrange
            $backlogPath = New-BacklogAtomicityFixture -Name 'weak-focused-verification' -WeakFocusedVerification

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $backlogPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'FocusedVerificationIncomplete:EXR-900-A01*' -Because 'focused verification requires both an exact expected count and a deterministic red-discovery contract'
        }

        It 'rejects historical generation or prose parsed as current executable metadata' {
            # Arrange
            $backlogPath = New-BacklogAtomicityFixture -Name 'historical-metadata' -HistoricalMetadata

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $backlogPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'HistoricalMetadataParsedAsCurrent:EXR-899-A77*' -Because 'only the current canonical generation may contribute executable metadata'
        }
    }

    Context 'Negative: dependency safety is violated' {

        It 'rejects an executable card that depends on itself' {
            # Arrange
            $backlogPath = New-BacklogAtomicityFixture -Name 'unsafe-dependencies' -UnsafeDependencies

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $backlogPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DependencyUnsafe:EXR-900-A01*' -Because 'self-dependency prevents a safe acyclic execution order'
        }

        It 'rejects an executable card whose dependency ID is unknown' {
            # Arrange
            $backlogPath = New-BacklogAtomicityFixture -Name 'unknown-dependency' -UnknownDependency

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $backlogPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DependencyUnknown:EXR-900-A01:EXR-999-A01*' -Because 'every dependency must identify a current executable card'
        }

        It 'rejects a non-self dependency cycle between executable cards' {
            # Arrange
            $backlogPath = New-BacklogAtomicityFixture -Name 'dependency-cycle' -DependencyCycle

            # Act
            $act = {
                & $script:ValidatorPath -BacklogPath $backlogPath
            }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DependencyCycle:EXR-900-A01->EXR-900-A02->EXR-900-A01*' -Because 'non-self cycles prevent a safe acyclic execution order'
        }
    }

    Context 'Positive: a frozen canonical backlog is atomic and execution-ready' {

        It 'discovers every actual production-format card before refusing unresolved atomic completeness' {
            # Arrange
            $completeBacklogPath = New-BacklogAtomicityFixture -Name 'complete-production-format'
            $backlogPath = $script:ActualBacklogPath
            $canonicalHeader = [regex]::Match(
                (Get-Content -LiteralPath $backlogPath -Raw),
                '(?im)^Canonical generation\s*:\s*\d+\..*?To Do\s+(?<todo>\d+)\s*,\s*In Progress\s+(?<inprogress>\d+)\s*,\s*Done\s+(?<done>\d+)'
            )
            $expectedBuckets = '{0}:{1}:{2}' -f
                $canonicalHeader.Groups['todo'].Value,
                $canonicalHeader.Groups['inprogress'].Value,
                $canonicalHeader.Groups['done'].Value

            # Act
            $completeResult = & $script:ValidatorPath -BacklogPath $completeBacklogPath

            # Assert
            $completeResult.CanonicalGeneration | Should -Be 900
            "$($completeResult.ExecutableCount):$($completeResult.SummaryCount)" | Should -Be '1:1'
            "$($completeResult.ToDoCount):$($completeResult.InProgressCount):$($completeResult.DoneCount)" | Should -Be '1:0:0'
            $completeResult.DiscoverySucceeded | Should -BeTrue
            $completeResult.InventoryResolved | Should -BeTrue
            $completeResult.DependenciesAcyclic | Should -BeTrue

            # Act
            $validationError = try {
                & $script:ValidatorPath -BacklogPath $backlogPath
                $null
            }
            catch {
                $_
            }

            # Assert
            $validationError | Should -Not -BeNullOrEmpty -Because 'the actual backlog intentionally retains unresolved atomic-completeness findings'
            $validationError.Exception.Message |
                Should -BeLike 'MissingFieldInventoryUnresolved:*' -Because 'successful production discovery must remain distinct from expected unresolved completeness'
            "$($validationError.Exception.Data['ExecutableCount']):$($validationError.Exception.Data['SummaryCount'])" |
                Should -Be '90:24' -Because 'all production-format executable cards and explicit summaries must be discovered before completeness is evaluated'
            "$($validationError.Exception.Data['ToDoCount']):$($validationError.Exception.Data['InProgressCount']):$($validationError.Exception.Data['DoneCount'])" |
                Should -Be $expectedBuckets -Because 'discovered executable statuses must reconcile to the canonical header buckets'
            $validationError.Exception.Data['DiscoverySucceeded'] |
                Should -BeTrue -Because 'an unresolved atomic finding is not a production-parser discovery failure'
        }
    }
}
