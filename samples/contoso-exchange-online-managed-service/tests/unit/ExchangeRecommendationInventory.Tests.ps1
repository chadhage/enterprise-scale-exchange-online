BeforeAll {
    $sampleRoot = Join-Path $PSScriptRoot '../..'
    $script:inventoryValidator = Join-Path $sampleRoot 'scripts/Test-ExchangeRecommendationInventory.ps1'
    function New-TraceabilityFixture {
        Get-Content (Join-Path $sampleRoot 'config/exchange-recommendations.v1.json') -Raw | ConvertFrom-Json -AsHashtable
    }
}

Describe 'EXR007 recommendation inventory refusals' {
    It 'rejects <Name> with <Code>' -ForEach @(
        @{ Name = 'missing manifest mapping'; Code = 'MissingMapping'; Mutate = { param($document) $document.Mappings = @($document.Mappings | Select-Object -Skip 1) } }
        @{ Name = 'duplicate control'; Code = 'DuplicateMapping'; Mutate = { param($document) $document.Mappings += $document.Mappings[0] } }
        @{ Name = 'unknown control'; Code = 'DanglingControl'; Mutate = { param($document) $document.Mappings[0].ControlId = 'EXO-999' } }
        @{ Name = 'stale source'; Code = 'StaleSource'; Mutate = { param($document) $document.Sources[0].ReviewedOn = '2026-01-01' } }
        @{ Name = 'future source'; Code = 'InvalidReviewDate'; Mutate = { param($document) $document.Sources[0].ReviewedOn = '2026-09-22' } }
        @{ Name = 'invalid date'; Code = 'InvalidReviewDate'; Mutate = { param($document) $document.Sources[0].ReviewedOn = 'yesterday' } }
        @{ Name = 'missing source'; Code = 'DanglingSource'; Mutate = { param($document) $document.Mappings[0].SourceId = 'absent' } }
        @{ Name = 'duplicate source'; Code = 'DuplicateSource'; Mutate = { param($document) $document.Sources += $document.Sources[0] } }
        @{ Name = 'unreviewed section'; Code = 'DanglingSection'; Mutate = { param($document) $document.Mappings[0].Section = 'invented' } }
        @{ Name = 'unofficial source'; Code = 'UnsupportedSource'; Mutate = { param($document) $document.Sources[0].Url = 'https://learn.microsoft.com.evil.example/article' } }
        @{ Name = 'missing license'; Code = 'MissingField'; Mutate = { param($document) $document.Mappings[0].License = '' } }
        @{ Name = 'missing desired setting'; Code = 'MissingField'; Mutate = { param($document) $document.Mappings[0].Setting = '' } }
        @{ Name = 'missing command'; Code = 'MissingCommand'; Mutate = { param($document) $document.Mappings[0].Commands = @() } }
        @{ Name = 'invented command'; Code = 'DanglingCommand'; Mutate = { param($document) $document.Mappings[0].Commands = @('Get-ImaginaryExchangeSetting') } }
        @{ Name = 'missing evaluator'; Code = 'DanglingEvaluator'; Mutate = { param($document) $document.Mappings[0].Evaluator = 'Test-ImaginaryControl' } }
        @{ Name = 'wrong evaluator binding'; Code = 'EvaluatorBindingMismatch'; Mutate = { param($document) $document.Mappings[0].Evaluator = 'Test-ClientProtocolControl' } }
        @{ Name = 'invented evidence'; Code = 'EvidenceBindingMismatch'; Mutate = { param($document) $document.Mappings[0].Evidence = 'fabricated.pass' } }
        @{ Name = 'missing runbook'; Code = 'DanglingRunbook'; Mutate = { param($document) $document.Mappings[0].Runbook = 'docs/missing.md' } }
        @{ Name = 'missing runbook section'; Code = 'DanglingRunbook'; Mutate = { param($document) $document.Mappings[0].RunbookSection = 'invented' } }
        @{ Name = 'escaping runbook'; Code = 'DanglingRunbook'; Mutate = { param($document) $document.Mappings[0].Runbook = '../../.github/backlog.md' } }
        @{ Name = 'universal claim'; Code = 'UnsupportedClaim'; Mutate = { param($document) $document.Claim = '100% Microsoft 365 compliant' } }
        @{ Name = 'universal setting claim'; Code = 'UnsupportedClaim'; Mutate = { param($document) $document.Mappings[0].Setting = 'Fully compliant with all Microsoft recommendations' } }
        @{ Name = 'invented recommendation basis'; Code = 'UnsupportedBasis'; Mutate = { param($document) $document.Mappings[0].Basis = 'UniversalMicrosoftDefault' } }
        @{ Name = 'hidden manifest applicability'; Code = 'UnsupportedApplicability'; Mutate = { param($document) $document.Mappings[0].Applicability = 'NotApplicable' } }
        @{ Name = 'missing assessment area'; Code = 'MissingAssessmentArea'; Mutate = { param($document) $document.Assessments = @($document.Assessments | Where-Object Area -ne 'SharingDelegation') } }
        @{ Name = 'gap hidden as N/A'; Code = 'UnsupportedApplicability'; Mutate = { param($document) $document.Assessments[0].Applicability = 'NotApplicable' } }
        @{ Name = 'gap without child'; Code = 'UntrackedGap'; Mutate = { param($document) $document.Assessments[0].Proposal = '' } }
        @{ Name = 'false covered assessment'; Code = 'UnsupportedCoverage'; Mutate = { param($document) $document.Assessments[0].Coverage = 'Covered' } }
        @{ Name = 'duplicate assessment'; Code = 'DuplicateAssessment'; Mutate = { param($document) $document.Assessments += $document.Assessments[0] } }
        @{ Name = 'duplicate rank'; Code = 'DuplicateRank'; Mutate = { param($document) $document.Proposals += @{ Id = 'EXR007-C2'; Rank = 1; Title = 'Other gap'; Owner = 'Exchange engineering'; Status = 'Proposed'; ExistingCard = 'EXR-009'; Acceptance = @('Negative','Positive') } } }
        @{ Name = 'missing child acceptance'; Code = 'MissingAcceptance'; Mutate = { param($document) $document.Proposals[0].Acceptance = @() } }
        @{ Name = 'missing exclusion'; Code = 'MissingExclusion'; Mutate = { param($document) $document.Exclusions = @($document.Exclusions | Select-Object -Skip 1) } }
        @{ Name = 'duplicate exclusion'; Code = 'DuplicateExclusion'; Mutate = { param($document) $document.Exclusions += $document.Exclusions[0] } }
        @{ Name = 'retained control excluded'; Code = 'UnsupportedExclusion'; Mutate = { param($document) $document.Exclusions[0].ControlId += 'EXO-001' } }
        @{ Name = 'missing exclusion reason'; Code = 'ExclusionReasonRequired'; Mutate = { param($document) $document.Exclusions[0].Reason = '' } }
        @{ Name = 'missing external owner'; Code = 'ExternalOwnerRequired'; Mutate = { param($document) $document.Exclusions[0].ExternalOwner = '' } }
        @{ Name = 'dangling RAID'; Code = 'DanglingExternalReference'; Mutate = { param($document) $document.Exclusions[0].Reference = 'RAID-D99' } }
        @{ Name = 'fabricated readiness'; Code = 'UnsupportedClaim'; Mutate = { param($document) $document.ExternalReadiness = 'Verified' } }
        @{ Name = 'relaxed cadence'; Code = 'InvalidReviewCadence'; Mutate = { param($document) $document.ReviewCadenceDays = 365 } }
        @{ Name = 'missing reviewer'; Code = 'MissingField'; Mutate = { param($document) $document.ReviewOwner = '' } }
        @{ Name = 'wrong profile'; Code = 'ManifestBindingMismatch'; Mutate = { param($document) $document.Profile = 'Microsoft365' } }
        @{ Name = 'wrong manifest version'; Code = 'ManifestBindingMismatch'; Mutate = { param($document) $document.ManifestVersion = '0.0.0' } }
        @{ Name = 'same source URL under another ID'; Code = 'DuplicateSourceUrl'; Mutate = { param($document) $document.Sources[1].Url = $document.Sources[0].Url } }
        @{ Name = 'orphaned child after assessment deletion'; Code = 'DanglingProposal'; Mutate = { param($document) $document.Assessments = @($document.Assessments | Where-Object Id -ne 'A03') } }
        @{ Name = 'null command list'; Code = 'MissingCommand'; Mutate = { param($document) $document.Mappings[0].Commands = $null } }
        @{ Name = 'empty source sections'; Code = 'MissingField'; Mutate = { param($document) $document.Sources[0].Sections = @('') } }
        @{ Name = 'missing assessment identity'; Code = 'MissingField'; Mutate = { param($document) $document.Assessments[0].Id = '' } }
        @{ Name = 'invented assessment area'; Code = 'UnknownAssessmentArea'; Mutate = { param($document) $document.Assessments[0].Area = 'IgnoredArea' } }
        @{ Name = 'fabricated gap evidence'; Code = 'UnsupportedCoverage'; Mutate = { param($document) $document.Assessments[0].Evidence = 'fabricated.pass' } }
        @{ Name = 'wrong existing RAID binding'; Code = 'ExternalBindingMismatch'; Mutate = { param($document) $document.Exclusions[0].Reference = 'RAID-D05' } }
    ) {
        # Arrange
        $document = New-TraceabilityFixture
        & $Mutate $document
        # Act
        $result = & $script:inventoryValidator -Document $document -AsOfUtc ([datetime]'2026-09-21T12:00:00Z')
        # Assert
        $result.Codes | Should -Contain $Code
        $result.Valid | Should -BeFalse
    }

    It 'validates only the shipped declared manifest while retaining proposed gaps and unverified readiness' {
        # Arrange
        $inventoryPath = Join-Path $sampleRoot 'config/exchange-recommendations.v1.json'
        # Act
        $result = & $script:inventoryValidator -InventoryPath $inventoryPath -AsOfUtc ([datetime]'2026-09-21T12:00:00Z')
        # Assert
        $result.Valid | Should -BeTrue
        $result.Codes.Count | Should -Be 0
        $result.ManifestCount | Should -Be 25
        $result.MappedCount | Should -Be 25
        $result.Scope | Should -BeExactly 'DeclaredExchangeManifest'
        $result.ExternalReadiness | Should -BeExactly 'Unverified'
        $result.ProposedGapCount | Should -BeGreaterThan 0
        $result.ReleaseReady | Should -BeFalse
    }
}