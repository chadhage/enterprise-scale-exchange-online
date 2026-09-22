#requires -Version 7.0

# Discovery-scope copies so the per-section, per-decision, and per-contract negative cases can
# be expanded by -ForEach.
$MandatedSections = @(
    'Result And Go-Live Semantics'
    'Canonical Comparisons'
    'Applicability And Entitlement Authority'
    'Artifact Versions'
    'Approval Signature Model'
    'Contract Approval'
)
$RecordedDecisions = @('DES-001', 'DES-002', 'DES-003', 'DES-004', 'DES-005')
$ApprovableContracts = @('Configuration', 'Evidence', 'Preview', 'Approval', 'Rollback', 'Exception')

BeforeAll {
    $script:MandatedSections = @(
        'Result And Go-Live Semantics'
        'Canonical Comparisons'
        'Applicability And Entitlement Authority'
        'Artifact Versions'
        'Approval Signature Model'
        'Contract Approval'
    )
    $script:RecordedDecisions = @('DES-001', 'DES-002', 'DES-003', 'DES-004', 'DES-005')
    $script:ApprovableContracts = @('Configuration', 'Evidence', 'Preview', 'Approval', 'Rollback', 'Exception')
    $script:SectionDecision = [ordered]@{
        'Result And Go-Live Semantics'            = 'DES-001'
        'Canonical Comparisons'                   = 'DES-002'
        'Applicability And Entitlement Authority' = 'DES-003'
        'Artifact Versions'                       = 'DES-004'
        'Approval Signature Model'                = 'DES-005'
    }

    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:DesignDocumentPath = Join-Path $script:SampleRoot 'docs' 'DESIGN.md'

    function Get-DesignPublicationVerdict {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyString()]
            [string]$Path
        )

        $verdict = [ordered]@{
            Satisfied  = $false
            Reason     = $null
            Violations = @()
        }

        if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            $verdict.Reason = 'DocumentMissing'
            return [pscustomobject]$verdict
        }

        $content = Get-Content -LiteralPath $Path -Raw
        if ([string]::IsNullOrWhiteSpace($content)) {
            $verdict.Reason = 'DocumentEmpty'
            return [pscustomobject]$verdict
        }

        $lines = $content -split "`r?`n"
        $headings = @($lines | Where-Object { $_ -match '^##\s+(.+?)\s*$' } | ForEach-Object { $Matches[1] })

        $missingSections = @($script:MandatedSections | Where-Object { $_ -notin $headings })
        if ($missingSections.Count -gt 0) {
            $verdict.Reason = 'SectionMissing'
            $verdict.Violations = $missingSections
            return [pscustomobject]$verdict
        }

        $unrecordedDecisions = @($script:RecordedDecisions | Where-Object { $content -notmatch [regex]::Escape($_) })
        if ($unrecordedDecisions.Count -gt 0) {
            $verdict.Reason = 'DecisionNotRecorded'
            $verdict.Violations = $unrecordedDecisions
            return [pscustomobject]$verdict
        }

        $approvalRows = [System.Collections.Generic.List[object]]::new()
        $inApprovalSection = $false
        foreach ($line in $lines) {
            if ($line -match '^##\s+(.+?)\s*$') {
                $inApprovalSection = ($Matches[1] -eq 'Contract Approval')
                continue
            }

            if (-not $inApprovalSection -or $line -notmatch '^\s*\|') { continue }

            $cells = @(($line.Trim() -split '\|') | ForEach-Object { $_.Trim() })
            if ($cells.Count -lt 4) { continue }
            if ($cells[1] -eq 'Contract' -or $cells[1] -match '^-+$') { continue }

            $approvalRows.Add([pscustomobject]@{
                    Contract = $cells[1]
                    Status   = $cells[3]
                })
        }

        $approvedNames = @($approvalRows | ForEach-Object { $_.Contract })
        $missingApprovals = @($script:ApprovableContracts | Where-Object { $_ -notin $approvedNames })
        if ($missingApprovals.Count -gt 0) {
            $verdict.Reason = 'ContractApprovalMissing'
            $verdict.Violations = $missingApprovals
            return [pscustomobject]$verdict
        }

        $notApproved = @($approvalRows | Where-Object { $_.Status -ne 'Approved' } | ForEach-Object { $_.Contract })
        if ($notApproved.Count -gt 0) {
            $verdict.Reason = 'ContractNotApproved'
            $verdict.Violations = $notApproved
            return [pscustomobject]$verdict
        }

        $verdict.Satisfied = $true
        $verdict.Reason = 'DesignPublicationSatisfied'
        return [pscustomobject]$verdict
    }

    function New-DesignDocumentFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path,
            [switch]$Empty,
            [string]$OmitSection,
            [string]$OmitDecision,
            [string]$OmitContractApproval,
            [string]$UnapprovedContract
        )

        if ($Empty) {
            Set-Content -LiteralPath $Path -Value "   `n" -NoNewline
            return $Path
        }

        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add('# Exchange Online Baseline Design')
        $lines.Add('')

        foreach ($section in $script:MandatedSections) {
            if ($section -eq $OmitSection) { continue }

            $lines.Add("## $section")
            $lines.Add('')

            if ($section -eq 'Contract Approval') {
                $lines.Add('| Contract | Schema Version | Status |')
                $lines.Add('| --- | --- | --- |')
                foreach ($contract in $script:ApprovableContracts) {
                    if ($contract -eq $OmitContractApproval) { continue }

                    $status = if ($contract -eq $UnapprovedContract) { 'Proposed' } else { 'Approved' }
                    $lines.Add("| $contract | 1.0.0 | $status |")
                }
                $lines.Add('')
                continue
            }

            $decision = $script:SectionDecision[$section]
            if ($decision -eq $OmitDecision) {
                $lines.Add('Decision recorded.')
            }
            else {
                $lines.Add("$decision decision recorded.")
            }
            $lines.Add('')
        }

        Set-Content -LiteralPath $Path -Value ($lines -join [System.Environment]::NewLine)
        return $Path
    }
}

Describe 'DES-006-A published and approved design contracts' {

    Context 'Negative: publication and approval are not satisfied' {

        It 'reports DocumentMissing when the design document does not exist' {
            # Arrange
            $path = Join-Path $TestDrive 'absent-DESIGN.md'

            # Act
            $verdict = Get-DesignPublicationVerdict -Path $path

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'an absent design document publishes nothing'
            $verdict.Reason | Should -Be 'DocumentMissing'
        }

        It 'reports DocumentEmpty when the design document has no content' {
            # Arrange
            $path = New-DesignDocumentFixture -Path (Join-Path $TestDrive 'empty-DESIGN.md') -Empty

            # Act
            $verdict = Get-DesignPublicationVerdict -Path $path

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'an empty design document records no decisions'
            $verdict.Reason | Should -Be 'DocumentEmpty'
        }

        It "reports SectionMissing when the '<_>' section is absent" -ForEach $MandatedSections {
            # Arrange
            $section = $_
            $path = New-DesignDocumentFixture -Path (Join-Path $TestDrive "no-section-$($section -replace '\W').md") -OmitSection $section

            # Act
            $verdict = Get-DesignPublicationVerdict -Path $path

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because "$section is a mandated section"
            $verdict.Reason | Should -Be 'SectionMissing'
            $verdict.Violations | Should -Be @($section)
        }

        It "reports DecisionNotRecorded when the '<_>' decision is not referenced" -ForEach $RecordedDecisions {
            # Arrange
            $decision = $_
            $path = New-DesignDocumentFixture -Path (Join-Path $TestDrive "no-decision-$decision.md") -OmitDecision $decision

            # Act
            $verdict = Get-DesignPublicationVerdict -Path $path

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because "$decision must be recorded in the published design"
            $verdict.Reason | Should -Be 'DecisionNotRecorded'
            $verdict.Violations | Should -Be @($decision)
        }

        It "reports ContractApprovalMissing when the '<_>' contract has no approval entry" -ForEach $ApprovableContracts {
            # Arrange
            $contract = $_
            $path = New-DesignDocumentFixture -Path (Join-Path $TestDrive "no-approval-$contract.md") -OmitContractApproval $contract

            # Act
            $verdict = Get-DesignPublicationVerdict -Path $path

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because "every versioned contract needs an approval entry, including $contract"
            $verdict.Reason | Should -Be 'ContractApprovalMissing'
            $verdict.Violations | Should -Be @($contract)
        }

        It 'reports ContractNotApproved when a versioned contract is recorded as unapproved' {
            # Arrange
            $path = New-DesignDocumentFixture -Path (Join-Path $TestDrive 'unapproved-DESIGN.md') -UnapprovedContract 'Rollback'

            # Act
            $verdict = Get-DesignPublicationVerdict -Path $path

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'a proposed contract is not an approved contract'
            $verdict.Reason | Should -Be 'ContractNotApproved'
            $verdict.Violations | Should -Be @('Rollback')
        }
    }

    Context 'Positive: publication and approval are satisfied' {

        It 'publishes every mandated section, records every decision, and approves every versioned contract' {
            # Arrange
            $path = $script:DesignDocumentPath

            # Act
            $verdict = Get-DesignPublicationVerdict -Path $path

            # Assert
            $verdict.Satisfied | Should -BeTrue -Because "design publication violation: $($verdict.Reason) $($verdict.Violations -join ', ')"
        }
    }
}
