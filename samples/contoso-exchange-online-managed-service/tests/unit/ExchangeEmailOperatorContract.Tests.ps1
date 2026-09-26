#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:EmailContractPath = Join-Path $script:SampleRoot 'docs' 'EXCHANGE-EMAIL-PROTECTION.md'
    $script:RunbookPath = Join-Path $script:SampleRoot 'docs' 'RUNBOOKS.md'
    $script:CatalogPath = Join-Path $script:SampleRoot 'docs' 'CONTROL-CATALOG.md'
    $script:LicensingPath = Join-Path $script:SampleRoot 'docs' 'LICENSING-GATE.md'

    $script:EmailContract = Get-Content -LiteralPath $script:EmailContractPath -Raw
    $script:Runbooks = Get-Content -LiteralPath $script:RunbookPath -Raw
    $script:Catalog = Get-Content -LiteralPath $script:CatalogPath -Raw
    $script:Licensing = Get-Content -LiteralPath $script:LicensingPath -Raw

    function Get-RunbookSection {
        param(
            [Parameter(Mandatory)]
            [string]$Document,

            [Parameter(Mandatory)]
            [string]$ControlId
        )

        $match = [regex]::Match(
            $Document,
            "(?ms)^### R-$([regex]::Escape($ControlId))\b.*?(?=^### R-|\z)"
        )
        return $match.Value
    }

    function Get-OperatorContractViolation {
        param(
            [Parameter(Mandatory)]
            [string]$EmailContract,

            [Parameter(Mandatory)]
            [string]$Runbooks,

            [Parameter(Mandatory)]
            [string]$Catalog,

            [Parameter(Mandatory)]
            [string]$Licensing
        )

        $violation = [Collections.Generic.List[string]]::new()
        $externalRunbook = @('MDO-004', 'MDO-005' | ForEach-Object {
                Get-RunbookSection -Document $Runbooks -ControlId $_
            }) -join "`n"

        if ($externalRunbook -notmatch '(?s)MDO-004.*\*\*Verify\*\*.*\*\*Expected\*\*') {
            $violation.Add('RunbookVerifyMissing:MDO-004')
        }
        if ($EmailContract -notmatch '(?im)^\|\s*Historical\s*\|\s*43\s*\|') {
            $violation.Add('HistoricalDenominatorMissing:43')
        }
        if ($EmailContract -notmatch '(?im)^\|\s*ExchangeOnly\s*\|\s*25\s*\|') {
            $violation.Add('ExchangeOnlyDenominatorMissing:25')
        }
        if ($EmailContract -notmatch '(?is)Historical[^\r\n]*MDO-004[^\r\n]*MDO-005[^\r\n]*(opt-in|reference)') {
            $violation.Add('HistoricalControlsNotPreserved:MDO-004,MDO-005')
        }
        if ($EmailContract -notmatch '(?is)ExchangeOnly[^\r\n]*(exclude|not applicable)[^\r\n]*MDO-004[^\r\n]*MDO-005') {
            $violation.Add('ExchangeOnlyExclusionMissing:MDO-004,MDO-005')
        }
        if ($Catalog -notmatch '(?im)^\| MDO-004 \| MUST \| Excluded \| External owner \|' -or
            $Catalog -notmatch '(?im)^\| MDO-005 \| SHOULD \| Excluded \| External owner \|' -or
            $EmailContract -notmatch '(?is)MicrosoftRecommendation.*LocalPolicy.*ApprovedException') {
            $violation.Add('CatalogParityProfileOrValueClassMissing')
        }
        if ($EmailContract -notmatch '(?im)^\|\s*TST-006 evidence\s*\|\s*Historical\s*\|\s*43/43\s*\|') {
            $violation.Add('Tst006EvidenceDenominatorMissing:43/43')
        }
        if ($EmailContract -notmatch '(?im)^\|\s*TST-006 result\s*\|\s*Historical\s*\|\s*43/43\s*\|\s*0\s*\|') {
            $violation.Add('Tst006ResultDenominatorOrExitMissing:43/43,0')
        }
        if ($Licensing -notmatch '(?is)supplied licensing-owner handoff.*does not.*query Graph.*grant consent' -or
            $EmailContract -match '(?im)^\s*(Connect-MgGraph|Invoke-MgGraphRequest)\b' -or
            $EmailContract -match '(?im)^\s*(Set-AtpPolicyForO365|Set-SPOTenant)\b') {
            $violation.Add('ActiveExchangeExternalBoundaryMissing')
        }

        $requiredHeading = @('Inputs', 'Set', 'Verify', 'Expected Output', 'Recovery')
        foreach ($heading in $requiredHeading) {
            if ($EmailContract -notmatch "(?im)^###\s+$([regex]::Escape($heading))\s*$") {
                $violation.Add("OperatorStepMissing:$heading")
            }
        }

        return @($violation)
    }
}

Describe 'EXR-010-A11 email operator documentation and legacy reconciliation' {
    Context 'Negative: the excluded collaboration runbook remains verifiable as an external handoff' {
        It 'reconciles the one runbook Verify failure without adding excluded-workload setup' {
            # Arrange
            $runbooks = $script:Runbooks

            # Act
            $violation = Get-OperatorContractViolation -EmailContract $script:EmailContract -Runbooks $runbooks -Catalog $script:Catalog -Licensing $script:Licensing

            # Assert
            $violation | Should -Not -Contain 'RunbookVerifyMissing:MDO-004'
        }
    }

    Context 'Negative: catalog extraction and parity retain distinct profile denominators' {
        It 'reconciles EVD-003-A1 with an explicit 43-control historical denominator' {
            # Arrange
            $emailContract = $script:EmailContract

            # Act
            $violation = Get-OperatorContractViolation -EmailContract $emailContract -Runbooks $script:Runbooks -Catalog $script:Catalog -Licensing $script:Licensing

            # Assert
            $violation | Should -Not -Contain 'HistoricalDenominatorMissing:43'
        }

        It 'reconciles EVD-003-A3 missing controls with an explicit 25-control ExchangeOnly denominator' {
            # Arrange
            $emailContract = $script:EmailContract

            # Act
            $violation = Get-OperatorContractViolation -EmailContract $emailContract -Runbooks $script:Runbooks -Catalog $script:Catalog -Licensing $script:Licensing

            # Assert
            $violation | Should -Not -Contain 'ExchangeOnlyDenominatorMissing:25'
        }

        It 'reconciles EVD-003-A3 unknown controls by preserving MDO-004 and MDO-005 as historical opt-in references' {
            # Arrange
            $emailContract = $script:EmailContract

            # Act
            $violation = Get-OperatorContractViolation -EmailContract $emailContract -Runbooks $script:Runbooks -Catalog $script:Catalog -Licensing $script:Licensing

            # Assert
            $violation | Should -Not -Contain 'HistoricalControlsNotPreserved:MDO-004,MDO-005'
        }

        It 'reconciles EVD-003-A3 extra controls without restoring MDO-004 or MDO-005 to ExchangeOnly' {
            # Arrange
            $emailContract = $script:EmailContract

            # Act
            $violation = Get-OperatorContractViolation -EmailContract $emailContract -Runbooks $script:Runbooks -Catalog $script:Catalog -Licensing $script:Licensing

            # Assert
            $violation | Should -Not -Contain 'ExchangeOnlyExclusionMissing:MDO-004,MDO-005'
        }

        It 'reconciles EVD-003-A3 exact parity while keeping Microsoft, local and approved-exception values distinct' {
            # Arrange
            $catalog = $script:Catalog

            # Act
            $violation = Get-OperatorContractViolation -EmailContract $script:EmailContract -Runbooks $script:Runbooks -Catalog $catalog -Licensing $script:Licensing

            # Assert
            $violation | Should -Not -Contain 'CatalogParityProfileOrValueClassMissing'
        }
    }

    Context 'Negative: TST-006 downstream evidence remains bound to the historical profile' {
        It 'reconciles emitted evidence as 43 of 43 historical controls' {
            # Arrange
            $emailContract = $script:EmailContract

            # Act
            $violation = Get-OperatorContractViolation -EmailContract $emailContract -Runbooks $script:Runbooks -Catalog $script:Catalog -Licensing $script:Licensing

            # Assert
            $violation | Should -Not -Contain 'Tst006EvidenceDenominatorMissing:43/43'
        }

        It 'reconciles emitted results as 43 of 43 with public exit zero' {
            # Arrange
            $emailContract = $script:EmailContract

            # Act
            $violation = Get-OperatorContractViolation -EmailContract $emailContract -Runbooks $script:Runbooks -Catalog $script:Catalog -Licensing $script:Licensing

            # Assert
            $violation | Should -Not -Contain 'Tst006ResultDenominatorOrExitMissing:43/43,0'
        }
    }

    Context 'Negative: the active Exchange path consumes external handoffs without mandatory Graph consent' {
        It 'reconciles the Graph-permission expectation and excludes collaboration writes' {
            # Arrange
            $licensing = $script:Licensing

            # Act
            $violation = Get-OperatorContractViolation -EmailContract $script:EmailContract -Runbooks $script:Runbooks -Catalog $script:Catalog -Licensing $licensing

            # Assert
            $violation | Should -Not -Contain 'ActiveExchangeExternalBoundaryMissing'
        }
    }

    Context 'Positive: one complete operator contract is accepted' {
        It 'accepts exact inputs, set, verify, expected output and recovery with separated profiles and handoffs' {
            # Arrange
            $emailContract = $script:EmailContract

            # Act
            $violation = Get-OperatorContractViolation -EmailContract $emailContract -Runbooks $script:Runbooks -Catalog $script:Catalog -Licensing $script:Licensing

            # Assert
            $violation | Should -BeNullOrEmpty
        }
    }
}