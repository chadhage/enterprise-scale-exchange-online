#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:CatalogPath = Join-Path $script:SampleRoot 'docs' 'CONTROL-CATALOG.md'

    # Microsoft.Graph and ExchangeOnlineManagement are not installed and must never be imported.
    # Parity is decided from a markdown file and a declaration, so nothing here reaches a service.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-CatalogFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Name,

            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [AllowEmptyString()]
            [string[]]$Line
        )

        $path = Join-Path $TestDrive $Name
        Set-Content -LiteralPath $path -Value $Line -Encoding utf8
        return $path
    }

    function New-CatalogControlRow {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ControlId,

            [string]$Priority = 'MUST'
        )

        return "| $ControlId | $Priority | Both | EOP | Setting | Required state | ``Get-Something`` | [R-$ControlId](RUNBOOKS.md#r) |"
    }

    function New-ThreeControlCatalog {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Name
        )

        return (New-CatalogFixture -Name $Name -Line @(
                '| ID | Priority | Profile | Tier | Setting | Required state | Evidence | Runbook |'
                '| --- | --- | --- | --- | --- | --- | --- | --- |'
                (New-CatalogControlRow -ControlId 'EXO-001')
                (New-CatalogControlRow -ControlId 'EXO-002')
                (New-CatalogControlRow -ControlId 'EXO-003' -Priority 'SHOULD')
            ))
    }

    function Get-CoverageFold {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Coverage
        )

        return '{0}|missing={1}|unknown={2}|duplicated={3}' -f `
            $Coverage.Satisfied,
        (@($Coverage.Missing) -join '+'),
        (@($Coverage.Unknown) -join '+'),
        (@($Coverage.Duplicated) -join '+')
    }

    function ConvertTo-ControlDefinition {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Registry
        )

        $definition = foreach ($entry in $Registry) {
            $record = [ordered]@{}
            foreach ($name in @('ControlId', 'Priority', 'ApplicableProfile', 'Prerequisite', 'Collector', 'Evaluator', 'EvidencePath')) {
                $record[$name] = $entry.$name
            }

            $record
        }

        return $definition
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EVD-003-A1 control catalog identifiers' {

    Context 'Negative: the catalog must be named and readable' {

        It 'refuses a catalog that is not named' {
            # Arrange
            $noPath = $null

            # Act
            $result = { Get-BaselineControlCatalog -Path $noPath }

            # Assert
            $result | Should -Throw -ExpectedMessage 'CatalogPathRequired*' -Because 'parity measured against an unnamed catalog is parity against nothing, and every registry satisfies nothing'
        }

        It 'refuses a catalog whose path is blank' {
            # Arrange
            $blankPath = '   '

            # Act
            $result = { Get-BaselineControlCatalog -Path $blankPath }

            # Assert
            $result | Should -Throw -ExpectedMessage 'CatalogPathRequired*' -Because 'whitespace names no file any more than nothing does'
        }

        It 'refuses a catalog that does not exist' {
            # Arrange
            $absentPath = Join-Path $TestDrive 'no-such-catalog.md'

            # Act
            $result = { Get-BaselineControlCatalog -Path $absentPath }

            # Assert
            $result | Should -Throw -ExpectedMessage 'CatalogNotFound*' -Because 'a renamed or moved catalog must stop the run rather than silently become an empty one'
        }
    }

    Context 'Negative: the catalog must declare controls, and declare each of them once' {

        It 'refuses a catalog that declares no control row' {
            # Arrange
            $emptyCatalog = New-CatalogFixture -Name 'empty-catalog.md' -Line @(
                '# Control Catalog'
                ''
                'Prose with no table in it.'
            )

            # Act
            $result = { Get-BaselineControlCatalog -Path $emptyCatalog }

            # Assert
            $result | Should -Throw -ExpectedMessage 'CatalogDeclaresNoControl*' -Because 'a catalog that declares nothing holds the registry to nothing, so a registry that collapsed to zero controls would still read as complete'
        }

        It 'refuses a catalog whose only rows are anti-patterns' {
            # Arrange
            $antiPatternOnly = New-CatalogFixture -Name 'anti-pattern-catalog.md' -Line @(
                '| ID | Anti-pattern | Why it is harmful |'
                '| --- | --- | --- |'
                '| BAD-001 | SCL `-1` rules for gateway traffic | Bypasses Microsoft spam evaluation |'
                '| BAD-002 | Adding gateway IPs to allow lists | Over-trusts a shared gateway |'
            )

            # Act
            $result = { Get-BaselineControlCatalog -Path $antiPatternOnly }

            # Assert
            $result | Should -Throw -ExpectedMessage 'CatalogDeclaresNoControl*' -Because 'the AVOID table names patterns to refuse rather than controls to verify, and counting them as controls would demand a collector and an evaluator for each one'
        }

        It 'refuses a catalog that declares one control twice' {
            # Arrange
            $duplicateCatalog = New-CatalogFixture -Name 'duplicate-catalog.md' -Line @(
                '| ID | Priority | Profile | Tier | Setting | Required state | Evidence | Runbook |'
                '| --- | --- | --- | --- | --- | --- | --- | --- |'
                (New-CatalogControlRow -ControlId 'EXO-001')
                (New-CatalogControlRow -ControlId 'EXO-001' -Priority 'SHOULD')
            )

            # Act
            $result = { Get-BaselineControlCatalog -Path $duplicateCatalog }

            # Assert
            $result | Should -Throw -ExpectedMessage 'CatalogControlDuplicated*' -Because 'a control listed twice can be listed at two priorities, and the gate then blocks or waives it depending on which row a reader reached first'
        }
    }

    Context 'Negative: the catalog cannot be edited after it is read' {

        It 'returns a catalog that rejects assignment' {
            # Arrange
            $catalog = Get-BaselineControlCatalog -Path $script:CatalogPath

            # Act
            $act = { $catalog[0] = 'EXO-999' }

            # Assert
            $act | Should -Throw -Because 'a catalog a caller can rewrite mid-run cannot prove which controls the run was held to'
        }
    }

    Context 'Positive: the shipped catalog declares every control the solution verifies' {

        It 'returns every shipped catalog control identifier exactly once in catalog order' {
            # Arrange
            $expected = @(
                'EXO-001', 'EXO-002', 'EXO-003', 'EXO-004', 'EXO-005', 'EXO-006'
                'EXO-007', 'EXO-008', 'EXO-009', 'EXO-010', 'EXO-011', 'EXO-012'
                'MDO-001', 'MDO-002', 'MDO-003', 'MDO-004', 'MDO-005'
                'MDO-006', 'MDO-007', 'MDO-008', 'MDO-009'
                'PP-001', 'PP-002', 'PP-003', 'PP-004', 'PP-005'
                'AUTH-001', 'AUTH-002', 'AUTH-003'
                'ABN-001', 'ABN-002'
                'MON-001', 'MON-002', 'MON-003'
                'OPS-001', 'OPS-002'
                'GOV-001', 'GOV-002', 'GOV-003', 'GOV-004', 'GOV-005', 'GOV-006', 'GOV-007'
            ) -join ','

            # Act
            $catalog = Get-BaselineControlCatalog -Path $script:CatalogPath

            # Assert
            (@($catalog) -join ',') |
                Should -BeExactly $expected `
                    -Because 'the catalog is the list every other artifact is measured against, so reading it must yield exactly the controls a reviewer sees in the document'
        }
    }
}

Describe 'EVD-003-A2 control coverage against the catalog' {

    Context 'Negative: a coverage comparison must name a catalog, a subject and a set of controls' {

        It 'refuses a comparison that names no catalog' {
            # Arrange
            $noCatalog = $null

            # Act
            $result = { Test-BaselineControlCoverage -CatalogPath $noCatalog -Observed @([pscustomobject]@{ ControlId = 'EXO-001' }) -Subject 'registry' }

            # Assert
            $result | Should -Throw -ExpectedMessage 'CatalogPathRequired*' -Because 'coverage against no catalog is coverage against nothing, and nothing is always fully covered'
        }

        It 'refuses a comparison that names no subject' {
            # Arrange
            $catalog = New-ThreeControlCatalog -Name 'no-subject-catalog.md'

            # Act
            $result = { Test-BaselineControlCoverage -CatalogPath $catalog -Observed @([pscustomobject]@{ ControlId = 'EXO-001' }) -Subject '  ' }

            # Assert
            $result | Should -Throw -ExpectedMessage 'CoverageSubjectRequired*' -Because 'a drift report that does not say whether the registry or the evidence drifted tells an operator nothing about what to fix'
        }

        It 'refuses a comparison over no controls at all' {
            # Arrange
            $catalog = New-ThreeControlCatalog -Name 'no-observed-catalog.md'

            # Act
            $result = { Test-BaselineControlCoverage -CatalogPath $catalog -Observed $null -Subject 'evidence' }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ObservedControlRequired*' -Because 'a run that produced nothing is a collection failure, and reporting it as forty-three missing controls hides that the run never started'
        }

        It 'refuses a comparison over an empty set of controls' {
            # Arrange
            $catalog = New-ThreeControlCatalog -Name 'empty-observed-catalog.md'

            # Act
            $result = { Test-BaselineControlCoverage -CatalogPath $catalog -Observed @() -Subject 'evidence' }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ObservedControlRequired*' -Because 'an empty set is the same silent absence as no set at all'
        }
    }

    Context 'Negative: every compared entry must name the control it stands for' {

        It 'refuses an entry that is not a record' {
            # Arrange
            $catalog = New-ThreeControlCatalog -Name 'not-a-record-catalog.md'

            # Act
            $result = { Test-BaselineControlCoverage -CatalogPath $catalog -Observed @('EXO-001') -Subject 'evidence' }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ObservedControlNotRecognized*' -Because 'a bare string alongside real records is a shape nobody meant to produce, and counting it as coverage credits a control that was never observed'
        }

        It 'refuses an entry that names no control' {
            # Arrange
            $catalog = New-ThreeControlCatalog -Name 'no-control-id-catalog.md'

            # Act
            $result = { Test-BaselineControlCoverage -CatalogPath $catalog -Observed @([pscustomobject]@{ Source = 'ExchangeOnline' }) -Subject 'evidence' }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ObservedControlIdRequired*' -Because 'an anonymous record cannot be matched to a catalog row, so it would be reported as coverage of nothing while a real control stays uncovered'
        }
    }

    Context 'Negative: missing, unknown and duplicated controls are all drift' {

        It 'reports a catalog control that was never observed' {
            # Arrange
            $catalog = New-ThreeControlCatalog -Name 'missing-control-catalog.md'
            $observed = @(
                [pscustomobject]@{ ControlId = 'EXO-001' }
                [pscustomobject]@{ ControlId = 'EXO-003' }
            )

            # Act
            $coverage = Test-BaselineControlCoverage -CatalogPath $catalog -Observed $observed -Subject 'evidence'

            # Assert
            (Get-CoverageFold -Coverage $coverage) |
                Should -BeExactly 'False|missing=EXO-002|unknown=|duplicated=' `
                    -Because 'a control that was never observed is the one case an operator reads as clean, because nothing failed'
        }

        It 'reports an observed control the catalog does not declare' {
            # Arrange
            $catalog = New-ThreeControlCatalog -Name 'unknown-control-catalog.md'
            $observed = @(
                [pscustomobject]@{ ControlId = 'EXO-001' }
                [pscustomobject]@{ ControlId = 'EXO-002' }
                [pscustomobject]@{ ControlId = 'EXO-003' }
                [pscustomobject]@{ ControlId = 'EXO-099' }
            )

            # Act
            $coverage = Test-BaselineControlCoverage -CatalogPath $catalog -Observed $observed -Subject 'registry'

            # Assert
            (Get-CoverageFold -Coverage $coverage) |
                Should -BeExactly 'False|missing=|unknown=EXO-099|duplicated=' `
                    -Because 'a control nobody documented is a control nobody reviewed, and it gates a release on a rule that was never agreed'
        }

        It 'reports a catalog control observed more than once' {
            # Arrange
            $catalog = New-ThreeControlCatalog -Name 'duplicate-control-catalog.md'
            $observed = @(
                [pscustomobject]@{ ControlId = 'EXO-001' }
                [pscustomobject]@{ ControlId = 'EXO-002' }
                [pscustomobject]@{ ControlId = 'EXO-002' }
                [pscustomobject]@{ ControlId = 'EXO-003' }
            )

            # Act
            $coverage = Test-BaselineControlCoverage -CatalogPath $catalog -Observed $observed -Subject 'evidence'

            # Assert
            (Get-CoverageFold -Coverage $coverage) |
                Should -BeExactly 'False|missing=|unknown=|duplicated=EXO-002' `
                    -Because 'one control reported twice can be reported two ways, and the gate then depends on which copy it read last'
        }
    }

    Context 'Negative: a coverage result cannot be edited after it is decided' {

        It 'returns a coverage result that rejects assignment' {
            # Arrange
            $catalog = New-ThreeControlCatalog -Name 'immutable-result-catalog.md'
            $coverage = Test-BaselineControlCoverage -CatalogPath $catalog -Observed @(
                [pscustomobject]@{ ControlId = 'EXO-001' }
                [pscustomobject]@{ ControlId = 'EXO-002' }
                [pscustomobject]@{ ControlId = 'EXO-003' }
            ) -Subject 'evidence'

            # Act
            $act = { $coverage.Satisfied = $true }

            # Assert
            $act | Should -Throw -Because 'a drift verdict a caller can flip is a gate that can be opened without changing the catalog, the registry or the evidence'
        }

        It 'returns a coverage result that rejects a new member' {
            # Arrange
            $catalog = New-ThreeControlCatalog -Name 'sealed-result-catalog.md'
            $coverage = Test-BaselineControlCoverage -CatalogPath $catalog -Observed @(
                [pscustomobject]@{ ControlId = 'EXO-001' }
                [pscustomobject]@{ ControlId = 'EXO-002' }
                [pscustomobject]@{ ControlId = 'EXO-003' }
            ) -Subject 'evidence'

            # Act
            $act = { $coverage.Waived = $true }

            # Assert
            $act | Should -Throw -Because 'a member added after the comparison is a claim the comparison never made, and the next reader cannot tell it from a decided one'
        }
    }

    Context 'Positive: evidence carrying each catalog control exactly once is satisfied coverage' {

        It 'reports satisfied coverage with nothing missing, nothing unknown and nothing duplicated' {
            # Arrange
            $catalog = New-ThreeControlCatalog -Name 'satisfied-catalog.md'
            $evidence = @('EXO-001', 'EXO-002', 'EXO-003' | ForEach-Object {
                    New-BaselineEvidence -ControlId $_ -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value @{ state = 'observed' }
                })

            # Act
            $coverage = Test-BaselineControlCoverage -CatalogPath $catalog -Observed $evidence -Subject 'evidence'

            # Assert
            (Get-CoverageFold -Coverage $coverage) |
                Should -BeExactly 'True|missing=|unknown=|duplicated=' `
                    -Because 'coverage is only satisfied when every catalog control is accounted for exactly once and nothing outside the catalog was smuggled in'
        }
    }
}

Describe 'EVD-003-A3 shipped catalog and shipped registry parity' {

    Context 'Negative: drift between the shipped catalog and the shipped registry is refused' {

        It 'refuses a registry that drops a catalog control' {
            # Arrange
            $short = @(ConvertTo-ControlDefinition -Registry (Get-BaselineControlRegistry -Profile Historical) | Where-Object { $_.ControlId -cne 'EXO-006' })
            $registry = New-BaselineControlRegistry -Definition $short

            # Act
            $coverage = Test-BaselineControlCoverage -CatalogPath $script:CatalogPath -Observed $registry -Subject 'registry'

            # Assert
            (Get-CoverageFold -Coverage $coverage) |
                Should -BeExactly 'False|missing=EXO-006|unknown=|duplicated=' `
                    -Because 'a catalogued control with no registry entry is never collected, so the run reports every control it does know about as passing and the gate opens'
        }

        It 'refuses a registry that registers a control the catalog does not declare' {
            # Arrange
            $extended = @(ConvertTo-ControlDefinition -Registry (Get-BaselineControlRegistry -Profile Historical)) + @(
                [ordered]@{
                    ControlId         = 'EXO-099'
                    Priority          = 'MUST'
                    ApplicableProfile = @('Native', 'Gateway')
                    Prerequisite      = @('EOP')
                    Collector         = 'Get-UndocumentedEvidence'
                    Evaluator         = 'Test-UndocumentedControl'
                    EvidencePath      = 'exchangeOnline.undocumented'
                }
            )
            $registry = New-BaselineControlRegistry -Definition $extended

            # Act
            $coverage = Test-BaselineControlCoverage -CatalogPath $script:CatalogPath -Observed $registry -Subject 'registry'

            # Assert
            (Get-CoverageFold -Coverage $coverage) |
                Should -BeExactly 'False|missing=|unknown=EXO-099|duplicated=' `
                    -Because 'a control nobody catalogued was never reviewed or licensed, and it blocks a release on a rule the customer never agreed to'
        }

        It 'refuses a catalog that declares a control the registry does not register' {
            # Arrange
            $extendedCatalog = New-CatalogFixture -Name 'extended-shipped-catalog.md' -Line (
                @(Get-Content -LiteralPath $script:CatalogPath) + @(New-CatalogControlRow -ControlId 'EXO-013'))

            # Act
            $coverage = Test-BaselineControlCoverage -CatalogPath $extendedCatalog -Observed (Get-BaselineControlRegistry -Profile Historical) -Subject 'registry'

            # Assert
            (Get-CoverageFold -Coverage $coverage) |
                Should -BeExactly 'False|missing=EXO-013|unknown=|duplicated=' `
                    -Because 'documenting a control without registering it ships a promise the tooling never keeps, and the gap is visible only to whoever reads both files side by side'
        }
    }

    Context 'Positive: the shipped registry covers the shipped catalog exactly' {

        It 'reports satisfied coverage of the shipped catalog by the shipped registry' {
            # Arrange
            $registry = Get-BaselineControlRegistry -Profile Historical

            # Act
            $coverage = Test-BaselineControlCoverage -CatalogPath $script:CatalogPath -Observed $registry -Subject 'registry'

            # Assert
            (Get-CoverageFold -Coverage $coverage) |
                Should -BeExactly 'True|missing=|unknown=|duplicated=' `
                    -Because 'the catalog a reviewer reads and the registry the run executes must name the same controls, or the document and the tool disagree about what the tenant was held to'
        }
    }
}
