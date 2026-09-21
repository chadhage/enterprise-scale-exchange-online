#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:EvidenceScript = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:EvidenceScript, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw ($errors | ForEach-Object Message | Join-String -Separator '; ') }
    $function = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -cin @(
                    'Resolve-CompleteControlRegistryOrchestration',
                    'Get-BaselineProfileExclusion',
                    'Invoke-BaselineControlRegistryExecution',
                    'Invoke-CompleteControlRegistryOrchestration'
                )
            }, $true))
    foreach ($definition in $function) { . ([scriptblock]::Create($definition.Extent.Text)) }

    function New-IntegrityRegistry {
        @(
            [pscustomobject]@{ ControlId = 'EXO-001'; Collector = 'Get-ExoOneEvidence'; Evaluator = 'Test-ExoOneControl' }
            [pscustomobject]@{ ControlId = 'PP-001'; Collector = 'Get-GatewayEvidence'; Evaluator = 'Test-GatewayControl' }
            [pscustomobject]@{ ControlId = 'PP-005'; Collector = 'Get-NativeEvidence'; Evaluator = 'Test-NativeControl' }
        )
    }

    function New-IntegrityProjection {
        param(
            [string]$ControlId,
            [ValidateSet('Evaluated', 'NotApplicable', 'Inline')]
            [string]$Kind = 'Evaluated',
            [string]$Status = 'Pass',
            [string]$Collector,
            [string]$Evaluator,
            [string]$EvidenceControlId = $ControlId,
            [string]$ResultControlId = $ControlId,
            [switch]$OmitEvidence,
            [switch]$OmitResult
        )

        $registryEntry = @(New-IntegrityRegistry | Where-Object ControlId -CEQ $ControlId)[0]
        if ([string]::IsNullOrWhiteSpace($Collector)) { $Collector = [string]$registryEntry.Collector }
        if ([string]::IsNullOrWhiteSpace($Evaluator)) { $Evaluator = [string]$registryEntry.Evaluator }
        $evidence = if ($OmitEvidence) { $null } else { [pscustomobject]@{ ControlId = $EvidenceControlId; Collected = $true } }
        $result = if ($OmitResult) { $null } else { [pscustomobject]@{ ControlId = $ResultControlId; Status = $Status; Evidence = $evidence } }

        [pscustomobject]@{
            ControlId = $ControlId
            Kind = $Kind
            Collector = $Collector
            Evaluator = $Evaluator
            Evidence = $evidence
            Result = $result
        }
    }

    function New-CompleteIntegrityProjection {
        @(
            New-IntegrityProjection -ControlId 'EXO-001'
            New-IntegrityProjection -ControlId 'PP-001'
            New-IntegrityProjection -ControlId 'PP-005' -Kind NotApplicable -Status NotApplicable
        )
    }

    function Invoke-IntegrityReconciliation {
        param([object[]]$Projection)

        Resolve-CompleteControlRegistryOrchestration `
            -CatalogControlId @('EXO-001', 'PP-001', 'PP-005') `
            -Registry (New-IntegrityRegistry) `
            -Projection $Projection
    }
}

Describe 'EVD-007 final catalog result and evidence integrity reconciliation' {
    Context 'Negative: every catalog control has one registry-produced evidence and result projection' {
        It 'refuses a catalog control whose projection is missing' {
            # Arrange
            $projection = @(New-CompleteIntegrityProjection | Where-Object ControlId -CNE 'PP-005')

            # Act
            $act = { Invoke-IntegrityReconciliation -Projection $projection }

            # Assert
            $act | Should -Throw -ExpectedMessage "RegistryProjectionMissing: catalog control 'PP-005' has no final projection."
        }

        It 'refuses a control projected more than once' {
            # Arrange
            $projection = @((New-CompleteIntegrityProjection) + @(New-IntegrityProjection -ControlId 'EXO-001'))

            # Act
            $act = { Invoke-IntegrityReconciliation -Projection $projection }

            # Assert
            $act | Should -Throw -ExpectedMessage "RegistryProjectionDuplicated: control 'EXO-001' has 2 final projections."
        }

        It 'refuses a projection for a control outside the catalog and registry' {
            # Arrange
            $projection = @((New-CompleteIntegrityProjection) + @([pscustomobject]@{
                        ControlId = 'EXO-999'; Kind = 'Evaluated'; Collector = 'Get-UnknownEvidence'; Evaluator = 'Test-UnknownControl'
                        Evidence = [pscustomobject]@{ ControlId = 'EXO-999'; Collected = $true }
                        Result = [pscustomobject]@{ ControlId = 'EXO-999'; Status = 'Pass' }
                    }))

            # Act
            $act = { Invoke-IntegrityReconciliation -Projection $projection }

            # Assert
            $act | Should -Throw -ExpectedMessage "UnknownRegistryProjection: control 'EXO-999' is not declared by both the catalog and registry."
        }

        It 'refuses an inline result that bypassed the registered evaluator' {
            # Arrange
            $projection = @(New-CompleteIntegrityProjection)
            $projection[0].Kind = 'Inline'

            # Act
            $act = { Invoke-IntegrityReconciliation -Projection $projection }

            # Assert
            $act | Should -Throw -ExpectedMessage "InlineRegistryResult: control 'EXO-001' did not come from its registered evaluator."
        }

        It 'refuses a literal Manual result' {
            # Arrange
            $projection = @(New-CompleteIntegrityProjection)
            $projection[0].Result.Status = 'Manual'

            # Act
            $act = { Invoke-IntegrityReconciliation -Projection $projection }

            # Assert
            $act | Should -Throw -ExpectedMessage "ManualRegistryResult: control 'EXO-001' ended with a literal Manual result."
        }

        It 'refuses evidence or a result identified as another control' {
            # Arrange
            $projection = @(New-CompleteIntegrityProjection)
            $projection[1].Evidence.ControlId = 'PP-005'

            # Act
            $act = { Invoke-IntegrityReconciliation -Projection $projection }

            # Assert
            $act | Should -Throw -ExpectedMessage "RegistryEvidenceMisidentified: projection 'PP-001' carries evidence for 'PP-005'."
        }

        It 'refuses a result identified as another control' {
            # Arrange
            $projection = @(New-CompleteIntegrityProjection)
            $projection[1].Result.ControlId = 'PP-005'

            # Act
            $act = { Invoke-IntegrityReconciliation -Projection $projection }

            # Assert
            $act | Should -Throw -ExpectedMessage "RegistryResultMisidentified: projection 'PP-001' carries a result for 'PP-005'."
        }

        It 'refuses a projection attributed to a collector or evaluator other than the registered pair' {
            # Arrange
            $projection = @(New-CompleteIntegrityProjection)
            $projection[0].Evaluator = 'Test-SomeOtherControl'

            # Act
            $act = { Invoke-IntegrityReconciliation -Projection $projection }

            # Assert
            $act | Should -Throw -ExpectedMessage "RegistryEvaluatorMisidentified: control 'EXO-001' names 'Test-SomeOtherControl', expected 'Test-ExoOneControl'."
        }

        It 'refuses a partial projection with no evidence record' {
            # Arrange
            $projection = @(New-CompleteIntegrityProjection)
            $projection[0] = New-IntegrityProjection -ControlId 'EXO-001' -OmitEvidence

            # Act
            $act = { Invoke-IntegrityReconciliation -Projection $projection }

            # Assert
            $act | Should -Throw -ExpectedMessage "RegistryEvidenceMissing: control 'EXO-001' has no final evidence record."
        }

        It 'refuses a partial projection with no result record' {
            # Arrange
            $projection = @(New-CompleteIntegrityProjection)
            $projection[0] = New-IntegrityProjection -ControlId 'EXO-001' -OmitResult

            # Act
            $act = { Invoke-IntegrityReconciliation -Projection $projection }

            # Assert
            $act | Should -Throw -ExpectedMessage "RegistryResultMissing: control 'EXO-001' has no final result."
        }
    }

    Context 'Positive: one complete reconciliation across both shipped profiles' {
        It 'returns one catalog-ordered evidence record and result per control for Gateway and Native' {
            # Arrange
            $registry = New-IntegrityRegistry
            $registry[0] | Add-Member ApplicableProfile @('Native', 'Gateway')
            $registry[1] | Add-Member ApplicableProfile @('Gateway')
            $registry[2] | Add-Member ApplicableProfile @('Native')
            $invocation = @{}
            $resolver = {
                param($Name)
                switch ($Name) {
                    'Get-ExoOneEvidence' { return { $invocation['Get-ExoOneEvidence']++; [pscustomobject]@{ ControlId = 'EXO-001'; Collected = $true } } }
                    'Test-ExoOneControl' { return { param($Evidence) $invocation['Test-ExoOneControl']++; [pscustomobject]@{ ControlId = 'EXO-001'; Status = 'Pass' } } }
                    'Get-GatewayEvidence' { return { $invocation['Get-GatewayEvidence']++; [pscustomobject]@{ ControlId = 'PP-001'; Collected = $true } } }
                    'Test-GatewayControl' { return { param($Evidence) $invocation['Test-GatewayControl']++; [pscustomobject]@{ ControlId = 'PP-001'; Status = 'Pass' } } }
                    'Get-NativeEvidence' { return { $invocation['Get-NativeEvidence']++; [pscustomobject]@{ ControlId = 'PP-005'; Collected = $true } } }
                    'Test-NativeControl' { return { param($Evidence) $invocation['Test-NativeControl']++; [pscustomobject]@{ ControlId = 'PP-005'; Status = 'Pass' } } }
                }
            }

            # Act
            $actual = @('Gateway', 'Native' | ForEach-Object {
                    $resolved = Invoke-CompleteControlRegistryOrchestration `
                        -CatalogControlId @('EXO-001', 'PP-001', 'PP-005') `
                        -Registry $registry -SelectedProfile $_ -CommandResolver $resolver
                    '{0}|{1}' -f `
                        (@($resolved.Evidence | ForEach-Object ControlId) -join ','),
                        (@($resolved.Result | ForEach-Object { '{0}:{1}' -f $_.ControlId, $_.Status }) -join ',')
                })

            # Assert
            $actual | Should -Be @(
                'EXO-001,PP-001,PP-005|EXO-001:Pass,PP-001:Pass,PP-005:NotApplicable'
                'EXO-001,PP-001,PP-005|EXO-001:Pass,PP-001:NotApplicable,PP-005:Pass'
            )
            @($invocation.Keys | Sort-Object | ForEach-Object { "$_=$($invocation[$_])" }) -join '|' |
                Should -BeExactly 'Get-ExoOneEvidence=2|Get-GatewayEvidence=1|Get-NativeEvidence=1|Test-ExoOneControl=2|Test-GatewayControl=1|Test-NativeControl=1'
        }
    }
}