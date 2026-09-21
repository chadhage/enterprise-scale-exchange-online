#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:EvidenceScript = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:ManifestPath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psd1'
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
    $script:ProfilePath = @(
        (Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json')
        (Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.microsoft-native.json')
    )
    $script:ExpectedControl = @('MON-001', 'MON-002', 'MON-003', 'OPS-001', 'OPS-002')
    $script:ExpectedCollector = @('Get-ChangeSafetyEvidence', 'Get-DriftEvidenceEvidence', 'Get-IncidentExerciseEvidence', 'Get-TelemetrySourceEvidence', 'Get-UnifiedAuditEvidence')
    $script:ExpectedEvaluator = @('Test-ChangeSafetyControl', 'Test-DriftEvidenceControl', 'Test-IncidentExerciseControl', 'Test-TelemetrySourceControl', 'Test-UnifiedAuditControl')

    function Get-MonitoringOperationsBlock {
        $text = Get-Content -LiteralPath $script:EvidenceScript -Raw
        $start = $text.IndexOf('# MON/OPS orchestration:')
        $end = $text.IndexOf('# End MON/OPS orchestration', $start + 1)
        if ($start -ge 0 -and $end -gt $start) { return $text.Substring($start, $end - $start) }
        return ''
    }

    function Get-MonitoringOperationsFold {
        $block = Get-MonitoringOperationsBlock
        [pscustomobject]@{
            Block = $block
            Collector = @([regex]::Matches($block, '(?m)\bGet-(TelemetrySource|UnifiedAudit|DriftEvidence|ChangeSafety|IncidentExercise)Evidence\b') | ForEach-Object Value)
            Evaluator = @([regex]::Matches($block, '(?m)\bTest-(TelemetrySource|UnifiedAudit|DriftEvidence|ChangeSafety|IncidentExercise)Control\b') | ForEach-Object Value)
            ResultId = @([regex]::Matches($block, '(?m)Add-Check\s+[''"](MON|OPS)-[0-9]{3}[^''"]*[''"]\s+\$[^\r\n]+\.Status\s+\$[^\r\n]+\.Reason') | ForEach-Object { $_.Value -replace '^.*?((?:MON|OPS)-[0-9]{3}).*$', '$1' })
            AllId = @([regex]::Matches($block, '(?:MON|OPS)-[0-9]{3}') | ForEach-Object Value | Sort-Object -Unique)
            Manual = [regex]::Matches($block, '(?m)Add-Check\s+[''"](?:MON|OPS)-[0-9]{3}[^''"]*[''"]\s+[''"]Manual[''"]').Count
            Inline = [regex]::Matches($block, '(?m)Add-Result\s+[''"](?:MON|OPS)-[0-9]{3}').Count
        }
    }
}

Describe 'OPS-002 incident-exercise configuration contract' {
    Context 'Negative: both profiles and schema require a concrete quarterly contract' {
        It 'rejects a shipped profile without complete incident-exercise desired state' -ForEach @(
            'exchange-online-secure-baseline.json'
            'exchange-online-secure-baseline.microsoft-native.json'
        ) {
            # Arrange
            $profile = Get-Content -LiteralPath (Join-Path $script:SampleRoot 'config' $_) -Raw | ConvertFrom-Json -Depth 100

            # Act
            $actual = $profile.desiredState.operations.incidentExercise

            # Assert
            $actual.requiredServicePlan | Should -BeExactly 'MDO P2'
            $actual.frequencyDays | Should -Be 90
            @($actual.exerciseTypes) | Should -Be @('PhishingSimulation', 'RemediationValidation')
            @($actual.owners).Count | Should -BeGreaterThan 0
            $actual.requireTrackedActions | Should -BeTrue
            $actual.maximumEvidenceAgeDays | Should -Be 7
        }

        It 'rejects a schema that admits an incomplete incident-exercise contract' {
            # Arrange
            $schema = Get-Content -LiteralPath $script:SchemaPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100

            # Act
            $operations = $schema.properties.desiredState.properties.operations
            $actual = $operations.properties.incidentExercise

            # Assert
            @($operations.required) | Should -Contain 'incidentExercise'
            $operations.additionalProperties | Should -BeFalse
            @($actual.required | Sort-Object) | Should -Be @('exerciseTypes', 'frequencyDays', 'maximumEvidenceAgeDays', 'owners', 'requiredServicePlan', 'requireTrackedActions')
            $actual.additionalProperties | Should -BeFalse
            $actual.properties.frequencyDays.maximum | Should -Be 90
            $actual.properties.exerciseTypes.minItems | Should -Be 2
            $actual.properties.owners.minItems | Should -Be 1
        }
    }

    Context 'Positive: one complete shipped incident-exercise contract' {
        It 'defines the quarterly exercise in both profiles and the schema' {
            # Arrange
            $profiles = @($script:ProfilePath | ForEach-Object { Get-Content -LiteralPath $_ -Raw | ConvertFrom-Json -Depth 100 })
            $schema = Get-Content -LiteralPath $script:SchemaPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100

            # Act
            $profileSummary = @($profiles | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.desiredState.operations.incidentExercise.requiredServicePlan, $_.desiredState.operations.incidentExercise.frequencyDays, $_.desiredState.operations.incidentExercise.exerciseTypes.Count, $_.desiredState.operations.incidentExercise.owners.Count })
            $required = @($schema.properties.desiredState.properties.operations.required)

            # Assert
            $profileSummary | Should -Be @('MDO P2|90|2|2', 'MDO P2|90|2|2')
            $required | Should -Contain 'incidentExercise'
        }
    }
}

Describe 'MON-004 shared public operation surface' {
    Context 'Negative: every MON and OPS operation is exported from both declarations' {
        It 'rejects a missing MON or OPS collector/evaluator export' {
            # Arrange
            $manifest = Import-PowerShellDataFile -LiteralPath $script:ManifestPath
            $moduleText = Get-Content -LiteralPath $script:ModulePath -Raw
            $exportText = $moduleText.Substring($moduleText.LastIndexOf('Export-ModuleMember -Function @('))
            $expected = @($script:ExpectedCollector + $script:ExpectedEvaluator | Sort-Object)

            # Act
            $manifestActual = @($expected | Where-Object { $_ -cin @($manifest.FunctionsToExport) })
            $moduleActual = @($expected | Where-Object { $exportText -match "'$([regex]::Escape($_))'" })

            # Assert
            $manifestActual | Should -Be $expected
            $moduleActual | Should -Be $expected
        }
    }

    Context 'Positive: one complete exported MON/OPS operation surface' {
        It 'exports all five collector and evaluator pairs from both declarations' {
            # Arrange
            $manifest = Import-PowerShellDataFile -LiteralPath $script:ManifestPath
            $moduleText = Get-Content -LiteralPath $script:ModulePath -Raw
            $expected = @($script:ExpectedCollector + $script:ExpectedEvaluator | Sort-Object)

            # Act
            $manifestActual = @($expected | Where-Object { $_ -cin @($manifest.FunctionsToExport) })
            $moduleActual = @($expected | Where-Object { $moduleText.Substring($moduleText.LastIndexOf('Export-ModuleMember -Function @(')) -match "'$([regex]::Escape($_))'" })

            # Assert
            $manifestActual | Should -Be $expected
            $moduleActual | Should -Be $expected
        }
    }
}

Describe 'MON-004 public monitoring and operations orchestration' {
    Context 'Negative: every applicable result uses its registered operation exactly once' {
        It 'rejects missing or duplicate MON/OPS collectors' {
            # Arrange
            $fold = Get-MonitoringOperationsFold

            # Act
            $actual = @($fold.Collector | Sort-Object)

            # Assert
            $actual | Should -Be $script:ExpectedCollector
        }

        It 'rejects missing or duplicate MON/OPS evaluators' {
            # Arrange
            $fold = Get-MonitoringOperationsFold

            # Act
            $actual = @($fold.Evaluator | Sort-Object)

            # Assert
            $actual | Should -Be $script:ExpectedEvaluator
        }

        It 'rejects missing, duplicate, or unknown MON/OPS result identities' {
            # Arrange
            $fold = Get-MonitoringOperationsFold

            # Act
            $actual = @($fold.ResultId | Sort-Object)

            # Assert
            $actual | Should -Be $script:ExpectedControl
            $fold.AllId | Should -Be $script:ExpectedControl
        }

        It 'rejects inline or Manual MON/OPS verdicts' {
            # Arrange
            $fold = Get-MonitoringOperationsFold

            # Act
            $actual = 'manual={0};inline={1};evaluated={2}' -f $fold.Manual, $fold.Inline, $fold.Evaluator.Count

            # Assert
            $actual | Should -BeExactly 'manual=0;inline=0;evaluated=5'
        }

        It 'rejects a MON/OPS control missing from the authoritative evidence map' {
            # Arrange
            $text = Get-Content -LiteralPath $script:EvidenceScript -Raw
            $start = $text.IndexOf('$observation = [ordered]@{')
            $end = $text.IndexOf("`n}", $start)
            $map = if ($start -ge 0 -and $end -gt $start) { $text.Substring($start, $end - $start) } else { '' }

            # Act
            $actual = @([regex]::Matches($map, "'(?<id>(?:MON|OPS)-[0-9]{3})'") | ForEach-Object { $_.Groups['id'].Value } | Sort-Object)

            # Assert
            $actual | Should -Be $script:ExpectedControl
        }
    }

    Context 'Positive: one complete applicable MON-001-through-OPS-002 dispatch' {
        It 'collects, evaluates, maps, and emits every MON/OPS result exactly once' {
            # Arrange
            $fold = Get-MonitoringOperationsFold
            $text = Get-Content -LiteralPath $script:EvidenceScript -Raw
            $start = $text.IndexOf('$observation = [ordered]@{')
            $end = $text.IndexOf("`n}", $start)
            $map = $text.Substring($start, $end - $start)

            # Act
            $mapped = @([regex]::Matches($map, "'(?<id>(?:MON|OPS)-[0-9]{3})'") | ForEach-Object { $_.Groups['id'].Value } | Sort-Object)
            $actual = 'collect={0};evaluate={1};result={2};map={3};manual={4};inline={5}' -f (($fold.Collector | Sort-Object) -join ','), (($fold.Evaluator | Sort-Object) -join ','), (($fold.ResultId | Sort-Object) -join ','), ($mapped -join ','), $fold.Manual, $fold.Inline

            # Assert
            $actual | Should -BeExactly ('collect={0};evaluate={1};result={2};map={2};manual=0;inline=0' -f ($script:ExpectedCollector -join ','), ($script:ExpectedEvaluator -join ','), ($script:ExpectedControl -join ','))
        }
    }
}