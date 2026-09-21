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
    $script:ExpectedCollector = @(
        'Get-AuditRetentionEvidence'
        'Get-DataLossPreventionEvidence'
        'Get-EDiscoveryReadinessEvidence'
        'Get-InformationRightsManagementEvidence'
        'Get-LitigationHoldEvidence'
        'Get-MailboxRetentionEvidence'
        'Get-SensitivityLabelEvidence'
    )
    $script:ExpectedEvaluator = @(
        'Test-AuditRetentionControl'
        'Test-DataLossPreventionControl'
        'Test-EDiscoveryReadinessControl'
        'Test-InformationRightsManagementControl'
        'Test-LitigationHoldControl'
        'Test-MailboxRetentionControl'
        'Test-SensitivityLabelControl'
    )
    $script:ExpectedControl = 1..7 | ForEach-Object { 'GOV-{0:d3}' -f $_ }

    function Get-GovernanceBlock {
        $text = Get-Content -LiteralPath $script:EvidenceScript -Raw
        $start = $text.IndexOf('# Purview governance orchestration:')
        $end = $text.IndexOf('# End Purview governance orchestration', $start + 1)
        if ($start -ge 0 -and $end -gt $start) { return $text.Substring($start, $end - $start) }

        $start = $text.IndexOf('if ($purviewLicensed)')
        $end = $text.IndexOf('$summary = [ordered]@{}', $start)
        if ($start -ge 0 -and $end -gt $start) { return $text.Substring($start, $end - $start) }
        return ''
    }

    function Get-GovernanceFold {
        $block = Get-GovernanceBlock
        [pscustomobject]@{
            Block = $block
            Collector = @([regex]::Matches($block, '(?m)\bGet-(AuditRetention|DataLossPrevention|MailboxRetention|LitigationHold|InformationRightsManagement|SensitivityLabel|EDiscoveryReadiness)Evidence\b') | ForEach-Object Value)
            Evaluator = @([regex]::Matches($block, '(?m)\bTest-(AuditRetention|DataLossPrevention|MailboxRetention|LitigationHold|InformationRightsManagement|SensitivityLabel|EDiscoveryReadiness)Control\b') | ForEach-Object Value)
            ResultId = @([regex]::Matches($block, '(?m)Add-Check\s+[''"](GOV-[0-9]{3})[^''"]*[''"]\s+\$[^\r\n]+\.Status\s+\$[^\r\n]+\.Reason') | ForEach-Object { $_.Groups[1].Value })
            AllId = @([regex]::Matches($block, 'GOV-[0-9]{3}') | ForEach-Object Value | Sort-Object -Unique)
            Manual = [regex]::Matches($block, '(?m)Add-Check\s+[''"]GOV-[0-9]{3}[^''"]*[''"]\s+[''"]Manual[''"]').Count
            NotEntitled = [regex]::Matches($block, '(?m)Add-Check\s+[''"]GOV-[0-9]{3}[^''"]*[''"]\s+[''"]NotEntitled[''"]').Count
            Inline = [regex]::Matches($block, '(?m)Add-Result\s+[''"]GOV-[0-9]{3}').Count
        }
    }
}

Describe 'GOV-008 sensitivity-label and eDiscovery configuration contract' {
    Context 'Negative: both profiles and the schema require concrete governance state' {
        It 'rejects a shipped profile without the complete sensitivity-label subtree' -ForEach @(
            'exchange-online-secure-baseline.json'
            'exchange-online-secure-baseline.microsoft-native.json'
        ) {
            # Arrange
            $profile = Get-Content -LiteralPath (Join-Path $script:SampleRoot 'config' $_) -Raw | ConvertFrom-Json -Depth 100

            # Act
            $actual = $profile.desiredState.governance.sensitivityLabels

            # Assert
            $actual.requiredServicePlan | Should -BeExactly 'E5 Compliance'
            @($actual.encryptionLabelNames) | Should -Be @('Confidential')
            @($actual.messagingTargets) | Should -Be @('__ADMIN_REQUIRED:SECURITY_OPERATIONS_MAILBOX__')
            $actual.maximumEvidenceAgeDays | Should -Be 7
        }

        It 'rejects a shipped profile without the complete eDiscovery subtree' -ForEach @(
            'exchange-online-secure-baseline.json'
            'exchange-online-secure-baseline.microsoft-native.json'
        ) {
            # Arrange
            $profile = Get-Content -LiteralPath (Join-Path $script:SampleRoot 'config' $_) -Raw | ConvertFrom-Json -Depth 100

            # Act
            $actual = $profile.desiredState.governance.eDiscovery

            # Assert
            $actual.requiredServicePlan | Should -BeExactly 'E5 Compliance'
            @($actual.caseOwners) | Should -Be @('__ADMIN_REQUIRED:EDISCOVERY_CASE_OWNER_UPN__')
            $actual.roleGroupIdentity | Should -BeExactly 'eDiscovery Manager'
            $actual.maximumAccessReviewAgeDays | Should -Be 90
            $actual.maximumEvidenceAgeDays | Should -Be 7
        }

        It 'rejects a schema that does not require both governance subtrees' {
            # Arrange
            $schema = Get-Content -LiteralPath $script:SchemaPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100
            $governance = $schema.properties.desiredState.properties.governance

            # Act
            $required = @($governance.required | Sort-Object)

            # Assert
            $required | Should -Contain 'sensitivityLabels'
            $required | Should -Contain 'eDiscovery'
            $governance.additionalProperties | Should -BeFalse
        }

        It 'rejects a schema that admits empty or incomplete sensitivity-label state' {
            # Arrange
            $schema = Get-Content -LiteralPath $script:SchemaPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100

            # Act
            $actual = $schema.properties.desiredState.properties.governance.properties.sensitivityLabels

            # Assert
            @($actual.required | Sort-Object) | Should -Be @('encryptionLabelNames', 'maximumEvidenceAgeDays', 'messagingTargets', 'requiredServicePlan')
            $actual.additionalProperties | Should -BeFalse
            $actual.properties.encryptionLabelNames.minItems | Should -Be 1
            $actual.properties.messagingTargets.minItems | Should -Be 1
        }

        It 'rejects a schema that admits empty or incomplete eDiscovery state' {
            # Arrange
            $schema = Get-Content -LiteralPath $script:SchemaPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100

            # Act
            $actual = $schema.properties.desiredState.properties.governance.properties.eDiscovery

            # Assert
            @($actual.required | Sort-Object) | Should -Be @('caseOwners', 'maximumAccessReviewAgeDays', 'maximumEvidenceAgeDays', 'requiredServicePlan', 'roleGroupIdentity')
            $actual.additionalProperties | Should -BeFalse
            $actual.properties.caseOwners.minItems | Should -Be 1
        }
    }

    Context 'Positive: one complete shipped governance configuration contract' {
        It 'defines both concrete governance subtrees in both profiles and the schema' {
            # Arrange
            $profiles = @($script:ProfilePath | ForEach-Object { Get-Content -LiteralPath $_ -Raw | ConvertFrom-Json -Depth 100 })
            $schema = Get-Content -LiteralPath $script:SchemaPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100

            # Act
            $profileSummary = @($profiles | ForEach-Object {
                    '{0}|{1}|{2}|{3}' -f $_.desiredState.governance.sensitivityLabels.encryptionLabelNames.Count,
                    $_.desiredState.governance.sensitivityLabels.messagingTargets.Count,
                    $_.desiredState.governance.eDiscovery.caseOwners.Count,
                    $_.desiredState.governance.eDiscovery.roleGroupIdentity
                })
            $required = @($schema.properties.desiredState.properties.governance.required | Sort-Object)

            # Assert
            $profileSummary | Should -Be @('1|1|1|eDiscovery Manager', '1|1|1|eDiscovery Manager')
            $required | Should -Contain 'sensitivityLabels'
            $required | Should -Contain 'eDiscovery'
        }
    }
}

Describe 'GOV-008 shared public operation surface' {
    Context 'Negative: every registered GOV operation is exported from both surfaces' {
        It 'rejects a missing GOV collector or evaluator export' {
            # Arrange
            $manifest = Import-PowerShellDataFile -LiteralPath $script:ManifestPath
            $moduleText = Get-Content -LiteralPath $script:ModulePath -Raw
            $exportStart = $moduleText.LastIndexOf('Export-ModuleMember -Function @(')
            $moduleExport = $moduleText.Substring($exportStart)
            $expected = @($script:ExpectedCollector + $script:ExpectedEvaluator | Sort-Object)

            # Act
            $manifestActual = @($manifest.FunctionsToExport | Where-Object { $_ -match '^(Get|Test)-(AuditRetention|DataLossPrevention|MailboxRetention|LitigationHold|InformationRightsManagement|SensitivityLabel|EDiscoveryReadiness)' } | Sort-Object)
            $moduleActual = @($expected | Where-Object { $moduleExport -match "'$([regex]::Escape($_))'" })

            # Assert
            $manifestActual | Should -Be $expected
            $moduleActual | Should -Be $expected
        }
    }

    Context 'Positive: one complete exported GOV operation surface' {
        It 'exports all seven registered collector and evaluator pairs from both declarations' {
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

Describe 'GOV-008 public Purview governance orchestration' {
    Context 'Negative: applicable governance results use each registered operation exactly once' {
        It 'rejects missing or duplicate GOV collectors' {
            # Arrange
            $fold = Get-GovernanceFold

            # Act
            $actual = @($fold.Collector | Sort-Object)

            # Assert
            $actual | Should -Be $script:ExpectedCollector
        }

        It 'rejects missing or duplicate GOV evaluators' {
            # Arrange
            $fold = Get-GovernanceFold

            # Act
            $actual = @($fold.Evaluator | Sort-Object)

            # Assert
            $actual | Should -Be $script:ExpectedEvaluator
        }

        It 'rejects missing, duplicate, or unknown GOV result identities' {
            # Arrange
            $fold = Get-GovernanceFold

            # Act
            $actual = @($fold.ResultId | Sort-Object)

            # Assert
            $actual | Should -Be $script:ExpectedControl
            $fold.AllId | Should -Be $script:ExpectedControl
        }

        It 'rejects Manual, NotEntitled, or inline GOV verdicts' {
            # Arrange
            $fold = Get-GovernanceFold

            # Act
            $forbidden = 'manual={0};notEntitled={1};inline={2};evaluated={3}' -f $fold.Manual, $fold.NotEntitled, $fold.Inline, $fold.Evaluator.Count

            # Assert
            $forbidden | Should -BeExactly 'manual=0;notEntitled=0;inline=0;evaluated=7'
        }

        It 'rejects a GOV control missing from the authoritative evidence map' {
            # Arrange
            $text = Get-Content -LiteralPath $script:EvidenceScript -Raw
            $start = $text.IndexOf('$observation = [ordered]@{')
            $end = $text.IndexOf("`n}", $start)
            $map = if ($start -ge 0 -and $end -gt $start) { $text.Substring($start, $end - $start) } else { '' }

            # Act
            $actual = @([regex]::Matches($map, "'(?<id>GOV-[0-9]{3})'") | ForEach-Object { $_.Groups['id'].Value } | Sort-Object)

            # Assert
            $actual | Should -Be $script:ExpectedControl
        }
    }

    Context 'Positive: one fully entitled complete GOV-001-through-GOV-007 fixture' {
        It 'collects, evaluates, maps, and emits every applicable GOV result exactly once' {
            # Arrange
            $fold = Get-GovernanceFold
            $text = Get-Content -LiteralPath $script:EvidenceScript -Raw
            $start = $text.IndexOf('$observation = [ordered]@{')
            $end = $text.IndexOf("`n}", $start)
            $map = $text.Substring($start, $end - $start)

            # Act
            $mapped = @([regex]::Matches($map, "'(?<id>GOV-[0-9]{3})'") | ForEach-Object { $_.Groups['id'].Value } | Sort-Object)
            $summary = 'collect={0};evaluate={1};result={2};map={3};manual={4};notEntitled={5};inline={6}' -f `
                (($fold.Collector | Sort-Object) -join ','),
                (($fold.Evaluator | Sort-Object) -join ','),
                (($fold.ResultId | Sort-Object) -join ','),
                ($mapped -join ','),
                $fold.Manual,
                $fold.NotEntitled,
                $fold.Inline

            # Assert
            $summary | Should -BeExactly ('collect={0};evaluate={1};result={2};map={2};manual=0;notEntitled=0;inline=0' -f `
                    ($script:ExpectedCollector -join ','),
                    ($script:ExpectedEvaluator -join ','),
                    ($script:ExpectedControl -join ','))
        }
    }
}