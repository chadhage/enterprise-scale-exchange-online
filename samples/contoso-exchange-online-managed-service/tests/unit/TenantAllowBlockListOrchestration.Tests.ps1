#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:EvidenceCommandPath = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ExpectedMdoOperation = @(
        'MDO-001|Native+Gateway|Get-StandardPresetEvidence|Test-StandardPresetControl'
        'MDO-002|Native+Gateway|Get-StrictPresetEvidence|Test-StrictPresetControl'
        'MDO-003|Native+Gateway|Get-BuiltInProtectionEvidence|Test-BuiltInProtectionControl'
        'MDO-004|Native+Gateway|Get-SafeAttachmentsEvidence|Test-SafeAttachmentsControl'
        'MDO-005|Native+Gateway|Get-SafeDocumentsEvidence|Test-SafeDocumentsControl'
        'MDO-006|Native+Gateway|Get-ReportSubmissionEvidence|Test-ReportSubmissionControl'
        'MDO-007|Native+Gateway|Get-TenantAllowBlockListEvidence|Test-TenantAllowBlockListControl'
        'MDO-008|Native+Gateway|Get-QuarantinePolicyEvidence|Test-QuarantinePolicyControl'
        'MDO-009|Native+Gateway|Get-PriorityAccountEvidence|Test-PriorityAccountControl'
    )

    function Get-MdoOperationFold {
        param([object[]]$Registry)

        return @($Registry |
                Where-Object { $_.ControlId -like 'MDO-*' } |
                ForEach-Object {
                    '{0}|{1}|{2}|{3}' -f $_.ControlId, (@($_.ApplicableProfile) -join '+'), $_.Collector, $_.Evaluator
                })
    }

    function Get-Mdo007ScriptFold {
        param([string]$Text)

        $start = $Text.IndexOf("Add-Check  'MDO-006 userSubmissions'")
        $end = $Text.IndexOf("Add-Result 'MDO-008 quarantineNotificationCadence'")
        if ($start -ge 0) { $start = $Text.IndexOf("`n", $start) + 1 }
        $block = if ($start -gt 0 -and $end -gt $start) { $Text.Substring($start, $end - $start) } else { '' }

        return [pscustomobject]@{
            Block = $block
            CollectorCount = [regex]::Matches($block, '(?m)\bGet-TenantAllowBlockListEvidence\b').Count
            EvaluatorCount = [regex]::Matches($block, '(?m)\bTest-TenantAllowBlockListControl\b').Count
            ManualCount = [regex]::Matches($block, '(?m)Add-Check\s+''MDO-007[^'']*''\s+''Manual''').Count
            InlineCount = [regex]::Matches($block, '(?m)Add-Result\s+''MDO-007').Count
            ResultControlId = @([regex]::Matches($block, '(?m)Add-Check\s+''(MDO-[0-9]{3})[^'']*''\s+\$tenantAllowBlockListResult\.Status\s+\$tenantAllowBlockListResult\.Reason') | ForEach-Object { $_.Groups[1].Value })
        }
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'MDO-009 TABL public orchestration and phase-exit parity' {
    Context 'Negative: MDO-007 is emitted only by its declared operations' {
        It 'rejects a literal Manual MDO-007 result' {
            # Arrange
            $text = Get-Content -LiteralPath $script:EvidenceCommandPath -Raw

            # Act
            $fold = Get-Mdo007ScriptFold -Text $text

            # Assert
            $fold.ManualCount | Should -Be 0
        }

        It 'rejects a missing or repeated MDO-007 collector call' {
            # Arrange
            $text = Get-Content -LiteralPath $script:EvidenceCommandPath -Raw

            # Act
            $fold = Get-Mdo007ScriptFold -Text $text

            # Assert
            $fold.CollectorCount | Should -Be 1
        }

        It 'rejects a missing or repeated MDO-007 evaluator call' {
            # Arrange
            $text = Get-Content -LiteralPath $script:EvidenceCommandPath -Raw

            # Act
            $fold = Get-Mdo007ScriptFold -Text $text

            # Assert
            $fold.EvaluatorCount | Should -Be 1
        }

        It 'rejects inline truthiness instead of the evaluator status' {
            # Arrange
            $text = Get-Content -LiteralPath $script:EvidenceCommandPath -Raw

            # Act
            $fold = Get-Mdo007ScriptFold -Text $text

            # Assert
            $fold.InlineCount | Should -Be 0
            $fold.ResultControlId | Should -Be @('MDO-007')
        }

        It 'passes collection and evaluation Error through without converting it to Pass or Fail' {
            # Arrange
            $text = Get-Content -LiteralPath $script:EvidenceCommandPath -Raw

            # Act
            $fold = Get-Mdo007ScriptFold -Text $text
            $statusProjection = [regex]::Matches(
                $fold.Block,
                '(?m)Add-Check\s+''MDO-007 tenantAllowBlockList''\s+\$tenantAllowBlockListResult\.Status\s+\$tenantAllowBlockListResult\.Reason'
            )

            # Assert
            $statusProjection.Count | Should -Be 1
        }

        It 'attributes TABL drift only to MDO-007' {
            # Arrange
            $text = Get-Content -LiteralPath $script:EvidenceCommandPath -Raw

            # Act
            $fold = Get-Mdo007ScriptFold -Text $text
            $attributedControl = @([regex]::Matches($fold.Block, '(?m)MDO-[0-9]{3}') | ForEach-Object Value | Sort-Object -Unique)

            # Assert
            $attributedControl | Should -Be @('MDO-007')
            $fold.ResultControlId | Should -Be @('MDO-007')
        }
    }

    Context 'Negative: every applicable MDO operation has exact identity and scope' {
        It 'rejects a missing, duplicate, unknown, wrongly scoped or wrongly operated MDO declaration' {
            # Arrange
            $registry = @(Get-BaselineControlRegistry -Profile Historical)[0]

            # Act
            $actual = @(Get-MdoOperationFold -Registry $registry)
            $duplicate = @($actual | Group-Object | Where-Object Count -ne 1)

            # Assert
            $actual | Should -Be $script:ExpectedMdoOperation
            $duplicate | Should -BeNullOrEmpty
        }
    }

    Context 'Positive: one complete compliant MDO result set' {
        It 'emits every applicable MDO identity, scope and operation once with MDO-007 evaluated' {
            # Arrange
            $registry = @(Get-BaselineControlRegistry -Profile Historical)[0]
            $text = Get-Content -LiteralPath $script:EvidenceCommandPath -Raw

            # Act
            $operation = @(Get-MdoOperationFold -Registry $registry)
            $result = @($operation | ForEach-Object { "$_|Pass" })
            $fold = Get-Mdo007ScriptFold -Text $text

            # Assert
            $result | Should -Be @($script:ExpectedMdoOperation | ForEach-Object { "$_|Pass" })
            ('collector={0};evaluator={1};manual={2};inline={3};result={4}' -f
                $fold.CollectorCount,
                $fold.EvaluatorCount,
                $fold.ManualCount,
                $fold.InlineCount,
                ($fold.ResultControlId -join ',')) |
                Should -BeExactly 'collector=1;evaluator=1;manual=0;inline=0;result=MDO-007'
        }
    }
}
