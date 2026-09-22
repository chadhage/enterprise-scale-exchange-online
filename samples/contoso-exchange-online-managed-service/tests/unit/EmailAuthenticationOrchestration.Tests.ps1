#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:EvidenceScript = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'

    function Get-AuthenticationBlock {
        $text = Get-Content -LiteralPath $script:EvidenceScript -Raw
        $start = $text.IndexOf('# Email authentication orchestration:')
        $end = $text.IndexOf('$ppResult = @()', $start)
        if ($start -lt 0 -or $end -le $start) { return '' }
        return $text.Substring($start, $end - $start)
    }

    function Get-AuthenticationFold {
        $block = Get-AuthenticationBlock
        [pscustomobject]@{
            Block = $block
            Collector = @([regex]::Matches($block, '(?m)\bGet-(Dkim|Spf|Dmarc)Evidence\b') | ForEach-Object Value)
            Evaluator = @([regex]::Matches($block, '(?m)\bTest-(Dkim|Spf|Dmarc)Control\b') | ForEach-Object Value)
            ResultId = @([regex]::Matches($block, '(?m)Add-Check\s+[''"](AUTH-[0-9]{3})[^''"]*[''"]\s+\$[^\r\n]+\.Status\s+\$[^\r\n]+\.Reason') | ForEach-Object { $_.Groups[1].Value })
            AllId = @([regex]::Matches($block, 'AUTH-[0-9]{3}') | ForEach-Object Value | Sort-Object -Unique)
            Manual = [regex]::Matches($block, '(?m)Add-Check\s+[''"]AUTH-[0-9]{3}[^''"]*[''"]\s+[''"]Manual[''"]').Count
            Inline = [regex]::Matches($block, '(?m)Add-Result\s+[''"]AUTH-[0-9]{3}').Count
        }
    }
}

Describe 'AUTH-004 public email-authentication orchestration' {
    Context 'Negative: public results fail closed through only their registered operations' {
        It 'rejects a missing or duplicate AUTH collector' {
            # Arrange
            $fold = Get-AuthenticationFold

            # Act
            $actual = @($fold.Collector | Sort-Object)

            # Assert
            $actual | Should -Be @('Get-DkimEvidence', 'Get-DmarcEvidence', 'Get-SpfEvidence')
        }

        It 'rejects a missing or duplicate AUTH evaluator' {
            # Arrange
            $fold = Get-AuthenticationFold

            # Act
            $actual = @($fold.Evaluator | Sort-Object)

            # Assert
            $actual | Should -Be @('Test-DkimControl', 'Test-DmarcControl', 'Test-SpfControl')
        }

        It 'rejects missing, duplicate, or unknown AUTH result identities' {
            # Arrange
            $fold = Get-AuthenticationFold

            # Act
            $actual = @($fold.ResultId | Sort-Object)

            # Assert
            $actual | Should -Be @('AUTH-001', 'AUTH-002', 'AUTH-003')
            $fold.AllId | Should -Be @('AUTH-001', 'AUTH-002', 'AUTH-003')
        }

        It 'rejects literal Manual AUTH results' {
            # Arrange
            $fold = Get-AuthenticationFold

            # Act
            $manual = $fold.Manual

            # Assert
            $manual | Should -Be 0
        }

        It 'rejects inline AUTH truthiness verdicts' {
            # Arrange
            $fold = Get-AuthenticationFold

            # Act
            $inline = $fold.Inline

            # Assert
            $inline | Should -Be 0
        }
    }

    Context 'Positive: one complete evaluated AUTH result set' {
        It 'collects, evaluates, and projects AUTH-001 through AUTH-003 exactly once' {
            # Arrange
            $fold = Get-AuthenticationFold

            # Act
            $summary = 'collect={0};evaluate={1};result={2};manual={3};inline={4}' -f `
                (($fold.Collector | Sort-Object) -join ','),
                (($fold.Evaluator | Sort-Object) -join ','),
                (($fold.ResultId | Sort-Object) -join ','),
                $fold.Manual,
                $fold.Inline

            # Assert
            $summary | Should -BeExactly 'collect=Get-DkimEvidence,Get-DmarcEvidence,Get-SpfEvidence;evaluate=Test-DkimControl,Test-DmarcControl,Test-SpfControl;result=AUTH-001,AUTH-002,AUTH-003;manual=0;inline=0'
        }
    }
}