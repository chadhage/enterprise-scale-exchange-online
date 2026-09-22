#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:EvidenceScript = Join-Path $script:SampleRoot 'scripts\Test-ExchangeOnlineBaseline.ps1'
    $script:DeploymentScript = Join-Path $script:SampleRoot 'scripts\Deploy-ExchangeOnlineBaseline.ps1'
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts\ExchangeOnlineBaseline.Common.psm1'
    $script:ManifestPath = Join-Path $script:SampleRoot 'scripts\ExchangeOnlineBaseline.Common.psd1'
    Import-Module $script:ModulePath -Force -DisableNameChecking

    function Get-PpDispatchFold {
        param([string]$Path)
        $text = Get-Content $Path -Raw
        [pscustomobject]@{
            Text = $text
            ResultId = @([regex]::Matches($text, '(?m)[''"](PP-00[1-5])(?:\s|[''"])') | ForEach-Object { $_.Groups[1].Value })
        }
    }
}

Describe 'PP-006 profile orchestration' {
    It 'does not retain the misidentified Native PP-002 no-partner result' {
        # Arrange
        $dispatch = Get-PpDispatchFold $script:EvidenceScript
        # Act
        $misidentified = $dispatch.Text -match "PP-002 noUndeclaredPartnerInbound"
        # Assert
        $misidentified | Should -BeFalse
    }

    It 'does not emit inline or Manual PP evidence results' {
        # Arrange
        $dispatch = Get-PpDispatchFold $script:EvidenceScript
        # Act
        $manual = [regex]::Matches($dispatch.Text, '(?m)Add-Check\s+[''"]PP-00[1-5].*[''"]Manual[''"]')
        # Assert
        $manual.Count | Should -Be 0
        $dispatch.Text | Should -Not -Match 'Add-Result\s+[''"]PP-00[1-5]'
    }

    It 'exports every PP collector and evaluator from both public surfaces' {
        # Arrange
        $expected = @(
            'Get-GatewayInboundConnectorEvidence', 'Test-GatewayInboundConnectorControl',
            'Get-EnhancedFilteringEvidence', 'Test-EnhancedFilteringControl',
            'Get-GatewayOutboundConnectorEvidence', 'Test-GatewayOutboundConnectorControl',
            'Get-TrustedArcSealerEvidence', 'Test-TrustedArcSealerControl',
            'Get-PartnerInboundConnectorEvidence', 'Test-PartnerInboundConnectorControl'
        )
        $manifest = Import-PowerShellDataFile $script:ManifestPath
        $moduleText = Get-Content $script:ModulePath -Raw
        # Act
        $missing = @($expected | Where-Object { $_ -cnotin $manifest.FunctionsToExport -or $moduleText -notmatch "'$_'" })
        # Assert
        $missing | Should -BeNullOrEmpty
    }

    It 'dispatches trusted ARC only for Gateway and PP-005 only for Native' {
        # Arrange
        $evidenceText = Get-Content $script:EvidenceScript -Raw
        $deploymentText = Get-Content $script:DeploymentScript -Raw
        # Act
        $combined = $evidenceText + "`n" + $deploymentText
        # Assert
        $combined | Should -Match 'Get-TrustedArcSealerEvidence'
        $combined | Should -Match 'Test-TrustedArcSealerControl'
        $combined | Should -Match 'Get-PartnerInboundConnectorEvidence'
        $combined | Should -Match 'Test-PartnerInboundConnectorControl'
        $deploymentText | Should -Match 'Set-TrustedArcSealer'
    }

    It 'produces one complete non-Manual PP result set for each shipped profile' {
        # Arrange
        $registry = @(Get-BaselineControlRegistry -Profile Historical)[0]
        $gateway = @($registry | Where-Object { $_.ControlId -like 'PP-*' -and 'Gateway' -cin $_.ApplicableProfile })
        $native = @($registry | Where-Object { $_.ControlId -like 'PP-*' -and 'Native' -cin $_.ApplicableProfile })
        # Act
        $profileResult = [ordered]@{
            Gateway = @($gateway.ControlId | Sort-Object -Unique)
            Native = @($native.ControlId | Sort-Object -Unique)
        }
        # Assert
        $profileResult.Gateway | Should -Be @('PP-001', 'PP-002', 'PP-003', 'PP-004')
        $profileResult.Native | Should -Be @('PP-005')
        @($profileResult.Gateway + $profileResult.Native | Group-Object | Where-Object Count -ne 1) | Should -BeNullOrEmpty
    }
}