BeforeAll {
    $script:protectionRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:protectionModule = Import-Module (Join-Path $script:protectionRoot 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -PassThru
    function Invoke-ProtectionQuarantineDefinitions {
        param([string]$PolicyName)
        $configuration = Get-Content (Join-Path $script:protectionRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
        & $script:protectionModule {
            param($configuration, $policyName)
            function Get-HostedContentFilterPolicy { [CmdletBinding()]param() @{ Identity = $policyName; Name = $policyName } }
            function Get-MalwareFilterPolicy { [CmdletBinding()]param() @{ Identity = $policyName; Name = $policyName } }
            function Get-AntiPhishPolicy { [CmdletBinding()]param() @{ Identity = $policyName; Name = $policyName } }
            @(Get-ApprovedAdapterDefinitions @{ Configuration = $configuration; Parameters = @{} } @('Quarantine'))
        } $configuration $PolicyName
    }
}

Describe 'EXR-010 supported quarantine mutation surfaces' {
    It 'never emits individual mutations for <PolicyName>' -ForEach @(
        @{ PolicyName = 'Standard Preset Security Policy' }
        @{ PolicyName = 'Strict Preset Security Policy' }
        @{ PolicyName = 'Built-In Protection Policy' }
    ) {
        # Arrange
        $forbidden = @('HostedContentFilterPolicy','MalwareFilterPolicy','AntiPhishPolicy')
        # Act
        $definitions = Invoke-ProtectionQuarantineDefinitions $PolicyName
        # Assert
        @($definitions | Where-Object { $_.Noun -in $forbidden }).Count | Should -Be 0
    }

    It 'does not send the anti-phishing spoof tag to a content filter policy' {
        # Arrange
        $policyName = 'Custom email policy'
        # Act
        $definitions = Invoke-ProtectionQuarantineDefinitions $policyName
        # Assert
        @($definitions | Where-Object { $_.Noun -eq 'HostedContentFilterPolicy' -and $_.Desired.ContainsKey('SpoofQuarantineTag') }).Count | Should -Be 0
    }

    It 'maps custom email quarantine tags to their supported policy families' {
        # Arrange
        $policyName = 'Custom email policy'
        # Act
        $definitions = Invoke-ProtectionQuarantineDefinitions $policyName
        # Assert
        $content = @($definitions | Where-Object Noun -eq HostedContentFilterPolicy)
        $malware = @($definitions | Where-Object Noun -eq MalwareFilterPolicy)
        $phishing = @($definitions | Where-Object Noun -eq AntiPhishPolicy)
        $content.Count | Should -Be 1
        $malware.Count | Should -Be 1
        $phishing.Count | Should -Be 1
        @($content[0].Desired.Keys).Count | Should -Be 5
        $malware[0].Desired.QuarantineTag | Should -BeExactly 'Baseline-AdminOnlyAccess'
        $phishing[0].Desired.SpoofQuarantineTag | Should -BeExactly 'Baseline-FullAccess'
    }
}