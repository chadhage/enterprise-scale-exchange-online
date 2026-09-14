BeforeAll {
    $script:sampleRoot = Split-Path -Parent $PSScriptRoot
    $script:configPath = Join-Path $sampleRoot 'config\exchange-online-secure-baseline.json'
    $script:configText = Get-Content -Path $configPath -Raw
    $script:config = $configText | ConvertFrom-Json
}

Describe 'Secure Exchange Online sample configuration' {
    It 'is valid JSON' {
        { $script:configText | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
    }

    It 'uses explicit administrator placeholders' {
        $tokens = [regex]::Matches($script:configText, '__ADMIN_REQUIRED:[A-Z0-9_]+__')
        $tokens.Count | Should -BeGreaterThan 10
        $script:configText | Should -Not -Match '\{\{[^}]+\}\}'
    }

    It 'places array placeholders in replaceable singleton arrays' {
        foreach ($tokenName in @(
            'CURRENT_PROOFPOINT_PUBLIC_IP_OR_CIDR',
            'ALL_NON_MICROSOFT_PUBLIC_HOP_IPS_OR_CIDRS',
            'PROOFPOINT_OUTBOUND_SMART_HOST_FQDN'
        )) {
            $pattern = '\[\s*"__ADMIN_REQUIRED:' + $tokenName + '__"\s*\]'
            $script:configText | Should -Match $pattern
        }
    }

    It 'uses constrained Proofpoint connectors and Enhanced Filtering' {
        $mailFlow = $script:config.desiredState.mailFlow
        $mailFlow.proofpointInboundConnector.connectorType | Should -Be 'Partner'
        $mailFlow.proofpointInboundConnector.requireTls | Should -BeTrue
        $mailFlow.proofpointInboundConnector.restrictDomainsToIpAddresses | Should -BeTrue
        $mailFlow.enhancedFiltering.enabled | Should -BeTrue
        $mailFlow.prohibitedBypass.sclMinusOneTransportRules | Should -BeFalse
    }

    It 'enables Microsoft managed protection profiles' {
        $mdo = $script:config.desiredState.defenderForOffice365
        $mdo.standardPreset.enabled | Should -BeTrue
        $mdo.strictPreset.enabled | Should -BeTrue
        $mdo.safeAttachmentsForSharePointOneDriveTeams | Should -BeTrue
        $mdo.safeDocuments.allowBypass | Should -BeFalse
    }

    It 'keeps Abnormal API based and out of SMTP routing' {
        $abnormal = $script:config.desiredState.abnormalSecurity
        $abnormal.integrationMode | Should -Be 'Microsoft API post-delivery'
        $abnormal.smtpConnectorCreated | Should -BeFalse
        $abnormal.transportBypassCreated | Should -BeFalse
    }

    It 'defines centralized monitoring and retention' {
        $monitoring = $script:config.desiredState.centralMonitoring
        $monitoring.siemIntegration.enabled | Should -BeTrue
        $monitoring.siemIntegration.minimumRetentionDays | Should -BeGreaterOrEqual 180
        $monitoring.siemIntegration.sources.Count | Should -BeGreaterOrEqual 6
    }

    It 'disables high-risk legacy paths' {
        $exchange = $script:config.desiredState.exchangeOnline
        $exchange.smtpClientAuthenticationDisabled | Should -BeTrue
        $exchange.legacyAuthenticationBlockedByConditionalAccess | Should -BeTrue
        $exchange.automaticExternalForwarding | Should -Be 'Off'
    }
}