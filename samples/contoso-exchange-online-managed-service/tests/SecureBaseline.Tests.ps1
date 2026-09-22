BeforeAll {
    $script:sampleRoot = Split-Path -Parent $PSScriptRoot
    $script:gatewayPath = Join-Path $sampleRoot 'config\exchange-online-secure-baseline.json'
    $script:nativePath = Join-Path $sampleRoot 'config\exchange-online-secure-baseline.microsoft-native.json'
    $script:gatewayText = Get-Content -Path $gatewayPath -Raw
    $script:nativeText = Get-Content -Path $nativePath -Raw
    $script:gateway = $gatewayText | ConvertFrom-Json
    $script:native = $nativeText | ConvertFrom-Json
    $script:profiles = @(
        @{ Name = 'gateway'; Config = $script:gateway; Text = $script:gatewayText }
        @{ Name = 'native'; Config = $script:native; Text = $script:nativeText }
    )
}

Describe 'Baseline configuration hygiene' {
    It 'is valid JSON in both profiles' {
        { $script:gatewayText | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
        { $script:nativeText | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
    }

    It 'uses explicit administrator placeholders' {
        foreach ($item in $script:profiles) {
            $tokens = [regex]::Matches($item.Text, '__ADMIN_REQUIRED:[A-Z0-9_]+__')
            $tokens.Count | Should -BeGreaterThan 10 -Because "profile $($item.Name) must not ship real values"
            $item.Text | Should -Not -Match '\{\{[^}]+\}\}'
        }
    }

    It 'declares a deployment profile and a licence tier' {
        $script:gateway.metadata.deploymentProfile | Should -Be 'ThirdPartyGateway'
        $script:native.metadata.deploymentProfile | Should -Be 'MicrosoftNative'
        foreach ($item in $script:profiles) {
            $item.Config.licensing.messagingTier | Should -BeIn @('EOP', 'MDO_P1', 'MDO_P2')
            $item.Config.licensing.complianceTier | Should -BeIn @('None', 'E3', 'E5Compliance')
        }
    }

    It 'places array placeholders in replaceable singleton arrays' {
        foreach ($tokenName in @(
            'CURRENT_PROOFPOINT_PUBLIC_IP_OR_CIDR',
            'ALL_NON_MICROSOFT_PUBLIC_HOP_IPS_OR_CIDRS',
            'PROOFPOINT_OUTBOUND_SMART_HOST_FQDN'
        )) {
            $pattern = '\[\s*"__ADMIN_REQUIRED:' + $tokenName + '__"\s*\]'
            $script:gatewayText | Should -Match $pattern
        }
    }
}

Describe 'Deployment profile gating' {
    It 'declares a gateway only in the gateway profile' {
        $script:gateway.desiredState.mailFlow.gateway.declared | Should -BeTrue
        $script:native.desiredState.mailFlow.gateway.declared | Should -BeFalse
    }

    It 'ties Enhanced Filtering to a declared gateway' {
        $script:gateway.desiredState.mailFlow.enhancedFiltering.enabled | Should -BeTrue
        $script:native.desiredState.mailFlow.enhancedFiltering.enabled | Should -BeFalse
    }

    It 'defines gateway connectors only in the gateway profile' {
        foreach ($connector in 'gatewayInboundConnector', 'gatewayOutboundConnector') {
            $script:gateway.desiredState.mailFlow.PSObject.Properties.Name | Should -Contain $connector
            $script:native.desiredState.mailFlow.PSObject.Properties.Name | Should -Not -Contain $connector
        }
    }

    It 'uses constrained Partner connectors in the gateway profile' {
        $mailFlow = $script:gateway.desiredState.mailFlow
        $mailFlow.gatewayInboundConnector.connectorType | Should -Be 'Partner'
        $mailFlow.gatewayInboundConnector.requireTls | Should -BeTrue
        $mailFlow.gatewayInboundConnector.restrictDomainsToIpAddresses | Should -BeTrue
        $mailFlow.gatewayOutboundConnector.tlsSettings | Should -Be 'DomainValidation'
    }

    It 'prohibits bypass patterns in both profiles' {
        foreach ($item in $script:profiles) {
            $item.Config.desiredState.mailFlow.prohibitedBypass.sclMinusOneTransportRules | Should -BeFalse
            $item.Config.desiredState.mailFlow.prohibitedBypass.directToTenantMxFromInternet | Should -BeFalse
        }
    }
}

Describe 'Microsoft managed protection' {
    It 'enables the Standard and Strict presets in both profiles' {
        foreach ($item in $script:profiles) {
            $mdo = $item.Config.desiredState.defenderForOffice365
            $mdo.standardPreset.enabled | Should -BeTrue
            $mdo.strictPreset.enabled | Should -BeTrue
            $mdo.builtInProtection.enabled | Should -BeTrue
            $mdo.builtInProtection.exceptions | Should -BeNullOrEmpty
        }
    }

    It 'keeps file protection enabled with no user bypass' {
        foreach ($item in $script:profiles) {
            $mdo = $item.Config.desiredState.defenderForOffice365
            $mdo.safeAttachmentsForSharePointOneDriveTeams | Should -BeTrue
            $mdo.safeDocuments.allowBypass | Should -BeFalse
        }
    }

    It 'keeps high-risk quarantine categories admin-only' {
        foreach ($item in $script:profiles) {
            $quarantine = $item.Config.desiredState.defenderForOffice365.quarantinePolicies
            $quarantine.highRiskAccessLevel | Should -Be 'AdminOnlyAccess'
            $quarantine.highRiskCategories | Should -Contain 'Malware'
            $quarantine.highRiskCategories | Should -Contain 'HighConfidencePhish'
            $quarantine.endUserSpamNotificationFrequencyInDays | Should -BeLessOrEqual 3
        }
    }

    It 'carries no transcribed preset policy values' {
        foreach ($item in $script:profiles) {
            $item.Text | Should -Not -Match '(?i)"(phishThresholdLevel|bulkThreshold|spamAction|highConfidenceSpamAction|commonAttachmentTypesFilter)"'
        }
    }
}

Describe 'Exchange Online hardening' {
    It 'disables high-risk legacy paths' {
        foreach ($item in $script:profiles) {
            $exchange = $item.Config.desiredState.exchangeOnline
            $exchange.smtpClientAuthenticationDisabled | Should -BeTrue
            $exchange.legacyAuthenticationBlockedByConditionalAccess | Should -BeTrue
            $exchange.automaticExternalForwarding | Should -Be 'Off'
            $exchange.mailboxAuditingDefault | Should -BeTrue
            $exchange.mailboxAuditBypassAssociations | Should -BeNullOrEmpty
        }
    }

    It 'tags external senders with an empty allow list' {
        foreach ($item in $script:profiles) {
            $external = $item.Config.desiredState.exchangeOnline.externalSenderIdentification
            $external.enabled | Should -BeTrue
            $external.allowList | Should -BeNullOrEmpty
        }
    }

    It 'hardens the default remote domain' {
        foreach ($item in $script:profiles) {
            $remote = $item.Config.desiredState.exchangeOnline.remoteDomainDefault
            $remote.autoForwardEnabled | Should -BeFalse
            $remote.autoReplyEnabled | Should -BeFalse
            $remote.allowedOOFType | Should -Be 'None'
            $remote.nonDeliveryReportEnabled | Should -BeFalse
        }
    }

    It 'restricts the legacy protocol surface' {
        foreach ($item in $script:profiles) {
            $protocols = $item.Config.desiredState.exchangeOnline.protocolRestriction
            $protocols.ewsEnabled | Should -BeFalse
            $protocols.popEnabledByDefault | Should -BeFalse
            $protocols.imapEnabledByDefault | Should -BeFalse
            $protocols.outlookAddInsForUsers | Should -BeFalse
        }
    }

    It 'requires reviewed, just-in-time privilege' {
        foreach ($item in $script:profiles) {
            $rbac = $item.Config.desiredState.exchangeOnline.roleBasedAccessControl
            $rbac.noStandingGlobalAdministratorForMessaging | Should -BeTrue
            $rbac.privilegedRolesJustInTime | Should -BeTrue
            $rbac.roleGroupReviewFrequencyDays | Should -BeLessOrEqual 90
        }
    }

    It 'enforces transport security reporting' {
        foreach ($item in $script:profiles) {
            $tls = $item.Config.desiredState.exchangeOnline.transportSecurity
            $tls.mtaStsMode | Should -Be 'enforce'
            $tls.tlsRptEnabled | Should -BeTrue
        }
    }
}

Describe 'Email authentication target state' {
    It 'targets DMARC reject with subdomain coverage' {
        foreach ($item in $script:profiles) {
            $dmarc = $item.Config.desiredState.emailAuthentication.dmarc
            $dmarc.policy | Should -Be 'reject'
            $dmarc.subdomainPolicy | Should -Be 'reject'
            $dmarc.percentage | Should -Be 100
        }
    }

    It 'targets SPF hard fail with a single record' {
        foreach ($item in $script:profiles) {
            $spf = $item.Config.desiredState.emailAuthentication.spf
            $spf.hardFail | Should -BeTrue
            $spf.singleRecordOnly | Should -BeTrue
        }
    }

    It 'requires 2048-bit DKIM' {
        foreach ($item in $script:profiles) {
            $item.Config.desiredState.emailAuthentication.dkim.keySize | Should -Be 2048
        }
    }
}

Describe 'Third-party post-delivery integration' {
    It 'keeps Abnormal API based and out of SMTP routing' {
        $abnormal = $script:gateway.desiredState.abnormalSecurity
        $abnormal.integrationMode | Should -Be 'Microsoft API post-delivery'
        $abnormal.smtpConnectorCreated | Should -BeFalse
        $abnormal.transportBypassCreated | Should -BeFalse
    }

    It 'omits vendor integration from the Microsoft-native profile' {
        $script:native.desiredState.PSObject.Properties.Name | Should -Not -Contain 'abnormalSecurity'
    }
}

Describe 'Monitoring and governance' {
    It 'defines centralized monitoring and retention' {
        foreach ($item in $script:profiles) {
            $monitoring = $item.Config.desiredState.centralMonitoring
            $monitoring.siemIntegration.enabled | Should -BeTrue
            $monitoring.siemIntegration.minimumRetentionDays | Should -BeGreaterOrEqual 180
            $monitoring.siemIntegration.sources.Count | Should -BeGreaterOrEqual 6
        }
    }

    It 'defines Purview governance requirements' {
        foreach ($item in $script:profiles) {
            $governance = $item.Config.desiredState.purviewGovernance
            $governance.unifiedAuditLogEnabled | Should -BeTrue
            $governance.auditRetentionDays | Should -BeGreaterOrEqual 180
            $governance.exchangeDlpPolicyRequired | Should -BeTrue
            $governance.mailboxRetentionPolicyRequired | Should -BeTrue
            $governance.litigationHoldRequiredForPriorityUsers | Should -BeTrue
        }
    }

    It 'requires WhatIf, pilot, and rollback before apply' {
        foreach ($item in $script:profiles) {
            $deployment = $item.Config.deployment
            $deployment.defaultMode | Should -Be 'Audit'
            $deployment.requireWhatIfBeforeApply | Should -BeTrue
            $deployment.pilotRequired | Should -BeTrue
            $deployment.pilotMinimumBusinessDays | Should -BeGreaterOrEqual 5
            $deployment.rollbackPlanRequired | Should -BeTrue
        }
    }
}

Describe 'Documentation contract' {
    BeforeAll {
        $script:docsRoot = Join-Path $script:sampleRoot 'docs'
        $script:catalog = Get-Content -Path (Join-Path $docsRoot 'CONTROL-CATALOG.md') -Raw
        $script:runbooks = Get-Content -Path (Join-Path $docsRoot 'RUNBOOKS.md') -Raw
    }

    It 'ships a runbook and a licensing gate' {
        Test-Path (Join-Path $script:docsRoot 'RUNBOOKS.md') | Should -BeTrue
        Test-Path (Join-Path $script:docsRoot 'LICENSING-GATE.md') | Should -BeTrue
    }

    It 'gives every catalog control a runbook anchor' {
        $controlIds = [regex]::Matches($script:catalog, '(?m)^\| ((?:EXO|MDO|PP|AUTH|ABN|MON|OPS|GOV)-\d{3}) \|') |
            ForEach-Object { $_.Groups[1].Value } |
            Sort-Object -Unique

        $controlIds.Count | Should -BeGreaterThan 30

        foreach ($id in $controlIds) {
            $script:runbooks | Should -Match "### R-$id " -Because "$id needs a setting-level runbook"
        }
    }

    It 'gives every runbook a verification step and expected output' {
        $sections = $script:runbooks -split '(?m)^### R-' | Select-Object -Skip 1
        foreach ($section in $sections) {
            $title = ($section -split "`n")[0].Trim()
            $section | Should -Match '\*\*Verify\*\*' -Because "R-$title must state how to verify"
            $section | Should -Match '\*\*Expected\*\*' -Because "R-$title must state the expected output"
        }
    }
}