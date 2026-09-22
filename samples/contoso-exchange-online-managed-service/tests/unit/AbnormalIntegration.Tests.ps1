#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
    $script:GatewayPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'
    $script:CommonModule = Import-Module -Name $script:ModulePath -Force -DisableNameChecking -PassThru -ErrorAction Stop
    $script:AsOfUtc = [datetime]::new(2026, 9, 19, 12, 0, 0, [System.DateTimeKind]::Utc)

    function New-AbnormalIntegrationDesiredState {
        [pscustomobject]@{
            mode = 'Microsoft API post-delivery'
            smtpConnectorCreated = $false
            journalRuleCreated = $false
            sclBypassCreated = $false
            transportExceptionCreated = $false
            maximumVendorHealthAgeMinutes = 60
            maximumFunctionalTestAgeHours = 24
            requiredFunctionalOutcomes = @('Detection', 'Removal', 'Restoration', 'AuditAttribution')
            requireSignedEvidence = $true
            requireCompleteCollection = $true
        }
    }

    function New-AbnormalIntegrationPayload {
        param(
            [bool]$Complete = $true,
            [string]$Mode = 'Microsoft API post-delivery',
            [bool]$SmtpConnectorCreated = $false,
            [bool]$JournalRuleCreated = $false,
            [bool]$SclBypassCreated = $false,
            [bool]$TransportExceptionCreated = $false,
            [string]$HealthStatus = 'Healthy',
            [datetime]$HealthCheckedAtUtc = $script:AsOfUtc.AddMinutes(-30),
            [datetime]$FunctionalTestAtUtc = $script:AsOfUtc.AddHours(-2),
            [bool]$Detection = $true,
            [bool]$Removal = $true,
            [bool]$Restoration = $true,
            [bool]$AuditAttribution = $true
        )
        [pscustomobject]@{
            Complete = $Complete
            Integration = [pscustomobject]@{
                Mode = $Mode
                SmtpConnectorCreated = $SmtpConnectorCreated
                JournalRuleCreated = $JournalRuleCreated
                SclBypassCreated = $SclBypassCreated
                TransportExceptionCreated = $TransportExceptionCreated
            }
            VendorHealth = [pscustomobject]@{
                Status = $HealthStatus
                CheckedAtUtc = $HealthCheckedAtUtc
            }
            FunctionalTest = [pscustomobject]@{
                TestedAtUtc = $FunctionalTestAtUtc
                Detection = $Detection
                Removal = $Removal
                Restoration = $Restoration
                AuditAttribution = $AuditAttribution
                AuditActor = 'abnormal-service-principal'
                AuditRecordId = 'audit-abn-001'
            }
        }
    }

    function New-AbnormalIntegrationDecision {
        param(
            [bool]$Satisfied = $true,
            [object[]]$Admitted = @(),
            [object[]]$Refused = @(),
            [object]$Payload = (New-AbnormalIntegrationPayload)
        )
        if ($Satisfied -and $Admitted.Count -eq 0) {
            $Admitted = @([pscustomobject]@{
                    EvidenceId = 'evd-abn-001'
                    ControlId = 'ABN-001'
                    Evidence = [pscustomobject]@{
                        ControlId = 'ABN-001'
                        Payload = $Payload
                    }
                })
        }
        [pscustomobject]@{ Satisfied = $Satisfied; Admitted = @($Admitted); Refused = @($Refused) }
    }

    function New-AbnormalIntegrationEvidence {
        param(
            [object]$Decision = (New-AbnormalIntegrationDecision),
            [datetime]$CollectedAtUtc = $script:AsOfUtc.AddMinutes(-10)
        )
        & $script:CommonModule {
            param($ImportDecision, $At)
            New-BaselineEvidence -ControlId 'ABN-001' -Source 'ExternalEvidence' `
                -Command 'Import-BaselineExternalEvidence' -CollectedAtUtc $At `
                -Value ([ordered]@{ AbnormalIntegrationImportDecision = $ImportDecision })
        } $Decision $CollectedAtUtc
    }

    function Get-TestAbnormalIntegrationEvidence {
        param([object]$Decision, [datetime]$CollectedAtUtc = $script:AsOfUtc.AddMinutes(-10))
        & $script:CommonModule {
            param($ImportDecision, $At)
            Get-AbnormalIntegrationEvidence -AbnormalIntegrationImportDecision $ImportDecision -CollectedAtUtc $At
        } $Decision $CollectedAtUtc
    }

    function Test-AbnormalIntegrationFixture {
        param(
            [object]$Evidence,
            [object]$DesiredState = (New-AbnormalIntegrationDesiredState)
        )
        & $script:CommonModule {
            param($Record, $Desired, $At)
            Test-AbnormalIntegrationControl -Evidence $Record -DesiredState $Desired -AsOfUtc $At
        } $Evidence $DesiredState $script:AsOfUtc
    }

    function Copy-GatewayConfiguration {
        $configuration = Get-Content -LiteralPath $script:GatewayPath -Raw | ConvertFrom-Json -Depth 100
        $integration = New-AbnormalIntegrationDesiredState
        if ($configuration.desiredState.abnormalSecurity.PSObject.Properties.Match('integration').Count -eq 0) {
            $configuration.desiredState.abnormalSecurity | Add-Member -NotePropertyName integration -NotePropertyValue $integration
        }
        else {
            $configuration.desiredState.abnormalSecurity.integration = $integration
        }
        return $configuration
    }

    function Test-GatewayConfigurationSchema {
        param([object]$Configuration)
        $schema = Get-Content -LiteralPath $script:SchemaPath -Raw | ConvertFrom-Json -Depth 100
        $integrationSchema = $schema.properties.desiredState.properties.abnormalSecurity.properties.integration | ConvertTo-Json -Depth 100
        $integration = $Configuration.desiredState.abnormalSecurity.integration | ConvertTo-Json -Depth 100
        $integration | Test-Json -Schema $integrationSchema -ErrorAction SilentlyContinue
    }

    function Test-ShippedGatewayIntegrationContract {
        $configuration = Get-Content -LiteralPath $script:GatewayPath -Raw | ConvertFrom-Json -Depth 100
        if ($configuration.desiredState.abnormalSecurity.PSObject.Properties.Match('integration').Count -eq 0) {
            return $false
        }
        return Test-GatewayConfigurationSchema -Configuration $configuration
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'ABN-001 Gateway integration schema contract' {
    Context 'Negative: absent, partial, non-API or unsafe integration state' {
        It 'rejects a partial integration subtree' {
            # Arrange
            $configuration = Copy-GatewayConfiguration
            $configuration.desiredState.abnormalSecurity.integration.PSObject.Properties.Remove('requiredFunctionalOutcomes')

            # Act
            $actual = Test-GatewayConfigurationSchema -Configuration $configuration

            # Assert
            $actual | Should -BeFalse
        }

        It 'rejects SMTP delivery mode' {
            # Arrange
            $configuration = Copy-GatewayConfiguration
            $configuration.desiredState.abnormalSecurity.integration.mode = 'SMTP gateway'

            # Act
            $actual = Test-GatewayConfigurationSchema -Configuration $configuration

            # Assert
            $actual | Should -BeFalse
        }

        It 'rejects any declared SMTP, journal, SCL bypass or transport exception path' -ForEach @(
            @{ Member = 'smtpConnectorCreated' }
            @{ Member = 'journalRuleCreated' }
            @{ Member = 'sclBypassCreated' }
            @{ Member = 'transportExceptionCreated' }
        ) {
            # Arrange
            $configuration = Copy-GatewayConfiguration
            $configuration.desiredState.abnormalSecurity.integration.$Member = $true

            # Act
            $actual = Test-GatewayConfigurationSchema -Configuration $configuration

            # Assert
            $actual | Should -BeFalse
        }
    }

    Context 'Positive: complete API-only Gateway contract' {
        It 'admits the shipped Gateway integration subtree' {
            # Arrange
            $gatewayPath = $script:GatewayPath

            # Act
            $actual = Test-ShippedGatewayIntegrationContract

            # Assert
            $gatewayPath | Should -Exist
            $actual | Should -BeTrue
        }
    }
}

Describe 'ABN-001 admitted integration evidence collection' {
    Context 'Negative: missing or refused EVD-008 decision' {
        It 'refuses a missing external-evidence import decision' {
            # Arrange
            $decision = $null

            # Act
            $act = { Get-TestAbnormalIntegrationEvidence -Decision $decision }

            # Assert
            $act | Should -Throw '*AbnormalIntegrationImportDecisionRequired*ABN-001*'
        }

        It 'preserves an unsigned EVD-008 refusal by name' {
            # Arrange
            $decision = New-AbnormalIntegrationDecision -Satisfied $false -Refused @(
                [pscustomobject]@{ Reason = 'ExternalEvidenceSignatureMissing: detached CMS signature is required.' }
            )

            # Act
            $actual = Get-TestAbnormalIntegrationEvidence -Decision $decision

            # Assert
            $actual.ControlId | Should -BeExactly 'ABN-001'
            $actual.Value.AbnormalIntegrationImportDecision.Refused[0].Reason | Should -Match '^ExternalEvidenceSignatureMissing:'
        }
    }

    Context 'Positive: one admitted signed integration decision' {
        It 'preserves the complete EVD-008 decision without manufacturing a verdict' {
            # Arrange
            $decision = New-AbnormalIntegrationDecision

            # Act
            $actual = Get-TestAbnormalIntegrationEvidence -Decision $decision

            # Assert
            $actual.ControlId | Should -BeExactly 'ABN-001'
            $actual.Source | Should -BeExactly 'ExternalEvidence'
            $actual.Command | Should -BeExactly 'Import-BaselineExternalEvidence'
            $actual.Value.AbnormalIntegrationImportDecision.Satisfied | Should -BeTrue
            $actual.Value.AbnormalIntegrationImportDecision.Admitted[0].Evidence.ControlId | Should -BeExactly 'ABN-001'
        }
    }
}

Describe 'ABN-001 post-delivery integration evaluation' {
    Context 'Negative: missing, partial, refused or stale evidence' {
        It 'returns Error for a partial record with no import decision' {
            # Arrange
            $evidence = & $script:CommonModule {
                param($At)
                New-BaselineEvidence -ControlId 'ABN-001' -Source 'ExternalEvidence' `
                    -Command 'Import-BaselineExternalEvidence' -CollectedAtUtc $At -Value ([ordered]@{})
            } $script:AsOfUtc.AddMinutes(-10)

            # Act
            $actual = Test-AbnormalIntegrationFixture -Evidence $evidence

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^AbnormalIntegrationEvidenceIncomplete:'
        }

        It 'returns Error naming unsigned evidence refusal' {
            # Arrange
            $decision = New-AbnormalIntegrationDecision -Satisfied $false -Refused @([pscustomobject]@{ Reason = 'ExternalEvidenceSignatureMissing: detached CMS signature is required.' })
            $evidence = New-AbnormalIntegrationEvidence -Decision $decision

            # Act
            $actual = Test-AbnormalIntegrationFixture -Evidence $evidence

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^AbnormalIntegrationEvidenceRefused:.*ExternalEvidenceSignatureMissing'
        }

        It 'returns Error preserving a general EVD-008 refusal name' {
            # Arrange
            $decision = New-AbnormalIntegrationDecision -Satisfied $false -Refused @([pscustomobject]@{ Reason = 'ExternalEvidenceSignerUnauthorized: signer is not authorized.' })
            $evidence = New-AbnormalIntegrationEvidence -Decision $decision

            # Act
            $actual = Test-AbnormalIntegrationFixture -Evidence $evidence

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^AbnormalIntegrationEvidenceRefused:.*ExternalEvidenceSignerUnauthorized'
        }

        It 'returns Error for stale collected evidence' {
            # Arrange
            $evidence = New-AbnormalIntegrationEvidence -CollectedAtUtc $script:AsOfUtc.AddHours(-25)

            # Act
            $actual = Test-AbnormalIntegrationFixture -Evidence $evidence

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^AbnormalIntegrationEvidenceStale:'
        }

        It 'returns Error when no admitted ABN-001 record exists' {
            # Arrange
            $decision = New-AbnormalIntegrationDecision -Admitted @([pscustomobject]@{ Evidence = [pscustomobject]@{ ControlId = 'ABN-002'; Payload = (New-AbnormalIntegrationPayload) } })
            $evidence = New-AbnormalIntegrationEvidence -Decision $decision

            # Act
            $actual = Test-AbnormalIntegrationFixture -Evidence $evidence

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^AbnormalIntegrationEvidenceWrongControl:'
        }

        It 'returns Error for an incomplete admitted payload' {
            # Arrange
            $payload = New-AbnormalIntegrationPayload
            $payload.PSObject.Properties.Remove('FunctionalTest')
            $decision = New-AbnormalIntegrationDecision -Payload $payload
            $evidence = New-AbnormalIntegrationEvidence -Decision $decision

            # Act
            $actual = Test-AbnormalIntegrationFixture -Evidence $evidence

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^AbnormalIntegrationEvidenceIncomplete:.*FunctionalTest'
        }
    }

    Context 'Negative: delivery path, health and functional drift' {
        It 'fails non-API integration mode by name' {
            # Arrange
            $decision = New-AbnormalIntegrationDecision -Payload (New-AbnormalIntegrationPayload -Mode 'SMTP gateway')
            $evidence = New-AbnormalIntegrationEvidence -Decision $decision

            # Act
            $actual = Test-AbnormalIntegrationFixture -Evidence $evidence

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^AbnormalIntegrationModeDrift:.*SMTP gateway.*Microsoft API post-delivery'
        }

        It 'fails each prohibited delivery path by name' -ForEach @(
            @{ Argument = 'SmtpConnectorCreated'; Reason = 'SmtpConnector' }
            @{ Argument = 'JournalRuleCreated'; Reason = 'JournalRule' }
            @{ Argument = 'SclBypassCreated'; Reason = 'SclBypass' }
            @{ Argument = 'TransportExceptionCreated'; Reason = 'TransportException' }
        ) {
            # Arrange
            $payloadArgument = @{ $Argument = $true }
            $decision = New-AbnormalIntegrationDecision -Payload (New-AbnormalIntegrationPayload @payloadArgument)
            $evidence = New-AbnormalIntegrationEvidence -Decision $decision

            # Act
            $actual = Test-AbnormalIntegrationFixture -Evidence $evidence

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match "^AbnormalIntegrationDeliveryPathDrift:.*$Reason"
        }

        It 'fails unhealthy current vendor state by name' {
            # Arrange
            $decision = New-AbnormalIntegrationDecision -Payload (New-AbnormalIntegrationPayload -HealthStatus 'Degraded')
            $evidence = New-AbnormalIntegrationEvidence -Decision $decision

            # Act
            $actual = Test-AbnormalIntegrationFixture -Evidence $evidence

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^AbnormalIntegrationVendorHealthFailed:.*Degraded'
        }

        It 'returns Error for stale vendor health' {
            # Arrange
            $decision = New-AbnormalIntegrationDecision -Payload (New-AbnormalIntegrationPayload -HealthCheckedAtUtc $script:AsOfUtc.AddMinutes(-61))
            $evidence = New-AbnormalIntegrationEvidence -Decision $decision

            # Act
            $actual = Test-AbnormalIntegrationFixture -Evidence $evidence

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^AbnormalIntegrationVendorHealthStale:'
        }

        It 'fails each required functional outcome by name' -ForEach @(
            @{ Argument = 'Detection'; Reason = 'Detection' }
            @{ Argument = 'Removal'; Reason = 'Removal' }
            @{ Argument = 'Restoration'; Reason = 'Restoration' }
            @{ Argument = 'AuditAttribution'; Reason = 'AuditAttribution' }
        ) {
            # Arrange
            $payloadArgument = @{ $Argument = $false }
            $decision = New-AbnormalIntegrationDecision -Payload (New-AbnormalIntegrationPayload @payloadArgument)
            $evidence = New-AbnormalIntegrationEvidence -Decision $decision

            # Act
            $actual = Test-AbnormalIntegrationFixture -Evidence $evidence

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match "^AbnormalIntegrationFunctionalTestFailed:.*$Reason"
        }

        It 'returns Error for stale functional evidence' {
            # Arrange
            $decision = New-AbnormalIntegrationDecision -Payload (New-AbnormalIntegrationPayload -FunctionalTestAtUtc $script:AsOfUtc.AddHours(-25))
            $evidence = New-AbnormalIntegrationEvidence -Decision $decision

            # Act
            $actual = Test-AbnormalIntegrationFixture -Evidence $evidence

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^AbnormalIntegrationFunctionalTestStale:'
        }

        It 'fails audit attribution without a functional actor and record' {
            # Arrange
            $payload = New-AbnormalIntegrationPayload
            $payload.FunctionalTest.AuditActor = ''
            $payload.FunctionalTest.AuditRecordId = ''
            $decision = New-AbnormalIntegrationDecision -Payload $payload
            $evidence = New-AbnormalIntegrationEvidence -Decision $decision

            # Act
            $actual = Test-AbnormalIntegrationFixture -Evidence $evidence

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^AbnormalIntegrationAuditAttributionFailed:'
        }
    }

    Context 'Positive: current API-only health and functional proof' {
        It 'passes one admitted record proving health, detection, removal, restoration and audit attribution' {
            # Arrange
            $evidence = New-AbnormalIntegrationEvidence

            # Act
            $actual = Test-AbnormalIntegrationFixture -Evidence $evidence

            # Assert
            $actual.ControlId | Should -BeExactly 'ABN-001'
            $actual.Status | Should -BeExactly 'Pass'
            $actual.GoLiveSuccess | Should -BeTrue
        }
    }
}
