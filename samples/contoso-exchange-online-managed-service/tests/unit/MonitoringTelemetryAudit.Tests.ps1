#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:CommonModule = Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -PassThru -ErrorAction Stop
    $script:DecisionTime = [datetime]::new(2026, 9, 19, 12, 0, 0, [System.DateTimeKind]::Utc)
    $script:Sources = @('Defender XDR', 'Office 365 audit', 'Exchange admin audit')
    $script:TelemetryDesired = [pscustomobject]@{
        enabled                         = $true
        destination                     = 'Central SOC SIEM'
        sources                         = $script:Sources
        minimumRetentionDays            = 180
        alertRecipients                 = @('soc@example.test')
        maximumConnectorAgeMinutes      = 60
        maximumSyntheticAlertAgeMinutes = 60
        requireSignedEvidence           = $true
        requireCompleteCollection       = $true
    }
    $script:AuditDesired = [pscustomobject]@{
        enabled                   = $true
        minimumRetentionDays      = 180
        maximumEvidenceAgeHours   = 24
        requireSignedEvidence     = $true
        requireCompleteCollection = $true
        requireSearchResults      = $true
    }

    function New-SignatureState {
        param([bool]$Verified = $true)
        [pscustomobject]@{ Model = 'DetachedCms'; Verified = $Verified }
    }

    function New-TelemetryCollection {
        param(
            [bool]$Complete = $true,
            [string[]]$Refused = @(),
            [object]$Signature = (New-SignatureState),
            [string[]]$ObservedSources = $script:Sources,
            [string]$Destination = 'Central SOC SIEM',
            [bool]$Enabled = $true,
            [int]$RetentionDays = 180,
            [string]$UnhealthySource,
            [datetime]$ConnectorCheckedAtUtc = $script:DecisionTime.AddMinutes(-30),
            [bool]$SyntheticDelivered = $true,
            [datetime]$SyntheticReceivedAtUtc = $script:DecisionTime.AddMinutes(-30)
        )
        [pscustomobject]@{
            Complete       = $Complete
            Refused        = @($Refused)
            Signature      = $Signature
            Integration    = [pscustomobject]@{ Enabled = $Enabled; Destination = $Destination; RetentionDays = $RetentionDays }
            Sources        = @($ObservedSources | ForEach-Object { [pscustomobject]@{ Name = $_; LastEventUtc = $script:DecisionTime.AddMinutes(-30) } })
            ConnectorHealth = @($ObservedSources | ForEach-Object {
                    [pscustomobject]@{ Source = $_; Healthy = ($_ -cne $UnhealthySource); CheckedAtUtc = $ConnectorCheckedAtUtc }
                })
            SyntheticAlert = [pscustomobject]@{ Delivered = $SyntheticDelivered; ReceivedAtUtc = $SyntheticReceivedAtUtc }
        }
    }

    function New-UnifiedAuditCollection {
        param(
            [bool]$Complete = $true,
            [string[]]$Refused = @(),
            [object]$Signature = (New-SignatureState),
            [bool]$Enabled = $true,
            [int]$RetentionDays = 180,
            [object[]]$Records = @([pscustomobject]@{ RecordType = 'ExchangeAdmin'; CreationDateUtc = $script:DecisionTime.AddHours(-1) })
        )
        [pscustomobject]@{
            Complete         = $Complete
            Refused          = @($Refused)
            Signature        = $Signature
            IngestionEnabled = $Enabled
            RetentionDays    = $RetentionDays
            SearchRecords    = @($Records)
        }
    }

    function Get-TestTelemetryEvidence {
        param([scriptblock]$Collection, [datetime]$CollectedAtUtc = $script:DecisionTime.AddMinutes(-30))
        & $script:CommonModule {
            param($Call, $At)
            Get-TelemetrySourceEvidence -TelemetryCollection $Call -CollectedAtUtc $At
        } $Collection $CollectedAtUtc
    }

    function Get-TestUnifiedAuditEvidence {
        param([scriptblock]$Collection, [datetime]$CollectedAtUtc = $script:DecisionTime.AddHours(-1))
        & $script:CommonModule {
            param($Call, $At)
            Get-UnifiedAuditEvidence -AuditCollection $Call -CollectedAtUtc $At
        } $Collection $CollectedAtUtc
    }

    function New-TestEvidence {
        param([string]$ControlId, [string]$Source, [object]$Value, [datetime]$CollectedAtUtc)
        & $script:CommonModule {
            param($Id, $EvidenceSource, $Payload, $At)
            New-BaselineEvidence -ControlId $Id -Source $EvidenceSource -Command 'Synthetic signed collection' `
                -Value $Payload -CollectedAtUtc $At
        } $ControlId $Source $Value $CollectedAtUtc
    }

    function New-TestTelemetryEvidence {
        param([object]$Value, [datetime]$CollectedAtUtc = $script:DecisionTime.AddMinutes(-30))
        New-TestEvidence -ControlId 'MON-001' -Source 'SignedSiemExport' -Value $Value -CollectedAtUtc $CollectedAtUtc
    }

    function New-TestUnifiedAuditEvidence {
        param([object]$Value, [datetime]$CollectedAtUtc = $script:DecisionTime.AddHours(-1))
        New-TestEvidence -ControlId 'MON-002' -Source 'SignedPurviewAuditExport' -Value $Value -CollectedAtUtc $CollectedAtUtc
    }

    function Test-TelemetryFixture {
        param([object]$Evidence, [object]$DesiredState = $script:TelemetryDesired)
        & $script:CommonModule {
            param($Record, $Desired, $At)
            Test-TelemetrySourceControl -Evidence $Record -DesiredState $Desired -AsOfUtc $At
        } $Evidence $DesiredState $script:DecisionTime
    }

    function Test-UnifiedAuditFixture {
        param([object]$Evidence, [object]$DesiredState = $script:AuditDesired)
        & $script:CommonModule {
            param($Record, $Desired, $At)
            Test-UnifiedAuditControl -Evidence $Record -DesiredState $Desired -AsOfUtc $At
        } $Evidence $DesiredState $script:DecisionTime
    }

    function Get-ResultText {
        param([object]$Result)
        '{0}|golive={1}|{2}' -f $Result.Status, $Result.GoLiveSuccess, $Result.Reason
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'MON-001 central telemetry collector' {
    Context 'Negative: collection prerequisites and refusal remain explicit' {
        It 'refuses a missing injected telemetry collection' {
            # Arrange
            $collection = $null

            # Act
            $action = { Get-TestTelemetryEvidence -Collection $collection }

            # Assert
            $action | Should -Throw '*TelemetryCollectionRequired*MON-001*'
        }

        It 'records a named telemetry collection refusal' {
            # Arrange
            $collection = { throw 'offline SIEM export refused' }

            # Act
            $evidence = Get-TestTelemetryEvidence -Collection $collection

            # Assert
            ('{0}|{1}|{2}' -f $evidence.Collected, $evidence.Command, $evidence.FailureReason) |
                Should -BeLike 'False|Import signed SIEM telemetry collection|CollectionFailed:*offline SIEM export refused*'
        }
    }

    Context 'Positive: one signed SIEM collection is preserved whole' {
        It 'records the complete synthetic payload without deciding it' {
            # Arrange
            $payload = New-TelemetryCollection

            # Act
            $evidence = Get-TestTelemetryEvidence -Collection { $payload }

            # Assert
            ('{0}|{1}|{2}|{3}' -f $evidence.ControlId, $evidence.Source, $evidence.Collected, $evidence.Value.Integration.Destination) |
                Should -BeExactly 'MON-001|SignedSiemExport|True|Central SOC SIEM'
            $evidence.Value.Sources.Name | Should -Be $script:Sources
            { $evidence.Value.Integration.Destination = 'changed' } | Should -Throw
        }
    }
}

Describe 'MON-001 central telemetry evaluator' {
    Context 'Negative: signed complete current collection is mandatory' {
        It 'errors when telemetry evidence is unsigned' {
            # Arrange
            $evidence = New-TestTelemetryEvidence -Value (New-TelemetryCollection -Signature $null)

            # Act
            $result = Test-TelemetryFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|TelemetryEvidenceUnsigned:*'
        }

        It 'errors when telemetry collection is partial' {
            # Arrange
            $evidence = New-TestTelemetryEvidence -Value (New-TelemetryCollection -Complete $false)

            # Act
            $result = Test-TelemetryFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|TelemetryCollectionIncomplete:*'
        }

        It 'errors with the named telemetry refusal' {
            # Arrange
            $evidence = New-TestTelemetryEvidence -Value (New-TelemetryCollection -Refused @('Proofpoint connector page 2 refused'))

            # Act
            $result = Test-TelemetryFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|TelemetryCollectionRefused:*Proofpoint connector page 2 refused*'
        }
    }

    Context 'Negative: every source and current health signal is required' {
        It 'fails with the missing declared telemetry source' {
            # Arrange
            $evidence = New-TestTelemetryEvidence -Value (New-TelemetryCollection -ObservedSources @('Defender XDR', 'Office 365 audit'))

            # Act
            $result = Test-TelemetryFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|TelemetrySourceMissing:*Exchange admin audit*'
        }

        It 'fails with the named unhealthy connector' {
            # Arrange
            $evidence = New-TestTelemetryEvidence -Value (New-TelemetryCollection -UnhealthySource 'Office 365 audit')

            # Act
            $result = Test-TelemetryFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|TelemetryConnectorUnhealthy:*Office 365 audit*'
        }

        It 'errors with the named stale connector health record' {
            # Arrange
            $evidence = New-TestTelemetryEvidence -Value (
                New-TelemetryCollection -ConnectorCheckedAtUtc $script:DecisionTime.AddMinutes(-61)
            )

            # Act
            $result = Test-TelemetryFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|TelemetryConnectorHealthStale:*Defender XDR*61*60*'
        }

        It 'fails when the synthetic alert was not delivered' {
            # Arrange
            $evidence = New-TestTelemetryEvidence -Value (New-TelemetryCollection -SyntheticDelivered $false)

            # Act
            $result = Test-TelemetryFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|TelemetrySyntheticAlertMissing:*'
        }

        It 'errors when the synthetic alert is stale' {
            # Arrange
            $evidence = New-TestTelemetryEvidence -Value (
                New-TelemetryCollection -SyntheticReceivedAtUtc $script:DecisionTime.AddMinutes(-61)
            )

            # Act
            $result = Test-TelemetryFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|TelemetrySyntheticAlertStale:*61*60*'
        }

        It 'fails when SIEM retention drifts below the declared period' {
            # Arrange
            $evidence = New-TestTelemetryEvidence -Value (New-TelemetryCollection -RetentionDays 179)

            # Act
            $result = Test-TelemetryFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|TelemetryRetentionDrift:*179*180*'
        }
    }

    Context 'Positive: one complete current telemetry fixture satisfies both profiles' {
        It 'validates both profiles and passes all declared SIEM sources, health and synthetic alert evidence' {
            # Arrange
            $profilePaths = @(
                (Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'),
                (Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.microsoft-native.json')
            )
            $schemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
            $evidence = New-TestTelemetryEvidence -Value (New-TelemetryCollection)

            # Act
            $actual = [pscustomobject]@{
                SchemaValid = @($profilePaths | ForEach-Object { Test-Json -Path $_ -SchemaFile $schemaPath -ErrorAction Stop })
                Configured  = @($profilePaths | ForEach-Object {
                        $profile = Get-Content -LiteralPath $_ -Raw | ConvertFrom-Json
                        '{0}|{1}|{2}' -f $profile.desiredState.centralMonitoring.siemIntegration.maximumConnectorAgeMinutes,
                            $profile.desiredState.centralMonitoring.siemIntegration.maximumSyntheticAlertAgeMinutes,
                            $profile.desiredState.centralMonitoring.siemIntegration.requireSignedEvidence
                    })
                Result      = Get-ResultText (Test-TelemetryFixture -Evidence $evidence)
            }

            # Assert
            $actual.SchemaValid | Should -Be @($true, $true)
            $actual.Configured | Should -Be @('60|60|True', '60|60|True')
            $actual.Result | Should -BeExactly 'Pass|golive=True|'
        }
    }
}

Describe 'MON-002 unified audit collector' {
    Context 'Negative: collection prerequisites and refusal remain explicit' {
        It 'refuses a missing injected unified-audit collection' {
            # Arrange
            $collection = $null

            # Act
            $action = { Get-TestUnifiedAuditEvidence -Collection $collection }

            # Assert
            $action | Should -Throw '*UnifiedAuditCollectionRequired*MON-002*'
        }

        It 'records a named unified-audit collection refusal' {
            # Arrange
            $collection = { throw 'offline Purview audit export refused' }

            # Act
            $evidence = Get-TestUnifiedAuditEvidence -Collection $collection

            # Assert
            ('{0}|{1}|{2}' -f $evidence.Collected, $evidence.Command, $evidence.FailureReason) |
                Should -BeLike 'False|Import signed Purview unified-audit collection|CollectionFailed:*offline Purview audit export refused*'
        }
    }

    Context 'Positive: one signed Purview collection is preserved whole' {
        It 'records the complete synthetic payload without deciding it' {
            # Arrange
            $payload = New-UnifiedAuditCollection

            # Act
            $evidence = Get-TestUnifiedAuditEvidence -Collection { $payload }

            # Assert
            ('{0}|{1}|{2}|{3}' -f $evidence.ControlId, $evidence.Source, $evidence.Collected, $evidence.Value.RetentionDays) |
                Should -BeExactly 'MON-002|SignedPurviewAuditExport|True|180'
            $evidence.Value.SearchRecords.RecordType | Should -BeExactly 'ExchangeAdmin'
            { $evidence.Value.RetentionDays = 1 } | Should -Throw
        }
    }
}

Describe 'MON-002 unified audit evaluator' {
    Context 'Negative: signed complete current collection is mandatory' {
        It 'errors when unified-audit evidence is unsigned' {
            # Arrange
            $evidence = New-TestUnifiedAuditEvidence -Value (New-UnifiedAuditCollection -Signature $null)

            # Act
            $result = Test-UnifiedAuditFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|UnifiedAuditEvidenceUnsigned:*'
        }

        It 'errors when unified-audit collection is partial' {
            # Arrange
            $evidence = New-TestUnifiedAuditEvidence -Value (New-UnifiedAuditCollection -Complete $false)

            # Act
            $result = Test-UnifiedAuditFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|UnifiedAuditCollectionIncomplete:*'
        }

        It 'errors with the named unified-audit refusal' {
            # Arrange
            $evidence = New-TestUnifiedAuditEvidence -Value (New-UnifiedAuditCollection -Refused @('Purview audit page 3 refused'))

            # Act
            $result = Test-UnifiedAuditFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|UnifiedAuditCollectionRefused:*Purview audit page 3 refused*'
        }

        It 'errors when unified-audit evidence is stale' {
            # Arrange
            $evidence = New-TestUnifiedAuditEvidence -Value (New-UnifiedAuditCollection) `
                -CollectedAtUtc $script:DecisionTime.AddHours(-25)

            # Act
            $result = Test-UnifiedAuditFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|UnifiedAuditEvidenceStale:*25*24*'
        }
    }

    Context 'Negative: enabled ingestion, retention and search proof are required' {
        It 'fails when unified-audit ingestion is disabled' {
            # Arrange
            $evidence = New-TestUnifiedAuditEvidence -Value (New-UnifiedAuditCollection -Enabled $false)

            # Act
            $result = Test-UnifiedAuditFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|UnifiedAuditDisabled:*'
        }

        It 'fails when unified-audit retention drifts below the declared period' {
            # Arrange
            $evidence = New-TestUnifiedAuditEvidence -Value (New-UnifiedAuditCollection -RetentionDays 179)

            # Act
            $result = Test-UnifiedAuditFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|UnifiedAuditRetentionDrift:*179*180*'
        }

        It 'fails when the audit search proves no ingested event' {
            # Arrange
            $evidence = New-TestUnifiedAuditEvidence -Value (New-UnifiedAuditCollection -Records @())

            # Act
            $result = Test-UnifiedAuditFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|UnifiedAuditSearchMissing:*'
        }
    }

    Context 'Positive: one complete current audit fixture satisfies both profiles' {
        It 'validates both profiles and passes enabled retained searchable signed audit evidence' {
            # Arrange
            $profilePaths = @(
                (Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'),
                (Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.microsoft-native.json')
            )
            $schemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
            $evidence = New-TestUnifiedAuditEvidence -Value (New-UnifiedAuditCollection)

            # Act
            $actual = [pscustomobject]@{
                SchemaValid = @($profilePaths | ForEach-Object { Test-Json -Path $_ -SchemaFile $schemaPath -ErrorAction Stop })
                Configured  = @($profilePaths | ForEach-Object {
                        $profile = Get-Content -LiteralPath $_ -Raw | ConvertFrom-Json
                        '{0}|{1}|{2}' -f $profile.desiredState.centralMonitoring.unifiedAudit.enabled,
                            $profile.desiredState.centralMonitoring.unifiedAudit.minimumRetentionDays,
                            $profile.desiredState.centralMonitoring.unifiedAudit.requireSignedEvidence
                    })
                Result      = Get-ResultText (Test-UnifiedAuditFixture -Evidence $evidence)
            }

            # Assert
            $actual.SchemaValid | Should -Be @($true, $true)
            $actual.Configured | Should -Be @('True|180|True', 'True|180|True')
            $actual.Result | Should -BeExactly 'Pass|golive=True|'
        }
    }
}