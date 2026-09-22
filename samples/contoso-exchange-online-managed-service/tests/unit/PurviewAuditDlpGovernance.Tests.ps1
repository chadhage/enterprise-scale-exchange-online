#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:CommonModule = Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -PassThru -ErrorAction Stop
    $script:DecisionTime = [datetime]::new(2026, 9, 19, 12, 0, 0, [System.DateTimeKind]::Utc)

    $script:AuditDesired = [pscustomobject]@{
        policyName              = 'Regulatory audit retention'
        requiredServicePlan     = 'M365_ADVANCED_AUDITING'
        retentionDays           = 365
        recordTypes             = @('ExchangeAdmin', 'ExchangeItem', 'SharePointFileOperation', 'AzureActiveDirectory')
        maximumEvidenceAgeHours = 24
    }
    $script:DlpDesired = [pscustomobject]@{
        policyName              = 'Regulated data protection'
        requiredServicePlan     = 'EXCHANGE_S_ENTERPRISE'
        mode                    = 'Enforce'
        regulatedDataClasses    = @('Credit Card Number', 'U.S. Social Security Number (SSN)')
        maximumEvidenceAgeHours = 24
    }

    function New-CollectionResult {
        param([object[]]$Items = @(), [bool]$Complete = $true, [string[]]$Refused = @())
        [pscustomobject]@{ Complete = $Complete; Refused = @($Refused); Items = @($Items) }
    }

    function New-AuditPolicy {
        param(
            [string]$Name = 'Regulatory audit retention',
            [bool]$Enabled = $true,
            [int]$RetentionDuration = 365,
            [string[]]$RecordTypes = @('ExchangeAdmin', 'ExchangeItem', 'SharePointFileOperation', 'AzureActiveDirectory')
        )
        [pscustomobject]@{ Name = $Name; Enabled = $Enabled; RetentionDuration = $RetentionDuration; RecordTypes = @($RecordTypes) }
    }

    function New-DlpPolicy {
        param([string]$Name = 'Regulated data protection', [string]$Mode = 'Enforce', [bool]$Enabled = $true)
        [pscustomobject]@{ Name = $Name; Mode = $Mode; Enabled = $Enabled }
    }

    function New-DlpRule {
        param(
            [string]$Policy = 'Regulated data protection',
            [bool]$Enabled = $true,
            [string[]]$SensitiveInformationTypes = @('Credit Card Number', 'U.S. Social Security Number (SSN)')
        )
        [pscustomobject]@{ Policy = $Policy; Enabled = $Enabled; SensitiveInformationTypes = @($SensitiveInformationTypes) }
    }

    function New-Entitlement {
        param([string]$Plan, [string]$Status = 'Pass')
        [pscustomobject]@{ RequiredServicePlanName = $Plan; Status = $Status; Reason = "Synthetic $Plan entitlement is $Status." }
    }

    function Get-TestAuditEvidence {
        param([scriptblock]$Collection, [datetime]$CollectedAtUtc = $script:DecisionTime.AddHours(-1))
        & $script:CommonModule { param($Call, $At) Get-AuditRetentionEvidence -RetentionPolicyCollection $Call -CollectedAtUtc $At } $Collection $CollectedAtUtc
    }

    function Get-TestDlpEvidence {
        param([scriptblock]$PolicyCollection, [scriptblock]$RuleCollection, [datetime]$CollectedAtUtc = $script:DecisionTime.AddHours(-1))
        & $script:CommonModule {
            param($Policies, $Rules, $At)
            Get-DataLossPreventionEvidence -PolicyCollection $Policies -RuleCollection $Rules -CollectedAtUtc $At
        } $PolicyCollection $RuleCollection $CollectedAtUtc
    }

    function Test-AuditFixture {
        param([object]$Evidence, [object]$Entitlement, [object]$DesiredState = $script:AuditDesired)
        & $script:CommonModule {
            param($Record, $Desired, $License, $At)
            Test-AuditRetentionControl -Evidence $Record -DesiredState $Desired -EntitlementVerdict $License -AsOfUtc $At
        } $Evidence $DesiredState $Entitlement $script:DecisionTime
    }

    function Test-DlpFixture {
        param([object]$Evidence, [object]$Entitlement, [object]$DesiredState = $script:DlpDesired)
        & $script:CommonModule {
            param($Record, $Desired, $License, $At)
            Test-DataLossPreventionControl -Evidence $Record -DesiredState $Desired -EntitlementVerdict $License -AsOfUtc $At
        } $Evidence $DesiredState $Entitlement $script:DecisionTime
    }

    function Get-ResultText {
        param([object]$Result)
        '{0}|golive={1}|{2}' -f $Result.Status, $Result.GoLiveSuccess, $Result.Reason
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GOV-008 audit retention and data loss prevention governance' {
    Context 'Negative: refused Purview commands remain named collection failures' {
        It 'records audit retention collection refusal' {
            # Arrange
            $refusing = { throw 'offline Purview audit access refused' }

            # Act
            $evidence = Get-TestAuditEvidence -Collection $refusing

            # Assert
            ('{0}|{1}|{2}' -f $evidence.Collected, $evidence.Command, $evidence.FailureReason) |
                Should -BeLike 'False|Get-UnifiedAuditLogRetentionPolicy|CollectionFailed:*offline Purview audit access refused*'
        }

        It 'records DLP rule collection refusal without accepting the policy half' {
            # Arrange
            $policies = { New-CollectionResult -Items @(New-DlpPolicy) }
            $refusingRules = { throw 'offline Purview DLP rule access refused' }

            # Act
            $evidence = Get-TestDlpEvidence -PolicyCollection $policies -RuleCollection $refusingRules

            # Assert
            ('{0}|{1}|{2}' -f $evidence.Collected, $evidence.Command, $evidence.FailureReason) |
                Should -BeLike 'False|Get-DlpCompliancePolicy; Get-DlpComplianceRule|CollectionFailed:*offline Purview DLP rule access refused*'
        }
    }

    Context 'Negative: entitlement is authoritative and unresolved entitlement fails closed' {
        It 'marks audit retention NotApplicable when its declared plan is not entitled' {
            # Arrange
            $evidence = Get-TestAuditEvidence -Collection { New-CollectionResult -Items @(New-AuditPolicy) }
            $entitlement = New-Entitlement -Plan 'M365_ADVANCED_AUDITING' -Status 'NotEntitled'

            # Act
            $result = Test-AuditFixture -Evidence $evidence -Entitlement $entitlement

            # Assert
            (Get-ResultText $result) | Should -BeLike 'NotApplicable|golive=True|AuditRetentionNotEntitled:*'
        }

        It 'marks DLP NotApplicable when its declared plan is not entitled' {
            # Arrange
            $evidence = Get-TestDlpEvidence -PolicyCollection { New-CollectionResult -Items @(New-DlpPolicy) } `
                -RuleCollection { New-CollectionResult -Items @(New-DlpRule) }
            $entitlement = New-Entitlement -Plan 'EXCHANGE_S_ENTERPRISE' -Status 'NotEntitled'

            # Act
            $result = Test-DlpFixture -Evidence $evidence -Entitlement $entitlement

            # Assert
            (Get-ResultText $result) | Should -BeLike 'NotApplicable|golive=True|DataLossPreventionNotEntitled:*'
        }

        It 'errors when DLP entitlement did not resolve' {
            # Arrange
            $evidence = Get-TestDlpEvidence -PolicyCollection { New-CollectionResult -Items @(New-DlpPolicy) } `
                -RuleCollection { New-CollectionResult -Items @(New-DlpRule) }
            $entitlement = New-Entitlement -Plan 'EXCHANGE_S_ENTERPRISE' -Status 'Error'

            # Act
            $result = Test-DlpFixture -Evidence $evidence -Entitlement $entitlement

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|DataLossPreventionEntitlementUnresolved:*'
        }
    }

    Context 'Negative: incomplete or refused collection metadata decides no governance state' {
        It 'errors on an incomplete audit retention collection' {
            # Arrange
            $evidence = Get-TestAuditEvidence -Collection { New-CollectionResult -Items @(New-AuditPolicy) -Complete $false }
            $entitlement = New-Entitlement -Plan 'M365_ADVANCED_AUDITING'

            # Act
            $result = Test-AuditFixture -Evidence $evidence -Entitlement $entitlement

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|AuditRetentionCollectionIncomplete:*'
        }

        It 'errors on a partial DLP rule collection' {
            # Arrange
            $evidence = Get-TestDlpEvidence -PolicyCollection { New-CollectionResult -Items @(New-DlpPolicy) } `
                -RuleCollection { New-CollectionResult -Items @(New-DlpRule) -Complete $false }
            $entitlement = New-Entitlement -Plan 'EXCHANGE_S_ENTERPRISE'

            # Act
            $result = Test-DlpFixture -Evidence $evidence -Entitlement $entitlement

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|DataLossPreventionCollectionIncomplete:*DlpRules*'
        }

        It 'preserves a named DLP policy refusal' {
            # Arrange
            $evidence = Get-TestDlpEvidence -PolicyCollection { New-CollectionResult -Refused @('Purview denied policy page 2') } `
                -RuleCollection { New-CollectionResult -Items @(New-DlpRule) }
            $entitlement = New-Entitlement -Plan 'EXCHANGE_S_ENTERPRISE'

            # Act
            $result = Test-DlpFixture -Evidence $evidence -Entitlement $entitlement

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|DataLossPreventionCollectionRefused:*Purview denied policy page 2*'
        }
    }

    Context 'Negative: stale Purview evidence is never current governance evidence' {
        It 'errors on stale audit retention evidence' {
            # Arrange
            $evidence = Get-TestAuditEvidence -Collection { New-CollectionResult -Items @(New-AuditPolicy) } `
                -CollectedAtUtc $script:DecisionTime.AddHours(-25)
            $entitlement = New-Entitlement -Plan 'M365_ADVANCED_AUDITING'

            # Act
            $result = Test-AuditFixture -Evidence $evidence -Entitlement $entitlement

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|AuditRetentionEvidenceStale:*25*24*'
        }

        It 'errors on stale DLP evidence' {
            # Arrange
            $evidence = Get-TestDlpEvidence -PolicyCollection { New-CollectionResult -Items @(New-DlpPolicy) } `
                -RuleCollection { New-CollectionResult -Items @(New-DlpRule) } -CollectedAtUtc $script:DecisionTime.AddHours(-25)
            $entitlement = New-Entitlement -Plan 'EXCHANGE_S_ENTERPRISE'

            # Act
            $result = Test-DlpFixture -Evidence $evidence -Entitlement $entitlement

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|DataLossPreventionEvidenceStale:*25*24*'
        }
    }

    Context 'Negative: missing, partial and drifted regulatory controls fail by name' {
        It 'fails when the named audit retention policy is missing' {
            # Arrange
            $evidence = Get-TestAuditEvidence -Collection { New-CollectionResult }
            $entitlement = New-Entitlement -Plan 'M365_ADVANCED_AUDITING'

            # Act
            $result = Test-AuditFixture -Evidence $evidence -Entitlement $entitlement

            # Assert
            (Get-ResultText $result) | Should -BeLike "Fail|golive=False|AuditRetentionMissing:*Regulatory audit retention*"
        }

        It 'fails when audit retention is shorter than the exact regulatory period' {
            # Arrange
            $evidence = Get-TestAuditEvidence -Collection { New-CollectionResult -Items @(New-AuditPolicy -RetentionDuration 364) }
            $entitlement = New-Entitlement -Plan 'M365_ADVANCED_AUDITING'

            # Act
            $result = Test-AuditFixture -Evidence $evidence -Entitlement $entitlement

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|AuditRetentionDrift:*364*365*'
        }

        It 'fails when audit retention only partially covers required record types' {
            # Arrange
            $evidence = Get-TestAuditEvidence -Collection {
                New-CollectionResult -Items @(New-AuditPolicy -RecordTypes @('ExchangeAdmin', 'ExchangeItem'))
            }
            $entitlement = New-Entitlement -Plan 'M365_ADVANCED_AUDITING'

            # Act
            $result = Test-AuditFixture -Evidence $evidence -Entitlement $entitlement

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|AuditRetentionCoveragePartial:*SharePointFileOperation*AzureActiveDirectory*'
        }

        It 'fails when the named enforced DLP policy is missing' {
            # Arrange
            $evidence = Get-TestDlpEvidence -PolicyCollection { New-CollectionResult } -RuleCollection { New-CollectionResult }
            $entitlement = New-Entitlement -Plan 'EXCHANGE_S_ENTERPRISE'

            # Act
            $result = Test-DlpFixture -Evidence $evidence -Entitlement $entitlement

            # Assert
            (Get-ResultText $result) | Should -BeLike "Fail|golive=False|DataLossPreventionMissing:*Regulated data protection*"
        }

        It 'fails when the DLP policy is not enforced' {
            # Arrange
            $evidence = Get-TestDlpEvidence -PolicyCollection { New-CollectionResult -Items @(New-DlpPolicy -Mode 'TestWithNotifications') } `
                -RuleCollection { New-CollectionResult -Items @(New-DlpRule) }
            $entitlement = New-Entitlement -Plan 'EXCHANGE_S_ENTERPRISE'

            # Act
            $result = Test-DlpFixture -Evidence $evidence -Entitlement $entitlement

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|DataLossPreventionDrift:*TestWithNotifications*Enforce*'
        }

        It 'fails when enforced DLP rules cover only part of the declared regulated classes' {
            # Arrange
            $evidence = Get-TestDlpEvidence -PolicyCollection { New-CollectionResult -Items @(New-DlpPolicy) } `
                -RuleCollection { New-CollectionResult -Items @(New-DlpRule -SensitiveInformationTypes @('Credit Card Number')) }
            $entitlement = New-Entitlement -Plan 'EXCHANGE_S_ENTERPRISE'

            # Act
            $result = Test-DlpFixture -Evidence $evidence -Entitlement $entitlement

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|DataLossPreventionCoveragePartial:*U.S. Social Security Number (SSN)*'
        }
    }

    Context 'Positive: one fully entitled complete Purview fixture satisfies both governance controls' {
        It 'validates both shipped profiles and passes exact audit retention and regulated-class DLP coverage' {
            # Arrange
            $profilePath = @(
                (Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'),
                (Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.microsoft-native.json')
            )
            $schemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
            $auditEntitlement = New-Entitlement -Plan 'M365_ADVANCED_AUDITING'
            $dlpEntitlement = New-Entitlement -Plan 'EXCHANGE_S_ENTERPRISE'

            # Act
            $actual = & {
                $profile = @($profilePath | ForEach-Object { Get-Content -LiteralPath $_ -Raw | ConvertFrom-Json -AsHashtable })
                $schemaValid = @($profilePath | ForEach-Object { Test-Json -Path $_ -SchemaFile $schemaPath -ErrorAction Stop })
                $configured = @($profile | ForEach-Object {
                        '{0}:{1}:{2}:{3}' -f `
                            $_.desiredState.governance.auditRetention.requiredServicePlan,
                            $_.desiredState.governance.auditRetention.retentionDays,
                            $_.desiredState.governance.dataLossPrevention.requiredServicePlan,
                            $_.desiredState.governance.dataLossPrevention.mode
                    })

                $auditEvidence = Get-TestAuditEvidence -Collection { New-CollectionResult -Items @(New-AuditPolicy) }
                $dlpEvidence = Get-TestDlpEvidence -PolicyCollection { New-CollectionResult -Items @(New-DlpPolicy) } `
                    -RuleCollection { New-CollectionResult -Items @(New-DlpRule) }
                $audit = Test-AuditFixture -Evidence $auditEvidence -Entitlement $auditEntitlement
                $dlp = Test-DlpFixture -Evidence $dlpEvidence -Entitlement $dlpEntitlement

                [pscustomobject]@{
                    SchemaValid = $schemaValid
                    Configured  = $configured
                    Audit       = Get-ResultText $audit
                    Dlp         = Get-ResultText $dlp
                }
            }

            # Assert
            $actual.SchemaValid | Should -Be @($true, $true)
            $actual.Configured | Should -Be @(
                'M365_ADVANCED_AUDITING:365:EXCHANGE_S_ENTERPRISE:Enforce',
                'M365_ADVANCED_AUDITING:180:EXCHANGE_S_ENTERPRISE:Enforce'
            )
            $actual.Audit | Should -BeExactly 'Pass|golive=True|'
            $actual.Dlp | Should -BeExactly 'Pass|golive=True|'
        }
    }
}