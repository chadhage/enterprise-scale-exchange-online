#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    Import-Module -Name $script:ModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-IncidentExerciseDesiredState {
        [ordered]@{
            requiredServicePlan = 'MDO P2'
            frequencyDays = 90
            exerciseTypes = @('PhishingSimulation', 'RemediationValidation')
            owners = @('soc-owner@contoso.example', 'messaging-owner@contoso.example')
            requireTrackedActions = $true
            maximumEvidenceAgeDays = 7
        }
    }

    function New-IncidentExerciseEntitlement {
        param([string]$Status = 'Pass')
        [pscustomobject]@{ Status = $Status; RequiredServicePlanName = 'MDO P2'; Reason = "MDO P2 is $Status." }
    }

    function New-IncidentExerciseDecision {
        param(
            [bool]$Satisfied = $true,
            [object[]]$Admitted = @(),
            [object[]]$Refused = @()
        )
        if ($Admitted.Count -eq 0 -and $Satisfied) {
            $Admitted = @([pscustomobject]@{
                    Evidence = [pscustomobject]@{
                        ControlId = 'OPS-002'
                        Payload = [pscustomobject]@{
                            ExerciseId = 'IR-2026-Q3'
                            CompletedAtUtc = [datetime]::UtcNow.AddDays(-14)
                            ExerciseTypes = @('PhishingSimulation', 'RemediationValidation')
                            Owners = @('soc-owner@contoso.example', 'messaging-owner@contoso.example')
                            Actions = @([pscustomobject]@{ ActionId = 'SEC-481'; Owner = 'soc-owner@contoso.example'; Status = 'Closed'; TrackingReference = 'INC-481' })
                        }
                    }
                })
        }
        [pscustomobject]@{ Satisfied = $Satisfied; Admitted = @($Admitted); Refused = @($Refused) }
    }

    function New-IncidentExerciseRecord {
        param(
            [object]$Decision = (New-IncidentExerciseDecision),
            [datetime]$CollectedAtUtc = [datetime]::UtcNow
        )
        New-BaselineEvidence -ControlId 'OPS-002' -Source 'ExternalEvidence' `
            -Command 'Import-BaselineExternalEvidence' -CollectedAtUtc $CollectedAtUtc `
            -Value ([ordered]@{ IncidentExerciseImportDecision = $Decision })
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'OPS-002 incident-exercise evidence collection' {
    Context 'Negative: collection prerequisites and signed-evidence refusal' {
        It 'refuses a missing external-evidence import decision' {
            # Arrange
            $decision = $null

            # Act
            $act = { Get-IncidentExerciseEvidence -IncidentExerciseImportDecision $decision }

            # Assert
            $act | Should -Throw '*IncidentExerciseImportDecisionRequired*'
        }

        It 'preserves a named EVD-008 refusal for evaluation' {
            # Arrange
            $decision = New-IncidentExerciseDecision -Satisfied $false -Refused @([pscustomobject]@{ Reason = 'ExternalEvidenceSignatureInvalid: detached CMS verification failed.' })

            # Act
            $actual = Get-IncidentExerciseEvidence -IncidentExerciseImportDecision $decision

            # Assert
            $actual.ControlId | Should -BeExactly 'OPS-002'
            $actual.Value.IncidentExerciseImportDecision.Refused[0].Reason | Should -Match '^ExternalEvidenceSignatureInvalid:'
        }
    }

    Context 'Positive: one admitted signed incident-exercise decision' {
        It 'preserves the complete EVD-008 decision without manufacturing a verdict' {
            # Arrange
            $decision = New-IncidentExerciseDecision

            # Act
            $actual = Get-IncidentExerciseEvidence -IncidentExerciseImportDecision $decision

            # Assert
            $actual.ControlId | Should -BeExactly 'OPS-002'
            $actual.Source | Should -BeExactly 'ExternalEvidence'
            $actual.Command | Should -BeExactly 'Import-BaselineExternalEvidence'
            $actual.Value.IncidentExerciseImportDecision.Satisfied | Should -BeTrue
            $actual.Value.IncidentExerciseImportDecision.Admitted[0].Evidence.ControlId | Should -BeExactly 'OPS-002'
        }
    }
}

Describe 'OPS-002 quarterly phish and remediation exercise evaluation' {
    Context 'Negative: entitlement, completeness, freshness, owners and tracked actions' {
        It 'returns NotApplicable only for a resolved unentitled verdict' {
            # Arrange
            $evidence = New-IncidentExerciseRecord

            # Act
            $actual = Test-IncidentExerciseControl -Evidence $evidence -DesiredState (New-IncidentExerciseDesiredState) -EntitlementVerdict (New-IncidentExerciseEntitlement -Status NotEntitled) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'NotApplicable'
            $actual.Reason | Should -Match '^IncidentExerciseNotEntitled:'
        }

        It 'returns Error rather than NotApplicable when entitlement is unresolved' {
            # Arrange
            $evidence = New-IncidentExerciseRecord

            # Act
            $actual = Test-IncidentExerciseControl -Evidence $evidence -DesiredState (New-IncidentExerciseDesiredState) -EntitlementVerdict (New-IncidentExerciseEntitlement -Status Error) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^IncidentExerciseEntitlementUnresolved:'
        }

        It 'returns Error for partial evidence without an import decision' {
            # Arrange
            $evidence = New-BaselineEvidence -ControlId 'OPS-002' -Source 'ExternalEvidence' -Command 'Import-BaselineExternalEvidence' -Value ([ordered]@{})

            # Act
            $actual = Test-IncidentExerciseControl -Evidence $evidence -DesiredState (New-IncidentExerciseDesiredState) -EntitlementVerdict (New-IncidentExerciseEntitlement) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^IncidentExerciseEvidenceIncomplete:'
        }

        It 'returns Error with the named signed-evidence refusal' {
            # Arrange
            $decision = New-IncidentExerciseDecision -Satisfied $false -Refused @([pscustomobject]@{ Reason = 'ExternalEvidenceSignatureInvalid: detached CMS verification failed.' })
            $evidence = New-IncidentExerciseRecord -Decision $decision

            # Act
            $actual = Test-IncidentExerciseControl -Evidence $evidence -DesiredState (New-IncidentExerciseDesiredState) -EntitlementVerdict (New-IncidentExerciseEntitlement) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^IncidentExerciseEvidenceRefused:.*ExternalEvidenceSignatureInvalid'
        }

        It 'returns Error for stale collected evidence' {
            # Arrange
            $asOf = [datetime]::UtcNow
            $evidence = New-IncidentExerciseRecord -CollectedAtUtc $asOf.AddDays(-8)

            # Act
            $actual = Test-IncidentExerciseControl -Evidence $evidence -DesiredState (New-IncidentExerciseDesiredState) -EntitlementVerdict (New-IncidentExerciseEntitlement) -AsOfUtc $asOf

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^IncidentExerciseEvidenceStale:'
        }

        It 'fails when the latest exercise is older than one quarter' {
            # Arrange
            $payload = [pscustomobject]@{ ExerciseId = 'IR-old'; CompletedAtUtc = [datetime]::UtcNow.AddDays(-91); ExerciseTypes = @('PhishingSimulation', 'RemediationValidation'); Owners = @('soc-owner@contoso.example', 'messaging-owner@contoso.example'); Actions = @([pscustomobject]@{ ActionId = 'SEC-1'; Owner = 'soc-owner@contoso.example'; Status = 'Closed'; TrackingReference = 'INC-1' }) }
            $decision = New-IncidentExerciseDecision -Admitted @([pscustomobject]@{ Evidence = [pscustomobject]@{ ControlId = 'OPS-002'; Payload = $payload } })
            $evidence = New-IncidentExerciseRecord -Decision $decision

            # Act
            $actual = Test-IncidentExerciseControl -Evidence $evidence -DesiredState (New-IncidentExerciseDesiredState) -EntitlementVerdict (New-IncidentExerciseEntitlement) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^IncidentExerciseQuarterlyCadenceDrift:'
        }

        It 'fails naming a missing phishing or remediation exercise type' {
            # Arrange
            $payload = [pscustomobject]@{ ExerciseId = 'IR-partial'; CompletedAtUtc = [datetime]::UtcNow.AddDays(-14); ExerciseTypes = @('PhishingSimulation'); Owners = @('soc-owner@contoso.example', 'messaging-owner@contoso.example'); Actions = @([pscustomobject]@{ ActionId = 'SEC-2'; Owner = 'soc-owner@contoso.example'; Status = 'Closed'; TrackingReference = 'INC-2' }) }
            $decision = New-IncidentExerciseDecision -Admitted @([pscustomobject]@{ Evidence = [pscustomobject]@{ ControlId = 'OPS-002'; Payload = $payload } })
            $evidence = New-IncidentExerciseRecord -Decision $decision

            # Act
            $actual = Test-IncidentExerciseControl -Evidence $evidence -DesiredState (New-IncidentExerciseDesiredState) -EntitlementVerdict (New-IncidentExerciseEntitlement) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^IncidentExerciseTypeDrift:.*RemediationValidation'
        }

        It 'fails naming a required owner absent from the exercise' {
            # Arrange
            $payload = [pscustomobject]@{ ExerciseId = 'IR-owner'; CompletedAtUtc = [datetime]::UtcNow.AddDays(-14); ExerciseTypes = @('PhishingSimulation', 'RemediationValidation'); Owners = @('soc-owner@contoso.example'); Actions = @([pscustomobject]@{ ActionId = 'SEC-3'; Owner = 'soc-owner@contoso.example'; Status = 'Closed'; TrackingReference = 'INC-3' }) }
            $decision = New-IncidentExerciseDecision -Admitted @([pscustomobject]@{ Evidence = [pscustomobject]@{ ControlId = 'OPS-002'; Payload = $payload } })
            $evidence = New-IncidentExerciseRecord -Decision $decision

            # Act
            $actual = Test-IncidentExerciseControl -Evidence $evidence -DesiredState (New-IncidentExerciseDesiredState) -EntitlementVerdict (New-IncidentExerciseEntitlement) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^IncidentExerciseOwnerDrift:.*messaging-owner@contoso\.example'
        }

        It 'fails when a remediation action has no owner or tracking reference' {
            # Arrange
            $payload = [pscustomobject]@{ ExerciseId = 'IR-action'; CompletedAtUtc = [datetime]::UtcNow.AddDays(-14); ExerciseTypes = @('PhishingSimulation', 'RemediationValidation'); Owners = @('soc-owner@contoso.example', 'messaging-owner@contoso.example'); Actions = @([pscustomobject]@{ ActionId = 'SEC-4'; Owner = ''; Status = 'Open'; TrackingReference = '' }) }
            $decision = New-IncidentExerciseDecision -Admitted @([pscustomobject]@{ Evidence = [pscustomobject]@{ ControlId = 'OPS-002'; Payload = $payload } })
            $evidence = New-IncidentExerciseRecord -Decision $decision

            # Act
            $actual = Test-IncidentExerciseControl -Evidence $evidence -DesiredState (New-IncidentExerciseDesiredState) -EntitlementVerdict (New-IncidentExerciseEntitlement) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^IncidentExerciseActionTrackingDrift:.*SEC-4'
        }
    }

    Context 'Positive: one current signed quarterly exercise' {
        It 'passes complete phish and remediation evidence with named owners and tracked actions' {
            # Arrange
            $evidence = New-IncidentExerciseRecord

            # Act
            $actual = Test-IncidentExerciseControl -Evidence $evidence -DesiredState (New-IncidentExerciseDesiredState) -EntitlementVerdict (New-IncidentExerciseEntitlement) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.ControlId | Should -BeExactly 'OPS-002'
            $actual.Status | Should -BeExactly 'Pass'
            $actual.GoLiveSuccess | Should -BeTrue
        }
    }
}