#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:CommonModule = Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -PassThru -ErrorAction Stop
    $script:DecisionTime = [datetime]::new(2026, 9, 19, 12, 0, 0, [System.DateTimeKind]::Utc)

    $script:DriftDesired = [pscustomobject]@{
        scheduledCollectionEnabled = $true
        collectionFrequencyHours   = 24
        minimumRetentionDays       = 180
        maximumEvidenceAgeHours    = 24
        requireSignedEvidence      = $true
    }
    $script:ChangeDesired = [pscustomobject]@{
        maximumEvidenceAgeHours = 24
        requireSignedEvidence   = $true
        requirePreview          = $true
        requirePilot            = $true
        requireApproval         = $true
        requireRollback         = $true
        requirePostChange       = $true
    }

    function New-DriftArtifact {
        param([hashtable]$Override = @{})
        $value = [ordered]@{
            Complete                 = $true
            Refused                  = @()
            ScheduledCollection      = $true
            CollectionFrequencyHours = 24
            RetentionDays            = 180
            GeneratedAtUtc           = $script:DecisionTime.AddHours(-1)
            SignatureVerified        = $true
            DriftDetected            = $false
            Findings                 = @()
        }
        foreach ($key in $Override.Keys) { $value[$key] = $Override[$key] }
        [pscustomobject]$value
    }

    function New-ChangeArtifact {
        param([hashtable]$Override = @{})
        $changeId = 'CHG-2026-0919-001'
        $value = [ordered]@{
            Complete          = $true
            Refused           = @()
            ChangeId          = $changeId
            GeneratedAtUtc    = $script:DecisionTime.AddHours(-1)
            SignatureVerified = $true
            Preview           = [pscustomobject]@{ ChangeId = $changeId; Completed = $true }
            Pilot             = [pscustomobject]@{ ChangeId = $changeId; Completed = $true }
            Approval          = [pscustomobject]@{ ChangeId = $changeId; Completed = $true }
            Rollback          = [pscustomobject]@{ ChangeId = $changeId; Completed = $true }
            PostChange        = [pscustomobject]@{ ChangeId = $changeId; Completed = $true }
        }
        foreach ($key in $Override.Keys) { $value[$key] = $Override[$key] }
        [pscustomobject]$value
    }

    function Get-TestDriftEvidence {
        param([AllowNull()][scriptblock]$Collection)
        & $script:CommonModule { param($Call) Get-DriftEvidenceEvidence -DriftEvidenceCollection $Call } $Collection
    }

    function Test-DriftFixture {
        param([object]$Evidence, [AllowNull()][object]$DesiredState = $script:DriftDesired)
        & $script:CommonModule {
            param($Record, $Desired, $At)
            Test-DriftEvidenceControl -Evidence $Record -DesiredState $Desired -AsOfUtc $At
        } $Evidence $DesiredState $script:DecisionTime
    }

    function Get-TestChangeEvidence {
        param([AllowNull()][scriptblock]$Collection)
        & $script:CommonModule { param($Call) Get-ChangeSafetyEvidence -ChangeArtifactCollection $Call } $Collection
    }

    function Test-ChangeFixture {
        param([object]$Evidence, [AllowNull()][object]$DesiredState = $script:ChangeDesired)
        & $script:CommonModule {
            param($Record, $Desired, $At)
            Test-ChangeSafetyControl -Evidence $Record -DesiredState $Desired -AsOfUtc $At
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

Describe 'MON-003 drift evidence collector' {
    Context 'Negative: collection prerequisites and refusals are named' {
        It 'refuses a missing injected drift-evidence collection' {
            # Arrange
            $collection = $null

            # Act
            $act = { Get-TestDriftEvidence -Collection $collection }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DriftEvidenceCollectionRequired:*'
        }

        It 'records a refused scheduled collection without manufacturing drift state' {
            # Arrange
            $collection = { throw 'offline drift store refused access' }

            # Act
            $evidence = Get-TestDriftEvidence -Collection $collection

            # Assert
            ('{0}|{1}|{2}|{3}' -f $evidence.ControlId, $evidence.Collected, $evidence.Command, $evidence.FailureReason) |
                Should -BeLike 'MON-003|False|Get-ScheduledDriftEvidence|CollectionFailed:*offline drift store refused access*'
        }
    }

    Context 'Positive: one complete scheduled artifact is preserved' {
        It 'collects the signed drift artifact without reshaping it' {
            # Arrange
            $artifact = New-DriftArtifact
            $collection = { $artifact }.GetNewClosure()

            # Act
            $evidence = Get-TestDriftEvidence -Collection $collection

            # Assert
            ('{0}|{1}|{2}|{3}|{4}|{5}' -f $evidence.ControlId, $evidence.Collected, $evidence.Command,
                $evidence.Value.RetentionDays, $evidence.Value.SignatureVerified, $evidence.Value.GeneratedAtUtc.ToString('o')) |
                Should -BeExactly "MON-003|True|Get-ScheduledDriftEvidence|180|True|$($artifact.GeneratedAtUtc.ToString('o'))"
        }
    }
}

Describe 'MON-003 drift evidence evaluator' {
    Context 'Negative: unresolved and partial evidence fails closed by name' {
        It 'refuses missing resolved drift desired state' {
            # Arrange
            $evidence = New-BaselineEvidence -ControlId 'MON-003' -Source 'MonitoringEvidence' -Command 'fixture' -Value (New-DriftArtifact)

            # Act
            $act = { Test-DriftFixture -Evidence $evidence -DesiredState $null }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DesiredDriftEvidenceStateRequired:*'
        }

        It 'errors when the drift artifact is partial' {
            # Arrange
            $artifact = New-DriftArtifact -Override @{ Complete = $false }
            $evidence = New-BaselineEvidence -ControlId 'MON-003' -Source 'MonitoringEvidence' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-DriftFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|DriftEvidenceIncomplete:*'
        }

        It 'preserves a named drift-evidence refusal' {
            # Arrange
            $artifact = New-DriftArtifact -Override @{ Refused = @('archive page 3 unavailable') }
            $evidence = New-BaselineEvidence -ControlId 'MON-003' -Source 'MonitoringEvidence' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-DriftFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|DriftEvidenceRefused:*archive page 3 unavailable*'
        }

        It 'errors when signed drift evidence cannot be verified' {
            # Arrange
            $artifact = New-DriftArtifact -Override @{ SignatureVerified = $false }
            $evidence = New-BaselineEvidence -ControlId 'MON-003' -Source 'MonitoringEvidence' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-DriftFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|DriftEvidenceSignatureRefused:*'
        }

        It 'errors when drift evidence is stale' {
            # Arrange
            $artifact = New-DriftArtifact -Override @{ GeneratedAtUtc = $script:DecisionTime.AddHours(-25) }
            $evidence = New-BaselineEvidence -ControlId 'MON-003' -Source 'MonitoringEvidence' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-DriftFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|DriftEvidenceStale:*25*24*'
        }
    }

    Context 'Negative: schedule, retention and current drift fail their own control' {
        It 'fails when scheduled drift collection is disabled' {
            # Arrange
            $artifact = New-DriftArtifact -Override @{ ScheduledCollection = $false }
            $evidence = New-BaselineEvidence -ControlId 'MON-003' -Source 'MonitoringEvidence' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-DriftFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|DriftCollectionScheduleDrift:*disabled*'
        }

        It 'fails when the collection cadence exceeds the declared schedule' {
            # Arrange
            $artifact = New-DriftArtifact -Override @{ CollectionFrequencyHours = 25 }
            $evidence = New-BaselineEvidence -ControlId 'MON-003' -Source 'MonitoringEvidence' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-DriftFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|DriftCollectionScheduleDrift:*25*24*'
        }

        It 'fails retention below the 180-day control floor' {
            # Arrange
            $artifact = New-DriftArtifact -Override @{ RetentionDays = 179 }
            $evidence = New-BaselineEvidence -ControlId 'MON-003' -Source 'MonitoringEvidence' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-DriftFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|DriftEvidenceRetentionDrift:*179*180*'
        }

        It 'fails when fresh evidence reports current control drift' {
            # Arrange
            $artifact = New-DriftArtifact -Override @{ DriftDetected = $true; Findings = @('EXO-003 outbound forwarding drift') }
            $evidence = New-BaselineEvidence -ControlId 'MON-003' -Source 'MonitoringEvidence' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-DriftFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Fail|golive=False|CurrentControlDrift:*EXO-003 outbound forwarding drift*'
        }
    }

    Context 'Positive: one fresh signed scheduled drift fixture passes' {
        It 'validates both profiles and passes a complete artifact retained for at least 180 days' {
            # Arrange
            $profilePath = @(
                (Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'),
                (Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.microsoft-native.json')
            )
            $schemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
            $evidence = New-BaselineEvidence -ControlId 'MON-003' -Source 'MonitoringEvidence' -Command 'fixture' -Value (New-DriftArtifact)

            # Act
            $actual = & {
                $profiles = @($profilePath | ForEach-Object { Get-Content -LiteralPath $_ -Raw | ConvertFrom-Json })
                $schemaValid = @($profilePath | ForEach-Object { Test-Json -Path $_ -SchemaFile $schemaPath -ErrorAction Stop })
                $results = @($profiles | ForEach-Object {
                        Test-DriftFixture -Evidence $evidence -DesiredState $_.desiredState.centralMonitoring.driftEvidence
                    })
                [pscustomobject]@{ Profiles = $profiles; SchemaValid = $schemaValid; Results = $results }
            }

            # Assert
            @($actual.SchemaValid | Where-Object { $_ -ne $true }).Count | Should -Be 0
            @($actual.Profiles | Where-Object { $_.desiredState.centralMonitoring.driftEvidence.minimumRetentionDays -lt 180 }).Count | Should -Be 0
            @($actual.Results | ForEach-Object { Get-ResultText $_ } | Sort-Object -Unique) |
                Should -Be @('Pass|golive=True|')
        }
    }
}

Describe 'OPS-001 change-safety collector' {
    Context 'Negative: change-artifact collection prerequisites and refusals are named' {
        It 'refuses a missing injected change-artifact collection' {
            # Arrange
            $collection = $null

            # Act
            $act = { Get-TestChangeEvidence -Collection $collection }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangeArtifactCollectionRequired:*'
        }

        It 'records a refused change-artifact collection without manufacturing safety state' {
            # Arrange
            $collection = { throw 'offline change archive refused access' }

            # Act
            $evidence = Get-TestChangeEvidence -Collection $collection

            # Assert
            ('{0}|{1}|{2}|{3}' -f $evidence.ControlId, $evidence.Collected, $evidence.Command, $evidence.FailureReason) |
                Should -BeLike 'OPS-001|False|Get-ChangeSafetyArtifactSet|CollectionFailed:*offline change archive refused access*'
        }
    }

    Context 'Positive: one complete change artifact set is preserved' {
        It 'collects all safety phases without reshaping them' {
            # Arrange
            $artifact = New-ChangeArtifact
            $collection = { $artifact }.GetNewClosure()

            # Act
            $evidence = Get-TestChangeEvidence -Collection $collection

            # Assert
            ('{0}|{1}|{2}|{3}|{4}|{5}' -f $evidence.ControlId, $evidence.Collected, $evidence.Command,
                $evidence.Value.ChangeId, $evidence.Value.Pilot.ChangeId, $evidence.Value.PostChange.Completed) |
                Should -BeExactly 'OPS-001|True|Get-ChangeSafetyArtifactSet|CHG-2026-0919-001|CHG-2026-0919-001|True'
        }
    }
}

Describe 'OPS-001 change-safety evaluator' {
    Context 'Negative: unresolved, partial, stale and unsigned evidence fails closed' {
        It 'refuses missing resolved change-safety desired state' {
            # Arrange
            $evidence = New-BaselineEvidence -ControlId 'OPS-001' -Source 'ChangeArtifacts' -Command 'fixture' -Value (New-ChangeArtifact)

            # Act
            $act = { Test-ChangeFixture -Evidence $evidence -DesiredState $null }

            # Assert
            $act | Should -Throw -ExpectedMessage 'DesiredChangeSafetyStateRequired:*'
        }

        It 'errors when the change artifact set is partial' {
            # Arrange
            $artifact = New-ChangeArtifact -Override @{ Complete = $false }
            $evidence = New-BaselineEvidence -ControlId 'OPS-001' -Source 'ChangeArtifacts' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-ChangeFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|ChangeSafetyEvidenceIncomplete:*'
        }

        It 'preserves a named change-artifact refusal' {
            # Arrange
            $artifact = New-ChangeArtifact -Override @{ Refused = @('approval artifact unreadable') }
            $evidence = New-BaselineEvidence -ControlId 'OPS-001' -Source 'ChangeArtifacts' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-ChangeFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|ChangeSafetyEvidenceRefused:*approval artifact unreadable*'
        }

        It 'errors when signed change evidence cannot be verified' {
            # Arrange
            $artifact = New-ChangeArtifact -Override @{ SignatureVerified = $false }
            $evidence = New-BaselineEvidence -ControlId 'OPS-001' -Source 'ChangeArtifacts' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-ChangeFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|ChangeSafetySignatureRefused:*'
        }

        It 'errors when change evidence is stale' {
            # Arrange
            $artifact = New-ChangeArtifact -Override @{ GeneratedAtUtc = $script:DecisionTime.AddHours(-25) }
            $evidence = New-BaselineEvidence -ControlId 'OPS-001' -Source 'ChangeArtifacts' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-ChangeFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike 'Error|golive=False|ChangeSafetyEvidenceStale:*25*24*'
        }
    }

    Context 'Negative: every required phase exists, succeeds and binds to one change' {
        It "fails when the required '<Phase>' phase is absent" -ForEach @(
            @{ Phase = 'Preview' }, @{ Phase = 'Pilot' }, @{ Phase = 'Approval' },
            @{ Phase = 'Rollback' }, @{ Phase = 'PostChange' }
        ) {
            # Arrange
            $artifact = New-ChangeArtifact -Override @{ $Phase = $null }
            $evidence = New-BaselineEvidence -ControlId 'OPS-001' -Source 'ChangeArtifacts' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-ChangeFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike "Fail|golive=False|ChangeSafetyPhaseMissing:*$Phase*"
        }

        It "fails when the required '<Phase>' phase did not complete" -ForEach @(
            @{ Phase = 'Preview' }, @{ Phase = 'Pilot' }, @{ Phase = 'Approval' },
            @{ Phase = 'Rollback' }, @{ Phase = 'PostChange' }
        ) {
            # Arrange
            $changeId = 'CHG-2026-0919-001'
            $artifact = New-ChangeArtifact -Override @{ $Phase = [pscustomobject]@{ ChangeId = $changeId; Completed = $false } }
            $evidence = New-BaselineEvidence -ControlId 'OPS-001' -Source 'ChangeArtifacts' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-ChangeFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike "Fail|golive=False|ChangeSafetyPhaseRefused:*$Phase*"
        }

        It "fails when the '<Phase>' phase belongs to another change" -ForEach @(
            @{ Phase = 'Preview' }, @{ Phase = 'Pilot' }, @{ Phase = 'Approval' },
            @{ Phase = 'Rollback' }, @{ Phase = 'PostChange' }
        ) {
            # Arrange
            $artifact = New-ChangeArtifact -Override @{ $Phase = [pscustomobject]@{ ChangeId = 'CHG-OTHER'; Completed = $true } }
            $evidence = New-BaselineEvidence -ControlId 'OPS-001' -Source 'ChangeArtifacts' -Command 'fixture' -Value $artifact

            # Act
            $result = Test-ChangeFixture -Evidence $evidence

            # Assert
            (Get-ResultText $result) | Should -BeLike "Fail|golive=False|ChangeSafetyBindingDrift:*$Phase*CHG-OTHER*CHG-2026-0919-001*"
        }
    }

    Context 'Positive: one complete change is bound across every safety phase' {
        It 'validates both profiles and passes preview, pilot, approval, rollback and post-change for one change' {
            # Arrange
            $profilePath = @(
                (Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'),
                (Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.microsoft-native.json')
            )
            $schemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
            $evidence = New-BaselineEvidence -ControlId 'OPS-001' -Source 'ChangeArtifacts' -Command 'fixture' -Value (New-ChangeArtifact)

            # Act
            $actual = & {
                $profiles = @($profilePath | ForEach-Object { Get-Content -LiteralPath $_ -Raw | ConvertFrom-Json })
                $schemaValid = @($profilePath | ForEach-Object { Test-Json -Path $_ -SchemaFile $schemaPath -ErrorAction Stop })
                $results = @($profiles | ForEach-Object {
                        Test-ChangeFixture -Evidence $evidence -DesiredState $_.desiredState.operations.changeSafety
                    })
                [pscustomobject]@{ SchemaValid = $schemaValid; Results = $results }
            }

            # Assert
            @($actual.SchemaValid | Where-Object { $_ -ne $true }).Count | Should -Be 0
            @($actual.Results | ForEach-Object { Get-ResultText $_ } | Sort-Object -Unique) |
                Should -Be @('Pass|golive=True|')
        }
    }
}
