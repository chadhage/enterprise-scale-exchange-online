#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:CatalogPath = Join-Path $script:SampleRoot 'docs' 'CONTROL-CATALOG.md'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:TenantId = '11111111-2222-4333-8444-555555555555'
    $script:DeploymentProfile = 'MicrosoftNative'
    $script:ConfigurationHash = 'sha256:a3f1c9d2b4e6708192a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f809'
    $script:CollectionTimeUtc = '2026-09-19T12:00:00.0000000Z'

    function Copy-ReconciliationContract {
        [CmdletBinding()]
        param([Parameter(Mandatory)][object]$InputObject)

        return ($InputObject | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20)
    }

    function New-ReconciliationContract {
        [CmdletBinding()]
        param()

        $declaredControl = Get-BaselineControlCatalog -Path $script:CatalogPath
        $catalog = @($declaredControl)
        $evidence = foreach ($controlId in $catalog) {
            [pscustomobject]@{
                ControlId      = $controlId
                CollectedAtUtc = $script:CollectionTimeUtc
            }
        }
        $result = foreach ($controlId in $catalog) {
            [pscustomobject]@{
                ControlId = $controlId
                Status    = 'Pass'
            }
        }

        return [pscustomobject]@{
            Fixture = [pscustomobject]@{
                Binding = [pscustomobject]@{
                    TenantId          = $script:TenantId
                    DeploymentProfile = $script:DeploymentProfile
                    ConfigurationHash = $script:ConfigurationHash
                    CollectedAtUtc    = $script:CollectionTimeUtc
                }
            }
            Artifact = [pscustomobject]@{
                Envelope = [pscustomobject]@{
                    TenantId          = $script:TenantId
                    DeploymentProfile = $script:DeploymentProfile
                    ConfigurationHash = $script:ConfigurationHash
                    CollectedAtUtc    = $script:CollectionTimeUtc
                    Evidence          = @($evidence)
                    Check             = @($result)
                }
                GoLiveDecision = [pscustomobject]@{ Admitted = $true }
                Outcome        = [pscustomobject]@{ ExitCode = 0 }
                ProcessExitCode = 0
            }
        }
    }

    function Test-Tst006CatalogReconciliation {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][object]$Fixture,
            [Parameter(Mandatory)][object]$Artifact
        )

        $finding = [System.Collections.Generic.List[string]]::new()
        $evidenceCoverage = Test-BaselineControlCoverage -CatalogPath $script:CatalogPath `
            -Observed @($Artifact.Envelope.Evidence) -Subject 'TST-006 evidence'
        $resultCoverage = Test-BaselineControlCoverage -CatalogPath $script:CatalogPath `
            -Observed @($Artifact.Envelope.Check) -Subject 'TST-006 result'

        foreach ($controlId in @($evidenceCoverage.Missing)) { $finding.Add("EvidenceControlMissing: $controlId") }
        foreach ($controlId in @($evidenceCoverage.Unknown)) { $finding.Add("EvidenceControlUnknown: $controlId") }
        foreach ($controlId in @($evidenceCoverage.Duplicated)) { $finding.Add("EvidenceControlDuplicated: $controlId") }
        foreach ($controlId in @($resultCoverage.Missing)) { $finding.Add("ResultControlMissing: $controlId") }
        foreach ($controlId in @($resultCoverage.Unknown)) { $finding.Add("ResultControlUnknown: $controlId") }
        foreach ($controlId in @($resultCoverage.Duplicated)) { $finding.Add("ResultControlDuplicated: $controlId") }

        if ([string]$Artifact.Envelope.TenantId -cne [string]$Fixture.Binding.TenantId) {
            $finding.Add('ArtifactTenantMismatch')
        }
        if ([string]$Artifact.Envelope.DeploymentProfile -cne [string]$Fixture.Binding.DeploymentProfile) {
            $finding.Add('ArtifactProfileMismatch')
        }
        if ([string]$Artifact.Envelope.ConfigurationHash -cne [string]$Fixture.Binding.ConfigurationHash) {
            $finding.Add('ArtifactConfigurationHashMismatch')
        }
        if ([string]$Artifact.Envelope.CollectedAtUtc -cne [string]$Fixture.Binding.CollectedAtUtc) {
            $finding.Add('ArtifactCollectionTimeMismatch')
        }

        foreach ($record in @($Artifact.Envelope.Evidence)) {
            if ([string]$record.CollectedAtUtc -cne [string]$Fixture.Binding.CollectedAtUtc) {
                $finding.Add("EvidenceCollectionTimeMismatch: $($record.ControlId)")
            }
        }

        if (-not [bool]$Artifact.GoLiveDecision.Admitted) { $finding.Add('GoLiveRunNotAdmitted') }
        if ([int]$Artifact.Outcome.ExitCode -ne 0) { $finding.Add('RunOutcomeExitCodeMismatch') }
        if ([int]$Artifact.ProcessExitCode -ne 0) { $finding.Add('ProcessExitCodeMismatch') }
        if ([int]$Artifact.Outcome.ExitCode -ne [int]$Artifact.ProcessExitCode) { $finding.Add('ExitCodeDisagreement') }

        return [pscustomobject]@{
            Satisfied = ($finding.Count -eq 0)
            Finding   = @($finding)
        }
    }

    function Get-ReconciliationFold {
        [CmdletBinding()]
        param([Parameter(Mandatory)][object]$Contract)

        $verdict = Test-Tst006CatalogReconciliation -Fixture $Contract.Fixture -Artifact $Contract.Artifact
        return '{0}|{1}' -f $verdict.Satisfied, (@($verdict.Finding) -join '|')
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'TST-006 emitted catalog and binding reconciliation' {
    Context 'Negative: every catalog control must emit exactly one evidence record' {
        It 'refuses a missing evidence record by control ID' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.Envelope.Evidence = @($contract.Artifact.Envelope.Evidence | Select-Object -Skip 1)

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|EvidenceControlMissing: EXO-001'
        }

        It 'refuses a duplicate evidence record by control ID' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.Envelope.Evidence = @($contract.Artifact.Envelope.Evidence) + @($contract.Artifact.Envelope.Evidence[0])

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|EvidenceControlDuplicated: EXO-001'
        }

        It 'refuses an evidence record for an unknown control ID' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.Envelope.Evidence[0].ControlId = 'EXO-999'

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|EvidenceControlMissing: EXO-001|EvidenceControlUnknown: EXO-999'
        }
    }

    Context 'Negative: every catalog control must emit exactly one result' {
        It 'refuses a missing result by control ID' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.Envelope.Check = @($contract.Artifact.Envelope.Check | Select-Object -Skip 1)

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|ResultControlMissing: EXO-001'
        }

        It 'refuses a duplicate result by control ID' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.Envelope.Check = @($contract.Artifact.Envelope.Check) + @($contract.Artifact.Envelope.Check[0])

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|ResultControlDuplicated: EXO-001'
        }

        It 'refuses a result for an unknown control ID' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.Envelope.Check[0].ControlId = 'EXO-999'

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|ResultControlMissing: EXO-001|ResultControlUnknown: EXO-999'
        }
    }

    Context 'Negative: emitted records must retain the fixture bindings' {
        It 'refuses an artifact bound to another tenant' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.Envelope.TenantId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|ArtifactTenantMismatch'
        }

        It 'refuses an artifact bound to another deployment profile' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.Envelope.DeploymentProfile = 'ThirdPartyGateway'

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|ArtifactProfileMismatch'
        }

        It 'refuses an artifact bound to another canonical configuration hash' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.Envelope.ConfigurationHash = 'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|ArtifactConfigurationHashMismatch'
        }

        It 'refuses an envelope stamped with another collection time' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.Envelope.CollectedAtUtc = '2026-09-19T12:00:01.0000000Z'

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|ArtifactCollectionTimeMismatch'
        }

        It 'refuses an evidence record stamped with another collection time' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.Envelope.Evidence[0].CollectedAtUtc = '2026-09-19T12:00:01.0000000Z'

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|EvidenceCollectionTimeMismatch: EXO-001'
        }
    }

    Context 'Negative: admission and emitted exit state must agree on success' {
        It 'refuses a go-live decision that did not admit the run' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.GoLiveDecision.Admitted = $false

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|GoLiveRunNotAdmitted'
        }

        It 'refuses an emitted run outcome that is not exit zero' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.Outcome.ExitCode = 3

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|RunOutcomeExitCodeMismatch|ExitCodeDisagreement'
        }

        It 'refuses a public-command process exit that is not zero' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.ProcessExitCode = 3

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|ProcessExitCodeMismatch|ExitCodeDisagreement'
        }

        It 'refuses disagreement between the emitted outcome and public-command process exit' {
            # Arrange
            $contract = New-ReconciliationContract
            $contract.Artifact.Outcome.ExitCode = 4
            $contract.Artifact.ProcessExitCode = 3

            # Act
            $actual = Get-ReconciliationFold -Contract $contract

            # Assert
            $actual | Should -BeExactly 'False|RunOutcomeExitCodeMismatch|ProcessExitCodeMismatch|ExitCodeDisagreement'
        }
    }

    Context 'Positive: one complete admitted artifact agrees with its fixture and public exit' {
        It 'reconciles every catalog record and all run bindings exactly once' {
            # Arrange
            $contract = New-ReconciliationContract
            $declaredControl = Get-BaselineControlCatalog -Path $script:CatalogPath
            $catalogCount = @($declaredControl).Count

            # Act
            $verdict = Test-Tst006CatalogReconciliation -Fixture $contract.Fixture -Artifact $contract.Artifact
            $actual = '{0}|evidence={1}/{2}|result={3}/{2}|tenant={4}|profile={5}|hash={6}|time={7}|admitted={8}|outcome={9}|process={10}' -f `
                $verdict.Satisfied,
            @($contract.Artifact.Envelope.Evidence).Count,
            $catalogCount,
            @($contract.Artifact.Envelope.Check).Count,
            $contract.Artifact.Envelope.TenantId,
            $contract.Artifact.Envelope.DeploymentProfile,
            $contract.Artifact.Envelope.ConfigurationHash,
            $contract.Artifact.Envelope.CollectedAtUtc,
            $contract.Artifact.GoLiveDecision.Admitted,
            $contract.Artifact.Outcome.ExitCode,
            $contract.Artifact.ProcessExitCode

            # Assert
            $actual | Should -BeExactly "True|evidence=43/43|result=43/43|tenant=$script:TenantId|profile=MicrosoftNative|hash=$script:ConfigurationHash|time=$script:CollectionTimeUtc|admitted=True|outcome=0|process=0"
        }
    }
}