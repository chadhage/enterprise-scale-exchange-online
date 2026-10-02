BeforeAll {
    $script:root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:report = Join-Path $script:root 'scripts/New-ExchangeChangeEvidenceReport.ps1'
    $script:tenant = '11111111-2222-3333-4444-555555555555'

    function New-EvidenceFixture {
        param([string[]]$Omit = @(), [string]$ApplyStatus = 'Succeeded')
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path (Join-Path $directory 'evidence') -Force
        $id = 'CHG-1001'
        $files = [ordered]@{
            Preview    = @{ Name = "preview-$($id).json"; Content = @{
                    ChangeId = $id; Tenant = $script:tenant; DeploymentProfile = 'ExchangeOnly'; ConfigurationHash = 'abc123'
                    Scope = @('Transport'); GeneratedOn = '2026-01-01T00:00:00Z'; ExpiresOn = '2026-01-02T00:00:00Z'
                    Operation = @(@{ Sequence = 1; OperationId = 'Transport-01'; Command = 'Set-TransportConfig'; Identity = 'Default'; Before = @{ SmtpClientAuthenticationDisabled = $false }; After = @{ SmtpClientAuthenticationDisabled = $true } })
                } }
            Approval   = @{ Name = "approval-$($id).json"; Content = @{ ChangeId = $id; ApprovalIdentity = 'approver@contoso.example'; ApprovalTimeUtc = '2026-01-01T01:00:00Z' } }
            PreChange  = @{ Name = "prechange-$($id).json"; Content = @{ ChangeId = $id } }
            Apply      = @{ Name = "apply-$($id).json"; Content = @{ ChangeId = $id; Status = $ApplyStatus; Fault = ''; CompletedOn = '2026-01-01T02:00:00Z'; Operation = @(@{ OperationId = 'Transport-01'; State = 'Succeeded'; Fault = '' }) } }
            Rollback   = @{ Name = "rollback-$($id).ps1"; Content = $null }
            PostChange = @{ Name = "postchange-$($id).json"; Content = @{ ChangeId = $id; Status = $ApplyStatus } }
        }
        foreach ($key in $files.Keys) {
            if ($key -in $Omit) { continue }
            $path = Join-Path $directory $files[$key].Name
            if ($key -in 'Approval', 'Apply', 'PostChange' -and 'Preview' -notin $Omit) {
                $files[$key].Content.Tenant = $script:tenant
                $files[$key].Content.DeploymentProfile = 'ExchangeOnly'
                $files[$key].Content.PreviewHash = (Get-FileHash -LiteralPath (Join-Path $directory $files.Preview.Name) -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($key -ne 'Approval') { $files[$key].Content.ConfigurationHash = 'abc123' }
            }
            if ($null -eq $files[$key].Content) { Set-Content -LiteralPath $path -Value '#requires -Version 7.5' }
            else { $files[$key].Content | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path }
        }
        if ('Evidence' -notin $Omit) {
            @{
                TenantId = $script:tenant; DeploymentProfile = 'ExchangeOnly'; ConfigurationHash = 'abc123'; ManifestHash = 'def456'
                CollectedAtUtc = '2026-01-01T03:00:00Z'
                Check = @(
                    @{ ControlId = 'EXO-001'; Status = 'Pass'; Reason = '' }
                    @{ ControlId = 'EXO-002'; Status = 'Fail'; Reason = 'SMTP AUTH still enabled on 2 mailboxes' }
                    @{ ControlId = 'EXO-003'; Status = 'Manual'; Reason = 'Owner evidence required' }
                )
                Exclusion = @(@{ ControlId = 'EXO-009'; Reason = 'Out of scope' })
                ExternalReadiness = @(@{ ControlId = 'EXT-001'; Status = 'Unverified'; Owner = 'DNS team' })
            } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $directory 'evidence/exchange-online-evidence.json')
        }
        $directory
    }
}

Describe 'New-ExchangeChangeEvidenceReport.ps1' {
    It 'refuses a change identifier that could escape the artifact folder' {
        # Arrange
        $root = New-EvidenceFixture
        # Act
        $act = { & $script:report -ArtifactRoot $root -ChangeId '..\CHG-1001' -InformationAction Ignore }
        # Assert
        $act | Should -Throw '*ChangeIdentifierNotRecognized*'
    }

    It 'refuses a missing artifact folder with the fix' {
        # Arrange
        $missing = Join-Path $TestDrive 'not-there'
        # Act
        $act = { & $script:report -ArtifactRoot $missing -ChangeId 'CHG-1001' -InformationAction Ignore }
        # Assert
        $act | Should -Throw '*ArtifactRootMissing*'
    }

    It 'refuses to summarise when evidence was never collected and names the command to run' {
        # Arrange
        $root = New-EvidenceFixture -Omit 'Evidence'
        # Act
        $message = try { & $script:report -ArtifactRoot $root -ChangeId 'CHG-1001' -InformationAction Ignore; '' } catch { $_.Exception.Message }
        # Assert
        $message | Should -BeLike '*EvidenceMissing*Test-ExchangeOnlineBaseline.ps1*'
        $message | Should -Not -BeLike '*SkipConnection*'
    }

    It 'refuses unreadable evidence JSON' {
        # Arrange
        $root = New-EvidenceFixture
        Set-Content -LiteralPath (Join-Path $root 'evidence/exchange-online-evidence.json') -Value '{ not json'
        # Act
        $act = { & $script:report -ArtifactRoot $root -ChangeId 'CHG-1001' -InformationAction Ignore }
        # Assert
        $act | Should -Throw '*EvidenceUnreadable*'
    }

    It 'refuses an output path that would overwrite the <Source> input' -ForEach @(
        @{ Source = 'preview'; RelativePath = 'preview-CHG-1001.json' }
        @{ Source = 'apply'; RelativePath = 'apply-CHG-1001.json' }
        @{ Source = 'evidence'; RelativePath = 'evidence\exchange-online-evidence.json' }
    ) {
        # Arrange
        $root = New-EvidenceFixture
        $sourcePath = Join-Path $root $RelativePath
        $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($sourcePath))
        # Act
        $act = { & $script:report -ArtifactRoot $root -ChangeId 'CHG-1001' -OutputPath $sourcePath -InformationAction Ignore }
        # Assert
        $act | Should -Throw '*EvidenceReportOutputPathCollision*'
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($sourcePath)) | Should -BeExactly $before
    }

    It 'refuses an output path that resolves to the custom evidence input' {
        # Arrange
        $root = New-EvidenceFixture
        $evidencePath = Join-Path $root 'evidence\exchange-online-evidence.json'
        $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($evidencePath))
        # Act
        $act = { & $script:report -ArtifactRoot $root -ChangeId 'CHG-1001' -EvidencePath $evidencePath -OutputPath $evidencePath -InformationAction Ignore }
        # Assert
        $act | Should -Throw '*EvidenceReportOutputPathCollision*'
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($evidencePath)) | Should -BeExactly $before
    }

    It 'reports missing change artifacts as missing and marks the record incomplete' {
        # Arrange
        $root = New-EvidenceFixture -Omit 'Rollback', 'PostChange'
        # Act
        $result = & $script:report -ArtifactRoot $root -ChangeId 'CHG-1001' -PassThru -InformationAction Ignore
        $markdown = Get-Content -LiteralPath $result.Path -Raw
        # Assert
        $result.Complete | Should -BeFalse
        $result.MissingArtifact | Should -Be @('Rollback', 'PostChange')
        $markdown | Should -Match '\| Rollback \| `rollback-CHG-1001\.ps1` \| \*\*Missing\*\*'
        $markdown | Should -Match 'INCOMPLETE'
    }

    It 'does not call a failed apply a success' {
        # Arrange
        $root = New-EvidenceFixture -ApplyStatus 'Failed'
        # Act
        $result = & $script:report -ArtifactRoot $root -ChangeId 'CHG-1001' -PassThru -InformationAction Ignore
        # Assert
        $result.Complete | Should -BeFalse
        (Get-Content -LiteralPath $result.Path -Raw) | Should -Match 'Apply status \| Failed'
    }

    It 'does not call evidence collected for <Field> <Value> evidence for this change' -ForEach @(
        @{ Field = 'TenantId'; Value = '99999999-2222-3333-4444-555555555555'; Label = 'Tenant' }
        @{ Field = 'DeploymentProfile'; Value = 'MicrosoftNative'; Label = 'DeploymentProfile' }
        @{ Field = 'ConfigurationHash'; Value = 'sha256:ffff'; Label = 'ConfigurationHash' }
        @{ Field = 'TenantId'; Value = ''; Label = 'Tenant' }
        @{ Field = 'CollectedAtUtc'; Value = '2026-01-01T01:00:00Z'; Label = 'CollectedAfterApply' }
    ) {
        # Arrange
        $root = New-EvidenceFixture
        $evidencePath = Join-Path $root 'evidence/exchange-online-evidence.json'
        $evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json -AsHashtable
        $evidence[$Field] = $Value
        $evidence | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $evidencePath
        # Act
        $result = & $script:report -ArtifactRoot $root -ChangeId 'CHG-1001' -PassThru -InformationAction Ignore
        $markdown = Get-Content -LiteralPath $result.Path -Raw
        # Assert
        $result.Complete | Should -BeFalse
        $result.Outcome | Should -BeExactly 'INCOMPLETE'
        $result.BindingMismatch | Should -Be @($Label)
        $markdown | Should -Match "\| $($Label) \| [^|]+ \| [^|]+ \| \*\*No\*\* \|"
        $markdown | Should -Match 'Recollect evidence'
    }

    It 'binds evidence whose configuration hash carries the sha256 prefix' {
        # Arrange
        $root = New-EvidenceFixture
        $evidencePath = Join-Path $root 'evidence/exchange-online-evidence.json'
        $evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json -AsHashtable
        $evidence.ConfigurationHash = 'sha256:ABC123'
        $evidence | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $evidencePath
        # Act
        $result = & $script:report -ArtifactRoot $root -ChangeId 'CHG-1001' -PassThru -InformationAction Ignore
        # Assert
        $result.Complete | Should -BeTrue
        $result.BindingMismatch | Should -BeNullOrEmpty
    }

    It 'marks an empty evidence check collection incomplete instead of claiming every check passed' {
        # Arrange
        $root = New-EvidenceFixture
        $evidencePath = Join-Path $root 'evidence/exchange-online-evidence.json'
        $evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json -AsHashtable
        $evidence.Check = @()
        $evidence | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $evidencePath
        # Act
        $result = & $script:report -ArtifactRoot $root -ChangeId 'CHG-1001' -PassThru -InformationAction Ignore
        $markdown = Get-Content -LiteralPath $result.Path -Raw
        # Assert
        $result.Complete | Should -BeFalse
        $result.Outcome | Should -BeExactly 'INCOMPLETE'
        $result.EvidenceCheckCount | Should -Be 0
        $markdown | Should -Match 'No evidence checks were found; evidence collection is incomplete'
        $markdown | Should -Not -Match 'Every check passed'
    }

    It 'marks evidence with no check collection incomplete' {
        # Arrange
        $root = New-EvidenceFixture
        $evidencePath = Join-Path $root 'evidence/exchange-online-evidence.json'
        $evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json -AsHashtable
        $evidence.Remove('Check')
        $evidence | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $evidencePath
        # Act
        $result = & $script:report -ArtifactRoot $root -ChangeId 'CHG-1001' -PassThru -InformationAction Ignore
        $markdown = Get-Content -LiteralPath $result.Path -Raw
        # Assert
        $result.Complete | Should -BeFalse
        $result.Outcome | Should -BeExactly 'INCOMPLETE'
        $result.EvidenceCheckCount | Should -Be 0
        $markdown | Should -Match 'No evidence checks were found; evidence collection is incomplete'
        $markdown | Should -Not -Match 'Every check passed'
    }

    It 'does not accept a <Artifact> artifact whose <Field> belongs to another change' -ForEach @(
        @{ Artifact = 'Approval'; Name = 'approval-CHG-1001.json'; Field = 'PreviewHash'; Value = ('0' * 64) }
        @{ Artifact = 'Approval'; Name = 'approval-CHG-1001.json'; Field = 'ChangeId'; Value = 'CHG-2002' }
        @{ Artifact = 'Apply'; Name = 'apply-CHG-1001.json'; Field = 'Tenant'; Value = '99999999-2222-3333-4444-555555555555' }
        @{ Artifact = 'Apply'; Name = 'apply-CHG-1001.json'; Field = 'ConfigurationHash'; Value = 'ffff' }
        @{ Artifact = 'PostChange'; Name = 'postchange-CHG-1001.json'; Field = 'PreviewHash'; Value = '' }
        @{ Artifact = 'Preview'; Name = 'preview-CHG-1001.json'; Field = 'ChangeId'; Value = 'CHG-2002' }
    ) {
        # Arrange
        $root = New-EvidenceFixture
        $path = Join-Path $root $Name
        $document = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable
        $document[$Field] = $Value
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path
        foreach ($dependent in 'approval', 'apply', 'postchange') {
            if ($Artifact -ne 'Preview') { break }
            $dependentPath = Join-Path $root "$($dependent)-CHG-1001.json"
            $record = Get-Content -LiteralPath $dependentPath -Raw | ConvertFrom-Json -AsHashtable
            $record.PreviewHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $dependentPath
        }
        # Act
        $result = & $script:report -ArtifactRoot $root -ChangeId 'CHG-1001' -PassThru -InformationAction Ignore
        $markdown = Get-Content -LiteralPath $result.Path -Raw
        # Assert
        $result.Complete | Should -BeFalse
        $result.Outcome | Should -BeExactly 'INCOMPLETE'
        $result.ArtifactMismatch | Should -Be @("$($Artifact) $($Field)")
        $markdown | Should -Match "do not belong to this change: $($Artifact) $($Field)"
    }

    It 'marks an Apply receipt with <Scenario> operation results incomplete' -ForEach @(
        @{ Scenario = 'no'; Operation = @() }
        @{ Scenario = 'duplicate'; Operation = @(
                @{ OperationId = 'Transport-01'; State = 'Succeeded'; Fault = '' }
                @{ OperationId = 'Transport-01'; State = 'Unchanged'; Fault = '' }
            ) }
        @{ Scenario = 'missing'; Operation = @(@{ OperationId = 'Other-01'; State = 'Succeeded'; Fault = '' }) }
        @{ Scenario = 'failed'; Operation = @(@{ OperationId = 'Transport-01'; State = 'Failed'; Fault = 'Mutation failed' }) }
        @{ Scenario = 'extra'; Operation = @(
                @{ OperationId = 'Transport-01'; State = 'Succeeded'; Fault = '' }
                @{ OperationId = 'Unexpected-01'; State = 'Succeeded'; Fault = '' }
            ) }
    ) {
        # Arrange
        $root = New-EvidenceFixture
        $applyPath = Join-Path $root 'apply-CHG-1001.json'
        $apply = Get-Content -LiteralPath $applyPath -Raw | ConvertFrom-Json -AsHashtable
        $apply.Operation = $Operation
        $apply | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $applyPath
        # Act
        $result = & $script:report -ArtifactRoot $root -ChangeId 'CHG-1001' -PassThru -InformationAction Ignore
        $markdown = Get-Content -LiteralPath $result.Path -Raw
        # Assert
        $result.Complete | Should -BeFalse
        $result.Outcome | Should -BeExactly 'INCOMPLETE'
        $result.OperationMismatch | Should -Not -BeNullOrEmpty
        $markdown | Should -Match 'Apply operation results do not match the preview'
    }

    It 'accepts one Unchanged Apply result for each preview operation' {
        # Arrange
        $root = New-EvidenceFixture
        $applyPath = Join-Path $root 'apply-CHG-1001.json'
        $apply = Get-Content -LiteralPath $applyPath -Raw | ConvertFrom-Json -AsHashtable
        $apply.Operation[0].State = 'Unchanged'
        $apply | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $applyPath
        # Act
        $result = & $script:report -ArtifactRoot $root -ChangeId 'CHG-1001' -PassThru -InformationAction Ignore
        # Assert
        $result.Complete | Should -BeTrue
        $result.OperationMismatch | Should -BeNullOrEmpty
    }

    It 'writes a Markdown summary of every artifact, operation and evidence result' {
        # Arrange
        $root = New-EvidenceFixture
        # Act
        $result = & $script:report -ArtifactRoot $root -ChangeId 'CHG-1001' -PassThru -InformationAction Ignore
        $markdown = Get-Content -LiteralPath $result.Path -Raw
        # Assert
        $result.Path | Should -Be (Join-Path $root 'evidence-report-CHG-1001.md')
        $result.Complete | Should -BeTrue
        $result.ArtifactMismatch | Should -BeNullOrEmpty
        $result.StatusCount.Fail | Should -Be 1
        $markdown | Should -Match '^# Exchange Online change evidence report: CHG-1001'
        $markdown | Should -Match "Tenant \| $($script:tenant)"
        $markdown | Should -Match 'Scope \| Transport'
        $markdown | Should -Match 'Approved by \| approver@contoso\.example'
        $markdown | Should -Match '\| 1 \| `Set-TransportConfig` \| Default \| Succeeded \|'
        $markdown | Should -Match '\| Pass \| 1 \|'
        $markdown | Should -Match '\| EXO-002 \| Fail \| SMTP AUTH still enabled on 2 mailboxes \|'
        $markdown | Should -Not -Match '\| EXO-001 \|'
        $markdown | Should -Match 'EXT-001'
        $markdown | Should -Match 'not a go-live approval'
        $markdown | Should -Match '\| Tenant \| [^|]+ \| [^|]+ \| Yes \|'
        $hash = (Get-FileHash -LiteralPath (Join-Path $root 'apply-CHG-1001.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        $markdown | Should -Match $hash
    }
}
