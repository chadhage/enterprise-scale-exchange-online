BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $publicCommandPath = Join-Path $sampleRoot 'scripts/Test-ExchangeOnlineBaseline.ps1'
    $harness = Join-Path $sampleRoot 'tests/helpers/ExchangeLiveRawHarness.ps1'
    . (Join-Path $sampleRoot 'tests/helpers/ExchangeGovernanceRawFixture.ps1')
    function Invoke-GovernanceRawCase {
        param($Mutation, [string]$Name)
        $parameters = Get-Content (Join-Path $sampleRoot 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
        $parameters.entitlement.verified = $true
        $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
        $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE','THREAT_INTELLIGENCE')
        $fixture = New-ExchangeGovernanceRawFixture $parameters
        if ($null -ne $Mutation) { & $Mutation $fixture }
        $parameters.governanceEvidence = @{ recipientFlows = $fixture.RecipientFlows }
        $parameterPath = Join-Path $TestDrive "$Name.parameters.json"
        $configPath = Join-Path $TestDrive "$Name.config.json"
        $rawPath = Join-Path $TestDrive "$Name.raw.json"
        $callsPath = Join-Path $TestDrive "$Name.calls"
        $outputPath = Join-Path $TestDrive $Name
        $parameters | ConvertTo-Json -Depth 50 | Set-Content $parameterPath
        $fixture.Configuration | ConvertTo-Json -Depth 50 | Set-Content $configPath
        $fixture.Raw | ConvertTo-Json -Depth 50 | Set-Content $rawPath
        $output = & pwsh -NoProfile -NonInteractive -File $harness $publicCommandPath $parameterPath $outputPath $rawPath $callsPath $configPath 2>&1 | Out-String
        if (-not (Test-Path (Join-Path $outputPath 'exchange-online-evidence.json'))) { throw "PublicEvidenceMissing: $output" }
        @{ Envelope = Get-Content (Join-Path $outputPath 'exchange-online-evidence.json') -Raw | ConvertFrom-Json; Calls = @(Get-Content $callsPath); Output = $output }
    }
}

Describe 'EXR-009 public raw governance collection' {
    It 'retains raw refusal for <Case>' -ForEach @(
        @{ Case = 'tag collection denied'; Control = 'GOV-003'; Command = 'Get-RetentionPolicyTag'; Mutation = { param($fixture) $fixture.Raw['Get-RetentionPolicyTag'].Error = 'Access denied' } }
        @{ Case = 'diagnostics collection denied'; Control = 'GOV-003'; Command = 'Export-MailboxDiagnosticLogs'; Mutation = { param($fixture) $fixture.Raw['Export-MailboxDiagnosticLogs'].Error = 'Access denied' } }
        @{ Case = 'role scopes truncated'; Control = 'EXO-010'; Command = 'Get-ManagementScope'; Mutation = { param($fixture) $fixture.Raw['Get-ManagementScope'].Warning = 'More results available' } }
        @{ Case = 'statistics throttled'; Control = 'GOV-004'; Command = 'Get-MailboxStatistics'; Mutation = { param($fixture) $fixture.Raw['Get-MailboxStatistics'].Error = '429 Too many requests' } }
        @{ Case = 'transport rules truncated'; Control = 'GOV-005'; Command = 'Get-TransportRule'; Mutation = { param($fixture) $fixture.Raw['Get-TransportRule'].Warning = 'More results available' } }
    ) {
        # Arrange
        $mutationScript = $Mutation
        # Act
        $run = Invoke-GovernanceRawCase $mutationScript $Case
        # Assert
        $check = $run.Envelope.Check | Where-Object ControlId -EQ $Control
        $check.Status | Should -Be Error -Because ($check.Reason + $run.Output)
        $observation = @(($run.Envelope.Evidence | Where-Object ControlId -EQ $Control).Observation | Where-Object Command -EQ $Command)
        $observation.Count | Should -Be 1
        $observation[0].Complete | Should -BeFalse
        $observation[0].Error | Should -Match 'denied|429|ExchangeRawWarning'
        $run.Calls -join ' ' | Should -Not -Match 'EXCLUDED:'
    }
    It 'collects and evaluates one approved governance contract through public evidence' {
        # Arrange
        $caseName = 'approved-governance'
        # Act
        $run = Invoke-GovernanceRawCase $null $caseName
        # Assert
        foreach ($controlId in @('EXO-006','EXO-010','EXO-012','GOV-003','GOV-004','GOV-005')) {
            $check = $run.Envelope.Check | Where-Object ControlId -EQ $controlId
            $check.Status | Should -Be Pass -Because ($check.Reason + $run.Output)
        }
        foreach ($cmdlet in @('Get-RetentionPolicyTag','Export-MailboxDiagnosticLogs','Get-ManagementScope','Get-MailboxStatistics','Get-TransportRule')) {
            $run.Calls -join ' ' | Should -Match ([regex]::Escape($cmdlet + ':'))
        }
        $run.Calls -join ' ' | Should -Match 'GetEffectiveUsers.*true'
        $run.Calls -join ' ' | Should -Match 'InactiveMailboxOnly.*true'
        $run.Calls -join ' ' | Should -Match 'SoftDeletedMailbox.*true'
        $run.Calls -join ' ' | Should -Not -Match 'EXCLUDED:'
        $run.Envelope.ExternalReadiness.Status | Should -Be Unverified
        $irm = $run.Envelope.Evidence | Where-Object ControlId -EQ GOV-005
        ($irm.Observation | Where-Object Command -EQ Test-IRMConfiguration).Arguments.Recipient | Should -Be 'user@contoso.example'
    }
}