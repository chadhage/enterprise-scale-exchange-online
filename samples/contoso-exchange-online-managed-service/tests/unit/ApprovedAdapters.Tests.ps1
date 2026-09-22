BeforeAll {
    $script:root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:command = Join-Path $script:root 'scripts/Invoke-ExchangeOnlineChange.ps1'
    Import-Module (Join-Path $script:root 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking
    function global:Get-ConnectionInformation { [pscustomobject]@{ TenantID = '00000000-0000-0000-0000-000000000000'; State = 'Connected' } }
    function New-AdapterFixture {
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory $directory
        $parameters = Get-Content (Join-Path $script:root 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
        $parameters.entitlement.verified = $true
        $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
        $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE','THREAT_INTELLIGENCE')
        $parameterPath = Join-Path $directory 'parameters.json'
        $parameters | ConvertTo-Json -Depth 30 | Set-Content $parameterPath
        @{ ParameterPath = $parameterPath; ConfigurationPath = (Join-Path $script:root 'config/exchange-only.v1.json'); ArtifactRoot = $directory; ChangeId = 'ADAPTER004'; RequestedBy = 'operator@example.test' }
    }
    $script:readCommands = @('Get-OrganizationConfig','Get-ExternalInOutlook','Get-RemoteDomain','Get-CASMailbox','Get-CASMailboxPlan','Get-HostedOutboundSpamFilterPolicy','Get-AcceptedDomain','Get-ReportSubmissionPolicy','Get-SecOpsOverridePolicy','Get-AntiPhishPolicy','Get-EOPProtectionPolicyRule','Get-ATPProtectionPolicyRule','Get-ATPBuiltInProtectionRule','Get-QuarantinePolicy','Get-HostedContentFilterPolicy','Get-MalwareFilterPolicy','Get-Mailbox','Get-InboxRule','Get-RoleAssignmentPolicy','Get-ManagementRoleAssignment','Get-DkimSigningConfig','Get-TenantAllowBlockListItems')
    foreach ($name in $script:readCommands) {
        Set-Item "Function:global:$name" {
            [CmdletBinding()]param([string]$Identity, [string]$ResultSize, [string]$Mailbox, [switch]$IncludeHidden, [string]$ListType)
            $target = switch ($MyInvocation.MyCommand.Name) {
                Get-AcceptedDomain { 'contoso.example' }
                Get-ReportSubmissionPolicy { 'DefaultReportSubmissionPolicy' }
                Get-SecOpsOverridePolicy { 'SecOpsOverridePolicy' }
                Get-AntiPhishPolicy { 'Contoso Impersonation Protection' }
                Get-QuarantinePolicy { 'Baseline-AdminOnlyAccess' }
                Get-DkimSigningConfig { 'contoso.example' }
                default { 'incomplete' }
            }
            [pscustomobject]@{ Identity = $target; Name = $target; DomainName = $target }
        }
    }
}

Describe 'EXR-004 concrete adapter admission' {
    It 'does not omit supported scopes or guarded failure recovery from the operator guide' {
        # Arrange
        $path = Join-Path $script:root 'docs/APPROVED-CHANGE.md'
        $required = @('Transport','Organization','ExternalSender','RemoteDomains','MailboxProtocols','MailboxPlans','OutboundSpam','AcceptedDomains','ReportSubmission','SecOpsOverride','Impersonation','EopPresets','AtpPresets','BuiltInProtection','Quarantine','Forwarding','AddInAcquisition','Dkim','TenantAllowBlockList','ObjectFingerprint','rollback-attempt-','attempted operations','workflowOptions')
        # Act
        $guide = Get-Content $path -Raw
        # Assert
        foreach ($term in $required) { $guide | Should -Match ([regex]::Escape($term)) }
        $guide | Should -Not -Match 'supported reversible scope in workflow version 1.0.0 is `Transport`'
    }
    It 'rejects incomplete <Scope> capture before emitting a preview' -ForEach @(
        @{ Scope = 'Organization' }, @{ Scope = 'ExternalSender' }, @{ Scope = 'RemoteDomains' },
        @{ Scope = 'MailboxProtocols' }, @{ Scope = 'MailboxPlans' }, @{ Scope = 'OutboundSpam' },
        @{ Scope = 'AcceptedDomains' }, @{ Scope = 'ReportSubmission' }, @{ Scope = 'SecOpsOverride' },
        @{ Scope = 'Impersonation' }, @{ Scope = 'EopPresets' }, @{ Scope = 'AtpPresets' },
        @{ Scope = 'BuiltInProtection' }, @{ Scope = 'Quarantine' }, @{ Scope = 'Forwarding' },
        @{ Scope = 'AddInAcquisition' }, @{ Scope = 'Dkim' }, @{ Scope = 'TenantAllowBlockList' }
    ) {
        # Arrange
        $arguments = New-AdapterFixture
        # Act
        $invoke = { & $script:command -Stage Preview @arguments -Scope $Scope -Confirm:$false }
        # Assert
        $invoke | Should -Throw '*ChangeReadIncomplete*'
        Test-Path (Join-Path $arguments.ArtifactRoot 'preview-ADAPTER004.json') | Should -BeFalse
    }
}

AfterAll {
    foreach ($name in @($script:readCommands) + @('Get-ConnectionInformation')) { Remove-Item "Function:global:$name" -ErrorAction SilentlyContinue }
}