param([string]$CommandPath, [string]$ParameterPath, [string]$OutputPath, [string]$CallPath, [switch]$RawExchange, [string]$ConfigurationPath, [switch]$Deployment)
$ErrorActionPreference = 'Stop'
$global:ExchangeOnlyCallPath = $CallPath
function global:Import-Module {
    param([Parameter(Position=0)]$Name, [switch]$Force, [switch]$DisableNameChecking, $MinimumVersion)
    if ($Name -eq 'ExchangeOnlineManagement') { return }
    if ($Name -like 'Microsoft.Graph*') { Add-Content $global:ExchangeOnlyCallPath 'EXCLUDED:GraphImport'; throw 'ExcludedServiceCalled' }
    Microsoft.PowerShell.Core\Import-Module $Name -Force:$Force -DisableNameChecking:$DisableNameChecking
}
function global:Connect-ExchangeOnline { param($ShowBanner) Add-Content $global:ExchangeOnlyCallPath 'Connect-ExchangeOnline' }
foreach ($name in @('Connect-MgGraph','Invoke-MgGraphRequest','Get-AtpPolicyForO365','Set-AtpPolicyForO365','Get-DlpCompliancePolicy','Get-DlpComplianceRule','Get-RetentionCompliancePolicy','Get-UnifiedAuditLogRetentionPolicy','Get-AdminAuditLogConfig','Search-UnifiedAuditLog','Get-Label','Get-LabelPolicy','Get-ComplianceCase','Get-Recipient','Resolve-DnsName','Connect-IPPSSession','Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance','Get-MgIdentityGovernanceAccessReviewDefinition')) {
    Set-Item "function:global:$name" ([scriptblock]::Create("Add-Content `$global:ExchangeOnlyCallPath 'EXCLUDED:$name'; throw 'ExcludedServiceCalled:$name'"))
}
foreach ($name in @('Get-AcceptedDomain','Get-TransportConfig','Get-CASMailbox','Get-HostedOutboundSpamFilterPolicy','Get-Mailbox','Get-InboxRule','Get-OrganizationConfig','Get-MailboxAuditBypassAssociation','Get-ExternalInOutlook','Get-RemoteDomain','Get-CASMailboxPlan','Get-RoleGroup','Get-RoleGroupMember','Get-ManagementRoleAssignment','Get-RoleAssignmentPolicy','Get-EOPProtectionPolicyRule','Get-ATPProtectionPolicyRule','Get-ATPBuiltInProtectionRule','Get-ReportSubmissionPolicy','Get-SecOpsOverridePolicy','Get-TenantAllowBlockListItems','Get-QuarantinePolicy','Get-HostedContentFilterPolicy','Get-MalwareFilterPolicy','Get-AntiPhishPolicy','Get-InboundConnector','Get-DkimSigningConfig','Get-RetentionPolicy','Get-IRMConfiguration','Test-IRMConfiguration','Get-DistributionGroup')) {
    Set-Item "function:global:$name" ([scriptblock]::Create("Add-Content `$global:ExchangeOnlyCallPath '$name'; throw 'SyntheticCollectionUnavailable:$name'"))
}
if ($RawExchange) {
    function global:Get-AcceptedDomain {
        param($Identity, $ErrorAction)
        Add-Content $global:ExchangeOnlyCallPath 'Get-AcceptedDomain'
        [pscustomobject]@{ Name = $Identity; DomainName = $Identity; DomainType = 'Authoritative' }
    }
}
$arguments = @{ ParameterPath = $ParameterPath }
if (-not $Deployment) { $arguments.OutputPath = $OutputPath }
if ($ConfigurationPath) { $arguments.ConfigurationPath = $ConfigurationPath }
if ($Deployment) { & $CommandPath @arguments | ConvertTo-Json -Depth 30 }
else { & $CommandPath @arguments }
exit $LASTEXITCODE