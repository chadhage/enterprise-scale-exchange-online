param([string]$CommandPath, [string]$ParameterPath, [string]$OutputPath, [string]$RawPath, [string]$CallPath, [string]$ConfigurationPath)
$ErrorActionPreference = 'Stop'
$global:ExchangeLiveRaw = Get-Content -LiteralPath $RawPath -Raw | ConvertFrom-Json -AsHashtable
$global:ExchangeLiveCalls = $CallPath
function global:Import-Module {
    param([Parameter(Position=0)]$Name, [switch]$Force, [switch]$DisableNameChecking, $MinimumVersion)
    if ($Name -eq 'ExchangeOnlineManagement') { return }
    if ($Name -like 'Microsoft.Graph*') { throw 'EXCLUDED:GraphImport' }
    Microsoft.PowerShell.Core\Import-Module $Name -Force:$Force -DisableNameChecking:$DisableNameChecking
}
function global:Connect-ExchangeOnline { param($ShowBanner) Add-Content $global:ExchangeLiveCalls 'Connect-ExchangeOnline' }
foreach ($name in @('Connect-MgGraph','Invoke-MgGraphRequest','Connect-IPPSSession','Get-DlpCompliancePolicy','Get-DlpComplianceRule','Get-RetentionCompliancePolicy','Get-Label','Get-LabelPolicy')) {
    Set-Item "function:global:$name" ([scriptblock]::Create("Add-Content `$global:ExchangeLiveCalls 'EXCLUDED:$name'; throw 'EXCLUDED:$name'"))
}
foreach ($name in $global:ExchangeLiveRaw.Keys) {
    $signature = switch ($name) {
        'Get-TenantAllowBlockListItems' { '[Parameter(Mandatory)][ValidateSet("Sender","Url","FileHash","IP")][string]$ListType, [switch]$Allow, [switch]$Block' }
        'Get-InboxRule' { '[Parameter(Mandatory)][string]$Mailbox, $Identity, $ResultSize, [switch]$IncludeHidden' }
        'Get-OrganizationConfig' { '[switch]$RetrieveEwsOperationAccessPolicy' }
        'Get-TransportConfig' { '' }
        'Get-IRMConfiguration' { '' }
        'Test-IRMConfiguration' { '$Sender, $Recipient' }
        'Get-ManagementRoleAssignment' { '$Identity, [switch]$GetEffectiveUsers' }
        'Get-Mailbox' { '$Identity, $ResultSize, [switch]$InactiveMailboxOnly, [switch]$SoftDeletedMailbox' }
        'Get-MailboxStatistics' { '$Identity, [switch]$IncludeSoftDeletedRecipients' }
        'Export-MailboxDiagnosticLogs' { '$Identity, [switch]$ExtendedProperties, $ResultSize' }
        'Get-TransportRule' { '$Identity, $ResultSize' }
        'Get-QuarantinePolicy' { '$Identity, $QuarantinePolicyType' }
        'Get-ExoSecOpsOverrideRule' { '$Identity, $Policy' }
        { $_ -in @('Get-CASMailbox','Get-CASMailboxPlan','Get-MailboxAuditBypassAssociation','Get-RemoteDomain','Get-RoleGroup','Get-RoleGroupMember','Get-DistributionGroup','Get-Recipient','Get-DistributionGroupMember') } { '$Identity, $ResultSize' }
        default { '$Identity' }
    }
    $body = @'
    [CmdletBinding()]
    param(__SIGNATURE__)
    $name = $MyInvocation.MyCommand.Name
    Add-Content $global:ExchangeLiveCalls ($name + ':' + ($PSBoundParameters | ConvertTo-Json -Compress))
    $response = $global:ExchangeLiveRaw[$name]
    $items = $response.Items
    if ($response.ContainsKey('ByIdentity') -and $Identity) { $items = $response.ByIdentity[$Identity] }
    if ($response.ContainsKey('ByType') -and $QuarantinePolicyType) { $items = $response.ByType[$QuarantinePolicyType] }
    if ($response.ContainsKey('ByList')) { $items = $response.ByList["${ListType}:$(if ($Allow) { 'Allow' } else { 'Block' })"] }
    if ($response.ContainsKey('ByPolicy')) { $items = $response.ByPolicy[$Policy] }
    if ($name -eq 'Get-ManagementRoleAssignment' -and $GetEffectiveUsers) { $items = $response.Effective }
    if ($name -eq 'Get-Mailbox' -and $InactiveMailboxOnly) { $items = $response.Inactive }
    if ($name -eq 'Get-Mailbox' -and $SoftDeletedMailbox) { $items = $response.SoftDeleted }
    if ($name -in @('Get-RemoteDomain','Get-RoleGroup') -and $ResultSize -ne 'Unlimited') { $items = @($items | Select-Object -First 1000) }
    foreach ($item in @($items)) { if ($null -ne $item) { [pscustomobject]$item } }
    if ($response.ContainsKey('Warning')) { Write-Warning $response.Warning }
    if ($response.ContainsKey('Error')) { throw $response.Error }
'@
    Set-Item "function:global:$name" ([scriptblock]::Create($body.Replace('__SIGNATURE__', $signature)))
}
$arguments = @{ ParameterPath = $ParameterPath; OutputPath = $OutputPath }
if ($ConfigurationPath) { $arguments.ConfigurationPath = $ConfigurationPath }
& $CommandPath @arguments
exit $LASTEXITCODE