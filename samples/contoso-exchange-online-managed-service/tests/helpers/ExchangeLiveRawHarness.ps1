param([string]$CommandPath, [string]$ParameterPath, [string]$OutputPath, [string]$RawPath, [string]$CallPath, [string]$ConfigurationPath)
$ErrorActionPreference = 'Stop'
$PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText
$env:NO_COLOR = '1'
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
        'Get-OMEFunctionalEvidence' { '$Sender, $Recipient, $Uri, $Partition, $Collection' }
        'Get-ActivePimAssignment' { '$Identity, $Uri, $Partition, $Collection' }
        'Get-EligiblePimAssignment' { '$Identity, $Uri, $Partition, $Collection' }
        'Get-AccessReview' { '$Identity, $Uri, $Partition, $Collection' }
        'Resolve-DkimSelectorDns' { '$Identity, $Uri, $Partition' }
        'Get-MailboxRetentionDistribution' { '$Identity, $Uri, $Partition, $Collection' }
        'Resolve-PriorityIdentity' { '$Identity, $Uri, $Partition, $Collection' }
        'Resolve-Custodian' { '$Identity, $Uri, $Partition, $Collection' }
        'Get-ManagementRoleAssignment' { '$Identity, [switch]$GetEffectiveUsers' }
        'Get-Mailbox' { '$Identity, $ResultSize, [switch]$InactiveMailboxOnly, [switch]$SoftDeletedMailbox' }
        'Get-MailboxStatistics' { '$Identity, [switch]$IncludeSoftDeletedRecipients' }
        'Export-MailboxDiagnosticLogs' { '$Identity, [switch]$ExtendedProperties, $ResultSize' }
        'Get-TransportRule' { '$Identity, $ResultSize' }
        'Get-AcceptedDomain' { '$Identity, $ResultSize' }
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
    if (-not $global:ExchangeLiveRaw.ContainsKey($name)) {
        throw "OFFLINE_FIXTURE_COMMAND_MISSING:$name"
    }
    $response = $global:ExchangeLiveRaw[$name]
    if ($response -isnot [System.Collections.IDictionary]) {
        throw "OFFLINE_FIXTURE_RESPONSE_MALFORMED:$name"
    }
    $items = $response.Items
    $resolved = $response.ContainsKey('Items')
    if ($response.ContainsKey('ByIdentity')) {
        if ($PSBoundParameters.ContainsKey('Identity')) {
            $key = @($Identity | ForEach-Object { [string]$_ }) -join '|'
            if (-not $response.ByIdentity.ContainsKey($key)) { throw "OFFLINE_FIXTURE_IDENTITY_MISSING:${name}:$key" }
            $items = $response.ByIdentity[$key]
            $resolved = $true
        }
        elseif (-not $response.ContainsKey('Items')) {
            throw "OFFLINE_FIXTURE_IDENTITY_OR_ITEMS_REQUIRED:$name"
        }
    }
    if ($response.ContainsKey('ByUri')) {
        if ([string]::IsNullOrWhiteSpace([string]$Uri)) { throw "OFFLINE_FIXTURE_URI_REQUIRED:$name" }
        $key = [string]$Uri
        if (-not $response.ByUri.ContainsKey($key)) { throw "OFFLINE_FIXTURE_URI_MISSING:${name}:$key" }
        $items = $response.ByUri[$key]
        $resolved = $true
    }
    if ($response.ContainsKey('ByPartition')) {
        if ([string]::IsNullOrWhiteSpace([string]$Partition)) { throw "OFFLINE_FIXTURE_PARTITION_REQUIRED:$name" }
        $key = [string]$Partition
        if (-not $response.ByPartition.ContainsKey($key)) { throw "OFFLINE_FIXTURE_PARTITION_MISSING:${name}:$key" }
        $items = $response.ByPartition[$key]
        $resolved = $true
    }
    if ($response.ContainsKey('ByCollection')) {
        if ($null -eq $Collection) { throw "OFFLINE_FIXTURE_COLLECTION_REQUIRED:$name" }
        $key = $Collection | ConvertTo-Json -Compress -Depth 20
        if (-not $response.ByCollection.ContainsKey($key)) { throw "OFFLINE_FIXTURE_COLLECTION_MISSING:${name}:$key" }
        $items = $response.ByCollection[$key]
        $resolved = $true
    }
    if ($response.ContainsKey('BySenderRecipient')) {
        if ([string]::IsNullOrWhiteSpace([string]$Sender) -or [string]::IsNullOrWhiteSpace([string]$Recipient)) {
            throw "OFFLINE_FIXTURE_ROUTE_REQUIRED:$name"
        }
        $key = '{0}|{1}' -f [string]$Sender, [string]$Recipient
        if (-not $response.BySenderRecipient.ContainsKey($key)) { throw "OFFLINE_FIXTURE_ROUTE_MISSING:${name}:$key" }
        $items = $response.BySenderRecipient[$key]
        $resolved = $true
    }
    if ($response.ContainsKey('ByType') -and $QuarantinePolicyType) {
        $key = [string]$QuarantinePolicyType
        if (-not $response.ByType.ContainsKey($key)) { throw "OFFLINE_FIXTURE_TYPE_MISSING:${name}:$key" }
        $items = $response.ByType[$key]
        $resolved = $true
    }
    if ($response.ContainsKey('ByList')) {
        $key = "${ListType}:$(if ($Allow) { 'Allow' } else { 'Block' })"
        if ($response.ByList.ContainsKey($key)) {
            $items = $response.ByList[$key]
            $resolved = $true
        }
        elseif (-not $response.ContainsKey('Items')) {
            throw "OFFLINE_FIXTURE_LIST_MISSING:${name}:$key"
        }
    }
    if ($response.ContainsKey('ByPolicy')) {
        $key = [string]$Policy
        if (-not $response.ByPolicy.ContainsKey($key)) { throw "OFFLINE_FIXTURE_POLICY_MISSING:${name}:$key" }
        $items = $response.ByPolicy[$key]
        $resolved = $true
    }
    if (-not $resolved) { throw "OFFLINE_FIXTURE_ITEMS_MISSING:$name" }
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