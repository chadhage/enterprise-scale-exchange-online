param([Parameter(Mandatory)][string]$ParameterPath, [string]$ConnectionCallPath)

$global:OfflineExchangeSessionCallPath = $ConnectionCallPath
$global:OfflineExchangeSessionTenant = [string](
    Get-Content -LiteralPath $ParameterPath -Raw | ConvertFrom-Json
).MICROSOFT_ENTRA_TENANT_GUID

function global:Get-Module {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string[]]$Name, [switch]$All, [switch]$ListAvailable)
    if ($null -ne $Name -and $Name.Count -eq 1 -and $Name[0] -eq 'ExchangeOnlineManagement') {
        [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.0' }
        return
    }
    Microsoft.PowerShell.Core\Get-Module @PSBoundParameters
}

function global:Get-ConnectionInformation {
    [CmdletBinding()]
    param()
    if (-not [string]::IsNullOrWhiteSpace($global:OfflineExchangeSessionCallPath)) {
        Add-Content -LiteralPath $global:OfflineExchangeSessionCallPath -Value 'Get-ConnectionInformation'
    }
    [pscustomobject]@{
        State = 'Connected'
        TenantID = $global:OfflineExchangeSessionTenant
        UserPrincipalName = 'offline-operator@contoso.example'
        ConnectionUri = 'https://outlook.office365.com'
        IsEopSession = $false
    }
}
