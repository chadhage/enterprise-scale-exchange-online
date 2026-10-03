#requires -Version 7.5
<#
.SYNOPSIS
Read-only readiness gate for an approved Exchange Online change.

.DESCRIPTION
Checks the workstation, the downloaded kit, the change inputs, and (unless skipped) the
Exchange Online session before the Preview stage. Every failed check prints the exact fix. When all
checks pass, the script prints the copyable $change block and Preview command for the next step.

Sign-in: an existing session is shown (account and tenant) and you confirm it; with no session the
script signs you in (browser with MFA, or -UseDeviceCode). Use -ConfirmSession:$false to accept an
existing session without a prompt, and -NonInteractive to never prompt or open a sign-in window.

The script never changes the tenant. Tenant checks only call Get-* cmdlets.

.EXAMPLE
./scripts/Test-ExchangeOnlineChangeReadiness.ps1 -WorkstationOnly

.EXAMPLE
./scripts/Test-ExchangeOnlineChangeReadiness.ps1 -ParameterPath 'D:\protected\contoso.parameters.json' `
    -ArtifactRoot 'D:\protected\changes\CHG-1001' -ChangeId 'CHG-1001' -RequestedBy 'requester@contoso.com' `
    -AuthorizedSignerPath 'D:\protected\authorized-signers.json' -Scope 'Transport'
#>
[CmdletBinding(DefaultParameterSetName = 'Change')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Workstation')][switch]$WorkstationOnly,
    [Parameter(Mandatory, ParameterSetName = 'Change')][string]$ParameterPath,
    [Parameter(Mandatory, ParameterSetName = 'Change')][string]$ArtifactRoot,
    [Parameter(Mandatory, ParameterSetName = 'Change')][string]$ChangeId,
    [Parameter(Mandatory, ParameterSetName = 'Change')][string]$RequestedBy,
    [Parameter(Mandatory, ParameterSetName = 'Change')][string]$AuthorizedSignerPath,
    [Parameter(Mandatory, ParameterSetName = 'Change')][string[]]$Scope,
    [Parameter(ParameterSetName = 'Change')][string]$ConfigurationPath,
    [Parameter(ParameterSetName = 'Change')][switch]$SkipTenantConnection,
    [Parameter(ParameterSetName = 'Change')][string]$UserPrincipalName,
    [Parameter(ParameterSetName = 'Change')][switch]$UseDeviceCode,
    [Parameter(ParameterSetName = 'Change')][bool]$ConfirmSession = $true,
    [Parameter(ParameterSetName = 'Change')][switch]$NonInteractive,
    [version]$MinimumPowerShellVersion = '7.6',
    [version]$MinimumModuleVersion = '3.10.0',
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('InformationAction')) { $InformationPreference = 'Continue' }

$kitRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ConfigurationPath)) {
    $ConfigurationPath = Join-Path $kitRoot 'config/exchange-only.v1.json'
}

$results = [System.Collections.Generic.List[object]]::new()

function Add-ReadinessResult {
    param(
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][bool]$Passed,
        [string]$Detail = '',
        [string]$Fix = ''
    )
    $record = [pscustomobject]@{
        Area   = $Area
        Check  = $Check
        Status = $(if ($Passed) { 'PASS' } else { 'FAIL' })
        Detail = $Detail
        Fix    = $(if ($Passed) { '' } else { $Fix })
    }
    $results.Add($record)
    $label = if ($Passed) { "$($PSStyle.Foreground.Green)PASS$($PSStyle.Reset)" } else { "$($PSStyle.Foreground.Red)FAIL$($PSStyle.Reset)" }
    Write-Information "  [$($label)] $($Check)$(if ($Detail) { " - $($Detail)" })"
    if (-not $Passed -and $Fix) {
        foreach ($line in ($Fix -split "`n")) { Write-Information "         $($PSStyle.Foreground.Yellow)$($line)$($PSStyle.Reset)" }
    }
}

function Test-PathInsideKit {
    param([string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $root = [System.IO.Path]::GetFullPath($kitRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $full.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or
        $full.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-Literal {
    param([string]$Value)
    "'$($Value -replace "'", "''")'"
}

function Find-PlaceholderPath {
    param($Node, [string]$Path, [System.Collections.Generic.List[string]]$Found)
    if ($Node -is [System.Collections.IDictionary]) {
        foreach ($key in $Node.Keys) {
            $child = if ($Path) { "$($Path).$($key)" } else { [string]$key }
            Find-PlaceholderPath -Node $Node[$key] -Path $child -Found $Found
        }
    }
    elseif ($Node -is [System.Collections.IList]) {
        for ($index = 0; $index -lt $Node.Count; $index++) {
            Find-PlaceholderPath -Node $Node[$index] -Path "$($Path)[$($index)]" -Found $Found
        }
    }
    elseif ($Node -is [string] -and $Node.Contains('REPLACE-')) {
        $Found.Add($Path)
    }
}

Write-Information "$($PSStyle.Bold)Exchange Online change readiness$($PSStyle.Reset) (read-only)"
Write-Information "Kit folder: $($kitRoot)"
Write-Information ''
Write-Information "$($PSStyle.Bold)1. Workstation and kit$($PSStyle.Reset)"

$edition = $PSVersionTable.PSEdition
$version = $PSVersionTable.PSVersion
Add-ReadinessResult -Area Workstation -Check 'PowerShell 7 (pwsh)' `
    -Passed ($edition -eq 'Core' -and [version]"$($version.Major).$($version.Minor)" -ge $MinimumPowerShellVersion) `
    -Detail "$($edition) $($version); minimum $($MinimumPowerShellVersion)" `
    -Fix "winget install --id Microsoft.PowerShell --source winget`nThen open a new 'PowerShell 7' terminal (pwsh), not Windows PowerShell 5.1."

$requiredFiles = @(
    'scripts/Invoke-ExchangeOnlineChange.ps1'
    'scripts/Deploy-ExchangeOnlineBaseline.ps1'
    'scripts/Test-ExchangeOnlineBaseline.ps1'
    'scripts/New-ExchangeChangeEvidenceReport.ps1'
    'scripts/ExchangeOnlineBaseline.Connection.psm1'
    'scripts/ExchangeOnlineBaseline.Common.psm1'
    'scripts/ExchangeOnlineBaseline.ApprovedAdapters.ps1'
    'config/exchange-only.v1.json'
    'config/exchange-only.schema.v1.json'
)
$missing = @($requiredFiles | Where-Object { -not (Test-Path -LiteralPath (Join-Path $kitRoot $_) -PathType Leaf) })
Add-ReadinessResult -Area Workstation -Check 'Kit files present' -Passed ($missing.Count -eq 0) `
    -Detail $(if ($missing.Count) { "missing: $($missing -join ', ')" } else { "$($requiredFiles.Count) required files found" }) `
    -Fix 'Download the release zip again, expand it, and run this script from the expanded folder.'

if ($IsWindows) {
    $blocked = @(Get-ChildItem -LiteralPath $kitRoot -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1', '*.json' |
            Where-Object { Get-Item -LiteralPath $_.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue })
    Add-ReadinessResult -Area Workstation -Check 'Downloaded files unblocked' -Passed ($blocked.Count -eq 0) `
        -Detail $(if ($blocked.Count) { "$($blocked.Count) file(s) still marked as downloaded from the internet" } else { 'no Mark-of-the-Web found' }) `
        -Fix "Get-ChildItem -LiteralPath $(ConvertTo-Literal $kitRoot) -Recurse -File | Unblock-File"

    $policy = Get-ExecutionPolicy
    Add-ReadinessResult -Area Workstation -Check 'Execution policy allows local scripts' `
        -Passed ($policy -notin @('Restricted', 'AllSigned')) -Detail "effective policy $($policy)" `
        -Fix 'Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned'
}

$module = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
Add-ReadinessResult -Area Workstation -Check 'ExchangeOnlineManagement module' `
    -Passed ($null -ne $module -and $module.Version -ge $MinimumModuleVersion) `
    -Detail $(if ($module) { "installed $($module.Version); minimum $($MinimumModuleVersion)" } else { 'not installed' }) `
    -Fix "Install-Module ExchangeOnlineManagement -MinimumVersion $($MinimumModuleVersion) -Scope CurrentUser"

$changeBlock = $null
$previewCommand = $null

if ($PSCmdlet.ParameterSetName -eq 'Change') {
    Write-Information ''
    Write-Information "$($PSStyle.Bold)2. Change inputs (offline)$($PSStyle.Reset)"

    $common = $null
    try {
        $common = Import-Module (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psm1') -DisableNameChecking -Force -PassThru
    }
    catch {
        Add-ReadinessResult -Area Inputs -Check 'Load change module' -Passed $false -Detail $_.Exception.Message `
            -Fix 'Unblock the kit files and confirm the scripts folder is complete.'
    }

    $context = $null
    $tenant = ''
    if ($common) {
        $parameterOk = [System.IO.Path]::IsPathFullyQualified($ParameterPath) -and
            (Test-Path -LiteralPath $ParameterPath -PathType Leaf) -and -not (Test-PathInsideKit $ParameterPath)
        Add-ReadinessResult -Area Inputs -Check 'Parameter file location' -Passed $parameterOk -Detail $ParameterPath `
            -Fix "Use an absolute path to your tenant copy, stored outside the kit and source control:`nCopy-Item ./config/parameters.exchange-only.sample.json 'D:\protected\contoso.parameters.json'"

        if ($parameterOk) {
            try {
                $context = Get-BaselineExchangeContext -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath
                $parameters = $context.Parameters
                $tenant = [string]$parameters.MICROSOFT_ENTRA_TENANT_GUID
                $profileOk = [string]$context.DeploymentProfile -ceq 'ExchangeOnly'
                Add-ReadinessResult -Area Inputs -Check 'Configuration and parameters resolve' -Passed $profileOk `
                    -Detail "profile $($context.DeploymentProfile); configuration hash $($context.Hash.Substring(0, 12))..." `
                    -Fix 'Use ./config/exchange-only.v1.json. Historical profiles are not supported by the approved change workflow.'
            }
            catch {
                Add-ReadinessResult -Area Inputs -Check 'Configuration and parameters resolve' -Passed $false `
                    -Detail $_.Exception.Message -Fix 'Replace the named value in your parameter copy with the owner-supplied value, then rerun.'
            }
        }

        $tenantOk = $tenant -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' -and $tenant -ne '00000000-0000-0000-0000-000000000000'
        Add-ReadinessResult -Area Inputs -Check 'Tenant ID is real' -Passed $tenantOk `
            -Detail $(if ($tenant) { $tenant } else { 'not resolved' }) `
            -Fix 'Set MICROSOFT_ENTRA_TENANT_GUID (and entitlement.tenantId) to the Microsoft Entra tenant ID shown in Entra admin center, Overview.'

        if ($context) {
            $decision = & $common { param($c) Get-BaselineExchangeCapabilityDecision -Context $c -Capability EmailProtection } $context
            Add-ReadinessResult -Area Inputs -Check 'Licensing entitlement verified' -Passed ([bool]$decision.Entitled) `
                -Detail (([string]$decision.Reason -split "`n")[0]) `
                -Fix 'Ask the licensing owner for a current handoff; they set entitlement.verified, servicePlans, and a future expiresOn. Never set verified yourself.'

            if (@($Scope | Where-Object { $_ -in @('AtpPresets', 'BuiltInProtection', 'Impersonation') }).Count -gt 0) {
                $atp = & $common { param($c) Get-BaselineExchangeCapabilityDecision -Context $c -Capability AtpPresets } $context
                Add-ReadinessResult -Area Inputs -Check 'Defender for Office 365 entitlement (ATP_ENTERPRISE)' -Passed ([bool]$atp.Entitled) `
                    -Detail (([string]$atp.Reason -split "`n")[0]) `
                    -Fix 'Remove AtpPresets, BuiltInProtection, and Impersonation from -Scope, or obtain an ATP_ENTERPRISE entitlement handoff.'
            }
        }

        try {
            & $common { param($s) Assert-ApprovedAdapterScope -Scope $s } $Scope
            Add-ReadinessResult -Area Inputs -Check 'Scope is supported' -Passed $true -Detail ($Scope -join ', ')
        }
        catch {
            Add-ReadinessResult -Area Inputs -Check 'Scope is supported' -Passed $false -Detail $_.Exception.Message `
                -Fix 'Use only scopes listed in docs/APPROVED-CHANGE.md, each once, exactly as approved in the change request.'
        }

        if ($parameterOk) {
            $placeholderPaths = [System.Collections.Generic.List[string]]::new()
            try {
                Find-PlaceholderPath -Node (Get-Content -LiteralPath $ParameterPath -Raw | ConvertFrom-Json -AsHashtable -Depth 64) -Path '' -Found $placeholderPaths
            }
            catch {
                $placeholderPaths.Add('parameter file is not readable JSON')
            }
            $placeholderDetail = if ($placeholderPaths.Count) { "$($placeholderPaths.Count) left: $(($placeholderPaths | Select-Object -First 5) -join ', ')" } else { 'none found' }
            Add-ReadinessResult -Area Inputs -Check 'No REPLACE- placeholders remain' -Passed ($placeholderPaths.Count -eq 0) `
                -Detail $placeholderDetail `
                -Fix 'Replace every REPLACE- value copied from the microsite template with the owner-supplied value. Never invent approvals, owners, or evidence.'
        }

        if ($context) {
            $requiredOptions = [ordered]@{
                ApplicationAssignmentScope = 'applicationAssignmentScope'; ConnectorTrust = 'connectorTrust'
                FullAccess = 'fullAccessDelegations'; MailboxSafeSender = 'mailboxSafeSenders'
                OrganizationAllowList = 'organizationAllowList'; OrganizationRelationship = 'organizationRelationships'
                SendAs = 'sendAsDelegations'; SendOnBehalf = 'sendOnBehalfDelegations'
                SharingPolicyBinding = 'sharingPolicyBinding'; TransportBypass = 'transportSclExceptions'
            }
            $options = $context.Parameters['workflowOptions']
            $missingOptions = @(foreach ($area in $Scope) {
                    $key = $requiredOptions[$area]
                    if ($key -and ($options -isnot [System.Collections.IDictionary] -or -not $options.Contains($key) -or $null -eq $options[$key] -or @($options[$key]).Count -eq 0)) {
                        "workflowOptions.$($key) (for $($area))"
                    }
                })
            $neededOptions = @($Scope | Where-Object { $requiredOptions[$_] })
            if ($neededOptions.Count) {
                Add-ReadinessResult -Area Inputs -Check 'Required workflowOptions present' -Passed ($missingOptions.Count -eq 0) `
                    -Detail $(if ($missingOptions.Count) { "missing $($missingOptions -join ', ')" } else { "present for $($neededOptions -join ', ')" }) `
                    -Fix 'Use the microsite Step 2 option builder to generate the workflowOptions block for these scopes, paste it into your parameter copy, and replace every REPLACE- value.'
            }
        }

        $governance = @($Scope | Where-Object { $_ -in @('GovernanceMailboxPolicy', 'GovernanceMrm', 'GovernanceEncryption') })
        if ($governance.Count) {
            $shippedConfiguration = [System.IO.Path]::GetFullPath((Join-Path $kitRoot 'config/exchange-only.v1.json'))
            $usesShipped = [System.IO.Path]::GetFullPath($ConfigurationPath).Equals($shippedConfiguration, [StringComparison]::OrdinalIgnoreCase)
            Add-ReadinessResult -Area Inputs -Check 'Governance uses an approved configuration copy' -Passed (-not $usesShipped) `
                -Detail $ConfigurationPath `
                -Fix "Governance scopes ($($governance -join ', ')) need the approved governance copy of the configuration (docs/EXCHANGE-GOVERNANCE.md). Rerun with -ConfigurationPath 'D:\ExchangeChanges\contoso.exchange-only.governance.json'."
        }

        $pattern = [string](& $common { Get-BaselineChangeArtifactContract }).ChangeIdentifierPattern
        Add-ReadinessResult -Area Inputs -Check 'Change ID format' -Passed ($ChangeId -cmatch $pattern) -Detail $ChangeId `
            -Fix 'Use your change ticket number: letters, digits, and hyphens, starting with a letter or digit, at most 64 characters (for example CHG-1001).'

        Add-ReadinessResult -Area Inputs -Check 'Requester identity' -Passed (-not [string]::IsNullOrWhiteSpace($RequestedBy)) `
            -Detail $RequestedBy -Fix 'Supply the UPN of the person requesting the change, for example requester@contoso.com.'

        $artifactOk = [System.IO.Path]::IsPathFullyQualified($ArtifactRoot) -and -not (Test-PathInsideKit $ArtifactRoot)
        $artifactDetail = $ArtifactRoot
        $previewPath = $null
        $approvalPath = $null
        if ($artifactOk -and ($ChangeId -cmatch $pattern)) {
            $paths = @{}
            foreach ($entry in (New-BaselineChangeArtifactSet -ChangeId $ChangeId -Root $ArtifactRoot)) { $paths[[string]$entry.Artifact] = [string]$entry.Path }
            $previewPath = $paths['Preview']
            $approvalPath = $paths['Approval']
            if (Test-Path -LiteralPath $previewPath) {
                $artifactOk = $false
                $artifactDetail = "a preview already exists for $($ChangeId)"
            }
            elseif (-not (Test-Path -LiteralPath $ArtifactRoot -PathType Container)) {
                $artifactDetail = "$($ArtifactRoot) (will be created at Preview)"
            }
        }
        Add-ReadinessResult -Area Inputs -Check 'Artifact folder' -Passed $artifactOk -Detail $artifactDetail `
            -Fix 'Use a new absolute folder outside the kit and source control, protected so only change operators can write to it. A new change needs a new change ID.'

        $signerOk = $false
        $signerDetail = $AuthorizedSignerPath
        if ([System.IO.Path]::IsPathFullyQualified($AuthorizedSignerPath) -and (Test-Path -LiteralPath $AuthorizedSignerPath -PathType Leaf)) {
            try {
                $signers = Get-Content -LiteralPath $AuthorizedSignerPath -Raw | ConvertFrom-Json -AsHashtable -Depth 20 -NoEnumerate
                $valid = $signers -is [array] -and $signers.Count -gt 0 -and @($signers | Where-Object {
                            $_ -isnot [hashtable] -or [string]::IsNullOrWhiteSpace([string]$_.Identity) -or
                            [string]::IsNullOrWhiteSpace([string]$_.Subject) -or [string]$_.Authority -cne 'ExchangeOnlineChangeApproval'
                        }).Count -eq 0
                $duplicateSigner = $false
                if ($valid) {
                    $signerKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($signer in $signers) {
                        $key = ConvertTo-Json -InputObject @(
                            ([string]$signer.Identity).Trim()
                            ([string]$signer.Subject).Trim()
                            ([string]$signer.Authority).Trim()
                        ) -Compress
                        if (-not $signerKeys.Add($key)) { $duplicateSigner = $true }
                    }
                }
                $requesterIdentity = ([string]$RequestedBy).Trim()
                $independent = @($signers | Where-Object {
                        -not [string]::Equals(
                            ([string]$_.Identity).Trim(),
                            $requesterIdentity,
                            [System.StringComparison]::OrdinalIgnoreCase
                        )
                    }).Count -gt 0
                $signerOk = $valid -and -not $duplicateSigner -and $independent -and -not (Test-PathInsideKit $AuthorizedSignerPath)
                $signerDetail = if (-not $valid) { 'entries need Identity, Subject, and Authority = ExchangeOnlineChangeApproval' }
                elseif ($duplicateSigner) { 'duplicate authorized signer entries after case-insensitive normalization' }
                elseif (-not $independent) { 'every authorized signer is the requester' }
                else { "$($signers.Count) authorized signer(s)" }
            }
            catch {
                $signerDetail = 'not readable JSON'
            }
        }
        Add-ReadinessResult -Area Inputs -Check 'Authorized signer metadata' -Passed $signerOk -Detail $signerDetail `
            -Fix "Ask the approval authority owner for the protected signer file (absolute path, outside the kit). Format:`n[ { `"Identity`": `"approver@contoso.com`", `"Subject`": `"CN=Approver`", `"Authority`": `"ExchangeOnlineChangeApproval`" } ]"

        if (-not $SkipTenantConnection) {
            Write-Information ''
            Write-Information "$($PSStyle.Bold)3. Exchange Online session (read-only)$($PSStyle.Reset)"
            Import-Module (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Connection.psm1') -DisableNameChecking
            $connection = $null
            try {
                $connection = Connect-ExchangeOnlineSession -UserPrincipalName $UserPrincipalName -UseDeviceCode:$UseDeviceCode `
                    -ConfirmSession $ConfirmSession -NonInteractive:$NonInteractive -SkipModuleCheck
                Add-ReadinessResult -Area Tenant -Check 'Exactly one Exchange Online session' -Passed $true `
                    -Detail "$($connection.UserPrincipalName) in tenant $($connection.TenantID)"
            }
            catch {
                $lines = @($_.Exception.Message -split "`n")
                Add-ReadinessResult -Area Tenant -Check 'Exactly one Exchange Online session' -Passed $false `
                    -Detail $lines[0] -Fix ((@($lines | Select-Object -Skip 1) + 'Then rerun this script.') -join "`n")
            }

            if ($null -ne $connection) {
                $connectFix = "Disconnect-ExchangeOnline -Confirm:`$false`nThen rerun this script and sign in with an administrator account from the parameter-file tenant (it runs Connect-ExchangeOnline for you; add -UserPrincipalName to choose the account)."
                Add-ReadinessResult -Area Tenant -Check 'Session tenant matches parameters' `
                    -Passed ($tenantOk -and [string]$connection.TenantID -eq $tenant) `
                    -Detail "session $($connection.TenantID) as $($connection.UserPrincipalName)" -Fix $connectFix
                Add-ReadinessResult -Area Tenant -Check 'Worldwide endpoint' `
                    -Passed ([string]$connection.ConnectionUri -match '^https://outlook\.office365\.com') `
                    -Detail ([string]$connection.ConnectionUri) -Fix 'Only Worldwide (O365Default) tenants are supported. Stop for sovereign clouds.'

                $scopeCmdlets = Get-ExchangeScopeReadCommand
                foreach ($area in $Scope) {
                    $cmdlets = @($scopeCmdlets[$area])
                    foreach ($cmdlet in $cmdlets) {
                        if (-not $cmdlet) { continue }
                        Add-ReadinessResult -Area Tenant -Check "Role grants $($cmdlet) for $($area)" `
                            -Passed ($null -ne (Get-Command -Name $cmdlet -ErrorAction SilentlyContinue)) `
                            -Fix 'Your Exchange role does not expose this cmdlet. Ask the role owner for the least-privilege role group that covers this scope, then reconnect.'
                    }
                }

                foreach ($preset in @(@{ Scope = 'EopPresets'; Cmdlet = 'Get-EOPProtectionPolicyRule' }, @{ Scope = 'AtpPresets'; Cmdlet = 'Get-ATPProtectionPolicyRule' })) {
                    if ($preset.Scope -notin $Scope -or -not (Get-Command -Name $preset.Cmdlet -ErrorAction SilentlyContinue)) { continue }
                    try {
                        $rules = @(& $preset.Cmdlet -ErrorAction Stop)
                    }
                    catch {
                        Add-ReadinessResult -Area Tenant -Check "$($preset.Scope) rules initialized" -Passed $false `
                            -Detail "could not read preset rules: $($_.Exception.Message)" `
                            -Fix "Your session could not run $($preset.Cmdlet). Confirm the account's Exchange role covers this scope, reconnect, and rerun this check."
                        continue
                    }
                    $names = @($rules | ForEach-Object { [string]$_.Identity })
                    Add-ReadinessResult -Area Tenant -Check "$($preset.Scope) rules initialized" -Passed ($rules.Count -gt 0) `
                        -Detail $(if ($names.Count) { $names -join '; ' } else { 'no Standard or Strict rule found' }) `
                        -Fix 'Turn on Standard/Strict once in the Defender portal (Email and collaboration, Policies, Preset security policies). This workflow does not create them.'
                }
            }
        }

        if ($previewPath) {
            $signerLine = "    AuthorizedSignerPath = $(ConvertTo-Literal $AuthorizedSignerPath)"
            $shippedConfigurationPath = [System.IO.Path]::GetFullPath((Join-Path $kitRoot 'config/exchange-only.v1.json'))
            # Both requester and approver run from their own kit folder, so the shipped configuration is kit-relative.
            $configurationLiteral = if ([System.IO.Path]::GetFullPath($ConfigurationPath).Equals($shippedConfigurationPath, [StringComparison]::OrdinalIgnoreCase)) {
                "'./config/exchange-only.v1.json'"
            }
            else {
                ConvertTo-Literal $ConfigurationPath
            }
            $changeBlock = @(
                '$change = @{'
                "    ParameterPath        = $(ConvertTo-Literal $ParameterPath)"
                "    ConfigurationPath    = $($configurationLiteral)"
                "    ArtifactRoot         = $(ConvertTo-Literal $ArtifactRoot)"
                "    ChangeId             = $(ConvertTo-Literal $ChangeId)"
                "    RequestedBy          = $(ConvertTo-Literal $RequestedBy)"
                $signerLine
                "    PreviewPath          = $(ConvertTo-Literal $previewPath)"
                "    ApprovalPath         = $(ConvertTo-Literal $approvalPath)"
                '}'
            ) -join [Environment]::NewLine
            $previewCommand = "./scripts/Invoke-ExchangeOnlineChange.ps1 -Stage Preview @change -Scope $(($Scope | ForEach-Object { ConvertTo-Literal $_ }) -join ',') -Confirm:`$false"
        }
    }
}

$failed = @($results | Where-Object Status -eq 'FAIL')
Write-Information ''
if ($failed.Count -gt 0) {
    Write-Information "$($PSStyle.Foreground.Red)NOT READY$($PSStyle.Reset): $($failed.Count) of $($results.Count) checks failed. Fix each item above, then rerun this script."
}
elseif ($WorkstationOnly) {
    Write-Information "$($PSStyle.Foreground.Green)WORKSTATION READY$($PSStyle.Reset): $($results.Count) checks passed."
    Write-Information 'Next: prepare your inputs, then rerun with the change parameters (the script signs you in to Exchange Online and asks you to confirm the account):'
    Write-Information "  ./scripts/Test-ExchangeOnlineChangeReadiness.ps1 -ParameterPath 'D:\protected\contoso.parameters.json' -ArtifactRoot 'D:\protected\changes\CHG-1001' -ChangeId 'CHG-1001' -RequestedBy 'requester@contoso.com' -AuthorizedSignerPath 'D:\protected\authorized-signers.json' -Scope 'Transport'"
}
else {
    $suffix = if ($SkipTenantConnection) { ' Tenant session checks were skipped; rerun without -SkipTenantConnection to sign in and check the session.' } else { '' }
    Write-Information "$($PSStyle.Foreground.Green)READY FOR PREVIEW$($PSStyle.Reset): $($results.Count) checks passed.$($suffix)"
    Write-Information 'Copy these lines into this same terminal to create the preview:'
    Write-Information ''
    Write-Information $changeBlock
    Write-Information $previewCommand
}

if ($PassThru) {
    [pscustomobject]@{
        Ready          = $failed.Count -eq 0
        Results        = $results.ToArray()
        ChangeBlock    = $changeBlock
        PreviewCommand = $previewCommand
    }
}
exit $(if ($failed.Count -gt 0) { 1 } else { 0 })
