#requires -Version 7.0

Set-StrictMode -Version Latest

# ARC-001 establishes this module as the single owner of configuration resolution, canonical
# serialization, SHA-256 hashing, schema validation, licensing and entitlement decisions,
# normalized control evaluation, risk acceptance, and evidence/deployment artifacts.
# Behaviour for each capability is delivered by the Phase 1 COM-* cards.

# Administrator inputs are carried in the baseline documents as whole-value placeholders so
# resolution can walk the parsed object graph instead of rewriting JSON text.
$script:PlaceholderPattern = '^__ADMIN_REQUIRED:(?<name>[A-Z0-9_]+)__$'
$script:PlaceholderScanPattern = '__ADMIN_REQUIRED:[A-Z0-9_]+__'

# The deployment profiles a baseline document may declare. Kept in step with the ValidateSet on
# Resolve-BaselineConfiguration, which cannot read a variable.
$script:DeploymentProfileName = @('MicrosoftNative', 'ThirdPartyGateway')

# GATE-002 fixes the field set a risk acceptance must carry, and DES-005 fixes the only role
# that may approve one.
$script:RiskAcceptanceRequiredMember = @(
    'ControlId'
    'TenantId'
    'Owner'
    'Justification'
    'CompensatingControl'
    'ExternalReference'
    'ApprovalIdentity'
    'ApprovalAuthority'
    'ApprovalTimeUtc'
    'EffectiveTimeUtc'
    'ExpiryTimeUtc'
    'Signature'
)
$script:RiskAcceptanceAuthority = 'ExchangeOnlineChangeApproval'

# LIC-002: the Graph vocabulary the tenant inventory is read in, mapped onto the baseline states
# LIC-001 defines. A status outside these tables is refused rather than guessed, because guessing
# can only ever invent an entitlement the tenant does not hold.
$script:GraphSkuCapabilityState = @{
    'Enabled'   = 'Enabled'
    'Warning'   = 'Enabled'
    'Suspended' = 'Suspended'
    'Deleted'   = 'Suspended'
    'LockedOut' = 'Suspended'
}
$script:GraphServicePlanState = @{
    'Success'             = 'Enabled'
    'Disabled'            = 'Disabled'
    'PendingInput'        = 'Pending'
    'PendingActivation'   = 'Pending'
    'PendingProvisioning' = 'Pending'
}
$script:SubscribedSkuRequiredMember = @('skuId', 'skuPartNumber', 'capabilityStatus', 'servicePlans')
$script:ServicePlanRequiredMember = @('servicePlanId', 'servicePlanName', 'provisioningStatus')

# LIC-003: an entry in a user's assignedPlans carries an identifier and a capability status and no
# service-plan name at all, which is why a targeted user's entitlement can only ever be decided on
# the identifier.
$script:GraphAssignedPlanState = @{
    'Enabled'   = 'Enabled'
    'Warning'   = 'Enabled'
    'Suspended' = 'Suspended'
    'Deleted'   = 'Disabled'
}
$script:AssignedPlanRequiredMember = @('servicePlanId', 'capabilityStatus')

# LIC-004: the only response statuses a Graph read is allowed to interpret. A refused status will
# not change by asking again, so it is reported immediately; a transient status is retried within a
# bounded budget; anything else is refused rather than guessed into a success or an empty tenant.
$script:GraphRefusalStatus = @{
    400 = 'GraphRequestInvalid'
    401 = 'GraphRequestUnauthorized'
    403 = 'GraphRequestForbidden'
    404 = 'GraphResourceNotFound'
}
$script:GraphTransientStatus = @(429, 500, 502, 503, 504)
$script:GraphMaximumRetryDelaySecond = 60

# A refusal of the caller rather than of the resource cannot be isolated to one resource: every
# other resource would be refused the same way, and the surviving partial result would be read as
# a tenant that genuinely holds less.
$script:GraphFatalDiscoveryReason = @('GraphRequestUnauthorized', 'GraphRequestForbidden')

# LIC-005: the recipient vocabulary the target population is classified in. A resource mailbox is
# protected by policy but holds no per-user licence, and a mail user is a forwarding address rather
# than a mailbox, so the class decides what may be demanded of the recipient.
$script:RecipientRequiredMember = @('userPrincipalName', 'primarySmtpAddress', 'recipientTypeDetails', 'userType', 'accountEnabled', 'isLicensed')
$script:RecipientTypeClass = @{
    'UserMailbox'      = 'Mailbox'
    'SharedMailbox'    = 'Resource'
    'RoomMailbox'      = 'Resource'
    'EquipmentMailbox' = 'Resource'
    'MailUser'         = 'MailUser'
    'GuestMailUser'    = 'MailUser'
}
$script:RecipientUserType = @('Member', 'Guest')

# LIC-006: the vocabulary the licensing matrix is written in. A control declares which profiles it
# applies to and which service plans it needs; an assignment state is the LIC-003 verdict for one
# user and one plan. Anything outside either list is refused rather than folded into a row.
$script:ControlRequiredMember = @('controlId', 'applicableProfiles', 'requiredServicePlan')
$script:ControlProfile = @('Standard', 'Strict')
$script:LicensingAssignmentRequiredMember = @('UserPrincipalName', 'ServicePlanId', 'State')
$script:LicensingAssignmentState = @('Enabled', 'Suspended', 'Disabled', 'NotAssigned')

# LIC-008: the capabilities the entry scripts branch on, and the service plan each one needs. Only
# the plan name lives here: the baseline declares the identifier and the tenant inventory decides
# the verdict, so no capability can be inferred from a declared licence tier.
$script:BaselineCapabilityServicePlanName = [ordered]@{
    EopPresets         = 'EXCHANGE_S_ENTERPRISE'
    AtpPresets         = 'ATP_ENTERPRISE'
    BuiltInProtection  = 'ATP_ENTERPRISE'
    SafeAttachmentsSpo = 'ATP_ENTERPRISE'
    SafeDocuments      = 'SAFEDOCS'
    PurviewRetention   = 'EXCHANGE_S_ENTERPRISE'
    AuditPremium       = 'M365_ADVANCED_AUDITING'
}

function Test-BaselineParameterValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Parameter
    )

    foreach ($key in $Parameter.Keys) {
        $value = $Parameter[$key]

        $candidates = if ($value -is [string]) {
            @($value)
        }
        elseif ($value -is [System.Collections.IList]) {
            @($value)
        }
        else {
            throw "UnsupportedParameterValueType: parameter '$key' must be a string or an array of strings."
        }

        foreach ($candidate in $candidates) {
            if ($candidate -isnot [string]) {
                throw "UnsupportedParameterValueType: parameter '$key' must be a string or an array of strings."
            }

            if ($candidate -match $script:PlaceholderScanPattern) {
                throw "RecursivePlaceholderValue: parameter '$key' supplies a value that itself contains an administrator placeholder."
            }
        }
    }
}

function Get-BaselinePlaceholderName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Node
    )

    if ($Node -is [string]) {
        if ($Node -match $script:PlaceholderPattern) {
            return @($Matches['name'])
        }

        return @()
    }

    if ($Node -is [System.Collections.IDictionary]) {
        return @(foreach ($key in $Node.Keys) { Get-BaselinePlaceholderName -Node $Node[$key] })
    }

    if ($Node -is [System.Collections.IList]) {
        return @(foreach ($item in $Node) { Get-BaselinePlaceholderName -Node $item })
    }

    return @()
}

function Convert-BaselinePlaceholderNode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Node,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Parameter
    )

    if ($Node -is [string]) {
        if ($Node -match $script:PlaceholderPattern) {
            $name = $Matches['name']
            if (-not $Parameter.Contains($name)) {
                return $Node
            }

            $value = $Parameter[$name]
            if ($value -isnot [string]) {
                throw "ArrayValueForScalarPlaceholder: parameter '$name' supplies an array for a scalar placeholder."
            }

            return $value
        }

        return $Node
    }

    if ($Node -is [System.Collections.IDictionary]) {
        $resolved = [ordered]@{}
        foreach ($key in $Node.Keys) {
            $resolved[$key] = Convert-BaselinePlaceholderNode -Node $Node[$key] -Parameter $Parameter
        }

        return $resolved
    }

    if ($Node -is [System.Collections.IList]) {
        $items = @($Node)
        $placeholders = @($items | Where-Object { $_ -is [string] -and $_ -match $script:PlaceholderPattern })

        if ($placeholders.Count -gt 0) {
            if ($items.Count -gt 1) {
                throw "MixedArrayPlaceholder: an array placeholder must be the only element of its array."
            }

            $null = $items[0] -match $script:PlaceholderPattern
            $name = $Matches['name']
            if (-not $Parameter.Contains($name)) {
                return , $items
            }

            $value = $Parameter[$name]
            # Both shipped baselines bind one input to a scalar slot and to a single-item list
            # slot, so a string widens into a one-element array rather than being rejected.
            if ($value -is [string]) {
                return , @($value)
            }

            if (@($value).Count -eq 0) {
                throw "EmptyArrayValueForArrayPlaceholder: parameter '$name' supplies no values for an array placeholder."
            }

            return , @($value)
        }

        return , @($items | ForEach-Object { Convert-BaselinePlaceholderNode -Node $_ -Parameter $Parameter })
    }

    return $Node
}

# COM-002: load the baseline document for the selected deployment profile and substitute the
# administrator inputs by walking the parsed graph, so a supplied value can never inject JSON.
function Resolve-BaselineConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigurationPath,

        [Parameter(Mandatory)]
        [string]$ParameterPath,

        [ValidateSet('MicrosoftNative', 'ThirdPartyGateway')]
        [string]$DeploymentProfile
    )

    if (-not (Test-Path -LiteralPath $ConfigurationPath -PathType Leaf)) {
        throw "ConfigurationFileNotFound: '$ConfigurationPath' does not exist."
    }

    if (-not (Test-Path -LiteralPath $ParameterPath -PathType Leaf)) {
        throw "ParameterFileNotFound: '$ParameterPath' does not exist."
    }

    try {
        $document = Get-Content -LiteralPath $ConfigurationPath -Raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    }
    catch {
        throw "ConfigurationJsonInvalid: '$ConfigurationPath' is not valid JSON. $($_.Exception.Message)"
    }

    try {
        $parameter = Get-Content -LiteralPath $ParameterPath -Raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    }
    catch {
        throw "ParameterJsonInvalid: '$ParameterPath' is not valid JSON. $($_.Exception.Message)"
    }

    if ($parameter -isnot [System.Collections.IDictionary]) {
        throw "ParameterDocumentNotObject: '$ParameterPath' must contain a JSON object of administrator inputs."
    }

    Test-BaselineParameterValue -Parameter $parameter

    $declaredProfile = $null
    if ($document -is [System.Collections.IDictionary] -and $document.Contains('metadata')) {
        $metadata = $document['metadata']
        if ($metadata -is [System.Collections.IDictionary] -and $metadata.Contains('deploymentProfile')) {
            $declaredProfile = [string]$metadata['deploymentProfile']
        }
    }

    if ($PSBoundParameters.ContainsKey('DeploymentProfile')) {
        if ([string]::IsNullOrWhiteSpace($declaredProfile)) {
            throw "DeploymentProfileNotDeclared: '$ConfigurationPath' declares no metadata.deploymentProfile."
        }

        if ($declaredProfile -ne $DeploymentProfile) {
            throw "DeploymentProfileMismatch: '$ConfigurationPath' declares '$declaredProfile' but '$DeploymentProfile' was selected."
        }
    }

    $resolved = Convert-BaselinePlaceholderNode -Node $document -Parameter $parameter

    return [pscustomobject]@{
        Configuration           = ($resolved | ConvertTo-Json -Depth 64 | ConvertFrom-Json)
        DeploymentProfile       = $declaredProfile
        SuppliedParameterName   = @($parameter.Keys | Sort-Object)
        DeclaredPlaceholderName = @(Get-BaselinePlaceholderName -Node $document | Sort-Object -Unique)
    }
}

# COM-003: refuse a resolution that carries an unknown administrator input or an unresolved
# placeholder, and validate the resolved document against the selected schema. Every check is
# offline, so an invalid configuration is rejected before any tenant connection is attempted.
function Assert-BaselineConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Resolution,

        [Parameter(Mandatory)]
        [string]$SchemaPath
    )

    foreach ($property in @('Configuration', 'DeploymentProfile', 'SuppliedParameterName', 'DeclaredPlaceholderName')) {
        if ($null -eq $Resolution -or $Resolution.PSObject.Properties.Match($property).Count -eq 0) {
            throw "ResolutionNotRecognized: the supplied resolution does not expose '$property'; pass the output of Resolve-BaselineConfiguration."
        }
    }

    if (-not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) {
        throw "SchemaFileNotFound: '$SchemaPath' does not exist."
    }

    $unknownKey = @($Resolution.SuppliedParameterName | Where-Object { $_ -notin $Resolution.DeclaredPlaceholderName })
    if ($unknownKey.Count -gt 0) {
        throw "UnknownParameterKey: the parameter file supplies '$($unknownKey -join "', '")', which the baseline does not declare."
    }

    $resolvedJson = $Resolution.Configuration | ConvertTo-Json -Depth 64

    $unresolvedToken = @([regex]::Matches($resolvedJson, $script:PlaceholderScanPattern) | ForEach-Object { $_.Value } | Sort-Object -Unique)
    if ($unresolvedToken.Count -gt 0) {
        throw "UnresolvedPlaceholder: the resolved configuration still contains '$($unresolvedToken -join "', '")'."
    }

    try {
        $null = Get-Content -LiteralPath $SchemaPath -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "SchemaJsonInvalid: '$SchemaPath' is not valid JSON. $($_.Exception.Message)"
    }

    try {
        $null = Test-Json -Json $resolvedJson -SchemaFile $SchemaPath -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -like '*parse the JSON schema*') {
            throw "SchemaNotValid: '$SchemaPath' is not a usable JSON Schema. $($_.Exception.Message)"
        }

        throw "SchemaValidationFailed: the resolved configuration violates '$SchemaPath'. $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Valid             = $true
        SchemaPath        = (Resolve-Path -LiteralPath $SchemaPath).ProviderPath
        DeploymentProfile = $Resolution.DeploymentProfile
        Configuration     = $Resolution.Configuration
    }
}

function Get-BaselineConfigValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Configuration,

        [Parameter(Mandatory)]
        [string]$Path,

        [AllowNull()]
        [object]$Default = $null
    )

    $current = $Configuration
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $current) { return $Default }
        $property = $current.PSObject.Properties[$segment]
        if (-not $property) { return $Default }
        $current = $property.Value
    }

    if ($null -eq $current) { return $Default }
    return $current
}

# COM-006: the desired-state rules the entry scripts used to restate. The JSON Schema already
# rejects a malformed document; these are the cross-member rules a schema cannot express, and they
# live here so deployment and evidence reach one verdict from one resolved configuration.
function Assert-BaselineDesiredState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Configuration
    )

    if ($null -eq $Configuration -or $Configuration.PSObject.Properties.Match('desiredState').Count -eq 0) {
        throw 'DesiredStateNotRecognized: the supplied configuration carries no desiredState; pass a validated resolved configuration.'
    }

    $state = $Configuration.desiredState
    $gatewayDeclared = [bool](Get-BaselineConfigValue -Configuration $Configuration -Path 'desiredState.mailFlow.gateway.declared' -Default $false)
    $enhancedFiltering = [bool](Get-BaselineConfigValue -Configuration $Configuration -Path 'desiredState.mailFlow.enhancedFiltering.enabled' -Default $false)

    if (Get-BaselineConfigValue -Configuration $Configuration -Path 'desiredState.mailFlow.prohibitedBypass.sclMinusOneTransportRules' -Default $false) {
        throw 'SCL -1 bypass rules are prohibited. They suppress Microsoft spam and phish evaluation.'
    }
    if (-not $state.exchangeOnline.smtpClientAuthenticationDisabled) {
        throw 'SMTP AUTH must be disabled at the organization level.'
    }
    if ($state.exchangeOnline.automaticExternalForwarding -ne 'Off') {
        throw 'Automatic external forwarding must be Off.'
    }

    # Enhanced Filtering only makes sense when a non-Microsoft public hop is declared.
    if ($gatewayDeclared) {
        if (-not $enhancedFiltering) {
            throw 'A mail gateway is declared, so Enhanced Filtering for Connectors must be enabled. Without it, Microsoft sees the gateway as the sending host and loses the true originating IP.'
        }
        foreach ($required in 'gatewayInboundConnector', 'gatewayOutboundConnector') {
            if (-not $state.mailFlow.PSObject.Properties[$required]) {
                throw "A mail gateway is declared but desiredState.mailFlow.$required is missing."
            }
        }
        $skipIps = @(Get-BaselineConfigValue -Configuration $Configuration -Path 'desiredState.mailFlow.enhancedFiltering.skipIpAddresses' -Default @())
        $skipLast = [bool](Get-BaselineConfigValue -Configuration $Configuration -Path 'desiredState.mailFlow.enhancedFiltering.skipLastIp' -Default $false)
        if ($skipIps.Count -eq 0 -and -not $skipLast) {
            throw 'Enhanced Filtering is enabled but no skip addresses are declared. List every non-Microsoft public hop.'
        }
    }
    else {
        if ($enhancedFiltering) {
            throw 'Enhanced Filtering is enabled but no mail gateway is declared. Set mailFlow.gateway.declared to true and declare the connectors, or disable Enhanced Filtering.'
        }
        foreach ($forbidden in 'gatewayInboundConnector', 'gatewayOutboundConnector') {
            if ($state.mailFlow.PSObject.Properties[$forbidden]) {
                throw "No mail gateway is declared, so desiredState.mailFlow.$forbidden must be removed. A Microsoft-native tenant receives directly on its Microsoft 365 MX target."
            }
        }
    }

    $abnormalMode = Get-BaselineConfigValue -Configuration $Configuration -Path 'desiredState.abnormalSecurity.integrationMode'
    if ($abnormalMode -and $abnormalMode -ne 'Microsoft API post-delivery') {
        throw 'Abnormal Security must use API post-delivery integration, not SMTP routing.'
    }

    return [pscustomobject]@{
        Valid           = $true
        GatewayDeclared = $gatewayDeclared
    }
}

# LIC-008: the entitlement both entry scripts consume. DES-003 makes the runtime tenant
# service-plan inventory the only authority, so every capability is decided on a service-plan
# identifier the baseline declares and the tenant has enabled. Safe Documents follows the SAFEDOCS
# plan alone and is never inferred from a Defender plan or suite.
function Resolve-BaselineEntitlement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Configuration,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$TenantServicePlan
    )

    if ($null -eq $TenantServicePlan) {
        throw 'TenantServicePlanRequired: entitlement is decided from the tenant service-plan inventory, and an inventory that was never collected must never be assumed.'
    }

    $enabled = Get-BaselineGraphMemberValue -Node $TenantServicePlan -Name 'ServicePlanId'
    if ($null -eq $enabled -or $enabled -isnot [System.Collections.IList]) {
        throw "TenantServicePlanContractViolation: the inventory does not declare a 'ServicePlanId' collection, and a summary verdict is not the evidence a capability is decided from."
    }

    return New-BaselineEntitlementProjection -Configuration $Configuration -EnabledServicePlanId @($enabled) -Source 'GraphSubscribedSkus' -Determined
}

# The one place a capability becomes a verdict, shared by the collected and the uncollected case so
# a context that never reached Graph reports the same shape, fail-closed, rather than nothing.
function New-BaselineEntitlementProjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Configuration,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$EnabledServicePlanId,

        [Parameter(Mandatory)]
        [string]$Source,

        [switch]$Determined
    )

    if ($null -eq $Configuration) {
        throw 'ConfigurationRequired: without the baseline nothing declares which service plan a capability needs.'
    }

    $declared = @(Get-BaselineConfigValue -Configuration $Configuration -Path 'licensing.requiredServicePlans' -Default @())
    if ($declared.Count -eq 0) {
        throw 'LicensingRequirementMissing: the baseline declares no licensing.requiredServicePlans, and an empty requirement set cannot be told from a tenant that holds everything.'
    }

    $identifierByName = @{}
    foreach ($entry in $declared) {
        $planId = [string](Get-BaselineGraphMemberValue -Node $entry -Name 'servicePlanId')
        if ([string]::IsNullOrWhiteSpace($planId)) {
            throw "RequiredServicePlanContractViolation: a required service plan does not declare 'servicePlanId', and the tenant inventory carries no display name to match on instead."
        }

        $planName = [string](Get-BaselineGraphMemberValue -Node $entry -Name 'servicePlanName')
        if ([string]::IsNullOrWhiteSpace($planName)) {
            throw "RequiredServicePlanContractViolation: a required service plan does not declare 'servicePlanName', so no capability can be bound to it."
        }

        $planId = $planId.ToLowerInvariant()
        if ($identifierByName.ContainsKey($planName) -and $identifierByName[$planName] -ne $planId) {
            throw "RequiredServicePlanAmbiguous: '$planName' is declared with more than one service-plan identifier, which would make the verdict depend on the declaration order."
        }

        $identifierByName[$planName] = $planId
    }

    $enabledIdentifier = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($identifier in @($EnabledServicePlanId)) {
        if (-not [string]::IsNullOrWhiteSpace($identifier)) { $null = $enabledIdentifier.Add($identifier.Trim()) }
    }

    $capability = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $script:BaselineCapabilityServicePlanName.Keys) {
        $planName = $script:BaselineCapabilityServicePlanName[$name]
        $planId = if ($identifierByName.ContainsKey($planName)) { $identifierByName[$planName] } else { '' }

        $entitled = $false
        $reason = ''
        if (-not $Determined) {
            $reason = "'$name' is not entitled because the tenant service-plan inventory was not collected."
        }
        elseif ([string]::IsNullOrWhiteSpace($planId)) {
            $reason = "'$name' is not entitled because the baseline declares no service plan named '$planName'."
        }
        elseif ($enabledIdentifier.Contains($planId)) {
            $entitled = $true
            $reason = "'$name' is entitled because the tenant service plan '$planName' ($planId) is enabled."
        }
        else {
            $reason = "'$name' is not entitled because the tenant has no enabled service plan '$planName' ($planId)."
        }

        $capability.Add([pscustomobject]@{
                Name                    = $name
                RequiredServicePlanName = $planName
                RequiredServicePlanId   = $planId
                Entitled                = $entitled
                Reason                  = $reason
            })
    }

    $projection = [ordered]@{
        Source                 = $Source
        Determined             = [bool]$Determined
        DeclaredMessagingTier  = [string](Get-BaselineConfigValue -Configuration $Configuration -Path 'licensing.messagingTier' -Default 'EOP')
        DeclaredComplianceTier = [string](Get-BaselineConfigValue -Configuration $Configuration -Path 'licensing.complianceTier' -Default 'None')
        EnabledServicePlanId   = @($enabledIdentifier | Sort-Object)
        Capability             = @($capability)
        NotEntitled            = @($capability | Where-Object { -not $_.Entitled } | ForEach-Object { $_.Name })
    }

    foreach ($row in $capability) { $projection[$row.Name] = $row.Entitled }

    return [pscustomobject]$projection
}

# LIC-002: the tenant service-plan inventory, which DES-003 makes the only entitlement authority.
# Graph is reached through an injected request seam so the collector is exercisable offline and so
# no Microsoft.Graph dependency leaks into the module.
function Get-BaselineTenantServicePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$GraphRequest
    )

    if ($null -eq $GraphRequest) {
        throw 'GraphRequestRequired: the tenant service-plan inventory is read through an injected Graph request, so one must be supplied.'
    }

    $response = & $GraphRequest 'subscribedSkus'

    if ($null -eq $response) {
        throw 'GraphResponseMissing: subscribedSkus returned nothing, which is not the same as a tenant holding no subscription.'
    }

    $subscription = Get-BaselineGraphMemberValue -Node $response -Name 'value'
    if ($null -eq $subscription) {
        throw "GraphResponseContractViolation: the subscribedSkus response does not declare 'value'."
    }

    if ($subscription -isnot [System.Collections.IList]) {
        throw 'GraphResponseValueNotACollection: the subscribedSkus response does not carry a collection of subscriptions.'
    }

    $sku = [System.Collections.Generic.List[object]]::new()
    $plan = [System.Collections.Generic.List[object]]::new()

    foreach ($subscribedSku in @($subscription)) {
        foreach ($member in $script:SubscribedSkuRequiredMember) {
            if ($null -eq (Get-BaselineGraphMemberValue -Node $subscribedSku -Name $member)) {
                throw "SubscribedSkuContractViolation: a subscribed SKU does not declare '$member'."
            }
        }

        $capabilityStatus = [string](Get-BaselineGraphMemberValue -Node $subscribedSku -Name 'capabilityStatus')
        if (-not $script:GraphSkuCapabilityState.ContainsKey($capabilityStatus)) {
            throw "UnknownSkuCapabilityStatus: '$capabilityStatus' is not a declared subscription capability status."
        }

        $skuState = $script:GraphSkuCapabilityState[$capabilityStatus]
        $skuId = [string](Get-BaselineGraphMemberValue -Node $subscribedSku -Name 'skuId')
        $skuPartNumber = [string](Get-BaselineGraphMemberValue -Node $subscribedSku -Name 'skuPartNumber')

        $sku.Add([pscustomobject]@{
                SkuId            = $skuId
                SkuPartNumber    = $skuPartNumber
                CapabilityStatus = $capabilityStatus
                State            = $skuState
            })

        $servicePlanList = Get-BaselineGraphMemberValue -Node $subscribedSku -Name 'servicePlans'

        foreach ($servicePlan in @($servicePlanList)) {
            foreach ($member in $script:ServicePlanRequiredMember) {
                if ($null -eq (Get-BaselineGraphMemberValue -Node $servicePlan -Name $member)) {
                    throw "ServicePlanContractViolation: a service plan on '$skuPartNumber' does not declare '$member'."
                }
            }

            $provisioningStatus = [string](Get-BaselineGraphMemberValue -Node $servicePlan -Name 'provisioningStatus')
            if (-not $script:GraphServicePlanState.ContainsKey($provisioningStatus)) {
                throw "UnknownProvisioningStatus: '$provisioningStatus' is not a declared service-plan provisioning status."
            }

            # A plan is never more usable than the subscription carrying it.
            $state = if ($skuState -eq 'Enabled') { $script:GraphServicePlanState[$provisioningStatus] } else { $skuState }

            $plan.Add([pscustomobject]@{
                    ServicePlanId       = ([string](Get-BaselineGraphMemberValue -Node $servicePlan -Name 'servicePlanId')).ToLowerInvariant()
                    ServicePlanName     = [string](Get-BaselineGraphMemberValue -Node $servicePlan -Name 'servicePlanName')
                    SkuId               = $skuId
                    SkuPartNumber       = $skuPartNumber
                    ProvisioningStatus  = $provisioningStatus
                    SkuCapabilityStatus = $capabilityStatus
                    State               = $state
                    Enabled             = ($state -eq 'Enabled')
                })
        }
    }

    $enabled = @($plan | Where-Object { $_.Enabled })

    return [pscustomobject]@{
        Source          = 'GraphSubscribedSkus'
        Sku             = @($sku)
        Plan            = @($plan)
        ServicePlanId   = @($enabled | ForEach-Object { $_.ServicePlanId } | Sort-Object -Unique)
        ServicePlanName = @($enabled | ForEach-Object { $_.ServicePlanName } | Sort-Object -Unique)
    }
}

# LIC-003: whether each targeted user actually holds each required service plan. Safe Documents is
# decided here on the SAFEDOCS identifier alone, never inferred from a Defender plan bundle.
function Get-BaselineTargetEntitlement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$UserPrincipalName,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$RequiredServicePlan,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$GraphRequest
    )

    if ($null -eq $GraphRequest) {
        throw 'GraphRequestRequired: targeted entitlement is read through an injected Graph request, so one must be supplied.'
    }

    $target = @($UserPrincipalName)
    if ($target.Count -eq 0) {
        throw 'TargetRequired: an empty target population is not a fully entitled population, so at least one target must be supplied.'
    }

    foreach ($upn in $target) {
        if ([string]::IsNullOrWhiteSpace($upn) -or $upn -notmatch '^[^@\s]+@[^@\s]+$') {
            throw "TargetNotAUserPrincipalName: '$upn' cannot be looked up as a user principal name."
        }
    }

    $required = @($RequiredServicePlan)
    if ($required.Count -eq 0) {
        throw 'RequiredServicePlanMissing: an empty requirement declares every target entitled to everything, so at least one required service plan must be supplied.'
    }

    $requirement = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $required) {
        $requiredId = [string](Get-BaselineGraphMemberValue -Node $entry -Name 'servicePlanId')
        if ([string]::IsNullOrWhiteSpace($requiredId)) {
            throw "RequiredServicePlanContractViolation: a required service plan does not declare 'servicePlanId', and assignedPlans carries no service-plan name to match on instead."
        }

        $requirement.Add([pscustomobject]@{
                ServicePlanId   = $requiredId.ToLowerInvariant()
                ServicePlanName = [string](Get-BaselineGraphMemberValue -Node $entry -Name 'servicePlanName')
            })
    }

    $assignment = [System.Collections.Generic.List[object]]::new()
    $missing = [System.Collections.Generic.List[object]]::new()

    foreach ($upn in $target) {
        $response = & $GraphRequest "users/$upn"

        if ($null -eq $response) {
            throw "GraphResponseMissing: '$upn' returned nothing, which is not the same as a target holding no licence."
        }

        $assignedPlans = Get-BaselineGraphMemberValue -Node $response -Name 'assignedPlans'
        if ($null -eq $assignedPlans) {
            throw "GraphResponseContractViolation: the response for '$upn' does not declare 'assignedPlans'."
        }

        if ($assignedPlans -isnot [System.Collections.IList]) {
            throw "AssignedPlansNotACollection: the response for '$upn' does not carry a collection of assigned plans."
        }

        $stateByPlanId = @{}
        foreach ($plan in @($assignedPlans)) {
            foreach ($member in $script:AssignedPlanRequiredMember) {
                if ($null -eq (Get-BaselineGraphMemberValue -Node $plan -Name $member)) {
                    throw "AssignedPlanContractViolation: an assigned plan on '$upn' does not declare '$member'."
                }
            }

            $capabilityStatus = [string](Get-BaselineGraphMemberValue -Node $plan -Name 'capabilityStatus')
            if (-not $script:GraphAssignedPlanState.ContainsKey($capabilityStatus)) {
                throw "UnknownAssignedPlanCapabilityStatus: '$capabilityStatus' is not a declared assigned-plan capability status."
            }

            $planId = ([string](Get-BaselineGraphMemberValue -Node $plan -Name 'servicePlanId')).ToLowerInvariant()
            $planState = $script:GraphAssignedPlanState[$capabilityStatus]

            # A plan granted by one licence is not taken away by a dormant duplicate of the same plan.
            if (-not $stateByPlanId.ContainsKey($planId) -or $planState -eq 'Enabled') {
                $stateByPlanId[$planId] = $planState
            }
        }

        foreach ($entry in $requirement) {
            $state = if ($stateByPlanId.ContainsKey($entry.ServicePlanId)) { $stateByPlanId[$entry.ServicePlanId] } else { 'NotAssigned' }
            $entitled = ($state -eq 'Enabled')

            $verdict = [pscustomobject]@{
                UserPrincipalName = $upn
                ServicePlanId     = $entry.ServicePlanId
                ServicePlanName   = $entry.ServicePlanName
                State             = $state
                Entitled          = $entitled
            }

            $assignment.Add($verdict)
            if (-not $entitled) { $missing.Add($verdict) }
        }
    }

    return [pscustomobject]@{
        Source     = 'GraphUserAssignedPlans'
        Target     = @($target)
        Assignment = @($assignment)
        Missing    = @($missing)
        Entitled   = ($missing.Count -eq 0)
    }
}

# LIC-004: one hardened Graph read. Pagination, throttling and retry are sequential stages of a
# single request, so they are decided here rather than restated by every collector. The transport
# and the wait are both injected, so the module never binds a Graph SDK and never sleeps in a test.
function Invoke-BaselineGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Resource,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Transport,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Wait,

        [int]$MaximumAttempt = 4,

        [int]$MaximumPage = 200
    )

    if ($null -eq $Transport) {
        throw 'GraphTransportRequired: a Graph read is issued through an injected transport, so one must be supplied.'
    }

    if ([string]::IsNullOrWhiteSpace($Resource)) {
        throw 'GraphResourceRequired: a blank resource addresses nothing and cannot be read.'
    }

    if ($null -eq $Wait) {
        throw 'RetryWaitRequired: retry needs a clock, and the clock is injected so the module never sleeps on its own.'
    }

    if ($MaximumAttempt -lt 1) {
        throw "MaximumAttemptOutOfRange: '$MaximumAttempt' would never attempt the request, which cannot report what the tenant holds."
    }

    if ($MaximumPage -lt 1) {
        throw "MaximumPageOutOfRange: '$MaximumPage' would return an empty result for a populated tenant."
    }

    $item = [System.Collections.Generic.List[object]]::new()
    $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $attemptCount = 0
    $pageCount = 0
    $uri = $Resource

    while ($true) {
        if (-not $visited.Add($uri)) {
            throw "GraphPaginationLoop: '$uri' was offered as its own continuation, so paging would never terminate."
        }

        if ($pageCount -ge $MaximumPage) {
            throw "GraphPageLimitExceeded: '$Resource' has more than $MaximumPage pages, and a truncated page set would be read as the whole tenant."
        }

        $page = $null
        for ($attempt = 1; $attempt -le $MaximumAttempt; $attempt++) {
            $attemptCount++
            $response = & $Transport $uri

            if ($null -eq $response) {
                throw "GraphResponseMissing: '$uri' returned nothing, which is not the same as returning no results."
            }

            $status = Get-BaselineGraphMemberValue -Node $response -Name 'status'
            if ($null -eq $status) {
                throw "GraphResponseContractViolation: the response for '$uri' does not declare 'status'."
            }

            $statusCode = [int]$status
            if ($statusCode -eq 200) {
                $page = $response
                break
            }

            if ($script:GraphRefusalStatus.ContainsKey($statusCode)) {
                throw "$($script:GraphRefusalStatus[$statusCode]): '$uri' was refused with status $statusCode."
            }

            if ($statusCode -notin $script:GraphTransientStatus) {
                throw "UnexpectedGraphStatus: '$statusCode' is not a status this read knows how to interpret."
            }

            if ($attempt -eq $MaximumAttempt) {
                if ($statusCode -eq 429) {
                    throw "GraphThrottled: '$uri' was throttled on every one of $MaximumAttempt attempts, so the tenant never reported what it holds."
                }

                throw "GraphRequestFailed: '$uri' returned status $statusCode on every one of $MaximumAttempt attempts."
            }

            & $Wait (Get-BaselineGraphRetryDelay -Response $response -Attempt $attempt)
        }

        $value = Get-BaselineGraphMemberValue -Node $page -Name 'value'
        if ($null -eq $value) {
            throw "GraphResponseContractViolation: the page for '$uri' does not declare 'value'."
        }

        if ($value -isnot [System.Collections.IList]) {
            throw "GraphResponseValueNotACollection: the page for '$uri' does not carry a collection of results."
        }

        foreach ($entry in @($value)) { $item.Add($entry) }
        $pageCount++

        $nextLink = Get-BaselineGraphMemberValue -Node $page -Name '@odata.nextLink'
        if ($null -eq $nextLink) { break }

        if ($nextLink -isnot [string] -or [string]::IsNullOrWhiteSpace($nextLink)) {
            throw "GraphNextLinkInvalid: the page for '$uri' offers a continuation that cannot be followed, which would truncate the result."
        }

        $uri = $nextLink
    }

    return [pscustomobject]@{
        Resource     = $Resource
        Value        = @($item)
        PageCount    = $pageCount
        AttemptCount = $attemptCount
    }
}

# LIC-005: who the baseline actually targets. The eight classes are decided by one set of rules
# with a fixed precedence, because a recipient that falls into two classes must land in the same
# class on every run for the evidence of two runs to be comparable.
function Get-BaselineTargetPopulation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Recipient,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$StandardDomain,

        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$PriorityGroupMember = @(),

        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ExcludedRecipient = @()
    )

    $collected = @($Recipient)
    if ($collected.Count -eq 0) {
        throw 'RecipientRequired: an empty population is not a tenant with nobody in it, so at least one recipient must be supplied.'
    }

    $domain = @($StandardDomain)
    if ($domain.Count -eq 0) {
        throw 'StandardDomainRequired: with no accepted domain every recipient would silently fall out of scope.'
    }

    $standardDomainSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $domain) {
        if ([string]::IsNullOrWhiteSpace($entry)) {
            throw 'StandardDomainNotADomain: a blank accepted domain matches nothing and hides a configuration error.'
        }

        $null = $standardDomainSet.Add($entry.Trim())
    }

    $priorityMemberSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($PriorityGroupMember)) {
        if ([string]::IsNullOrWhiteSpace($entry)) {
            throw 'PriorityGroupMemberNotAUserPrincipalName: a blank member cannot be matched and would silently shrink the Strict population.'
        }

        $null = $priorityMemberSet.Add($entry.Trim())
    }

    $exclusionSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($ExcludedRecipient)) {
        if ([string]::IsNullOrWhiteSpace($entry)) {
            throw 'ExcludedRecipientNotAUserPrincipalName: a blank exclusion cannot be reviewed or approved.'
        }

        $null = $exclusionSet.Add($entry.Trim())
    }

    $classified = [System.Collections.Generic.List[object]]::new()
    $exception = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($record in $collected) {
        foreach ($member in $script:RecipientRequiredMember) {
            if ($null -eq (Get-BaselineGraphMemberValue -Node $record -Name $member)) {
                throw "RecipientContractViolation: a recipient does not declare '$member'."
            }
        }

        $upn = [string](Get-BaselineGraphMemberValue -Node $record -Name 'userPrincipalName')
        if (-not $seen.Add($upn)) {
            throw "RecipientDuplicated: '$upn' was collected more than once, which would make the licensing matrix depend on the collection order."
        }

        $typeDetails = [string](Get-BaselineGraphMemberValue -Node $record -Name 'recipientTypeDetails')
        if (-not $script:RecipientTypeClass.ContainsKey($typeDetails)) {
            throw "UnknownRecipientTypeDetails: '$typeDetails' is not a recipient type this baseline knows how to classify."
        }

        $userType = [string](Get-BaselineGraphMemberValue -Node $record -Name 'userType')
        if ($userType -notin $script:RecipientUserType) {
            throw "UnknownUserType: '$userType' is not a declared user type."
        }

        $class = $script:RecipientTypeClass[$typeDetails]
        $smtp = [string](Get-BaselineGraphMemberValue -Node $record -Name 'primarySmtpAddress')
        $enabled = [bool](Get-BaselineGraphMemberValue -Node $record -Name 'accountEnabled')
        $licensed = [bool](Get-BaselineGraphMemberValue -Node $record -Name 'isLicensed')
        $recipientDomain = if ($smtp.Contains('@')) { $smtp.Substring($smtp.LastIndexOf('@') + 1) } else { '' }

        $verdict = $null

        # Precedence is fixed so a recipient that qualifies for two classes lands in the same class
        # on every run. An approved exclusion is a deliberate decision and outranks everything.
        if ($exclusionSet.Contains($upn)) {
            $verdict = @('ExplicitlyExcluded', 'None', $false, $false, 'The recipient is on the approved exclusion list.')
        }
        elseif ($userType -eq 'Guest') {
            $verdict = @('Guest', 'None', $false, $false, 'A guest holds no mailbox in this tenant.')
        }
        elseif ($class -eq 'MailUser') {
            $verdict = @('MailUser', 'None', $false, $false, 'A mail user is a forwarding address, not a mailbox this baseline can harden.')
        }
        elseif (-not $enabled) {
            $verdict = @('InactiveUser', 'None', $false, $false, 'The account is disabled and cannot sign in.')
        }
        else {
            $profileName = if ($priorityMemberSet.Contains($upn)) { 'Strict' }
            elseif ($standardDomainSet.Contains($recipientDomain)) { 'Standard' }
            else { 'None' }

            if ($profileName -eq 'None') {
                $verdict = @('UnmanagedDomain', 'None', $false, $false, "'$recipientDomain' is not an accepted domain of the managed service.")
            }
            elseif ($class -eq 'Resource') {
                $verdict = @('ResourceMailbox', $profileName, $true, $false, 'A resource mailbox is protected by policy but holds no per-user licence to prove.')
            }
            elseif (-not $licensed) {
                $verdict = @('UnlicensedMailbox', $profileName, $true, $false, 'The mailbox is in scope but holds no licence, so it needs an approved exception.')
            }
            else {
                $classification = if ($profileName -eq 'Strict') { 'StrictPriority' } else { 'StandardDomain' }
                $verdict = @($classification, $profileName, $true, $true, "The recipient is targeted by the $profileName profile.")
            }
        }

        $entry = [pscustomobject]@{
            UserPrincipalName    = $upn
            PrimarySmtpAddress   = $smtp
            RecipientTypeDetails = $typeDetails
            Classification       = $verdict[0]
            Profile              = $verdict[1]
            InScope              = $verdict[2]
            LicensingRequired    = $verdict[3]
            Reason               = $verdict[4]
        }

        $classified.Add($entry)
        if ($entry.Classification -eq 'UnlicensedMailbox') { $exception.Add($entry) }
    }

    return [pscustomobject]@{
        Recipient       = @($classified)
        Strict          = @($classified | Where-Object { $_.Profile -eq 'Strict' } | ForEach-Object { $_.UserPrincipalName })
        Standard        = @($classified | Where-Object { $_.Profile -eq 'Standard' } | ForEach-Object { $_.UserPrincipalName })
        Excluded        = @($classified | Where-Object { -not $_.InScope } | ForEach-Object { $_.UserPrincipalName })
        LicensingTarget = @($classified | Where-Object { $_.LicensingRequired } | ForEach-Object { $_.UserPrincipalName })
        Exception       = @($exception)
    }
}

# LIC-006: the licensing matrix. One row per licensing target, per applicable control, per service
# plan that control requires, so a gap can be named as a user, a control and a plan rather than as
# a tenant-wide shortfall.
function Get-BaselineLicensingMatrix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$TargetPopulation,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Control,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Entitlement
    )

    if ($null -eq $TargetPopulation) {
        throw 'TargetPopulationRequired: a matrix built over nobody reports every control satisfied, so a classified population must be supplied.'
    }

    $recipient = Get-BaselineGraphMemberValue -Node $TargetPopulation -Name 'Recipient'
    if ($null -eq $recipient -or $recipient -isnot [System.Collections.IList]) {
        throw "TargetPopulationContractViolation: the target population does not declare a 'Recipient' collection, and only a classified population carries the profile each row is scoped by."
    }

    $supplied = @($Control)
    if ($supplied.Count -eq 0) {
        throw 'ControlRequired: an empty control set produces an empty matrix, which would read as a fully licensed tenant.'
    }

    $definition = [System.Collections.Generic.List[object]]::new()
    $seenControl = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($entry in $supplied) {
        foreach ($member in $script:ControlRequiredMember) {
            if ($null -eq (Get-BaselineGraphMemberValue -Node $entry -Name $member)) {
                throw "ControlContractViolation: a control does not declare '$member'."
            }
        }

        $controlId = [string](Get-BaselineGraphMemberValue -Node $entry -Name 'controlId')
        if (-not $seenControl.Add($controlId)) {
            throw "ControlDuplicated: '$controlId' was supplied more than once, which would make the gap count depend on the registry order."
        }

        $declaredProfile = Get-BaselineGraphMemberValue -Node $entry -Name 'applicableProfiles'
        $applicableProfile = @($declaredProfile)
        if ($applicableProfile.Count -eq 0) {
            throw "ControlContractViolation: '$controlId' declares no 'applicableProfiles', so it would never be evaluated and never reported."
        }

        foreach ($name in $applicableProfile) {
            if ($name -notin $script:ControlProfile) {
                throw "UnknownControlProfile: '$name' on '$controlId' is not a declared deployment profile."
            }
        }

        $planRequirement = [System.Collections.Generic.List[object]]::new()
        $declaredPlan = Get-BaselineGraphMemberValue -Node $entry -Name 'requiredServicePlan'
        foreach ($plan in @($declaredPlan)) {
            $planId = [string](Get-BaselineGraphMemberValue -Node $plan -Name 'servicePlanId')
            if ([string]::IsNullOrWhiteSpace($planId)) {
                throw "RequiredServicePlanContractViolation: a required service plan on '$controlId' does not declare 'servicePlanId', and an assignment carries no service-plan name to match on instead."
            }

            $planRequirement.Add([pscustomobject]@{
                    ServicePlanId   = $planId.ToLowerInvariant()
                    ServicePlanName = [string](Get-BaselineGraphMemberValue -Node $plan -Name 'servicePlanName')
                })
        }

        $definition.Add([pscustomobject]@{
                ControlId         = $controlId
                ApplicableProfile = $applicableProfile
                Requirement       = @($planRequirement)
            })
    }

    if ($null -eq $Entitlement) {
        throw 'EntitlementRequired: without the per-user verdicts the matrix has no assigned state to report.'
    }

    $assignment = Get-BaselineGraphMemberValue -Node $Entitlement -Name 'Assignment'
    if ($null -eq $assignment -or $assignment -isnot [System.Collections.IList]) {
        throw "EntitlementContractViolation: the entitlement does not declare an 'Assignment' collection, and a summary verdict is not the per-user evidence a row is built from."
    }

    $stateByKey = @{}
    foreach ($record in @($assignment)) {
        foreach ($member in $script:LicensingAssignmentRequiredMember) {
            if ($null -eq (Get-BaselineGraphMemberValue -Node $record -Name $member)) {
                throw "EntitlementAssignmentContractViolation: an assignment does not declare '$member'."
            }
        }

        $state = [string](Get-BaselineGraphMemberValue -Node $record -Name 'State')
        if ($state -notin $script:LicensingAssignmentState) {
            throw "UnknownAssignmentState: '$state' is not a declared assignment state."
        }

        $assignedTo = ([string](Get-BaselineGraphMemberValue -Node $record -Name 'UserPrincipalName')).ToLowerInvariant()
        $assignedPlan = ([string](Get-BaselineGraphMemberValue -Node $record -Name 'ServicePlanId')).ToLowerInvariant()
        $key = '{0}|{1}' -f $assignedTo, $assignedPlan

        # A plan granted by one licence is not taken away by a dormant duplicate of the same plan.
        if (-not $stateByKey.ContainsKey($key) -or $state -eq 'Enabled') { $stateByKey[$key] = $state }
    }

    $row = [System.Collections.Generic.List[object]]::new()

    foreach ($record in @($recipient)) {
        if (-not [bool](Get-BaselineGraphMemberValue -Node $record -Name 'LicensingRequired')) { continue }

        $upn = [string](Get-BaselineGraphMemberValue -Node $record -Name 'UserPrincipalName')
        $recipientProfile = [string](Get-BaselineGraphMemberValue -Node $record -Name 'Profile')

        foreach ($definitionEntry in $definition) {
            if ($recipientProfile -notin $definitionEntry.ApplicableProfile) { continue }

            # A control that needs no service plan still owes the target a row, because a pair that
            # is simply absent from the matrix cannot be told from a pair nobody evaluated.
            if ($definitionEntry.Requirement.Count -eq 0) {
                $row.Add([pscustomobject]@{
                        UserPrincipalName       = $upn
                        Profile                 = $recipientProfile
                        ControlId               = $definitionEntry.ControlId
                        RequiredServicePlanId   = ''
                        RequiredServicePlanName = ''
                        AssignedState           = 'NotRequired'
                        Entitled                = $true
                        Reason                  = "'$upn' is entitled to '$($definitionEntry.ControlId)' because the control requires no service plan."
                    })

                continue
            }

            foreach ($requirement in $definitionEntry.Requirement) {
                $key = '{0}|{1}' -f $upn.ToLowerInvariant(), $requirement.ServicePlanId
                if (-not $stateByKey.ContainsKey($key)) {
                    throw "EntitlementIncomplete: '$upn' has no recorded assignment for the service plan '$($requirement.ServicePlanName)' ($($requirement.ServicePlanId)) that '$($definitionEntry.ControlId)' requires, so the row would read entitled only because nobody looked."
                }

                $state = $stateByKey[$key]
                $entitled = ($state -eq 'Enabled')
                $verb = if ($entitled) { 'is entitled to' } else { 'is not entitled to' }

                $row.Add([pscustomobject]@{
                        UserPrincipalName       = $upn
                        Profile                 = $recipientProfile
                        ControlId               = $definitionEntry.ControlId
                        RequiredServicePlanId   = $requirement.ServicePlanId
                        RequiredServicePlanName = $requirement.ServicePlanName
                        AssignedState           = $state
                        Entitled                = $entitled
                        Reason                  = "'$upn' $verb '$($definitionEntry.ControlId)' because the required service plan '$($requirement.ServicePlanName)' ($($requirement.ServicePlanId)) is $state."
                    })
            }
        }
    }

    $gap = @($row | Where-Object { -not $_.Entitled })

    return [pscustomobject]@{
        Source   = 'BaselineLicensingMatrix'
        Row      = @($row)
        Gap      = @($gap)
        Complete = ($gap.Count -eq 0)
    }
}

# LIC-009: the Safe Documents preflight. The tenant verdict alone is not a licence to apply the
# capability, because a tenant-wide SAFEDOCS plan says nothing about whether every targeted user
# holds one. Coverage is decided here, per target, on the declared SAFEDOCS identifier alone, and
# any disagreement between the tenant and its targets fails rather than applies.
function Test-BaselineSafeDocumentsPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Configuration,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Entitlement,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$TargetPopulation,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$TargetEntitlement
    )

    if ($null -eq $Configuration) {
        throw 'ConfigurationRequired: without the baseline nothing declares the service-plan identifier Safe Documents is decided on.'
    }

    $declared = @(Get-BaselineConfigValue -Configuration $Configuration -Path 'licensing.requiredServicePlans' -Default @())
    if ($declared.Count -eq 0) {
        throw 'LicensingRequirementMissing: the baseline declares no licensing.requiredServicePlans, and an empty requirement set cannot be told from a tenant that holds everything.'
    }

    $planName = $script:BaselineCapabilityServicePlanName['SafeDocuments']
    $declaration = @($declared | Where-Object { [string](Get-BaselineGraphMemberValue -Node $_ -Name 'servicePlanName') -eq $planName })
    if ($declaration.Count -eq 0) {
        throw "SafeDocumentsServicePlanUndeclared: the baseline declares no service plan named '$planName', and a requirement nobody declared cannot have been checked against the tenant."
    }

    $planId = [string](Get-BaselineGraphMemberValue -Node $declaration[0] -Name 'servicePlanId')
    if ([string]::IsNullOrWhiteSpace($planId)) {
        throw "RequiredServicePlanContractViolation: the '$planName' requirement does not declare 'servicePlanId', and assignedPlans carries no service-plan name to match on instead."
    }

    $planId = $planId.ToLowerInvariant()

    if ($null -eq $Entitlement) {
        throw 'EntitlementRequired: a tenant Safe Documents verdict that was never collected must never be assumed.'
    }

    $capability = Get-BaselineGraphMemberValue -Node $Entitlement -Name 'Capability'
    $verdict = @(@($capability) | Where-Object { [string](Get-BaselineGraphMemberValue -Node $_ -Name 'Name') -eq 'SafeDocuments' })
    if ($verdict.Count -ne 1) {
        throw "SafeDocumentsCapabilityMissing: the entitlement carries no single Safe Documents capability verdict, and an entitlement silent about Safe Documents is not one that cleared it."
    }

    $tenantEntitled = [bool](Get-BaselineGraphMemberValue -Node $verdict[0] -Name 'Entitled')

    if ($null -eq $TargetPopulation) {
        throw 'TargetPopulationRequired: a preflight run over nobody reports every target covered.'
    }

    $recipient = Get-BaselineGraphMemberValue -Node $TargetPopulation -Name 'Recipient'
    if ($null -eq $recipient -or $recipient -isnot [System.Collections.IList]) {
        throw "TargetPopulationContractViolation: the target population does not declare a 'Recipient' collection, and only a classified population carries the licensing decision each row is scoped by."
    }

    if ($null -eq $TargetEntitlement) {
        throw 'TargetEntitlementRequired: without the per-user verdicts the preflight has no target state to report.'
    }

    $assignment = Get-BaselineGraphMemberValue -Node $TargetEntitlement -Name 'Assignment'
    if ($null -eq $assignment -or $assignment -isnot [System.Collections.IList]) {
        throw "TargetEntitlementContractViolation: the target entitlement does not declare an 'Assignment' collection, and a summary verdict is not the per-user evidence a target row is built from."
    }

    # Only the declared SAFEDOCS identifier decides a target. A bundle carrying the same display
    # name under another identifier is a different plan and grants Safe Documents to nobody.
    $stateByUser = @{}
    foreach ($record in @($assignment)) {
        if (([string](Get-BaselineGraphMemberValue -Node $record -Name 'ServicePlanId')).ToLowerInvariant() -ne $planId) { continue }

        $state = [string](Get-BaselineGraphMemberValue -Node $record -Name 'State')
        $assignedTo = ([string](Get-BaselineGraphMemberValue -Node $record -Name 'UserPrincipalName')).ToLowerInvariant()

        # A plan granted by one licence is not taken away by a dormant duplicate of the same plan.
        if (-not $stateByUser.ContainsKey($assignedTo) -or $state -eq 'Enabled') { $stateByUser[$assignedTo] = $state }
    }

    $target = [System.Collections.Generic.List[object]]::new()

    foreach ($record in @($recipient)) {
        # A resource mailbox holds no per-user licence, so demanding one would fail the gate on a
        # fact that is not a finding.
        if (-not [bool](Get-BaselineGraphMemberValue -Node $record -Name 'LicensingRequired')) { continue }

        $upn = [string](Get-BaselineGraphMemberValue -Node $record -Name 'UserPrincipalName')
        $key = $upn.ToLowerInvariant()
        if (-not $stateByUser.ContainsKey($key)) {
            throw "TargetEntitlementIncomplete: '$upn' has no recorded assignment for the service plan '$planName' ($planId), so the target would read covered only because nobody looked."
        }

        $state = $stateByUser[$key]
        $entitled = ($state -eq 'Enabled')
        $verb = if ($entitled) { 'holds' } else { 'does not hold' }

        $target.Add([pscustomobject]@{
                UserPrincipalName = $upn
                ServicePlanId     = $planId
                ServicePlanName   = $planName
                State             = $state
                Entitled          = $entitled
                Reason            = "'$upn' $verb an enabled '$planName' ($planId) service plan; the recorded state is $state."
            })
    }

    if ($target.Count -eq 0) {
        throw 'LicensingTargetRequired: a preflight with nobody to cover would clear Safe Documents vacuously.'
    }

    $gap = @($target | Where-Object { -not $_.Entitled })

    # Safe Documents is applied only on complete coverage. Uniform absence is a capability the
    # tenant simply does not have; any disagreement between the tenant and its targets is a
    # licensing mismatch that must fail the preflight rather than be applied over.
    if ($tenantEntitled -and $gap.Count -eq 0) {
        $status = 'Pass'
        $reason = "Safe Documents may be applied: the tenant holds an enabled '$planName' ($planId) plan and all $($target.Count) licensing targets hold it enabled."
    }
    elseif (-not $tenantEntitled -and $gap.Count -eq $target.Count) {
        $status = 'NotEntitled'
        $reason = "Safe Documents is not applied: neither the tenant nor any of the $($target.Count) licensing targets holds an enabled '$planName' ($planId) plan."
    }
    else {
        $status = 'Fail'
        $reason = "Safe Documents preflight failed: the tenant '$planName' ($planId) verdict is $tenantEntitled while $($gap.Count) of $($target.Count) licensing targets do not hold the plan enabled."
    }

    return [pscustomobject]@{
        Source                  = 'BaselineSafeDocumentsPreflight'
        RequiredServicePlanName = $planName
        RequiredServicePlanId   = $planId
        TenantEntitled          = $tenantEntitled
        Target                  = @($target)
        Gap                     = $gap
        Status                  = $status
        MayApply                = ($status -eq 'Pass')
        Reason                  = $reason
    }
}

# LIC-004: discovery across a set of Graph resources. One resource that cannot be read is recorded
# as a partial failure so the rest of the inventory survives, but the discovery is never reported
# complete while any resource is missing, because an incomplete inventory read as a complete one
# understates what the tenant holds.
function Get-BaselineGraphDiscovery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Resource,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Transport,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Wait,

        [int]$MaximumAttempt = 4,

        [int]$MaximumPage = 200
    )

    if ($null -eq $Transport) {
        throw 'GraphTransportRequired: a discovery is issued through an injected transport, so one must be supplied.'
    }

    if ($null -eq $Wait) {
        throw 'RetryWaitRequired: retry needs a clock, and the clock is injected before any resource is read.'
    }

    if ($MaximumAttempt -lt 1) {
        throw "MaximumAttemptOutOfRange: '$MaximumAttempt' would never attempt a resource, and a resource that is never attempted has not answered."
    }

    $requested = @($Resource)
    if ($requested.Count -eq 0) {
        throw 'GraphResourceRequired: a discovery that reads nothing is not a complete inventory, so at least one resource must be supplied.'
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $requested) {
        if ([string]::IsNullOrWhiteSpace($entry)) {
            throw 'GraphResourceRequired: a blank resource addresses nothing and cannot be read.'
        }

        if (-not $seen.Add($entry)) {
            throw "GraphResourceDuplicated: '$entry' was requested more than once, which would double its items and make the result depend on the request order."
        }
    }

    $succeeded = [System.Collections.Generic.List[object]]::new()
    $failed = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $requested) {
        try {
            $succeeded.Add((Invoke-BaselineGraphRequest -Resource $entry -Transport $Transport -Wait $Wait -MaximumAttempt $MaximumAttempt -MaximumPage $MaximumPage))
        }
        catch {
            $reason = [string]$_.Exception.Message

            foreach ($fatal in $script:GraphFatalDiscoveryReason) {
                if ($reason.StartsWith($fatal, [System.StringComparison]::Ordinal)) { throw }
            }

            $failed.Add([pscustomobject]@{
                    Resource = $entry
                    Reason   = $reason
                })
        }
    }

    return [pscustomobject]@{
        Requested = @($requested)
        Succeeded = @($succeeded)
        Failed    = @($failed)
        Complete  = ($failed.Count -eq 0)
    }
}

# The service's own Retry-After is preferred, but only when it is a usable delay. A missing,
# non-numeric or non-positive value falls back to bounded exponential backoff, and any delay is
# capped, because a day-long Retry-After would stall a deployment rather than pace it.
function Get-BaselineGraphRetryDelay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Response,

        [Parameter(Mandatory)]
        [int]$Attempt
    )

    $delay = [int][Math]::Pow(2, $Attempt - 1)

    $requested = Get-BaselineGraphMemberValue -Node $Response -Name 'retryAfterSeconds'
    if ($null -ne $requested) {
        $parsed = 0
        if ([int]::TryParse([string]$requested, [ref]$parsed) -and $parsed -gt 0) { $delay = $parsed }
    }

    return [Math]::Min($delay, $script:GraphMaximumRetryDelaySecond)
}

# Graph responses arrive as objects or as dictionaries depending on the caller's serializer, and
# Set-StrictMode makes an absent member fatal, so member access is funnelled through one reader.
# An absent member and a null member are the same thing here: neither can be judged.
function Get-BaselineGraphMemberValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Node,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Node) { return $null }

    # The comma operator keeps a collection-valued member whole; a bare return would unroll it and
    # a single-element list would arrive at the caller as a scalar.
    if ($Node -is [System.Collections.IDictionary]) {
        if ($Node.Contains($Name)) { return , $Node[$Name] }
        return $null
    }

    if ($Node.PSObject.Properties.Match($Name).Count -gt 0) { return , $Node.$Name }

    return $null
}

function ConvertTo-CanonicalNode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Node,

        [Parameter(Mandatory)]
        [int]$Depth,

        [Parameter(Mandatory)]
        [int]$Level
    )

    if ($null -eq $Node) {
        return $null
    }

    if ($Node -is [string] -or $Node -is [bool] -or $Node -is [decimal] -or $Node.GetType().IsPrimitive) {
        return $Node
    }

    if ($Level -ge $Depth) {
        throw "CanonicalDepthExceeded: the document nests deeper than the supported depth of $Depth."
    }

    if ($Node -is [System.Collections.IDictionary]) {
        $names = [string[]]@($Node.Keys)
        [System.Array]::Sort($names, [System.StringComparer]::Ordinal)

        $canonical = [ordered]@{}
        foreach ($name in $names) {
            $canonical[$name] = ConvertTo-CanonicalNode -Node $Node[$name] -Depth $Depth -Level ($Level + 1)
        }

        return $canonical
    }

    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        $properties = @($Node.PSObject.Properties)
        $names = [string[]]@($properties.Name)
        [System.Array]::Sort($names, [System.StringComparer]::Ordinal)

        $canonical = [ordered]@{}
        foreach ($name in $names) {
            $canonical[$name] = ConvertTo-CanonicalNode -Node $Node.PSObject.Properties[$name].Value -Depth $Depth -Level ($Level + 1)
        }

        return $canonical
    }

    if ($Node -is [System.Collections.IList]) {
        return , @(foreach ($item in $Node) { ConvertTo-CanonicalNode -Node $item -Depth $Depth -Level ($Level + 1) })
    }

    throw "UnsupportedCanonicalValue: a value of type '$($Node.GetType().FullName)' cannot be canonicalized."
}

# COM-004: one deterministic text for one document. Members are ordered by ordinal name, arrays
# keep their order because order is data, and the text carries no whitespace, line break or BOM.
function ConvertTo-CanonicalJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$InputObject,

        [ValidateRange(1, 256)]
        [int]$Depth = 64
    )

    if ($null -eq $InputObject) {
        throw 'CanonicalInputNotProvided: a document is required to produce a canonical text.'
    }

    $canonical = ConvertTo-CanonicalNode -Node $InputObject -Depth $Depth -Level 0

    # An empty list leaves the pipeline empty, and ConvertTo-Json then emits nothing at all; a
    # canonical text that vanishes cannot be hashed, so the empty array is written out directly.
    if ($canonical -is [System.Collections.IList] -and $canonical.Count -eq 0) {
        return '[]'
    }

    return ($canonical | ConvertTo-Json -Depth $Depth -Compress)
}

# COM-004: a read-only projection of the resolved document. Every dictionary and every list is
# wrapped, so no caller can alter a configuration after it has been hashed. The comma operator
# stops PowerShell unrolling the read-only collection back into a mutable array.
function ConvertTo-ImmutableBaselineNode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Node
    )

    if ($null -eq $Node -or $Node -is [string]) {
        return , $Node
    }

    if ($Node -is [System.Collections.IDictionary]) {
        $members = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
        foreach ($key in $Node.Keys) {
            $members[[string]$key] = ConvertTo-ImmutableBaselineNode -Node $Node[$key]
        }

        return , ([System.Collections.ObjectModel.ReadOnlyDictionary[string, object]]::new($members))
    }

    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        $members = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
        foreach ($property in $Node.PSObject.Properties) {
            $members[$property.Name] = ConvertTo-ImmutableBaselineNode -Node $property.Value
        }

        return , ([System.Collections.ObjectModel.ReadOnlyDictionary[string, object]]::new($members))
    }

    if ($Node -is [System.Collections.IList]) {
        return , ([System.Array]::AsReadOnly([object[]]@(foreach ($item in $Node) { ConvertTo-ImmutableBaselineNode -Node $item })))
    }

    return , $Node
}

# COM-004: the identity of a resolved configuration. The hash covers the canonical text of the
# configuration only, so the resolution envelope can change without moving the identity.
function Get-BaselineConfigurationHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Resolution
    )

    if ($null -eq $Resolution -or
        $Resolution.PSObject.Properties.Match('Configuration').Count -eq 0 -or
        $null -eq $Resolution.Configuration) {
        throw 'ResolutionNotRecognized: the supplied resolution does not carry a configuration; pass the output of Resolve-BaselineConfiguration.'
    }

    $canonicalJson = ConvertTo-CanonicalJson -InputObject $Resolution.Configuration
    $canonicalBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($canonicalJson)

    return [pscustomobject]@{
        Algorithm     = 'SHA256'
        Hash          = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($canonicalBytes)).ToLowerInvariant()
        CanonicalJson = $canonicalJson
        Configuration = (ConvertTo-ImmutableBaselineNode -Node $Resolution.Configuration)
    }
}

function ConvertTo-NormalizedCanonicalValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory)]
        [string[]]$Rule,

        [scriptblock]$Resolver
    )

    if ($Value -isnot [string]) {
        throw "NonStringCollectionMember: a canonical collection may contain only strings, but a member of type '$(if ($null -eq $Value) { 'null' } else { $Value.GetType().FullName })' was supplied."
    }

    $normalized = [string]$Value

    foreach ($name in $Rule) {
        switch ($name) {
            'Trim' { $normalized = $normalized.Trim() }
            'RemoveSmtpPrefix' { $normalized = [regex]::Replace($normalized, '^(?i)smtp:', '') }
            'RemoveTrailingDot' { $normalized = $normalized.TrimEnd('.') }
            'LowerInvariant' { $normalized = $normalized.ToLowerInvariant() }
            'ExpandCidr' {
                if ($normalized -notmatch '/') {
                    $address = [System.Net.IPAddress]::None
                    if ([System.Net.IPAddress]::TryParse($normalized, [ref]$address)) {
                        $prefix = if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { 128 } else { 32 }
                        $normalized = '{0}/{1}' -f $normalized, $prefix
                    }
                }
            }
            'NormalizeIPv6' {
                $part = $normalized -split '/', 2
                $address = [System.Net.IPAddress]::None
                if ([System.Net.IPAddress]::TryParse($part[0], [ref]$address)) {
                    $normalized = if ($part.Count -eq 2) { '{0}/{1}' -f $address.ToString(), $part[1] } else { $address.ToString() }
                }
            }
            { $_ -in @('ResolveToPrimarySmtpAddress', 'ResolveToImmutableIdentifier') } {
                $resolved = & $Resolver $normalized
                if ($resolved -isnot [string]) {
                    throw "UnresolvedCanonicalValue: the resolver did not return a string for '$normalized'."
                }

                $normalized = $resolved
            }
            'RemoveEmptyEntry' { }
            'RemoveDuplicate' { }
            default { throw "UnknownNormalizationRule: the comparison contract declares rule '$name', which is not implemented." }
        }
    }

    return $normalized
}

# DES-002: normalized set equality. Formatting never reads as drift, and drift never reads as
# agreement, because both sides are normalized by the same contract rules before comparison.
function Compare-NormalizedCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Desired,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Actual,

        [Parameter(Mandatory)]
        [string]$Kind,

        [scriptblock]$Resolver
    )

    $contract = Get-CanonicalComparisonContract
    $declared = @($contract.Kind | Where-Object { $_.Kind -eq $Kind })
    if ($declared.Count -ne 1) {
        throw "UnknownCanonicalKind: '$Kind' is not declared by the canonical comparison contract."
    }

    if ($null -eq $Desired -or $null -eq $Actual) {
        throw 'CollectionNotProvided: both a desired and an actual collection are required; a null collection is never treated as empty.'
    }

    $rule = @($declared[0].NormalizationRule)

    if (@($rule | Where-Object { $_ -like 'ResolveTo*' }).Count -gt 0 -and -not $PSBoundParameters.ContainsKey('Resolver')) {
        throw "ResolverRequired: canonical kind '$Kind' resolves its members, so a resolver is required."
    }

    $normalize = {
        param($Collection)

        $values = @(foreach ($item in $Collection) { ConvertTo-NormalizedCanonicalValue -Value $item -Rule $rule -Resolver $Resolver })

        if ($rule -contains 'RemoveEmptyEntry') {
            $values = @($values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }

        if ($rule -contains 'RemoveDuplicate') {
            $values = @($values | Select-Object -Unique)
        }

        return , @($values | Sort-Object -CaseSensitive)
    }

    $normalizedDesired = & $normalize $Desired
    $normalizedActual = & $normalize $Actual

    $missing = @($normalizedDesired | Where-Object { $_ -cnotin $normalizedActual })
    $surplus = @($normalizedActual | Where-Object { $_ -cnotin $normalizedDesired })

    return [pscustomobject]@{
        Kind              = $Kind
        Equal             = ($missing.Count -eq 0 -and $surplus.Count -eq 0)
        NormalizedDesired = $normalizedDesired
        NormalizedActual  = $normalizedActual
        Missing           = $missing
        Surplus           = $surplus
    }
}

# DES-003: profile, tenant service plans and catalog priority decide applicability, and the
# runtime tenant inventory is the only entitlement authority. Declared licensing metadata in the
# baseline is planning information and is never read here.
function Get-ControlApplicability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Control,

        [Parameter(Mandatory)]
        [string]$DeploymentProfile,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$TenantServicePlan,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$PriorityInScope
    )

    if ($null -eq $Control) {
        throw 'ControlNotProvided: a catalog control is required to decide applicability.'
    }

    foreach ($member in @('Id', 'DeploymentProfile', 'RequiredServicePlan', 'Priority')) {
        if ($Control.PSObject.Properties.Match($member).Count -eq 0) {
            throw "ControlContractViolation: the catalog control does not declare '$member'."
        }
    }

    if ($DeploymentProfile -notin $script:DeploymentProfileName) {
        throw "UnknownDeploymentProfile: '$DeploymentProfile' is not a declared deployment profile."
    }

    if ($null -eq $TenantServicePlan) {
        throw 'ServicePlanInventoryRequired: entitlement is decided by the tenant, so a service-plan inventory is required.'
    }

    $inProfile = $DeploymentProfile -in @($Control.DeploymentProfile)
    $inPriorityScope = [string]$Control.Priority -in @($PriorityInScope)

    if (-not $inProfile -or -not $inPriorityScope) {
        $reason = if (-not $inProfile) {
            "the control does not apply to deployment profile '$DeploymentProfile'"
        }
        else {
            "priority '$($Control.Priority)' is outside the priorities in scope"
        }

        return [pscustomobject]@{
            ControlId          = [string]$Control.Id
            Applicable         = $false
            Entitled           = $false
            Status             = 'NotApplicable'
            MissingServicePlan = @()
            Reason             = $reason
        }
    }

    $missingServicePlan = @(@($Control.RequiredServicePlan) | Where-Object { $_ -notin $TenantServicePlan } | Sort-Object)

    if ($missingServicePlan.Count -gt 0) {
        return [pscustomobject]@{
            ControlId          = [string]$Control.Id
            Applicable         = $true
            Entitled           = $false
            Status             = 'NotEntitled'
            MissingServicePlan = $missingServicePlan
            Reason             = "the tenant does not grant '$($missingServicePlan -join "', '")'"
        }
    }

    return [pscustomobject]@{
        ControlId          = [string]$Control.Id
        Applicable         = $true
        Entitled           = $true
        Status             = 'Applicable'
        MissingServicePlan = @()
        Reason             = "the control applies to deployment profile '$DeploymentProfile' and the tenant grants every required service plan"
    }
}

# GATE-002: the published schema an exception is held to before any semantic check reads it. A
# document the schema refuses is refused as the wrong shape, rather than read as an acceptance
# that happens to declare nothing - an absent member and a member the reader never looked for are
# indistinguishable once the document is being interpreted rather than validated.
$script:RiskAcceptanceSchemaPath = Join-Path $PSScriptRoot '..' 'config' 'risk-acceptance.schema.json'

function Test-RiskAcceptanceDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$RiskAcceptance,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$SchemaPath
    )

    if ($null -eq $RiskAcceptance) {
        throw 'RiskAcceptanceNotProvided: a risk acceptance is required.'
    }

    if ($RiskAcceptance -is [string] -or $RiskAcceptance -is [System.Collections.IList] -or $RiskAcceptance.GetType().IsPrimitive) {
        throw "RiskAcceptanceNotAnObject: a risk acceptance must be an object, but a value of type '$($RiskAcceptance.GetType().FullName)' was supplied."
    }

    if ([string]::IsNullOrWhiteSpace($SchemaPath)) {
        throw 'RiskAcceptanceSchemaPathRequired: an exception measured against no schema is an exception nobody reviewed.'
    }

    if (-not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) {
        throw "RiskAcceptanceSchemaNotFound: no risk acceptance schema exists at '$SchemaPath'."
    }

    try {
        $null = Get-Content -LiteralPath $SchemaPath -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "RiskAcceptanceSchemaJsonInvalid: '$SchemaPath' is not valid JSON. $($_.Exception.Message)"
    }

    # A schema that cannot be applied is a fault in this repository, not a fault in the document
    # somebody submitted, so it is thrown rather than reported as a non-conforming acceptance.
    $violation = [System.Collections.Generic.List[string]]::new()
    try {
        $null = Test-Json -Json ($RiskAcceptance | ConvertTo-Json -Depth 20) -SchemaFile $SchemaPath -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -like '*parse the JSON schema*') {
            throw "RiskAcceptanceSchemaNotUsable: '$SchemaPath' is not a usable JSON Schema. $($_.Exception.Message)"
        }

        $violation.Add([string]$_.Exception.Message)
    }

    return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                Conforms   = ($violation.Count -eq 0)
                SchemaPath = (Resolve-Path -LiteralPath $SchemaPath).ProviderPath
                Violation  = @($violation)
            }))
}

# GATE-002 field set, DES-005 authority and signature model. Every check fails closed: an
# incomplete, misbound, unapproved, out-of-window or unsigned acceptance is simply not valid.
function Test-RiskAcceptance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$RiskAcceptance,

        [Parameter(Mandatory)]
        [string]$ControlId,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$ConfigurationHash,

        [Parameter(Mandatory)]
        [string]$RequestedBy,

        [Parameter(Mandatory)]
        [datetime]$AsOf,

        [AllowEmptyString()]
        [string]$DeploymentProfile,

        [AllowEmptyString()]
        [string]$BaselineVersion
    )

    if ($null -eq $RiskAcceptance) {
        throw 'RiskAcceptanceNotProvided: a risk acceptance is required.'
    }

    if ($RiskAcceptance -is [string] -or $RiskAcceptance -is [System.Collections.IList] -or $RiskAcceptance.GetType().IsPrimitive) {
        throw "RiskAcceptanceNotAnObject: a risk acceptance must be an object, but a value of type '$($RiskAcceptance.GetType().FullName)' was supplied."
    }

    $reject = {
        param($Reason)

        return [pscustomobject]@{
            ControlId = $ControlId
            Valid     = $false
            Status    = 'Fail'
            Reason    = $Reason
        }
    }

    $isEmpty = {
        param($Value)

        if ($null -eq $Value) { return $true }
        if ($Value -is [string]) { return [string]::IsNullOrWhiteSpace($Value) }
        if ($Value -is [System.Collections.IList]) { return @($Value).Count -eq 0 }

        return $false
    }

    foreach ($member in $script:RiskAcceptanceRequiredMember) {
        if ($RiskAcceptance.PSObject.Properties.Match($member).Count -eq 0 -or (& $isEmpty $RiskAcceptance.$member)) {
            return & $reject ("IncompleteRiskAcceptance: the risk acceptance does not declare '$member'.")
        }
    }

    $document = Test-RiskAcceptanceDocument -RiskAcceptance $RiskAcceptance -SchemaPath $script:RiskAcceptanceSchemaPath
    if (-not $document.Conforms) {
        return & $reject ("RiskAcceptanceSchemaViolation: the risk acceptance does not conform to '$($document.SchemaPath)'. $(@($document.Violation) -join ' ')")
    }

    if ([string]$RiskAcceptance.ControlId -ne $ControlId) {
        return & $reject "ControlMismatch: the risk acceptance is raised for '$($RiskAcceptance.ControlId)', not '$ControlId'."
    }

    if ([string]$RiskAcceptance.TenantId -ne $TenantId) {
        return & $reject "TenantMismatch: the risk acceptance is raised for another tenant."
    }

    # An acceptance may be pinned to one resolved configuration by hash, or to a stated finite
    # applicability instead. The schema guarantees one of the two is present. Where a hash is
    # stated it is the tighter binding and is decided first, so a matching applicability can
    # never excuse a hash raised against another configuration.
    if ($RiskAcceptance.PSObject.Properties.Match('ConfigurationHash').Count -gt 0 -and -not (& $isEmpty $RiskAcceptance.ConfigurationHash)) {
        if ([string]$RiskAcceptance.ConfigurationHash -ne $ConfigurationHash) {
            return & $reject "ConfigurationHashMismatch: the risk acceptance is bound to configuration '$($RiskAcceptance.ConfigurationHash)', but this run resolved '$ConfigurationHash'."
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($DeploymentProfile) -or [string]::IsNullOrWhiteSpace($BaselineVersion)) {
            return & $reject 'ApplicabilityRunContextRequired: the risk acceptance is bound by applicability, but this run states no deployment profile and baseline version to measure it against.'
        }

        $appliesTo = $RiskAcceptance.AppliesTo

        if ([string]$appliesTo.DeploymentProfile -ne $DeploymentProfile) {
            return & $reject "ApplicabilityProfileMismatch: the risk acceptance is bounded to deployment profile '$($appliesTo.DeploymentProfile)', but this run is '$DeploymentProfile'."
        }

        if ([string]$appliesTo.BaselineVersion -ne $BaselineVersion) {
            return & $reject "ApplicabilityBaselineMismatch: the risk acceptance is bounded to baseline version '$($appliesTo.BaselineVersion)', but this run is '$BaselineVersion'."
        }
    }

    if ([string]$RiskAcceptance.ApprovalAuthority -ne $script:RiskAcceptanceAuthority) {
        return & $reject "ApprovalAuthorityNotApproved: '$($RiskAcceptance.ApprovalAuthority)' does not hold the '$($script:RiskAcceptanceAuthority)' role."
    }

    if ([string]$RiskAcceptance.ApprovalIdentity -eq $RequestedBy) {
        return & $reject 'SelfApproved: the approver and the operator requesting the change are the same identity.'
    }

    if ($AsOf -lt $RiskAcceptance.EffectiveTimeUtc) {
        return & $reject 'NotYetEffective: the risk acceptance is not effective at the evaluation time.'
    }

    if ($AsOf -ge $RiskAcceptance.ExpiryTimeUtc) {
        return & $reject 'Expired: the risk acceptance has expired at the evaluation time.'
    }

    $signature = $RiskAcceptance.Signature
    foreach ($member in @('Model', 'Value')) {
        if ($signature.PSObject.Properties.Match($member).Count -eq 0 -or (& $isEmpty $signature.$member)) {
            return & $reject "SignatureIncomplete: the signature does not declare '$member'."
        }
    }

    $selectedModel = @((Get-ApprovalSignatureContract).SelectedModel)
    if ([string]$signature.Model -notin $selectedModel) {
        return & $reject "SignatureModelNotApproved: '$($signature.Model)' is not the selected approval signature model."
    }

    return [pscustomobject]@{
        ControlId = $ControlId
        Valid     = $true
        Status    = 'ApprovedException'
        Reason    = "The risk acceptance is complete, bound to this control, tenant and configuration, independently approved and in force until $($RiskAcceptance.ExpiryTimeUtc.ToString('o'))."
    }
}

# DES-001: the only vocabulary a control evaluation may speak. A status outside the contract is
# refused outright, a non-normalized status can never admit go-live, and the recorded result is
# immutable so a later stage cannot rewrite a verdict.
function New-ControlResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ControlId,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Status,

        [string]$Reason,

        [AllowNull()]
        [object]$Evidence,

        [datetime]$EvaluatedAtUtc = [datetime]::UtcNow
    )

    if ([string]::IsNullOrWhiteSpace($ControlId)) {
        throw 'ControlIdRequired: a control result must name the control it describes.'
    }

    if ([string]::IsNullOrWhiteSpace($Status)) {
        throw 'StatusRequired: a control result must carry a status.'
    }

    $contract = Get-BaselineResultContract
    $declaredStatus = @($contract.NormalizedStatus) + @($contract.NonNormalizedStatus)

    if ($Status -cnotin $declaredStatus) {
        throw "UnknownControlStatus: '$Status' is not declared by the result contract."
    }

    if ($Status -cne 'Pass' -and [string]::IsNullOrWhiteSpace($Reason)) {
        throw "ReasonRequired: a '$Status' result must record why the control did not simply pass."
    }

    $member = [ordered]@{
        ControlId      = $ControlId
        Status         = $Status
        Normalized     = ($Status -cin @($contract.NormalizedStatus))
        GoLiveSuccess  = ($Status -cin @($contract.GoLiveSuccessStatus))
        Reason         = $Reason
        Evidence       = $Evidence
        EvaluatedAtUtc = $EvaluatedAtUtc
    }

    return , (ConvertTo-ImmutableBaselineNode -Node $member)
}

# DES-001: the only statuses a control result may normalize to, the statuses that can never
# normalize, and the normalized statuses that permit a successful go-live.
function Get-BaselineResultContract {
    [CmdletBinding()]
    param()

    return [pscustomobject]@{
        NormalizedStatus    = @('Pass', 'Fail', 'ApprovedException', 'NotApplicable', 'Error')
        NonNormalizedStatus = @('Manual', 'NotEntitled', 'Unverified')
        GoLiveSuccessStatus = @('Pass', 'ApprovedException', 'NotApplicable')
    }
}

# DES-002: how every desired-state value is normalized before comparison, and how collections
# of those values are judged equal.
function Get-CanonicalComparisonContract {
    [CmdletBinding()]
    param()

    return [pscustomobject]@{
        CollectionEquality = 'NormalizedSetEquality'
        Kind               = @(
            [pscustomobject]@{
                Kind              = 'SmtpAddress'
                Ordered           = $false
                CaseInsensitive   = $true
                NormalizationRule = @('Trim', 'RemoveSmtpPrefix', 'LowerInvariant', 'RemoveEmptyEntry', 'RemoveDuplicate')
            }
            [pscustomobject]@{
                Kind              = 'Domain'
                Ordered           = $false
                CaseInsensitive   = $true
                NormalizationRule = @('Trim', 'RemoveTrailingDot', 'LowerInvariant', 'RemoveEmptyEntry', 'RemoveDuplicate')
            }
            [pscustomobject]@{
                Kind              = 'Group'
                Ordered           = $false
                CaseInsensitive   = $true
                NormalizationRule = @('Trim', 'ResolveToPrimarySmtpAddress', 'LowerInvariant', 'RemoveEmptyEntry', 'RemoveDuplicate')
            }
            [pscustomobject]@{
                Kind              = 'IpAddress'
                Ordered           = $false
                CaseInsensitive   = $true
                NormalizationRule = @('Trim', 'ExpandCidr', 'NormalizeIPv6', 'RemoveEmptyEntry', 'RemoveDuplicate')
            }
            [pscustomobject]@{
                Kind              = 'Identity'
                Ordered           = $false
                CaseInsensitive   = $true
                NormalizationRule = @('Trim', 'ResolveToImmutableIdentifier', 'LowerInvariant', 'RemoveEmptyEntry', 'RemoveDuplicate')
            }
        )
    }
}

# DES-003: the inputs that decide whether a control applies, and which entitlement source wins
# when the tenant contradicts the declared licensing metadata. Lower Precedence wins.
function Get-ApplicabilityAuthorityContract {
    [CmdletBinding()]
    param()

    return [pscustomobject]@{
        ApplicabilityInput = @('DeploymentProfile', 'ActualServicePlan', 'CatalogControlPriority')
        ConflictResolution = 'RuntimeGraphWins'
        Authority          = @(
            [pscustomobject]@{
                Source        = 'RuntimeGraphServicePlan'
                Precedence    = 1
                Authoritative = $true
            }
            [pscustomobject]@{
                Source        = 'DeclaredLicensingMetadata'
                Precedence    = 2
                Authoritative = $false
            }
        )
    }
}

# DES-004: each artifact carries its own schema version so an artifact can evolve without
# forcing a baseline version change. VersionSource records where that version comes from.
function Get-ArtifactVersionContract {
    [CmdletBinding()]
    param()

    return [pscustomobject]@{
        BaselineVersion = '1.0.0'
        Artifact        = @(
            [pscustomobject]@{
                Artifact      = 'Configuration'
                SchemaVersion = '1.0.0'
                VersionSource = 'ArtifactSchema'
            }
            [pscustomobject]@{
                Artifact      = 'Evidence'
                SchemaVersion = '1.0.0'
                VersionSource = 'ArtifactSchema'
            }
            [pscustomobject]@{
                Artifact      = 'Preview'
                SchemaVersion = '1.0.0'
                VersionSource = 'ArtifactSchema'
            }
            [pscustomobject]@{
                Artifact      = 'Approval'
                SchemaVersion = '1.0.0'
                VersionSource = 'ArtifactSchema'
            }
            [pscustomobject]@{
                Artifact      = 'Rollback'
                SchemaVersion = '1.0.0'
                VersionSource = 'ArtifactSchema'
            }
            [pscustomobject]@{
                Artifact      = 'Exception'
                SchemaVersion = '1.0.0'
                VersionSource = 'ArtifactSchema'
            }
        )
    }
}

# DES-005: exactly one approval signature model governs every preview approval and risk
# acceptance. Detached CMS is selected because it binds the signature to the approved artifact
# bytes without mutating them, and it verifies offline against an enterprise trust chain.
function Get-ApprovalSignatureContract {
    [CmdletBinding()]
    param()

    return [pscustomobject]@{
        SelectedModel = @('DetachedCms')
        ApprovedModel = @('DetachedCms', 'EnterpriseCertificate', 'ExternalTicketEvidence')
        Rule          = @(
            [pscustomobject]@{
                Category    = 'Authority'
                Requirement = 'The signer certificate subject must map to a named approver holding the Exchange Online change-approval role, and the approver must not be the operator requesting the change.'
            }
            [pscustomobject]@{
                Category    = 'Verification'
                Requirement = 'The detached CMS signature must verify against the canonical SHA-256 hash of the approved artifact and chain to the enterprise root, with the full chain validated offline.'
            }
            [pscustomobject]@{
                Category    = 'Expiry'
                Requirement = 'An approval is honoured only while the signing time is within the artifact validity window and the signer certificate is unexpired; an approval older than the declared maximum evidence age is rejected.'
            }
            [pscustomobject]@{
                Category    = 'Revocation'
                Requirement = 'Signer revocation status must be checked against the enterprise CRL or OCSP responder, and an unavailable or inconclusive revocation answer fails closed.'
            }
        )
    }
}

# SAFE-001: the six files a single change leaves behind, in the order the change makes them. Each
# one is named after the change it belongs to, so a second change cannot overwrite the evidence of
# the first, and none of them is optional: an artifact a run may skip is an artifact no audit can
# rely on. The rollback is the one artifact that has to execute, so it is the one that is not JSON.
function Get-BaselineChangeArtifactContract {
    [CmdletBinding()]
    param()

    return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                ChangeIdentifierPattern     = '^[A-Za-z0-9][A-Za-z0-9-]{0,63}\z'
                ChangeIdentifierPlaceholder = '<id>'
                Artifact                    = @(
                    [ordered]@{ Artifact = 'Preview'; FileNameTemplate = 'preview-<id>.json'; Format = 'Json'; Sequence = 1; Required = $true }
                    [ordered]@{ Artifact = 'Approval'; FileNameTemplate = 'approval-<id>.json'; Format = 'Json'; Sequence = 2; Required = $true }
                    [ordered]@{ Artifact = 'PreChange'; FileNameTemplate = 'prechange-<id>.json'; Format = 'Json'; Sequence = 3; Required = $true }
                    [ordered]@{ Artifact = 'Apply'; FileNameTemplate = 'apply-<id>.json'; Format = 'Json'; Sequence = 4; Required = $true }
                    [ordered]@{ Artifact = 'Rollback'; FileNameTemplate = 'rollback-<id>.ps1'; Format = 'PowerShell'; Sequence = 5; Required = $true }
                    [ordered]@{ Artifact = 'PostChange'; FileNameTemplate = 'postchange-<id>.json'; Format = 'Json'; Sequence = 6; Required = $true }
                )
            }))
}

# SAFE-001: the file names one change writes. The identifier is checked against the contract pattern
# before it is ever substituted into a file name, because a separator, a parent-directory segment or
# a drive qualifier that survives into the name is a write to wherever the caller pointed rather than
# to the change directory. The pattern is anchored with \z so a trailing newline cannot slip through.
function New-BaselineChangeArtifactSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ChangeId,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$Root
    )

    $contract = Get-BaselineChangeArtifactContract
    $pattern = [string]$contract.ChangeIdentifierPattern

    if ([string]::IsNullOrWhiteSpace($ChangeId) -or $ChangeId -cnotmatch $pattern) {
        throw "ChangeIdentifierNotRecognized: '$ChangeId' is not a change identifier; supply one matching $pattern."
    }

    $placeholder = [string]$contract.ChangeIdentifierPlaceholder
    $rooted = -not [string]::IsNullOrWhiteSpace($Root)

    $entries = foreach ($artifact in (@($contract.Artifact) | Sort-Object { [int]$_.Sequence })) {
        $fileName = ([string]$artifact.FileNameTemplate).Replace($placeholder, $ChangeId)

        [ordered]@{
            Artifact = [string]$artifact.Artifact
            FileName = $fileName
            Path     = if ($rooted) { Join-Path $Root $fileName } else { $fileName }
            Format   = [string]$artifact.Format
            Sequence = [int]$artifact.Sequence
        }
    }

    return , (ConvertTo-ImmutableBaselineNode -Node @($entries))
}

# SAFE-001: writing one artifact of a change to the place the set resolved for it. A JSON artifact
# is written as canonical text so two runs of the same change produce the same bytes and the same
# seal; the rollback is written exactly as it was handed over, because a script the writer
# reformatted is a script nobody reviewed. An artifact the change has already emitted is refused
# rather than replaced: a change that can rewrite its own preview is a change whose approved plan
# is whatever it last wrote.
function Write-BaselineChangeArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ChangeId,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Artifact,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Root,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Content
    )

    $declared = @((Get-BaselineChangeArtifactContract).Artifact | ForEach-Object { [string]$_.Artifact })
    if ([string]::IsNullOrWhiteSpace($Artifact) -or ($declared -cnotcontains $Artifact)) {
        throw "ChangeArtifactNotDeclared: '$Artifact' is not a change artifact; supply one of $($declared -join ', ')."
    }

    if ([string]::IsNullOrWhiteSpace($Root)) {
        throw 'ChangeArtifactRootNotSupplied: supply the directory the change writes its artifacts to.'
    }

    if ($null -eq $Content) {
        throw "ChangeArtifactContentNotSupplied: the $Artifact artifact was handed no content to write."
    }

    $set = New-BaselineChangeArtifactSet -ChangeId $ChangeId -Root $Root
    $entry = $null
    foreach ($candidate in $set) {
        if ([string]$candidate['Artifact'] -eq $Artifact) {
            $entry = $candidate
            break
        }
    }

    $text = if ([string]$entry['Format'] -eq 'PowerShell') {
        if ($Content -isnot [string]) {
            throw "ChangeArtifactContentNotExecutable: the $Artifact artifact must be handed the script text it is to run, not a $($Content.GetType().Name)."
        }

        [string]$Content
    }
    else {
        ConvertTo-CanonicalJson -InputObject (ConvertTo-BaselineHashableNode -Node $Content)
    }

    $path = [string]$entry['Path']
    if (Test-Path -LiteralPath $path) {
        throw "ChangeArtifactAlreadyEmitted: '$path' was already written by this change; a change does not rewrite its own evidence."
    }

    $directory = Split-Path -Parent $path
    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($text)
    [System.IO.File]::WriteAllBytes($path, $bytes)

    return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                Artifact  = [string]$entry['Artifact']
                FileName  = [string]$entry['FileName']
                Path      = $path
                Format    = [string]$entry['Format']
                Sequence  = [int]$entry['Sequence']
                Algorithm = 'SHA256'
                Hash      = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
            }))
}

# Membership rather than value: a member that is present and null is a caller who said nothing
# about it, and a member that is absent is a caller who never knew it was required. Both are
# refused, but only a presence test can tell them apart from a member legitimately holding $false.
function Test-BaselineNodeMember {
    param(
        [AllowNull()]
        [object]$Node,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Node) { return $false }

    if ($Node -is [System.Collections.IDictionary]) {
        return (@(foreach ($key in $Node.Keys) { [string]$key }) -ccontains $Name)
    }

    return ($Node.PSObject.Properties.Match($Name).Count -gt 0)
}

# SAFE-002: the version of the tool that produced an artifact, read from the shipped manifest
# rather than from the loaded module, because the tests import the .psm1 directly and a module
# loaded without its manifest reports no version at all.
$script:BaselineToolVersion = $null

function Get-BaselineToolVersion {
    if ($null -eq $script:BaselineToolVersion) {
        $manifestPath = Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psd1'
        $script:BaselineToolVersion = [string](Import-PowerShellDataFile -LiteralPath $manifestPath).ModuleVersion
    }

    return $script:BaselineToolVersion
}

$script:BaselineChangeStateMember = @('Exists', 'Value')
$script:BaselineChangeOperationMember = @('OperationId', 'Command', 'Identity', 'Before', 'After')

# SAFE-002: the whole change, written down before any of it happens. Everything an approver needs
# to decide is here and nothing is left for the run to fill in later: which tenant, which profile,
# which resolved configuration by hash, every operation in the order it runs with the value the
# object holds now and the value it will hold, what each operation waits on, when the plan was made
# and when it stops being true. A dependency is resolved against the operations already declared
# rather than against the whole set, because an operation that runs before the one it waits on is
# applied to an object that does not exist yet, and a cycle can never be ordered at all.
function New-BaselineChangePreview {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ChangeId,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Tenant,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Context,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Operation,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$GeneratedOn,

        [AllowNull()]
        [object]$ValidFor
    )

    $pattern = [string](Get-BaselineChangeArtifactContract).ChangeIdentifierPattern
    if ([string]::IsNullOrWhiteSpace($ChangeId) -or $ChangeId -cnotmatch $pattern) {
        throw "ChangeIdentifierNotRecognized: '$ChangeId' is not a change identifier; supply one matching $pattern."
    }

    if ([string]::IsNullOrWhiteSpace($Tenant)) {
        throw 'ChangePreviewTenantNotSupplied: a preview must name the tenant the change is planned against.'
    }

    foreach ($required in @('DeploymentProfile', 'Algorithm', 'Hash')) {
        $value = Get-BaselineRecordMember -Node $Context -Name $required
        if (-not (Test-BaselineNodeMember -Node $Context -Name $required) -or [string]::IsNullOrWhiteSpace([string]$value)) {
            throw "ChangePreviewContextNotRecognized: the supplied context carries no $required; pass the output of Get-BaselineContext."
        }
    }

    $declaredOperation = @($Operation | Where-Object { $null -ne $_ })
    if ($declaredOperation.Count -eq 0) {
        throw 'ChangePreviewOperationNotSupplied: a preview of no operations approves every mutation the run later invents.'
    }

    if ($GeneratedOn -isnot [datetime] -and $GeneratedOn -isnot [datetimeoffset]) {
        throw 'ChangePreviewGenerationTimeNotSupplied: a preview must record the instant it was built.'
    }

    $generated = if ($GeneratedOn -is [datetimeoffset]) { $GeneratedOn.UtcDateTime } else { $GeneratedOn.ToUniversalTime() }

    $window = if ($null -eq $ValidFor) { [timespan]::FromHours(24) } else { [timespan]$ValidFor }
    if ($window -le [timespan]::Zero) {
        throw "ChangePreviewValidityNotUsable: a validity period of $window leaves no window an approval can be acted on inside."
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $entry = foreach ($candidate in $declaredOperation) {
        foreach ($required in $script:BaselineChangeOperationMember) {
            if (-not (Test-BaselineNodeMember -Node $candidate -Name $required)) {
                throw "ChangePreviewOperationNotRecognized: an operation carries no $required; every planned mutation must state all of $($script:BaselineChangeOperationMember -join ', ')."
            }
        }

        $operationId = [string](Get-BaselineRecordMember -Node $candidate -Name 'OperationId')
        $command = [string](Get-BaselineRecordMember -Node $candidate -Name 'Command')
        $identity = [string](Get-BaselineRecordMember -Node $candidate -Name 'Identity')

        foreach ($name in @('OperationId', 'Command', 'Identity')) {
            if ([string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember -Node $candidate -Name $name))) {
                throw "ChangePreviewOperationNotRecognized: an operation carries an empty $name; every planned mutation must state all of $($script:BaselineChangeOperationMember -join ', ')."
            }
        }

        foreach ($stateName in @('Before', 'After')) {
            $state = Get-BaselineRecordMember -Node $candidate -Name $stateName
            foreach ($required in $script:BaselineChangeStateMember) {
                if (-not (Test-BaselineNodeMember -Node $state -Name $required)) {
                    throw "ChangePreviewStateNotRecognized: the $stateName state of operation '$operationId' carries no $required; a state that does not declare both is a state nothing can be restored to."
                }
            }
        }

        if (-not $seen.Add($operationId)) {
            throw "ChangePreviewOperationNotUnique: operation identifier '$operationId' is declared more than once, so every dependency on it is ambiguous."
        }

        $dependsOn = @()
        if (Test-BaselineNodeMember -Node $candidate -Name 'DependsOn') {
            $dependsOn = @(Get-BaselineRecordMember -Node $candidate -Name 'DependsOn' | ForEach-Object { [string]$_ })
        }

        foreach ($dependency in $dependsOn) {
            if ($dependency -ceq $operationId) {
                throw "ChangePreviewDependencyNotResolvable: operation '$operationId' depends on itself, so it never runs."
            }

            if (-not $seen.Contains($dependency)) {
                throw "ChangePreviewDependencyNotResolvable: operation '$operationId' depends on '$dependency', which the preview does not declare before it."
            }
        }

        [ordered]@{
            Sequence    = 0
            OperationId = $operationId
            Command     = $command
            Identity    = $identity
            Before      = ConvertTo-BaselineHashableNode -Node (Get-BaselineRecordMember -Node $candidate -Name 'Before')
            After       = ConvertTo-BaselineHashableNode -Node (Get-BaselineRecordMember -Node $candidate -Name 'After')
            DependsOn   = $dependsOn
        }
    }

    $entry = @($entry)
    for ($index = 0; $index -lt $entry.Count; $index++) { $entry[$index]['Sequence'] = $index + 1 }

    $schemaVersion = [string](@((Get-ArtifactVersionContract).Artifact) | Where-Object { [string]$_.Artifact -eq 'Preview' }).SchemaVersion
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture

    return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                SchemaVersion          = $schemaVersion
                ChangeId               = $ChangeId
                Tenant                 = $Tenant
                DeploymentProfile      = [string](Get-BaselineRecordMember -Node $Context -Name 'DeploymentProfile')
                ConfigurationAlgorithm = [string](Get-BaselineRecordMember -Node $Context -Name 'Algorithm')
                ConfigurationHash      = [string](Get-BaselineRecordMember -Node $Context -Name 'Hash')
                Operation              = $entry
                GeneratedOn            = $generated.ToString('o', $invariant)
                ExpiresOn              = $generated.Add($window).ToString('o', $invariant)
                ToolVersion            = Get-BaselineToolVersion
            }))
}

$script:BaselineChangeApprovalPreviewMember = @('SchemaVersion', 'ChangeId', 'Tenant', 'DeploymentProfile', 'ConfigurationAlgorithm', 'ConfigurationHash', 'Operation', 'GeneratedOn', 'ExpiresOn', 'ToolVersion')
$script:BaselineChangeApprovalMember = @('SchemaVersion', 'ChangeId', 'Tenant', 'DeploymentProfile', 'PreviewHash', 'ApprovalIdentity', 'ApprovalAuthority', 'ApprovalTimeUtc', 'Signature')

# DES-005: the one role whose approval admits a change into Exchange Online. Anyone else's
# sign-off is a record that somebody looked, not an authorisation to mutate a tenant.
$script:BaselineChangeApprovalAuthority = 'ExchangeOnlineChangeApproval'

# SAFE-003: one artifact read off disk and held to its declared member set. The bytes are hashed
# before they are parsed, because the approval binds to the bytes rather than to the document a
# parser reconstructed from them. A document short of any required member is unreadable as a
# whole rather than member by member, so an operator is handed one refusal naming everything
# missing instead of a queue of them.
function Read-BaselineChangeApprovalArtifact {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Path,

        [Parameter(Mandatory)]
        [string[]]$Member
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return @{ Fault = 'NotSupplied'; Detail = ''; Document = $null; Hash = $null }
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return @{ Fault = 'NotFound'; Detail = $Path; Document = $null; Hash = $null }
    }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $hash = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    $text = [System.Text.UTF8Encoding]::new($false).GetString($bytes)

    $document = $null
    try { $document = $text | ConvertFrom-Json -Depth 64 } catch { $document = $null }

    if ($null -eq $document -or $document -is [string] -or $document -is [System.Collections.IList] -or $document -is [valuetype]) {
        return @{ Fault = 'NotReadable'; Detail = "'$Path' does not parse as a JSON document"; Document = $null; Hash = $hash }
    }

    $missing = @(foreach ($name in $Member) {
            $value = Get-BaselineRecordMember -Node $document -Name $name
            if (-not (Test-BaselineNodeMember -Node $document -Name $name) -or
                $null -eq $value -or
                ($value -is [string] -and [string]::IsNullOrWhiteSpace($value))) {
                $name
            }
        })

    if ($missing.Count -gt 0) {
        return @{ Fault = 'NotReadable'; Detail = "'$Path' carries no $($missing -join ', ')"; Document = $null; Hash = $hash }
    }

    return @{ Fault = $null; Detail = ''; Document = $document; Hash = $hash }
}

# SAFE-003: the gate an apply has to get through, and the only thing that separates a reviewed
# change from a change invented at run time. The approval is bound to the preview by the hash of
# the preview's bytes on disk, so a plan edited after it was signed is a plan nobody approved; the
# preview is bound to this run by the tenant, the deployment profile and the configuration hash
# the run actually resolved, so an approval cannot be carried across tenants, across profiles or
# across a configuration that moved after review. Every refusal is collected rather than thrown,
# because an operator handed one blocker at a time has to run the whole gate again to learn what
# else was already wrong, and the decision is immutable, because a verdict a caller can rewrite is
# a gate that permits whatever the caller wanted.
function Test-BaselineChangeApproval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$PreviewPath,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ApprovalPath,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Tenant,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$DeploymentProfile,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ConfigurationHash,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$RequestedBy,

        [AllowNull()]
        [object]$AsOf
    )

    $finding = [System.Collections.Generic.List[string]]::new()

    $preview = Read-BaselineChangeApprovalArtifact -Path $PreviewPath -Member $script:BaselineChangeApprovalPreviewMember
    switch ($preview.Fault) {
        'NotSupplied' { $finding.Add('ChangeApprovalPreviewPathNotSupplied: supply the preview the apply is to be held to; an apply with no plan to point at is an apply from configuration alone.') }
        'NotFound' { $finding.Add("ChangeApprovalPreviewNotFound: '$($preview.Detail)' names no preview, so there is nothing to check the approval against.") }
        'NotReadable' { $finding.Add("ChangeApprovalPreviewNotReadable: $($preview.Detail); a file the gate cannot read is a plan the gate cannot hold the run to.") }
    }

    $approval = Read-BaselineChangeApprovalArtifact -Path $ApprovalPath -Member $script:BaselineChangeApprovalMember
    switch ($approval.Fault) {
        'NotSupplied' { $finding.Add('ChangeApprovalPathNotSupplied: supply the approval that admits this change; a plan nobody signed is a plan nobody approved.') }
        'NotFound' { $finding.Add("ChangeApprovalNotFound: '$($approval.Detail)' names no approval; a missing approval is a refusal, not an absence of opinion.") }
        'NotReadable' { $finding.Add("ChangeApprovalNotReadable: $($approval.Detail); an approval the gate cannot read grants nothing.") }
    }

    $changeId = ''

    if ($null -ne $preview.Document -and $null -ne $approval.Document) {
        $changeId = [string](Get-BaselineRecordMember -Node $preview.Document -Name 'ChangeId')
        $previewTenant = [string](Get-BaselineRecordMember -Node $preview.Document -Name 'Tenant')
        $previewProfile = [string](Get-BaselineRecordMember -Node $preview.Document -Name 'DeploymentProfile')
        $previewHash = [string](Get-BaselineRecordMember -Node $preview.Document -Name 'ConfigurationHash')
        $expiresOn = Get-BaselineRecordMember -Node $preview.Document -Name 'ExpiresOn'

        $approvedHash = [string](Get-BaselineRecordMember -Node $approval.Document -Name 'PreviewHash')
        if ($approvedHash -ne [string]$preview.Hash) {
            $finding.Add("ChangeApprovalPreviewTampered: the approval was raised over preview $approvedHash and '$PreviewPath' now hashes to $($preview.Hash); a preview edited after it was signed is a plan nobody approved.")
        }

        $approvedChangeId = [string](Get-BaselineRecordMember -Node $approval.Document -Name 'ChangeId')
        if ($approvedChangeId -ne $changeId) {
            $finding.Add("ChangeApprovalChangeMismatch: the approval names change '$approvedChangeId' and the preview plans change '$changeId'.")
        }

        $approvedTenant = [string](Get-BaselineRecordMember -Node $approval.Document -Name 'Tenant')
        if ($approvedTenant -ne $previewTenant) {
            $finding.Add("ChangeApprovalTenantMismatch: the approval names tenant '$approvedTenant' and the preview plans against '$previewTenant'.")
        }
        elseif ($previewTenant -ne [string]$Tenant) {
            $finding.Add("ChangeApprovalTenantMismatch: the preview plans against tenant '$previewTenant' and this run is connected to '$Tenant'.")
        }

        $approvedProfile = [string](Get-BaselineRecordMember -Node $approval.Document -Name 'DeploymentProfile')
        if ($approvedProfile -ne $previewProfile) {
            $finding.Add("ChangeApprovalProfileMismatch: the approval names deployment profile '$approvedProfile' and the preview plans profile '$previewProfile'.")
        }
        elseif ($previewProfile -ne [string]$DeploymentProfile) {
            $finding.Add("ChangeApprovalProfileMismatch: the preview plans deployment profile '$previewProfile' and this run resolved '$DeploymentProfile'.")
        }

        if ($previewHash -ne [string]$ConfigurationHash) {
            $finding.Add("ChangeApprovalConfigurationMismatch: the preview was built over configuration $previewHash and this run resolved $ConfigurationHash; a configuration edited after approval turns an approved plan into an unreviewed one.")
        }

        $decisionInstant = if ($AsOf -is [datetimeoffset]) { $AsOf.UtcDateTime }
        elseif ($AsOf -is [datetime]) { ([datetime]$AsOf).ToUniversalTime() }
        else { [datetime]::UtcNow }

        $expiryInstant = [datetime]::MinValue
        $expiryParsed = $false
        $expiryCandidate = [datetime]::MinValue

        if ($expiresOn -is [datetimeoffset]) {
            $expiryInstant = $expiresOn.UtcDateTime
            $expiryParsed = $true
        }
        elseif ($expiresOn -is [datetime]) {
            $expiryCandidate = [datetime]$expiresOn
            $expiryParsed = $true
        }
        elseif ([datetime]::TryParse(
                [string]$expiresOn,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind,
                [ref]$expiryCandidate)) {
            $expiryParsed = $true
        }

        # A declared UTC expiry that arrives without a kind is still a UTC expiry; reading it as
        # local time moves the instant the plan stops being true by the operator's offset.
        if ($expiryParsed -and $expiresOn -isnot [datetimeoffset]) {
            $expiryInstant = if ($expiryCandidate.Kind -eq [System.DateTimeKind]::Unspecified) {
                [datetime]::SpecifyKind($expiryCandidate, [System.DateTimeKind]::Utc)
            }
            else {
                $expiryCandidate.ToUniversalTime()
            }
        }

        if (-not $expiryParsed) {
            $finding.Add("ChangeApprovalPreviewNotReadable: the preview expiry '$expiresOn' is not an instant, so nothing can decide whether the plan is still in force.")
        }
        elseif ($decisionInstant -ge $expiryInstant) {
            $finding.Add("ChangeApprovalPreviewExpired: the preview stopped being in force at $($expiryInstant.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)) and the decision is being made at $($decisionInstant.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)).")
        }

        $signature = Get-BaselineRecordMember -Node $approval.Document -Name 'Signature'
        $signatureModel = [string](Get-BaselineRecordMember -Node $signature -Name 'Model')
        $signatureValue = [string](Get-BaselineRecordMember -Node $signature -Name 'Value')
        $selectedModel = @((Get-ApprovalSignatureContract).SelectedModel)

        if ([string]::IsNullOrWhiteSpace($signatureValue)) {
            $finding.Add('ChangeApprovalUnsigned: the approval carries no signature value, so it binds these bytes to nobody.')
        }

        if ([string]::IsNullOrWhiteSpace($signatureModel) -or $selectedModel -notcontains $signatureModel) {
            $finding.Add("ChangeApprovalSignatureModelNotApproved: the approval is signed under '$signatureModel' and only $($selectedModel -join ', ') is selected; a signature model nobody selected is a signature nobody can verify.")
        }

        $approvalAuthority = [string](Get-BaselineRecordMember -Node $approval.Document -Name 'ApprovalAuthority')
        if ($approvalAuthority -ne $script:BaselineChangeApprovalAuthority) {
            $finding.Add("ChangeApprovalAuthorityNotApproved: the approval was granted under '$approvalAuthority' and only $($script:BaselineChangeApprovalAuthority) admits a change; an approval from somebody who does not hold the role is not an approval.")
        }

        $approvalIdentity = [string](Get-BaselineRecordMember -Node $approval.Document -Name 'ApprovalIdentity')
        if (-not [string]::IsNullOrWhiteSpace($approvalIdentity) -and $approvalIdentity -eq [string]$RequestedBy) {
            $finding.Add("ChangeApprovalSelfApproved: '$approvalIdentity' both requested and approved this change, which removes the review entirely.")
        }
    }

    return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                Permitted    = ($finding.Count -eq 0)
                ChangeId     = $changeId
                PreviewPath  = [string]$PreviewPath
                ApprovalPath = [string]$ApprovalPath
                DecidedFor   = [string]$RequestedBy
                Finding      = @($finding)
            }))
}

# SAFE-004: what the tenant held before the run touched it, written down while it is still true.
# The capture is taken from the operations the change declared rather than from whatever the run
# happens to touch later, so an object mutated without being declared has no captured prior value
# and no rollback - which is the point. One object may be captured once: two recorded prior values
# for the same object under the same command is no restorable prior value at all. The snapshot is
# sealed over the canonical text of the entries alone, so the instant it was taken can be read
# without moving the identity of the state it describes.
function New-BaselineChangeStateCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ChangeId,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Tenant,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Operation,

        [AllowNull()]
        [object]$CapturedOn
    )

    $pattern = [string](Get-BaselineChangeArtifactContract).ChangeIdentifierPattern
    if ([string]::IsNullOrWhiteSpace($ChangeId) -or $ChangeId -cnotmatch $pattern) {
        throw "ChangeIdentifierNotRecognized: '$ChangeId' is not a change identifier; supply one matching $pattern."
    }

    if ([string]::IsNullOrWhiteSpace($Tenant)) {
        throw 'ChangeCaptureTenantNotSupplied: a capture must name the tenant the prior state was read from.'
    }

    $declared = @($Operation | Where-Object { $null -ne $_ })
    if ($declared.Count -eq 0) {
        throw 'ChangeCaptureOperationNotSupplied: a capture of no objects lets a run mutate anything and still claim it captured the state first.'
    }

    if ($null -eq $CapturedOn) { $CapturedOn = [datetime]::UtcNow }
    if ($CapturedOn -isnot [datetime] -and $CapturedOn -isnot [datetimeoffset]) {
        throw 'ChangeCaptureTimeNotSupplied: a capture must record the instant it was taken, so it can be shown to predate the mutation it precedes.'
    }

    $captured = if ($CapturedOn -is [datetimeoffset]) { $CapturedOn.UtcDateTime } else { ([datetime]$CapturedOn).ToUniversalTime() }

    $seenOperation = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $seenObject = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $entry = foreach ($candidate in $declared) {
        foreach ($required in @('OperationId', 'Command', 'Identity')) {
            if (-not (Test-BaselineNodeMember -Node $candidate -Name $required) -or
                [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember -Node $candidate -Name $required))) {
                throw "ChangeCaptureOperationNotRecognized: an operation carries no $required; every captured object must state all of OperationId, Command, Identity."
            }
        }

        $operationId = [string](Get-BaselineRecordMember -Node $candidate -Name 'OperationId')
        $command = [string](Get-BaselineRecordMember -Node $candidate -Name 'Command')
        $identity = [string](Get-BaselineRecordMember -Node $candidate -Name 'Identity')

        $before = Get-BaselineRecordMember -Node $candidate -Name 'Before'
        foreach ($required in $script:BaselineChangeStateMember) {
            if (-not (Test-BaselineNodeMember -Node $candidate -Name 'Before') -or
                -not (Test-BaselineNodeMember -Node $before -Name $required)) {
                throw "ChangeCaptureStateNotRecognized: the prior state of operation '$operationId' carries no $required; a state that does not declare both is a state nothing can be restored to."
            }
        }

        $exists = [bool](Get-BaselineRecordMember -Node $before -Name 'Exists')
        $value = Get-BaselineRecordMember -Node $before -Name 'Value'

        if (-not $exists -and -not ($null -eq $value -or ($value -is [string] -and $value -eq ''))) {
            throw "ChangeCaptureStateNotRestorable: operation '$operationId' captured '$identity' as absent while recording the value '$value'; an object that did not exist and held a value is two prior states at once."
        }

        if (-not $seenOperation.Add($operationId)) {
            throw "ChangeCaptureOperationNotUnique: operation identifier '$operationId' is captured more than once, so every restore of it is ambiguous."
        }

        if (-not $seenObject.Add("$command`u{001F}$identity")) {
            throw "ChangeCaptureObjectNotUnique: '$identity' is captured more than once under $command, so it has no restorable prior value."
        }

        [ordered]@{
            Sequence    = 0
            OperationId = $operationId
            Command     = $command
            Identity    = $identity
            Exists      = $exists
            Value       = ConvertTo-BaselineHashableNode -Node $value
        }
    }

    $entry = @($entry)
    for ($index = 0; $index -lt $entry.Count; $index++) { $entry[$index]['Sequence'] = $index + 1 }

    $sealed = ConvertTo-ImmutableBaselineNode -Node $entry
    $canonical = [System.Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-CanonicalJson -InputObject $sealed))
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture

    return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                SchemaVersion = [string](@((Get-ArtifactVersionContract).Artifact) | Where-Object { [string]$_.Artifact -eq 'Rollback' }).SchemaVersion
                ChangeId      = $ChangeId
                Tenant        = $Tenant
                CapturedOn    = $captured.ToString('o', $invariant)
                Algorithm     = 'SHA256'
                Hash          = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($canonical)).ToLowerInvariant()
                Entry         = $entry
            }))
}

# SAFE-004: the script that puts the tenant back, written from the capture and from nothing else.
# Every value is emitted as a single-quoted literal with its quotes doubled, so a prior value that
# happens to contain PowerShell is restored as text rather than run as code. An object the change
# created is removed rather than set, because setting a value on it leaves it behind; an object the
# change only edited is set rather than removed, because deleting it turns a rollback into an
# outage. The restores unwind in the reverse of the capture order, so nothing is restored before
# the object it depends on. Each one sits inside a `ShouldProcess` decision, so the rollback can
# itself be rehearsed with `-WhatIf` before anyone runs it against a tenant.
function New-BaselineRollbackScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Capture
    )

    foreach ($required in @('ChangeId', 'Tenant', 'CapturedOn', 'Entry')) {
        if ($null -eq $Capture -or -not (Test-BaselineNodeMember -Node $Capture -Name $required)) {
            throw "ChangeRollbackCaptureNotRecognized: the supplied capture carries no $required; pass the output of New-BaselineChangeStateCapture."
        }
    }

    $entry = @(Get-BaselineRecordMember -Node $Capture -Name 'Entry')
    if ($entry.Count -eq 0) {
        throw 'ChangeRollbackCaptureNotRecognized: the supplied capture carries no entries, so the script it generates would make an irreversible change look reversible.'
    }

    $changeId = [string](Get-BaselineRecordMember -Node $Capture -Name 'ChangeId')
    $tenant = [string](Get-BaselineRecordMember -Node $Capture -Name 'Tenant')
    $capturedOn = [string](Get-BaselineRecordMember -Node $Capture -Name 'CapturedOn')

    if ([string]::IsNullOrWhiteSpace($changeId) -or [string]::IsNullOrWhiteSpace($tenant)) {
        throw 'ChangeRollbackCaptureNotRecognized: the supplied capture does not name both the change and the tenant it was taken from.'
    }

    $sealed = [string](Get-BaselineRecordMember -Node $Capture -Name 'Hash')
    if (-not (Test-BaselineNodeMember -Node $Capture -Name 'Hash') -or [string]::IsNullOrWhiteSpace($sealed)) {
        throw 'ChangeRollbackCaptureNotSealed: the supplied capture carries no hash, so it cannot be shown to be the snapshot the run took.'
    }

    $recomputed = [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData(
            [System.Text.UTF8Encoding]::new($false).GetBytes(
                (ConvertTo-CanonicalJson -InputObject (Get-BaselineRecordMember -Node $Capture -Name 'Entry'))))).ToLowerInvariant()

    if ($sealed -ne $recomputed) {
        throw "ChangeRollbackCaptureNotSealed: the capture is sealed as $sealed and now hashes to $recomputed; a snapshot edited after it was sealed is a prior state nobody observed."
    }

    $line = [System.Collections.Generic.List[string]]::new()
    $line.Add('#requires -Version 7.0')
    $line.Add("# SAFE-004 rollback for change $changeId in tenant $tenant.")
    $line.Add("# Generated from capture $sealed taken at $capturedOn.")
    $line.Add('# Restores run in the reverse of the order the mutations were captured in.')
    $line.Add('[CmdletBinding(SupportsShouldProcess)]')
    $line.Add('param()')
    $line.Add('')
    $line.Add("`$ErrorActionPreference = 'Stop'")

    for ($index = $entry.Count - 1; $index -ge 0; $index--) {
        $restore = $entry[$index]

        foreach ($required in @('OperationId', 'Command', 'Identity', 'Exists', 'Value')) {
            if (-not (Test-BaselineNodeMember -Node $restore -Name $required)) {
                throw "ChangeRollbackEntryNotRecognized: a captured entry carries no $required; a restore must name the object, the command it is restored through, whether it existed and what it held."
            }
        }

        $command = [string](Get-BaselineRecordMember -Node $restore -Name 'Command')
        $part = $command.Split('-')
        if ($part.Count -ne 2 -or [string]::IsNullOrWhiteSpace($part[0]) -or [string]::IsNullOrWhiteSpace($part[1])) {
            throw "ChangeRollbackCommandNotRecognized: '$command' is not a verb-noun command, so no removal can be derived from it; guessing one is worse than admitting the change cannot be rolled back."
        }

        $operationId = [string](Get-BaselineRecordMember -Node $restore -Name 'OperationId') -replace '[\r\n]+', ' '
        $identity = [string](Get-BaselineRecordMember -Node $restore -Name 'Identity')
        $quotedIdentity = $identity.Replace("'", "''")
        $safeIdentity = $identity -replace '[\r\n]+', ' '

        $line.Add('')

        if ([bool](Get-BaselineRecordMember -Node $restore -Name 'Exists')) {
            $quotedValue = ([string](Get-BaselineRecordMember -Node $restore -Name 'Value')).Replace("'", "''")

            $line.Add("# $operationId restores $safeIdentity to the value the capture recorded.")
            $line.Add("if (`$PSCmdlet.ShouldProcess('$quotedIdentity', '$command')) {")
            $line.Add("    $command -Identity '$quotedIdentity' -Value '$quotedValue' -Confirm:`$false")
            $line.Add('}')
        }
        else {
            $removal = "Remove-$($part[1])"

            $line.Add("# $operationId restores $safeIdentity, which did not exist before the change.")
            $line.Add("if (`$PSCmdlet.ShouldProcess('$quotedIdentity', '$removal')) {")
            $line.Add("    $removal -Identity '$quotedIdentity' -Confirm:`$false")
            $line.Add('}')
        }
    }

    $line.Add('')

    return ($line -join "`n")
}

# SAFE-005: which commands change a tenant and what a decision to change one looks like. The verbs# are listed rather than the cmdlets, so a mutation added later is caught by default instead of
# being invisible until someone remembers to extend a list. The non-tenant commands are the ones
# that carry a mutating verb while changing nothing outside this process.
function Get-BaselineMutationGuardContract {
    [CmdletBinding()]
    param()

    return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                MutatingVerb     = @('Add', 'Clear', 'Disable', 'Enable', 'Grant', 'New', 'Remove', 'Reset', 'Revoke', 'Set', 'Start', 'Stop', 'Update')
                NonTenantCommand = @(
                    'Add-Member'
                    'Add-Type'
                    'Clear-Variable'
                    'New-Guid'
                    'New-Item'
                    'New-Object'
                    'New-TemporaryFile'
                    'New-TimeSpan'
                    'New-Variable'
                    'Remove-Item'
                    'Remove-Module'
                    'Remove-Variable'
                    'Set-Content'
                    'Set-Item'
                    'Set-Location'
                    'Set-StrictMode'
                    'Set-Variable'
                    'Start-Sleep'
                    'Update-TypeData'
                )
                GuardExpression  = '$PSCmdlet.ShouldProcess'
                State            = @('Pending', 'Succeeded', 'Failed', 'RolledBack')
            }))
}

# SAFE-005: one entry per mutation the run declared, carrying the object it touched and the state
# it reached. The journal is built from the declared plan rather than from whatever the run managed
# to do, so a mutation that was never attempted is still present and still outstanding instead of
# silently absent. A mutation the operator declined at the guard never ran, so it is recorded
# pending whatever outcome the caller claims for it - otherwise a declined change reads as an
# applied one. A failure has to carry its fault, because a failure nobody can diagnose cannot be
# recovered from, and a state the contract never declared is refused rather than written through.
function New-BaselineMutationJournal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Operation
    )

    $declared = @($Operation | Where-Object { $null -ne $_ })
    if ($declared.Count -eq 0) {
        throw 'MutationJournalOperationNotSupplied: a journal of no mutations reports the same empty record whether the run changed one object or every object.'
    }

    $state = @((Get-BaselineMutationGuardContract).State)
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $sequence = 0

    $entry = foreach ($candidate in $declared) {
        foreach ($required in @('OperationId', 'Command', 'Identity')) {
            if (-not (Test-BaselineNodeMember -Node $candidate -Name $required) -or
                [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember -Node $candidate -Name $required))) {
                throw "MutationJournalOperationNotRecognized: a mutation carries no $required; every entry must state all of OperationId, Command, Identity."
            }
        }

        $operationId = [string](Get-BaselineRecordMember -Node $candidate -Name 'OperationId')
        if (-not $seen.Add($operationId)) {
            throw "MutationJournalOperationNotUnique: operation identifier '$operationId' is journalled more than once, so neither entry is the state it reached."
        }

        $reached = if (Test-BaselineNodeMember -Node $candidate -Name 'State') {
            [string](Get-BaselineRecordMember -Node $candidate -Name 'State')
        }
        else { 'Pending' }

        if ($reached -cnotin $state) {
            throw "MutationJournalStateNotDeclared: operation '$operationId' reached '$reached', which is not one of $($state -join ', ')."
        }

        if ((Test-BaselineNodeMember -Node $candidate -Name 'Approved') -and
            -not [bool](Get-BaselineRecordMember -Node $candidate -Name 'Approved')) {
            $reached = 'Pending'
        }

        $fault = [string](Get-BaselineRecordMember -Node $candidate -Name 'Fault')
        if ($reached -eq 'Failed' -and [string]::IsNullOrWhiteSpace($fault)) {
            throw "MutationJournalFaultNotRecorded: operation '$operationId' is journalled as failed while recording no fault, so the failure cannot be diagnosed or recovered from."
        }

        if ($reached -ne 'Failed') { $fault = '' }

        $sequence++

        [ordered]@{
            Sequence    = $sequence
            OperationId = $operationId
            Command     = [string](Get-BaselineRecordMember -Node $candidate -Name 'Command')
            Identity    = [string](Get-BaselineRecordMember -Node $candidate -Name 'Identity')
            State       = $reached
            Fault       = $fault
        }
    }

    return , (ConvertTo-ImmutableBaselineNode -Node @($entry))
}

# SAFE-005: a condition counts as a decision only when it is exactly `$PSCmdlet.ShouldProcess(...)`.
# Anything wrapping it can invert or short-circuit the answer it gave - `-not` runs the mutation
# precisely when the operator declined - and a `ShouldProcess` on any other object is a method the
# script invented and can answer however it finds convenient.
function Test-BaselineShouldProcessCondition {
    param([object]$Condition)

    if ($Condition -isnot [System.Management.Automation.Language.PipelineAst]) { return $false }
    if (@($Condition.PipelineElements).Count -ne 1) { return $false }

    $element = $Condition.PipelineElements[0]
    if ($element -isnot [System.Management.Automation.Language.CommandExpressionAst]) { return $false }

    $expression = $element.Expression
    while ($expression -is [System.Management.Automation.Language.ParenExpressionAst]) {
        $inner = $expression.Pipeline
        if ($inner -isnot [System.Management.Automation.Language.PipelineAst] -or @($inner.PipelineElements).Count -ne 1) { return $false }
        if ($inner.PipelineElements[0] -isnot [System.Management.Automation.Language.CommandExpressionAst]) { return $false }
        $expression = $inner.PipelineElements[0].Expression
    }

    if ($expression -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst]) { return $false }
    if ([string]$expression.Member.Value -ne 'ShouldProcess') { return $false }

    $target = $expression.Expression
    return ($target -is [System.Management.Automation.Language.VariableExpressionAst] -and
        [string]$target.VariablePath.UserPath -eq 'PSCmdlet')
}

# SAFE-005: walk from the command out to the script root and look for an enclosing `if` whose
# taken branch this command sits in. Matching the branch by reference is what keeps an `else` from
# counting: the else branch is the path the operator declined, so a mutation there runs exactly
# when it was refused. Walking the whole ancestry is what stops a loop or a nested `if` from being
# used to slip a mutation out from under a guard that does enclose it.
function Test-BaselineShouldProcessEnclosure {
    param([object]$Node)

    $child = $Node
    $parent = $Node.Parent

    while ($null -ne $parent) {
        if ($parent -is [System.Management.Automation.Language.IfStatementAst]) {
            foreach ($clause in $parent.Clauses) {
                if ([object]::ReferenceEquals($clause.Item2, $child) -and
                    (Test-BaselineShouldProcessCondition -Condition $clause.Item1)) {
                    return $true
                }
            }
        }

        $child = $parent
        $parent = $parent.Parent
    }

    return $false
}

# SAFE-005: every tenant-mutating command a script can reach, and whether a `ShouldProcess`
# decision encloses it. This is decided from the parsed script rather than from a run, because a
# mutation only reachable down some branch nobody exercised is exactly the one that ships
# unguarded. A command the script defines itself is not counted: the helper mutates nothing on its
# own, and counting it hides the real mutations inside it behind a name that looks handled.
function Get-BaselineMutationGuardReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ScriptPath
    )

    if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
        throw 'ScriptPathNotSupplied: supply the path of the script whose mutations are to be reported.'
    }

    if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
        throw "ScriptPathNotFound: '$ScriptPath' names no file."
    }

    $parseToken = $null
    $parseError = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Resolve-Path -LiteralPath $ScriptPath).ProviderPath, [ref]$parseToken, [ref]$parseError)

    if (@($parseError).Count -gt 0) {
        throw "ScriptNotParsable: '$ScriptPath' did not parse; $($parseError[0].Message)"
    }

    $contract = Get-BaselineMutationGuardContract
    $verbPattern = '^(?:' + ((@($contract.MutatingVerb) | ForEach-Object { [regex]::Escape([string]$_) }) -join '|') + ')-'
    $nonTenantCommand = @($contract.NonTenantCommand | ForEach-Object { [string]$_ })

    $localFunction = @(
        $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
            ForEach-Object { [string]$_.Name }
    )

    $site = foreach ($command in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $name = $command.GetCommandName()

        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if ($name -notmatch $verbPattern) { continue }
        if ($localFunction -contains $name) { continue }
        if ($nonTenantCommand -contains $name) { continue }

        [ordered]@{
            Command = [string]$name
            Line    = [int]$command.Extent.StartLineNumber
            Guarded = [bool](Test-BaselineShouldProcessEnclosure -Node $command)
        }
    }

    $site = @($site)

    return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                ScriptPath    = [string]$ScriptPath
                MutationSite  = $site
                UnguardedSite = @(
                    $site |
                        Where-Object { -not $_.Guarded } |
                        ForEach-Object { [ordered]@{ Command = $_.Command; Line = $_.Line } }
                )
            }))
}

# SAFE-006: what a run that stopped halfway actually left on the tenant, and the one order it can
# be recovered in. The record is reconciled against the plan the change declared rather than
# against whatever the run managed to journal, because a mutation outside the approved plan is the
# one change nobody previewed and a declared mutation nobody journalled is a change whose state the
# run cannot state either way. An operation is halted transitively: stopping only the immediate
# dependents of a failure leaves everything behind them free to apply onto a state that never
# arrived. An operation that already landed is never called halted, because a mutation reported as
# stopped is a mutation the recovery will not account for. The record carries no clock, so two runs
# over the same plan and journal produce the same recovery and the same bytes.
function Resolve-BaselinePartialApplication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ChangeId,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Operation,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Journal,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$Root
    )

    $null = New-BaselineChangeArtifactSet -ChangeId $ChangeId

    $declared = @($Operation | Where-Object { $null -ne $_ })
    if ($declared.Count -eq 0) {
        throw 'PartialApplicationOperationNotSupplied: a run reconciled against no plan calls any amount of damage a complete application.'
    }

    $plan = [ordered]@{}
    foreach ($candidate in $declared) {
        foreach ($required in @('OperationId', 'Command', 'Identity')) {
            if (-not (Test-BaselineNodeMember -Node $candidate -Name $required) -or
                [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember -Node $candidate -Name $required))) {
                throw "PartialApplicationOperationNotRecognized: a declared operation carries no $required; every operation must state all of OperationId, Command, Identity."
            }
        }

        $operationId = [string](Get-BaselineRecordMember -Node $candidate -Name 'OperationId')
        if ($plan.Contains($operationId)) {
            throw "PartialApplicationOperationNotRecognized: operation identifier '$operationId' is declared more than once, so neither declaration is the change that was planned."
        }

        $plan[$operationId] = [ordered]@{
            OperationId = $operationId
            Command     = [string](Get-BaselineRecordMember -Node $candidate -Name 'Command')
            Identity    = [string](Get-BaselineRecordMember -Node $candidate -Name 'Identity')
            DependsOn   = @(@(Get-BaselineRecordMember -Node $candidate -Name 'DependsOn') |
                    Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                    ForEach-Object { [string]$_ })
        }
    }

    if ($null -eq $Journal -or @($Journal | Where-Object { $null -ne $_ }).Count -eq 0) {
        throw 'PartialApplicationJournalNotSupplied: a run with no journal behind it has no partial state to persist, only an assumption.'
    }

    $recorded = [ordered]@{}
    foreach ($entry in @($Journal | Where-Object { $null -ne $_ })) {
        $operationId = [string](Get-BaselineRecordMember -Node $entry -Name 'OperationId')
        if (-not $plan.Contains($operationId)) {
            throw "PartialApplicationJournalNotReconciled: the run journalled operation '$operationId', which the approved plan never declared."
        }

        $recorded[$operationId] = $entry
    }

    foreach ($operationId in @($plan.Keys)) {
        if (-not $recorded.Contains($operationId)) {
            throw "PartialApplicationJournalNotReconciled: the plan declared operation '$operationId', which the run never journalled, so its state cannot be stated either way."
        }
    }

    foreach ($operationId in @($plan.Keys)) {
        foreach ($dependency in $plan[$operationId]['DependsOn']) {
            if ($dependency -ceq $operationId) {
                throw "PartialApplicationDependencyNotOrdered: operation '$operationId' depends on itself, so it can never be stopped or resumed."
            }

            if (-not $plan.Contains($dependency)) {
                throw "PartialApplicationDependencyNotDeclared: operation '$operationId' waits on '$dependency', which the plan never declared."
            }
        }
    }

    $settled = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $order = [System.Collections.Generic.List[string]]::new()
    while ($order.Count -lt $plan.Count) {
        $progressed = $false
        foreach ($operationId in @($plan.Keys)) {
            if ($settled.Contains($operationId)) { continue }

            $ready = $true
            foreach ($dependency in $plan[$operationId]['DependsOn']) {
                if (-not $settled.Contains($dependency)) { $ready = $false; break }
            }

            if ($ready) {
                $null = $settled.Add($operationId)
                $order.Add($operationId)
                $progressed = $true
            }
        }

        if (-not $progressed) {
            throw 'PartialApplicationDependencyNotOrdered: the plan carries a cycle of dependencies, so every operation in it is both the blocker and the blocked and no recovery order exists.'
        }
    }

    $state = [ordered]@{}
    $blocker = [ordered]@{}
    foreach ($operationId in $order) {
        $journalled = [string](Get-BaselineRecordMember -Node $recorded[$operationId] -Name 'State')

        if ($journalled -ceq 'Succeeded') {
            $state[$operationId] = 'Applied'
            continue
        }

        if ($journalled -ceq 'Failed') {
            $state[$operationId] = 'Failed'
            continue
        }

        $stopped = $null
        foreach ($dependency in $plan[$operationId]['DependsOn']) {
            if ($state[$dependency] -cin @('Failed', 'Halted')) { $stopped = $dependency; break }
        }

        if ($null -ne $stopped) {
            $state[$operationId] = 'Halted'
            $blocker[$operationId] = $stopped
        }
        else {
            $state[$operationId] = 'Outstanding'
        }
    }

    $sequence = 0
    $recovery = foreach ($operationId in @($plan.Keys)) {
        $reached = [string]$state[$operationId]
        if ($reached -ceq 'Applied') { continue }

        $action = 'Apply'
        $reason = ''
        if ($reached -ceq 'Failed') {
            $action = 'Investigate'
            $reason = [string](Get-BaselineRecordMember -Node $recorded[$operationId] -Name 'Fault')
        }
        elseif ($reached -ceq 'Halted') {
            $action = 'Resume'
            $reason = "blocked by '{0}'" -f $blocker[$operationId]
        }

        $sequence++

        [ordered]@{
            Sequence    = $sequence
            OperationId = $operationId
            Action      = $action
            Reason      = $reason
            Command     = [string]$plan[$operationId]['Command']
            Identity    = [string]$plan[$operationId]['Identity']
        }
    }

    $named = {
        param([string]$Reached)
        return @(@($plan.Keys) | Where-Object { [string]$state[$_] -ceq $Reached })
    }

    $application = [ordered]@{
        ChangeId    = $ChangeId
        Applied     = @(& $named 'Applied')
        Failed      = @(& $named 'Failed')
        Halted      = @(& $named 'Halted')
        Outstanding = @(& $named 'Outstanding')
        Recovery    = @($recovery)
    }

    if (-not [string]::IsNullOrWhiteSpace($Root)) {
        $null = Write-BaselineChangeArtifact -ChangeId $ChangeId -Artifact 'Apply' -Root $Root -Content $application
    }

    return , (ConvertTo-ImmutableBaselineNode -Node $application)
}

# SAFE-006: the one verdict that may call a change successful. Success is not "nothing threw": a
# run whose mutations all returned has still only proved that the commands were accepted, so the
# verdict is withheld until something observed the tenant afterwards and admitted it. A decision
# that reached no conclusion is silence rather than consent, and a decision nobody can trace back
# to the evidence behind it is an assertion an audit cannot re-decide, so both refuse. Every reason
# is collected rather than returned at the first one, because an operator handed one blocker at a
# time has to rerun the whole change to learn what else was already wrong.
function Test-BaselineChangeSuccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Application,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$PostChange
    )

    if ($null -eq $Application) {
        throw 'ChangeSuccessApplicationNotSupplied: a change cannot be called successful without the record of what its run actually left behind.'
    }

    $finding = [System.Collections.Generic.List[string]]::new()

    foreach ($operationId in @(Get-BaselineRecordMember -Node $Application -Name 'Failed')) {
        $finding.Add("ChangeOperationFailed: operation '$operationId' failed, so the tenant does not hold the change the plan declared.")
    }

    foreach ($operationId in @(Get-BaselineRecordMember -Node $Application -Name 'Halted')) {
        $finding.Add("ChangeOperationHalted: operation '$operationId' was stopped behind an earlier failure and is still owed.")
    }

    foreach ($operationId in @(Get-BaselineRecordMember -Node $Application -Name 'Outstanding')) {
        $finding.Add("ChangeOperationOutstanding: operation '$operationId' was never applied, which is not the same as having succeeded.")
    }

    $evidence = ''
    if ($null -eq $PostChange) {
        $finding.Add('PostChangeDecisionNotSupplied: nothing observed the tenant after the change, so this run can report its intentions and nothing else.')
    }
    else {
        $evidence = [string](Get-BaselineRecordMember -Node $PostChange -Name 'Evidence')
        if ([string]::IsNullOrWhiteSpace($evidence)) {
            $finding.Add('PostChangeEvidenceNotNamed: the post-change decision names no evidence it was decided from, so no audit can re-decide it.')
        }

        if (-not (Test-BaselineNodeMember -Node $PostChange -Name 'Permitted')) {
            $finding.Add('PostChangeDecidedNothing: the post-change decision reached no conclusion, and silence is not consent.')
        }
        elseif (-not [bool](Get-BaselineRecordMember -Node $PostChange -Name 'Permitted')) {
            $refusal = @(Get-BaselineRecordMember -Node $PostChange -Name 'Finding')
            $finding.Add("PostChangeRefused: the post-change decision refused this run: $($refusal -join '; ')")
        }
    }

    return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                Successful         = ($finding.Count -eq 0)
                ChangeId           = [string](Get-BaselineRecordMember -Node $Application -Name 'ChangeId')
                PostChangeEvidence = $evidence
                Finding            = @($finding)
            }))
}

# SAFE-007: the one decision that lets `-Apply` reach a tenant. A run that applies from the
# configuration alone applies whatever the configuration happens to say today, so an apply has to
# name the preview it was reviewed against, the approval that admitted it and the directory its
# pre-change state, outcome and rollback will be written to. The approval itself is decided
# elsewhere and handed in, so this gate can be exercised without a tenant; an approval decision
# that is absent or that reached no conclusion is refused rather than read as consent, because two
# paths on a command line prove that two files were named and not that anything read them. An audit
# run is governed by none of this: a read-only run that demands an approval before it may look at a
# tenant makes the audit harder to run than the change.
function Test-BaselineApplyPrerequisite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [bool]$Apply,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$PreviewPath,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$ApprovalPath,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$ArtifactRoot,

        [AllowNull()]
        [object]$ApprovalDecision
    )

    $finding = [System.Collections.Generic.List[string]]::new()
    $changeId = ''

    if ($Apply) {
        if ([string]::IsNullOrWhiteSpace($PreviewPath)) {
            $finding.Add('ApplyPreviewPathNotSupplied: an apply must name the preview it was reviewed against, or it applies whatever the configuration says at the moment it runs.')
        }

        if ([string]::IsNullOrWhiteSpace($ApprovalPath)) {
            $finding.Add('ApplyApprovalPathNotSupplied: an apply must name the approval that admitted it; a preview nobody approved is a plan, not permission.')
        }

        if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
            $finding.Add('ApplyArtifactRootNotSupplied: an apply must name the directory its pre-change state, outcome and rollback are written to, or the change can be neither audited nor undone.')
        }

        if ($null -eq $ApprovalDecision) {
            $finding.Add('ApplyApprovalNotDecided: no approval decision stands behind this apply; naming two files is not the same as reading them.')
        }
        else {
            $changeId = [string](Get-BaselineRecordMember -Node $ApprovalDecision -Name 'ChangeId')

            if (-not (Test-BaselineNodeMember -Node $ApprovalDecision -Name 'Permitted')) {
                $finding.Add('ApplyApprovalDecidedNothing: the approval gate reached no conclusion, and silence is not consent.')
            }
            elseif (-not [bool](Get-BaselineRecordMember -Node $ApprovalDecision -Name 'Permitted')) {
                $refusal = @(Get-BaselineRecordMember -Node $ApprovalDecision -Name 'Finding')
                $finding.Add("ApplyApprovalRefused: the approval gate refused this change: $($refusal -join '; ')")
            }
        }
    }

    return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                Permitted    = ($finding.Count -eq 0)
                Apply        = $Apply
                ChangeId     = $changeId
                PreviewPath  = [string]$PreviewPath
                ApprovalPath = [string]$ApprovalPath
                ArtifactRoot = [string]$ArtifactRoot
                Finding      = @($finding)
            }))
}

# SAFE-007-A2: the function a command sits lexically inside, or nothing when it sits at script
# level. A definition runs nothing on its own, so this is what separates where a command is
# written from where it is reached.
function Get-BaselineEnclosingFunction {
    param([object]$Node)

    $parent = $Node.Parent
    while ($null -ne $parent -and $parent -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) {
        $parent = $parent.Parent
    }

    return $parent
}

# SAFE-007-A2: the earliest line a command can actually run at. A command at script level runs
# where it is written; a command inside a function runs no earlier than the earliest call that
# reaches that function, resolved through however many helpers stand between them. A function
# nothing calls runs nowhere, and a function that reaches itself is not made any earlier by the
# recursion, so both report the last line any ordering could place them at.
function Get-BaselineApplyOrderLine {
    param(
        [object]$Node,
        [object]$Root,
        [System.Collections.Generic.HashSet[string]]$Visited
    )

    $enclosing = Get-BaselineEnclosingFunction -Node $Node
    if ($null -eq $enclosing) { return [int]$Node.Extent.StartLineNumber }

    $name = [string]$enclosing.Name
    if ($Visited.Contains($name)) { return [int]::MaxValue }

    $reached = [int]::MaxValue
    foreach ($candidate in $Root.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        if ([string]$candidate.GetCommandName() -ne $name) { continue }

        $branch = [System.Collections.Generic.HashSet[string]]::new($Visited, [System.StringComparer]::OrdinalIgnoreCase)
        $null = $branch.Add($name)

        $line = Get-BaselineApplyOrderLine -Node $candidate -Root $Root -Visited $branch
        if ($line -lt $reached) { $reached = $line }
    }

    return $reached
}

# SAFE-007-A2: whether the gate is governed by the run's own apply switch. A gate reached outside
# it refuses audit runs that change nothing, which proves nothing about the apply run that does.
function Test-BaselineApplySwitchEnclosure {
    param([object]$Node)

    $child = $Node
    $parent = $Node.Parent

    while ($null -ne $parent) {
        if ($parent -is [System.Management.Automation.Language.IfStatementAst]) {
            foreach ($clause in $parent.Clauses) {
                if (-not [object]::ReferenceEquals($clause.Item2, $child)) { continue }

                $read = @(
                    $clause.Item1.FindAll({ param($node) $node -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) |
                        Where-Object { [string]$_.VariablePath.UserPath -eq 'Apply' }
                )

                if ($read.Count -gt 0) { return $true }
            }
        }

        $child = $parent
        $parent = $parent.Parent
    }

    return $false
}

# SAFE-007-A2: whether a refusal from the gate stops the run. The decision has to be captured
# before anything can test it, an `if` has to test the captured decision, and that branch has to
# terminate: a refusal the run only logs is a refusal that changed the tenant anyway.
function Test-BaselineApplyRefusalEnforced {
    param([object]$Node, [object]$Root)

    $assignment = $Node.Parent
    while ($null -ne $assignment -and $assignment -isnot [System.Management.Automation.Language.AssignmentStatementAst]) {
        $assignment = $assignment.Parent
    }

    if ($null -eq $assignment) { return $false }

    $target = $assignment.Left
    while ($target -is [System.Management.Automation.Language.ConvertExpressionAst]) { $target = $target.Child }
    if ($target -isnot [System.Management.Automation.Language.VariableExpressionAst]) { return $false }

    $name = [string]$target.VariablePath.UserPath

    foreach ($statement in $Root.FindAll({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] }, $true)) {
        foreach ($clause in $statement.Clauses) {
            $read = @(
                $clause.Item1.FindAll({ param($node) $node -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) |
                    Where-Object { [string]$_.VariablePath.UserPath -eq $name }
            )

            if ($read.Count -eq 0) { continue }

            $terminator = @(
                $clause.Item2.Statements |
                    Where-Object {
                        $_ -is [System.Management.Automation.Language.ThrowStatementAst] -or
                        $_ -is [System.Management.Automation.Language.ReturnStatementAst] -or
                        $_ -is [System.Management.Automation.Language.ExitStatementAst]
                    }
            )

            if ($terminator.Count -gt 0) { return $true }
        }
    }

    return $false
}

# SAFE-007-A2: the one order in which an apply can still be refused. The gate is the only thing
# that can withhold a change, so everything it exists to withhold - the credential and every
# tenant mutation - has to come after it decided. This is read off the parsed script rather than
# from a run, because the branch nobody exercised is exactly the one that connects first, and it
# is read from the shipped script rather than from a description of it, because a documented
# ordering nothing checks is the ordering that drifts. The mutation sites are taken from the
# mutation guard report rather than re-derived from the verb, so creating a local directory above
# the gate is not reported as changing a tenant. Every refusal is collected rather than thrown, so
# an operator learns the whole ordering at once instead of one reordering at a time.
function Test-BaselineDeploymentApplyOrder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ScriptPath
    )

    $finding = [System.Collections.Generic.List[string]]::new()

    if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
        $finding.Add("ApplyOrderScriptNotFound: '$ScriptPath' names no file, so there is no shipped apply order to read and nothing a run can be held to.")

        return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                    Ordered        = $false
                    Finding        = @($finding)
                    GateLine       = 0
                    ConnectionSite = @()
                    MutationSite   = @()
                }))
    }

    $parseToken = $null
    $parseError = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Resolve-Path -LiteralPath $ScriptPath).ProviderPath, [ref]$parseToken, [ref]$parseError)

    if (@($parseError).Count -gt 0) {
        throw "ScriptNotParsable: '$ScriptPath' did not parse; $($parseError[0].Message)"
    }

    $requiredParameter = [ordered]@{
        PreviewPath  = 'the preview it was reviewed against, so it applies whatever the configuration happens to say at the moment it runs'
        ApprovalPath = 'the approval that admitted it, so nothing tells it that anyone agreed to the change it is about to make'
        ChangeId     = 'the change it is applying, so the mutation cannot be tied back to the change record that authorised it'
        ArtifactRoot = 'anywhere to write its preview, approval and outcome, so the apply leaves no evidence that it happened'
    }

    $declared = @(
        if ($null -ne $ast.ParamBlock) {
            $ast.ParamBlock.Parameters | ForEach-Object { [string]$_.Name.VariablePath.UserPath }
        }
    )

    foreach ($name in $requiredParameter.Keys) {
        if ($declared -contains $name) { continue }
        $finding.Add("ApplyOrderParameter${name}NotDeclared: the script cannot be handed $($requiredParameter[$name]).")
    }

    $command = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
    $gate = @(
        $command |
            Where-Object { [string]$_.GetCommandName() -eq 'Test-BaselineApplyPrerequisite' } |
            Sort-Object { [int]$_.Extent.StartLineNumber }
    )

    $gateLine = 0
    if ($gate.Count -eq 0) {
        $finding.Add('ApplyOrderGateNotReached: the script never asks the apply prerequisite gate whether it may apply, so it has no gate, only a gate function nobody calls.')
    }
    else {
        $gateLine = [int]$gate[0].Extent.StartLineNumber

        if (-not (Test-BaselineApplySwitchEnclosure -Node $gate[0])) {
            $finding.Add("ApplyOrderGateNotUnderApplySwitch: the gate on line $gateLine is not governed by the run's own apply switch, so it refuses audit runs that change nothing and decides nothing about the apply run that does.")
        }

        if (-not (Test-BaselineApplyRefusalEnforced -Node $gate[0] -Root $ast)) {
            $finding.Add("ApplyOrderGateRefusalNotEnforced: nothing captures the decision on line $gateLine and terminates the run when it refuses, and a gate whose No is advisory is not a gate.")
        }
    }

    $reported = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($entry in @((Get-BaselineMutationGuardReport -ScriptPath $ScriptPath).MutationSite)) {
        $null = $reported.Add(('{0}@{1}' -f $entry.Command, $entry.Line))
    }

    $connectionSite = [System.Collections.Generic.List[object]]::new()
    $mutationSite = [System.Collections.Generic.List[object]]::new()

    foreach ($candidate in $command) {
        $name = [string]$candidate.GetCommandName()
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $line = [int]$candidate.Extent.StartLineNumber
        $isConnection = $name -match '^Connect-'
        $isMutation = $reported.Contains(('{0}@{1}' -f $name, $line))

        if (-not $isConnection -and -not $isMutation) { continue }

        $site = [ordered]@{
            Command       = $name
            Line          = $line
            EffectiveLine = (Get-BaselineApplyOrderLine -Node $candidate -Root $ast `
                    -Visited ([System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)))
        }

        if ($isConnection) { $connectionSite.Add($site) }
        if ($isMutation) { $mutationSite.Add($site) }
    }

    if ($gateLine -gt 0) {
        $earlyConnection = @($connectionSite | Where-Object { [int]$_.EffectiveLine -lt $gateLine })
        if ($earlyConnection.Count -gt 0) {
            $finding.Add("ApplyOrderConnectionBeforeGate: $((@($earlyConnection | ForEach-Object { '{0} reached at line {1}' -f $_.Command, $_.EffectiveLine }) -join '; ')) signs into the tenant before the gate on line $gateLine decides, so the credential the gate exists to withhold is already spent.")
        }

        $earlyMutation = @($mutationSite | Where-Object { [int]$_.EffectiveLine -lt $gateLine })
        if ($earlyMutation.Count -gt 0) {
            $finding.Add("ApplyOrderMutationBeforeGate: $((@($earlyMutation | ForEach-Object { '{0} reached at line {1}' -f $_.Command, $_.EffectiveLine }) -join '; ')) changes the tenant before the gate on line $gateLine decides, so the gate can only refuse it retrospectively, which is not a refusal at all.")
        }
    }

    return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                Ordered        = ($finding.Count -eq 0)
                Finding        = @($finding)
                GateLine       = $gateLine
                ConnectionSite = @($connectionSite)
                MutationSite   = @($mutationSite)
            }))
}

# SAFE-007-A3: the one variable a mutation plan is declared as, and the four artifacts the
# mutating run itself leaves behind. `Preview` and `Approval` are made before the run that mutates
# and are governed by the approval gate, so they are not counted here.
$script:BaselineMutationPlanVariable = 'MutationPlan'
$script:BaselineMutationPlanArtifactReason = [ordered]@{
    PreChange  = 'the run writes no record of the state it found, so the change cannot be shown to have altered only what it meant to.'
    Apply      = 'the run writes no account of what it applied, so the before and after states have nothing between them to explain the difference.'
    Rollback   = 'the run writes no script that puts the tenant back, so the change has to be survived rather than reversed.'
    PostChange = 'the run writes no record of the state it left behind, so it has asserted its own success rather than confirmed it.'
}
$script:BaselineMutationPlanArtifact = @($script:BaselineMutationPlanArtifactReason.Keys)
$script:BaselineToolCommandName = $null

# SAFE-007-A3: the commands this solution ships itself, read from the manifest rather than
# restated here, so an added export cannot silently become an unreviewed exemption. They write
# this run's own records and reach no tenant, so no mutation plan declares them.
function Get-BaselineToolCommandName {
    if ($null -eq $script:BaselineToolCommandName) {
        $manifestPath = Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psd1'
        $script:BaselineToolCommandName = @([string[]](Import-PowerShellDataFile -LiteralPath $manifestPath).FunctionsToExport)
    }

    return $script:BaselineToolCommandName
}

# SAFE-007-A3: what a named parameter was actually bound to, whether it was written as
# `-Name value` or `-Name:value`. A parameter nobody bound is nothing rather than whatever
# element happened to follow it.
function Get-BaselineCommandArgument {
    param([object]$Command, [string]$ParameterName)

    $element = @($Command.CommandElements)
    for ($index = 1; $index -lt $element.Count; $index++) {
        $candidate = $element[$index]
        if ($candidate -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
        if ([string]$candidate.ParameterName -ne $ParameterName) { continue }
        if ($null -ne $candidate.Argument) { return $candidate.Argument }
        if ($index + 1 -lt $element.Count) { return $element[$index + 1] }

        return $null
    }

    return $null
}

# SAFE-007-A3: the literal a plan member was written as. A member assembled from an expression
# names no object at the time the plan is read, so it names nothing here rather than whatever it
# would have evaluated to on some run.
function Get-BaselineMutationPlanMemberValue {
    param([object]$Statement)

    $expression = $Statement
    if ($expression -is [System.Management.Automation.Language.PipelineAst]) {
        if (@($expression.PipelineElements).Count -ne 1) { return '' }

        $element = $expression.PipelineElements[0]
        if ($element -isnot [System.Management.Automation.Language.CommandExpressionAst]) { return '' }

        $expression = $element.Expression
    }

    if ($expression -is [System.Management.Automation.Language.ConstantExpressionAst]) { return [string]$expression.Value }

    return ''
}

# SAFE-007-A3: the operations the script declares, read from the script-level assignment the plan
# is written as. Only the outermost record of each entry is an operation: a record nested inside
# one is a member of that operation rather than a mutation of its own.
function Get-BaselineMutationPlanDeclaration {
    param([object]$Root)

    $declared = $false
    $operation = [System.Collections.Generic.List[object]]::new()

    foreach ($assignment in $Root.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
        $target = $assignment.Left
        while ($target -is [System.Management.Automation.Language.ConvertExpressionAst]) { $target = $target.Child }
        if ($target -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }
        if ([string]$target.VariablePath.UserPath -cne $script:BaselineMutationPlanVariable) { continue }

        $declared = $true

        foreach ($entry in $assignment.Right.FindAll({ param($node) $node -is [System.Management.Automation.Language.HashtableAst] }, $true)) {
            $nested = $false
            $parent = $entry.Parent
            while ($null -ne $parent -and -not [object]::ReferenceEquals($parent, $assignment)) {
                if ($parent -is [System.Management.Automation.Language.HashtableAst]) { $nested = $true; break }
                $parent = $parent.Parent
            }

            if ($nested) { continue }

            $member = [ordered]@{ OperationId = ''; Command = ''; Identity = '' }
            foreach ($pair in $entry.KeyValuePairs) {
                $name = ''
                if ($pair.Item1 -is [System.Management.Automation.Language.ConstantExpressionAst]) { $name = [string]$pair.Item1.Value }
                if (-not [string]::IsNullOrWhiteSpace($name) -and $member.Contains($name)) {
                    $member[$name] = Get-BaselineMutationPlanMemberValue -Statement $pair.Item2
                }
            }

            $operation.Add($member)
        }
    }

    return [pscustomobject]@{ Declared = $declared; Operation = @($operation) }
}

# SAFE-007-A3: whether an `if` exists to stop the run rather than to do something optional. A
# conditional that can abort leaves the run only one way to be past it; one that merely does
# something when asked leaves two, and evidence that depends on which way is evidence nobody can
# count on.
function Test-BaselineMutationPlanAbortive {
    param([object]$Statement)

    $body = @(
        foreach ($clause in $Statement.Clauses) { $clause.Item2 }
        if ($null -ne $Statement.ElseClause) { $Statement.ElseClause }
    )

    foreach ($block in $body) {
        foreach ($inner in $block.Statements) {
            if ($inner -is [System.Management.Automation.Language.ThrowStatementAst] -or
                $inner -is [System.Management.Automation.Language.ReturnStatementAst] -or
                $inner -is [System.Management.Automation.Language.ExitStatementAst]) {
                return $true
            }
        }
    }

    return $false
}

# SAFE-007-A3: whether a branch is part of the path a mutating run takes. The run's own apply
# switch and the `ShouldProcess` decision the operator answered yes to are both conditions that a
# run which changes a tenant has already satisfied, so what is inside them is reached rather than
# skipped.
function Test-BaselineMutationPlanRunClause {
    param([object]$Clause)

    if (Test-BaselineShouldProcessCondition -Condition $Clause.Item1) { return $true }

    $read = @(
        $Clause.Item1.FindAll({ param($node) $node -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) |
            Where-Object { [string]$_.VariablePath.UserPath -eq 'Apply' }
    )

    return ($read.Count -gt 0)
}

# SAFE-007-A3: the artifact writes a mutating run certainly reaches. A definition runs nothing on
# its own, so function bodies are not walked; an optional branch is not entered, because an
# artifact the caller has to ask for is one the tenant is changed without; and nothing after an
# optional branch on the run's own path is counted either, because the run can reach the end by a
# path that skipped it.
function Get-BaselineMutationPlanEmission {
    param(
        [object]$Block,
        [bool]$OnRunPath,
        [System.Collections.Generic.List[object]]$Emission
    )

    foreach ($statement in $Block.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) { continue }

        if ($statement -is [System.Management.Automation.Language.IfStatementAst]) {
            $entered = $false
            foreach ($clause in $statement.Clauses) {
                if (-not (Test-BaselineMutationPlanRunClause -Clause $clause)) { continue }

                Get-BaselineMutationPlanEmission -Block $clause.Item2 -OnRunPath $true -Emission $Emission
                $entered = $true
            }

            if ($entered) { continue }
            if (Test-BaselineMutationPlanAbortive -Statement $statement) { continue }
            if ($OnRunPath) { return }

            continue
        }

        foreach ($candidate in $statement.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            if ([string]$candidate.GetCommandName() -ne 'Write-BaselineChangeArtifact') { continue }

            $Emission.Add($candidate)
        }
    }
}

# SAFE-007-A3: every tenant mutation the shipped script can reach, held to the plan the script
# declares and to the lifecycle a change has to run. The mutation sites are taken from the
# mutation guard report rather than re-derived from the verb, so a local helper and a file-system
# call are not reported as changes to a tenant; the commands this solution ships itself are
# exempt, because they write this run's own records and a plan that declared them would be a plan
# of its own bookkeeping. The lifecycle is read off the parsed script rather than from a run,
# because a step that is missing is missing on every path, and the rollback is only a restoration
# when it is generated from the capture this run took - a rollback written from anything else
# describes a tenant nobody observed. Every refusal is collected rather than thrown, so an
# operator learns the whole gap at once instead of one omission at a time.
function Test-BaselineDeploymentMutationPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ScriptPath
    )

    $finding = [System.Collections.Generic.List[string]]::new()

    if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
        $finding.Add("MutationPlanScriptNotFound: '$ScriptPath' names no file, so there is no shipped mutation plan to read and no run that can be held to one.")

        return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                    Planned      = $false
                    Finding      = @($finding)
                    Operation    = @()
                    MutationSite = @()
                    Artifact     = @()
                }))
    }

    $parseToken = $null
    $parseError = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Resolve-Path -LiteralPath $ScriptPath).ProviderPath, [ref]$parseToken, [ref]$parseError)

    if (@($parseError).Count -gt 0) {
        throw "ScriptNotParsable: '$ScriptPath' did not parse; $($parseError[0].Message)"
    }

    $plan = Get-BaselineMutationPlanDeclaration -Root $ast
    if (-not $plan.Declared) {
        $finding.Add('MutationPlanScriptNotDeclared: the script declares no mutation plan, so every change it makes is applied outside a plan anyone reviewed, captured a prior state for or can roll back.')
    }

    $declaredCommand = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($operation in $plan.Operation) {
        $operationId = [string]$operation['OperationId']

        if ([string]::IsNullOrWhiteSpace([string]$operation['Command'])) {
            $finding.Add("MutationPlanOperationCommandNotNamed: operation '$operationId' names no command, so it cannot be matched to the mutation it covers and clears every mutation and none of them.")
        }
        else {
            $null = $declaredCommand.Add([string]$operation['Command'])
        }

        if ([string]::IsNullOrWhiteSpace([string]$operation['Identity'])) {
            $finding.Add("MutationPlanOperationIdentityNotNamed: operation '$operationId' names no identity, so nothing says which object it changes, no prior state can be captured for it and no restore can be written.")
        }
    }

    $toolCommand = @(Get-BaselineToolCommandName)
    $site = [System.Collections.Generic.List[object]]::new()
    $undeclared = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

    foreach ($entry in @((Get-BaselineMutationGuardReport -ScriptPath $ScriptPath).MutationSite)) {
        $name = [string]$entry['Command']
        $covered = ($toolCommand -contains $name) -or $declaredCommand.Contains($name)

        $site.Add([ordered]@{ Command = $name; Line = [int]$entry['Line']; Declared = $covered })

        if ($covered -or -not $plan.Declared) { continue }
        if (-not $undeclared.Add($name)) { continue }

        $finding.Add("MutationPlanOperationNotDeclared: the run can reach '$name', which the mutation plan does not declare, so that change is applied outside the plan that was previewed and approved.")
    }

    $command = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
    $called = {
        param([string]$Name)

        return @($command | Where-Object { [string]$_.GetCommandName() -eq $Name })
    }

    $assigned = [System.Collections.Generic.List[object]]::new()
    $capturedBy = @{}
    foreach ($assignment in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
        $target = $assignment.Left
        while ($target -is [System.Management.Automation.Language.ConvertExpressionAst]) { $target = $target.Child }
        if ($target -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }

        $name = [string]$target.VariablePath.UserPath
        $line = [int]$assignment.Extent.StartLineNumber
        $assigned.Add([pscustomobject]@{ Name = $name; Line = $line })

        $produced = @(
            $assignment.Right.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
                Where-Object { [string]$_.GetCommandName() -eq 'New-BaselineChangeStateCapture' }
        )

        if ($produced.Count -eq 0) { continue }
        if (-not $capturedBy.ContainsKey($name) -or $line -lt $capturedBy[$name]) { $capturedBy[$name] = $line }
    }

    if (@(& $called 'New-BaselineChangeStateCapture').Count -eq 0) {
        $finding.Add('MutationPlanLifecycleStateNotCaptured: nothing records what the tenant held before this run overwrote it, so a prior state read from anywhere else is whatever the last run left behind and the change has nothing to be put back to.')
    }

    if (@(& $called 'New-BaselineMutationJournal').Count -eq 0) {
        $finding.Add('MutationPlanLifecycleMutationNotJournalled: nothing records the state each mutation actually reached, so the run reports its own plan back to itself instead of what the tenant now holds.')
    }

    if (@(& $called 'Resolve-BaselinePartialApplication').Count -eq 0) {
        $finding.Add('MutationPlanLifecyclePartialApplicationNotResolved: nothing reconciles the declared plan against the journal, so a half-applied tenant is indistinguishable from a finished one.')
    }

    $restored = @(
        foreach ($candidate in @(& $called 'New-BaselineRollbackScript')) {
            $argument = Get-BaselineCommandArgument -Command $candidate -ParameterName 'Capture'
            if ($argument -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }

            $name = [string]$argument.VariablePath.UserPath
            if (-not $capturedBy.ContainsKey($name)) { continue }
            if ($capturedBy[$name] -ge [int]$candidate.Extent.StartLineNumber) { continue }

            $candidate
        }
    )

    if ($restored.Count -eq 0) {
        $finding.Add('MutationPlanLifecycleRollbackNotGeneratedFromCapture: no restoration is generated from the capture this run took, so a capture taken and never turned into a script leaves a tenant that reads as reversible and is not.')
    }

    $decided = @(
        foreach ($candidate in @(& $called 'Test-BaselineChangeSuccess')) {
            if ($null -eq (Get-BaselineCommandArgument -Command $candidate -ParameterName 'Application')) { continue }

            $postChange = Get-BaselineCommandArgument -Command $candidate -ParameterName 'PostChange'
            if ($postChange -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }

            $name = [string]$postChange.VariablePath.UserPath
            $line = [int]$candidate.Extent.StartLineNumber
            if (@($assigned | Where-Object { $_.Name -eq $name -and $_.Line -lt $line }).Count -eq 0) { continue }

            $candidate
        }
    )

    if ($decided.Count -eq 0) {
        $finding.Add('MutationPlanLifecycleSuccessNotDecidedFromPostChange: no verdict is reached from the record of what the run applied together with evidence read back from the tenant afterwards, so the run proves only that its commands returned.')
    }

    $emission = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $ast.EndBlock) {
        Get-BaselineMutationPlanEmission -Block $ast.EndBlock -OnRunPath $false -Emission $emission
    }

    $emitted = @{}
    foreach ($candidate in $emission) {
        $argument = Get-BaselineCommandArgument -Command $candidate -ParameterName 'Artifact'
        if ($argument -isnot [System.Management.Automation.Language.ConstantExpressionAst]) { continue }

        $name = [string]$argument.Value
        if (-not $emitted.ContainsKey($name)) { $emitted[$name] = [int]$candidate.Extent.StartLineNumber }
    }

    $artifact = foreach ($name in $script:BaselineMutationPlanArtifact) {
        $present = $emitted.ContainsKey($name)
        if (-not $present) {
            $finding.Add("MutationPlanArtifact${name}NotEmitted: $($script:BaselineMutationPlanArtifactReason[$name])")
        }

        [ordered]@{
            Artifact = $name
            Emitted  = $present
            Line     = $(if ($present) { $emitted[$name] } else { 0 })
        }
    }

    return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                Planned      = ($finding.Count -eq 0)
                Finding      = @($finding)
                Operation    = @($plan.Operation)
                MutationSite = @($site)
                Artifact     = @($artifact)
            }))
}

# GATE-004: the only exit statuses this solution speaks. An automation caller has to be able to
# act on which kind of failure this was - a configuration it can fix, a connection it can retry,
# a collection it can rerun, a compliance gap it must escalate, an approval it must obtain, or a
# defect in this tool - and a run that reports every one of those as `1` tells it none of that.
# Every code sits inside 1-125: 126 and 127 already mean "could not execute" to a POSIX shell,
# 128 and above are signal terminations, and 0 is reserved for the one outcome that is success.
function Get-BaselineExitCodeContract {
    [CmdletBinding()]
    param()

    return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                Success       = 0
                Configuration = 10
                Connection    = 11
                Collection    = 12
                Compliance    = 13
                Approval      = 14
                Internal      = 15
            }))
}

# A control decided `Error` was never measured, so it is a rerun the caller can act on rather than
# a compliance gap it must escalate. The rest were measured and found wanting, or could not be
# decided at all, and neither is a control anyone has verified.
$script:BaselineCollectionStatus = @('Error')
$script:BaselineComplianceStatus = @('Fail', 'Manual', 'NotEntitled', 'Unverified')

# The one refusal the caller resolves by obtaining an approval rather than by fixing a control.
$script:BaselineApprovalFinding = 'GoLiveExceptionRefused'

# GATE-004: which of the contract's outcomes a finished run resolved to. The run is read here and
# nowhere else, so an entry script cannot decide its own exit: a collection that never happened, a
# control nobody could decide and an approval nobody granted are three different answers to the
# caller, and a script that resolves them itself is a script that can quietly resolve them all to
# zero.
function Get-BaselineRunOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Check,

        [AllowNull()]
        [object]$GoLive
    )

    if ($null -eq $Check) {
        throw 'RunOutcomeCheckRequired: a run outcome must be decided from the verdicts the run produced.'
    }

    $code = Get-BaselineExitCodeContract
    $decided = @($Check | Where-Object { $null -ne $_ })

    $outcome = 'Success'
    $controlId = ''
    $reason = ''

    if ($decided.Count -eq 0) {
        $outcome = 'Collection'
        $reason = 'RunDecidedNothing: the run produced no verdicts at all, so there is nothing it could have been found compliant against.'
    }
    else {
        $status = @(foreach ($result in $decided) { [string](Get-BaselineRecordMember -Node $result -Name 'Status') })
        $uncollected = @(0..($decided.Count - 1) | Where-Object { $status[$_] -cin $script:BaselineCollectionStatus })
        $unverified = @(0..($decided.Count - 1) | Where-Object { $status[$_] -cin $script:BaselineComplianceStatus })

        if ($uncollected.Count -gt 0) {
            $index = $uncollected[0]
            $outcome = 'Collection'
            $controlId = [string](Get-BaselineRecordMember -Node $decided[$index] -Name 'ControlId')
            $reason = "ControlNotCollected: '$controlId' was decided '$($status[$index])'."
        }
        elseif ($unverified.Count -gt 0) {
            $index = $unverified[0]
            $outcome = 'Compliance'
            $controlId = [string](Get-BaselineRecordMember -Node $decided[$index] -Name 'ControlId')
            $reason = "ControlNotPassed: '$controlId' was decided '$($status[$index])'."
        }
    }

    if ($outcome -ceq 'Success' -and $null -ne $GoLive -and -not [bool](Get-BaselineRecordMember -Node $GoLive -Name 'Admitted')) {
        $finding = @(Get-BaselineRecordMember -Node $GoLive -Name 'Finding')
        $ungranted = @($finding | Where-Object { ([string]$_).StartsWith($script:BaselineApprovalFinding, [System.StringComparison]::Ordinal) })
        $outcome = if ($ungranted.Count -gt 0) { 'Approval' } else { 'Compliance' }

        $result = Get-BaselineRecordMember -Node $GoLive -Name 'Result'
        $controlId = [string](Get-BaselineRecordMember -Node $result -Name 'ControlId')
        $reason = [string](Get-BaselineRecordMember -Node $result -Name 'Reason')
    }

    $member = [ordered]@{
        Outcome   = $outcome
        ExitCode  = $code.$outcome
        ControlId = $controlId
        Reason    = $reason
    }

    return , (ConvertTo-ImmutableBaselineNode -Node $member)
}


$script:ControlResultVerdictMember = @('Status', 'Normalized', 'GoLiveSuccess')

function Test-BaselineEvidenceVerdict {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Node
    )

    if ($null -eq $Node -or $Node -is [string] -or $Node.GetType().IsPrimitive) {
        return $false
    }

    if ($Node -is [System.Collections.IDictionary]) {
        $key = @(foreach ($name in $Node.Keys) { [string]$name })
        $present = @($script:ControlResultVerdictMember | Where-Object { $key -ccontains $_ })
        return $present.Count -eq $script:ControlResultVerdictMember.Count
    }

    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        $present = @($script:ControlResultVerdictMember | Where-Object { $Node.PSObject.Properties.Match($_).Count -gt 0 })
        return $present.Count -eq $script:ControlResultVerdictMember.Count
    }

    if ($Node -is [System.Collections.IList]) {
        foreach ($item in $Node) {
            if (Test-BaselineEvidenceVerdict -Node $item) { return $true }
        }
    }

    return $false
}

function New-BaselineEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ControlId,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Source,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Command,

        [AllowNull()]
        [object]$Value,

        [switch]$Failed,

        [string]$FailureReason,

        [datetime]$CollectedAtUtc = [datetime]::UtcNow
    )

    if ([string]::IsNullOrWhiteSpace($ControlId)) {
        throw 'ControlIdRequired: an evidence record must name the control it was collected for.'
    }

    if ([string]::IsNullOrWhiteSpace($Source)) {
        throw 'EvidenceSourceRequired: an evidence record must name the source it was collected from.'
    }

    if ([string]::IsNullOrWhiteSpace($Command)) {
        throw 'EvidenceCommandRequired: an evidence record must name the command that produced it.'
    }

    # A payload that was never supplied is not the same observation as a service that returned
    # nothing, so the parameter must be bound even when its value is null.
    if (-not $PSBoundParameters.ContainsKey('Value')) {
        throw "EvidenceValueRequired: '$Command' recorded no collected value; pass -Value explicitly, using `$null for a command that returned nothing."
    }

    if ($CollectedAtUtc.Kind -ne [System.DateTimeKind]::Utc) {
        throw "CollectionTimeNotUtc: the collection time for '$ControlId' is '$($CollectedAtUtc.Kind)'; evidence age is only decidable against UTC."
    }

    if ($Failed -and [string]::IsNullOrWhiteSpace($FailureReason)) {
        throw "FailureReasonRequired: the failed collection of '$Command' for '$ControlId' must name why it failed."
    }

    if (-not $Failed -and -not [string]::IsNullOrWhiteSpace($FailureReason)) {
        throw "FailureReasonUnexpected: '$Command' for '$ControlId' reports a failure reason without being marked failed."
    }

    if (Test-BaselineEvidenceVerdict -Node $Value) {
        throw "EvidenceCarriesVerdict: the payload recorded for '$ControlId' already carries a control verdict; collectors observe and evaluators decide."
    }

    $member = [ordered]@{
        ControlId      = $ControlId
        Source         = $Source
        Command        = $Command
        Collected      = -not [bool]$Failed
        FailureReason  = if ($Failed) { $FailureReason } else { $null }
        Value          = (ConvertTo-ImmutableBaselineNode -Node $Value)
        CollectedAtUtc = $CollectedAtUtc
    }

    return , (ConvertTo-ImmutableBaselineNode -Node $member)
}

# EVD-001: the collecting half of the separation. The collector owns when the service is reached
# and what is recorded; it owns no opinion about what the answer means. A collection that threw is
# a recorded outcome rather than an exception, so one refused command costs one control instead of
# discarding the whole run, and the payload is never inspected beyond refusing a collector that
# already decided.
function Get-BaselineEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ControlId,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Source,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Command,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Collection
    )

    if ([string]::IsNullOrWhiteSpace($ControlId)) {
        throw 'ControlIdRequired: a collection must name the control it is collected for.'
    }

    if ([string]::IsNullOrWhiteSpace($Source)) {
        throw "EvidenceSourceRequired: the collection for '$ControlId' must name the source it reaches."
    }

    if ([string]::IsNullOrWhiteSpace($Command)) {
        throw "EvidenceCommandRequired: the collection for '$ControlId' must name the command it runs."
    }

    if ($null -eq $Collection) {
        throw "CollectionRequired: '$Command' cannot be collected for '$ControlId' without a collection to run."
    }

    # Assigning rather than wrapping keeps the shape the service returned: a scalar stays scalar
    # and a collection stays a collection, including a collection of one.
    try {
        $payload = & $Collection
    }
    catch {
        return New-BaselineEvidence -ControlId $ControlId -Source $Source -Command $Command -Value $null `
            -Failed -FailureReason "CollectionFailed: '$Command' did not complete for '$ControlId': $($_.Exception.Message)"
    }

    return New-BaselineEvidence -ControlId $ControlId -Source $Source -Command $Command -Value $payload
}

# EVD-001: a control is decided by an evaluator over one already-collected record. Every way an
# evaluator can misbehave, and every record that was never collected, becomes an `Error` result
# rather than an exception, so one defective control degrades itself and not the whole run. The
# caller's own mistakes - no control, no record, no evaluator, the wrong record - still throw,
# because those produce no evidence to report against.
$script:BaselineEvidenceMember = @('ControlId', 'Source', 'Command', 'Collected', 'FailureReason', 'Value', 'CollectedAtUtc')

function Test-BaselineEvidenceRecord {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Node
    )

    if ($null -eq $Node -or $Node -is [string]) {
        return $false
    }

    if ($Node -is [System.Collections.IDictionary]) {
        $key = @(foreach ($name in $Node.Keys) { [string]$name })
        $present = @($script:BaselineEvidenceMember | Where-Object { $key -ccontains $_ })
        return $present.Count -eq $script:BaselineEvidenceMember.Count
    }

    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        $present = @($script:BaselineEvidenceMember | Where-Object { $Node.PSObject.Properties.Match($_).Count -gt 0 })
        return $present.Count -eq $script:BaselineEvidenceMember.Count
    }

    return $false
}

function Get-BaselineRecordMember {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Node,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Node) {
        return $null
    }

    if ($Node -is [System.Collections.IDictionary]) {
        $key = @(foreach ($declared in $Node.Keys) { [string]$declared })
        if ($key -ccontains $Name) {
            $value = $Node[$Name]
            return $value
        }

        return $null
    }

    if ($Node.PSObject.Properties.Match($Name).Count -gt 0) {
        $value = $Node.PSObject.Properties[$Name].Value
        return $value
    }

    return $null
}

function Test-BaselineControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ControlId,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Evaluator
    )

    if ([string]::IsNullOrWhiteSpace($ControlId)) {
        throw 'ControlIdRequired: a control evaluation must name the control it decides.'
    }

    if ($null -eq $Evidence) {
        throw "EvidenceRequired: '$ControlId' cannot be decided without an evidence record; collect first, then evaluate."
    }

    if (-not (Test-BaselineEvidenceRecord -Node $Evidence)) {
        throw "EvidenceNotRecognized: the evidence supplied for '$ControlId' is not a baseline evidence record; pass the output of New-BaselineEvidence."
    }

    if ($null -eq $Evaluator) {
        throw "EvaluatorRequired: '$ControlId' cannot be decided without an evaluator."
    }

    $evidenceControlId = [string](Get-BaselineRecordMember -Node $Evidence -Name 'ControlId')
    if ($evidenceControlId -cne $ControlId) {
        throw "EvidenceControlMismatch: '$ControlId' cannot be decided from a record collected for '$evidenceControlId'."
    }

    if (-not (Get-BaselineRecordMember -Node $Evidence -Name 'Collected')) {
        $failureReason = [string](Get-BaselineRecordMember -Node $Evidence -Name 'FailureReason')
        return New-ControlResult -ControlId $ControlId -Status 'Error' -Evidence $Evidence `
            -Reason "EvidenceCollectionFailed: $failureReason"
    }

    try {
        $verdict = @(& $Evaluator $Evidence)
    }
    catch {
        return New-ControlResult -ControlId $ControlId -Status 'Error' -Evidence $Evidence `
            -Reason "EvaluatorThrew: the evaluator for '$ControlId' failed: $($_.Exception.Message)"
    }

    if ($verdict.Count -eq 0) {
        return New-ControlResult -ControlId $ControlId -Status 'Error' -Evidence $Evidence `
            -Reason "EvaluatorReturnedNoVerdict: the evaluator for '$ControlId' decided nothing."
    }

    if ($verdict.Count -gt 1) {
        return New-ControlResult -ControlId $ControlId -Status 'Error' -Evidence $Evidence `
            -Reason "EvaluatorReturnedMultipleVerdicts: the evaluator for '$ControlId' returned $($verdict.Count) verdicts; a control holds exactly one."
    }

    $decision = $verdict[0]
    $verdictControlId = [string](Get-BaselineRecordMember -Node $decision -Name 'ControlId')
    if (-not [string]::IsNullOrWhiteSpace($verdictControlId) -and $verdictControlId -cne $ControlId) {
        return New-ControlResult -ControlId $ControlId -Status 'Error' -Evidence $Evidence `
            -Reason "EvaluatorControlMismatch: the evaluator for '$ControlId' returned a verdict naming '$verdictControlId'."
    }

    $status = [string](Get-BaselineRecordMember -Node $decision -Name 'Status')
    if ([string]::IsNullOrWhiteSpace($status)) {
        return New-ControlResult -ControlId $ControlId -Status 'Error' -Evidence $Evidence `
            -Reason "EvaluatorVerdictMissingStatus: the evaluator for '$ControlId' returned a verdict that carries no status."
    }

    $contract = Get-BaselineResultContract
    $declaredStatus = @($contract.NormalizedStatus) + @($contract.NonNormalizedStatus)
    if ($status -cnotin $declaredStatus) {
        return New-ControlResult -ControlId $ControlId -Status 'Error' -Evidence $Evidence `
            -Reason "UnknownControlStatus: the evaluator for '$ControlId' returned '$status', which the result contract does not declare."
    }

    $reason = [string](Get-BaselineRecordMember -Node $decision -Name 'Reason')
    if ($status -cne 'Pass' -and [string]::IsNullOrWhiteSpace($reason)) {
        return New-ControlResult -ControlId $ControlId -Status 'Error' -Evidence $Evidence `
            -Reason "EvaluatorReasonMissing: the evaluator for '$ControlId' returned '$status' without recording why."
    }

    return New-ControlResult -ControlId $ControlId -Status $status -Reason $reason -Evidence $Evidence
}

# EVD-002: the control registry. One entry per catalog control, naming the priority it is gated at,
# the deployment profiles it applies to, the licence prerequisites that entitle it, the collector
# that observes it, the evaluator that decides it, and the evidence path it is recorded under. A
# control that is absent here is a control nobody collects, so the registry refuses anything it
# cannot place: an unnamed control, an unknown priority or profile, a control registered twice, or
# two controls claiming one evidence path.
$script:ControlRegistryMember = @('ControlId', 'Priority', 'ApplicableProfile', 'Prerequisite', 'Collector', 'Evaluator', 'EvidencePath')
$script:ControlRegistryPriority = @('MUST', 'SHOULD')

# The registry names profiles the way the catalog does; each name resolves to a declared deployment profile.
$script:ControlRegistryProfile = [ordered]@{
    Native  = 'MicrosoftNative'
    Gateway = 'ThirdPartyGateway'
}

$script:ControlRegistryPrerequisite = @('EOP', 'MDO P1', 'MDO P2', 'E3', 'E5 Compliance')

function Get-BaselineRecordMemberName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Node
    )

    if ($Node -is [System.Collections.IDictionary]) {
        return @(foreach ($key in $Node.Keys) { [string]$key })
    }

    return @(foreach ($property in $Node.PSObject.Properties) { $property.Name })
}

function New-BaselineControlRegistry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Definition
    )

    if ($null -eq $Definition -or @($Definition).Count -eq 0) {
        throw 'ControlDefinitionRequired: a control registry must be built from at least one declared control; a registry that registers nothing evaluates nothing.'
    }

    $registered = [System.Collections.Generic.List[object]]::new()
    $registeredControl = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $registeredPath = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $declaredProfile = @($script:ControlRegistryProfile.Keys)

    foreach ($entry in $Definition) {
        if ($null -eq $entry -or -not ($entry -is [System.Collections.IDictionary] -or $entry -is [System.Management.Automation.PSCustomObject])) {
            throw "ControlDefinitionNotRecognized: a control registry entry must be a record naming $($script:ControlRegistryMember -join ', ')."
        }

        $unknownMember = @((Get-BaselineRecordMemberName -Node $entry) | Where-Object { $_ -cnotin $script:ControlRegistryMember })
        if ($unknownMember.Count -gt 0) {
            throw "UnknownControlRegistryMember: the registry entry declares '$($unknownMember -join ', ')', which the control registry contract does not name."
        }

        $controlId = [string](Get-BaselineRecordMember -Node $entry -Name 'ControlId')
        if ([string]::IsNullOrWhiteSpace($controlId)) {
            throw 'ControlIdRequired: a control registry entry must name the control it registers.'
        }

        $priority = [string](Get-BaselineRecordMember -Node $entry -Name 'Priority')
        if ([string]::IsNullOrWhiteSpace($priority)) {
            throw "ControlPriorityRequired: '$controlId' must name the priority the go-live gate holds it to."
        }

        if ($priority -cnotin $script:ControlRegistryPriority) {
            throw "UnknownControlPriority: '$controlId' is gated at '$priority', which is not one of $($script:ControlRegistryPriority -join ', ')."
        }

        $applicableProfile = @(@(Get-BaselineRecordMember -Node $entry -Name 'ApplicableProfile') |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                ForEach-Object { [string]$_ })
        if ($applicableProfile.Count -eq 0) {
            throw "ControlProfileRequired: '$controlId' must name at least one deployment profile it applies to."
        }

        $unknownProfile = @($applicableProfile | Where-Object { $_ -cnotin $declaredProfile })
        if ($unknownProfile.Count -gt 0) {
            throw "UnknownControlProfile: '$controlId' applies to '$($unknownProfile -join ', ')', which is not one of $($declaredProfile -join ', ')."
        }

        $prerequisite = @(@(Get-BaselineRecordMember -Node $entry -Name 'Prerequisite') |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                ForEach-Object { [string]$_ })
        if ($prerequisite.Count -eq 0) {
            throw "ControlPrerequisiteRequired: '$controlId' must name at least one licence tier that entitles it."
        }

        $unknownPrerequisite = @($prerequisite | Where-Object { $_ -cnotin $script:ControlRegistryPrerequisite })
        if ($unknownPrerequisite.Count -gt 0) {
            throw "UnknownControlPrerequisite: '$controlId' requires '$($unknownPrerequisite -join ', ')', which is not one of $($script:ControlRegistryPrerequisite -join ', ')."
        }

        $collector = [string](Get-BaselineRecordMember -Node $entry -Name 'Collector')
        if ([string]::IsNullOrWhiteSpace($collector)) {
            throw "ControlCollectorRequired: '$controlId' must name the collector that observes it."
        }

        $evaluator = [string](Get-BaselineRecordMember -Node $entry -Name 'Evaluator')
        if ([string]::IsNullOrWhiteSpace($evaluator)) {
            throw "ControlEvaluatorRequired: '$controlId' must name the evaluator that decides it."
        }

        $evidencePath = [string](Get-BaselineRecordMember -Node $entry -Name 'EvidencePath')
        if ([string]::IsNullOrWhiteSpace($evidencePath)) {
            throw "ControlEvidencePathRequired: '$controlId' must name the evidence path it is recorded under."
        }

        if (-not $registeredControl.Add($controlId)) {
            throw "ControlDuplicated: '$controlId' is registered more than once; a control holds exactly one entry."
        }

        if (-not $registeredPath.Add($evidencePath)) {
            throw "EvidencePathDuplicated: '$controlId' records to '$evidencePath', which another control already claims."
        }

        $member = [ordered]@{
            ControlId         = $controlId
            Priority          = $priority
            ApplicableProfile = $applicableProfile
            Prerequisite      = $prerequisite
            Collector         = $collector
            Evaluator         = $evaluator
            EvidencePath      = $evidencePath
        }

        $registered.Add((ConvertTo-ImmutableBaselineNode -Node $member))
    }

    return , ([System.Array]::AsReadOnly([object[]]$registered.ToArray()))
}

# EVD-002: the shipped declaration, in catalog order. This is the only place a control is added to
# or removed from the solution, so the catalog and the run cannot drift apart silently.
$script:BaselineControlDefinition = @(
    [ordered]@{ ControlId = 'EXO-001'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-AcceptedDomainEvidence'; Evaluator = 'Test-AcceptedDomainControl'; EvidencePath = 'exchangeOnline.acceptedDomain' }
    [ordered]@{ ControlId = 'EXO-002'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-SmtpAuthenticationEvidence'; Evaluator = 'Test-SmtpAuthenticationControl'; EvidencePath = 'exchangeOnline.transportConfig' }
    [ordered]@{ ControlId = 'EXO-003'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-ConditionalAccessEvidence'; Evaluator = 'Test-ConditionalAccessControl'; EvidencePath = 'graph.conditionalAccessPolicy' }
    [ordered]@{ ControlId = 'EXO-004'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-OutboundForwardingEvidence'; Evaluator = 'Test-OutboundForwardingControl'; EvidencePath = 'exchangeOnline.outboundSpamFilterPolicy' }
    [ordered]@{ ControlId = 'EXO-005'; Priority = 'SHOULD'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-ExternalPostmasterEvidence'; Evaluator = 'Test-ExternalPostmasterControl'; EvidencePath = 'exchangeOnline.externalPostmaster' }
    [ordered]@{ ControlId = 'EXO-006'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-MailboxAuditingEvidence'; Evaluator = 'Test-MailboxAuditingControl'; EvidencePath = 'exchangeOnline.mailboxAudit' }
    [ordered]@{ ControlId = 'EXO-007'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-ExternalSenderTagEvidence'; Evaluator = 'Test-ExternalSenderTagControl'; EvidencePath = 'exchangeOnline.externalInOutlook' }
    [ordered]@{ ControlId = 'EXO-008'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-RemoteDomainEvidence'; Evaluator = 'Test-RemoteDomainControl'; EvidencePath = 'exchangeOnline.remoteDomain' }
    [ordered]@{ ControlId = 'EXO-009'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-ClientProtocolEvidence'; Evaluator = 'Test-ClientProtocolControl'; EvidencePath = 'exchangeOnline.clientProtocol' }
    [ordered]@{ ControlId = 'EXO-010'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-ExchangeRoleAssignmentEvidence'; Evaluator = 'Test-ExchangeRoleAssignmentControl'; EvidencePath = 'exchangeOnline.roleAssignment' }
    [ordered]@{ ControlId = 'EXO-011'; Priority = 'SHOULD'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-MtaStsEvidence'; Evaluator = 'Test-MtaStsControl'; EvidencePath = 'dns.mtaSts' }
    [ordered]@{ ControlId = 'EXO-012'; Priority = 'SHOULD'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-AddInAcquisitionEvidence'; Evaluator = 'Test-AddInAcquisitionControl'; EvidencePath = 'exchangeOnline.roleAssignmentPolicy' }
    [ordered]@{ ControlId = 'MDO-001'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-StandardPresetEvidence'; Evaluator = 'Test-StandardPresetControl'; EvidencePath = 'defender.standardPreset' }
    [ordered]@{ ControlId = 'MDO-002'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-StrictPresetEvidence'; Evaluator = 'Test-StrictPresetControl'; EvidencePath = 'defender.strictPreset' }
    [ordered]@{ ControlId = 'MDO-003'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('MDO P1'); Collector = 'Get-BuiltInProtectionEvidence'; Evaluator = 'Test-BuiltInProtectionControl'; EvidencePath = 'defender.builtInProtection' }
    [ordered]@{ ControlId = 'MDO-004'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('MDO P1'); Collector = 'Get-SafeAttachmentsEvidence'; Evaluator = 'Test-SafeAttachmentsControl'; EvidencePath = 'defender.atpPolicyForO365' }
    [ordered]@{ ControlId = 'MDO-005'; Priority = 'SHOULD'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('MDO P2'); Collector = 'Get-SafeDocumentsEvidence'; Evaluator = 'Test-SafeDocumentsControl'; EvidencePath = 'defender.safeDocuments' }
    [ordered]@{ ControlId = 'MDO-006'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-ReportSubmissionEvidence'; Evaluator = 'Test-ReportSubmissionControl'; EvidencePath = 'defender.reportSubmissionPolicy' }
    [ordered]@{ ControlId = 'MDO-007'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-TenantAllowBlockListEvidence'; Evaluator = 'Test-TenantAllowBlockListControl'; EvidencePath = 'defender.tenantAllowBlockList' }
    [ordered]@{ ControlId = 'MDO-008'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-QuarantinePolicyEvidence'; Evaluator = 'Test-QuarantinePolicyControl'; EvidencePath = 'defender.quarantinePolicy' }
    [ordered]@{ ControlId = 'MDO-009'; Priority = 'SHOULD'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('MDO P2'); Collector = 'Get-PriorityAccountEvidence'; Evaluator = 'Test-PriorityAccountControl'; EvidencePath = 'defender.priorityAccount' }
    [ordered]@{ ControlId = 'PP-001'; Priority = 'MUST'; ApplicableProfile = @('Gateway'); Prerequisite = @('EOP'); Collector = 'Get-GatewayInboundConnectorEvidence'; Evaluator = 'Test-GatewayInboundConnectorControl'; EvidencePath = 'exchangeOnline.inboundConnector' }
    [ordered]@{ ControlId = 'PP-002'; Priority = 'MUST'; ApplicableProfile = @('Gateway'); Prerequisite = @('EOP'); Collector = 'Get-EnhancedFilteringEvidence'; Evaluator = 'Test-EnhancedFilteringControl'; EvidencePath = 'exchangeOnline.enhancedFiltering' }
    [ordered]@{ ControlId = 'PP-003'; Priority = 'MUST'; ApplicableProfile = @('Gateway'); Prerequisite = @('EOP'); Collector = 'Get-GatewayOutboundConnectorEvidence'; Evaluator = 'Test-GatewayOutboundConnectorControl'; EvidencePath = 'exchangeOnline.outboundConnector' }
    [ordered]@{ ControlId = 'PP-004'; Priority = 'SHOULD'; ApplicableProfile = @('Gateway'); Prerequisite = @('EOP'); Collector = 'Get-TrustedArcSealerEvidence'; Evaluator = 'Test-TrustedArcSealerControl'; EvidencePath = 'exchangeOnline.arcConfig' }
    [ordered]@{ ControlId = 'PP-005'; Priority = 'MUST'; ApplicableProfile = @('Native'); Prerequisite = @('EOP'); Collector = 'Get-PartnerInboundConnectorEvidence'; Evaluator = 'Test-PartnerInboundConnectorControl'; EvidencePath = 'exchangeOnline.partnerInboundConnector' }
    [ordered]@{ ControlId = 'AUTH-001'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-DkimEvidence'; Evaluator = 'Test-DkimControl'; EvidencePath = 'dns.dkim' }
    [ordered]@{ ControlId = 'AUTH-002'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-SpfEvidence'; Evaluator = 'Test-SpfControl'; EvidencePath = 'dns.spf' }
    [ordered]@{ ControlId = 'AUTH-003'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-DmarcEvidence'; Evaluator = 'Test-DmarcControl'; EvidencePath = 'dns.dmarc' }
    [ordered]@{ ControlId = 'ABN-001'; Priority = 'MUST'; ApplicableProfile = @('Gateway'); Prerequisite = @('EOP'); Collector = 'Get-AbnormalIntegrationEvidence'; Evaluator = 'Test-AbnormalIntegrationControl'; EvidencePath = 'graph.abnormalIntegration' }
    [ordered]@{ ControlId = 'ABN-002'; Priority = 'MUST'; ApplicableProfile = @('Gateway'); Prerequisite = @('EOP'); Collector = 'Get-AbnormalPermissionEvidence'; Evaluator = 'Test-AbnormalPermissionControl'; EvidencePath = 'graph.abnormalPermission' }
    [ordered]@{ ControlId = 'MON-001'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-TelemetrySourceEvidence'; Evaluator = 'Test-TelemetrySourceControl'; EvidencePath = 'monitoring.telemetrySource' }
    [ordered]@{ ControlId = 'MON-002'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-UnifiedAuditEvidence'; Evaluator = 'Test-UnifiedAuditControl'; EvidencePath = 'purview.unifiedAudit' }
    [ordered]@{ ControlId = 'MON-003'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-DriftEvidenceEvidence'; Evaluator = 'Test-DriftEvidenceControl'; EvidencePath = 'monitoring.driftEvidence' }
    [ordered]@{ ControlId = 'OPS-001'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('EOP'); Collector = 'Get-ChangeSafetyEvidence'; Evaluator = 'Test-ChangeSafetyControl'; EvidencePath = 'operations.changeSafety' }
    [ordered]@{ ControlId = 'OPS-002'; Priority = 'SHOULD'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('MDO P2'); Collector = 'Get-IncidentExerciseEvidence'; Evaluator = 'Test-IncidentExerciseControl'; EvidencePath = 'operations.incidentExercise' }
    [ordered]@{ ControlId = 'GOV-001'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('E5 Compliance'); Collector = 'Get-AuditRetentionEvidence'; Evaluator = 'Test-AuditRetentionControl'; EvidencePath = 'purview.auditRetention' }
    [ordered]@{ ControlId = 'GOV-002'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('E3'); Collector = 'Get-DataLossPreventionEvidence'; Evaluator = 'Test-DataLossPreventionControl'; EvidencePath = 'purview.dlpPolicy' }
    [ordered]@{ ControlId = 'GOV-003'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('E3'); Collector = 'Get-MailboxRetentionEvidence'; Evaluator = 'Test-MailboxRetentionControl'; EvidencePath = 'purview.retentionPolicy' }
    [ordered]@{ ControlId = 'GOV-004'; Priority = 'MUST'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('E3'); Collector = 'Get-LitigationHoldEvidence'; Evaluator = 'Test-LitigationHoldControl'; EvidencePath = 'purview.litigationHold' }
    [ordered]@{ ControlId = 'GOV-005'; Priority = 'SHOULD'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('E3'); Collector = 'Get-InformationRightsManagementEvidence'; Evaluator = 'Test-InformationRightsManagementControl'; EvidencePath = 'purview.irmConfiguration' }
    [ordered]@{ ControlId = 'GOV-006'; Priority = 'SHOULD'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('E5 Compliance'); Collector = 'Get-SensitivityLabelEvidence'; Evaluator = 'Test-SensitivityLabelControl'; EvidencePath = 'purview.sensitivityLabel' }
    [ordered]@{ ControlId = 'GOV-007'; Priority = 'SHOULD'; ApplicableProfile = @('Native', 'Gateway'); Prerequisite = @('E5 Compliance'); Collector = 'Get-EDiscoveryReadinessEvidence'; Evaluator = 'Test-EDiscoveryReadinessControl'; EvidencePath = 'purview.eDiscoveryCase' }
)

function Get-BaselineControlRegistry {
    [CmdletBinding()]
    param()

    return , (New-BaselineControlRegistry -Definition $script:BaselineControlDefinition)
}

# EVD-006: EVD-002 refuses an entry that names no collector or evaluator; this refuses an entry
# that names the wrong one. The registry is a declaration of command names, so a name that no
# longer matches a shipped command registers a control that is collected by nobody or decided by
# nobody, and the run reports the tenant clean either way. Two defects are reported apart because
# they cost differently: `Unexported` is a command the module wrote and left out of the export
# list, one line from working, and `Unresolved` is a control shipped as half of itself. A control
# whose collector and evaluator are both absent is backlog the board already tracks, so it is
# reported as `Unbuilt` and is not drift - a guard that is red for unstarted work gets ignored.
function Test-BaselineControlResolution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Registry,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ExportedCommand,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$DefinedCommand
    )

    if ($null -eq $Registry -or @($Registry).Count -eq 0) {
        throw 'ControlRegistryRequired: a resolution check must be handed the registry it holds to the module; a check over no entry reports that nothing is broken.'
    }

    if ($null -eq $ExportedCommand -or @($ExportedCommand).Count -eq 0) {
        throw 'ExportedCommandSurfaceRequired: a resolution check must be handed the commands the module exports; a module that exports nothing is a broken measurement rather than a finding about the registry.'
    }

    if ($null -eq $DefinedCommand -or @($DefinedCommand).Count -eq 0) {
        throw 'DefinedCommandSurfaceRequired: a resolution check must be handed the commands the module defines; without them a function written and left unexported cannot be told from one nobody has written.'
    }

    # PowerShell resolves a command name case-insensitively, so the guard must too, or it reports
    # a defect the runtime does not have.
    $exported = [System.Collections.Generic.HashSet[string]]::new([string[]]@($ExportedCommand | ForEach-Object { ([string]$_).Trim() }), [System.StringComparer]::OrdinalIgnoreCase)
    $defined = [System.Collections.Generic.HashSet[string]]::new([string[]]@($DefinedCommand | ForEach-Object { ([string]$_).Trim() }), [System.StringComparer]::OrdinalIgnoreCase)

    $unresolved = [System.Collections.Generic.List[string]]::new()
    $unexported = [System.Collections.Generic.List[string]]::new()
    $unbuilt = [System.Collections.Generic.List[string]]::new()

    foreach ($entry in $Registry) {
        if ($null -eq $entry -or -not ($entry -is [System.Collections.IDictionary] -or $entry -is [System.Management.Automation.PSCustomObject])) {
            throw 'ControlRegistryEntryNotRecognized: a resolution check reads a registry of records naming a control, a collector and an evaluator.'
        }

        $controlId = [string](Get-BaselineRecordMember -Node $entry -Name 'ControlId')
        $declared = [ordered]@{
            Collector = [string](Get-BaselineRecordMember -Node $entry -Name 'Collector')
            Evaluator = [string](Get-BaselineRecordMember -Node $entry -Name 'Evaluator')
        }

        if ([string]::IsNullOrWhiteSpace($declared['Collector'])) {
            throw "ControlCollectorRequired: '$controlId' names no collector, so there is nothing to resolve and nothing to observe it."
        }

        if ([string]::IsNullOrWhiteSpace($declared['Evaluator'])) {
            throw "ControlEvaluatorRequired: '$controlId' names no evaluator, so there is nothing to resolve and nothing to decide it."
        }

        $absent = [System.Collections.Generic.List[string]]::new()
        foreach ($member in $declared.Keys) {
            $command = ([string]$declared[$member]).Trim()
            $named = "$controlId $member '$command'"

            if ($exported.Contains($command)) {
                continue
            }

            if ($defined.Contains($command)) {
                $unexported.Add($named)
                continue
            }

            $absent.Add($named)
        }

        if ($absent.Count -eq $declared.Count) {
            $unbuilt.Add($controlId)
            continue
        }

        $unresolved.AddRange($absent)
    }

    $member = [ordered]@{
        Satisfied  = ($unresolved.Count -eq 0 -and $unexported.Count -eq 0)
        Registered = @($Registry).Count
        Unresolved = @($unresolved)
        Unexported = @($unexported)
        Unbuilt    = @($unbuilt)
    }

    return , (ConvertTo-ImmutableBaselineNode -Node $member)
}

# EVD-003: the catalog is what a reviewer reads, so it is what every other artifact is measured
# against. The identifiers are read from the document itself rather than restated in code, because
# a restated list drifts silently the moment somebody edits only one of the two. A control row is
# one that names a gated priority, which is what separates the control tables from the AVOID table.
$script:CatalogControlRowPattern = '^\|\s*(?<id>[A-Z]+-\d{3})\s*\|\s*(?<priority>MUST|SHOULD)\s*\|'

function Get-BaselineControlCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'CatalogPathRequired: the control catalog must be named before the controls it declares can be read.'
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "CatalogNotFound: no control catalog exists at '$Path'."
    }

    $declared = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

    foreach ($line in (Get-Content -LiteralPath $Path)) {
        $row = [regex]::Match($line, $script:CatalogControlRowPattern)
        if (-not $row.Success) {
            continue
        }

        $controlId = $row.Groups['id'].Value
        if (-not $seen.Add($controlId)) {
            throw "CatalogControlDuplicated: the control catalog at '$Path' declares '$controlId' more than once; a control is declared once."
        }

        $declared.Add($controlId)
    }

    if ($declared.Count -eq 0) {
        throw "CatalogDeclaresNoControl: the control catalog at '$Path' declares no control; a catalog that demands nothing is satisfied by everything."
    }

    return , ([System.Array]::AsReadOnly([string[]]$declared.ToArray()))
}

# EVD-003: the one comparison that holds an artifact to the catalog. The registry and the evidence
# are both sets of records naming controls, so both are checked the same way and drift is named the
# same way: a catalog control nobody produced is Missing, a produced control the catalog never
# declared is Unknown, and a catalog control produced twice is Duplicated. Each is a way a run can
# read as clean while proving less than it claims, so each is reported separately and by name.
function Test-BaselineControlCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$CatalogPath,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Observed,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Subject
    )

    if ([string]::IsNullOrWhiteSpace($Subject)) {
        throw 'CoverageSubjectRequired: a coverage comparison must name the artifact it holds to the catalog.'
    }

    # Assigning before wrapping matters: the reader returns a read-only collection deliberately
    # protected from pipeline unrolling, so @(call) would yield one element holding the collection.
    $declaredControl = Get-BaselineControlCatalog -Path $CatalogPath
    $catalog = @($declaredControl)

    if ($null -eq $Observed -or @($Observed).Count -eq 0) {
        throw "ObservedControlRequired: '$Subject' names no control; a run that produced nothing has not covered the catalog, it has failed to start."
    }

    $observedId = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $Observed) {
        if ($null -eq $entry -or -not ($entry -is [System.Collections.IDictionary] -or $entry -is [System.Management.Automation.PSCustomObject])) {
            throw "ObservedControlNotRecognized: '$Subject' holds an entry that is not a record naming a control."
        }

        $controlId = [string](Get-BaselineRecordMember -Node $entry -Name 'ControlId')
        if ([string]::IsNullOrWhiteSpace($controlId)) {
            throw "ObservedControlIdRequired: '$Subject' holds a record that names no control."
        }

        $observedId.Add($controlId)
    }

    $distinctObserved = [System.Collections.Generic.HashSet[string]]::new([string[]]$observedId, [System.StringComparer]::Ordinal)
    $catalogControl = [System.Collections.Generic.HashSet[string]]::new([string[]]$catalog, [System.StringComparer]::Ordinal)

    $missing = @($catalog | Where-Object { -not $distinctObserved.Contains($_) })
    $unknown = @($observedId | Where-Object { -not $catalogControl.Contains($_) } | Select-Object -Unique)
    $duplicated = @($observedId | Group-Object -CaseSensitive | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })

    $member = [ordered]@{
        Subject    = $Subject
        Satisfied  = ($missing.Count -eq 0 -and $unknown.Count -eq 0 -and $duplicated.Count -eq 0)
        Catalog    = $catalog
        Missing    = $missing
        Unknown    = $unknown
        Duplicated = $duplicated
    }

    return , (ConvertTo-ImmutableBaselineNode -Node $member)
}

# EVD-004: the evidence envelope must identify the administrator inputs a run used, and the
# envelope is published to readers who are not cleared to hold those inputs. A parameter whose name
# claims a credential is therefore replaced by one fixed marker before the hash is taken, so the
# hash moves when the run's inputs move but never moves with a secret. The name stays in the record
# because newly supplying a credential is a different run, and the redacted names are reported so a
# reader can tell a withheld input from an input that was never supplied.
$script:SensitiveParameterNamePattern = '(?i)(secret|password|passphrase|credential|thumbprint|certificate|privatekey|[^a-z]key$|^key$|token|connectionstring|sharedaccess)'
$script:RedactedParameterValue = '(redacted)'

function Get-BaselineParameterHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'ParameterPathRequired: the administrator parameter file must be named before it can be identified.'
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "ParameterFileNotFound: '$Path' does not exist."
    }

    try {
        $parameter = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    }
    catch {
        throw "ParameterJsonInvalid: '$Path' is not valid JSON. $($_.Exception.Message)"
    }

    if ($parameter -isnot [System.Collections.IDictionary]) {
        throw "ParameterDocumentNotObject: '$Path' must contain a JSON object of administrator inputs."
    }

    $redacted = [System.Collections.Generic.List[string]]::new()
    $record = [ordered]@{}
    foreach ($name in @([string[]]@($parameter.Keys) | Sort-Object -CaseSensitive)) {
        if ($name -match $script:SensitiveParameterNamePattern) {
            $redacted.Add($name)
            $record[$name] = $script:RedactedParameterValue
        }
        else {
            $record[$name] = $parameter[$name]
        }
    }

    $canonicalBytes = [System.Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-CanonicalJson -InputObject $record))

    return , (ConvertTo-ImmutableBaselineNode -Node ([ordered]@{
                Algorithm         = 'SHA256'
                Hash              = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($canonicalBytes)).ToLowerInvariant()
                RedactedParameter = @($redacted)
            }))
}

# EVD-004: the one artifact that leaves the tenant boundary. Everything a reviewer needs to
# re-decide the run is on it and nothing may be inferred: which configuration and which
# administrator inputs produced it, which tenant it describes, which code collected it, which
# change had been applied, which service plans the tenant actually held, what was observed and what
# was decided. The builder refuses anything it cannot place, because a member a caller silently
# omits reads exactly like a fact that was checked and found harmless.
$script:BaselineCollectorVersion = '1.0.0'
$script:BaselineModuleVersion = [string](Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psd1')).ModuleVersion
$script:ControlResultMember = @('ControlId', 'Status', 'Normalized', 'GoLiveSuccess', 'Reason', 'Evidence', 'EvaluatedAtUtc')

function Test-BaselineControlResultRecord {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Node
    )

    if ($null -eq $Node -or $Node -is [string]) {
        return $false
    }

    if ($Node -is [System.Collections.IDictionary]) {
        $key = @(foreach ($name in $Node.Keys) { [string]$name })
        return @($script:ControlResultMember | Where-Object { $key -ccontains $_ }).Count -eq $script:ControlResultMember.Count
    }

    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        return @($script:ControlResultMember | Where-Object { $Node.PSObject.Properties.Match($_).Count -gt 0 }).Count -eq $script:ControlResultMember.Count
    }

    return $false
}

function New-BaselineEvidenceEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Context,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$OrganizationName,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ParameterPath,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Check,

        [AllowEmptyString()]
        [string]$PreviewId = '',

        [AllowEmptyString()]
        [string]$ChangeId = ''
    )

    if ($null -eq $Context) {
        throw 'EnvelopeContextRequired: an evidence envelope must name the resolved configuration the run was held to.'
    }

    $hash = [string](Get-BaselineRecordMember -Node $Context -Name 'Hash')
    if ([string]::IsNullOrWhiteSpace($hash)) {
        throw 'EnvelopeConfigurationHashRequired: the supplied context carries no configuration hash; pass the output of Get-BaselineContext.'
    }

    $algorithm = [string](Get-BaselineRecordMember -Node $Context -Name 'Algorithm')
    if ([string]::IsNullOrWhiteSpace($algorithm)) {
        throw 'EnvelopeConfigurationHashRequired: the supplied context names no hash algorithm; a bare digest cannot be re-computed.'
    }

    $deploymentProfile = [string](Get-BaselineRecordMember -Node $Context -Name 'DeploymentProfile')
    if ([string]::IsNullOrWhiteSpace($deploymentProfile)) {
        throw 'EnvelopeDeploymentProfileRequired: the supplied context names no deployment profile; the native and gateway profiles are held to different controls.'
    }

    $entitlement = Get-BaselineRecordMember -Node $Context -Name 'Entitlement'
    if ($null -eq $entitlement) {
        throw 'EnvelopeEntitlementRequired: the supplied context carries no entitlement; a NotEntitled verdict is only defensible beside the service plans the tenant actually held.'
    }

    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        throw 'EnvelopeTenantRequired: an evidence envelope must name the tenant it describes.'
    }

    if ([string]::IsNullOrWhiteSpace($OrganizationName)) {
        throw 'EnvelopeOrganizationRequired: an evidence envelope must name the organization it describes.'
    }

    if ($null -eq $Evidence -or @($Evidence).Count -eq 0) {
        throw 'EnvelopeEvidenceRequired: an evidence envelope must carry the raw observations its verdicts were decided from.'
    }

    foreach ($record in $Evidence) {
        if (-not (Test-BaselineEvidenceRecord -Node $record)) {
            throw 'EnvelopeEvidenceNotRecognized: the envelope was handed something that is not an evidence record; pass the output of New-BaselineEvidence or Get-BaselineEvidence.'
        }
    }

    if ($null -eq $Check -or @($Check).Count -eq 0) {
        throw 'EnvelopeCheckRequired: an evidence envelope must carry the verdicts the run decided.'
    }

    foreach ($result in $Check) {
        if (-not (Test-BaselineControlResultRecord -Node $result)) {
            throw 'EnvelopeCheckNotRecognized: the envelope was handed something that is not a control result; pass the output of New-ControlResult or Test-BaselineControl.'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ChangeId) -and [string]::IsNullOrWhiteSpace($PreviewId)) {
        throw "EnvelopePreviewRequired: the applied change '$ChangeId' names no approved preview; a change applied without one is never ordinary."
    }

    $parameterHash = Get-BaselineParameterHash -Path $ParameterPath

    $member = [ordered]@{
        SchemaVersion     = [string](@(Get-ArtifactVersionContract).Artifact | Where-Object { $_.Artifact -ceq 'Evidence' }).SchemaVersion
        BaselineVersion   = [string](Get-ArtifactVersionContract).BaselineVersion
        CollectedAtUtc    = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [System.Globalization.CultureInfo]::InvariantCulture)
        TenantId          = $TenantId
        OrganizationName  = $OrganizationName
        DeploymentProfile = $deploymentProfile
        ConfigurationHash = '{0}:{1}' -f $algorithm.ToLowerInvariant(), $hash
        ParameterHash     = '{0}:{1}' -f ([string]$parameterHash.Algorithm).ToLowerInvariant(), $parameterHash.Hash
        RedactedParameter = @($parameterHash.RedactedParameter)
        CollectorVersion  = $script:BaselineCollectorVersion
        ModuleVersion     = $script:BaselineModuleVersion
        PreviewId         = $PreviewId
        ChangeId          = $ChangeId
        ServicePlan       = [ordered]@{
            Source               = Get-BaselineRecordMember -Node $entitlement -Name 'Source'
            Determined           = Get-BaselineRecordMember -Node $entitlement -Name 'Determined'
            EnabledServicePlanId = @(Get-BaselineRecordMember -Node $entitlement -Name 'EnabledServicePlanId')
            Capability           = @(Get-BaselineRecordMember -Node $entitlement -Name 'Capability')
            NotEntitled          = @(Get-BaselineRecordMember -Node $entitlement -Name 'NotEntitled')
        }
        Evidence          = @($Evidence)
        Check             = @($Check)
    }

    return , (ConvertTo-ImmutableBaselineNode -Node $member)
}

# EVD-005: the evidence framework held to the catalog it claims to satisfy. Three ways a run can
# read as clean while proving less than it claims are made fatal here. A collector that did not run
# leaves a verdict with no observation behind it. A control observed twice or decided twice lets a
# reader choose whichever answer suits them. A control the catalog never declared, or a declared
# control nobody produced, means the artifact and the agreement have stopped being the same
# document. Each finding is reported by name, and the verdict the gate reads is an `Error`, which
# the result contract admits to no successful go-live.
function Test-BaselineEvidenceFramework {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$CatalogPath,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Envelope
    )

    if ($null -eq $Envelope) {
        throw 'FrameworkEnvelopeRequired: an evidence framework check must be handed the envelope the run produced.'
    }

    # A member that is absent and a member that is empty are the same silent absence, but @($null)
    # is a collection of one, so the two are separated before either is counted.
    $observed = Get-BaselineRecordMember -Node $Envelope -Name 'Evidence'
    $evidence = @()
    if ($null -ne $observed) { $evidence = @($observed) }
    if ($evidence.Count -eq 0) {
        throw 'FrameworkEvidenceRequired: the supplied envelope carries no evidence; a run that observed nothing has not covered the catalog, it has failed to start.'
    }

    $decided = Get-BaselineRecordMember -Node $Envelope -Name 'Check'
    $check = @()
    if ($null -ne $decided) { $check = @($decided) }
    if ($check.Count -eq 0) {
        throw 'FrameworkCheckRequired: the supplied envelope carries no checks; an envelope with no verdicts has nothing for the gate to fail on.'
    }

    $evidenceCoverage = Test-BaselineControlCoverage -CatalogPath $CatalogPath -Observed $evidence -Subject 'Evidence'
    $checkCoverage = Test-BaselineControlCoverage -CatalogPath $CatalogPath -Observed $check -Subject 'Check'

    $missingCollector = @(
        $evidence |
            Where-Object { -not [bool](Get-BaselineRecordMember -Node $_ -Name 'Collected') } |
            ForEach-Object { [string](Get-BaselineRecordMember -Node $_ -Name 'ControlId') } |
            Select-Object -Unique
    )

    $duplicatedControl = @(@($evidenceCoverage.Duplicated) + @($checkCoverage.Duplicated) | Select-Object -Unique)

    $catalogDrift = @(
        @($evidenceCoverage.Missing | ForEach-Object { "EvidenceMissing:$_" })
        @($evidenceCoverage.Unknown | ForEach-Object { "EvidenceUnknown:$_" })
        @($checkCoverage.Missing | ForEach-Object { "CheckMissing:$_" })
        @($checkCoverage.Unknown | ForEach-Object { "CheckUnknown:$_" })
    )

    $satisfied = ($missingCollector.Count -eq 0 -and $duplicatedControl.Count -eq 0 -and $catalogDrift.Count -eq 0)

    $result = if ($satisfied) {
        New-ControlResult -ControlId 'EVD-005' -Status 'Pass'
    }
    else {
        $finding = @(
            if ($missingCollector.Count -gt 0) { "collectors that did not run: $($missingCollector -join ', ')" }
            if ($duplicatedControl.Count -gt 0) { "controls produced more than once: $($duplicatedControl -join ', ')" }
            if ($catalogDrift.Count -gt 0) { "catalog drift: $($catalogDrift -join ', ')" }
        )

        New-ControlResult -ControlId 'EVD-005' -Status 'Error' -Reason "EvidenceFrameworkDrift: $($finding -join '; ')."
    }

    $member = [ordered]@{
        Satisfied         = $satisfied
        MissingCollector  = $missingCollector
        DuplicatedControl = $duplicatedControl
        CatalogDrift      = $catalogDrift
        Result            = $result
    }

    return , (ConvertTo-ImmutableBaselineNode -Node $member)
}

# GATE-003: the hash the evidence signature is taken over. Held apart from the envelope itself so
# that signing never mutates the artifact, and computed from the canonical form so that reordering
# or re-serializing the evidence cannot change the answer while editing it always does.
# Canonicalization is defined for configuration documents and refuses a timestamp outright, but an
# envelope is mostly timestamps, so each one is rendered round-trip first. A leaf of any other kind
# is rendered as its own text rather than refused, because the observations a tenant returns are
# not drawn from a fixed set of types and a hash that throws on an unfamiliar one would make
# unsigned evidence the easier path.
function ConvertTo-BaselineHashableNode {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Node,

        [int]$Level = 0
    )

    if ($null -eq $Node) {
        return $null
    }

    if ($Node -is [datetime]) {
        return $Node.ToUniversalTime().ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
    }

    if ($Node -is [datetimeoffset]) {
        return $Node.ToUniversalTime().ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
    }

    if ($Node -is [string] -or $Node -is [bool] -or $Node -is [decimal] -or $Node.GetType().IsPrimitive) {
        return $Node
    }

    if ($Level -ge 64) {
        throw 'CanonicalDepthExceeded: the evidence nests deeper than the supported depth of 64.'
    }

    if ($Node -is [System.Collections.IDictionary]) {
        $member = [ordered]@{}
        foreach ($name in @($Node.Keys)) {
            $member[[string]$name] = ConvertTo-BaselineHashableNode -Node $Node[$name] -Level ($Level + 1)
        }

        return $member
    }

    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        $member = [ordered]@{}
        foreach ($property in @($Node.PSObject.Properties)) {
            $member[$property.Name] = ConvertTo-BaselineHashableNode -Node $property.Value -Level ($Level + 1)
        }

        return $member
    }

    if ($Node -is [System.Collections.IList]) {
        return , @(foreach ($item in $Node) { ConvertTo-BaselineHashableNode -Node $item -Level ($Level + 1) })
    }

    return [string]$Node
}

function Get-BaselineEvidenceContentHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Envelope
    )

    if ($null -eq $Envelope) {
        throw 'GoLiveEnvelopeRequired: an evidence content hash must be taken over an envelope.'
    }

    $canonicalJson = ConvertTo-CanonicalJson -InputObject (ConvertTo-BaselineHashableNode -Node $Envelope)
    $canonicalBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($canonicalJson)

    return [pscustomobject]@{
        Algorithm = 'SHA256'
        Hash      = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($canonicalBytes)).ToLowerInvariant()
    }
}

# GATE-003: the one decision that lets a change reach production. Everything it can refuse on is
# refused on, and every refusal is collected rather than returned at the first one, because an
# operator who fixes one blocker and is handed the next has to run the whole collection again to
# learn what else was already wrong. Nothing here is a warning: a control that did not pass, a
# catalog control nobody decided, a binding that does not hold, evidence too old to describe the
# tenant, a licensing gap and an artifact nobody signed all produce the same refusal, because each
# one is a claim this run cannot support.
function Test-BaselineGoLive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Envelope,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$CatalogPath,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ExpectedTenantId,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ExpectedDeploymentProfile,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ExpectedConfigurationHash,

        [Parameter(Mandatory)]
        [timespan]$MaximumEvidenceAge,

        [AllowEmptyString()]
        [string]$RequestedBy = '',

        [AllowNull()]
        [object[]]$RiskAcceptance,

        [AllowNull()]
        [object]$Signature,

        [AllowNull()]
        [object]$TargetEntitlement,

        [datetime]$AsOf = [datetime]::UtcNow
    )

    if ($null -eq $Envelope) {
        throw 'GoLiveEnvelopeRequired: a go-live decision must be handed the evidence the run produced.'
    }

    foreach ($binding in @('TenantId', 'DeploymentProfile', 'ConfigurationHash')) {
        if ([string]::IsNullOrWhiteSpace((Get-Variable -Name ('Expected' + $binding) -ValueOnly))) {
            throw "GoLiveExpected$($binding)Required: a binding the caller never states is a binding the envelope decides for itself."
        }
    }

    # Read before anything is judged, so an unusable catalog is a fault the caller sees rather than
    # a coverage answer of nothing missing.
    $null = Get-BaselineControlCatalog -Path $CatalogPath

    $finding = [System.Collections.Generic.List[string]]::new()

    $decided = Get-BaselineRecordMember -Node $Envelope -Name 'Check'
    $check = @()
    if ($null -ne $decided) { $check = @($decided) }
    if ($check.Count -eq 0) {
        throw 'GoLiveCheckRequired: the supplied envelope carries no verdicts; a run that decided nothing has not passed, it has failed to start.'
    }

    $contract = Get-BaselineResultContract
    $declaredStatus = @($contract.NormalizedStatus) + @($contract.NonNormalizedStatus)

    $acceptance = @()
    if ($null -ne $RiskAcceptance) { $acceptance = @($RiskAcceptance | Where-Object { $null -ne $_ }) }
    $baselineVersion = [string](Get-ArtifactVersionContract).BaselineVersion
    $excused = [System.Collections.Generic.List[object]]::new()

    foreach ($result in $check) {
        $controlId = [string](Get-BaselineRecordMember -Node $result -Name 'ControlId')
        $status = [string](Get-BaselineRecordMember -Node $result -Name 'Status')

        if ($status -cnotin $declaredStatus) {
            $finding.Add("UnknownControlStatus: '$controlId' was decided '$status', which the result contract never declared.")
            continue
        }

        if ($status -cin @($contract.GoLiveSuccessStatus)) {
            continue
        }

        # GATE-003: an exception is honoured only for the one control it names, and only where
        # the control was measured and found wanting. A control nobody could decide - an `Error`,
        # a `Manual`, a `NotEntitled` or an `Unverified` - is a risk nobody has sized, and signing
        # off a risk nobody has sized is declining to look rather than accepting anything.
        $raised = @($acceptance | Where-Object { [string](Get-BaselineRecordMember -Node $_ -Name 'ControlId') -eq $controlId })

        if ($raised.Count -eq 0) {
            $finding.Add("ControlNotPassed: '$controlId' was decided '$status'.")
            continue
        }

        if ($status -cne 'Fail') {
            $finding.Add("GoLiveExceptionNotApplicable: '$controlId' was decided '$status', and a risk acceptance can only excuse a control decided 'Fail'.")
            continue
        }

        $verdict = Test-RiskAcceptance -RiskAcceptance $raised[0] `
            -ControlId $controlId `
            -TenantId $ExpectedTenantId `
            -ConfigurationHash $ExpectedConfigurationHash `
            -RequestedBy $RequestedBy `
            -AsOf $AsOf `
            -DeploymentProfile $ExpectedDeploymentProfile `
            -BaselineVersion $baselineVersion

        if (-not $verdict.Valid) {
            $finding.Add("GoLiveExceptionRefused: the risk acceptance raised for '$controlId' does not excuse it. $($verdict.Reason)")
            continue
        }

        $excused.Add((New-ControlResult -ControlId $controlId -Status 'ApprovedException' -Reason ([string]$verdict.Reason)))
    }

    $coverage = Test-BaselineControlCoverage -CatalogPath $CatalogPath -Observed $check -Subject 'Check'
    foreach ($controlId in @($coverage.Missing)) {
        $finding.Add("CatalogControlMissing: the catalog declares '$controlId' and no check decided it.")
    }
    foreach ($controlId in @($coverage.Unknown)) {
        $finding.Add("CatalogControlUnknown: '$controlId' was decided and the catalog never declared it.")
    }
    foreach ($controlId in @($coverage.Duplicated)) {
        $finding.Add("CatalogControlDuplicated: '$controlId' was decided more than once.")
    }

    $observedTenant = [string](Get-BaselineRecordMember -Node $Envelope -Name 'TenantId')
    if ($observedTenant -ne $ExpectedTenantId) {
        $finding.Add("GoLiveTenantMismatch: the evidence names tenant '$observedTenant', but this go-live is for '$ExpectedTenantId'.")
    }

    $observedProfile = [string](Get-BaselineRecordMember -Node $Envelope -Name 'DeploymentProfile')
    if ($observedProfile -ne $ExpectedDeploymentProfile) {
        $finding.Add("GoLiveProfileMismatch: the evidence was collected under deployment profile '$observedProfile', but this go-live is for '$ExpectedDeploymentProfile'.")
    }

    # The envelope carries the algorithm with the digest and a caller usually holds the bare digest,
    # so the prefix is not part of the comparison.
    $observedHash = ([string](Get-BaselineRecordMember -Node $Envelope -Name 'ConfigurationHash')) -replace '(?i)^sha256:', ''
    $expectedHash = $ExpectedConfigurationHash -replace '(?i)^sha256:', ''
    if ($observedHash -ne $expectedHash) {
        $finding.Add("GoLiveConfigurationHashMismatch: the evidence was collected for configuration '$observedHash', but this go-live is for '$expectedHash'.")
    }

    $collectedText = [string](Get-BaselineRecordMember -Node $Envelope -Name 'CollectedAtUtc')
    $collectedAt = [datetime]::MinValue
    $readable = [datetime]::TryParse(
        $collectedText,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$collectedAt)

    if (-not $readable) {
        $finding.Add("GoLiveCollectionTimeUnreadable: the evidence records its collection time as '$collectedText', which is not a timestamp.")
    }
    else {
        $age = $AsOf - $collectedAt
        if ($age -gt $MaximumEvidenceAge) {
            $finding.Add("GoLiveEvidenceStale: the evidence is $([math]::Floor($age.TotalDays)) days old and the maximum evidence age is $([math]::Floor($MaximumEvidenceAge.TotalDays)) days.")
        }
    }

    $servicePlan = Get-BaselineRecordMember -Node $Envelope -Name 'ServicePlan'
    if ($null -ne $servicePlan) {
        foreach ($capability in @(Get-BaselineRecordMember -Node $servicePlan -Name 'NotEntitled')) {
            if (-not [string]::IsNullOrWhiteSpace([string]$capability)) {
                $finding.Add("GoLiveTenantNotEntitled: the tenant holds no enabled service plan for '$capability'.")
            }
        }
    }

    # A tenant-wide licence says nothing about whether the people the baseline protects are covered,
    # so the per-user answer is read separately and a gap in it refuses on its own.
    if ($null -ne $TargetEntitlement) {
        foreach ($gap in @(Get-BaselineRecordMember -Node $TargetEntitlement -Name 'Missing')) {
            if ($null -eq $gap) { continue }
            $user = [string](Get-BaselineRecordMember -Node $gap -Name 'UserPrincipalName')
            $plan = [string](Get-BaselineRecordMember -Node $gap -Name 'ServicePlanName')
            $finding.Add("GoLiveTargetNotEntitled: '$user' holds no enabled service plan '$plan'.")
        }
    }

    $signatureModel = ''
    $signatureValue = ''
    $signatureContentHash = ''
    if ($null -ne $Signature) {
        $signatureModel = [string](Get-BaselineRecordMember -Node $Signature -Name 'Model')
        $signatureValue = [string](Get-BaselineRecordMember -Node $Signature -Name 'Value')
        $signatureContentHash = [string](Get-BaselineRecordMember -Node $Signature -Name 'ContentHash')
    }

    if ([string]::IsNullOrWhiteSpace($signatureValue)) {
        $finding.Add('GoLiveEvidenceUnsigned: the evidence carries no signature, so nothing binds these bytes to anybody who vouched for them.')
    }
    elseif ($signatureModel -cnotin @((Get-ApprovalSignatureContract).SelectedModel)) {
        $finding.Add("GoLiveSignatureModelNotApproved: the evidence is signed under '$signatureModel', which is not the selected approval signature model.")
    }
    elseif ($signatureContentHash -ne [string](Get-BaselineEvidenceContentHash -Envelope $Envelope).Hash) {
        $finding.Add("GoLiveEvidenceTampered: the evidence no longer hashes to the content that was signed as '$signatureContentHash'.")
    }

    $admitted = ($finding.Count -eq 0)
    $result = if ($admitted) {
        New-ControlResult -ControlId 'GATE-003' -Status 'Pass'
    }
    else {
        New-ControlResult -ControlId 'GATE-003' -Status 'Fail' -Reason "GoLiveRefused: $($finding -join ' ')"
    }

    $member = [ordered]@{
        Admitted    = $admitted
        RequestedBy = $RequestedBy
        Finding     = @($finding)
        Exception   = @($excused)
        Result      = $result
    }

    return , (ConvertTo-ImmutableBaselineNode -Node $member)
}

# EXO-003: the conditional access policies the tenant actually holds. Every policy is recorded
# whole rather than the one the baseline names, because a tenant that holds policies but not that
# one is a different finding from a tenant that holds none, and neither is visible once the
# collection has narrowed. Graph is reached only through the supplied seam, so a consent gap, a
# throttled tenant and an expired token are all recorded as uncollected rather than thrown.
function Get-ConditionalAccessEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Collection
    )

    return Get-BaselineEvidence -ControlId 'EXO-003' -Source 'MicrosoftGraph' `
        -Command 'GET /identity/conditionalAccess/policies' -Collection $Collection
}

# EXO-003: the members the named policy is decided by, as leaf paths through the Graph resource.
# Each is checked for presence rather than truthiness, because an absent member read as satisfied
# reports that legacy authentication is blocked on the strength of something nobody observed.
$script:ConditionalAccessDecidedMember = @(
    'state'
    'conditions.clientAppTypes'
    'conditions.users.includeUsers'
    'conditions.users.excludeUsers'
    'conditions.users.excludeGroups'
    'conditions.applications.includeApplications'
    'grantControls.builtInControls'
)

# The Office 365 Exchange Online resource legacy clients authenticate against, and the two client
# app types Graph splits legacy authentication into. Blocking one of the two leaves the other
# delivering mail exactly as before.
$script:ExchangeOnlineApplicationId = '00000002-0000-0ff1-ce00-000000000000'
$script:LegacyClientAppType = @('exchangeActiveSync', 'other')

function Get-BaselineRecordMemberByPath {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Node,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $node = $Node
    foreach ($segment in @($Path -split '\.')) {
        if ($null -eq $node -or $segment -cnotin @(Get-BaselineRecordMemberName -Node $node)) {
            return [pscustomobject]@{ Present = $false; Value = $null }
        }

        $node = Get-BaselineRecordMember -Node $node -Name $segment
    }

    return [pscustomobject]@{ Present = $true; Value = $node }
}

# EXO-003: the shipping script reports this control as `Manual`, so the one control that closes
# legacy authentication has never contributed anything a go-live gate can read. All four clauses of
# the card are decided together, because a policy that is enabled but scoped to one pilot account,
# or tenant-wide but granting multi-factor authentication a legacy client can never satisfy, or
# perfect but excluding a group anybody can be added to, leaves the route as open as no policy at
# all while reading in an export exactly like a compliant one.
function Test-ConditionalAccessControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$PolicyDisplayName,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ApprovedExclusion
    )

    if ([string]::IsNullOrWhiteSpace($PolicyDisplayName)) {
        throw 'PolicyDisplayNameRequired: EXO-003 cannot be decided without the conditional access policy the baseline resolved; an evaluator that is not told which policy carries the block takes the first policy that looks like one.'
    }

    # An exclusion list the baseline resolved to nothing means no principal may be exempted; one
    # that was never resolved means nobody decided, and the two must not decide the control alike.
    if ($null -eq $ApprovedExclusion) {
        throw 'ApprovedExclusionRequired: EXO-003 cannot be decided without the exclusions the baseline approved; an evaluator with no approved list approves every exclusion the tenant happens to hold.'
    }

    $caseRule = @('Trim', 'LowerInvariant')
    $expectedName = $PolicyDisplayName
    $normalizedName = ConvertTo-NormalizedCanonicalValue -Value $expectedName -Rule $caseRule
    $approvedExclusion = @(foreach ($entry in $ApprovedExclusion) {
            if (-not [string]::IsNullOrWhiteSpace($entry)) { ConvertTo-NormalizedCanonicalValue -Value ([string]$entry) -Rule $caseRule }
        })

    $decidedMember = $script:ConditionalAccessDecidedMember
    $applicationId = $script:ExchangeOnlineApplicationId
    $legacyClient = $script:LegacyClientAppType

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $observed = @()
        if ($null -ne $payload) { $observed = @($payload) }

        if ($observed.Count -eq 0) {
            return [pscustomobject]@{
                Status = 'Fail'
                Reason = 'LegacyAuthenticationOpen: the tenant holds no conditional access policy.'
            }
        }

        $named = @(foreach ($entry in $observed) {
                $displayName = [string](Get-BaselineRecordMember -Node $entry -Name 'displayName')
                if ((ConvertTo-NormalizedCanonicalValue -Value $displayName -Rule $caseRule) -ceq $normalizedName) { $entry }
            })

        if ($named.Count -eq 0) {
            return [pscustomobject]@{
                Status = 'Fail'
                Reason = "LegacyAuthenticationOpen: the tenant holds no conditional access policy named '$expectedName'."
            }
        }

        foreach ($policy in $named) {
            foreach ($path in $decidedMember) {
                if (-not (Get-BaselineRecordMemberByPath -Node $policy -Path $path).Present) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "ConditionalAccessEvidenceIncomplete: the observed conditional access policy '$expectedName' carries no '$path' member."
                    }
                }
            }
        }

        $finding = @(
            foreach ($policy in $named) {
                $read = { param($Path) (Get-BaselineRecordMemberByPath -Node $policy -Path $Path).Value }

                $state = [string](& $read 'state')
                if ($state -cne 'enabled') {
                    "conditional access policy '{0}' is '{1}' where 'enabled' is required" -f $expectedName, $state
                }

                if ('All' -cnotin @(& $read 'conditions.users.includeUsers')) {
                    "conditional access policy '{0}' does not apply to all users" -f $expectedName
                }

                $application = @(& $read 'conditions.applications.includeApplications')
                if ('All' -cnotin $application -and $applicationId -cnotin $application) {
                    "conditional access policy '{0}' does not apply to Exchange Online" -f $expectedName
                }

                $clientAppType = @(& $read 'conditions.clientAppTypes')
                foreach ($client in $legacyClient) {
                    if ($client -cnotin $clientAppType) {
                        "conditional access policy '{0}' does not cover legacy client '{1}'" -f $expectedName, $client
                    }
                }

                if ('block' -cnotin @(& $read 'grantControls.builtInControls')) {
                    "conditional access policy '{0}' does not grant 'block'" -f $expectedName
                }

                # A user exclusion and a group exclusion exempt their principals identically, so
                # both are held to the one approved list.
                $excluded = @(& $read 'conditions.users.excludeUsers') + @(& $read 'conditions.users.excludeGroups')
                foreach ($principal in $excluded) {
                    $identifier = [string]$principal
                    if ([string]::IsNullOrWhiteSpace($identifier)) { continue }

                    if ((ConvertTo-NormalizedCanonicalValue -Value $identifier -Rule $caseRule) -cnotin $approvedExclusion) {
                        "conditional access policy '{0}' excludes '{1}' which the baseline does not approve" -f $expectedName, $identifier
                    }
                }
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'LegacyAuthenticationOpen: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'EXO-003' -Evidence $Evidence -Evaluator $evaluator
}

# EXO-001: the accepted domains the tenant actually holds. The collector names the control, the
# source and the command the registry declares, and reaches Exchange Online only through the
# supplied seam, so a refused command is recorded as an uncollected observation rather than thrown.
function Get-AcceptedDomainEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Collection
    )

    return Get-BaselineEvidence -ControlId 'EXO-001' -Source 'ExchangeOnline' -Command 'Get-AcceptedDomain' -Collection $Collection
}

# EXO-001: every domain the baseline expects must be accepted, and accepted on exactly one set of
# terms. Domain names are compared through the canonical Domain rules, so casing, surrounding
# whitespace and a trailing root dot never read as drift. The domain type is compared ordinally,
# because the card requires exactly `Authoritative` and any other value - including a relay - lets
# Exchange Online accept mail for recipients it cannot verify.
function Test-AcceptedDomainControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ExpectedDomain
    )

    $expectedDomain = @(foreach ($name in @($ExpectedDomain)) { if (-not [string]::IsNullOrWhiteSpace($name)) { $name } })
    if ($expectedDomain.Count -eq 0) {
        throw 'ExpectedDomainRequired: EXO-001 cannot be decided without the accepted domains the baseline expects; a control that expects nothing is satisfied by every tenant.'
    }

    $domainRule = @(@((Get-CanonicalComparisonContract).Kind | Where-Object { $_.Kind -ceq 'Domain' })[0].NormalizationRule)

    # The evaluator reads $expectedDomain and $domainRule from this scope, which is its caller's
    # caller: Test-BaselineControl invokes it while this function is still on the stack.
    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $observed = @()
        if ($null -ne $payload) { $observed = @($payload) }

        $observedDomain = @(foreach ($entry in $observed) {
                $name = [string](Get-BaselineRecordMember -Node $entry -Name 'DomainName')
                if ([string]::IsNullOrWhiteSpace($name)) { continue }

                [pscustomobject]@{
                    Name = ConvertTo-NormalizedCanonicalValue -Value $name -Rule $domainRule
                    Type = [string](Get-BaselineRecordMember -Node $entry -Name 'DomainType')
                }
            })

        # Member access on an empty array yields null rather than an empty collection, and the
        # comparison refuses a null collection outright, so the names are gathered explicitly.
        $observedName = @(foreach ($entry in $observedDomain) { $entry.Name })

        $comparison = Compare-NormalizedCollection -Desired $expectedDomain -Actual $observedName -Kind 'Domain'

        $typeDrift = @(
            foreach ($name in $comparison.NormalizedDesired) {
                foreach ($entry in @($observedDomain | Where-Object { $_.Name -ceq $name })) {
                    if ($entry.Type -cne 'Authoritative') {
                        "'{0}' is '{1}' where exactly 'Authoritative' is required" -f $entry.Name, $entry.Type
                    }
                }
            }
        )

        $finding = @(
            if (@($comparison.Missing).Count -gt 0) {
                "the tenant holds no accepted domain for '{0}'" -f (@($comparison.Missing) -join "', '")
            }
            $typeDrift
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'AcceptedDomainDrift: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'EXO-001' -Evidence $Evidence -Evaluator $evaluator
}

# EXO-004: mail leaves the organization automatically by three independent routes - the outbound
# spam policy, a mailbox forwarding member, and a user-owned inbox rule - and closing two of them
# leaves the tenant exactly as exposed as closing none. One record therefore carries all three
# observations under their own names, and any one of the three commands refusing makes the whole
# record uncollected, because a record assembled from a partial view of the tenant is
# indistinguishable from a record of a tenant that has nothing to report.
function Get-OutboundForwardingEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$OutboundSpamPolicyCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$MailboxCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$InboxRuleCollection
    )

    if ($null -eq $OutboundSpamPolicyCollection) {
        throw 'OutboundSpamPolicyCollectionRequired: EXO-004 cannot be observed without a collection that reaches the outbound spam filter policies.'
    }

    if ($null -eq $MailboxCollection) {
        throw 'MailboxCollectionRequired: EXO-004 cannot be observed without a collection that reaches the mailboxes.'
    }

    if ($null -eq $InboxRuleCollection) {
        throw 'InboxRuleCollectionRequired: EXO-004 cannot be observed without a collection that reaches the inbox rules.'
    }

    # Each collection is invoked inside the one seam Get-BaselineEvidence runs, so a refusal from
    # any of the three is recorded as an uncollected observation rather than thrown.
    $collection = {
        [ordered]@{
            OutboundSpamFilterPolicy = @(& $OutboundSpamPolicyCollection)
            Mailbox                  = @(& $MailboxCollection)
            InboxRule                = @(& $InboxRuleCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'EXO-004' -Source 'ExchangeOnline' `
        -Command 'Get-HostedOutboundSpamFilterPolicy; Get-Mailbox; Get-InboxRule' -Collection $collection
}

# EXO-004: the three routes are decided together because closing any two of them leaves the tenant
# exactly as exposed as closing none. A policy set that observed nothing is a failure rather than a
# vacuous pass, an observation that is absent rather than empty is an `Error`, and a rule is judged
# only when it is enabled and only against the domains the organization actually holds.
$script:OutboundForwardingObservation = @('OutboundSpamFilterPolicy', 'Mailbox', 'InboxRule')

# The rule actions that put a copy of a message outside the organization, and the wording each is
# reported with. Exchange Online exposes them as three separate members, and a rule may use any of
# them independently of the others.
$script:InboxRuleForwardingAction = [ordered]@{
    ForwardTo             = 'forwards to'
    ForwardAsAttachmentTo = 'forwards as attachment to'
    RedirectTo            = 'redirects to'
}

function Test-OutboundForwardingControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$AcceptedDomain
    )

    $domainRule = @(@((Get-CanonicalComparisonContract).Kind | Where-Object { $_.Kind -ceq 'Domain' })[0].NormalizationRule)

    $acceptedDomain = @(foreach ($name in @($AcceptedDomain)) {
            if (-not [string]::IsNullOrWhiteSpace($name)) { ConvertTo-NormalizedCanonicalValue -Value $name -Rule $domainRule }
        })
    if ($acceptedDomain.Count -eq 0) {
        throw 'AcceptedDomainRequired: EXO-004 cannot be decided without the domains the organization holds; without them every recipient is either inside or outside by assumption rather than by evidence.'
    }

    $observationName = $script:OutboundForwardingObservation
    $forwardingAction = $script:InboxRuleForwardingAction

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @(Get-BaselineRecordMemberName -Node $payload)

        foreach ($name in $observationName) {
            if ($name -cnotin $present) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "OutboundForwardingEvidenceIncomplete: the record carries no '$name' observation."
                }
            }
        }

        $policy = @(Get-BaselineRecordMember -Node $payload -Name 'OutboundSpamFilterPolicy')
        $mailbox = @(Get-BaselineRecordMember -Node $payload -Name 'Mailbox')
        $inboxRule = @(Get-BaselineRecordMember -Node $payload -Name 'InboxRule')

        $isExternal = {
            param($Recipient)

            $address = [string]$Recipient
            $at = $address.LastIndexOf('@')
            if ($at -lt 0) { return $false }

            $domain = ConvertTo-NormalizedCanonicalValue -Value $address.Substring($at + 1) -Rule $domainRule
            return $domain -cnotin $acceptedDomain
        }

        $finding = @(
            if ($policy.Count -eq 0) {
                'the tenant holds no outbound spam filter policy'
            }

            foreach ($entry in $policy) {
                $mode = [string](Get-BaselineRecordMember -Node $entry -Name 'AutoForwardingMode')
                if ($mode -cne 'Off') {
                    "outbound spam policy '{0}' sets automatic forwarding to '{1}' where 'Off' is required" -f `
                    (Get-BaselineRecordMember -Node $entry -Name 'Name'), $mode
                }
            }

            foreach ($entry in $mailbox) {
                foreach ($member in @('ForwardingAddress', 'ForwardingSmtpAddress')) {
                    $configured = [string](Get-BaselineRecordMember -Node $entry -Name $member)
                    if (-not [string]::IsNullOrWhiteSpace($configured)) {
                        "mailbox '{0}' sets {1} to '{2}'" -f `
                        (Get-BaselineRecordMember -Node $entry -Name 'PrimarySmtpAddress'), $member, $configured
                    }
                }
            }

            foreach ($entry in $inboxRule) {
                if (-not (Get-BaselineRecordMember -Node $entry -Name 'Enabled')) { continue }

                foreach ($action in $forwardingAction.Keys) {
                    foreach ($recipient in @(Get-BaselineRecordMember -Node $entry -Name $action)) {
                        if (& $isExternal $recipient) {
                            "enabled inbox rule '{0}' {1} '{2}'" -f `
                            (Get-BaselineRecordMember -Node $entry -Name 'Identity'), $forwardingAction[$action], $recipient
                        }
                    }
                }
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'ForwardingPathOpen: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'EXO-004' -Evidence $Evidence -Evaluator $evaluator
}

# EXO-005: the transport configuration the tenant actually holds. The whole configuration is
# recorded rather than the postmaster member alone, because narrowing the payload at collection
# time makes an unset member indistinguishable from a member the collector chose not to carry.
function Get-ExternalPostmasterEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Collection
    )

    return Get-BaselineEvidence -ControlId 'EXO-005' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Collection $Collection
}

# EXO-005: the live external postmaster address must equal the address the baseline resolved. The
# two are compared through the canonical SmtpAddress rules, so the routing prefix, the casing and
# the whitespace Exchange Online reports back never read as drift. A record that never observed the
# member is an `Error` rather than a tenant that left it unset, because the default state of every
# tenant is unset and that is exactly the finding this control exists to report.
function Test-ExternalPostmasterControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ExpectedAddress
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedAddress)) {
        throw 'ExpectedPostmasterAddressRequired: EXO-005 cannot be decided without the external postmaster address the baseline resolved; an evaluator with no desired state decides on the absence of configuration rather than on the tenant.'
    }

    $addressRule = @(@((Get-CanonicalComparisonContract).Kind | Where-Object { $_.Kind -ceq 'SmtpAddress' })[0].NormalizationRule)
    $expectedAddress = $ExpectedAddress
    $normalizedExpected = ConvertTo-NormalizedCanonicalValue -Value $expectedAddress -Rule $addressRule

    # The evaluator reads the rule and both forms of the desired address from this scope, which is
    # its caller's caller: Test-BaselineControl invokes it while this function is still on the stack.
    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $observed = @()
        if ($null -ne $payload) { $observed = @(Get-BaselineRecordMemberName -Node $payload) }

        if ('ExternalPostmasterAddress' -cnotin $observed) {
            return [pscustomobject]@{
                Status = 'Error'
                Reason = "ExternalPostmasterEvidenceIncomplete: the record carries no 'ExternalPostmasterAddress' observation."
            }
        }

        $liveAddress = [string](Get-BaselineRecordMember -Node $payload -Name 'ExternalPostmasterAddress')

        if ([string]::IsNullOrWhiteSpace($liveAddress)) {
            return [pscustomobject]@{
                Status = 'Fail'
                Reason = "ExternalPostmasterDrift: the tenant has set no external postmaster address where '$expectedAddress' is required."
            }
        }

        if ((ConvertTo-NormalizedCanonicalValue -Value $liveAddress -Rule $addressRule) -cne $normalizedExpected) {
            return [pscustomobject]@{
                Status = 'Fail'
                Reason = "ExternalPostmasterDrift: the tenant sets the external postmaster address to '$liveAddress' where '$expectedAddress' is required."
            }
        }

        return [pscustomobject]@{ Status = 'Pass' }
    }

    return Test-BaselineControl -ControlId 'EXO-005' -Evidence $Evidence -Evaluator $evaluator
}

# EXO-006: auditing is switched on organization-wide, but an audit bypass association exempts a
# mailbox from it individually while the organization setting still reads as enabled. One record
# therefore carries both observations under their own names, and either command refusing makes the
# whole record uncollected, because a tenant with auditing on and its interesting mailboxes
# exempted is indistinguishable from a compliant tenant when only the first half was observed.
function Get-MailboxAuditingEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$OrganizationConfigCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$AuditBypassAssociationCollection
    )

    if ($null -eq $OrganizationConfigCollection) {
        throw 'OrganizationConfigCollectionRequired: EXO-006 cannot be observed without a collection that reaches the organization configuration.'
    }

    if ($null -eq $AuditBypassAssociationCollection) {
        throw 'AuditBypassAssociationCollectionRequired: EXO-006 cannot be observed without a collection that reaches the mailbox audit bypass associations.'
    }

    # Both collections are invoked inside the one seam Get-BaselineEvidence runs, so a refusal from
    # either is recorded as an uncollected observation rather than thrown.
    $collection = {
        [ordered]@{
            OrganizationConfig            = (& $OrganizationConfigCollection)
            MailboxAuditBypassAssociation = @(& $AuditBypassAssociationCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'EXO-006' -Source 'ExchangeOnline' `
        -Command 'Get-OrganizationConfig; Get-MailboxAuditBypassAssociation' -Collection $collection
}

# EXO-006: both halves are decided together. Auditing switched on organization-wide proves nothing
# about a mailbox whose bypass association is enabled, and an enabled bypass exempts that mailbox
# while `AuditDisabled` still reads as false - which is exactly how a tenant with every interesting
# mailbox exempted has been passing this control. An observation that is absent rather than empty
# is an `Error`, because an absent `AuditDisabled` member read as false reports auditing enabled on
# the strength of a member nobody observed.
$script:MailboxAuditingObservation = @('OrganizationConfig', 'MailboxAuditBypassAssociation')

function Test-MailboxAuditingControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence
    )

    $observationName = $script:MailboxAuditingObservation

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @()
        if ($null -ne $payload) { $present = @(Get-BaselineRecordMemberName -Node $payload) }

        foreach ($name in $observationName) {
            if ($name -cnotin $present) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "MailboxAuditingEvidenceIncomplete: the record carries no '$name' observation."
                }
            }
        }

        $organizationConfig = Get-BaselineRecordMember -Node $payload -Name 'OrganizationConfig'
        $organizationMember = @()
        if ($null -ne $organizationConfig) { $organizationMember = @(Get-BaselineRecordMemberName -Node $organizationConfig) }

        if ('AuditDisabled' -cnotin $organizationMember) {
            return [pscustomobject]@{
                Status = 'Error'
                Reason = "MailboxAuditingEvidenceIncomplete: the observed organization configuration carries no 'AuditDisabled' member."
            }
        }

        $association = @(Get-BaselineRecordMember -Node $payload -Name 'MailboxAuditBypassAssociation')

        $finding = @(
            if (Get-BaselineRecordMember -Node $organizationConfig -Name 'AuditDisabled') {
                'organization-wide mailbox auditing is disabled'
            }

            # Only an enabled bypass exempts a mailbox; an association that exists but is switched
            # off audits exactly like a mailbox that has none.
            $bypassed = @(foreach ($entry in $association) {
                    if (Get-BaselineRecordMember -Node $entry -Name 'AuditBypassEnabled') {
                        Get-BaselineRecordMember -Node $entry -Name 'Identity'
                    }
                })

            if ($bypassed.Count -gt 0) {
                "audit bypass is enabled for '{0}'" -f ($bypassed -join "', '")
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'MailboxAuditingGap: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'EXO-006' -Evidence $Evidence -Evaluator $evaluator
}

# EXO-007: the external sender identification configuration the tenant actually holds. The whole
# configuration is recorded rather than the enabled flag or the allow list alone, because the flag
# without the list decides only half the control and a list narrowed at collection time makes a
# configuration that carries no allow list indistinguishable from one whose allow list is empty.
function Get-ExternalSenderTagEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Collection
    )

    return Get-BaselineEvidence -ControlId 'EXO-007' -Source 'ExchangeOnline' -Command 'Get-ExternalInOutlook' -Collection $Collection
}

# EXO-007: the tag on the message is the only warning the recipient ever sees, and an allow-list
# entry removes it for that sender, so the enabled flag and the allow list are one control. The
# list is compared as a normalized set under the declared `SmtpAddress` rules, so the routing
# prefix, casing, whitespace and ordering Exchange Online reports back never read as drift, while
# an entry the baseline never declared always does. An allow list that was never observed is an
# `Error` rather than an empty one, because against the default desired state of no exemptions at
# all the two differ by exactly one silent pass.
$script:ExternalSenderTagObservation = @('Enabled', 'AllowList')

function Test-ExternalSenderTagControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ExpectedAllowList
    )

    # An allow list the baseline resolved to nothing is real desired state; one that was never
    # resolved is not, and the two must not decide the control the same way.
    if ($null -eq $ExpectedAllowList) {
        throw 'ExpectedAllowListRequired: EXO-007 cannot be decided without the sender allow list the baseline resolved; an evaluator with no desired state decides on the absence of configuration rather than on the tenant.'
    }

    $expectedAllowList = @(foreach ($entry in $ExpectedAllowList) { [string]$entry })
    $observationName = $script:ExternalSenderTagObservation

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $observed = @()
        if ($null -ne $payload) { $observed = @($payload) }

        if ($observed.Count -eq 0) {
            return [pscustomobject]@{
                Status = 'Fail'
                Reason = 'ExternalSenderTagGap: the tenant holds no external sender identification configuration.'
            }
        }

        foreach ($entry in $observed) {
            $present = @(Get-BaselineRecordMemberName -Node $entry)
            foreach ($name in $observationName) {
                if ($name -cnotin $present) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "ExternalSenderTagEvidenceIncomplete: the observed external sender identification carries no '$name' member."
                    }
                }
            }
        }

        $liveAllowList = @(foreach ($entry in $observed) {
                foreach ($value in @(Get-BaselineRecordMember -Node $entry -Name 'AllowList')) { [string]$value }
            })

        $comparison = Compare-NormalizedCollection -Desired $expectedAllowList -Actual $liveAllowList -Kind 'SmtpAddress'

        $disabled = @(foreach ($entry in $observed) {
                if (-not (Get-BaselineRecordMember -Node $entry -Name 'Enabled')) { $entry }
            })

        $finding = @(
            if ($disabled.Count -gt 0) {
                'external sender identification is disabled'
            }

            if (@($comparison.Surplus).Count -gt 0) {
                "the allow list holds '{0}' which the baseline does not declare" -f (@($comparison.Surplus) -join "', '")
            }

            if (@($comparison.Missing).Count -gt 0) {
                "the allow list does not hold '{0}'" -f (@($comparison.Missing) -join "', '")
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'ExternalSenderTagGap: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'EXO-007' -Evidence $Evidence -Evaluator $evaluator
}

# EXO-008: the remote domains the tenant actually holds. Every domain is recorded whole rather than
# the default domain alone or the five members the control decides on, because a non-default remote
# domain overrides the default for the addresses it covers, so narrowing the collection to `Default`
# reports a posture that does not apply to the mail that matters most.
function Get-RemoteDomainEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Collection
    )

    return Get-BaselineEvidence -ControlId 'EXO-008' -Source 'ExchangeOnline' -Command 'Get-RemoteDomain' -Collection $Collection
}

# EXO-008: the five values a remote domain is decided by, each paired with the name the baseline
# resolves it under. Exchange Online reports the non-delivery report switch as `NDREnabled` while
# the baseline declares it as `nonDeliveryReportEnabled`, so the pairing is declared once here
# rather than restated at each comparison.
$script:RemoteDomainDecidedMember = @(
    [pscustomobject]@{ Observed = 'AutoForwardEnabled'; Desired = 'autoForwardEnabled' }
    [pscustomobject]@{ Observed = 'AutoReplyEnabled'; Desired = 'autoReplyEnabled' }
    [pscustomobject]@{ Observed = 'AllowedOOFType'; Desired = 'allowedOOFType' }
    [pscustomobject]@{ Observed = 'DeliveryReportEnabled'; Desired = 'deliveryReportEnabled' }
    [pscustomobject]@{ Observed = 'NDREnabled'; Desired = 'nonDeliveryReportEnabled' }
)

# EXO-008: all five values are decided on every domain the tenant returned, because the shipping
# script decided three of them on one domain - and a remote domain created beside the default with
# automatic forwarding switched on overrides the default for exactly the addresses somebody created
# it for, which is the route this control exists to close. Each failure names the domain, the
# member, the value the tenant holds and the value the baseline requires, so an operator can act on
# one reading. A member that was never observed is an `Error`, because read as off it reports a
# hardened domain from a value nobody read.
function Test-RemoteDomainControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$DesiredState
    )

    if ($null -eq $DesiredState) {
        throw 'DesiredRemoteDomainStateRequired: EXO-008 cannot be decided without the remote-domain state the baseline resolved; an evaluator with no desired state decides the five values against whatever it defaults to rather than against what was approved.'
    }

    $decidedMember = $script:RemoteDomainDecidedMember
    $declared = @(Get-BaselineRecordMemberName -Node $DesiredState)
    $desired = [ordered]@{}

    foreach ($pair in $decidedMember) {
        $value = if ($pair.Desired -cin $declared) { Get-BaselineRecordMember -Node $DesiredState -Name $pair.Desired } else { $null }
        if ($null -eq $value) {
            throw "DesiredRemoteDomainMemberRequired: EXO-008 cannot be decided without a resolved '$($pair.Desired)' value; four values compared against the baseline and a fifth compared against nothing reads as a fully compared domain."
        }

        $desired[$pair.Observed] = $value
    }

    # One rule for all five, because four are switches and one is an out-of-office type, and the
    # casing and surrounding whitespace Exchange Online reports back is never drift.
    $normalize = { param($Value) ([string]$Value).Trim().ToLowerInvariant() }

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $observed = @()
        if ($null -ne $payload) { $observed = @($payload) }

        if ($observed.Count -eq 0) {
            return [pscustomobject]@{
                Status = 'Fail'
                Reason = 'RemoteDomainDrift: the tenant holds no remote domain at all.'
            }
        }

        foreach ($domain in $observed) {
            $present = @(Get-BaselineRecordMemberName -Node $domain)
            foreach ($pair in $decidedMember) {
                if ($pair.Observed -cnotin $present) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "RemoteDomainEvidenceIncomplete: an observed remote domain carries no '$($pair.Observed)' member."
                    }
                }
            }
        }

        $finding = @(
            foreach ($domain in $observed) {
                $identity = Get-BaselineRecordMember -Node $domain -Name 'Identity'

                foreach ($pair in $decidedMember) {
                    $live = Get-BaselineRecordMember -Node $domain -Name $pair.Observed
                    $want = $desired[$pair.Observed]
                    if ((& $normalize $live) -ceq (& $normalize $want)) { continue }

                    "remote domain '{0}' reports '{1}' as '{2}' where the baseline requires '{3}'" -f `
                        $identity, $pair.Observed, $live, $want
                }
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'RemoteDomainDrift: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'EXO-008' -Evidence $Evidence -Evaluator $evaluator
}

# EXO-009: the three observations the legacy protocol surface is decided from. The organization
# switch and its allow list are tenant-wide, the mailbox plan decides what every mailbox created
# after today is born with, and the existing mailboxes are what hardening the plan does not change
# - which is why the shipping script, reading the first two only, reports a closed tenant while
# every mailbox created before the plan was hardened still speaks POP and IMAP. Each command is
# reached only through the supplied seam, inside the one try Get-BaselineEvidence runs, so a
# refusal from any of the three is recorded as an uncollected observation rather than thrown.
$script:ClientProtocolObservation = @('OrganizationConfig', 'CasMailboxPlan', 'CasMailbox')

function Get-ClientProtocolEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$OrganizationConfigCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$CasMailboxPlanCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$CasMailboxCollection
    )

    if ($null -eq $OrganizationConfigCollection) {
        throw 'OrganizationConfigCollectionRequired: EXO-009 cannot be observed without a collection that reaches the organization configuration.'
    }

    if ($null -eq $CasMailboxPlanCollection) {
        throw 'CasMailboxPlanCollectionRequired: EXO-009 cannot be observed without a collection that reaches the client access mailbox plans.'
    }

    if ($null -eq $CasMailboxCollection) {
        throw 'CasMailboxCollectionRequired: EXO-009 cannot be observed without a collection that reaches the existing client access mailboxes.'
    }

    $collection = {
        [ordered]@{
            OrganizationConfig = (& $OrganizationConfigCollection)
            CasMailboxPlan     = @(& $CasMailboxPlanCollection)
            CasMailbox         = @(& $CasMailboxCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'EXO-009' -Source 'ExchangeOnline' `
        -Command 'Get-OrganizationConfig; Get-CASMailboxPlan; Get-CASMailbox' -Collection $collection
}

# EXO-009: the members each scope is decided by. The organization carries the tenant-wide EWS
# switch and its allow list; a plan and a mailbox each carry all four values plus the identity
# every failure has to name, because an operator told a legacy protocol is open somewhere cannot
# act on it.
$script:ClientProtocolOrganizationMember = @('EwsEnabled', 'EwsAllowList')
$script:ClientProtocolScopedMember = @('Identity', 'EwsEnabled', 'EwsAllowList', 'PopEnabled', 'ImapEnabled')

# The three switches, each paired with the name the baseline resolves it under. The organization
# carries only the first; a plan and a mailbox carry all three.
$script:ClientProtocolSwitch = @(
    [pscustomobject]@{ Observed = 'EwsEnabled'; Desired = 'ewsEnabled' }
    [pscustomobject]@{ Observed = 'PopEnabled'; Desired = 'popEnabledByDefault' }
    [pscustomobject]@{ Observed = 'ImapEnabled'; Desired = 'imapEnabledByDefault' }
)

# EXO-009: the three scopes are decided together because the tenant is only as closed as the
# weakest one. The shipping script reads the organization switch and the mailbox plans, so a tenant
# whose plans are all clean still passes while every mailbox created before somebody cleaned them
# keeps POP and IMAP - the existing mailboxes are the gap. The allow list is decided at every scope
# rather than once tenant-wide, because an entry reopens EWS for exactly the application named in
# it and is settable per plan and per mailbox. It is compared as a normalized set so the casing,
# surrounding whitespace and repetition Exchange Online reports back is never drift, while an entry
# the baseline never declared - and an approved one silently missing - always is.
function Test-ClientProtocolControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$DesiredState
    )

    if ($null -eq $DesiredState) {
        throw 'DesiredProtocolStateRequired: EXO-009 cannot be decided without the protocol state the baseline resolved; an evaluator with no desired state decides the protocol surface against whatever it defaults to rather than against what was approved.'
    }

    $declared = @(Get-BaselineRecordMemberName -Node $DesiredState)
    $resolve = {
        param($Name)

        $value = if ($Name -cin $declared) { Get-BaselineRecordMember -Node $DesiredState -Name $Name } else { $null }
        if ($null -eq $value) {
            throw "DesiredProtocolMemberRequired: EXO-009 cannot be decided without a resolved '$Name' value; three protocols compared against the baseline and a fourth compared against nothing reads as a fully compared tenant."
        }

        return $value
    }

    $desired = [ordered]@{}
    foreach ($pair in $script:ClientProtocolSwitch) {
        $desired[$pair.Observed] = & $resolve $pair.Desired
    }

    # The EWS allow list holds application identifiers, which the canonical comparison contract
    # declares no kind for, so the set is normalized here under the same trim-and-lower rule both
    # sides are held to.
    $normalize = { param($Value) ([string]$Value).Trim().ToLowerInvariant() }
    $normalizeList = {
        param($Collection)

        $value = @(foreach ($item in @($Collection)) { ([string]$item).Trim().ToLowerInvariant() })
        return , @(@($value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique) | Sort-Object -CaseSensitive)
    }

    $desiredAllowList = & $normalizeList (& $resolve 'ewsAllowList')

    $observationName = $script:ClientProtocolObservation
    $organizationMember = $script:ClientProtocolOrganizationMember
    $scopedMember = $script:ClientProtocolScopedMember
    $organizationSwitch = @($script:ClientProtocolSwitch | Where-Object { $_.Observed -ceq 'EwsEnabled' })
    $scopedSwitch = $script:ClientProtocolSwitch

    $decideScope = {
        param($Node, $Label, $SwitchPair)

        foreach ($pair in $SwitchPair) {
            $live = Get-BaselineRecordMember -Node $Node -Name $pair.Observed
            $want = $desired[$pair.Observed]
            if ((& $normalize $live) -ceq (& $normalize $want)) { continue }

            "{0} reports '{1}' as '{2}' where the baseline requires '{3}'" -f $Label, $pair.Observed, $live, $want
        }

        $liveAllowList = & $normalizeList (Get-BaselineRecordMember -Node $Node -Name 'EwsAllowList')
        $surplus = @($liveAllowList | Where-Object { $_ -cnotin $desiredAllowList })
        $missing = @($desiredAllowList | Where-Object { $_ -cnotin $liveAllowList })

        if ($surplus.Count -gt 0) {
            "the EWS allow list of {0} holds '{1}' which the baseline does not declare" -f $Label, ($surplus -join "', '")
        }

        if ($missing.Count -gt 0) {
            "the EWS allow list of {0} does not hold '{1}'" -f $Label, ($missing -join "', '")
        }
    }

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @()
        if ($null -ne $payload) { $present = @(Get-BaselineRecordMemberName -Node $payload) }

        foreach ($name in $observationName) {
            if ($name -cnotin $present) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "ClientProtocolEvidenceIncomplete: the record carries no '$name' observation."
                }
            }
        }

        $organization = Get-BaselineRecordMember -Node $payload -Name 'OrganizationConfig'
        $observedOrganizationMember = @()
        if ($null -ne $organization) { $observedOrganizationMember = @(Get-BaselineRecordMemberName -Node $organization) }

        foreach ($name in $organizationMember) {
            if ($name -cnotin $observedOrganizationMember) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "ClientProtocolEvidenceIncomplete: the observed organization configuration carries no '$name' member."
                }
            }
        }

        $plan = @(Get-BaselineRecordMember -Node $payload -Name 'CasMailboxPlan')
        $mailbox = @(Get-BaselineRecordMember -Node $payload -Name 'CasMailbox')

        foreach ($scope in @(
                [pscustomobject]@{ Entry = $plan; Noun = 'mailbox plan' }
                [pscustomobject]@{ Entry = $mailbox; Noun = 'mailbox' }
            )) {
            foreach ($entry in $scope.Entry) {
                foreach ($name in $scopedMember) {
                    if ($name -cnotin @(Get-BaselineRecordMemberName -Node $entry)) {
                        return [pscustomobject]@{
                            Status = 'Error'
                            Reason = "ClientProtocolEvidenceIncomplete: an observed $($scope.Noun) carries no '$name' member."
                        }
                    }
                }
            }
        }

        $finding = @(
            & $decideScope $organization 'the organization' $organizationSwitch

            foreach ($entry in $plan) {
                & $decideScope $entry ("mailbox plan '{0}'" -f (Get-BaselineRecordMember -Node $entry -Name 'Identity')) $scopedSwitch
            }

            foreach ($entry in $mailbox) {
                & $decideScope $entry ("mailbox '{0}'" -f (Get-BaselineRecordMember -Node $entry -Name 'Identity')) $scopedSwitch
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'LegacyProtocolOpen: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'EXO-009' -Evidence $Evidence -Evaluator $evaluator
}

# EXO-010: the five observations privilege is decided from. Exchange role membership alone reports
# who holds a role today and nothing about who can elevate into it, active and eligible PIM
# assignments report the elevation without the Exchange-side grants that bypass it, and neither
# says whether anybody has looked lately - so all five are observed together or the posture is
# decided from whichever quarter of it happened to be wired up. Each service is reached only
# through the supplied seam, inside the one try Get-BaselineEvidence runs, so a refusal from any of
# the five is recorded as an uncollected observation rather than thrown.
$script:RoleAssignmentObservation = @('RoleGroup', 'ManagementRoleAssignment', 'ActivePimAssignment', 'EligiblePimAssignment', 'AccessReview')

function Get-ExchangeRoleAssignmentEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$RoleGroupCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$ManagementRoleAssignmentCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$ActivePimAssignmentCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$EligiblePimAssignmentCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$AccessReviewCollection
    )

    if ($null -eq $RoleGroupCollection) {
        throw 'RoleGroupCollectionRequired: EXO-010 cannot be observed without a collection that reaches the Exchange role groups.'
    }

    if ($null -eq $ManagementRoleAssignmentCollection) {
        throw 'ManagementRoleAssignmentCollectionRequired: EXO-010 cannot be observed without a collection that reaches the management role assignments.'
    }

    if ($null -eq $ActivePimAssignmentCollection) {
        throw 'ActivePimAssignmentCollectionRequired: EXO-010 cannot be observed without a collection that reaches the active PIM assignments.'
    }

    if ($null -eq $EligiblePimAssignmentCollection) {
        throw 'EligiblePimAssignmentCollectionRequired: EXO-010 cannot be observed without a collection that reaches the eligible PIM assignments.'
    }

    if ($null -eq $AccessReviewCollection) {
        throw 'AccessReviewCollectionRequired: EXO-010 cannot be observed without a collection that reaches the access reviews.'
    }

    $collection = {
        [ordered]@{
            RoleGroup                = @(& $RoleGroupCollection)
            ManagementRoleAssignment = @(& $ManagementRoleAssignmentCollection)
            ActivePimAssignment      = @(& $ActivePimAssignmentCollection)
            EligiblePimAssignment    = @(& $EligiblePimAssignmentCollection)
            AccessReview             = @(& $AccessReviewCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'EXO-010' -Source 'ExchangeOnline,MicrosoftGraph' `
        -Command 'Get-RoleGroup; Get-ManagementRoleAssignment; GET /roleManagement/directory/roleAssignmentScheduleInstances; GET /roleManagement/directory/roleEligibilityScheduleInstances; GET /identityGovernance/accessReviews/definitions' `
        -Collection $collection
}

# EXO-010: the members a role group is decided by. A group with no name cannot be matched against
# the groups the baseline governs and a group with no membership reads as a group nobody is in, so
# either absence lets a privileged group pass by never being examined.
$script:RoleGroupDecidedMember = @('Name', 'Members')

# EXO-010: the shipping script reports this control as `Manual` after counting role groups, so a
# tenant with a standing administrator on every mailbox passes today by having a countable number
# of them. The four routes into privilege are decided together because closing any three of them
# leaves the tenant exactly as exposed as closing none: standing membership of a governed group, a
# role assigned straight to a user outside every group and outside PIM, an active assignment with
# no end, and eligibility for a role nobody declared. The review clause is what makes the other
# four evidence of governance rather than of one good day.
function Test-ExchangeRoleAssignmentControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$PrivilegedRoleGroup,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ApprovedMember,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$GovernedRole,

        [Parameter(Mandatory)]
        [int]$MaximumReviewAgeDay,

        # Injected rather than read, so a review that is current today does not become stale the
        # day the same evidence is re-decided.
        [datetime]$AsAtUtc = [datetime]::UtcNow
    )

    $caseRule = @('Trim', 'LowerInvariant')
    $normalize = { param($Value) ConvertTo-NormalizedCanonicalValue -Value ([string]$Value) -Rule $caseRule }

    $privilegedRoleGroup = @(foreach ($name in @($PrivilegedRoleGroup)) {
            if (-not [string]::IsNullOrWhiteSpace($name)) { & $normalize $name }
        })
    if ($privilegedRoleGroup.Count -eq 0) {
        throw 'PrivilegedRoleGroupRequired: EXO-010 cannot be decided without the role groups the baseline treats as privileged; a control that governs no role group is satisfied by every tenant.'
    }

    # An approved list the baseline resolved to nothing means no principal may hold standing
    # membership; one that was never resolved means nobody decided, and reading the second as the
    # first approves every member the tenant happens to hold.
    if ($null -eq $ApprovedMember) {
        throw 'ApprovedMemberRequired: EXO-010 cannot be decided without the members the baseline approves; an evaluator with no approved list approves everybody it finds.'
    }

    $governedRole = @(foreach ($role in @($GovernedRole)) {
            if (-not [string]::IsNullOrWhiteSpace($role)) { & $normalize $role }
        })
    if ($governedRole.Count -eq 0) {
        throw 'GovernedRoleRequired: EXO-010 cannot be decided without the roles the baseline governs; a control that governs no role reviews nothing and finds every eligibility acceptable.'
    }

    if ($MaximumReviewAgeDay -le 0) {
        throw 'ReviewIntervalRequired: EXO-010 cannot be decided without the review interval the baseline resolved; an interval nobody resolved accepts a review of any age, including one that never happened again.'
    }

    $approvedMember = @(foreach ($member in $ApprovedMember) {
            if (-not [string]::IsNullOrWhiteSpace($member)) { & $normalize $member }
        })

    $observationName = $script:RoleAssignmentObservation
    $decidedMember = $script:RoleGroupDecidedMember
    $reviewInterval = $MaximumReviewAgeDay
    $asAt = $AsAtUtc

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @(Get-BaselineRecordMemberName -Node $payload)

        foreach ($name in $observationName) {
            if ($name -cnotin $present) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "RoleAssignmentEvidenceIncomplete: the record carries no '$name' observation."
                }
            }
        }

        $roleGroup = @(Get-BaselineRecordMember -Node $payload -Name 'RoleGroup')
        $roleAssignment = @(Get-BaselineRecordMember -Node $payload -Name 'ManagementRoleAssignment')
        $activeAssignment = @(Get-BaselineRecordMember -Node $payload -Name 'ActivePimAssignment')
        $eligibleAssignment = @(Get-BaselineRecordMember -Node $payload -Name 'EligiblePimAssignment')
        $accessReview = @(Get-BaselineRecordMember -Node $payload -Name 'AccessReview')

        foreach ($group in $roleGroup) {
            foreach ($member in $decidedMember) {
                if ($member -cnotin @(Get-BaselineRecordMemberName -Node $group)) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "RoleAssignmentEvidenceIncomplete: an observed role group carries no '$member' member."
                    }
                }
            }
        }

        # Parsed once, before any verdict, because a completion time nobody can read is a review
        # age nobody knows rather than a review that is current.
        $reviewAge = @{}
        foreach ($review in $accessReview) {
            $reported = [string](Get-BaselineRecordMember -Node $review -Name 'lastCompletedDateTime')
            if ([string]::IsNullOrWhiteSpace($reported)) { continue }

            $completed = [datetime]::MinValue
            $style = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
            if (-not [datetime]::TryParse($reported, [cultureinfo]::InvariantCulture, $style, [ref]$completed)) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "RoleAssignmentEvidenceIncomplete: the access review '$(Get-BaselineRecordMember -Node $review -Name 'displayName')' reports a completion time of '$reported' that cannot be read."
                }
            }

            $reviewAge[[string](Get-BaselineRecordMember -Node $review -Name 'displayName')] = $completed
        }

        $finding = @(
            foreach ($group in $roleGroup) {
                $name = [string](Get-BaselineRecordMember -Node $group -Name 'Name')
                if ((& $normalize $name) -cnotin $privilegedRoleGroup) { continue }

                foreach ($member in @(Get-BaselineRecordMember -Node $group -Name 'Members')) {
                    $identifier = [string]$member
                    if ([string]::IsNullOrWhiteSpace($identifier)) { continue }

                    if ((& $normalize $identifier) -cnotin $approvedMember) {
                        "privileged role group '{0}' holds '{1}' which the baseline does not approve" -f $name, $identifier
                    }
                }
            }

            # A role held straight by a user sits outside every role group the baseline governs and
            # outside PIM entirely, so it survives every membership review the tenant runs.
            foreach ($assignment in $roleAssignment) {
                if ([string](Get-BaselineRecordMember -Node $assignment -Name 'RoleAssigneeType') -cne 'User') { continue }

                "management role '{0}' is assigned directly to user '{1}' rather than to a role group" -f `
                (Get-BaselineRecordMember -Node $assignment -Name 'Role'),
                (Get-BaselineRecordMember -Node $assignment -Name 'RoleAssigneeName')
            }

            foreach ($assignment in $activeAssignment) {
                if (-not [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember -Node $assignment -Name 'endDateTime'))) { continue }

                "the active assignment of role '{0}' to '{1}' is permanent rather than time-bound" -f `
                (Get-BaselineRecordMember -Node $assignment -Name 'roleDefinitionId'),
                (Get-BaselineRecordMember -Node $assignment -Name 'principalId')
            }

            foreach ($assignment in $eligibleAssignment) {
                $role = [string](Get-BaselineRecordMember -Node $assignment -Name 'roleDefinitionId')
                if ((& $normalize $role) -cin $governedRole) { continue }

                "the eligible assignment of role '{0}' to '{1}' is for a role the baseline does not govern" -f `
                    $role, (Get-BaselineRecordMember -Node $assignment -Name 'principalId')
            }

            foreach ($role in $governedRole) {
                $scoped = @(foreach ($review in $accessReview) {
                        if ((& $normalize (Get-BaselineRecordMember -Node $review -Name 'scopeRoleDefinitionId')) -ceq $role) { $review }
                    })

                if ($scoped.Count -eq 0) {
                    "role '{0}' carries no access review" -f $role
                    continue
                }

                foreach ($review in $scoped) {
                    $displayName = [string](Get-BaselineRecordMember -Node $review -Name 'displayName')
                    $reported = [string](Get-BaselineRecordMember -Node $review -Name 'lastCompletedDateTime')

                    if ([string]::IsNullOrWhiteSpace($reported)) {
                        "the access review '{0}' for role '{1}' has never completed" -f $displayName, $role
                        continue
                    }

                    # Counted inclusively, so a tenant that reviews exactly on schedule passes on
                    # the day the schedule falls due rather than the day before it.
                    if (($asAt - $reviewAge[$displayName]).TotalDays -gt $reviewInterval) {
                        "the access review '{0}' for role '{1}' last completed on '{2}', beyond the {3}-day review interval" -f `
                            $displayName, $role, $reported, $reviewInterval
                    }
                }
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'PrivilegeUngoverned: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'EXO-010' -Evidence $Evidence -Evaluator $evaluator
}

# EXO-002: SMTP AUTH is switched off organization-wide, but a per-mailbox setting overrides that
# switch for the mailbox that carries it, so the organization value alone reports a closed tenant
# while the service accounts everybody forgot still accept basic authentication. One record
# therefore carries both observations under their own names, and either command refusing makes the
# whole record uncollected.
function Get-SmtpAuthenticationEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$TransportConfigCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$CasMailboxCollection
    )

    if ($null -eq $TransportConfigCollection) {
        throw 'TransportConfigCollectionRequired: EXO-002 cannot be observed without a collection that reaches the transport configuration.'
    }

    if ($null -eq $CasMailboxCollection) {
        throw 'CasMailboxCollectionRequired: EXO-002 cannot be observed without a collection that reaches the client access mailboxes.'
    }

    # Both collections are invoked inside the one seam Get-BaselineEvidence runs, so a refusal from
    # either is recorded as an uncollected observation rather than thrown.
    $collection = {
        [ordered]@{
            TransportConfig = (& $TransportConfigCollection)
            CasMailbox      = @(& $CasMailboxCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' `
        -Command 'Get-TransportConfig; Get-CASMailbox' -Collection $collection
}

# EXO-002: both halves are decided together. SMTP AUTH disabled organization-wide proves nothing
# about a mailbox whose per-mailbox setting re-enables it, and that mailbox is always the service
# account nobody owns. A mailbox that has left the setting unset inherits the organization switch
# and one that sets it to disabled agrees with it, so neither is drift; only a mailbox that sets it
# to enabled overrides the tenant. An observation that is absent rather than empty is an `Error`,
# because an absent `SmtpClientAuthenticationDisabled` member read as true reports a closed tenant
# on the strength of a member nobody observed.
$script:SmtpAuthenticationObservation = @('TransportConfig', 'CasMailbox')
$script:CasMailboxDecidedMember = @('Identity', 'SmtpClientAuthenticationDisabled')

function Test-SmtpAuthenticationControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence
    )

    $observationName = $script:SmtpAuthenticationObservation
    $decidedMember = $script:CasMailboxDecidedMember

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @()
        if ($null -ne $payload) { $present = @(Get-BaselineRecordMemberName -Node $payload) }

        foreach ($name in $observationName) {
            if ($name -cnotin $present) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "SmtpAuthenticationEvidenceIncomplete: the record carries no '$name' observation."
                }
            }
        }

        $transportConfig = Get-BaselineRecordMember -Node $payload -Name 'TransportConfig'
        $transportMember = @()
        if ($null -ne $transportConfig) { $transportMember = @(Get-BaselineRecordMemberName -Node $transportConfig) }

        if ('SmtpClientAuthenticationDisabled' -cnotin $transportMember) {
            return [pscustomobject]@{
                Status = 'Error'
                Reason = "SmtpAuthenticationEvidenceIncomplete: the observed transport configuration carries no 'SmtpClientAuthenticationDisabled' member."
            }
        }

        $mailbox = @(Get-BaselineRecordMember -Node $payload -Name 'CasMailbox')

        foreach ($entry in $mailbox) {
            foreach ($member in $decidedMember) {
                if ($member -cnotin @(Get-BaselineRecordMemberName -Node $entry)) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "SmtpAuthenticationEvidenceIncomplete: an observed mailbox carries no '$member' member."
                    }
                }
            }
        }

        $finding = @(
            if (-not (Get-BaselineRecordMember -Node $transportConfig -Name 'SmtpClientAuthenticationDisabled')) {
                'SMTP client authentication is enabled organization-wide'
            }

            # Only an explicit `false` overrides the organization switch; an unset setting inherits
            # it and authenticates exactly like a mailbox that agrees with it.
            foreach ($entry in $mailbox) {
                $setting = Get-BaselineRecordMember -Node $entry -Name 'SmtpClientAuthenticationDisabled'
                if ($null -eq $setting -or $setting) { continue }

                "mailbox '{0}' enables SMTP client authentication by a per-mailbox override" -f `
                (Get-BaselineRecordMember -Node $entry -Name 'Identity')
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'SmtpAuthenticationOpen: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'EXO-002' -Evidence $Evidence -Evaluator $evaluator
}

# EXO-011: the four observations transport security is decided from. The discovery record tells a
# sending server a policy exists, the policy document is the only place the mode, the maximum age
# and the covered MX hosts are written down, the published MX answer is what the policy has to
# cover before enforce mode can be reached without losing mail, and the TLS-RPT record is the only
# thing that reports a failed negotiation to anybody. Both shipping scripts answer this control
# with a literal `Manual`, which is the one status a go-live gate cannot act on. Every lookup and
# the policy fetch are reached only through the supplied seam, inside the one try
# Get-BaselineEvidence runs, so a refusal from any of the four is recorded as an uncollected
# observation rather than thrown - and no query and no request is issued by this module itself.
$script:MtaStsObservation = @('MtaStsRecord', 'MtaStsPolicy', 'TlsRptRecord', 'MxRecord')

function Get-MtaStsEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$MtaStsRecordCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$MtaStsPolicyCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$TlsRptRecordCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$MxRecordCollection
    )

    if ($null -eq $MtaStsRecordCollection) {
        throw 'MtaStsRecordCollectionRequired: EXO-011 cannot be observed without a collection that reaches the MTA-STS discovery record.'
    }

    if ($null -eq $MtaStsPolicyCollection) {
        throw 'MtaStsPolicyCollectionRequired: EXO-011 cannot be observed without a collection that fetches the MTA-STS policy document.'
    }

    if ($null -eq $TlsRptRecordCollection) {
        throw 'TlsRptRecordCollectionRequired: EXO-011 cannot be observed without a collection that reaches the TLS-RPT record.'
    }

    if ($null -eq $MxRecordCollection) {
        throw 'MxRecordCollectionRequired: EXO-011 cannot be observed without a collection that reaches the published MX record.'
    }

    $collection = {
        [ordered]@{
            MtaStsRecord = (& $MtaStsRecordCollection)
            MtaStsPolicy = (& $MtaStsPolicyCollection)
            TlsRptRecord = (& $TlsRptRecordCollection)
            MxRecord     = (& $MxRecordCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'EXO-011' -Source 'Dns' `
        -Command 'Resolve-DnsName -Type TXT _mta-sts; Invoke-WebRequest mta-sts.txt; Resolve-DnsName -Type TXT _smtp._tls; Resolve-DnsName -Type MX' `
        -Collection $collection
}

# EXO-011: the members each observed answer is decided by. Every DNS answer carries whether the
# server that gave it was authoritative for the zone, because a recursive resolver answers from a
# cache that can outlive the record by the whole of its time to live - and the record that was just
# withdrawn is the one still cached, so a non-authoritative answer is wrong in the flattering
# direction. The policy fetch carries how it was reached as well as what it returned, because a
# document a sender could not fetch over authenticated HTTPS commits the domain to nothing.
$script:MtaStsTxtDecidedMember = @('Authoritative', 'Strings')
$script:MtaStsMxDecidedMember = @('Authoritative', 'NameExchange')
$script:MtaStsPolicyDecidedMember = @('Scheme', 'TlsValidated', 'StatusCode', 'ContentType', 'Content')

# RFC 8461 requires all four directives, and a sender that cannot parse one discards the whole
# policy rather than applying the rest.
$script:MtaStsPolicyDirective = @('version', 'mode', 'mx', 'max_age')

$script:MtaStsAuthoritativeAnswer = @(
    [pscustomobject]@{ Observation = 'MtaStsRecord'; Noun = 'MTA-STS discovery' }
    [pscustomobject]@{ Observation = 'TlsRptRecord'; Noun = 'TLS-RPT' }
    [pscustomobject]@{ Observation = 'MxRecord'; Noun = 'MX' }
)

# EXO-011: the four observations are decided together because each one on its own reports a domain
# that is protected. A discovery record announces a policy nobody has read, a policy document
# commits a domain nobody was told to check, MX coverage only matters once a policy exists, and a
# TLS-RPT destination is the only place a failed negotiation is ever visible. Both shipping scripts
# answer this control with a literal `Manual`; it is now decided from evidence, and an answer the
# run could not collect or could not trust is `Error` rather than a silent pass. Everything a real
# domain reports back that is not drift is normalized on both sides - a media type carrying a
# charset parameter, policy keys in any casing separated by carriage returns, values padded with
# whitespace, a host reported with the trailing root label, a wildcard MX pattern that covers the
# host, and a TXT answer split across character strings because it outgrew one.
function Test-MtaStsControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$DesiredState
    )

    if ($null -eq $DesiredState) {
        throw 'DesiredTransportSecurityStateRequired: EXO-011 cannot be decided without the transport-security state the baseline resolved; an evaluator with no desired state decides the published policy against whatever it defaults to rather than against what was approved.'
    }

    $declared = @(Get-BaselineRecordMemberName -Node $DesiredState)
    $resolve = {
        param($Name)

        $value = if ($Name -cin $declared) { Get-BaselineRecordMember -Node $DesiredState -Name $Name } else { $null }
        if ($null -eq $value) {
            throw "DesiredTransportSecurityMemberRequired: EXO-011 cannot be decided without a resolved '$Name' value; two values compared against the baseline and a third compared against nothing reads as a fully decided domain."
        }

        return $value
    }

    $desiredMode = & $resolve 'mtaStsMode'
    $desiredMaxAge = & $resolve 'mtaStsMaxAgeSeconds'
    $desiredTlsRptAddress = & $resolve 'tlsRptAddress'

    $normalize = { param($Value) ([string]$Value).Trim().ToLowerInvariant() }

    # DNS returns a host name with the trailing root label; a policy is written without it.
    $normalizeHost = { param($Value) ([string]$Value).Trim().TrimEnd('.').ToLowerInvariant() }

    # A TXT record longer than one character string comes back split at an arbitrary octet, and the
    # record is the concatenation rather than any one of the pieces.
    $joinStrings = {
        param($Collection)

        return (-join @(foreach ($item in @($Collection)) { [string]$item }))
    }

    # `v=STSv1; id=...` and `v=TLSRPTv1; rua=...` are both tag-value records.
    $parseTag = {
        param($Text)

        $tag = [ordered]@{}
        foreach ($part in ([string]$Text -split ';')) {
            $trimmed = $part.Trim()
            $split = $trimmed.IndexOf('=')
            if ($split -lt 1) { continue }

            $name = $trimmed.Substring(0, $split).Trim().ToLowerInvariant()
            if ($tag.Contains($name)) { continue }

            $tag[$name] = $trimmed.Substring($split + 1).Trim()
        }

        return $tag
    }

    # The policy document is `key: value` per line, and `mx` may appear more than once.
    $parsePolicy = {
        param($Text)

        $directive = [ordered]@{}
        foreach ($line in ([string]$Text -split "`r?`n")) {
            $trimmed = $line.Trim()
            $split = $trimmed.IndexOf(':')
            if ($split -lt 1) { continue }

            $name = $trimmed.Substring(0, $split).Trim().ToLowerInvariant()
            if (-not $directive.Contains($name)) { $directive[$name] = [System.Collections.Generic.List[string]]::new() }

            $directive[$name].Add($trimmed.Substring($split + 1).Trim())
        }

        return $directive
    }

    $covers = {
        param($Pattern, $HostName)

        $declaredPattern = & $normalizeHost $Pattern
        if ($declaredPattern.StartsWith('*.')) {
            $suffix = $declaredPattern.Substring(1)
            return $HostName.EndsWith($suffix) -and $HostName.Length -gt $suffix.Length
        }

        return $HostName -ceq $declaredPattern
    }

    $observationName = $script:MtaStsObservation
    $txtMember = $script:MtaStsTxtDecidedMember
    $mxMember = $script:MtaStsMxDecidedMember
    $policyMember = $script:MtaStsPolicyDecidedMember
    $requiredDirective = $script:MtaStsPolicyDirective
    $authoritativeAnswer = $script:MtaStsAuthoritativeAnswer

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @()
        if ($null -ne $payload) { $present = @(Get-BaselineRecordMemberName -Node $payload) }

        foreach ($name in $observationName) {
            if ($name -cnotin $present) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "MtaStsEvidenceIncomplete: the record carries no '$name' observation."
                }
            }
        }

        $discovery = Get-BaselineRecordMember -Node $payload -Name 'MtaStsRecord'
        $policy = Get-BaselineRecordMember -Node $payload -Name 'MtaStsPolicy'
        $tlsRpt = Get-BaselineRecordMember -Node $payload -Name 'TlsRptRecord'
        $mx = Get-BaselineRecordMember -Node $payload -Name 'MxRecord'

        foreach ($scope in @(
                [pscustomobject]@{ Node = $discovery; Member = $txtMember; Noun = 'MTA-STS discovery record' }
                [pscustomobject]@{ Node = $tlsRpt; Member = $txtMember; Noun = 'TLS-RPT record' }
                [pscustomobject]@{ Node = $mx; Member = $mxMember; Noun = 'MX answer' }
                [pscustomobject]@{ Node = $policy; Member = $policyMember; Noun = 'MTA-STS policy fetch' }
            )) {
            $observed = @()
            if ($null -ne $scope.Node) { $observed = @(Get-BaselineRecordMemberName -Node $scope.Node) }

            foreach ($name in $scope.Member) {
                if ($name -cnotin $observed) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "MtaStsEvidenceIncomplete: the observed $($scope.Noun) carries no '$name' member."
                    }
                }
            }
        }

        foreach ($answer in $authoritativeAnswer) {
            $node = Get-BaselineRecordMember -Node $payload -Name $answer.Observation
            if (Get-BaselineRecordMember -Node $node -Name 'Authoritative') { continue }

            return [pscustomobject]@{
                Status = 'Error'
                Reason = "MtaStsEvidenceInconclusive: the $($answer.Noun) answer was not authoritative for the zone."
            }
        }

        $finding = @(
            $scheme = & $normalize (Get-BaselineRecordMember -Node $policy -Name 'Scheme')
            if ($scheme -cne 'https') {
                "the MTA-STS policy endpoint was reached over '$scheme' rather than 'https'"
            }

            if (-not (Get-BaselineRecordMember -Node $policy -Name 'TlsValidated')) {
                'the MTA-STS policy endpoint did not present a TLS chain that validated'
            }

            $status = & $normalize (Get-BaselineRecordMember -Node $policy -Name 'StatusCode')
            if ($status -cne '200') {
                "the MTA-STS policy endpoint answered with status '$status' rather than '200'"
            }

            # A real endpoint serves `text/plain; charset=utf-8`, and the parameter is not drift.
            $mediaType = & $normalize (([string](Get-BaselineRecordMember -Node $policy -Name 'ContentType')) -split ';')[0]
            if ($mediaType -cne 'text/plain') {
                "the MTA-STS policy endpoint answered with media type '$mediaType' rather than 'text/plain'"
            }

            $directive = & $parsePolicy (Get-BaselineRecordMember -Node $policy -Name 'Content')

            foreach ($name in $requiredDirective) {
                if (-not $directive.Contains($name)) {
                    "the MTA-STS policy declares no '$name'"
                }
            }

            if ($directive.Contains('version')) {
                $declaredVersion = @($directive['version'])[0]
                if ((& $normalize $declaredVersion) -cne 'stsv1') {
                    "the MTA-STS policy declares 'version' as '$declaredVersion' where the standard requires 'STSv1'"
                }
            }

            foreach ($pair in @(
                    [pscustomobject]@{ Name = 'mode'; Want = $desiredMode }
                    [pscustomobject]@{ Name = 'max_age'; Want = $desiredMaxAge }
                )) {
                if (-not $directive.Contains($pair.Name)) { continue }

                $live = @($directive[$pair.Name])[0]
                if ((& $normalize $live) -ceq (& $normalize $pair.Want)) { continue }

                "the MTA-STS policy declares '{0}' as '{1}' where the baseline requires '{2}'" -f $pair.Name, $live, $pair.Want
            }

            $publishedHost = @(
                foreach ($item in @(Get-BaselineRecordMember -Node $mx -Name 'NameExchange')) {
                    $name = & $normalizeHost $item
                    if (-not [string]::IsNullOrWhiteSpace($name)) { $name }
                }
            )

            if ($publishedHost.Count -eq 0) {
                # An empty answer makes every coverage comparison vacuously true.
                'the domain publishes no MX host at all'
            }
            elseif ($directive.Contains('mx')) {
                $pattern = @($directive['mx'])
                foreach ($name in $publishedHost) {
                    $covered = $false
                    foreach ($declaredPattern in $pattern) {
                        if (& $covers $declaredPattern $name) { $covered = $true; break }
                    }

                    if (-not $covered) { "the MTA-STS policy does not cover published MX host '$name'" }
                }
            }

            $discoveryText = & $joinStrings (Get-BaselineRecordMember -Node $discovery -Name 'Strings')
            if ([string]::IsNullOrWhiteSpace($discoveryText)) {
                'the domain publishes no MTA-STS discovery record'
            }
            else {
                $discoveryTag = & $parseTag $discoveryText
                $declaredVersion = if ($discoveryTag.Contains('v')) { $discoveryTag['v'] } else { '' }
                if ((& $normalize $declaredVersion) -cne 'stsv1') {
                    "the MTA-STS discovery record declares 'v=$declaredVersion' where the standard requires 'v=STSv1'"
                }

                # The id is the only signal a sender has that the document changed.
                $policyId = if ($discoveryTag.Contains('id')) { $discoveryTag['id'] } else { '' }
                if ([string]::IsNullOrWhiteSpace($policyId)) {
                    'the MTA-STS discovery record carries no policy id'
                }
            }

            $tlsRptText = & $joinStrings (Get-BaselineRecordMember -Node $tlsRpt -Name 'Strings')
            if ([string]::IsNullOrWhiteSpace($tlsRptText)) {
                'the domain publishes no TLS-RPT record'
            }
            else {
                $tlsRptTag = & $parseTag $tlsRptText
                $declaredVersion = if ($tlsRptTag.Contains('v')) { $tlsRptTag['v'] } else { '' }
                if ((& $normalize $declaredVersion) -cne 'tlsrptv1') {
                    "the TLS-RPT record declares 'v=$declaredVersion' where the standard requires 'v=TLSRPTv1'"
                }

                $destination = if ($tlsRptTag.Contains('rua')) { $tlsRptTag['rua'] } else { '' }
                if ((& $normalize $destination) -cne (& $normalize $desiredTlsRptAddress)) {
                    "the TLS-RPT record reports its destination as '$destination' where the baseline requires '$desiredTlsRptAddress'"
                }
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'TransportSecurityUnenforced: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'EXO-011' -Evidence $Evidence -Evaluator $evaluator
}

# EXO-012: what a user may install into their own mailbox is written in two places that only mean
# something together. `Get-RoleAssignmentPolicy` says which policy every mailbox falls under by
# default, and `Get-ManagementRoleAssignment` says which roles hang off each policy; neither on its
# own reports whether a user can acquire an add-in. Both are recorded whole - every policy, not the
# default one, and every assignment, not the add-in ones - because narrowing at collection decides
# which policy and which roles the control is about before any evaluator sees the tenant. Either
# command refusing makes the whole record uncollected, since a record built from half the tenant is
# indistinguishable from a record of a tenant with nothing to report.
function Get-AddInAcquisitionEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$RoleAssignmentPolicyCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$ManagementRoleAssignmentCollection
    )

    if ($null -eq $RoleAssignmentPolicyCollection) {
        throw 'RoleAssignmentPolicyCollectionRequired: EXO-012 cannot be observed without a collection that reaches the role assignment policies.'
    }

    if ($null -eq $ManagementRoleAssignmentCollection) {
        throw 'ManagementRoleAssignmentCollectionRequired: EXO-012 cannot be observed without a collection that reaches the management role assignments.'
    }

    # Both collections are invoked inside the one seam Get-BaselineEvidence runs, so a refusal from
    # either is recorded as an uncollected observation rather than thrown.
    $collection = {
        [ordered]@{
            RoleAssignmentPolicy     = @(& $RoleAssignmentPolicyCollection)
            ManagementRoleAssignment = @(& $ManagementRoleAssignmentCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'EXO-012' -Source 'ExchangeOnline' `
        -Command 'Get-RoleAssignmentPolicy; Get-ManagementRoleAssignment' -Collection $collection
}

$script:AddInAcquisitionObservation = [ordered]@{
    RoleAssignmentPolicy     = 'Get-RoleAssignmentPolicy'
    ManagementRoleAssignment = 'Get-ManagementRoleAssignment'
}

# EXO-012: the three management roles that let a user acquire an add-in into their own mailbox.
# Each is a separate grant and each is cleared separately, so a verdict names the role it found
# rather than reporting that add-ins are on.
$script:AddInAcquisitionRole = @('My Custom Apps', 'My Marketplace Apps', 'My ReadWriteMailboxApps')
$script:AddInAcquisitionDecision = 'outlookAddInsForUsers'
$script:RoleAssignmentPolicyDecidedMember = @('Identity', 'IsDefault')
$script:ManagementRoleAssignmentDecidedMember = @('Role', 'RoleAssignee')

# EXO-012: the default role assignment policy is the one every mailbox falls under without anybody
# choosing it, so it is the only policy this control decides. An add-in acquisition role hanging
# off a policy somebody deliberately assigned is out of scope rather than drift, and an ordinary
# mailbox role hanging off the default policy is not an add-in grant. The comparison runs in both
# directions against the role set the baseline resolved, because a tenant more restricted than the
# approved state is still not the approved state.
function Test-AddInAcquisitionControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$DesiredState
    )

    if ($null -eq $DesiredState) {
        throw 'DesiredAddInAcquisitionStateRequired: EXO-012 cannot be decided without the add-in acquisition state the baseline resolved; an evaluator with no desired state decides against whatever it defaults to rather than against what was approved.'
    }

    $decision = $script:AddInAcquisitionDecision
    if ($decision -cnotin @(Get-BaselineRecordMemberName -Node $DesiredState)) {
        throw "DesiredAddInAcquisitionDecisionRequired: the resolved protocol restriction state declares no '$decision'; a baseline that never decided whether users may acquire add-ins reads identically to one that decided they may not."
    }

    $acquisitionRole = $script:AddInAcquisitionRole
    $desiredRole = @(if ([bool](Get-BaselineRecordMember -Node $DesiredState -Name $decision)) { $acquisitionRole })
    $observationName = @($script:AddInAcquisitionObservation.Keys)
    $policyMember = $script:RoleAssignmentPolicyDecidedMember
    $assignmentMember = $script:ManagementRoleAssignmentDecidedMember
    $normalize = { param($Value) ([string]$Value).Trim().ToLowerInvariant() }

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @()
        if ($null -ne $payload) { $present = @(Get-BaselineRecordMemberName -Node $payload) }

        foreach ($name in $observationName) {
            if ($name -cnotin $present) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "AddInAcquisitionEvidenceIncomplete: the record carries no '$name' observation."
                }
            }
        }

        $policy = @(Get-BaselineRecordMember -Node $payload -Name 'RoleAssignmentPolicy')
        foreach ($observed in $policy) {
            $observedMember = @(Get-BaselineRecordMemberName -Node $observed)
            foreach ($decided in $policyMember) {
                if ($decided -cnotin $observedMember) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "AddInAcquisitionEvidenceIncomplete: an observed RoleAssignmentPolicy carries no '$decided' member."
                    }
                }
            }
        }

        $assignment = @(Get-BaselineRecordMember -Node $payload -Name 'ManagementRoleAssignment')
        foreach ($observed in $assignment) {
            $observedMember = @(Get-BaselineRecordMemberName -Node $observed)
            foreach ($decided in $assignmentMember) {
                if ($decided -cnotin $observedMember) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "AddInAcquisitionEvidenceIncomplete: an observed ManagementRoleAssignment carries no '$decided' member."
                    }
                }
            }
        }

        $defaultPolicy = @(foreach ($observed in $policy) {
                if ([bool](Get-BaselineRecordMember -Node $observed -Name 'IsDefault')) {
                    & $normalize (Get-BaselineRecordMember -Node $observed -Name 'Identity')
                }
            })

        $finding = @(
            if ($defaultPolicy.Count -eq 0) {
                'the tenant holds no default role assignment policy'
            }
            else {
                $heldRole = @(foreach ($observed in $assignment) {
                        if ((& $normalize (Get-BaselineRecordMember -Node $observed -Name 'RoleAssignee')) -cin $defaultPolicy) {
                            & $normalize (Get-BaselineRecordMember -Node $observed -Name 'Role')
                        }
                    })

                foreach ($role in $acquisitionRole) {
                    $held = ((& $normalize $role) -cin $heldRole)
                    $permitted = ($role -cin $desiredRole)

                    if ($held -and -not $permitted) {
                        "the default role assignment policy holds user add-in acquisition role '$role'"
                    }

                    if ($permitted -and -not $held) {
                        "the default role assignment policy does not hold user add-in acquisition role '$role'"
                    }
                }
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'AddInAcquisitionDrift: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'EXO-012' -Evidence $Evidence -Evaluator $evaluator
}

# MDO-001: the Standard preset is applied by two rules, not one. The EOP rule scopes anti-spam,
# anti-malware and anti-phishing; the ATP rule scopes Safe Links and Safe Attachments. A tenant can
# hold one enabled and the other disabled or differently scoped, so both are observed together and
# either command refusing makes the whole record uncollected. Every rule the tenant holds is
# recorded, including the custom rules beside the preset rule, because a collector that filtered to
# the preset rule would decide which rule the control is about before any evaluator saw the set.
function Get-StandardPresetEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$EopRuleCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$AtpRuleCollection
    )

    if ($null -eq $EopRuleCollection) {
        throw 'EopProtectionPolicyRuleCollectionRequired: MDO-001 cannot be observed without a collection that reaches the EOP protection policy rules.'
    }

    if ($null -eq $AtpRuleCollection) {
        throw 'AtpProtectionPolicyRuleCollectionRequired: MDO-001 cannot be observed without a collection that reaches the ATP protection policy rules.'
    }

    $collection = {
        [ordered]@{
            EOPProtectionPolicyRule = @(& $EopRuleCollection)
            ATPProtectionPolicyRule = @(& $AtpRuleCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'MDO-001' -Source 'ExchangeOnline' `
        -Command 'Get-EOPProtectionPolicyRule; Get-ATPProtectionPolicyRule' -Collection $collection
}

# MDO-001: the name Exchange Online applies the Standard preset through, the two rule sets it is
# applied by, and the five members each rule is decided on. A tenant holds these rules beside every
# custom rule it has ever created, so the name is what separates the rule this control decides from
# the rules it must leave alone.
$script:StandardPresetRuleName = 'Standard Preset Security Policy'
$script:StandardPresetObservation = @('EOPProtectionPolicyRule', 'ATPProtectionPolicyRule')
$script:StandardPresetDecidedMember = @('Name', 'State', 'RecipientDomainIs', 'ExceptIfSentToMemberOf', 'ExceptIfSentTo')

# The three scoping members, each paired with the desired-state member it is compared against and
# the canonical kind that decides equality. Groups resolve to a primary SMTP address, which is why
# the evaluator takes a resolution seam rather than comparing display names to addresses.
$script:StandardPresetScopeComparison = @(
    [pscustomobject]@{ Observed = 'RecipientDomainIs'; Desired = 'sentToDomains'; Kind = 'Domain' }
    [pscustomobject]@{ Observed = 'ExceptIfSentToMemberOf'; Desired = 'excludedGroups'; Kind = 'Group' }
    [pscustomobject]@{ Observed = 'ExceptIfSentTo'; Desired = 'excludedSecOpsMailbox'; Kind = 'SmtpAddress' }
)

# MDO-001: both halves of the Standard preset are decided together, because the EOP rule scopes
# anti-spam, anti-malware and anti-phishing while the ATP rule alone scopes Safe Links and Safe
# Attachments, and the two are enabled and scoped independently. The deployment script reports this
# control as `Applied` on the strength of having called the preset cmdlets and the evidence script
# reads it out of the configuration document, so neither establishes who the preset actually
# reaches. Each scoping member is compared as a normalized set, so the casing, whitespace, trailing
# root label, routing prefix, duplication and ordering Exchange Online reports back is never drift,
# while a domain the preset never reaches and an exclusion nobody approved always is.
function Test-StandardPresetControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$DesiredState,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$GroupResolver
    )

    if ($null -eq $DesiredState) {
        throw 'DesiredStandardPresetStateRequired: MDO-001 cannot be decided without the Standard preset scope the baseline resolved; an evaluator with no desired state decides against whatever it defaults to rather than against what was approved.'
    }

    if ($null -eq $GroupResolver) {
        throw 'StandardPresetGroupResolverRequired: MDO-001 compares group exclusions as primary SMTP addresses, so it cannot be decided without a resolution seam; comparing an unresolved display name against a resolved address reads every correctly excluded group as drift.'
    }

    $ruleName = $script:StandardPresetRuleName
    $observationName = $script:StandardPresetObservation
    $decidedMember = $script:StandardPresetDecidedMember
    $comparison = $script:StandardPresetScopeComparison
    $resolver = $GroupResolver

    $declared = @(Get-BaselineRecordMemberName -Node $DesiredState)
    $desired = [ordered]@{}
    foreach ($pair in $comparison) {
        $desired[$pair.Observed] = if ($pair.Desired -cin $declared) { @(Get-BaselineRecordMember -Node $DesiredState -Name $pair.Desired) } else { @() }
    }

    if (@($desired['RecipientDomainIs']).Count -eq 0) {
        throw 'DesiredStandardPresetScopeRequired: MDO-001 cannot be decided without at least one resolved recipient domain; a preset scoped to no domain protects nobody, and comparing a tenant against an empty scope passes exactly the tenant that turned the preset off for everyone.'
    }

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @()
        if ($null -ne $payload) { $present = @(Get-BaselineRecordMemberName -Node $payload) }

        foreach ($name in $observationName) {
            if ($name -cnotin $present) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "StandardPresetEvidenceIncomplete: the record carries no '$name' observation."
                }
            }
        }

        foreach ($name in $observationName) {
            foreach ($rule in @(Get-BaselineRecordMember -Node $payload -Name $name)) {
                $ruleMember = @(Get-BaselineRecordMemberName -Node $rule)
                foreach ($decided in $decidedMember) {
                    if ($decided -cnotin $ruleMember) {
                        return [pscustomobject]@{
                            Status = 'Error'
                            Reason = "StandardPresetEvidenceIncomplete: an observed $name carries no '$decided' member."
                        }
                    }
                }
            }
        }

        $finding = @(
            foreach ($name in $observationName) {
                $preset = @(foreach ($rule in @(Get-BaselineRecordMember -Node $payload -Name $name)) {
                        if (([string](Get-BaselineRecordMember -Node $rule -Name 'Name')).Trim() -ieq $ruleName) { $rule }
                    })

                if ($preset.Count -eq 0) {
                    "the tenant holds no '$ruleName' rule among the $name rules"
                    continue
                }

                foreach ($rule in $preset) {
                    $state = ([string](Get-BaselineRecordMember -Node $rule -Name 'State')).Trim()
                    if ($state -ine 'Enabled') {
                        "the $name rule '$ruleName' is '$state' where 'Enabled' is required"
                    }

                    foreach ($pair in $comparison) {
                        $actual = @(Get-BaselineRecordMember -Node $rule -Name $pair.Observed)
                        $compared = if ($pair.Kind -ceq 'Group') {
                            Compare-NormalizedCollection -Desired $desired[$pair.Observed] -Actual $actual -Kind $pair.Kind -Resolver $resolver
                        }
                        else {
                            Compare-NormalizedCollection -Desired $desired[$pair.Observed] -Actual $actual -Kind $pair.Kind
                        }

                        foreach ($missing in @($compared.Missing)) {
                            "the $name rule does not scope '$($pair.Observed)' to '$missing'"
                        }

                        foreach ($surplus in @($compared.Surplus)) {
                            "the $name rule scopes '$($pair.Observed)' to unapproved '$surplus'"
                        }
                    }
                }
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'StandardPresetDrift: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'MDO-001' -Evidence $Evidence -Evaluator $evaluator
}

# MDO-002: the Strict preset is applied by the same two rules the Standard preset uses, under its
# own name, and is targeted rather than scoped-and-excluded: it reaches the priority group and
# nobody else. Both rule sets are observed together for the same reason as MDO-001, and every rule
# the tenant holds is recorded so the evaluator, not the collector, decides which rule is the
# Strict one.
function Get-StrictPresetEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$EopRuleCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$AtpRuleCollection
    )

    if ($null -eq $EopRuleCollection) {
        throw 'EopProtectionPolicyRuleCollectionRequired: MDO-002 cannot be observed without a collection that reaches the EOP protection policy rules.'
    }

    if ($null -eq $AtpRuleCollection) {
        throw 'AtpProtectionPolicyRuleCollectionRequired: MDO-002 cannot be observed without a collection that reaches the ATP protection policy rules.'
    }

    $collection = {
        [ordered]@{
            EOPProtectionPolicyRule = @(& $EopRuleCollection)
            ATPProtectionPolicyRule = @(& $AtpRuleCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'MDO-002' -Source 'ExchangeOnline' `
        -Command 'Get-EOPProtectionPolicyRule; Get-ATPProtectionPolicyRule' -Collection $collection
}

# MDO-002: the name Exchange Online applies the Strict preset through, and the five members each
# rule is decided on. The Strict preset is targeted rather than scoped-and-excluded, so the three
# targeting members are compared against the priority group and against nothing at all.
$script:StrictPresetRuleName = 'Strict Preset Security Policy'
$script:StrictPresetObservation = @('EOPProtectionPolicyRule', 'ATPProtectionPolicyRule')
$script:StrictPresetDecidedMember = @('Name', 'State', 'SentToMemberOf', 'SentTo', 'RecipientDomainIs')

# `SentToMemberOf` carries the priority group the baseline resolved; the other two carry nobody,
# because a Strict rule stretched over a recipient or a domain reaches a population that never
# approved the most restrictive policy the tenant applies.
$script:StrictPresetTargetComparison = @(
    [pscustomobject]@{ Observed = 'SentToMemberOf'; Kind = 'Group' }
    [pscustomobject]@{ Observed = 'SentTo'; Kind = 'SmtpAddress' }
    [pscustomobject]@{ Observed = 'RecipientDomainIs'; Kind = 'Domain' }
)

# MDO-002: both halves of the Strict preset are decided together, because the EOP rule targets
# anti-spam, anti-malware and anti-phishing while the ATP rule alone targets Safe Links and Safe
# Attachments, and the two are enabled and targeted independently. The evidence script reads
# `strictPresetEnabled` out of the configuration document, which establishes nothing about who the
# preset actually reaches. Each targeting member is compared as a normalized set in both
# directions, so the casing, whitespace, routing prefix, duplication and ordering Exchange Online
# reports back is never drift, while a rule that reaches nobody and a rule that reaches everybody
# always are.
function Test-StrictPresetControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$DesiredState,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$GroupResolver
    )

    if ($null -eq $DesiredState) {
        throw 'DesiredStrictPresetStateRequired: MDO-002 cannot be decided without the Strict preset target the baseline resolved; an evaluator with no desired state decides against whatever it defaults to rather than against what was approved.'
    }

    if ($null -eq $GroupResolver) {
        throw 'StrictPresetGroupResolverRequired: MDO-002 compares the priority group as a primary SMTP address, so it cannot be decided without a resolution seam; comparing an unresolved display name against a resolved address reads every correctly targeted rule as drift.'
    }

    $scopeGroup = 'scopeGroup'
    if ($scopeGroup -cnotin @(Get-BaselineRecordMemberName -Node $DesiredState)) {
        throw "DesiredStrictPresetGroupRequired: the resolved Defender state declares no '$scopeGroup'; the priority group is the entire target of the Strict preset, and comparing a tenant against no group at all passes exactly the tenant whose Strict rules reach nobody."
    }

    $ruleName = $script:StrictPresetRuleName
    $observationName = $script:StrictPresetObservation
    $decidedMember = $script:StrictPresetDecidedMember
    $comparison = $script:StrictPresetTargetComparison
    $resolver = $GroupResolver

    $desired = [ordered]@{
        SentToMemberOf    = @(Get-BaselineRecordMember -Node $DesiredState -Name $scopeGroup)
        SentTo            = @()
        RecipientDomainIs = @()
    }

    if (@($desired['SentToMemberOf']).Count -eq 0) {
        throw "DesiredStrictPresetGroupRequired: the resolved Defender state resolves '$scopeGroup' to no group; the priority group is the entire target of the Strict preset, and comparing a tenant against no group at all passes exactly the tenant whose Strict rules reach nobody."
    }

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @()
        if ($null -ne $payload) { $present = @(Get-BaselineRecordMemberName -Node $payload) }

        foreach ($name in $observationName) {
            if ($name -cnotin $present) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "StrictPresetEvidenceIncomplete: the record carries no '$name' observation."
                }
            }
        }

        foreach ($name in $observationName) {
            foreach ($rule in @(Get-BaselineRecordMember -Node $payload -Name $name)) {
                $ruleMember = @(Get-BaselineRecordMemberName -Node $rule)
                foreach ($decided in $decidedMember) {
                    if ($decided -cnotin $ruleMember) {
                        return [pscustomobject]@{
                            Status = 'Error'
                            Reason = "StrictPresetEvidenceIncomplete: an observed $name carries no '$decided' member."
                        }
                    }
                }
            }
        }

        $finding = @(
            foreach ($name in $observationName) {
                $preset = @(foreach ($rule in @(Get-BaselineRecordMember -Node $payload -Name $name)) {
                        if (([string](Get-BaselineRecordMember -Node $rule -Name 'Name')).Trim() -ieq $ruleName) { $rule }
                    })

                if ($preset.Count -eq 0) {
                    "the tenant holds no '$ruleName' rule among the $name rules"
                    continue
                }

                foreach ($rule in $preset) {
                    $state = ([string](Get-BaselineRecordMember -Node $rule -Name 'State')).Trim()
                    if ($state -ine 'Enabled') {
                        "the $name rule '$ruleName' is '$state' where 'Enabled' is required"
                    }

                    foreach ($pair in $comparison) {
                        $actual = @(Get-BaselineRecordMember -Node $rule -Name $pair.Observed)
                        $compared = if ($pair.Kind -ceq 'Group') {
                            Compare-NormalizedCollection -Desired $desired[$pair.Observed] -Actual $actual -Kind $pair.Kind -Resolver $resolver
                        }
                        else {
                            Compare-NormalizedCollection -Desired $desired[$pair.Observed] -Actual $actual -Kind $pair.Kind
                        }

                        foreach ($missing in @($compared.Missing)) {
                            "the $name rule does not target '$($pair.Observed)' at '$missing'"
                        }

                        foreach ($surplus in @($compared.Surplus)) {
                            "the $name rule targets '$($pair.Observed)' at unapproved '$surplus'"
                        }
                    }
                }
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'StrictPresetDrift: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'MDO-002' -Evidence $Evidence -Evaluator $evaluator
}

# MDO-003: built-in protection is applied by one always-on rule, and the only thing an operator can
# change about it is who it stops reaching. Every rule the command returns is recorded, including
# any rule beside the built-in one, because a collector that filtered to the built-in rule would
# decide which rule the control is about before any evaluator saw the set.
function Get-BuiltInProtectionEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$RuleCollection
    )

    if ($null -eq $RuleCollection) {
        throw 'BuiltInProtectionRuleCollectionRequired: MDO-003 cannot be observed without a collection that reaches the built-in protection rule.'
    }

    $collection = {
        [ordered]@{
            ATPBuiltInProtectionRule = @(& $RuleCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'MDO-003' -Source 'ExchangeOnline' `
        -Command 'Get-ATPBuiltInProtectionRule' -Collection $collection
}

# MDO-003: the name Exchange Online applies built-in protection through, the observation it is
# applied by, and the five members the rule is decided on.
$script:BuiltInProtectionRuleName = 'ATP Built-In Protection Rule'
$script:BuiltInProtectionObservation = 'ATPBuiltInProtectionRule'
$script:BuiltInProtectionDecidedMember = @('Name', 'State', 'ExceptIfSentTo', 'ExceptIfSentToMemberOf', 'ExceptIfRecipientDomainIs')

# Every approved exception is granted on exactly one exclusion member, and each member is compared
# under the canonical kind that decides equality for the values it carries. Keeping the approvals
# separated by member is what stops a mailbox approved by name from approving the whole domain it
# sits in, which is the broad exclusion the catalog forbids.
$script:BuiltInProtectionExclusion = @(
    [pscustomobject]@{ ExceptionType = 'Mailbox'; Observed = 'ExceptIfSentTo'; Kind = 'SmtpAddress' }
    [pscustomobject]@{ ExceptionType = 'Group'; Observed = 'ExceptIfSentToMemberOf'; Kind = 'Group' }
    [pscustomobject]@{ ExceptionType = 'Domain'; Observed = 'ExceptIfRecipientDomainIs'; Kind = 'Domain' }
)

# MDO-003: built-in protection is always on and cannot be scoped, so the only thing an operator can
# change about it is who it stops reaching. The evidence script decides this control from two of
# the three exclusion members and never reads `ExceptIfSentTo` at all, which passes a tenant that
# has exempted every interesting mailbox individually. Each exclusion member is compared as a
# normalized set against the approvals granted on that member, so the casing, whitespace, trailing
# root label, routing prefix, duplication and ordering Exchange Online reports back is never drift,
# while an exclusion nobody approved always is.
function Test-BuiltInProtectionControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$DesiredState,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$GroupResolver
    )

    if ($null -eq $DesiredState) {
        throw 'DesiredBuiltInProtectionStateRequired: MDO-003 cannot be decided without the exclusions the baseline approved; an evaluator with no desired state decides against whatever it defaults to rather than against what was approved.'
    }

    if ($null -eq $GroupResolver) {
        throw 'BuiltInProtectionGroupResolverRequired: MDO-003 compares group exclusions as primary SMTP addresses, so it cannot be decided without a resolution seam; comparing an unresolved display name against a resolved address reads every approved exclusion as drift.'
    }

    $declared = @(Get-BaselineRecordMemberName -Node $DesiredState)
    if ('exceptions' -cnotin $declared) {
        throw 'DesiredBuiltInProtectionExceptionsRequired: the resolved built-in protection state declares no approved exclusion register; a baseline that approves nothing and a baseline that never declared the register read identically once the member is absent, and only one of them is a decision somebody made.'
    }

    $ruleName = $script:BuiltInProtectionRuleName
    $observationName = $script:BuiltInProtectionObservation
    $decidedMember = $script:BuiltInProtectionDecidedMember
    $exclusion = $script:BuiltInProtectionExclusion
    $resolver = $GroupResolver

    $desired = [ordered]@{}
    foreach ($pair in $exclusion) {
        $desired[$pair.Observed] = @()
    }

    foreach ($entry in @(Get-BaselineRecordMember -Node $DesiredState -Name 'exceptions')) {
        $exceptionType = [string](Get-BaselineRecordMember -Node $entry -Name 'exceptionType')
        $granted = @($exclusion | Where-Object { $_.ExceptionType -ceq $exceptionType })
        if ($granted.Count -ne 1) {
            throw "UnknownBuiltInProtectionExceptionType: the baseline approves an exclusion of type '$exceptionType', which is not one of $(($exclusion.ExceptionType) -join ', '); an approval granted on a member the rule has no such exclusion for can never be matched."
        }

        $desired[$granted[0].Observed] = @($desired[$granted[0].Observed]) + [string](Get-BaselineRecordMember -Node $entry -Name 'value')
    }

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @()
        if ($null -ne $payload) { $present = @(Get-BaselineRecordMemberName -Node $payload) }

        if ($observationName -cnotin $present) {
            return [pscustomobject]@{
                Status = 'Error'
                Reason = "BuiltInProtectionEvidenceIncomplete: the record carries no '$observationName' observation."
            }
        }

        $observed = @(Get-BaselineRecordMember -Node $payload -Name $observationName)

        foreach ($rule in $observed) {
            $ruleMember = @(Get-BaselineRecordMemberName -Node $rule)
            foreach ($decided in $decidedMember) {
                if ($decided -cnotin $ruleMember) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "BuiltInProtectionEvidenceIncomplete: an observed $observationName carries no '$decided' member."
                    }
                }
            }
        }

        $builtIn = @(foreach ($rule in $observed) {
                if (([string](Get-BaselineRecordMember -Node $rule -Name 'Name')).Trim() -ieq $ruleName) { $rule }
            })

        $finding = @(
            if ($builtIn.Count -eq 0) {
                "the tenant holds no '$ruleName'"
            }

            foreach ($rule in $builtIn) {
                $state = ([string](Get-BaselineRecordMember -Node $rule -Name 'State')).Trim()
                if ($state -ine 'Enabled') {
                    "the rule '$ruleName' is '$state' where 'Enabled' is required"
                }

                foreach ($pair in $exclusion) {
                    $actual = @(Get-BaselineRecordMember -Node $rule -Name $pair.Observed)
                    $compared = if ($pair.Kind -ceq 'Group') {
                        Compare-NormalizedCollection -Desired $desired[$pair.Observed] -Actual $actual -Kind $pair.Kind -Resolver $resolver
                    }
                    else {
                        Compare-NormalizedCollection -Desired $desired[$pair.Observed] -Actual $actual -Kind $pair.Kind
                    }

                    foreach ($missing in @($compared.Missing)) {
                        "the rule does not exclude approved '$missing' under '$($pair.Observed)'"
                    }

                    foreach ($surplus in @($compared.Surplus)) {
                        "the rule excludes unapproved '$surplus' under '$($pair.Observed)'"
                    }
                }
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'BuiltInProtectionDrift: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'MDO-003' -Evidence $Evidence -Evaluator $evaluator
}

# MDO-009: impersonation protection of the priority identities lives on the anti-phish policies,
# and a tenant holds several of them at once - preset, custom and retired. Every policy the command
# returns is recorded, the disabled ones included, because a collector that kept only the enabled
# policies would decide which policies count before any evaluator saw the set.
function Get-PriorityAccountEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$AntiPhishPolicyCollection
    )

    if ($null -eq $AntiPhishPolicyCollection) {
        throw 'AntiPhishPolicyCollectionRequired: MDO-009 cannot be observed without a collection that reaches the anti-phish policies.'
    }

    $collection = {
        [ordered]@{
            AntiPhishPolicy = @(& $AntiPhishPolicyCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'MDO-009' -Source 'ExchangeOnline' `
        -Command 'Get-AntiPhishPolicy' -Collection $collection
}

# MDO-009: the observation impersonation protection is applied by, and the eight members each
# policy is decided on. A list of protected identities is inert while the switch that applies it is
# off, so the switches are decided beside the lists rather than assumed.
$script:ImpersonationObservation = 'AntiPhishPolicy'
$script:ImpersonationDecidedMember = @(
    'Name', 'Enabled', 'EnableTargetedUserProtection', 'EnableTargetedDomainsProtection',
    'TargetedUsersToProtect', 'TargetedDomainsToProtect', 'ExcludedSenders', 'ExcludedDomains'
)

# Each approved exception is granted on the one policy member it names, and each member is compared
# under the canonical kind that decides equality for the values it carries. Keeping them separated
# is what stops an approval for a laboratory subdomain approving the whole domain above it.
$script:ImpersonationException = @(
    [pscustomobject]@{ ExceptionType = 'TrustedSender'; Observed = 'ExcludedSenders'; Kind = 'SmtpAddress'; Noun = 'sender' }
    [pscustomobject]@{ ExceptionType = 'TrustedDomain'; Observed = 'ExcludedDomains'; Kind = 'Domain'; Noun = 'domain' }
)

# MDO-009: who the tenant actually protects from impersonation. A tenant holds several anti-phish
# policies at once and only the enabled ones reach a message, so the protection is read from the
# enabled policies together: a priority identity must be protected by at least one of them, while
# the custom protected domains and the trusted exceptions must match the register exactly in both
# directions. Protecting somebody beyond the priority identities is protection rather than drift;
# trusting a sender or a domain nobody approved is a standing exemption and always is.
function Test-PriorityAccountControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$DesiredState
    )

    if ($null -eq $DesiredState) {
        throw 'DesiredImpersonationProtectionStateRequired: MDO-009 cannot be decided without the impersonation protection the baseline resolved; an evaluator with no desired state decides against whatever it defaults to rather than against what was approved.'
    }

    $declared = @(Get-BaselineRecordMemberName -Node $DesiredState)

    $protectedUser = @()
    if ('protectedUsers' -cin $declared) { $protectedUser = @(Get-BaselineRecordMember -Node $DesiredState -Name 'protectedUsers') }
    if ($protectedUser.Count -eq 0) {
        throw 'DesiredImpersonationProtectedUserRequired: MDO-009 cannot be decided without at least one resolved priority identity; protection that names nobody passes exactly the tenant that protects nobody.'
    }

    if ('approvedExceptions' -cnotin $declared) {
        throw 'DesiredImpersonationExceptionsRequired: the resolved impersonation protection declares no approved exception register; a baseline that approves nothing and a baseline that never declared the register read identically once the member is absent, and only one of them is a decision somebody made.'
    }

    $protectedDomain = @()
    if ('protectedDomains' -cin $declared) { $protectedDomain = @(Get-BaselineRecordMember -Node $DesiredState -Name 'protectedDomains') }

    $exceptionContract = $script:ImpersonationException
    $approved = [ordered]@{}
    foreach ($pair in $exceptionContract) {
        $approved[$pair.Observed] = @()
    }

    foreach ($entry in @(Get-BaselineRecordMember -Node $DesiredState -Name 'approvedExceptions')) {
        $exceptionType = [string](Get-BaselineRecordMember -Node $entry -Name 'exceptionType')
        $granted = @($exceptionContract | Where-Object { $_.ExceptionType -ceq $exceptionType })
        if ($granted.Count -ne 1) {
            throw "UnknownImpersonationExceptionType: the baseline approves an exception of type '$exceptionType', which is not one of $(($exceptionContract.ExceptionType) -join ', '); an approval granted on a member an anti-phish policy has no such exception for can never be matched."
        }

        $approved[$granted[0].Observed] = @($approved[$granted[0].Observed]) + [string](Get-BaselineRecordMember -Node $entry -Name 'value')
    }

    $observationName = $script:ImpersonationObservation
    $decidedMember = $script:ImpersonationDecidedMember

    # Exchange Online reports a protected user as 'Display Name;address', and the address is the
    # only half of that the baseline names.
    $addressOf = {
        param($Entry)

        $text = [string]$Entry
        $separator = $text.LastIndexOf(';')

        return $(if ($separator -ge 0) { $text.Substring($separator + 1) } else { $text })
    }

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @()
        if ($null -ne $payload) { $present = @(Get-BaselineRecordMemberName -Node $payload) }

        if ($observationName -cnotin $present) {
            return [pscustomobject]@{
                Status = 'Error'
                Reason = "ImpersonationProtectionEvidenceIncomplete: the record carries no '$observationName' observation."
            }
        }

        $observed = @(Get-BaselineRecordMember -Node $payload -Name $observationName)

        foreach ($policy in $observed) {
            $policyMember = @(Get-BaselineRecordMemberName -Node $policy)
            foreach ($decided in $decidedMember) {
                if ($decided -cnotin $policyMember) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "ImpersonationProtectionEvidenceIncomplete: an observed $observationName carries no '$decided' member."
                    }
                }
            }
        }

        $enabledPolicy = @(foreach ($policy in $observed) {
                if ([bool](Get-BaselineRecordMember -Node $policy -Name 'Enabled')) { $policy }
            })

        if ($enabledPolicy.Count -eq 0) {
            return [pscustomobject]@{
                Status = 'Fail'
                Reason = 'ImpersonationProtectionDrift: the tenant holds no enabled anti-phish policy.'
            }
        }

        $protectingUser = @(foreach ($policy in $enabledPolicy) {
                if ([bool](Get-BaselineRecordMember -Node $policy -Name 'EnableTargetedUserProtection')) { $policy }
            })
        $protectingDomain = @(foreach ($policy in $enabledPolicy) {
                if ([bool](Get-BaselineRecordMember -Node $policy -Name 'EnableTargetedDomainsProtection')) { $policy }
            })

        $observedUser = @(foreach ($policy in $protectingUser) {
                foreach ($entry in @(Get-BaselineRecordMember -Node $policy -Name 'TargetedUsersToProtect')) { & $addressOf $entry }
            })
        $observedDomain = @(foreach ($policy in $protectingDomain) {
                @(Get-BaselineRecordMember -Node $policy -Name 'TargetedDomainsToProtect')
            })

        $finding = @(
            # Protecting an identity the baseline did not name is protection, not drift, so only
            # the identities nobody protects are reported.
            foreach ($missing in @((Compare-NormalizedCollection -Desired $protectedUser -Actual $observedUser -Kind 'SmtpAddress').Missing)) {
                "no enabled policy protects '$missing' from user impersonation"
            }

            foreach ($missing in @((Compare-NormalizedCollection -Desired $protectedDomain -Actual $observedDomain -Kind 'Domain').Missing)) {
                "no enabled policy protects the domain '$missing' from domain impersonation"
            }

            foreach ($policy in $protectingDomain) {
                $policyName = ([string](Get-BaselineRecordMember -Node $policy -Name 'Name')).Trim()
                $actual = @(Get-BaselineRecordMember -Node $policy -Name 'TargetedDomainsToProtect')
                foreach ($surplus in @((Compare-NormalizedCollection -Desired $protectedDomain -Actual $actual -Kind 'Domain').Surplus)) {
                    "the policy '$policyName' protects unapproved domain '$surplus'"
                }
            }

            foreach ($pair in $exceptionContract) {
                $observedException = @(foreach ($policy in $enabledPolicy) {
                        @(Get-BaselineRecordMember -Node $policy -Name $pair.Observed)
                    })

                foreach ($missing in @((Compare-NormalizedCollection -Desired $approved[$pair.Observed] -Actual $observedException -Kind $pair.Kind).Missing)) {
                    "no enabled policy trusts approved $($pair.Noun) '$missing'"
                }

                foreach ($policy in $enabledPolicy) {
                    $policyName = ([string](Get-BaselineRecordMember -Node $policy -Name 'Name')).Trim()
                    $actual = @(Get-BaselineRecordMember -Node $policy -Name $pair.Observed)
                    foreach ($surplus in @((Compare-NormalizedCollection -Desired $approved[$pair.Observed] -Actual $actual -Kind $pair.Kind).Surplus)) {
                        "the policy '$policyName' trusts unapproved $($pair.Noun) '$surplus'"
                    }
                }
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'ImpersonationProtectionDrift: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'MDO-009' -Evidence $Evidence -Evaluator $evaluator
}

# MDO-004 and MDO-005 are both recorded by `Get-AtpPolicyForO365`, but they are two controls with
# two entitlements, so each collects its own record. The whole policy is recorded either way: a
# collector narrowed to the one member Safe Attachments is decided on would leave Safe Documents
# with nothing to be decided from.
$script:AtpPolicyObservation = 'AtpPolicyForO365'

function Get-SafeAttachmentsEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$AtpPolicyCollection
    )

    if ($null -eq $AtpPolicyCollection) {
        throw 'AtpPolicyCollectionRequired: MDO-004 cannot be observed without a collection that reaches the tenant ATP policy.'
    }

    $observationName = $script:AtpPolicyObservation
    $collection = {
        [ordered]@{
            $observationName = @(& $AtpPolicyCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'MDO-004' -Source 'ExchangeOnline' `
        -Command 'Get-AtpPolicyForO365' -Collection $collection
}

# MDO-004: Safe Attachments for SharePoint, OneDrive and Teams is one tenant-wide switch, and this
# control owns that switch alone - the Safe Documents members sharing the same policy are MDO-005.
# The switch is compared against the resolved state in both directions, because an evaluator that
# only ever checked it was on would report a tenant compliant with a baseline it never read.
function Test-SafeAttachmentsControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$DesiredState
    )

    if ($null -eq $DesiredState) {
        throw 'DesiredSafeAttachmentsStateRequired: MDO-004 cannot be decided without the Safe Attachments state the baseline resolved; an evaluator with no desired state decides against whatever it defaults to rather than against what was approved.'
    }

    $decision = 'safeAttachmentsForSharePointOneDriveTeams'
    if ($decision -cnotin @(Get-BaselineRecordMemberName -Node $DesiredState)) {
        throw "DesiredSafeAttachmentsDecisionRequired: the resolved Defender state declares no '$decision'; a baseline that switched file scanning off and a baseline that never decided read identically once the member is absent, and only one of them is a decision somebody made."
    }

    $desired = [bool](Get-BaselineRecordMember -Node $DesiredState -Name $decision)
    $observationName = $script:AtpPolicyObservation
    $decidedMember = 'EnableATPForSPOTeamsODB'

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @()
        if ($null -ne $payload) { $present = @(Get-BaselineRecordMemberName -Node $payload) }

        if ($observationName -cnotin $present) {
            return [pscustomobject]@{
                Status = 'Error'
                Reason = "SafeAttachmentsEvidenceIncomplete: the record carries no '$observationName' observation."
            }
        }

        $observed = @(Get-BaselineRecordMember -Node $payload -Name $observationName)

        foreach ($policy in $observed) {
            if ($decidedMember -cnotin @(Get-BaselineRecordMemberName -Node $policy)) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "SafeAttachmentsEvidenceIncomplete: an observed $observationName carries no '$decidedMember' member."
                }
            }
        }

        # The ATP policy is one tenant-wide object. Deciding from whichever of several happened to
        # be first would pick the verdict by ordering.
        if ($observed.Count -gt 1) {
            return [pscustomobject]@{
                Status = 'Error'
                Reason = "SafeAttachmentsEvidenceAmbiguous: the record carries $($observed.Count) $observationName observations where the tenant holds one."
            }
        }

        if ($observed.Count -eq 0) {
            return [pscustomobject]@{
                Status = 'Fail'
                Reason = 'SafeAttachmentsDrift: the tenant holds no ATP policy.'
            }
        }

        $actual = [bool](Get-BaselineRecordMember -Node $observed[0] -Name $decidedMember)
        if ($actual -ne $desired) {
            return [pscustomobject]@{
                Status = 'Fail'
                Reason = "SafeAttachmentsDrift: '$decidedMember' is '$actual' where '$desired' is required."
            }
        }

        return [pscustomobject]@{ Status = 'Pass' }
    }

    return Test-BaselineControl -ControlId 'MDO-004' -Evidence $Evidence -Evaluator $evaluator
}

# MDO-005: the same command, collected again under its own control. The call is made whatever the
# tenant is entitled to, because a collector that skipped it on an unentitled tenant would leave
# the control with no observation to report `NotApplicable` from.
function Get-SafeDocumentsEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$AtpPolicyCollection
    )

    if ($null -eq $AtpPolicyCollection) {
        throw 'AtpPolicyCollectionRequired: MDO-005 cannot be observed without a collection that reaches the tenant ATP policy.'
    }

    $observationName = $script:AtpPolicyObservation
    $collection = {
        [ordered]@{
            $observationName = @(& $AtpPolicyCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'MDO-005' -Source 'ExchangeOnline' `
        -Command 'Get-AtpPolicyForO365' -Collection $collection
}

# MDO-005: Safe Documents is two decisions - the scanner is on, and a user cannot open a file it
# called malicious anyway - and the Safe Attachments member sharing the policy is MDO-004 rather
# than drift here. The SAFEDOCS entitlement verdict is supplied rather than inferred: an unlicensed
# tenant and a licensed tenant that switched Safe Documents off report the same ATP policy, so an
# evaluator reading entitlement out of the observation gets the other answer every time.
function Test-SafeDocumentsControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$DesiredState,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$EntitlementVerdict
    )

    if ($null -eq $DesiredState) {
        throw 'DesiredSafeDocumentsStateRequired: MDO-005 cannot be decided without the Safe Documents state the baseline resolved; an evaluator with no desired state decides against whatever it defaults to rather than against what was approved.'
    }

    $planDecision = 'requiredServicePlan'
    $desiredPlan = ''
    if ($planDecision -cin @(Get-BaselineRecordMemberName -Node $DesiredState)) {
        $desiredPlan = [string](Get-BaselineRecordMember -Node $DesiredState -Name $planDecision)
    }

    if ([string]::IsNullOrWhiteSpace($desiredPlan)) {
        throw "DesiredSafeDocumentsServicePlanRequired: the resolved Safe Documents state declares no '$planDecision'; the plan the baseline declares is the only thing that makes an entitlement verdict checkable, and an evaluator that accepts any verdict at all accepts one reached on a plan that grants nothing."
    }

    if ($null -eq $EntitlementVerdict) {
        throw 'SafeDocumentsEntitlementVerdictRequired: MDO-005 cannot be decided without an independently verified entitlement verdict; an unlicensed tenant and a licensed tenant that switched Safe Documents off report the same ATP policy.'
    }

    $verdictPlan = [string](Get-BaselineRecordMember -Node $EntitlementVerdict -Name 'RequiredServicePlanName')
    if ($verdictPlan -cne $desiredPlan) {
        throw "SafeDocumentsEntitlementPlanMismatch: the entitlement verdict was reached on '$verdictPlan' where the baseline declares '$desiredPlan'; a verdict cleared on another plan and read as this one passes Safe Documents on a licence that does not include it."
    }

    $entitlementStatus = [string](Get-BaselineRecordMember -Node $EntitlementVerdict -Name 'Status')
    $entitlementReason = [string](Get-BaselineRecordMember -Node $EntitlementVerdict -Name 'Reason')
    $observationName = $script:AtpPolicyObservation
    $decidedMember = [ordered]@{
        EnableSafeDocs    = [bool](Get-BaselineRecordMember -Node $DesiredState -Name 'enabled')
        AllowSafeDocsOpen = [bool](Get-BaselineRecordMember -Node $DesiredState -Name 'allowBypass')
    }

    $evaluator = {
        param($Record)

        if ($entitlementStatus -ceq 'NotEntitled') {
            return [pscustomobject]@{
                Status = 'NotApplicable'
                Reason = "SafeDocumentsNotEntitled: $entitlementReason"
            }
        }

        # A preflight that disagreed with itself answered neither entitled nor unentitled, and
        # resolving that silence either way decides the control on a question nobody settled.
        if ($entitlementStatus -cne 'Pass') {
            return [pscustomobject]@{
                Status = 'Error'
                Reason = "SafeDocumentsEntitlementUnresolved: $entitlementReason"
            }
        }

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @()
        if ($null -ne $payload) { $present = @(Get-BaselineRecordMemberName -Node $payload) }

        if ($observationName -cnotin $present) {
            return [pscustomobject]@{
                Status = 'Error'
                Reason = "SafeDocumentsEvidenceIncomplete: the record carries no '$observationName' observation."
            }
        }

        $observed = @(Get-BaselineRecordMember -Node $payload -Name $observationName)

        foreach ($policy in $observed) {
            $policyMember = @(Get-BaselineRecordMemberName -Node $policy)
            foreach ($name in $decidedMember.Keys) {
                if ($name -cnotin $policyMember) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "SafeDocumentsEvidenceIncomplete: an observed $observationName carries no '$name' member."
                    }
                }
            }
        }

        # The ATP policy is one tenant-wide object. Deciding from whichever of several happened to
        # be first would pick the verdict by ordering.
        if ($observed.Count -gt 1) {
            return [pscustomobject]@{
                Status = 'Error'
                Reason = "SafeDocumentsEvidenceAmbiguous: the record carries $($observed.Count) $observationName observations where the tenant holds one."
            }
        }

        if ($observed.Count -eq 0) {
            return [pscustomobject]@{
                Status = 'Fail'
                Reason = 'SafeDocumentsDrift: the tenant holds no ATP policy.'
            }
        }

        foreach ($name in $decidedMember.Keys) {
            $required = [bool]$decidedMember[$name]
            $actual = [bool](Get-BaselineRecordMember -Node $observed[0] -Name $name)
            if ($actual -ne $required) {
                return [pscustomobject]@{
                    Status = 'Fail'
                    Reason = "SafeDocumentsDrift: '$name' is '$actual' where '$required' is required."
                }
            }
        }

        return [pscustomobject]@{ Status = 'Pass' }
    }

    return Test-BaselineControl -ControlId 'MDO-005' -Evidence $Evidence -Evaluator $evaluator
}

# MDO-006: user reporting and Advanced Delivery are two commands and the card carries a clause
# each. The report submission policy holds every reporting decision, and the SecOps mailbox is
# registered on a separate Advanced Delivery override policy that no part of the reporting policy
# describes. Both are read inside the one try `Get-BaselineEvidence` runs, so either command
# refusing makes the whole record uncollected rather than letting the clause that answered stand in
# for the clause that did not.
$script:ReportSubmissionObservation = [ordered]@{
    ReportSubmissionPolicy = 'Get-ReportSubmissionPolicy'
    SecOpsOverridePolicy   = 'Get-SecOpsOverridePolicy'
}

function Get-ReportSubmissionEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$ReportSubmissionPolicyCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$SecOpsOverridePolicyCollection
    )

    if ($null -eq $ReportSubmissionPolicyCollection) {
        throw 'ReportSubmissionPolicyCollectionRequired: MDO-006 cannot be observed without a collection that reaches the tenant report submission policies.'
    }

    if ($null -eq $SecOpsOverridePolicyCollection) {
        throw 'SecOpsOverridePolicyCollectionRequired: MDO-006 cannot be observed without a collection that reaches the Advanced Delivery SecOps override policies.'
    }

    $collection = {
        [ordered]@{
            ReportSubmissionPolicy = @(& $ReportSubmissionPolicyCollection)
            SecOpsOverridePolicy   = @(& $SecOpsOverridePolicyCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'MDO-006' -Source 'ExchangeOnline' `
        -Command (@($script:ReportSubmissionObservation.Values) -join '; ') -Collection $collection
}

# MDO-006: the three reporting decisions the baseline declares and the member each is actually held
# by. The Microsoft report button is in use precisely when reports are not diverted to a
# third-party address, so that decision is compared against the inverse of the member Exchange
# Online reports it through rather than against a member of its own.
$script:ReportSubmissionDecision = @(
    [pscustomobject]@{ Declared = 'microsoftReportMessageButton'; Observed = 'EnableThirdPartyAddress'; Inverted = $true }
    [pscustomobject]@{ Declared = 'sendReportedMessagesToMicrosoft'; Observed = 'EnableReportToMicrosoft'; Inverted = $false }
    [pscustomobject]@{ Declared = 'sendCopyToSecOpsMailbox'; Observed = 'ReportJunkToCustomizedAddress'; Inverted = $false }
)

# Exchange Online exposes no destination member; the portal presents the destination as the
# combination of the two switches below, and that is the combination this control names.
$script:ReportingDestination = [ordered]@{
    Microsoft                 = [pscustomobject]@{ EnableReportToMicrosoft = $true; ReportJunkToCustomizedAddress = $false }
    CustomMailbox             = [pscustomobject]@{ EnableReportToMicrosoft = $false; ReportJunkToCustomizedAddress = $true }
    MicrosoftAndCustomMailbox = [pscustomobject]@{ EnableReportToMicrosoft = $true; ReportJunkToCustomizedAddress = $true }
}
$script:UnrecordedReportingDestination = 'Nowhere'
$script:ReportSubmissionMailboxMember = 'ReportJunkAddresses'
$script:SecOpsOverrideDecidedMember = @('Identity', 'SentTo')

# MDO-006: the card carries two clauses that no single command answers. The report submission
# policy holds the reporting switches, the destination they combine into and the mailbox reported
# messages land in; Advanced Delivery registers the SecOps mailboxes on a separate override policy.
# Every mailbox is compared as a normalized SMTP address set in both directions, so the casing,
# whitespace, routing prefix, duplication and ordering Exchange Online reports back is never drift,
# while a mailbox nobody approved and a mailbox nobody registered always are.
function Test-ReportSubmissionControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$DesiredState,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$SecOpsMailbox
    )

    if ($null -eq $DesiredState) {
        throw 'DesiredReportSubmissionStateRequired: MDO-006 cannot be decided without the user-submission state the baseline resolved; an evaluator with no desired state decides against whatever it defaults to rather than against what was approved.'
    }

    $declared = @(Get-BaselineRecordMemberName -Node $DesiredState)
    $decision = $script:ReportSubmissionDecision
    $destinationContract = $script:ReportingDestination
    $mailboxMember = $script:ReportSubmissionMailboxMember
    $overrideMember = $script:SecOpsOverrideDecidedMember
    $unrecorded = $script:UnrecordedReportingDestination

    $desiredSwitch = [ordered]@{}
    foreach ($pair in $decision) {
        if ($pair.Declared -cnotin $declared) {
            throw "DesiredReportSubmissionDecisionRequired: the resolved user-submission state declares no '$($pair.Declared)'; a baseline that never made the decision reads identically to a baseline that decided against it."
        }

        $value = [bool](Get-BaselineRecordMember -Node $DesiredState -Name $pair.Declared)
        $desiredSwitch[$pair.Observed] = if ($pair.Inverted) { -not $value } else { $value }
    }

    if ('reportingDestination' -cnotin $declared) {
        throw 'DesiredReportingDestinationRequired: the resolved user-submission state declares no reporting destination; the card calls the destination exact, and a tenant compared against none passes whether reported phishing reaches Microsoft, the SecOps mailbox or nobody.'
    }

    $desiredDestination = ([string](Get-BaselineRecordMember -Node $DesiredState -Name 'reportingDestination')).Trim()
    if ($desiredDestination -cnotin @($destinationContract.Keys)) {
        throw "DesiredReportingDestinationUnknown: the resolved user-submission state declares a reporting destination of '$desiredDestination', which the destination contract does not name; a destination with no declared switch combination behind it resolves to nothing."
    }

    $desiredMailbox = ([string](Get-BaselineRecordMember -Node $DesiredState -Name 'reportingMailbox')).Trim()
    if ([string]::IsNullOrWhiteSpace($desiredMailbox)) {
        throw 'DesiredReportingMailboxRequired: the resolved user-submission state names no reporting mailbox; the mailbox reported messages land in is the whole point of the custom destination.'
    }

    if ($desiredMailbox -match $script:PlaceholderPattern) {
        throw "DesiredReportingMailboxUnresolved: the reporting mailbox is still the placeholder '$desiredMailbox'; a placeholder that reached the evaluator is a parameter nobody supplied, and comparing a tenant against the literal placeholder text fails every tenant for the wrong reason."
    }

    $desiredSecOps = @(foreach ($mailbox in $SecOpsMailbox) {
            if (-not [string]::IsNullOrWhiteSpace($mailbox)) { $mailbox }
        })

    if ($desiredSecOps.Count -eq 0) {
        throw 'DesiredSecOpsMailboxRequired: MDO-006 cannot be decided without the SecOps mailboxes the baseline resolved; a tenant compared against no SecOps mailbox passes precisely when Advanced Delivery registers nobody.'
    }

    $observationName = @($script:ReportSubmissionObservation.Keys)
    $policyMember = @(@($decision.Observed) + @($mailboxMember))

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @()
        if ($null -ne $payload) { $present = @(Get-BaselineRecordMemberName -Node $payload) }

        foreach ($name in $observationName) {
            if ($name -cnotin $present) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "ReportSubmissionEvidenceIncomplete: the record carries no '$name' observation."
                }
            }
        }

        $reportPolicy = @(Get-BaselineRecordMember -Node $payload -Name 'ReportSubmissionPolicy')
        foreach ($policy in $reportPolicy) {
            $observedMember = @(Get-BaselineRecordMemberName -Node $policy)
            foreach ($decided in $policyMember) {
                if ($decided -cnotin $observedMember) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "ReportSubmissionEvidenceIncomplete: an observed ReportSubmissionPolicy carries no '$decided' member."
                    }
                }
            }
        }

        $overridePolicy = @(Get-BaselineRecordMember -Node $payload -Name 'SecOpsOverridePolicy')
        foreach ($policy in $overridePolicy) {
            $observedMember = @(Get-BaselineRecordMemberName -Node $policy)
            foreach ($decided in $overrideMember) {
                if ($decided -cnotin $observedMember) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "ReportSubmissionEvidenceIncomplete: an observed SecOpsOverridePolicy carries no '$decided' member."
                    }
                }
            }
        }

        if ($reportPolicy.Count -gt 1) {
            return [pscustomobject]@{
                Status = 'Error'
                Reason = "ReportSubmissionEvidenceAmbiguous: the record carries $($reportPolicy.Count) report submission policies where the tenant holds one."
            }
        }

        $finding = @(
            if ($reportPolicy.Count -eq 0) {
                'the tenant holds no report submission policy'
            }
            else {
                foreach ($observed in $desiredSwitch.Keys) {
                    $actual = [bool](Get-BaselineRecordMember -Node $reportPolicy[0] -Name $observed)
                    if ($actual -ne $desiredSwitch[$observed]) {
                        "the report submission policy sets '$observed' to '$actual' where '$($desiredSwitch[$observed])' is required"
                    }
                }

                $observedDestination = $unrecorded
                foreach ($name in $destinationContract.Keys) {
                    $combination = $destinationContract[$name]
                    $matched = $true
                    foreach ($member in @(Get-BaselineRecordMemberName -Node $combination)) {
                        if ([bool](Get-BaselineRecordMember -Node $reportPolicy[0] -Name $member) -ne [bool]$combination.$member) { $matched = $false }
                    }

                    if ($matched) { $observedDestination = $name }
                }

                if ($observedDestination -cne $desiredDestination) {
                    "the report submission policy sends reported messages to '$observedDestination' where '$desiredDestination' is required"
                }

                $mailbox = Compare-NormalizedCollection -Desired @($desiredMailbox) `
                    -Actual @(Get-BaselineRecordMember -Node $reportPolicy[0] -Name $mailboxMember) -Kind 'SmtpAddress'

                foreach ($missing in @($mailbox.Missing)) { "the report submission policy does not report to '$missing'" }
                foreach ($surplus in @($mailbox.Surplus)) { "the report submission policy reports to unapproved '$surplus'" }
            }

            if ($overridePolicy.Count -eq 0) {
                'the tenant registers no SecOps override policy in Advanced Delivery'
            }
            else {
                $registered = @(foreach ($policy in $overridePolicy) { Get-BaselineRecordMember -Node $policy -Name 'SentTo' })
                $secOps = Compare-NormalizedCollection -Desired $desiredSecOps -Actual $registered -Kind 'SmtpAddress'

                foreach ($missing in @($secOps.Missing)) { "Advanced Delivery does not register SecOps mailbox '$missing'" }
                foreach ($surplus in @($secOps.Surplus)) { "Advanced Delivery registers unapproved SecOps mailbox '$surplus'" }
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'ReportSubmissionDrift: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'MDO-006' -Evidence $Evidence -Evaluator $evaluator
}

# MDO-008: quarantine behaviour is spread over three commands and is decidable from no subset of
# them. The quarantine policies carry the notification cadence and the end-user permission values;
# the hosted content filter says which quarantine policy each spam and phish category is released
# under; and malware is quarantined by the malware filter, not by the content filter, so the one
# category the card names first is invisible without it. All three are read inside the one try
# `Get-BaselineEvidence` runs, so any command refusing makes the whole record uncollected rather
# than leaving the categories that did answer to stand in for the ones that did not.
$script:QuarantineObservation = [ordered]@{
    QuarantinePolicy          = 'Get-QuarantinePolicy'
    HostedContentFilterPolicy = 'Get-HostedContentFilterPolicy'
    MalwareFilterPolicy       = 'Get-MalwareFilterPolicy'
}

function Get-QuarantinePolicyEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$QuarantinePolicyCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$ContentFilterPolicyCollection,

        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$MalwareFilterPolicyCollection
    )

    if ($null -eq $QuarantinePolicyCollection) {
        throw 'QuarantinePolicyCollectionRequired: MDO-008 cannot be observed without a collection that reaches the tenant quarantine policies.'
    }

    if ($null -eq $ContentFilterPolicyCollection) {
        throw 'ContentFilterPolicyCollectionRequired: MDO-008 cannot be observed without a collection that reaches the hosted content filter policies.'
    }

    if ($null -eq $MalwareFilterPolicyCollection) {
        throw 'MalwareFilterPolicyCollectionRequired: MDO-008 cannot be observed without a collection that reaches the malware filter policies.'
    }

    $collection = {
        [ordered]@{
            QuarantinePolicy          = @(& $QuarantinePolicyCollection)
            HostedContentFilterPolicy = @(& $ContentFilterPolicyCollection)
            MalwareFilterPolicy       = @(& $MalwareFilterPolicyCollection)
        }
    }.GetNewClosure()

    return Get-BaselineEvidence -ControlId 'MDO-008' -Source 'ExchangeOnline' `
        -Command (@($script:QuarantineObservation.Values) -join '; ') -Collection $collection
}

# MDO-008: Exchange Online reports end-user quarantine permissions as a bitmask rather than as the
# access level name the baseline declares, so the access level is only comparable through the exact
# value each preset permission group is stored as. An access level with no value here resolves to
# nothing, which would compare every tenant as compliant, so it is refused rather than defaulted.
$script:QuarantinePermissionValue = [ordered]@{
    AdminOnlyAccess = 0
    LimitedAccess   = 106
    FullAccess      = 236
}

# The one member each quarantined category's release permission is actually decided through.
# Malware is quarantined by the malware filter and every other category by the hosted content
# filter, so a category with no entry here is a category the control can locate no quarantine tag
# for and must refuse rather than silently skip.
$script:QuarantineCategoryTag = [ordered]@{
    Malware             = [pscustomobject]@{ Observation = 'MalwareFilterPolicy'; Member = 'QuarantineTag' }
    HighConfidencePhish = [pscustomobject]@{ Observation = 'HostedContentFilterPolicy'; Member = 'HighConfidencePhishQuarantineTag' }
    Phish               = [pscustomobject]@{ Observation = 'HostedContentFilterPolicy'; Member = 'PhishQuarantineTag' }
    HighConfidenceSpam  = [pscustomobject]@{ Observation = 'HostedContentFilterPolicy'; Member = 'HighConfidenceSpamQuarantineTag' }
    Spam                = [pscustomobject]@{ Observation = 'HostedContentFilterPolicy'; Member = 'SpamQuarantineTag' }
    Bulk                = [pscustomobject]@{ Observation = 'HostedContentFilterPolicy'; Member = 'BulkQuarantineTag' }
    SpoofIntelligence   = [pscustomobject]@{ Observation = 'HostedContentFilterPolicy'; Member = 'SpoofQuarantineTag' }
}

$script:QuarantinePolicyDecidedMember = @(
    'Name'
    'QuarantinePolicyType'
    'EndUserQuarantinePermissionsValue'
    'EndUserSpamNotificationFrequency'
    'IncludeMessagesFromBlockedSenderAddress'
)
$script:GlobalQuarantinePolicyType = 'GlobalQuarantinePolicy'
$script:QuarantineAdminOnlyAccessLevel = 'AdminOnlyAccess'

# MDO-008: the cadence and the blocked-sender decision are held by the single global quarantine
# policy, while the permission a category actually gets is the permission of whichever quarantine
# policy that category's filter tag points at. The two are only decidable together, so every
# declared category is resolved through its tag to a policy and then to a permission value. Every
# observed filter policy is decided, because each one applies to some population and an evaluator
# that stopped at the first agreeing policy would report the whole tenant protected by a policy
# that reaches only part of it. Tag and policy names are matched trimmed and case-insensitively,
# because Exchange Online reports a name back in whatever form it was stored with.
function Test-QuarantinePolicyControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Evidence,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$DesiredState
    )

    if ($null -eq $DesiredState) {
        throw 'DesiredQuarantineStateRequired: MDO-008 cannot be decided without the quarantine state the baseline resolved; an evaluator with no desired state decides against whatever it defaults to rather than against what was approved.'
    }

    $declared = @(Get-BaselineRecordMemberName -Node $DesiredState)
    $permissionValue = $script:QuarantinePermissionValue
    $categoryTag = $script:QuarantineCategoryTag
    $adminOnly = $script:QuarantineAdminOnlyAccessLevel

    if ('endUserSpamNotificationFrequencyInDays' -cnotin $declared) {
        throw 'DesiredQuarantineNotificationCadenceRequired: the resolved quarantine state declares no end-user notification cadence; the cadence is the whole reason a user learns a message was quarantined, and a baseline that declares none compares every tenant against nothing at all.'
    }

    $cadenceDay = 0
    $declaredCadence = [string](Get-BaselineRecordMember -Node $DesiredState -Name 'endUserSpamNotificationFrequencyInDays')
    if (-not [int]::TryParse($declaredCadence, [ref]$cadenceDay) -or $cadenceDay -le 0) {
        throw "DesiredQuarantineNotificationCadenceInvalid: the resolved quarantine state declares an end-user notification cadence of '$declaredCadence'; the card requires an exact cadence, which is only comparable as a positive whole number of days."
    }

    if ('includeMessagesFromBlockedSenderAddress' -cnotin $declared) {
        throw 'DesiredQuarantineBlockedSenderDecisionRequired: the resolved quarantine state declares no blocked-sender decision; a baseline that never made it reads identically to a baseline that decided against it, and only one of them is a decision somebody made.'
    }

    $desiredBlockedSender = [bool](Get-BaselineRecordMember -Node $DesiredState -Name 'includeMessagesFromBlockedSenderAddress')

    $categoryPermission = @(foreach ($entry in @(Get-BaselineRecordMember -Node $DesiredState -Name 'categoryPermissions')) {
            if ($null -ne $entry) { $entry }
        })
    if ($categoryPermission.Count -eq 0) {
        throw 'DesiredQuarantineCategoryPermissionRequired: the resolved quarantine state declares no category permission at all; the category permissions are the entire comparison this control makes, and a tenant compared against none of them passes with every category on full end-user access.'
    }

    $desiredCategory = [ordered]@{}
    foreach ($entry in $categoryPermission) {
        $category = ([string](Get-BaselineRecordMember -Node $entry -Name 'category')).Trim()
        $accessLevel = ([string](Get-BaselineRecordMember -Node $entry -Name 'accessLevel')).Trim()

        if ([string]::IsNullOrWhiteSpace($category) -or [string]::IsNullOrWhiteSpace($accessLevel)) {
            throw "DesiredQuarantineCategoryPermissionIncomplete: the resolved quarantine state declares a permission naming category '$category' at access level '$accessLevel'; a permission missing either half approves nothing, and reading it as a permission grants whatever the missing half defaults to."
        }

        if ($accessLevel -cnotin @($permissionValue.Keys)) {
            throw "DesiredQuarantineAccessLevelUnknown: the resolved quarantine state declares '$category' at access level '$accessLevel', which the permission contract does not name; an access level with no declared permission value resolves to nothing and compares every tenant as compliant."
        }

        if ($category -cnotin @($categoryTag.Keys)) {
            throw "DesiredQuarantineCategoryUnmapped: the resolved quarantine state declares category '$category', which no filter policy member releases; a category the control can locate no quarantine tag for is a category the tenant is never actually checked for."
        }

        $desiredCategory[$category] = $accessLevel
    }

    $highRiskCategory = @(foreach ($name in @(Get-BaselineRecordMember -Node $DesiredState -Name 'highRiskCategories')) {
            $trimmed = ([string]$name).Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed)) { $trimmed }
        })

    if ($highRiskCategory.Count -eq 0) {
        throw 'DesiredQuarantineHighRiskCategoryRequired: the resolved quarantine state names no high-risk category; malware and high-confidence phishing being admin-only is the clause this control holds first, and a baseline naming no high-risk category has dropped it.'
    }

    foreach ($name in $highRiskCategory) {
        if ($name -cnotin @($desiredCategory.Keys)) {
            throw "DesiredQuarantineHighRiskCategoryUncovered: the resolved quarantine state names '$name' high-risk but declares no permission for it; a high-risk category with no permission is a category this control would never look at."
        }

        if ($desiredCategory[$name] -cne $adminOnly) {
            throw "DesiredQuarantineHighRiskAccessRequired: the resolved quarantine state names '$name' high-risk and then holds it at '$($desiredCategory[$name])'; the card requires the high-risk categories at '$adminOnly', so a baseline letting end users reach one is a baseline this control refuses rather than enforces."
        }
    }

    $observationName = @($script:QuarantineObservation.Keys)
    $policyMember = $script:QuarantinePolicyDecidedMember
    $globalType = $script:GlobalQuarantinePolicyType

    $evaluator = {
        param($Record)

        $payload = Get-BaselineRecordMember -Node $Record -Name 'Value'
        $present = @()
        if ($null -ne $payload) { $present = @(Get-BaselineRecordMemberName -Node $payload) }

        foreach ($name in $observationName) {
            if ($name -cnotin $present) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "QuarantineEvidenceIncomplete: the record carries no '$name' observation."
                }
            }
        }

        $quarantinePolicy = @(Get-BaselineRecordMember -Node $payload -Name 'QuarantinePolicy')
        foreach ($policy in $quarantinePolicy) {
            $observedMember = @(Get-BaselineRecordMemberName -Node $policy)
            foreach ($decided in $policyMember) {
                if ($decided -cnotin $observedMember) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "QuarantineEvidenceIncomplete: an observed QuarantinePolicy carries no '$decided' member."
                    }
                }
            }
        }

        foreach ($category in @($desiredCategory.Keys)) {
            $tagSource = $categoryTag[$category]
            foreach ($policy in @(Get-BaselineRecordMember -Node $payload -Name $tagSource.Observation)) {
                if ($tagSource.Member -cnotin @(Get-BaselineRecordMemberName -Node $policy)) {
                    return [pscustomobject]@{
                        Status = 'Error'
                        Reason = "QuarantineEvidenceIncomplete: an observed $($tagSource.Observation) carries no '$($tagSource.Member)' member for '$category'."
                    }
                }
            }
        }

        $policyByName = @{}
        foreach ($policy in $quarantinePolicy) {
            $key = ([string](Get-BaselineRecordMember -Node $policy -Name 'Name')).Trim().ToLowerInvariant()
            if ($policyByName.ContainsKey($key)) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "QuarantineEvidenceAmbiguous: the record carries two quarantine policies under the name '$key'."
                }
            }

            $policyByName[$key] = $policy
        }

        $globalPolicy = @(foreach ($policy in $quarantinePolicy) {
                if (([string](Get-BaselineRecordMember -Node $policy -Name 'QuarantinePolicyType')).Trim() -ieq $globalType) { $policy }
            })

        if ($globalPolicy.Count -gt 1) {
            return [pscustomobject]@{
                Status = 'Error'
                Reason = "QuarantineEvidenceAmbiguous: the record carries $($globalPolicy.Count) global quarantine policies where the tenant holds one."
            }
        }

        $observedCadence = [string]$null
        $cadenceSpan = [timespan]::Zero
        if ($globalPolicy.Count -eq 1) {
            $observedCadence = [string](Get-BaselineRecordMember -Node $globalPolicy[0] -Name 'EndUserSpamNotificationFrequency')
            if (-not [timespan]::TryParse($observedCadence, [ref]$cadenceSpan)) {
                return [pscustomobject]@{
                    Status = 'Error'
                    Reason = "QuarantineEvidenceNotRecognized: the global quarantine policy reports an end-user notification cadence of '$observedCadence', which is not a time span."
                }
            }
        }

        $finding = @(
            if ($globalPolicy.Count -eq 0) { 'the tenant holds no global quarantine policy' }
            if (@(Get-BaselineRecordMember -Node $payload -Name 'HostedContentFilterPolicy').Count -eq 0) { 'the tenant holds no hosted content filter policy' }
            if (@(Get-BaselineRecordMember -Node $payload -Name 'MalwareFilterPolicy').Count -eq 0) { 'the tenant holds no malware filter policy' }

            if ($globalPolicy.Count -eq 1) {
                if ($cadenceSpan.TotalDays -ne $cadenceDay) {
                    "the global quarantine policy notifies end users every '$observedCadence' where exactly $cadenceDay day is required"
                }

                $observedBlockedSender = [bool](Get-BaselineRecordMember -Node $globalPolicy[0] -Name 'IncludeMessagesFromBlockedSenderAddress')
                if ($observedBlockedSender -ne $desiredBlockedSender) {
                    "the global quarantine policy includes messages from blocked senders as '$observedBlockedSender' where '$desiredBlockedSender' is required"
                }
            }

            foreach ($category in @($desiredCategory.Keys)) {
                $tagSource = $categoryTag[$category]
                $accessLevel = $desiredCategory[$category]
                $required = $permissionValue[$accessLevel]

                foreach ($policy in @(Get-BaselineRecordMember -Node $payload -Name $tagSource.Observation)) {
                    $policyName = ([string](Get-BaselineRecordMember -Node $policy -Name 'Name')).Trim()
                    $tag = ([string](Get-BaselineRecordMember -Node $policy -Name $tagSource.Member)).Trim()

                    if (-not $policyByName.ContainsKey($tag.ToLowerInvariant())) {
                        "the $($tagSource.Observation) '$policyName' releases '$category' under quarantine tag '$tag', which the tenant does not hold"
                        continue
                    }

                    $observedValue = [int](Get-BaselineRecordMember -Node $policyByName[$tag.ToLowerInvariant()] -Name 'EndUserQuarantinePermissionsValue')
                    if ($observedValue -eq $required) { continue }

                    if ($category -cin $highRiskCategory) {
                        "the $($tagSource.Observation) '$policyName' resolves high-risk '$category' to permission value '$observedValue' where admin-only access requires '$required'"
                    }
                    else {
                        "the $($tagSource.Observation) '$policyName' resolves '$category' to permission value '$observedValue' where '$accessLevel' requires '$required'"
                    }
                }
            }
        )

        if ($finding.Count -eq 0) {
            return [pscustomobject]@{ Status = 'Pass' }
        }

        return [pscustomobject]@{
            Status = 'Fail'
            Reason = 'QuarantineDrift: {0}.' -f ($finding -join '; ')
        }
    }

    return Test-BaselineControl -ControlId 'MDO-008' -Evidence $Evidence -Evaluator $evaluator
}

# COM-007: the one configuration source both entry scripts share. Deployment and evidence cannot
# reach different desired state or different hashes because neither builds a configuration of its
# own; each receives this context, resolved, schema-validated and hashed by the same code path.
function Get-BaselineContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigurationPath,

        [Parameter(Mandatory)]
        [string]$ParameterPath,

        [Parameter(Mandatory)]
        [string]$SchemaPath,

        [ValidateSet('MicrosoftNative', 'ThirdPartyGateway')]
        [string]$DeploymentProfile,

        [AllowNull()]
        [scriptblock]$GraphRequest
    )

    $resolveArgument = @{
        ConfigurationPath = $ConfigurationPath
        ParameterPath     = $ParameterPath
    }
    if ($PSBoundParameters.ContainsKey('DeploymentProfile')) {
        $resolveArgument['DeploymentProfile'] = $DeploymentProfile
    }

    $resolution = Resolve-BaselineConfiguration @resolveArgument
    $validation = Assert-BaselineConfiguration -Resolution $resolution -SchemaPath $SchemaPath
    $desiredState = Assert-BaselineDesiredState -Configuration $validation.Configuration
    $configurationHash = Get-BaselineConfigurationHash -Resolution $resolution

    # LIC-008: the one entitlement both entry scripts consume. With a Graph seam it is the tenant
    # service-plan inventory; without one nothing was collected, so every capability is reported
    # unentitled rather than falling back to the tiers the baseline declares.
    $entitlement = if ($null -ne $GraphRequest) {
        Resolve-BaselineEntitlement -Configuration $validation.Configuration `
            -TenantServicePlan (Get-BaselineTenantServicePlan -GraphRequest $GraphRequest)
    }
    else {
        New-BaselineEntitlementProjection -Configuration $validation.Configuration `
            -EnabledServicePlanId @() -Source 'NotCollected'
    }

    return [pscustomobject]@{
        Configuration     = $validation.Configuration
        DeploymentProfile = $resolution.DeploymentProfile
        SchemaPath        = $validation.SchemaPath
        Algorithm         = $configurationHash.Algorithm
        Hash              = $configurationHash.Hash
        CanonicalJson     = $configurationHash.CanonicalJson
        GatewayDeclared   = $desiredState.GatewayDeclared
        Entitlement       = $entitlement
    }
}

Export-ModuleMember -Function @(
    'Resolve-BaselineConfiguration'
    'Assert-BaselineConfiguration'
    'Assert-BaselineDesiredState'
    'Get-BaselineContext'
    'Resolve-BaselineEntitlement'
    'Get-BaselineTenantServicePlan'
    'Get-BaselineTargetEntitlement'
    'Invoke-BaselineGraphRequest'
    'Get-BaselineGraphDiscovery'
    'Get-BaselineTargetPopulation'
    'Get-BaselineLicensingMatrix'
    'Test-BaselineSafeDocumentsPreflight'
    'ConvertTo-CanonicalJson'
    'Test-BaselineControl'
    'Get-BaselineConfigurationHash'
    'Compare-NormalizedCollection'
    'Get-ControlApplicability'
    'Test-RiskAcceptance'
    'Test-RiskAcceptanceDocument'
    'New-ControlResult'
    'New-BaselineEvidence'
    'Get-BaselineEvidence'
    'New-BaselineControlRegistry'
    'Get-BaselineControlRegistry'
    'Test-BaselineControlResolution'
    'Get-BaselineControlCatalog'
    'Test-BaselineControlCoverage'
    'Test-BaselineEvidenceFramework'
    'Get-BaselineEvidenceContentHash'
    'Test-BaselineGoLive'
    'Get-BaselineExitCodeContract'
    'Get-BaselineRunOutcome'
    'Get-ConditionalAccessEvidence'
    'Test-ConditionalAccessControl'
    'Get-AcceptedDomainEvidence'
    'Test-AcceptedDomainControl'
    'Get-OutboundForwardingEvidence'
    'Test-OutboundForwardingControl'
    'Get-ExternalPostmasterEvidence'
    'Test-ExternalPostmasterControl'
    'Get-MailboxAuditingEvidence'
    'Test-MailboxAuditingControl'
    'Get-ExternalSenderTagEvidence'
    'Test-ExternalSenderTagControl'
    'Get-RemoteDomainEvidence'
    'Test-RemoteDomainControl'
    'Get-ClientProtocolEvidence'
    'Test-ClientProtocolControl'
    'Get-ExchangeRoleAssignmentEvidence'
    'Test-ExchangeRoleAssignmentControl'
    'Get-SmtpAuthenticationEvidence'
    'Test-SmtpAuthenticationControl'
    'Get-MtaStsEvidence'
    'Test-MtaStsControl'
    'Get-AddInAcquisitionEvidence'
    'Test-AddInAcquisitionControl'
    'Get-StandardPresetEvidence'
    'Test-StandardPresetControl'
    'Get-StrictPresetEvidence'
    'Test-StrictPresetControl'
    'Get-BuiltInProtectionEvidence'
    'Test-BuiltInProtectionControl'
    'Get-PriorityAccountEvidence'
    'Test-PriorityAccountControl'
    'Get-SafeAttachmentsEvidence'
    'Test-SafeAttachmentsControl'
    'Get-SafeDocumentsEvidence'
    'Test-SafeDocumentsControl'
    'Get-ReportSubmissionEvidence'
    'Test-ReportSubmissionControl'
    'Get-QuarantinePolicyEvidence'
    'Test-QuarantinePolicyControl'
    'Get-BaselineParameterHash'
    'New-BaselineEvidenceEnvelope'
    'Get-BaselineResultContract'
    'Get-CanonicalComparisonContract'
    'Get-ApplicabilityAuthorityContract'
    'Get-ArtifactVersionContract'
    'Get-ApprovalSignatureContract'
    'Get-BaselineChangeArtifactContract'
    'New-BaselineChangeArtifactSet'
    'Write-BaselineChangeArtifact'
    'New-BaselineChangePreview'
    'Test-BaselineChangeApproval'
    'New-BaselineChangeStateCapture'
    'New-BaselineRollbackScript'
    'Get-BaselineMutationGuardContract'
    'Get-BaselineMutationGuardReport'
    'New-BaselineMutationJournal'
    'Resolve-BaselinePartialApplication'
    'Test-BaselineChangeSuccess'
    'Test-BaselineApplyPrerequisite'
    'Test-BaselineDeploymentApplyOrder'
    'Test-BaselineDeploymentMutationPlan'
)
