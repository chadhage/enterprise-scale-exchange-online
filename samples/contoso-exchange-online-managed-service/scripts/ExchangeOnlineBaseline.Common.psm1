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
    'ConfigurationHash'
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

# COM-006: the declared-tier entitlement projection both entry scripts used to restate. DES-003
# makes this planning metadata only; LIC-002 onward replaces it with the tenant service-plan
# inventory, which overrides anything declared here.
function Get-BaselineEntitlement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Configuration
    )

    $messaging = Get-BaselineConfigValue -Configuration $Configuration -Path 'licensing.messagingTier' -Default 'EOP'
    $compliance = Get-BaselineConfigValue -Configuration $Configuration -Path 'licensing.complianceTier' -Default 'None'
    $mdoP1 = $messaging -in @('MDO_P1', 'MDO_P2')

    return [pscustomobject]@{
        MessagingTier      = $messaging
        ComplianceTier     = $compliance
        EopPresets         = $true
        AtpPresets         = $mdoP1
        BuiltInProtection  = $mdoP1
        SafeAttachmentsSpo = $mdoP1
        SafeDocuments      = $messaging -eq 'MDO_P2'
        PurviewRetention   = $compliance -in @('E3', 'E5Compliance')
        AuditPremium       = $compliance -eq 'E5Compliance'
    }
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
        [datetime]$AsOf
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

    if ([string]$RiskAcceptance.ControlId -ne $ControlId) {
        return & $reject "ControlMismatch: the risk acceptance is raised for '$($RiskAcceptance.ControlId)', not '$ControlId'."
    }

    if ([string]$RiskAcceptance.TenantId -ne $TenantId) {
        return & $reject "TenantMismatch: the risk acceptance is raised for another tenant."
    }

    if ([string]$RiskAcceptance.ConfigurationHash -ne $ConfigurationHash) {
        return & $reject 'ConfigurationHashMismatch: the risk acceptance is bound to another configuration.'
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
        [string]$DeploymentProfile
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

    return [pscustomobject]@{
        Configuration     = $validation.Configuration
        DeploymentProfile = $resolution.DeploymentProfile
        SchemaPath        = $validation.SchemaPath
        Algorithm         = $configurationHash.Algorithm
        Hash              = $configurationHash.Hash
        CanonicalJson     = $configurationHash.CanonicalJson
        GatewayDeclared   = $desiredState.GatewayDeclared
        Entitlement       = (Get-BaselineEntitlement -Configuration $validation.Configuration)
    }
}

Export-ModuleMember -Function @(
    'Resolve-BaselineConfiguration'
    'Assert-BaselineConfiguration'
    'Assert-BaselineDesiredState'
    'Get-BaselineContext'
    'Get-BaselineEntitlement'
    'Get-BaselineTenantServicePlan'
    'Get-BaselineTargetEntitlement'
    'Invoke-BaselineGraphRequest'
    'Get-BaselineGraphDiscovery'
    'Get-BaselineTargetPopulation'
    'Get-BaselineLicensingMatrix'
    'ConvertTo-CanonicalJson'
    'Get-BaselineConfigurationHash'
    'Compare-NormalizedCollection'
    'Get-ControlApplicability'
    'Test-RiskAcceptance'
    'New-ControlResult'
    'Get-BaselineResultContract'
    'Get-CanonicalComparisonContract'
    'Get-ApplicabilityAuthorityContract'
    'Get-ArtifactVersionContract'
    'Get-ApprovalSignatureContract'
)
