#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Tests live Exchange Online state and writes machine-readable evidence.
.DESCRIPTION
    Builds the shared baseline context to learn the deployment profile and the
    entitlement the tenant service-plan inventory reports, then collects evidence
    for every control the tenant is entitled to run. Controls the tenant does not
    hold an enabled service plan for are reported as NotEntitled and do not fail
    the run. Controls owned by another system are reported as Manual.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ParameterPath,

    [string]$ConfigurationPath = (Join-Path $PSScriptRoot '..\config\exchange-only.v1.json'),

    [switch]$AllowHistoricalProfile,

    [string]$SchemaPath = (Join-Path $PSScriptRoot '..\config\exchange-online-secure-baseline.schema.json'),

    [string]$OutputPath = (Join-Path $PSScriptRoot '..\evidence'),

    # GATE-001: the go-live request and everything a fail-closed decision has to be measured
    # against. All four are optional, because an ordinary evidence run must stay able to collect
    # without being asked to decide, and a gate that every run is forced through is a gate that
    # gets switched off. None of them is read until GATE-003 wires the decision.
    [switch]$GoLive,

    [switch]$SignEvidence,

    [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,

    [string]$EvidenceSignerIdentity,

    [string]$AuthorizedSignerPath,

    [string]$ExpectedEvidenceHash,

    [string]$EvidencePath,

    [string]$EvidenceSignaturePath,

    [string]$EvidenceSignerSubject,

    [string]$RiskAcceptancePath,

    [timespan]$MaximumEvidenceAge,

    [string]$ExpectedConfigurationHash,

    [string]$RbacPimFallbackPath,

    [timespan]$MaximumRbacPimFallbackAge = ([timespan]::FromHours(24)),

    [string]$RbacPimFallbackSignerIdentity,

    [object[]]$RbacPimFallbackAuthorizedSigner = @(),

    [switch]$SkipConnection
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking

$exitCode = Get-BaselineExitCodeContract

try {
    $selectedProfile = Get-BaselineDeploymentProfile -ConfigurationPath $ConfigurationPath -AllowHistoricalProfile:$AllowHistoricalProfile
}
catch {
    Write-Error "ConfigurationUnusable: $($_.Exception.Message)" -ErrorAction Continue
    exit $exitCode.Configuration
}
if ($selectedProfile -ceq 'ExchangeOnly') {
    try {
        $exchangeContext = Get-BaselineExchangeContext -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath
    }
    catch {
        Write-Error "ConfigurationUnusable: $($_.Exception.Message)" -ErrorAction Continue
        exit $exitCode.Configuration
    }
    if ($GoLive -or $SignEvidence) {
        try {
            if (($GoLive -and $SignEvidence) -or $RiskAcceptancePath) { throw 'ExchangeGoLiveInputsRequired: select either -GoLive or -SignEvidence; separate risk-acceptance imports are not supported for this frozen Exchange artifact.' }
            $exchangeGate = Invoke-BaselineExchangeGoLive -Context $exchangeContext -EvidencePath $EvidencePath `
                -SignaturePath $EvidenceSignaturePath -SignerSubject $EvidenceSignerSubject -MaximumEvidenceAge $MaximumEvidenceAge `
                -SignerIdentity $EvidenceSignerIdentity -AuthorizedSignerPath $AuthorizedSignerPath `
                -ExpectedEvidenceHash $ExpectedEvidenceHash -ExpectedConfigurationHash $ExpectedConfigurationHash `
                -SignEvidence:$SignEvidence -SigningCertificate $SigningCertificate
            $exchangeGate.Decision | ConvertTo-Json -Depth 30 | Write-Output
            $outcome = $exchangeGate.Outcome
            exit $outcome.ExitCode
        }
        catch {
            $message = $_.Exception.Message
            Write-Error $message -ErrorAction Continue
            switch -Regex ($message) {
                '^(ExchangeGoLiveInputsRequired|GoLiveMaximumEvidenceAgeNotPositive|ExpectedConfigurationHashMismatch):' { exit $exitCode.Configuration }
                '^(EvidenceUnreadable|GoLiveCheckRequired):' { exit $exitCode.Collection }
                '^(EvidenceHashMismatch|ExchangeSignatureUnverified|ExternalEvidenceSigner|SigningCertificateRequired|SignatureAlreadyExists|EvidenceSigningFailed)' { exit $exitCode.Approval }
                default { exit $exitCode.Internal }
            }
        }
    }
    try {
        if (-not $SkipConnection) {
            Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0
            Connect-ExchangeOnline -ShowBanner:$false
        }
    }
    catch {
        Write-Error "ConnectionFailed: $($_.Exception.Message)" -ErrorAction Continue
        exit $exitCode.Connection
    }
    try {
        $outcome = Invoke-BaselineExchangeEvidence -Context $exchangeContext -OutputPath $OutputPath
        exit $outcome.ExitCode
    }
    catch {
        Write-Error "EvidenceUnreadable: $($_.Exception.Message)" -ErrorAction Continue
        exit $exitCode.Collection
    }
}
if ($SignEvidence) { Write-Error 'SignEvidence requires the ExchangeOnly profile.' -ErrorAction Continue; exit $exitCode.Configuration }

# GATE-004: every exit this command produces is resolved from the one contract, so an automation
# caller can tell a configuration it can fix from a connection it can retry, a collection it can
# rerun, a compliance gap it must escalate, an approval it must obtain, and a defect in this tool.
# A run that reported all six as `1` told the caller none of that.

# A fault nothing below anticipated is a defect in this tool rather than a finding about the
# tenant, and reporting it as a finding sends the operator to fix a tenant that was never at fault.
trap {
    Write-Error "InternalFault: $($_.Exception.Message)" -ErrorAction Continue
    exit $exitCode.Internal
}

# LIC-008: DES-003 makes the runtime tenant service-plan inventory the only entitlement authority,
# so Graph is connected before the context is built and the same seam feeds both entry scripts.
# With no connection nothing is collected and every capability is reported unentitled.
$graphRequest = $null
if (-not $SkipConnection) {
    try {
        Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0
        Connect-ExchangeOnline -ShowBanner:$false

        Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.0.0
        Connect-MgGraph -Scopes 'Organization.Read.All' -NoWelcome
    }
    catch {
        Write-Error "ConnectionFailed: $($_.Exception.Message)" -ErrorAction Continue
        exit $exitCode.Connection
    }

    $graphRequest = {
        param($Resource)
        Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/$Resource" -OutputType PSObject
    }
}

# COM-007: evidence and deployment draw from this one context, so neither can evaluate a desired
# state or report an identity the other never saw. Unresolved administrator inputs are rejected here.
try {
    $context = Get-BaselineContext -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath -SchemaPath $SchemaPath -GraphRequest $graphRequest
    $configuration = $context.Configuration
    $entitlement = $context.Entitlement
}
catch {
    Write-Error "ConfigurationUnusable: $($_.Exception.Message)" -ErrorAction Continue
    exit $exitCode.Configuration
}

$gatewayDeclared = $context.GatewayDeclared
$mdoLicensed = $entitlement.AtpPresets
$safeDocsLicensed = $entitlement.SafeDocuments
$purviewLicensed = $entitlement.PurviewRetention
$auditPremiumLicensed = $entitlement.AuditPremium
$entitlementReason = @{}
foreach ($capability in @($entitlement.Capability)) { $entitlementReason[$capability.Name] = $capability.Reason }

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$domain = $configuration.administratorInputs.primaryDomain

# A tenant this run could not read is a rerun the caller can act on, not a control it must escalate,
# so every observation is taken inside one boundary that reports the collection fault on its own.
try {
    $evidence = [ordered]@{
        licensing          = [ordered]@{
            entitlementSource      = $entitlement.Source
            entitlementDetermined  = $entitlement.Determined
            enabledServicePlanId   = @($entitlement.EnabledServicePlanId)
            capability             = @($entitlement.Capability)
            notEntitled            = @($entitlement.NotEntitled)
            declaredMessagingTier  = $entitlement.DeclaredMessagingTier
            declaredComplianceTier = $entitlement.DeclaredComplianceTier
        }
        acceptedDomain     = Get-AcceptedDomain -Identity $domain | Select-Object Name, DomainName, DomainType
        transport          = Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled, ExternalPostmasterAddress
        organization       = Get-OrganizationConfig -RetrieveEwsOperationAccessPolicy -ErrorAction Stop | Select-Object AuditDisabled, EwsEnabled, EwsApplicationAccessPolicy, EwsAllowList, EwsAllowedAppIDs
        externalInOutlook  = @(Get-ExternalInOutlook | Select-Object Enabled, AllowList)
        remoteDomain       = @(Get-RemoteDomain -ErrorAction Stop | Select-Object Identity, DomainName, Name, AutoForwardEnabled, AutoReplyEnabled, AllowedOOFType, DeliveryReportEnabled, NDREnabled)
        casMailboxPlans    = @(Get-CASMailboxPlan -ResultSize Unlimited | Select-Object Identity, PopEnabled, ImapEnabled)
        casMailboxes       = @(Get-CASMailbox -ResultSize Unlimited -ErrorAction Stop | Select-Object Identity, EwsEnabled, EwsApplicationAccessPolicy, EwsAllowList, PopEnabled, ImapEnabled)
        outboundSpam       = Get-HostedOutboundSpamFilterPolicy -Identity Default | Select-Object Name, AutoForwardingMode
        quarantineGlobal   = Get-QuarantinePolicy -Identity DefaultGlobalTag | Select-Object Name, EndUserSpamNotificationFrequency
        quarantinePolicies = @(Get-QuarantinePolicy | Select-Object Name, EndUserQuarantinePermissionsValue, ESNEnabled)
        dkim               = Get-DkimSigningConfig -Identity $domain | Select-Object Name, Enabled, Status, Selector1CNAME, Selector2CNAME, Selector1KeySize, Selector2KeySize
        standardEop        = Get-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' | Select-Object Name, State, RecipientDomainIs, ExceptIfSentTo, ExceptIfSentToMemberOf
        strictEop          = Get-EOPProtectionPolicyRule -Identity 'Strict Preset Security Policy' | Select-Object Name, State, SentToMemberOf
        bypassRules        = @(Get-TransportRule | Where-Object { $_.SetSCL -eq '-1' } | Select-Object Name, State, SetSCL)
    }

    if ($gatewayDeclared) {
        $inboundName = $configuration.administratorInputs.gatewayInboundConnectorName
        $outboundName = $configuration.administratorInputs.gatewayOutboundConnectorName
        $evidence.inboundConnector = Get-InboundConnector -Identity $inboundName | Select-Object Name, Enabled, ConnectorType, RequireTls, SenderIPAddresses, EFSkipLastIP, EFSkipIPs, EFUsers
        $evidence.outboundConnector = Get-OutboundConnector -Identity $outboundName | Select-Object Name, Enabled, ConnectorType, RecipientDomains, SmartHosts, TlsSettings, TlsDomain
        $evidence.arcConfig = @(Get-ArcConfig | Select-Object Identity, ArcTrustedSealers)
    }
    else {
        $evidence.partnerInboundConnectors = @(Get-InboundConnector | Select-Object Name, ConnectorType, Enabled, SenderIPAddresses)
    }

    if ($mdoLicensed) {
        $evidence.atpGlobal = Get-AtpPolicyForO365 | Select-Object EnableATPForSPOTeamsODB, EnableSafeDocs, AllowSafeDocsOpen
        $evidence.standardAtp = Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' | Select-Object Name, State, RecipientDomainIs, ExceptIfSentTo, ExceptIfSentToMemberOf
        $evidence.strictAtp = Get-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' | Select-Object Name, State, SentToMemberOf
        $evidence.builtInProtection = Get-ATPBuiltInProtectionRule | Select-Object Name, State, ExceptIfRecipientDomainIs, ExceptIfSentTo, ExceptIfSentToMemberOf
    }
}
catch {
    Write-Error "CollectionFailed: $($_.Exception.Message)" -ErrorAction Continue
    exit $exitCode.Collection
}

$checks = [ordered]@{}

function Add-Check {
    param([string]$Name, [string]$Status, [string]$Detail = '')
    $checks[$Name] = [ordered]@{ status = $Status; detail = $Detail }
}

function Add-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail = '')
    Add-Check -Name $Name -Status $(if ($Passed) { 'Pass' } else { 'Fail' }) -Detail $Detail
}

function Resolve-CompleteControlRegistryOrchestration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$CatalogControlId,

        [Parameter(Mandatory)]
        [object[]]$Registry,

        [Parameter(Mandatory)]
        [object[]]$Projection
    )

    $catalogId = @($CatalogControlId)
    $registryById = @{}
    foreach ($entry in @($Registry)) {
        $registryById[[string]$entry.ControlId] = $entry
    }

    $projectionById = @{}
    foreach ($entry in @($Projection)) {
        $controlId = [string]$entry.ControlId
        if ($controlId -cnotin $catalogId -or -not $registryById.ContainsKey($controlId)) {
            throw "UnknownRegistryProjection: control '$controlId' is not declared by both the catalog and registry."
        }
        if (-not $projectionById.ContainsKey($controlId)) {
            $projectionById[$controlId] = [System.Collections.Generic.List[object]]::new()
        }
        $projectionById[$controlId].Add($entry)
    }

    $evidence = [System.Collections.Generic.List[object]]::new()
    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($controlId in $catalogId) {
        if (-not $registryById.ContainsKey($controlId)) {
            throw "RegistryControlMissing: catalog control '$controlId' is not registered."
        }
        if (-not $projectionById.ContainsKey($controlId)) {
            throw "RegistryProjectionMissing: catalog control '$controlId' has no final projection."
        }

        $candidate = @($projectionById[$controlId])
        if ($candidate.Count -ne 1) {
            throw "RegistryProjectionDuplicated: control '$controlId' has $($candidate.Count) final projections."
        }

        $projectionEntry = $candidate[0]
        $registered = $registryById[$controlId]
        if ([string]$projectionEntry.Kind -ceq 'Inline') {
            throw "InlineRegistryResult: control '$controlId' did not come from its registered evaluator."
        }
        if ([string]$projectionEntry.Collector -cne [string]$registered.Collector) {
            throw "RegistryCollectorMisidentified: control '$controlId' names '$($projectionEntry.Collector)', expected '$($registered.Collector)'."
        }
        if ([string]$projectionEntry.Evaluator -cne [string]$registered.Evaluator) {
            throw "RegistryEvaluatorMisidentified: control '$controlId' names '$($projectionEntry.Evaluator)', expected '$($registered.Evaluator)'."
        }
        if ($null -eq $projectionEntry.Evidence) {
            throw "RegistryEvidenceMissing: control '$controlId' has no final evidence record."
        }
        if ([string]$projectionEntry.Evidence.ControlId -cne $controlId) {
            throw "RegistryEvidenceMisidentified: projection '$controlId' carries evidence for '$($projectionEntry.Evidence.ControlId)'."
        }
        if ($null -eq $projectionEntry.Result) {
            throw "RegistryResultMissing: control '$controlId' has no final result."
        }
        if ([string]$projectionEntry.Result.ControlId -cne $controlId) {
            throw "RegistryResultMisidentified: projection '$controlId' carries a result for '$($projectionEntry.Result.ControlId)'."
        }
        if ([string]$projectionEntry.Result.Status -ceq 'Manual') {
            throw "ManualRegistryResult: control '$controlId' ended with a literal Manual result."
        }

        $evidence.Add($projectionEntry.Evidence)
        $result.Add($projectionEntry.Result)
    }

    $resolved = [pscustomobject]@{ Result = @($result) }
    $resolved | Add-Member -NotePropertyName Evidence -NotePropertyValue @($evidence)
    $resolved
}

function Resolve-BaselineRegistryDecisionProjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Registry,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$SelectedProfile,

        [Parameter(Mandatory)]
        [AllowNull()]
        [hashtable]$EntitlementByControl,

        [Parameter(Mandatory)]
        [AllowNull()]
        [hashtable]$EvaluatedResultByControl,

        [switch]$ProfileExclusionOnly
    )

    $newRefusal = {
        param([string]$ControlId, [string]$Reason)
        [pscustomobject]@{ ControlId = $ControlId; Status = 'Error'; Reason = $Reason }
    }

    if ($SelectedProfile -cnotin @('Native', 'Gateway')) {
        return & $newRefusal '' "ApplicabilityProfileUnknown: '$SelectedProfile' is not a shipped registry profile."
    }
    if ($null -eq $Registry -or @($Registry).Count -eq 0) {
        return & $newRefusal '' 'ApplicabilityRegistryEmpty: no registry entry is available to decide applicability.'
    }

    $groups = @($Registry | Group-Object -Property ControlId)
    foreach ($group in $groups) {
        $controlId = [string]$group.Name
        if ($group.Count -ne 1) {
            & $newRefusal $controlId "ApplicabilityDeclarationConflicting: '$controlId' has $($group.Count) registry declarations."
            continue
        }

        $entry = $group.Group[0]
        if ($entry.PSObject.Properties.Match('ApplicableProfile').Count -eq 0) {
            & $newRefusal $controlId "ApplicabilityDeclarationMissing: '$controlId' has no registry applicability declaration."
            continue
        }

        $declaredProfile = @($entry.ApplicableProfile)
        if ($declaredProfile.Count -eq 0 -or @($declaredProfile | Where-Object { [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
            & $newRefusal $controlId "ApplicabilityDeclarationPartial: '$controlId' has an empty registry profile declaration."
            continue
        }
        $unknownProfile = @($declaredProfile | Where-Object { [string]$_ -cnotin @('Native', 'Gateway') })
        if ($unknownProfile.Count -gt 0) {
            & $newRefusal $controlId "ApplicabilityDeclarationPartial: '$controlId' declares unknown profile '$($unknownProfile -join "', '")'."
            continue
        }

        if ($SelectedProfile -cnotin $declaredProfile) {
            [pscustomobject]@{
                ControlId = $controlId
                Status = 'NotApplicable'
                Reason = "ProfileNotApplicable: '$controlId' is outside the selected '$SelectedProfile' profile."
            }
            continue
        }
        if ($ProfileExclusionOnly) { continue }

        if ($null -eq $EntitlementByControl -or -not $EntitlementByControl.ContainsKey($controlId) -or $null -eq $EntitlementByControl[$controlId]) {
            & $newRefusal $controlId "EntitlementDecisionMissing: '$controlId' has no entitlement decision."
            continue
        }

        $entitlement = $EntitlementByControl[$controlId]
        $missingMember = @('Determined', 'Entitled', 'Status', 'Reason') | Where-Object { $entitlement.PSObject.Properties.Match($_).Count -eq 0 }
        if ($missingMember.Count -gt 0) {
            & $newRefusal $controlId "EntitlementDecisionPartial: '$controlId' carries no '$($missingMember -join "', '")'."
            continue
        }
        if ($entitlement.Determined -isnot [bool] -or $entitlement.Determined -ne $true) {
            & $newRefusal $controlId "EntitlementDecisionUnresolved: '$controlId' was not determined by the entitlement authority."
            continue
        }
        if ($entitlement.Entitled -isnot [bool] -or
            ($entitlement.Entitled -eq $true -and [string]$entitlement.Status -cne 'Pass') -or
            ($entitlement.Entitled -eq $false -and [string]$entitlement.Status -cne 'NotEntitled')) {
            & $newRefusal $controlId "EntitlementDecisionConflicting: '$controlId' carries Entitled='$($entitlement.Entitled)' and Status='$($entitlement.Status)'."
            continue
        }
        if (-not $entitlement.Entitled) {
            [pscustomobject]@{ ControlId = $controlId; Status = 'NotEntitled'; Reason = [string]$entitlement.Reason }
            continue
        }

        if ($null -eq $EvaluatedResultByControl -or -not $EvaluatedResultByControl.ContainsKey($controlId) -or $null -eq $EvaluatedResultByControl[$controlId]) {
            & $newRefusal $controlId "EvaluatedResultMissing: '$controlId' is applicable and entitled but has no evaluator result."
            continue
        }
        $evaluated = $EvaluatedResultByControl[$controlId]
        [pscustomobject]@{
            ControlId = $controlId
            Status = [string]$evaluated.Status
            Reason = [string]$evaluated.Reason
        }
    }
}

function Get-BaselineProfileExclusion {
    param(
        [Parameter(Mandatory)]
        [object[]]$Registry,

        [Parameter(Mandatory)]
        [ValidateSet('Native', 'Gateway')]
        [string]$SelectedProfile
    )

    if ($null -ne (Get-Command -Name Resolve-BaselineRegistryDecisionProjection -CommandType Function -ErrorAction SilentlyContinue)) {
        Resolve-BaselineRegistryDecisionProjection -Registry $Registry `
            -SelectedProfile $SelectedProfile -EntitlementByControl @{} `
            -EvaluatedResultByControl @{} -ProfileExclusionOnly |
            Where-Object Status -CEQ 'NotApplicable'
        return
    }

    foreach ($control in @($Registry)) {
        if ($SelectedProfile -cin @($control.ApplicableProfile)) { continue }
        [pscustomobject]@{
            ControlId = [string]$control.ControlId
            Status = 'NotApplicable'
            Reason = "ProfileNotApplicable: '$($control.ControlId)' is outside the selected '$SelectedProfile' profile."
        }
    }
}

function Invoke-BaselineControlRegistryExecution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Registry,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ExpectedControlId,

        [scriptblock]$CommandResolver = {
            param($Name)
            @(Get-Command -Name $Name -CommandType Function, Cmdlet -ErrorAction SilentlyContinue)
        },

        [scriptblock]$CollectorArgumentResolver = { param($Entry) @{} },

        [scriptblock]$EvaluatorArgumentResolver = {
            param($Entry, $Evidence)
            $argument = @{}
            $argument['Evidence'] = $Evidence
            $argument
        }
    )

    if ($null -eq $Registry -or @($Registry).Count -eq 0) {
        throw 'RegistryExecutionRegistryRequired: at least one applicable control must be registered before execution.'
    }
    if ($null -eq $ExpectedControlId -or @($ExpectedControlId).Count -eq 0) {
        throw 'RegistryExecutionExpectedControlRequired: execution must name every control expected in the applicable registry.'
    }

    $registeredControl = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($entry in $Registry) {
        $controlId = [string]$entry.ControlId
        if ([string]::IsNullOrWhiteSpace($controlId)) {
            throw 'RegistryExecutionControlIdRequired: every applicable registry entry must name its control.'
        }
        if (-not $registeredControl.Add($controlId)) {
            throw "RegistryExecutionControlDuplicated: '$controlId' is registered more than once."
        }
    }

    $expectedControl = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($controlId in $ExpectedControlId) {
        if ([string]::IsNullOrWhiteSpace($controlId)) {
            throw 'RegistryExecutionExpectedControlRequired: an expected control identifier cannot be blank.'
        }
        if (-not $expectedControl.Add($controlId)) {
            throw "RegistryExecutionExpectedControlDuplicated: '$controlId' is expected more than once."
        }
    }

    $missingControl = @($ExpectedControlId | Where-Object { -not $registeredControl.Contains($_) })
    if ($missingControl.Count -gt 0) {
        throw "RegistryExecutionControlMissing: the applicable registry does not contain '$($missingControl -join "', '")'."
    }

    $unknownControl = @($Registry | ForEach-Object { [string]$_.ControlId } | Where-Object { -not $expectedControl.Contains($_) })
    if ($unknownControl.Count -gt 0) {
        throw "RegistryExecutionControlUnknown: the applicable registry contains '$($unknownControl -join "', '")', which was not expected."
    }

    $executionPlan = foreach ($entry in $Registry) {
        $collectorName = [string]$entry.Collector
        $evaluatorName = [string]$entry.Evaluator
        if ([string]::IsNullOrWhiteSpace($collectorName)) {
            throw "RegistryExecutionCollectorUnresolved: '$($entry.ControlId)' names no collector."
        }
        if ([string]::IsNullOrWhiteSpace($evaluatorName)) {
            throw "RegistryExecutionEvaluatorUnresolved: '$($entry.ControlId)' names no evaluator."
        }

        $collectorCommand = @(@(& $CommandResolver $collectorName) | Where-Object { $null -ne $_ })
        if ($collectorCommand.Count -ne 1) {
            throw "RegistryExecutionCollectorUnresolved: '$($entry.ControlId)' collector '$collectorName' resolved to $($collectorCommand.Count) commands."
        }

        $evaluatorCommand = @(@(& $CommandResolver $evaluatorName) | Where-Object { $null -ne $_ })
        if ($evaluatorCommand.Count -ne 1) {
            throw "RegistryExecutionEvaluatorUnresolved: '$($entry.ControlId)' evaluator '$evaluatorName' resolved to $($evaluatorCommand.Count) commands."
        }

        [pscustomobject]@{
            Entry = $entry
            CollectorCommand = $collectorCommand[0]
            EvaluatorCommand = $evaluatorCommand[0]
        }
    }

    foreach ($execution in $executionPlan) {
        $collectorArgument = & $CollectorArgumentResolver $execution.Entry
        if ($null -eq $collectorArgument) { $collectorArgument = @{} }
        if ($collectorArgument -isnot [System.Collections.IDictionary]) {
            throw "RegistryExecutionCollectorArgumentsInvalid: '$($execution.Entry.ControlId)' collector arguments must be a dictionary."
        }
        $evidence = & $execution.CollectorCommand @collectorArgument

        $evaluatorArgument = & $EvaluatorArgumentResolver $execution.Entry $evidence
        if ($null -eq $evaluatorArgument) { $evaluatorArgument = @{} }
        if ($evaluatorArgument -isnot [System.Collections.IDictionary]) {
            throw "RegistryExecutionEvaluatorArgumentsInvalid: '$($execution.Entry.ControlId)' evaluator arguments must be a dictionary."
        }
        $result = & $execution.EvaluatorCommand @evaluatorArgument

        $record = [pscustomobject]@{
            Entry = $execution.Entry
            Result = $result
        }
        $record | Add-Member -NotePropertyName Evidence -NotePropertyValue $evidence
        $record
    }
}

function Invoke-CompleteControlRegistryOrchestration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$CatalogControlId,

        [Parameter(Mandatory)]
        [object[]]$Registry,

        [Parameter(Mandatory)]
        [ValidateSet('Native', 'Gateway')]
        [string]$SelectedProfile,

        [scriptblock]$CommandResolver = {
            param($Name)
            @(Get-Command -Name $Name -CommandType Function, Cmdlet -ErrorAction SilentlyContinue)
        },

        [scriptblock]$CollectorArgumentResolver = { param($Entry) @{} },

        [scriptblock]$EvaluatorArgumentResolver = {
            param($Entry, $Evidence)
            $argument = @{}
            $argument['Evidence'] = $Evidence
            $argument
        }
    )

    $applicableRegistry = @($Registry | Where-Object { $SelectedProfile -cin @($_.ApplicableProfile) })
    $applicableControlId = @($applicableRegistry | ForEach-Object { [string]$_.ControlId })
    $execution = @(Invoke-BaselineControlRegistryExecution -Registry $applicableRegistry `
            -ExpectedControlId $applicableControlId -CommandResolver $CommandResolver `
            -CollectorArgumentResolver $CollectorArgumentResolver `
            -EvaluatorArgumentResolver $EvaluatorArgumentResolver)

    $projection = foreach ($record in $execution) {
        $evaluatedProjection = [pscustomobject]@{
            ControlId = [string]$record.Entry.ControlId
            Kind = 'Evaluated'
            Collector = [string]$record.Entry.Collector
            Evaluator = [string]$record.Entry.Evaluator
            Result = $record.Result
        }
        $evaluatedProjection | Add-Member -NotePropertyName Evidence -NotePropertyValue $record.Evidence
        $evaluatedProjection
    }

    foreach ($excluded in @(Get-BaselineProfileExclusion -Registry $Registry -SelectedProfile $SelectedProfile)) {
        $entry = @($Registry | Where-Object ControlId -CEQ $excluded.ControlId)[0]
        $excludedEvidence = [pscustomobject]@{
            ControlId = [string]$excluded.ControlId
            Collected = $false
            Reason = [string]$excluded.Reason
        }
        $excludedProjection = [pscustomobject]@{
            ControlId = [string]$excluded.ControlId
            Kind = 'NotApplicable'
            Collector = [string]$entry.Collector
            Evaluator = [string]$entry.Evaluator
            Result = [pscustomobject]@{
                ControlId = [string]$excluded.ControlId
                Status = 'NotApplicable'
                Reason = [string]$excluded.Reason
            }
        }
        $excludedProjection | Add-Member -NotePropertyName Evidence -NotePropertyValue $excludedEvidence
        $projection += $excludedProjection
    }

    Resolve-CompleteControlRegistryOrchestration -CatalogControlId $CatalogControlId `
        -Registry $Registry -Projection @($projection)
}

Add-Result 'EXO-001 acceptedDomainAuthoritative' ($evidence.acceptedDomain.DomainType -eq 'Authoritative')
Add-Result 'EXO-002 smtpAuthDisabled' ([bool]$evidence.transport.SmtpClientAuthenticationDisabled)
Add-Check  'EXO-003 legacyAuthBlocked' 'Manual' 'Verify the Conditional Access legacy authentication block in Microsoft Entra'
$mailboxPageVariable = Get-Variable -Name outboundForwardingMailboxPageCollection -ErrorAction SilentlyContinue
$mailboxPageCollection = if ($null -ne $mailboxPageVariable) {
    [scriptblock]$mailboxPageVariable.Value
}
else {
    {
        param($ContinuationToken)
        if ($null -ne $ContinuationToken) {
            throw "MailboxContinuationUnsupported: Get-Mailbox returned an unexpected continuation token '$ContinuationToken'."
        }
        [pscustomobject]@{
            Mailbox = @(Get-Mailbox -ResultSize Unlimited | Select-Object Identity, PrimarySmtpAddress, ForwardingAddress, ForwardingSmtpAddress)
            ContinuationToken = $null
        }
    }
}
$inboxRuleVariable = Get-Variable -Name outboundForwardingInboxRuleCollection -ErrorAction SilentlyContinue
$inboxRuleCollection = if ($null -ne $inboxRuleVariable) {
    [scriptblock]$inboxRuleVariable.Value
}
else {
    {
        param($Mailbox, $TimeoutSecond)
        try {
            $rule = @(Get-InboxRule -Mailbox $Mailbox.Identity -IncludeHidden -ErrorAction Stop |
                    Select-Object Identity, Enabled, ForwardTo, ForwardAsAttachmentTo, RedirectTo, SendTextMessageNotificationTo)
            [pscustomobject]@{ Status = 'Success'; Complete = $true; Rules = $rule }
        }
        catch {
            $reason = $_.Exception.Message
            if ($reason -match '(?i)throttl|server busy|too many requests') {
                return [pscustomobject]@{ Status = 'Throttled'; Complete = $false; Rules = @(); RetryAfterSecond = 1; Reason = $reason }
            }
            if ($reason -match '(?i)timeout|timed out|expired') {
                return [pscustomobject]@{ Status = 'TimedOut'; Complete = $false; Rules = @(); Reason = $reason }
            }
            if ($reason -match '(?i)access denied|inaccessible|not authorized|permission') {
                return [pscustomobject]@{ Status = 'Inaccessible'; Complete = $false; Rules = @(); Reason = $reason }
            }
            if ($reason -match '(?i)ambiguous|multiple recipients') {
                return [pscustomobject]@{ Status = 'Ambiguous'; Complete = $false; Rules = @(); Reason = $reason }
            }
            throw
        }
    }
}
$inboxRuleWaitVariable = Get-Variable -Name outboundForwardingWait -ErrorAction SilentlyContinue
$inboxRuleWait = if ($null -ne $inboxRuleWaitVariable) { [scriptblock]$inboxRuleWaitVariable.Value } else { { param($Second) Start-Sleep -Seconds $Second } }
$inboxRuleClockVariable = Get-Variable -Name outboundForwardingClock -ErrorAction SilentlyContinue
$inboxRuleClock = if ($null -ne $inboxRuleClockVariable) { [scriptblock]$inboxRuleClockVariable.Value } else { { [datetimeoffset]::UtcNow } }

$outboundForwardingEvidence = Get-OutboundForwardingEvidence `
    -OutboundSpamPolicyCollection { $evidence.outboundSpam } `
    -MailboxCollection {
        $completeMailbox = Get-BaselineCompleteMailboxCollection -PageCollection $mailboxPageCollection
        @($completeMailbox.Mailbox)
    } `
    -InboxRuleCollection {
        param([object[]]$Mailbox)
        Get-BaselineMailboxInboxRuleCollection -Mailbox $Mailbox -Collection $inboxRuleCollection `
            -Wait $inboxRuleWait -Clock $inboxRuleClock
    }
$outboundForwardingResult = Test-OutboundForwardingControl -Evidence $outboundForwardingEvidence `
    -AcceptedDomain @($evidence.acceptedDomain.DomainName)
Add-Check 'EXO-004 automaticForwardingOff' $outboundForwardingResult.Status $outboundForwardingResult.Reason
Add-Result 'EXO-005 externalPostmasterSet' ([bool]$evidence.transport.ExternalPostmasterAddress)
Add-Result 'EXO-006 mailboxAuditingOn' (-not [bool]$evidence.organization.AuditDisabled)
Add-Result 'EXO-007 externalSenderTagging' ([bool]($evidence.externalInOutlook | Where-Object { $_.Enabled }))
$remoteDomainEvidence = Get-RemoteDomainEvidence -Collection { $evidence.remoteDomain }
$remoteDomainResult = Test-RemoteDomainControl -Evidence $remoteDomainEvidence `
    -DesiredState $configuration.desiredState.exchangeOnline.remoteDomainDefault
Add-Check 'EXO-008 remoteDomainHardened' $remoteDomainResult.Status $remoteDomainResult.Reason
$clientProtocolEvidence = Get-ClientProtocolEvidence -OrganizationConfigCollection { $evidence.organization } `
    -CasMailboxPlanCollection { $evidence.casMailboxPlans } -CasMailboxCollection { $evidence.casMailboxes }
$clientProtocolResult = Test-ClientProtocolControl -Evidence $clientProtocolEvidence `
    -DesiredState $configuration.desiredState.exchangeOnline.protocolRestriction
Add-Check 'EXO-009 legacyProtocolsRestricted' $clientProtocolResult.Status $clientProtocolResult.Reason
$rbacPimFallback = $null
if (-not [string]::IsNullOrWhiteSpace($RbacPimFallbackPath)) {
    if (-not (Test-Path -LiteralPath $RbacPimFallbackPath -PathType Leaf)) {
        throw "RbacPimFallbackNotFound: no RBAC/PIM fallback evidence exists at '$RbacPimFallbackPath'."
    }
    if ($MaximumRbacPimFallbackAge -le [timespan]::Zero) {
        throw 'RbacPimFallbackMaximumAgeInvalid: -MaximumRbacPimFallbackAge must be greater than zero.'
    }

    $fallbackDocument = Get-Content -LiteralPath $RbacPimFallbackPath -Raw | ConvertFrom-Json -Depth 100
    $fallbackCmsVariable = Get-Variable -Name rbacPimFallbackCmsVerificationScript -ErrorAction SilentlyContinue
    $fallbackCmsVerification = if ($null -ne $fallbackCmsVariable) {
        [scriptblock]$fallbackCmsVariable.Value
    }
    else {
        {
            param([byte[]]$ContentBytes, [byte[]]$SignatureBytes)
            $content = [System.Security.Cryptography.Pkcs.ContentInfo]::new($ContentBytes)
            $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
            $cms.Decode($SignatureBytes)
            $cms.CheckSignature($true)
            $certificate = @($cms.SignerInfos)[0].Certificate
            $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Offline
            $chainTrusted = $chain.Build($certificate)
            [pscustomobject]@{
                SignatureValid = $true
                ContentMatched = $true
                SignerSubject = $certificate.Subject
                CertificateNotBeforeUtc = $certificate.NotBefore.ToUniversalTime()
                CertificateNotAfterUtc = $certificate.NotAfter.ToUniversalTime()
                ChainTrusted = $chainTrusted
                RevocationStatus = if ($chainTrusted) { 'Good' } else { 'Unknown' }
            }
        }
    }

    $resolvedConfigurationHash = ([string]$context.Hash) -replace '(?i)^sha256:', ''
    $rbacPimFallback = Import-BaselineRbacPimFallback -Evidence @($fallbackDocument) `
        -TenantId ([string]$configuration.administratorInputs.tenantId) `
        -DeploymentProfile ([string]$configuration.deploymentProfile) `
        -ConfigurationHash $resolvedConfigurationHash `
        -Registry (Get-BaselineControlRegistry -Profile Historical) `
        -MaximumAge $MaximumRbacPimFallbackAge `
        -AsOf ([datetimeoffset]::UtcNow) `
        -CmsVerificationScript $fallbackCmsVerification `
        -AuthorizedSigner $RbacPimFallbackAuthorizedSigner `
        -DeclaredSignerIdentity $RbacPimFallbackSignerIdentity
}

$roleAssignmentEvidence = Get-ExchangeRoleAssignmentEvidence `
    -RoleGroupCollection { Get-RoleGroup -ResultSize Unlimited } `
    -ManagementRoleAssignmentCollection { Get-ManagementRoleAssignment -ResultSize Unlimited } `
    -ActivePimAssignmentCollection {
        if ($null -eq $graphRequest) { throw 'LivePimCollectionUnavailable: no authenticated Graph request seam is available.' }
        @((& $graphRequest 'roleManagement/directory/roleAssignmentScheduleInstances').value)
    } `
    -EligiblePimAssignmentCollection {
        if ($null -eq $graphRequest) { throw 'LivePimCollectionUnavailable: no authenticated Graph request seam is available.' }
        @((& $graphRequest 'roleManagement/directory/roleEligibilityScheduleInstances').value)
    } `
    -AccessReviewCollection {
        if ($null -eq $graphRequest) { throw 'LivePimCollectionUnavailable: no authenticated Graph request seam is available.' }
        @((& $graphRequest 'identityGovernance/accessReviews/definitions').value)
    } `
    -FallbackEvidence $rbacPimFallback

$roleAssignmentResult = Test-ExchangeRoleAssignmentControl `
    -Evidence $roleAssignmentEvidence `
    -FallbackEvidence $rbacPimFallback `
    -PrivilegedRoleGroup @($configuration.desiredState.exchangeOnline.roleBasedAccessControl.approvedRoleGroups) `
    -ApprovedMember @() `
    -GovernedRole @('29232cdf-9323-42fd-ade2-1d097af3e4de') `
    -MaximumReviewAgeDay ([int]$configuration.desiredState.exchangeOnline.roleBasedAccessControl.roleGroupReviewFrequencyDays)
Add-Check 'EXO-010 rbacHygiene' $roleAssignmentResult.Status $roleAssignmentResult.Reason
Add-Check  'EXO-011 mtaStsAndTlsRpt' 'Manual' "Resolve _mta-sts.$domain and _smtp._tls.$domain and confirm the policy endpoint returns mode=enforce"

Add-Result 'MDO-001 standardPresetEnabled' (
    $evidence.standardEop.State -eq 'Enabled' -and
    (-not $mdoLicensed -or $evidence.standardAtp.State -eq 'Enabled')
)
Add-Result 'MDO-002 strictPresetEnabled' (
    $evidence.strictEop.State -eq 'Enabled' -and
    (-not $mdoLicensed -or $evidence.strictAtp.State -eq 'Enabled')
)

if ($mdoLicensed) {
    Add-Result 'MDO-003 builtInProtectionUnexcluded' (
        $evidence.builtInProtection.State -eq 'Enabled' -and
        -not $evidence.builtInProtection.ExceptIfRecipientDomainIs -and
        -not $evidence.builtInProtection.ExceptIfSentToMemberOf
    )
    Add-Result 'MDO-004 filesProtectionEnabled' ([bool]$evidence.atpGlobal.EnableATPForSPOTeamsODB)
    if ($safeDocsLicensed) {
        Add-Result 'MDO-005 safeDocumentsNoBypass' (
            [bool]$evidence.atpGlobal.EnableSafeDocs -and -not [bool]$evidence.atpGlobal.AllowSafeDocsOpen
        )
    }
    else {
        Add-Check 'MDO-005 safeDocumentsNoBypass' 'NotEntitled' $entitlementReason['SafeDocuments']
    }
}
else {
    foreach ($control in 'MDO-003 builtInProtectionUnexcluded', 'MDO-004 filesProtectionEnabled', 'MDO-005 safeDocumentsNoBypass') {
        Add-Check $control 'NotEntitled' $entitlementReason['AtpPresets']
    }
}

Add-Check  'MDO-006 userSubmissions' 'Manual' 'Confirm the user submission policy and the SecOps copy in the Defender portal'
$tenantAllowBlockListEvidence = Get-TenantAllowBlockListEvidence -Collection { Get-TenantAllowBlockListItems }
$tenantAllowBlockListResult = Test-TenantAllowBlockListControl -Evidence $tenantAllowBlockListEvidence `
    -DesiredState $configuration.desiredState.defenderForOffice365.tenantAllowBlockList
Add-Check 'MDO-007 tenantAllowBlockList' $tenantAllowBlockListResult.Status $tenantAllowBlockListResult.Reason
Add-Result 'MDO-008 quarantineNotificationCadence' ([bool]$evidence.quarantineGlobal.EndUserSpamNotificationFrequency)

# Email authentication orchestration: all three controls use their registered collectors and evaluators. The named variables
# are injection seams for offline runs; a normal connected run supplies the same observations from
# Exchange Online and authoritative DNS. DMARC report trust remains owned by EVD-008.
$sendingDomainCollectionVariable = Get-Variable -Name emailAuthenticationSendingDomainCollection -ErrorAction SilentlyContinue
$sendingDomainCollection = if ($null -ne $sendingDomainCollectionVariable) {
    [scriptblock]$sendingDomainCollectionVariable.Value
}
else {
    { @(Get-AcceptedDomain -ResultSize Unlimited | Where-Object DomainType -eq 'Authoritative' | ForEach-Object DomainName) }
}
$sendingDomain = @(& $sendingDomainCollection | ForEach-Object { ([string]$_).Trim().TrimEnd('.').ToLowerInvariant() } | Sort-Object -Unique)

$dkimCollectionVariable = Get-Variable -Name emailAuthenticationDkimCollection -ErrorAction SilentlyContinue
$dkimCollection = if ($null -ne $dkimCollectionVariable) { [scriptblock]$dkimCollectionVariable.Value } else { { param($Name) Get-DkimSigningConfig -Identity $Name } }
$dkimDnsVariable = Get-Variable -Name emailAuthenticationDkimDnsCollection -ErrorAction SilentlyContinue
$dkimDnsCollection = if ($null -ne $dkimDnsVariable) { [scriptblock]$dkimDnsVariable.Value } else { { param($Name) Resolve-DnsName -Name $Name -Type CNAME } }
$spfDnsVariable = Get-Variable -Name emailAuthenticationSpfDnsCollection -ErrorAction SilentlyContinue
$spfDnsCollection = if ($null -ne $spfDnsVariable) { [scriptblock]$spfDnsVariable.Value } else { { param($Domain) Resolve-DnsName -Name $Domain -Type TXT } }
$dmarcDnsVariable = Get-Variable -Name emailAuthenticationDmarcDnsCollection -ErrorAction SilentlyContinue
$dmarcDnsCollection = if ($null -ne $dmarcDnsVariable) { [scriptblock]$dmarcDnsVariable.Value } else { { param($Name) Resolve-DnsName -Name "_dmarc.$Name" -Type TXT } }
$dmarcReportVariable = Get-Variable -Name dmarcReportImportDecision -ErrorAction SilentlyContinue
$dmarcReportDecision = if ($null -ne $dmarcReportVariable) {
    $dmarcReportVariable.Value
}
else {
    [pscustomobject]@{
        Satisfied = $false
        Admitted = @()
        Refused = @([pscustomobject]@{
                ControlId = 'AUTH-003'
                Reason = @('DmarcReportEvidenceNotSupplied: no signed EVD-008 DMARC report decision was supplied to this run.')
            })
    }
}

$dkimEvidence = Get-DkimEvidence -SendingDomain $sendingDomain `
    -DkimSigningConfigCollection $dkimCollection -SelectorDnsCollection $dkimDnsCollection
$dkimResult = Test-DkimControl -Evidence $dkimEvidence -DesiredState $configuration.desiredState.emailAuthentication.dkim
Add-Check 'AUTH-001 evaluated' $dkimResult.Status $dkimResult.Reason

$spfEvidence = Get-SpfEvidence -SendingDomain $sendingDomain -TxtRecordCollection $spfDnsCollection
$spfResult = Test-SpfControl -Evidence $spfEvidence
Add-Check 'AUTH-002 evaluated' $spfResult.Status $spfResult.Reason

$dmarcEvidence = Get-DmarcEvidence -SendingDomain $sendingDomain `
    -DmarcRecordCollection $dmarcDnsCollection -ReportImportDecision $dmarcReportDecision
$dmarcResult = Test-DmarcControl -Evidence $dmarcEvidence `
    -DesiredState $configuration.desiredState.emailAuthentication.dmarc -SendingDomain $sendingDomain
Add-Check 'AUTH-003 evaluated' $dmarcResult.Status $dmarcResult.Reason

$selectedRegistryProfile = if ($gatewayDeclared) { 'Gateway' } else { 'Native' }
$ppRegistry = @(@(Get-BaselineControlRegistry -Profile Historical)[0] | Where-Object ControlId -Like 'PP-*')
foreach ($excludedControl in @(Get-BaselineProfileExclusion -Registry $ppRegistry -SelectedProfile $selectedRegistryProfile)) {
    Add-Check "$($excludedControl.ControlId) profileExcluded" $excludedControl.Status $excludedControl.Reason
}

$ppResult = @()
if ($gatewayDeclared) {
    $gatewayInboundEvidence = Get-GatewayInboundConnectorEvidence -InboundConnectorCollection { $evidence.inboundConnector }
    $enhancedFilteringEvidence = Get-EnhancedFilteringEvidence -InboundConnectorCollection { $evidence.inboundConnector }
    $gatewayOutboundEvidence = Get-GatewayOutboundConnectorEvidence -Collection { $evidence.outboundConnector }
    $trustedArcEvidence = Get-TrustedArcSealerEvidence -ArcConfigCollection { $evidence.arcConfig }
    $ppResult += Test-GatewayInboundConnectorControl -Evidence $gatewayInboundEvidence -DesiredState $configuration.desiredState.mailFlow.gatewayInboundConnector -ConnectorIdentity $inboundName
    $ppResult += Test-EnhancedFilteringControl -Evidence $enhancedFilteringEvidence -DesiredState $configuration.desiredState.mailFlow.enhancedFiltering -ConnectorIdentity $inboundName
    $ppResult += Test-GatewayOutboundConnectorControl -Evidence $gatewayOutboundEvidence -DesiredState $configuration.desiredState.mailFlow.gatewayOutboundConnector
    $ppResult += Test-TrustedArcSealerControl -Evidence $trustedArcEvidence -DesiredState @($configuration.desiredState.emailAuthentication.trustedArcSealers)
}
else {
    $partnerEvidence = Get-PartnerInboundConnectorEvidence -InboundConnectorCollection { $evidence.partnerInboundConnectors }
    $ppResult += Test-PartnerInboundConnectorControl -Evidence $partnerEvidence
}
foreach ($result in $ppResult) {
    Add-Check "$($result.ControlId) evaluated" $result.Status $result.Reason
}

# ABN post-delivery orchestration: Gateway consumes only admitted EVD-008 decisions through the
# registered collectors and evaluators. Native has no vendor integration and is excluded by profile.
$abnormalIntegrationDecisionVariable = Get-Variable -Name abnormalIntegrationImportDecision -ErrorAction SilentlyContinue
$abnormalIntegrationDecision = $null
if ($null -ne $abnormalIntegrationDecisionVariable) {
    $abnormalIntegrationDecision = $abnormalIntegrationDecisionVariable.Value
}
if ($null -eq $abnormalIntegrationDecisionVariable) {
    $abnormalIntegrationDecision = [pscustomobject]@{
        Satisfied = $false
        Admitted = @()
        Refused = @([pscustomobject]@{ Reason = 'OfflineArtifactUnavailable: no admitted signed ABN-001 evidence was supplied.' })
    }
}
$abnormalPermissionDecisionVariable = Get-Variable -Name abnormalPermissionImportDecision -ErrorAction SilentlyContinue
$abnormalPermissionDecision = $null
if ($null -ne $abnormalPermissionDecisionVariable) {
    $abnormalPermissionDecision = $abnormalPermissionDecisionVariable.Value
}
if ($null -eq $abnormalPermissionDecisionVariable) {
    $abnormalPermissionDecision = [pscustomobject]@{
        Satisfied = $false
        Admitted = @()
        Refused = @([pscustomobject]@{ Reason = 'OfflineArtifactUnavailable: no admitted signed ABN-002 evidence was supplied.' })
    }
}
$abnormalIntegrationEvidence = $null
$abnormalPermissionEvidence = $null

if ($gatewayDeclared) {
    $abnormalIntegrationEvidence = Get-AbnormalIntegrationEvidence -AbnormalIntegrationImportDecision $abnormalIntegrationDecision
    $abnormalIntegrationResult = Test-AbnormalIntegrationControl -Evidence $abnormalIntegrationEvidence -DesiredState $configuration.desiredState.abnormalSecurity.integration
    Add-Check 'ABN-001 evaluated' $abnormalIntegrationResult.Status $abnormalIntegrationResult.Reason

    $abnormalPermissionEvidence = Get-AbnormalPermissionEvidence -AbnormalPermissionImportDecision $abnormalPermissionDecision
    $abnormalPermissionResult = Test-AbnormalPermissionControl -Evidence $abnormalPermissionEvidence -DesiredState $configuration.desiredState.abnormalSecurity.permissions
    Add-Check 'ABN-002 evaluated' $abnormalPermissionResult.Status $abnormalPermissionResult.Reason
}
else {
    Add-Check 'ABN-001 gatewayOnly' 'NotApplicable' 'Microsoft-native profile: Abnormal post-delivery integration is not declared.'
    Add-Check 'ABN-002 gatewayOnly' 'NotApplicable' 'Microsoft-native profile: Abnormal application permissions are not declared.'
}
$abnormalEvidenceById = @{
    'ABN-001' = $abnormalIntegrationEvidence
    'ABN-002' = $abnormalPermissionEvidence
}
# End ABN post-delivery orchestration

Add-Result 'BAD-001 noSclMinusOneBypassRules' ($evidence.bypassRules.Count -eq 0)

# MON/OPS orchestration: all operational artifacts enter through injected offline seams. A missing
# artifact is a named collection refusal, never an inline or Manual verdict.
$monitoringOperationsSeam = @{}
foreach ($name in @(
        'monitoringTelemetryCollection', 'monitoringUnifiedAuditCollection', 'monitoringDriftEvidenceCollection',
        'operationsChangeArtifactCollection', 'operationsIncidentExerciseImportDecision'
    )) {
    $variable = Get-Variable -Name $name -ErrorAction SilentlyContinue
    if ($null -ne $variable) { $monitoringOperationsSeam[$name] = $variable.Value }
}
$missingArtifact = { throw 'OfflineArtifactUnavailable: no sanitized synthetic artifact was supplied for this control.' }
$incidentImportDecision = if ($monitoringOperationsSeam.ContainsKey('operationsIncidentExerciseImportDecision')) {
    $monitoringOperationsSeam.operationsIncidentExerciseImportDecision
}
else {
    [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ Reason = 'OfflineArtifactUnavailable: no admitted signed OPS-002 evidence was supplied.' }) }
}
$incidentEntitlement = [pscustomobject]@{
    RequiredServicePlanName = $configuration.desiredState.operations.incidentExercise.requiredServicePlan
    Status = if ($mdoLicensed) { 'Pass' } else { 'NotEntitled' }
    Reason = if ($mdoLicensed) { 'The target is entitled to MDO P2.' } else { $entitlementReason['MdoP2'] }
}

$telemetrySourceEvidence = Get-TelemetrySourceEvidence -TelemetryCollection $(if ($monitoringOperationsSeam.ContainsKey('monitoringTelemetryCollection')) { [scriptblock]$monitoringOperationsSeam.monitoringTelemetryCollection } else { $missingArtifact })
$telemetrySourceResult = Test-TelemetrySourceControl -Evidence $telemetrySourceEvidence -DesiredState $configuration.desiredState.centralMonitoring.siemIntegration
Add-Check 'MON-001 evaluated' $telemetrySourceResult.Status $telemetrySourceResult.Reason

$unifiedAuditEvidence = Get-UnifiedAuditEvidence -AuditCollection $(if ($monitoringOperationsSeam.ContainsKey('monitoringUnifiedAuditCollection')) { [scriptblock]$monitoringOperationsSeam.monitoringUnifiedAuditCollection } else { $missingArtifact })
$unifiedAuditResult = Test-UnifiedAuditControl -Evidence $unifiedAuditEvidence -DesiredState $configuration.desiredState.centralMonitoring.unifiedAudit
Add-Check 'MON-002 evaluated' $unifiedAuditResult.Status $unifiedAuditResult.Reason

$driftEvidenceEvidence = Get-DriftEvidenceEvidence -DriftEvidenceCollection $(if ($monitoringOperationsSeam.ContainsKey('monitoringDriftEvidenceCollection')) { [scriptblock]$monitoringOperationsSeam.monitoringDriftEvidenceCollection } else { $missingArtifact })
$driftEvidenceResult = Test-DriftEvidenceControl -Evidence $driftEvidenceEvidence -DesiredState $configuration.desiredState.centralMonitoring.driftEvidence
Add-Check 'MON-003 evaluated' $driftEvidenceResult.Status $driftEvidenceResult.Reason

$changeSafetyEvidence = Get-ChangeSafetyEvidence -ChangeArtifactCollection $(if ($monitoringOperationsSeam.ContainsKey('operationsChangeArtifactCollection')) { [scriptblock]$monitoringOperationsSeam.operationsChangeArtifactCollection } else { $missingArtifact })
$changeSafetyResult = Test-ChangeSafetyControl -Evidence $changeSafetyEvidence -DesiredState $configuration.desiredState.operations.changeSafety
Add-Check 'OPS-001 evaluated' $changeSafetyResult.Status $changeSafetyResult.Reason

$incidentExerciseEvidence = Get-IncidentExerciseEvidence -IncidentExerciseImportDecision $incidentImportDecision
$incidentExerciseResult = Test-IncidentExerciseControl -Evidence $incidentExerciseEvidence -DesiredState $configuration.desiredState.operations.incidentExercise -EntitlementVerdict $incidentEntitlement
Add-Check 'OPS-002 evaluated' $incidentExerciseResult.Status $incidentExerciseResult.Reason
$monitoringOperationsEvidenceById = @{
    'MON-001' = $telemetrySourceEvidence
    'MON-002' = $unifiedAuditEvidence
    'MON-003' = $driftEvidenceEvidence
    'OPS-001' = $changeSafetyEvidence
    'OPS-002' = $incidentExerciseEvidence
}
# End MON/OPS orchestration

# Purview governance orchestration: injected seams keep the complete GOV phase offline-testable,
# while connected runs call the authoritative Purview, Exchange Online and review sources.
$governanceEntitlement = {
    param([string]$RequiredServicePlanName, [bool]$Entitled, [string]$Reason)
    [pscustomobject]@{
        RequiredServicePlanName = $RequiredServicePlanName
        Status = if ($Entitled) { 'Pass' } else { 'NotEntitled' }
        Reason = $Reason
    }
}
$govAuditEntitlement = & $governanceEntitlement $configuration.desiredState.governance.auditRetention.requiredServicePlan $auditPremiumLicensed $entitlementReason['AuditPremium']
$govPurviewEntitlement = & $governanceEntitlement $configuration.desiredState.governance.dataLossPrevention.requiredServicePlan $purviewLicensed $entitlementReason['PurviewRetention']
$govExchangeEntitlement = & $governanceEntitlement $configuration.desiredState.purviewGovernance.mailboxRetention.requiredServicePlan $purviewLicensed $entitlementReason['PurviewRetention']
$govLabelsEntitlement = & $governanceEntitlement $configuration.desiredState.governance.sensitivityLabels.requiredServicePlan $purviewLicensed $entitlementReason['PurviewRetention']
$govEDiscoveryEntitlement = & $governanceEntitlement $configuration.desiredState.governance.eDiscovery.requiredServicePlan $purviewLicensed $entitlementReason['PurviewRetention']

$govSeam = @{}
foreach ($name in @(
        'governanceAuditRetentionCollection', 'governanceDlpPolicyCollection', 'governanceDlpRuleCollection',
        'governanceMailboxCollection', 'governanceRetentionPolicyCollection', 'governanceRetentionDistributionCollection',
        'governancePriorityIdentityCollection', 'governanceCustodianCollection', 'governanceIrmConfigurationCollection',
        'governanceOmeFunctionalEvidenceCollection', 'governanceSensitivityLabelCollection', 'governanceLabelPolicyCollection',
        'governanceComplianceCaseCollection', 'governanceRoleGroupMemberCollection', 'governanceAccessReviewCollection'
    )) {
    $variable = Get-Variable -Name $name -ErrorAction SilentlyContinue
    if ($null -ne $variable) { $govSeam[$name] = [scriptblock]$variable.Value }
}

$auditRetentionEvidence = Get-AuditRetentionEvidence -RetentionPolicyCollection $(if ($govSeam.ContainsKey('governanceAuditRetentionCollection')) { $govSeam.governanceAuditRetentionCollection } else { { Get-UnifiedAuditLogRetentionPolicy } })
$auditRetentionResult = Test-AuditRetentionControl -Evidence $auditRetentionEvidence -DesiredState $configuration.desiredState.governance.auditRetention -EntitlementVerdict $govAuditEntitlement
Add-Check 'GOV-001 evaluated' $auditRetentionResult.Status $auditRetentionResult.Reason

$dataLossPreventionEvidence = Get-DataLossPreventionEvidence `
    -PolicyCollection $(if ($govSeam.ContainsKey('governanceDlpPolicyCollection')) { $govSeam.governanceDlpPolicyCollection } else { { Get-DlpCompliancePolicy } }) `
    -RuleCollection $(if ($govSeam.ContainsKey('governanceDlpRuleCollection')) { $govSeam.governanceDlpRuleCollection } else { { Get-DlpComplianceRule } })
$dataLossPreventionResult = Test-DataLossPreventionControl -Evidence $dataLossPreventionEvidence -DesiredState $configuration.desiredState.governance.dataLossPrevention -EntitlementVerdict $govPurviewEntitlement
Add-Check 'GOV-002 evaluated' $dataLossPreventionResult.Status $dataLossPreventionResult.Reason

$mailboxCollection = if ($govSeam.ContainsKey('governanceMailboxCollection')) { $govSeam.governanceMailboxCollection } else { { [pscustomobject]@{ Complete = $true; Mailboxes = @(Get-EXOMailbox -ResultSize Unlimited) } } }
$mailboxRetentionEvidence = Get-MailboxRetentionEvidence -MailboxCollection $mailboxCollection `
    -RetentionPolicyCollection $(if ($govSeam.ContainsKey('governanceRetentionPolicyCollection')) { $govSeam.governanceRetentionPolicyCollection } else { { Get-RetentionPolicy } }) `
    -DistributionCollection $(if ($govSeam.ContainsKey('governanceRetentionDistributionCollection')) { $govSeam.governanceRetentionDistributionCollection } else { { Get-RetentionCompliancePolicy -Identity $configuration.desiredState.purviewGovernance.mailboxRetention.policyName } })
$mailboxRetentionResult = Test-MailboxRetentionControl -Evidence $mailboxRetentionEvidence -DesiredState $configuration.desiredState.purviewGovernance.mailboxRetention -EntitlementVerdict $govExchangeEntitlement
Add-Check 'GOV-003 evaluated' $mailboxRetentionResult.Status $mailboxRetentionResult.Reason

$litigationHoldDesired = [ordered]@{
    requiredServicePlan = $configuration.desiredState.purviewGovernance.litigationHold.requiredServicePlan
    enabled = $configuration.desiredState.purviewGovernance.litigationHold.enabled
    priorityIdentities = @($configuration.desiredState.purviewGovernance.litigationHold.priorityIdentitySources)
    custodians = @($configuration.desiredState.purviewGovernance.litigationHold.custodians)
}
$litigationHoldEvidence = Get-LitigationHoldEvidence -MailboxCollection $mailboxCollection `
    -PriorityIdentityCollection $(if ($govSeam.ContainsKey('governancePriorityIdentityCollection')) { $govSeam.governancePriorityIdentityCollection } else { { [pscustomobject]@{ Resolved = $true; Identities = @($litigationHoldDesired.priorityIdentities); Unresolved = @() } }.GetNewClosure() }) `
    -CustodianCollection $(if ($govSeam.ContainsKey('governanceCustodianCollection')) { $govSeam.governanceCustodianCollection } else { { [pscustomobject]@{ Resolved = $true; Identities = @($litigationHoldDesired.custodians); Unresolved = @() } }.GetNewClosure() })
$litigationHoldResult = Test-LitigationHoldControl -Evidence $litigationHoldEvidence -DesiredState $litigationHoldDesired -EntitlementVerdict $govExchangeEntitlement
Add-Check 'GOV-004 evaluated' $litigationHoldResult.Status $litigationHoldResult.Reason

$informationRightsManagementEvidence = Get-InformationRightsManagementEvidence `
    -IrmConfigurationCollection $(if ($govSeam.ContainsKey('governanceIrmConfigurationCollection')) { $govSeam.governanceIrmConfigurationCollection } else { { Get-IRMConfiguration } }) `
    -OmeFunctionalEvidenceCollection $(if ($govSeam.ContainsKey('governanceOmeFunctionalEvidenceCollection')) { $govSeam.governanceOmeFunctionalEvidenceCollection } else { { Test-IRMConfiguration } })
$informationRightsManagementResult = Test-InformationRightsManagementControl -Evidence $informationRightsManagementEvidence -DesiredState $configuration.desiredState.purviewGovernance.informationRightsManagement -EntitlementVerdict $govExchangeEntitlement
Add-Check 'GOV-005 evaluated' $informationRightsManagementResult.Status $informationRightsManagementResult.Reason

$sensitivityLabelEvidence = Get-SensitivityLabelEvidence `
    -SensitivityLabelCollection $(if ($govSeam.ContainsKey('governanceSensitivityLabelCollection')) { $govSeam.governanceSensitivityLabelCollection } else { { Get-Label } }) `
    -LabelPolicyCollection $(if ($govSeam.ContainsKey('governanceLabelPolicyCollection')) { $govSeam.governanceLabelPolicyCollection } else { { Get-LabelPolicy } })
$sensitivityLabelResult = Test-SensitivityLabelControl -Evidence $sensitivityLabelEvidence -DesiredState $configuration.desiredState.governance.sensitivityLabels -EntitlementVerdict $govLabelsEntitlement
Add-Check 'GOV-006 evaluated' $sensitivityLabelResult.Status $sensitivityLabelResult.Reason

$eDiscoveryReadinessEvidence = Get-EDiscoveryReadinessEvidence `
    -ComplianceCaseCollection $(if ($govSeam.ContainsKey('governanceComplianceCaseCollection')) { $govSeam.governanceComplianceCaseCollection } else { { Get-ComplianceCase } }) `
    -RoleGroupMemberCollection $(if ($govSeam.ContainsKey('governanceRoleGroupMemberCollection')) { $govSeam.governanceRoleGroupMemberCollection } else { { Get-RoleGroupMember -Identity $configuration.desiredState.governance.eDiscovery.roleGroupIdentity } }) `
    -AccessReviewCollection $(if ($govSeam.ContainsKey('governanceAccessReviewCollection')) { $govSeam.governanceAccessReviewCollection } else { { if ($null -eq $graphRequest) { throw 'AccessReviewCollectionUnavailable: no authenticated Graph request seam is available.' }; @((& $graphRequest 'identityGovernance/accessReviews/definitions').value) } })
$eDiscoveryReadinessResult = Test-EDiscoveryReadinessControl -Evidence $eDiscoveryReadinessEvidence -DesiredState $configuration.desiredState.governance.eDiscovery -EntitlementVerdict $govEDiscoveryEntitlement
Add-Check 'GOV-007 evaluated' $eDiscoveryReadinessResult.Status $eDiscoveryReadinessResult.Reason
$governanceEvidenceById = @{
    'GOV-001' = $auditRetentionEvidence
    'GOV-002' = $dataLossPreventionEvidence
    'GOV-003' = $mailboxRetentionEvidence
    'GOV-004' = $litigationHoldEvidence
    'GOV-005' = $informationRightsManagementEvidence
    'GOV-006' = $sensitivityLabelEvidence
    'GOV-007' = $eDiscoveryReadinessEvidence
}
# End Purview governance orchestration

$summary = [ordered]@{}
$checks.Values | Group-Object { $_.status } | ForEach-Object { $summary[$_.Name] = $_.Count }

# EVD-004: which control each raw observation belongs to, and the command that actually produced
# it. The envelope carries evidence records rather than a blob, so every observation has to name a
# control; a control this run does not observe is recorded as an uncollected record rather than
# left out, because a missing member reads exactly like a control that was checked and found clean.
$observation = [ordered]@{
    'EXO-001'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-AcceptedDomain'; Key = @('acceptedDomain') }
    'EXO-002'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-TransportConfig'; Key = @('transport') }
    'EXO-004'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-HostedOutboundSpamFilterPolicy'; Key = @('outboundSpam') }
    'EXO-005'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-TransportConfig'; Key = @('transport') }
    'EXO-006'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-OrganizationConfig'; Key = @('organization') }
    'EXO-007'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-ExternalInOutlook'; Key = @('externalInOutlook') }
    'EXO-008'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-RemoteDomain'; Key = @('remoteDomain') }
    'EXO-009'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-OrganizationConfig; Get-CASMailboxPlan; Get-CASMailbox'; Key = @('organization', 'casMailboxPlans', 'casMailboxes') }
    'EXO-010'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-RoleGroup'; Key = @('roleGroups') }
    'MDO-001'  = [ordered]@{ Source = 'Defender'; Command = 'Get-EOPProtectionPolicyRule'; Key = @('standardEop', 'standardAtp') }
    'MDO-002'  = [ordered]@{ Source = 'Defender'; Command = 'Get-EOPProtectionPolicyRule'; Key = @('strictEop', 'strictAtp') }
    'MDO-003'  = [ordered]@{ Source = 'Defender'; Command = 'Get-ATPBuiltInProtectionRule'; Key = @('builtInProtection') }
    'MDO-004'  = [ordered]@{ Source = 'Defender'; Command = 'Get-AtpPolicyForO365'; Key = @('atpGlobal') }
    'MDO-005'  = [ordered]@{ Source = 'Defender'; Command = 'Get-AtpPolicyForO365'; Key = @('atpGlobal') }
    'MDO-008'  = [ordered]@{ Source = 'Defender'; Command = 'Get-QuarantinePolicy'; Key = @('quarantineGlobal', 'quarantinePolicies') }
    'AUTH-001' = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-DkimSigningConfig'; Key = @('dkim') }
    'PP-001'   = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-InboundConnector'; Key = @('inboundConnector') }
    'PP-002'   = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-InboundConnector'; Key = @('inboundConnector') }
    'PP-003'   = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-OutboundConnector'; Key = @('outboundConnector') }
    'PP-004'   = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-ArcConfig'; Key = @('arcConfig') }
    'PP-005'   = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-InboundConnector'; Key = @('partnerInboundConnectors') }
    'ABN-001'  = [ordered]@{ Source = 'ExternalEvidence'; Command = 'Import-BaselineExternalEvidence'; Key = @('abnormalIntegrationEvidence') }
    'ABN-002'  = [ordered]@{ Source = 'ExternalEvidence'; Command = 'Import-BaselineExternalEvidence'; Key = @('abnormalPermissionEvidence') }
    'GOV-001'  = [ordered]@{ Source = 'Purview'; Command = 'Get-UnifiedAuditLogRetentionPolicy'; Key = @('auditRetentionEvidence') }
    'GOV-002'  = [ordered]@{ Source = 'Purview'; Command = 'Get-DlpCompliancePolicy; Get-DlpComplianceRule'; Key = @('dataLossPreventionEvidence') }
    'GOV-003'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-EXOMailbox; Get-RetentionPolicy; Get-RetentionCompliancePolicy'; Key = @('mailboxRetentionEvidence') }
    'GOV-004'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-EXOMailbox; Resolve-PriorityIdentity; Resolve-Custodian'; Key = @('litigationHoldEvidence') }
    'GOV-005'  = [ordered]@{ Source = 'ExchangeOnline+FunctionalEvidence'; Command = 'Get-IRMConfiguration; Test-IRMConfiguration; OME encrypted-message round trip'; Key = @('informationRightsManagementEvidence') }
    'GOV-006'  = [ordered]@{ Source = 'Purview'; Command = 'Get-Label;Get-LabelPolicy'; Key = @('sensitivityLabelEvidence') }
    'GOV-007'  = [ordered]@{ Source = 'Purview'; Command = 'Get-ComplianceCase;Get-RoleGroupMember;Get-AccessReview'; Key = @('eDiscoveryReadinessEvidence') }
    'MON-001'  = [ordered]@{ Source = 'SignedSiemExport'; Command = 'Import signed SIEM telemetry collection'; Key = @('telemetrySourceEvidence') }
    'MON-002'  = [ordered]@{ Source = 'SignedPurviewAuditExport'; Command = 'Import signed Purview unified-audit collection'; Key = @('unifiedAuditEvidence') }
    'MON-003'  = [ordered]@{ Source = 'MonitoringEvidence'; Command = 'Get-ScheduledDriftEvidence'; Key = @('driftEvidenceEvidence') }
    'OPS-001'  = [ordered]@{ Source = 'ChangeArtifacts'; Command = 'Get-ChangeSafetyArtifactSet'; Key = @('changeSafetyEvidence') }
    'OPS-002'  = [ordered]@{ Source = 'ExternalEvidence'; Command = 'Import-BaselineExternalEvidence'; Key = @('incidentExerciseEvidence') }
    'BAD-001'  = [ordered]@{ Source = 'ExchangeOnline'; Command = 'Get-TransportRule'; Key = @('bypassRules') }
}

$observed = foreach ($id in @($observation.Keys)) {
    $declaration = $observation[$id]
    if (($id -like 'MON-*' -or $id -like 'OPS-*') -and $monitoringOperationsEvidenceById.ContainsKey($id)) {
        $monitoringOperationsEvidenceById[$id]
        continue
    }
    if ($id -like 'GOV-*' -and $governanceEvidenceById.ContainsKey($id)) {
        $governanceEvidenceById[$id]
        continue
    }
    if ($gatewayDeclared -and $id -like 'ABN-*' -and $abnormalEvidenceById.ContainsKey($id)) {
        $abnormalEvidenceById[$id]
        continue
    }
    $absent = @(@($declaration.Key) | Where-Object { -not $evidence.Contains($_) })
    if ($absent.Count -gt 0) {
        New-BaselineEvidence -ControlId $id -Source $declaration.Source -Command $declaration.Command -Value $null `
            -Failed -FailureReason "CollectionNotRun: '$($absent -join "', '")' was not collected in this run."
        continue
    }

    $payload = [ordered]@{}
    foreach ($name in @($declaration.Key)) { $payload[$name] = $evidence[$name] }
    New-BaselineEvidence -ControlId $id -Source $declaration.Source -Command $declaration.Command -Value $payload
}

# The registry is returned as one collection, so it is enumerated through a variable: iterating the
# command itself binds the whole registry to `$control` and the run faults before it decides anything.
$registry = Get-BaselineControlRegistry -Profile Historical

$uncollected = foreach ($control in $registry) {
    if ($observation.Contains($control.ControlId)) { continue }
    New-BaselineEvidence -ControlId $control.ControlId -Source $control.EvidencePath.Split('.')[0] -Command $control.Collector -Value $null `
        -Failed -FailureReason "CollectorNotRun: '$($control.Collector)' observes '$($control.ControlId)' and did not run."
}

# The check names carry the control they decide, so the verdicts reach the envelope through the
# result contract instead of as free-form text nothing downstream can reason about.
$verdict = foreach ($check in $checks.GetEnumerator()) {
    $decided = ($check.Key -split '\s+', 2)[0]
    $reason = $check.Value.detail
    if ($check.Value.status -cne 'Pass' -and [string]::IsNullOrWhiteSpace($reason)) {
        $reason = "$($check.Key) did not pass."
    }

    New-ControlResult -ControlId $decided -Status $check.Value.status -Reason $reason
}

$envelope = New-BaselineEvidenceEnvelope -Context $context `
    -TenantId $configuration.administratorInputs.tenantId `
    -OrganizationName $configuration.administratorInputs.organizationName `
    -ParameterPath $ParameterPath `
    -Evidence (@($observed) + @($uncollected)) `
    -Check @($verdict)

$resultPath = Join-Path $OutputPath "exchange-online-evidence-$timestamp.json"
$envelope | ConvertTo-Json -Depth 20 | Set-Content -Path $resultPath -Encoding utf8

$checks.GetEnumerator() | ForEach-Object {
    $colour = switch ($_.Value.status) {
        'Pass'          { 'Green' }
        'Fail'          { 'Red' }
        'NotEntitled'   { 'Yellow' }
        'NotApplicable' { 'DarkGray' }
        default         { 'Cyan' }
    }
    Write-Host ("[{0,-13}] {1} {2}" -f $_.Value.status, $_.Key, $_.Value.detail) -ForegroundColor $colour
}

Write-Host ''
$summary.GetEnumerator() | ForEach-Object { Write-Host "$($_.Key): $($_.Value)" }
Write-Host "Evidence written to $resultPath"

$failed = @($checks.Values | Where-Object { $_.status -eq 'Fail' })
Write-Host "Failed: $($failed.Count)"

# GATE-006 INPUT MATERIALIZATION START
$goLiveInput = $null
if ($GoLive) {
    if ([string]::IsNullOrWhiteSpace($RiskAcceptancePath) -or -not (Test-Path -LiteralPath $RiskAcceptancePath)) {
        throw "GoLiveRiskAcceptanceNotFound: no risk acceptance exists at '$RiskAcceptancePath'."
    }
    if (-not (Test-Path -LiteralPath $RiskAcceptancePath -PathType Leaf)) {
        throw "GoLiveRiskAcceptanceUnreadable: '$RiskAcceptancePath' is not a readable file."
    }

    try {
        $riskAcceptanceText = Get-Content -LiteralPath $RiskAcceptancePath -Raw -ErrorAction Stop
    }
    catch {
        throw "GoLiveRiskAcceptanceUnreadable: '$RiskAcceptancePath' could not be read. $($_.Exception.Message)"
    }

    try {
        $riskAcceptance = @(ConvertFrom-Json -InputObject $riskAcceptanceText -Depth 20 -ErrorAction Stop)
    }
    catch {
        throw "GoLiveRiskAcceptanceMalformed: '$RiskAcceptancePath' is not valid JSON. $($_.Exception.Message)"
    }

    if ($riskAcceptance.Count -eq 0) {
        throw "GoLiveRiskAcceptanceSchemaInvalid: '$RiskAcceptancePath' contains no risk acceptance document."
    }

    $detachedSignature = $riskAcceptance[0].Signature
    if ($null -eq $detachedSignature -or [string]::IsNullOrWhiteSpace([string]$detachedSignature.Value)) {
        throw 'GoLiveEvidenceUnsigned: the go-live evidence carries no detached CMS signature.'
    }

    if (-not (Get-Variable -Name riskAcceptanceSchemaPath -ErrorAction SilentlyContinue)) {
        $riskAcceptanceSchemaPath = Join-Path $PSScriptRoot '..\config\risk-acceptance.schema.json'
    }
    foreach ($document in $riskAcceptance) {
        $schemaResult = Test-RiskAcceptanceDocument -RiskAcceptance $document -SchemaPath $riskAcceptanceSchemaPath
        if (-not $schemaResult.Conforms) {
            throw "GoLiveRiskAcceptanceSchemaInvalid: '$RiskAcceptancePath' violates the published schema. $(@($schemaResult.Violation) -join ' ')"
        }
    }

    if ([string]::IsNullOrWhiteSpace($ExpectedConfigurationHash)) {
        throw 'GoLiveExpectedConfigurationHashRequired: -ExpectedConfigurationHash is required for -GoLive.'
    }
    $resolvedHash = ([string]$context.Hash) -replace '(?i)^sha256:', ''
    $expectedHash = $ExpectedConfigurationHash -replace '(?i)^sha256:', ''
    if ($resolvedHash -cne $expectedHash) {
        throw "GoLiveExpectedConfigurationHashMismatch: the command expected '$expectedHash', but the resolved configuration is '$resolvedHash'."
    }

    if ($MaximumEvidenceAge -le [timespan]::Zero) {
        throw 'GoLiveMaximumEvidenceAgeNotPositive: -MaximumEvidenceAge must be greater than zero.'
    }

    $targetEntitlement = $context.Entitlement
    if ($null -eq $targetEntitlement -or $targetEntitlement.Determined -isnot [bool] -or -not $targetEntitlement.Determined) {
        throw 'GoLiveTargetEntitlementUnresolved: the target entitlement was not conclusively resolved.'
    }

    $canonicalEvidence = $envelope | ConvertTo-Json -Depth 100 -Compress
    $canonicalBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($canonicalEvidence)
    $verificationVariable = Get-Variable -Name goLiveCmsVerificationScript -ErrorAction SilentlyContinue
    if ($null -ne $verificationVariable) {
        $cmsVerificationScript = [scriptblock]$verificationVariable.Value
    }
    else {
        $cmsVerificationScript = {
            param([byte[]]$ContentBytes, [byte[]]$SignatureBytes)

            $content = [System.Security.Cryptography.Pkcs.ContentInfo]::new($ContentBytes)
            $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
            $cms.Decode($SignatureBytes)
            $cms.CheckSignature($true)
            $signer = @($cms.SignerInfos)[0]
            $certificate = $signer.Certificate
            $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Offline
            $chainTrusted = $chain.Build($certificate)

            [pscustomobject]@{
                SignatureValid          = $true
                ContentMatched          = $true
                SignerSubject           = $certificate.Subject
                CertificateNotBeforeUtc = $certificate.NotBefore.ToUniversalTime()
                CertificateNotAfterUtc  = $certificate.NotAfter.ToUniversalTime()
                ChainTrusted            = $chainTrusted
                RevocationStatus        = if ($chainTrusted) { 'Good' } else { 'Unknown' }
            }
        }
    }

    $signatureVerification = Test-BaselineDetachedCmsSignature -CanonicalBytes $canonicalBytes `
        -Signature $detachedSignature -VerificationScript $cmsVerificationScript
    if (-not $signatureVerification.Verified) {
        if ($signatureVerification.Reason -eq 'ExternalEvidenceWrongContent') {
            throw 'GoLiveEvidenceTampered: the detached CMS signature is bound to different evidence bytes.'
        }
        throw "GoLiveEvidenceUnverified: detached CMS verification failed. $($signatureVerification.Reason)"
    }
    if (-not $signatureVerification.ChainTrusted -or $signatureVerification.RevocationStatus -cne 'Good') {
        throw 'GoLiveEvidenceUnverified: detached CMS verification did not establish an offline trusted, non-revoked signer chain.'
    }

    $contentHash = Get-BaselineEvidenceContentHash -Envelope $envelope
    $catalogVariable = Get-Variable -Name goLiveCatalogPath -ErrorAction SilentlyContinue
    $catalogPath = if ($null -ne $catalogVariable) {
        [string]$catalogVariable.Value
    }
    else {
        Join-Path $PSScriptRoot '..\docs\CONTROL-CATALOG.md'
    }
    $goLiveSignature = [pscustomobject]@{
        Model        = 'DetachedCms'
        Value        = [string]$detachedSignature.Value
        ContentHash  = [string]$contentHash.Hash
        Verified     = $true
        Verification = $signatureVerification
    }
    $goLiveInput = [ordered]@{
        Envelope                      = $envelope
        CatalogPath                   = $catalogPath
        ExpectedTenantId              = [string]$configuration.administratorInputs.tenantId
        ExpectedDeploymentProfile     = [string]$context.DeploymentProfile
        ExpectedConfigurationHash     = $expectedHash
        MaximumEvidenceAge            = $MaximumEvidenceAge
        RequestedBy                   = [string]$configuration.metadata.configurationOwner
        RiskAcceptance                = @($riskAcceptance)
        Signature                     = $goLiveSignature
        TargetEntitlement             = $targetEntitlement
    }
}
# GATE-006 INPUT MATERIALIZATION END

$goLiveDecision = $null
if ($GoLive) {
    $goLiveDecision = Test-BaselineGoLive @goLiveInput
}

# GATE-004: the run's exit is resolved by the seam and nowhere else. The previous `exit 1` fired on
# `Fail` alone, so a control nobody could decide - a `Manual`, a `NotEntitled`, an `Error` - left
# this command reporting success, which is a gate that passes every tenant it never looked at.
$outcome = Get-BaselineRunOutcome -Check @($verdict) -GoLive $goLiveDecision
Write-Host ("Outcome: {0} ({1}) {2}" -f $outcome.Outcome, $outcome.ExitCode, $outcome.Reason)

exit $outcome.ExitCode