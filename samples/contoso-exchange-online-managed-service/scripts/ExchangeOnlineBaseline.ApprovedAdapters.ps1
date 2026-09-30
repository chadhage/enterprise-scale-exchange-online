function ConvertTo-ApprovedAdapterValue {
    param($Value, [string]$Type, [string]$Field)
    if ($null -eq $Value) {
        if ($Type -like 'Nullable*') { return $null }
        if ($Type -eq 'Strings') { return ,@() }
        throw "ChangeReadIncomplete: $Field cannot be null."
    }
    switch ($Type) {
        Boolean { if ($Value -isnot [bool]) { throw "ChangeReadIncomplete: $Field must be Boolean." }; return $Value }
        NullableBoolean { if ($Value -isnot [bool]) { throw "ChangeReadIncomplete: $Field must be Boolean or null." }; return $Value }
        Integer { if ($Value -isnot [int] -and $Value -isnot [long]) { throw "ChangeReadIncomplete: $Field must be integer." }; return [long]$Value }
        Strings {
            $result = @($Value | ForEach-Object {
                if ($_ -isnot [string] -and $_.GetType().IsPrimitive) { throw "ChangeReadIncomplete: $Field must contain strings." }
                [string]$_
            } | Sort-Object -Unique)
            return ,$result
        }
        Duration { try { return ([timespan]$Value).ToString('c') } catch { throw "ChangeReadIncomplete: $Field must be a TimeSpan." } }
        DateTime { try { return ([datetimeoffset]$Value).ToUniversalTime().ToString('o') } catch { throw "ChangeReadIncomplete: $Field must be an instant." } }
        default {
            if ($Value -is [bool] -or $Value -is [ValueType] -and $Value -isnot [enum]) { throw "ChangeReadIncomplete: $Field must be text." }
            return [string]$Value
        }
    }
}

function New-ApprovedAdapterDefinition {
    param([string]$Adapter, [string]$Noun, [hashtable]$Target, [hashtable]$Desired, [hashtable]$Types,
        [switch]$Create, [switch]$Delete, [switch]$Toggle, [hashtable]$CreateTarget = @{})
    @{ Adapter = $Adapter; Get = "Get-$Noun"; Set = "Set-$Noun"; New = $(if ($Create -or $Delete) { "New-$Noun" }); Remove = $(if ($Create -or $Delete) { "Remove-$Noun" }); Target = $Target; CreateTarget = $CreateTarget; Desired = $Desired; Types = $Types; Delete = [bool]$Delete; Toggle = [bool]$Toggle; Noun = $Noun }
}

function Assert-ApprovedAdapterScope {
    param([AllowEmptyCollection()][string[]]$Scope = @())
    $supported = @(
        'SharingPolicyBinding','ConnectorTrust','ApplicationAssignmentScope','OrganizationAllowList','MailboxSafeSender','OrganizationRelationship',
        'FullAccess','SendAs','SendOnBehalf','TransportBypass','GovernanceMailboxPolicy','GovernanceMrm',
        'GovernanceEncryption','Organization','Transport','ExternalSender','OutboundSpam','RemoteDomains',
        'MailboxProtocols','MailboxPlans','AcceptedDomains','ReportSubmission','SecOpsOverride',
        'Impersonation','EopPresets','AtpPresets','BuiltInProtection','Quarantine','Dkim',
        'Forwarding','AddInAcquisition','TenantAllowBlockList'
    )
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($Scope.Count -eq 0) { throw 'ChangeScopeUnsupported: select at least one approved adapter scope.' }
    foreach ($area in $Scope) {
        if ([string]::IsNullOrWhiteSpace($area) -or -not $seen.Add($area) -or $area -cnotin $supported) {
            throw "ChangeScopeUnsupported: '$area' is empty, duplicate, or unsupported."
        }
    }
}

function Resolve-BaselineEwsPolicy {
    param($DesiredState, [datetimeoffset]$Now = [datetimeoffset]::UtcNow)
    if ($DesiredState.ewsEnabled -isnot [bool]) { throw 'EwsEnabledInvalid: ewsEnabled must be Boolean.' }
    if ([string]$DesiredState.ewsApplicationAccessPolicy -cne 'EnforceAllowList') { throw 'EwsEnforcementRequired: EnforceAllowList is required.' }
    $allowList = @($DesiredState.ewsAllowList)
    if ($DesiredState.ewsEnabled -and
        ($allowList.Count -eq 0 -or @($allowList | Where-Object { [string]::IsNullOrWhiteSpace($_) -or $_ -eq '*' }).Count -or
            @($allowList | Select-Object -Unique).Count -ne $allowList.Count)) {
        throw 'EwsAllowListInvalid: a narrow unique user-agent allow list is required.'
    }
    $result = @{
        EwsEnabled = [bool]$DesiredState.ewsEnabled
        EwsApplicationAccessPolicy = [string]$DesiredState.ewsApplicationAccessPolicy
        EwsAllowList = $allowList
    }
    $applicationIds = @($DesiredState.ewsAllowedAppIds)
    if ($DesiredState.ewsEnabled) {
        if ($applicationIds.Count -eq 0 -or @($applicationIds | Where-Object { $_ -notmatch '^[0-9a-fA-F-]{36}$' }).Count) {
            throw 'EwsApplicationIdentityRequired: application IDs are required.'
        }
        $result.EwsAllowedAppIDs = $applicationIds -join ','
    }
    $result
}

function Resolve-BaselineRemoteDomainOofType {
    param($DesiredState)
    $type = [string]$DesiredState.allowedOOFType
    if ($type -cnotin @('None','InternalLegacy','External','ExternalLegacy')) { throw 'RemoteDomainOofTypeInvalid: an explicit supported OOF type is required.' }
    if ($type -ceq 'External' -and [string]::IsNullOrWhiteSpace([string]$DesiredState.externalOofApproval)) {
        throw 'RemoteDomainExternalApprovalRequired: External OOF requires approval.'
    }
    $type
}

function Assert-ExchangeGovernanceApproval {
    param($Approval, [datetimeoffset]$Now = [datetimeoffset]::UtcNow)
    if ($Approval -isnot [System.Collections.IDictionary] -or
        [string]::IsNullOrWhiteSpace([string]$Approval.reference) -or
        [string]::IsNullOrWhiteSpace([string]$Approval.owner)) {
        throw 'ChangeApprovalRequired: an owner and approval reference are required.'
    }
    $expiresOn = [datetimeoffset]::MinValue
    if (-not [datetimeoffset]::TryParse([string]$Approval.expiresOn, [ref]$expiresOn) -or $expiresOn -le $Now) {
        throw 'ChangeApprovalExpired: approval must have a future expiry.'
    }
}

function Get-ApprovedAdapterCollection {
    param([string]$Command, [hashtable]$Arguments = @{}, [string[]]$Required = @('Identity'), [string[]]$NullableRequired = @())
    $rows = @(& $Command @Arguments -ErrorAction Stop)
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $rows) {
        foreach ($field in $Required) {
            if (-not (Test-BaselineNodeMember $row $field) -or ($field -notin $NullableRequired -and [string]::IsNullOrWhiteSpace([string]$row.$field))) { throw "ChangeReadIncomplete: $Command omitted $field." }
        }
        if ($Required.Count -gt 0 -and -not $seen.Add([string]$row.($Required[0]))) { throw "ChangeReadIncomplete: $Command returned duplicate identities." }
    }
    return ,$rows
}

function Get-ApprovedAdapterDefinitions {
    param($Context, [string[]]$Scope, $Approved, [switch]$DesiredOnly)
    Assert-ApprovedAdapterScope -Scope $Scope
    $controls = $Context.Configuration.controls
    $parameters = $Context.Parameters
    $options = $parameters['workflowOptions']
    if ($null -eq $options) { $options = @{} }
    foreach ($key in $options.Keys) { if ($key -cnotin @('enableDkim','tenantAllowBlockEntries','outboundSpam','transportSclExceptions','externalSubjectPrefixRules','fullAccessDelegations','sendAsDelegations','sendOnBehalfDelegations','organizationAllowList','mailboxSafeSenders','organizationRelationships','applicationAssignmentScope','connectorTrust','sharingPolicyBinding')) { throw "ChangeOptionsInvalid: unsupported option $key." } }
    if ($options.ContainsKey('enableDkim') -and $options.enableDkim -isnot [bool]) { throw 'ChangeOptionsInvalid: enableDkim must be Boolean.' }
    $fixed = {
        param($Adapter, $Noun, $Target, $Desired, $Types, [bool]$Create = $false, $CreateTarget = @{})
        New-ApprovedAdapterDefinition $Adapter $Noun $Target $Desired $Types -Create:$Create -CreateTarget $CreateTarget
    }
    $targets = {
        param($Adapter, $Command, $Arguments = @{}, $Required = @('Identity'))
        if ($null -ne $Approved -and -not $DesiredOnly) {
            foreach ($operation in @($Approved | Where-Object { $_.OperationId -clike "$Adapter-*" })) {
                $target = ConvertFrom-Json -InputObject $operation.Identity -AsHashtable
                if (-not $target.ContainsKey('Identity') -or [string]::IsNullOrWhiteSpace([string]$target.Identity)) { throw 'ChangeOperationMismatch: target Identity is required.' }
                $target
            }
        } else {
            foreach ($row in (Get-ApprovedAdapterCollection $Command $Arguments $Required)) { @{ Identity = [string]$row.Identity } }
        }
    }
    foreach ($area in $Scope) {
        switch -CaseSensitive ($area) {
            SharingPolicyBinding {
                $settings = $options['sharingPolicyBinding']
                if ($settings -isnot [System.Collections.IDictionary]) {
                    throw 'SharingPolicyBindingOptionsRequired: an explicit sharing policy and mailbox binding declaration is required.'
                }
                if ([string](Get-BaselineRecordMember $settings partnerReadiness) -cne 'Unverified') {
                    throw 'SharingPolicyPartnerReadinessInvalid: external partner readiness must remain Unverified.'
                }
                $approval = Get-BaselineRecordMember $settings disclosureApproval
                $expiresOn = [datetimeoffset]::MinValue
                if ($approval -isnot [System.Collections.IDictionary] -or
                    (Get-BaselineRecordMember $approval Complete) -isnot [bool] -or -not (Get-BaselineRecordMember $approval Complete) -or
                    (Get-BaselineRecordMember $approval IndependentlyApproved) -isnot [bool] -or -not (Get-BaselineRecordMember $approval IndependentlyApproved) -or
                    [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $approval Reference)) -or
                    [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $approval Owner)) -or
                    -not [datetimeoffset]::TryParse([string](Get-BaselineRecordMember $approval ExpiresOn), [ref]$expiresOn) -or
                    $expiresOn -le [datetimeoffset]::UtcNow) {
                    throw 'SharingPolicyDisclosureApprovalMissing: complete current independent disclosure approval is required.'
                }

                $policies = @((Get-BaselineRecordMember $settings policies) | Where-Object { $null -ne $_ })
                if ($policies.Count -eq 0) { throw 'SharingPolicyCoverageRequired: at least one approved sharing policy is required.' }
                $policyNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($policy in $policies) {
                    $identity = ([string](Get-BaselineRecordMember $policy identity)).Trim()
                    $domains = @((Get-BaselineRecordMember $policy domains) | ForEach-Object { ([string]$_).Trim() })
                    if ([string]::IsNullOrWhiteSpace($identity) -or -not $policyNames.Add($identity) -or
                        $domains.Count -eq 0 -or @($domains | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -or
                        (Get-BaselineRecordMember $policy enabled) -isnot [bool] -or
                        (Get-BaselineRecordMember $policy isDefault) -isnot [bool]) {
                        throw 'SharingPolicyCoverageInvalid: policy identities, domains and typed state must be complete and unique.'
                    }
                }
                if ($DesiredOnly) {
                    foreach ($operation in @($Approved | Where-Object { $_.OperationId -clike 'SharingPolicyBindingDisplacedDefault-*' })) {
                        $target = ConvertFrom-Json -InputObject $operation.Identity -AsHashtable
                        $approvedIdentity = ([string](Get-BaselineRecordMember $target Identity)).Trim()
                        $before = ConvertTo-BaselineHashableNode (Get-BaselineRecordMember (Get-BaselineRecordMember $operation Before) Value)
                        if ([string]::IsNullOrWhiteSpace($approvedIdentity) -or
                            $before -isnot [System.Collections.IDictionary]) {
                            throw 'ChangeOperationMismatch: displaced sharing default lacks its approved identity and before-state.'
                        }
                        New-ApprovedAdapterDefinition -Adapter SharingPolicyBindingDisplacedDefault -Noun SharingPolicy `
                            -Target @{ Identity = $approvedIdentity } `
                            -Desired @{ Domains = @((Get-BaselineRecordMember $before Domains)); Enabled = [bool](Get-BaselineRecordMember $before Enabled); Default = $false } `
                            -Types @{ Domains = 'Strings'; Enabled = 'Boolean'; Default = 'Boolean' }
                    }
                } else {
                    $existingPolicies = Get-ApprovedAdapterCollection -Command Get-SharingPolicy -Arguments @{ ResultSize = 'Unlimited' } -Required @('Identity','Domains','Enabled','IsDefault')
                    foreach ($existing in @($existingPolicies | Where-Object { $_.IsDefault -and -not $policyNames.Contains([string]$_.Identity) })) {
                        New-ApprovedAdapterDefinition -Adapter SharingPolicyBindingDisplacedDefault -Noun SharingPolicy `
                            -Target @{ Identity = [string]$existing.Identity } `
                            -Desired @{ Domains = @($existing.Domains); Enabled = [bool]$existing.Enabled; Default = $false } `
                            -Types @{ Domains = 'Strings'; Enabled = 'Boolean'; Default = 'Boolean' }
                    }
                }
                foreach ($policy in $policies) {
                    $identity = ([string](Get-BaselineRecordMember $policy identity)).Trim()
                    $domains = @((Get-BaselineRecordMember $policy domains) | ForEach-Object { ([string]$_).Trim() })
                    New-ApprovedAdapterDefinition -Adapter SharingPolicyBindingPolicy -Noun SharingPolicy `
                        -Target @{ Identity = $identity } `
                        -Desired @{ Domains = $domains; Enabled = [bool](Get-BaselineRecordMember $policy enabled); Default = [bool](Get-BaselineRecordMember $policy isDefault) } `
                        -Types @{ Domains = 'Strings'; Enabled = 'Boolean'; Default = 'Boolean' }
                }

                $defaultPolicy = ([string](Get-BaselineRecordMember $settings defaultMailboxPolicy)).Trim()
                if ([string]::IsNullOrWhiteSpace($defaultPolicy) -or -not $policyNames.Contains($defaultPolicy) -or
                    @($policies | Where-Object { [string](Get-BaselineRecordMember $_ identity) -ieq $defaultPolicy -and (Get-BaselineRecordMember $_ isDefault) -eq $true }).Count -ne 1) {
                    throw 'SharingPolicyDefaultMailboxBindingMissing: the default mailbox policy must identify one approved default policy.'
                }
                $mailboxes = @((Get-BaselineRecordMember $settings explicitMailboxBindings) | Where-Object { $null -ne $_ })
                $mailboxNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($mailbox in $mailboxes) {
                    $identity = ([string](Get-BaselineRecordMember $mailbox identity)).Trim()
                    $sharingPolicy = ([string](Get-BaselineRecordMember $mailbox sharingPolicy)).Trim()
                    if ([string]::IsNullOrWhiteSpace($identity) -or -not $mailboxNames.Add($identity) -or
                        [string]::IsNullOrWhiteSpace($sharingPolicy) -or -not $policyNames.Contains($sharingPolicy)) {
                        throw 'SharingPolicyExplicitMailboxBindingUnresolved: every explicit mailbox must uniquely identify an approved policy.'
                    }
                    New-ApprovedAdapterDefinition -Adapter SharingPolicyBindingMailbox -Noun Mailbox `
                        -Target @{ Identity = $identity } -Desired @{ SharingPolicy = $sharingPolicy } -Types @{ SharingPolicy = 'String' }
                }
            }
            ConnectorTrust {
                $settings = $options['connectorTrust']
                if ($settings -isnot [System.Collections.IDictionary]) {
                    throw 'ConnectorTrustCoverageRequired: an explicit connector trust declaration is required.'
                }
                if ((Get-BaselineRecordMember $settings provisionExternalInfrastructure) -eq $true) {
                    throw 'ConnectorTrustExternalProvisioningForbidden: Exchange lifecycle authority stops at the Exchange boundary.'
                }

                $declarationByDirection = @{}
                foreach ($direction in @('Inbound','Outbound')) {
                    $name = $direction.ToLowerInvariant()
                    $declarations = @((Get-BaselineRecordMember $settings $name) | Where-Object { $null -ne $_ })
                    if ($declarations.Count -eq 0) {
                        throw "ConnectorTrust${direction}CoverageRequired: explicit $direction connector coverage is required."
                    }
                    foreach ($declaration in $declarations) {
                        $identity = ([string](Get-BaselineRecordMember $declaration identity)).Trim()
                        if ([string]::IsNullOrWhiteSpace($identity)) { throw "ConnectorTrust${direction}CoverageRequired: every declaration requires an identity." }
                        if ((Get-BaselineRecordMember $declaration declared) -isnot [bool] -or -not (Get-BaselineRecordMember $declaration declared)) {
                            throw "ConnectorTrustUndeclared: $direction connector '$identity' is not explicitly declared."
                        }
                        $scope = @((Get-BaselineRecordMember $declaration routingScope) | ForEach-Object { ([string]$_).Trim() })
                        if ($scope.Count -eq 0 -or @($scope | Where-Object { $_ -eq '*' }).Count) {
                            throw "ConnectorTrustRoutingScopeTooBroad: $direction connector '$identity' carries routing scope '$($scope -join ',')'."
                        }
                        $authentication = Get-BaselineRecordMember $declaration authentication
                        if ($authentication -isnot [System.Collections.IDictionary] -or
                            (Get-BaselineRecordMember $authentication required) -isnot [bool] -or
                            -not (Get-BaselineRecordMember $authentication required) -or
                            (Get-BaselineRecordMember $authentication verified) -isnot [bool] -or
                            -not (Get-BaselineRecordMember $authentication verified) -or
                            [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $authentication evidence))) {
                            throw "ConnectorTrustAuthenticationRequired: $direction connector '$identity' requires verified authentication evidence."
                        }
                        if ([string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $declaration owner))) {
                            throw "ConnectorTrustOwnerRequired: $direction connector '$identity' requires an accountable owner."
                        }
                        if ([string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $declaration approval))) {
                            throw "ConnectorTrustApprovalRequired: $direction connector '$identity' requires independent approval evidence."
                        }
                        $expiresOn = [datetimeoffset]::MinValue
                        if (-not [datetimeoffset]::TryParse([string](Get-BaselineRecordMember $declaration expiresOn), [ref]$expiresOn) -or
                            $expiresOn -le [datetimeoffset]::UtcNow) {
                            throw "ConnectorTrustApprovalExpired: $direction connector '$identity' approval is expired or invalid."
                        }
                    }
                    $declarationByDirection[$direction] = $declarations
                }

                foreach ($handoff in @((Get-BaselineRecordMember $settings externalRoutingHandoffs) | Where-Object { $null -ne $_ })) {
                    $name = [string](Get-BaselineRecordMember $handoff name)
                    if ((Get-BaselineRecordMember $handoff reconciled) -isnot [bool] -or
                        -not (Get-BaselineRecordMember $handoff reconciled) -or
                        [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $handoff owner)) -or
                        [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $handoff evidence))) {
                        throw "ConnectorTrustExternalHandoffUnreconciled: '$name' requires independently reconciled external routing evidence."
                    }
                }

                $desired = Get-BaselineRecordMember $settings desired
                if ($desired -isnot [System.Collections.IDictionary]) { throw 'ConnectorTrustCoverageRequired: desired connector state is required.' }
                $contracts = @(
                    @{
                        Direction = 'Inbound'; Noun = 'InboundConnector'
                        Fields = @('Enabled','SenderDomains','SenderIPAddresses','TlsSenderCertificateName','RestrictDomainsToCertificate','RestrictDomainsToIPAddresses','RequireTls')
                        Types = @{ Enabled = 'Boolean'; SenderDomains = 'Strings'; SenderIPAddresses = 'Strings'; TlsSenderCertificateName = 'String'; RestrictDomainsToCertificate = 'Boolean'; RestrictDomainsToIPAddresses = 'Boolean'; RequireTls = 'Boolean' }
                    },
                    @{
                        Direction = 'Outbound'; Noun = 'OutboundConnector'
                        Fields = @('Enabled','RecipientDomains','SmartHosts','TlsSettings','TlsDomain','RouteAllMessagesViaOnPremises','UseMxRecord')
                        Types = @{ Enabled = 'Boolean'; RecipientDomains = 'Strings'; SmartHosts = 'Strings'; TlsSettings = 'String'; TlsDomain = 'String'; RouteAllMessagesViaOnPremises = 'Boolean'; UseMxRecord = 'Boolean' }
                    }
                )
                foreach ($contract in $contracts) {
                    $direction = $contract.Direction
                    $desiredState = Get-BaselineRecordMember $desired $direction.ToLowerInvariant()
                    if ($desiredState -isnot [System.Collections.IDictionary]) { throw "ConnectorTrust${direction}CoverageRequired: desired state is required." }
                    $identity = ([string](Get-BaselineRecordMember $desiredState identity)).Trim()
                    if (@($declarationByDirection[$direction] | Where-Object { [string](Get-BaselineRecordMember $_ identity) -ceq $identity }).Count -ne 1) {
                        throw "ConnectorTrust${direction}CoverageRequired: desired connector '$identity' requires one matching declaration."
                    }
                    if (-not $DesiredOnly) {
                        $rows = Get-ApprovedAdapterCollection -Command "Get-$($contract.Noun)" -Arguments @{ ResultSize = 'Unlimited' } -Required @('Identity')
                        if (@($rows | Where-Object { [string]$_.Identity -ceq $identity }).Count -ne 1) {
                            throw "ChangeReadIncomplete: $($contract.Noun) requires exactly one target '$identity'."
                        }
                    }
                    $values = @{}
                    foreach ($field in $contract.Fields) {
                        $sourceName = $field.Substring(0,1).ToLowerInvariant() + $field.Substring(1)
                        $values[$field] = Get-BaselineRecordMember $desiredState $sourceName
                    }
                    New-ApprovedAdapterDefinition -Adapter "ConnectorTrust$direction" -Noun $contract.Noun `
                        -Target @{ Identity = $identity } -Desired $values -Types $contract.Types
                }
            }
            ApplicationAssignmentScope {
                $settings = $options['applicationAssignmentScope']
                if ($settings -isnot [System.Collections.IDictionary]) { throw 'ApplicationAuthorizationAssessmentMissing: EXR-007-A03-T01 assessment is required.' }
                $tenantId = ([string](Get-BaselineRecordMember $settings tenantId)).Trim()
                $applicationId = ([string](Get-BaselineRecordMember $settings applicationId)).Trim()
                $servicePrincipalObjectId = ([string](Get-BaselineRecordMember $settings servicePrincipalObjectId)).Trim()
                $inputHash = ([string](Get-BaselineRecordMember $settings inputHash)).Trim()
                if ($tenantId -cne [string]$parameters.MICROSOFT_ENTRA_TENANT_GUID -or
                    $tenantId -cne [string](Get-BaselineRecordMember (Get-BaselineRecordMember $parameters entitlement) tenantId) -or
                    $tenantId -cne [string](Get-BaselineRecordMember (Get-BaselineRecordMember $parameters domainInventory) tenantId)) {
                    throw 'ApplicationAuthorizationAssessmentMismatch: TenantId differs from the exact Exchange input tenant.'
                }
                if ($applicationId -notmatch '^[0-9a-fA-F-]{36}$' -or $servicePrincipalObjectId -notmatch '^[0-9a-fA-F-]{36}$' -or $inputHash -notmatch '^[0-9A-Fa-f]{64}$') { throw 'ApplicationAuthorizationAssessmentMismatch: exact ApplicationId, ServicePrincipalObjectId and InputHash are required.' }

                $assessment = Get-BaselineRecordMember $settings assessment
                if ($assessment -isnot [System.Collections.IDictionary]) { throw 'ApplicationAuthorizationAssessmentMissing: EXR-007-A03-T01 assessment is required.' }
                if ([string](Get-BaselineRecordMember $assessment ControlId) -cne 'EXR-007-A03-T01' -or [string](Get-BaselineRecordMember $assessment Status) -cne 'Pass') { throw 'ApplicationAuthorizationAssessmentMismatch: EXR-007-A03-T01 must report Pass.' }
                $assessedAt = [datetimeoffset]::MinValue
                if (-not [datetimeoffset]::TryParse([string](Get-BaselineRecordMember $assessment AssessedAtUtc), [ref]$assessedAt) -or $assessedAt -gt [datetimeoffset]::UtcNow -or $assessedAt -lt [datetimeoffset]::UtcNow.AddDays(-1)) { throw 'ApplicationAuthorizationAssessmentStale: EXR-007-A03-T01 must be current within 24 hours.' }
                if ([string](Get-BaselineRecordMember $assessment InputHash) -cne $inputHash) { throw 'ApplicationAuthorizationAssessmentMismatch: InputHash differs from the assessed input.' }
                if ([string](Get-BaselineRecordMember $assessment ExternalReadiness) -cne 'Unverified' -or (Get-BaselineRecordMember $assessment ReleaseReady) -isnot [bool] -or (Get-BaselineRecordMember $assessment ReleaseReady) -or
                    'Exchange probes cannot prove absence of tenant-wide Entra grants.' -cnotin @((Get-BaselineRecordMember $assessment Limitations))) {
                    throw 'ApplicationAuthorizationAssessmentMismatch: external readiness and Exchange probe limitations must remain explicit.'
                }

                $evidence = Get-BaselineRecordMember $settings additiveEntraEvidence
                if ($evidence -isnot [System.Collections.IDictionary] -or (Get-BaselineRecordMember $evidence Complete) -isnot [bool] -or -not (Get-BaselineRecordMember $evidence Complete)) { throw 'AdditiveEntraEvidenceMissing: complete independent Entra evidence is required.' }
                foreach ($binding in @{ TenantId = $tenantId; ApplicationId = $applicationId; ServicePrincipalObjectId = $servicePrincipalObjectId; InputHash = $inputHash }.GetEnumerator()) {
                    if ([string](Get-BaselineRecordMember $evidence $binding.Key) -cne $binding.Value) { throw "AdditiveEntraEvidenceMismatch: $($binding.Key) differs from the assessed input." }
                }
                $suppliedAt = [datetimeoffset]::MinValue
                if (-not [datetimeoffset]::TryParse([string](Get-BaselineRecordMember $evidence SuppliedAtUtc), [ref]$suppliedAt) -or $suppliedAt -gt [datetimeoffset]::UtcNow -or $suppliedAt -lt [datetimeoffset]::UtcNow.AddDays(-1) -or
                    [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $evidence SourceReference))) { throw 'AdditiveEntraEvidenceStale: current independently sourced evidence is required.' }
                if ([string](Get-BaselineRecordMember $evidence ConsentType) -cne 'AdminConsent' -or
                    (ConvertTo-CanonicalJson @((Get-BaselineRecordMember $evidence ApplicationRoles))) -cne (ConvertTo-CanonicalJson @('Exchange.ManageAsApp')) -or
                    (ConvertTo-CanonicalJson @((Get-BaselineRecordMember $evidence ConsentedPermissions))) -cne (ConvertTo-CanonicalJson @('Exchange.ManageAsApp'))) {
                    throw 'ApplicationAssignmentScopeRightsExpansion: only the additive Exchange.ManageAsApp prerequisite is recognized; no consent or grant is performed.'
                }

                $assignments = @((Get-BaselineRecordMember $settings assignments) | Where-Object { $null -ne $_ })
                $scopes = @((Get-BaselineRecordMember $settings managementScopes) | Where-Object { $null -ne $_ })
                if ($assignments.Count -ne 1 -or $scopes.Count -ne 1) { throw 'ApplicationAssignmentUnsupported: exactly one assignment and one custom recipient scope are required.' }
                $assignment = $assignments[0]
                $managementScope = $scopes[0]
                $assignmentIdentity = ([string](Get-BaselineRecordMember $assignment identity)).Trim()
                $scopeIdentity = ([string](Get-BaselineRecordMember $managementScope identity)).Trim()
                $role = [string](Get-BaselineRecordMember $assignment role)
                if ($role -cne 'Application Mail.Read') { throw "ApplicationAssignmentUnsupported: $role is not the approved least-privilege application role." }
                if ([string]::IsNullOrWhiteSpace($assignmentIdentity) -or [string](Get-BaselineRecordMember $assignment roleAssignee) -cne $servicePrincipalObjectId -or
                    [string](Get-BaselineRecordMember $assignment roleAssigneeType) -cne 'ServicePrincipal' -or (Get-BaselineRecordMember $assignment enabled) -isnot [bool] -or -not (Get-BaselineRecordMember $assignment enabled)) {
                    throw 'ApplicationAssignmentUnsupported: assignment identity, service principal and enabled state must match the assessment.'
                }
                $recipientReadScope = [string](Get-BaselineRecordMember $assignment recipientReadScope)
                $recipientWriteScope = [string](Get-BaselineRecordMember $assignment recipientWriteScope)
                $customResourceScope = [string](Get-BaselineRecordMember $assignment customResourceScope)
                if ($recipientReadScope -cne 'CustomRecipientScope') { throw "ApplicationAssignmentScopeRightsExpansion: RecipientReadScope '$recipientReadScope' must equal 'CustomRecipientScope'." }
                if ($recipientWriteScope -cne 'None') { throw "ApplicationAssignmentScopeRightsExpansion: RecipientWriteScope '$recipientWriteScope' must equal 'None'." }
                if ([string]::IsNullOrWhiteSpace($scopeIdentity)) { throw "ApplicationAssignmentScopeRightsExpansion: ManagementScope Identity '$scopeIdentity' must be non-empty." }
                if ($customResourceScope -cne $scopeIdentity) { throw "ApplicationAssignmentScopeRightsExpansion: CustomResourceScope '$customResourceScope' must equal approved ManagementScope Identity '$scopeIdentity'." }
                if ([string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $managementScope recipientRoot)) -or
                    [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $managementScope recipientRestrictionFilter)) -or
                    $null -ne (Get-BaselineRecordMember $managementScope serverRestrictionFilter) -or (Get-BaselineRecordMember $managementScope exclusive) -isnot [bool] -or (Get-BaselineRecordMember $managementScope exclusive)) {
                    throw 'ApplicationAssignmentScopeRightsExpansion: only a non-exclusive custom recipient scope with no server scope is supported.'
                }
                $normalized = Get-BaselineRecordMember $assessment Normalized
                if ((ConvertTo-CanonicalJson @((Get-BaselineRecordMember $normalized Assignments))) -cne (ConvertTo-CanonicalJson @(@{ Identity = $assignmentIdentity; Role = $role; RoleAssignee = $servicePrincipalObjectId; RoleAssigneeType = 'ServicePrincipal'; Enabled = $true; RecipientReadScope = 'CustomRecipientScope'; RecipientWriteScope = 'None'; CustomResourceScope = $scopeIdentity })) -or
                    (ConvertTo-CanonicalJson @((Get-BaselineRecordMember $normalized ManagementScopes))) -cne (ConvertTo-CanonicalJson @(@{ Identity = $scopeIdentity; RecipientRoot = [string]$managementScope.recipientRoot; RecipientRestrictionFilter = [string]$managementScope.recipientRestrictionFilter; ServerRestrictionFilter = $null; Exclusive = $false }))) {
                    throw 'ApplicationAuthorizationAssessmentMismatch: assignment or ManagementScope differs from the T01 normalized assessment.'
                }

                $allowedMailboxes = @((Get-BaselineRecordMember $settings allowedMailboxes))
                $deniedMailboxes = @((Get-BaselineRecordMember $settings deniedMailboxes))
                if ($allowedMailboxes.Count -ne 1 -or $deniedMailboxes.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$allowedMailboxes[0]) -or [string]::IsNullOrWhiteSpace([string]$deniedMailboxes[0]) -or [string]$allowedMailboxes[0] -ieq [string]$deniedMailboxes[0]) { throw 'ApplicationAssignmentScopeRightsExpansion: exactly one distinct allowed and denied mailbox probe is required.' }
                $propagation = Get-BaselineRecordMember $settings propagation
                $maximumDelay = [timespan]::Zero
                if ($propagation -isnot [System.Collections.IDictionary] -or [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $propagation statement))) { throw 'AuthorizationPropagationLimitMissing: a statement and positive maximum delay are required.' }
                try { $maximumDelay = [System.Xml.XmlConvert]::ToTimeSpan([string](Get-BaselineRecordMember $propagation maximumDelay)) }
                catch { throw 'AuthorizationPropagationLimitMissing: a statement and positive maximum delay are required.' }
                if ($maximumDelay -le [timespan]::Zero) { throw 'AuthorizationPropagationLimitMissing: a statement and positive maximum delay are required.' }

                if (-not $DesiredOnly) {
                    $servicePrincipals = Get-ApprovedAdapterCollection Get-ServicePrincipal @{ Identity = $servicePrincipalObjectId } @('Identity','ObjectId','AppId')
                    if ($servicePrincipals.Count -ne 1 -or [string]$servicePrincipals[0].ObjectId -cne $servicePrincipalObjectId -or [string]$servicePrincipals[0].AppId -cne $applicationId) { throw 'AdditiveEntraEvidenceMismatch: ServicePrincipalObjectId or ApplicationId differs from Exchange readback.' }
                    $null = Get-ApprovedAdapterCollection Get-ManagementScope @{ ResultSize = 'Unlimited' } @('Identity','RecipientRoot','RecipientRestrictionFilter','ServerRestrictionFilter','Exclusive') @('ServerRestrictionFilter')
                    $null = Get-ApprovedAdapterCollection Get-ManagementRoleAssignment @{ ResultSize = 'Unlimited' } @('Identity','Name','Role','RoleAssignee','RoleAssigneeType','Enabled','RecipientReadScope','RecipientWriteScope','CustomResourceScope')
                }

                New-ApprovedAdapterDefinition ApplicationManagementScope ManagementScope @{ Identity = $scopeIdentity } @{
                    RecipientRoot = [string]$managementScope.recipientRoot
                    RecipientRestrictionFilter = [string]$managementScope.recipientRestrictionFilter
                    ServerRestrictionFilter = $null
                    Exclusive = $false
                } @{ RecipientRoot = 'String'; RecipientRestrictionFilter = 'String'; ServerRestrictionFilter = 'NullableString'; Exclusive = 'Boolean' } -Create -CreateTarget @{ Name = $scopeIdentity }
                New-ApprovedAdapterDefinition ApplicationRoleAssignment ManagementRoleAssignment @{ Identity = $assignmentIdentity } @{
                    Name = $assignmentIdentity
                    Role = $role
                    RoleAssignee = $servicePrincipalObjectId
                    RoleAssigneeType = 'ServicePrincipal'
                    Enabled = $true
                    RecipientReadScope = 'CustomRecipientScope'
                    RecipientWriteScope = 'None'
                    CustomResourceScope = $scopeIdentity
                } @{ Name = 'String'; Role = 'String'; RoleAssignee = 'String'; RoleAssigneeType = 'String'; Enabled = 'Boolean'; RecipientReadScope = 'String'; RecipientWriteScope = 'String'; CustomResourceScope = 'String' } -Create -CreateTarget @{ Name = $assignmentIdentity }
            }
            OrganizationAllowList {
                $settings = $options['organizationAllowList']
                if ($settings -isnot [System.Collections.IDictionary]) { throw 'ChangeOptionsInvalid: OrganizationAllowList settings are required.' }
                $connection = Get-BaselineRecordMember $settings connectionFilter
                $antiSpam = Get-BaselineRecordMember $settings antiSpam
                if ($connection -isnot [System.Collections.IDictionary] -or $antiSpam -isnot [System.Collections.IDictionary]) { throw 'ChangeOptionsInvalid: OrganizationAllowList connection-filter and anti-spam settings are required.' }
                $connectionIdentity = ([string](Get-BaselineRecordMember $connection identity)).Trim()
                $contentIdentity = ([string](Get-BaselineRecordMember $antiSpam identity)).Trim()
                if ([string]::IsNullOrWhiteSpace($connectionIdentity) -or [string]::IsNullOrWhiteSpace($contentIdentity)) { throw 'ChangeOptionsInvalid: OrganizationAllowList policy identities are required.' }
                if ((Get-BaselineRecordMember $connection enableSafeList) -isnot [bool]) { throw 'ChangeOptionsInvalid: OrganizationAllowList enableSafeList must be Boolean.' }

                $validateApproval = {
                    param($Entry, [string]$ExpectedKind)
                    $value = ([string](Get-BaselineRecordMember $Entry value)).Trim()
                    if ([string](Get-BaselineRecordMember $Entry kind) -cne $ExpectedKind -or [string]::IsNullOrWhiteSpace($value)) { throw 'ChangeOptionsInvalid: OrganizationAllowList entry kind and value are required.' }
                    if ([string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $Entry owner))) { throw "OrganizationAllowListOwnerRequired: $value requires an accountable owner." }
                    if ([string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $Entry approval))) { throw "OrganizationAllowListApprovalRequired: $value requires an approval reference." }
                    $expiresOn = [datetimeoffset]::MinValue
                    if (-not [datetimeoffset]::TryParse([string](Get-BaselineRecordMember $Entry expiresOn), [ref]$expiresOn) -or $expiresOn -le [datetimeoffset]::UtcNow) { throw "OrganizationAllowListApprovalExpired: $value requires a future expiration." }
                    $authentication = Get-BaselineRecordMember $Entry authentication
                    if ($authentication -isnot [System.Collections.IDictionary] -or
                        (Get-BaselineRecordMember $authentication required) -isnot [bool] -or
                        -not (Get-BaselineRecordMember $authentication required) -or
                        (Get-BaselineRecordMember $authentication verified) -isnot [bool] -or
                        -not (Get-BaselineRecordMember $authentication verified) -or
                        [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $authentication evidence))) {
                        throw "OrganizationAllowListAuthenticationRequired: $value requires independently verified authentication."
                    }
                    $value
                }

                $ipAllowList = @(
                    foreach ($entry in @((Get-BaselineRecordMember $connection ipAllowEntries) | Where-Object { $null -ne $_ })) {
                        $value = & $validateApproval $entry IpAddress
                        $parts = $value -split '/', 2
                        $address = $null
                        $prefix = 0
                        if ($parts.Count -ne 2 -or -not [Net.IPAddress]::TryParse($parts[0], [ref]$address) -or -not [int]::TryParse($parts[1], [ref]$prefix) -or
                            ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and $prefix -ne 32) -or
                            ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and $prefix -ne 128)) {
                            throw "OrganizationAllowListIpScopeTooBroad: $value must identify one exact IP address."
                        }
                        if ((Get-BaselineRecordMember $entry shared) -isnot [bool] -or (Get-BaselineRecordMember $entry shared)) { throw "OrganizationAllowListSharedIpTrust: $value cannot be shared by unrelated senders or tenants." }
                        $value
                    }
                )
                $allowedSenders = @(
                    foreach ($entry in @((Get-BaselineRecordMember $antiSpam allowedSenders) | Where-Object { $null -ne $_ })) {
                        & $validateApproval $entry Sender
                    }
                )
                $allowedSenderDomains = @(
                    foreach ($entry in @((Get-BaselineRecordMember $antiSpam allowedSenderDomains) | Where-Object { $null -ne $_ })) {
                        & $validateApproval $entry Domain
                    }
                )

                if (-not $DesiredOnly) {
                    $null = Get-ApprovedAdapterCollection Get-HostedConnectionFilterPolicy @{ ResultSize = 'Unlimited' } @('Identity','IPAllowList','EnableSafeList')
                    $null = Get-ApprovedAdapterCollection Get-HostedContentFilterPolicy @{ ResultSize = 'Unlimited' } @('Identity','AllowedSenders','AllowedSenderDomains')
                }
                & $fixed OrganizationAllowListConnection HostedConnectionFilterPolicy @{ Identity = $connectionIdentity } @{ IPAllowList = $ipAllowList; EnableSafeList = [bool]$connection.enableSafeList } @{ IPAllowList = 'Strings'; EnableSafeList = 'Boolean' }
                & $fixed OrganizationAllowListContent HostedContentFilterPolicy @{ Identity = $contentIdentity } @{ AllowedSenders = $allowedSenders; AllowedSenderDomains = $allowedSenderDomains } @{ AllowedSenders = 'Strings'; AllowedSenderDomains = 'Strings' }
            }
            MailboxSafeSender {
                $declarations = @($options['mailboxSafeSenders'] | Where-Object { $null -ne $_ })
                if ($declarations.Count -eq 0) { throw 'MailboxSafeSenderMailboxOmitted: an explicit applicable mailbox inventory is required.' }

                $declarationByMailbox = @{}
                foreach ($declaration in $declarations) {
                    $mailbox = ([string](Get-BaselineRecordMember $declaration mailbox)).Trim().ToLowerInvariant()
                    $mailboxType = [string](Get-BaselineRecordMember $declaration mailboxType)
                    if ($mailbox -notmatch '^[^@\s*]+@[^@\s*]+\.[^@\s*]+$' -or $mailboxType -cnotin @('UserMailbox','SharedMailbox') -or
                        $declarationByMailbox.ContainsKey($mailbox)) {
                        throw "MailboxSafeSenderMailboxIdentityAmbiguous: $mailbox is missing, unsupported, or duplicated."
                    }
                    $approvedValues = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    foreach ($contract in @(
                            @{ Name = 'senders'; Kind = 'Sender'; Pattern = '^[^@\s*]+@[^@\s*]+\.[^@\s*]+$' }
                            @{ Name = 'domains'; Kind = 'Domain'; Pattern = '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$' }
                        )) {
                        foreach ($entry in @((Get-BaselineRecordMember $declaration $contract.Name) | Where-Object { $null -ne $_ })) {
                            $value = ([string](Get-BaselineRecordMember $entry value)).Trim().ToLowerInvariant()
                            if ([string](Get-BaselineRecordMember $entry kind) -cne $contract.Kind -or
                                [string]::IsNullOrWhiteSpace($value) -or $value -eq '*' -or $value -notmatch $contract.Pattern) {
                                throw "MailboxSafeSenderTrustTooBroad: $value is not narrow $($contract.Kind) trust."
                            }
                            if ([string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $entry owner))) {
                                throw "MailboxSafeSenderOwnerRequired: $value requires an accountable owner."
                            }
                            if ([string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $entry approval))) {
                                throw "MailboxSafeSenderApprovalRequired: $value requires an approval reference."
                            }
                            $expiresOn = [datetimeoffset]::MinValue
                            if (-not [datetimeoffset]::TryParse([string](Get-BaselineRecordMember $entry expiresOn), [ref]$expiresOn) -or
                                $expiresOn -le [datetimeoffset]::UtcNow) {
                                throw "MailboxSafeSenderApprovalExpired: $value requires a future expiration."
                            }
                            if (-not $approvedValues.Add($value)) {
                                throw "MailboxSafeSenderTrustTooBroad: duplicate trust value $value is ambiguous."
                            }
                        }
                    }
                    $declarationByMailbox[$mailbox] = @{
                        MailboxType = $mailboxType
                        ApprovedValues = @($approvedValues | Sort-Object)
                    }
                }

                $currentByMailbox = @{}
                if (-not $DesiredOnly) {
                    $mailboxes = @(& Get-Mailbox -ResultSize Unlimited -ErrorAction Stop)
                    $applicable = @($mailboxes | Where-Object RecipientTypeDetails -Cin @('UserMailbox','SharedMailbox'))
                    $seenMailbox = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    foreach ($mailboxRow in $applicable) {
                        foreach ($field in @('Identity','PrimarySmtpAddress','RecipientTypeDetails')) {
                            if (-not (Test-BaselineNodeMember $mailboxRow $field) -or [string]::IsNullOrWhiteSpace([string]$mailboxRow.$field)) {
                                throw "ChangeReadIncomplete: Get-Mailbox omitted $field."
                            }
                        }
                        $mailbox = ([string]$mailboxRow.PrimarySmtpAddress).Trim().ToLowerInvariant()
                        if (-not $seenMailbox.Add($mailbox)) {
                            throw "MailboxSafeSenderMailboxIdentityAmbiguous: $mailbox appears more than once."
                        }
                        if (-not $declarationByMailbox.ContainsKey($mailbox)) {
                            throw "MailboxSafeSenderMailboxOmitted: $mailbox is absent from the approved inventory."
                        }
                        if ([string]$mailboxRow.RecipientTypeDetails -cne [string]$declarationByMailbox[$mailbox].MailboxType) {
                            throw "MailboxSafeSenderMailboxIdentityAmbiguous: $mailbox has an unexpected mailbox type."
                        }
                        $rows = @(& Get-MailboxJunkEmailConfiguration -Identity $mailbox -ErrorAction Stop)
                        if ($rows.Count -ne 1) {
                            throw "ChangeReadIncomplete: MailboxJunkEmailConfiguration requires exactly one target for $mailbox."
                        }
                        foreach ($field in @('Identity','TrustedSendersAndDomains')) {
                            if (-not (Test-BaselineNodeMember $rows[0] $field) -or $null -eq $rows[0].$field) {
                                throw "ChangeReadIncomplete: MailboxJunkEmailConfiguration omitted $field for $mailbox."
                            }
                        }
                        if ([string]$rows[0].Identity -ine $mailbox) {
                            throw "ChangeReadIncomplete: MailboxJunkEmailConfiguration returned another target for $mailbox."
                        }
                        $currentByMailbox[$mailbox] = @($rows[0].TrustedSendersAndDomains | ForEach-Object {
                                if ($_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_)) {
                                    throw "ChangeReadIncomplete: MailboxJunkEmailConfiguration TrustedSendersAndDomains contains an unresolved value for $mailbox."
                                }
                                ([string]$_).Trim().ToLowerInvariant()
                            } | Sort-Object -Unique)
                    }
                    foreach ($mailbox in $declarationByMailbox.Keys) {
                        if (-not $seenMailbox.Contains($mailbox)) {
                            throw "MailboxSafeSenderMailboxIdentityAmbiguous: $mailbox is not one exact applicable mailbox."
                        }
                    }
                }

                foreach ($mailbox in @($declarationByMailbox.Keys | Sort-Object)) {
                    $target = @{ Identity = $mailbox }
                    $priorValues = if (-not $DesiredOnly) {
                        @($currentByMailbox[$mailbox])
                    } else {
                        $identity = ConvertTo-CanonicalJson $target
                        $operation = @($Approved | Where-Object { $_.Identity -ceq $identity })
                        if ($operation.Count -ne 1) {
                            throw "ChangeOperationMismatch: approved MailboxSafeSender operation is required for $mailbox."
                        }
                        @($operation[0].Before.Value.TrustedSendersAndDomains)
                    }
                    $desiredValues = @(@($priorValues) + @($declarationByMailbox[$mailbox].ApprovedValues) | Sort-Object -Unique)
                    & $fixed MailboxSafeSender MailboxJunkEmailConfiguration $target @{
                        TrustedSendersAndDomains = $desiredValues
                    } @{ TrustedSendersAndDomains = 'Strings' }
                }
            }
            OrganizationRelationship {
                $relationships = @($options['organizationRelationships'] | Where-Object { $null -ne $_ })
                if ($relationships.Count -eq 0) { throw 'OrganizationRelationshipApprovalRequired: at least one explicitly approved local relationship is required.' }
                $approvedIdentities = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($relationship in $relationships) {
                    $identity = ([string](Get-BaselineRecordMember $relationship identity)).Trim()
                    $domains = @((Get-BaselineRecordMember $relationship partnerDomains) | Where-Object { $null -ne $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
                    $enabled = Get-BaselineRecordMember $relationship enabled
                    $freeBusyEnabled = Get-BaselineRecordMember $relationship freeBusyAccessEnabled
                    $level = [string](Get-BaselineRecordMember $relationship freeBusyAccessLevel)
                    $accessScope = ([string](Get-BaselineRecordMember $relationship freeBusyAccessScope)).Trim()
                    if ([string]::IsNullOrWhiteSpace($identity) -or -not $approvedIdentities.Add($identity) -or $domains.Count -eq 0 -or
                        @($domains | Where-Object { $_ -notmatch '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$' }).Count) {
                        throw 'OrganizationRelationshipApprovalRequired: every local relationship requires one unique identity and exact partner domains.'
                    }
                    if ($enabled -isnot [bool] -or $freeBusyEnabled -isnot [bool] -or -not $enabled -or -not $freeBusyEnabled -or
                        $level -cne 'AvailabilityOnly' -or [string]::IsNullOrWhiteSpace($accessScope)) {
                        throw 'OrganizationRelationshipScopeOverbroad: only enabled AvailabilityOnly access to one explicit local scope is supported.'
                    }
                    $approval = Get-BaselineRecordMember $relationship approval
                    $expiresOn = [datetimeoffset]::MinValue
                    if ($approval -isnot [System.Collections.IDictionary] -or
                        [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $approval reference)) -or
                        [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $approval owner)) -or
                        -not [datetimeoffset]::TryParse([string](Get-BaselineRecordMember $approval expiresOn), [ref]$expiresOn) -or
                        $expiresOn -le [datetimeoffset]::UtcNow) {
                        throw 'OrganizationRelationshipApprovalRequired: current owner, approval reference and future expiration are required.'
                    }
                    $attestation = Get-BaselineRecordMember $relationship partnerAttestation
                    if ($attestation -isnot [System.Collections.IDictionary] -or [string](Get-BaselineRecordMember $attestation status) -cne 'Unverified') {
                        throw 'OrganizationRelationshipPartnerReadinessInvalid: partner readiness must remain Unverified until external attestation exists.'
                    }
                }

                if (-not $DesiredOnly) {
                    $currentRelationships = Get-ApprovedAdapterCollection Get-OrganizationRelationship @{ ResultSize = 'Unlimited' } @('Identity','Enabled','DomainNames','FreeBusyAccessEnabled','FreeBusyAccessLevel','FreeBusyAccessScope') @('FreeBusyAccessScope')
                    foreach ($current in $currentRelationships) {
                        if ($current.Enabled -isnot [bool] -or $current.FreeBusyAccessEnabled -isnot [bool]) { throw 'ChangeReadIncomplete: Get-OrganizationRelationship returned invalid enabled state.' }
                        if ($current.Enabled -and -not $approvedIdentities.Contains(([string]$current.Identity).Trim())) { throw "OrganizationRelationshipDomainUnapproved: enabled relationship '$($current.Identity)' has no local approval." }
                    }
                    foreach ($relationship in $relationships) {
                        $identity = ([string](Get-BaselineRecordMember $relationship identity)).Trim()
                        if (@($currentRelationships | Where-Object { [string]$_.Identity -ieq $identity }).Count -ne 1) { throw "ChangeReadIncomplete: OrganizationRelationship requires exactly one target '$identity'." }
                    }
                }

                foreach ($relationship in $relationships) {
                    $identity = ([string](Get-BaselineRecordMember $relationship identity)).Trim()
                    & $fixed OrganizationRelationship OrganizationRelationship @{ Identity = $identity } @{
                        Enabled = [bool](Get-BaselineRecordMember $relationship enabled)
                        DomainNames = @((Get-BaselineRecordMember $relationship partnerDomains) | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
                        FreeBusyAccessEnabled = [bool](Get-BaselineRecordMember $relationship freeBusyAccessEnabled)
                        FreeBusyAccessLevel = [string](Get-BaselineRecordMember $relationship freeBusyAccessLevel)
                        FreeBusyAccessScope = ([string](Get-BaselineRecordMember $relationship freeBusyAccessScope)).Trim()
                    } @{ Enabled = 'Boolean'; DomainNames = 'Strings'; FreeBusyAccessEnabled = 'Boolean'; FreeBusyAccessLevel = 'String'; FreeBusyAccessScope = 'NullableString' }
                }
            }
            FullAccess {
                $delegations = @($options['fullAccessDelegations'] | Where-Object { $null -ne $_ })
                if ($delegations.Count -eq 0) { throw 'FullAccessApprovalRequired: at least one explicitly approved FullAccess delegation is required.' }
                $approvedDelegation = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($delegation in $delegations) {
                    $mailbox = ([string](Get-BaselineRecordMember $delegation mailbox)).Trim()
                    $mailboxType = [string](Get-BaselineRecordMember $delegation mailboxType)
                    $delegate = ([string](Get-BaselineRecordMember $delegation delegate)).Trim()
                    $delegateType = [string](Get-BaselineRecordMember $delegation delegateType)
                    if ($mailbox -notmatch '^[^@\s*]+@[^@\s*]+\.[^@\s*]+$' -or $mailboxType -cnotin @('UserMailbox','SharedMailbox')) { throw 'FullAccessMailboxInventoryIncomplete: every delegation requires one exact applicable user or shared mailbox.' }
                    if ($delegate -notmatch '^[^@\s*]+@[^@\s*]+\.[^@\s*]+$' -or $delegateType -cnotin @('User','NestedGroup')) { throw 'FullAccessPrincipalOwnershipUnresolved: every delegate requires an exact supported principal classification.' }
                    if (Test-BaselineNodeMember $delegation equivalentPermission) { throw 'FullAccessPermissionTypeBoundary: SendAs and SendOnBehalf are independent permissions and cannot authorize FullAccess.' }
                    if ([string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $delegation owner))) { throw 'FullAccessOwnerRequired: every FullAccess delegation requires a current mailbox owner.' }
                    if ([string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $delegation approval))) { throw 'FullAccessApprovalRequired: every FullAccess delegation requires an approval reference.' }
                    $expiresOn = [datetimeoffset]::MinValue
                    if (-not [datetimeoffset]::TryParse([string](Get-BaselineRecordMember $delegation expiresOn), [ref]$expiresOn) -or $expiresOn -le [datetimeoffset]::UtcNow) { throw 'FullAccessApprovalExpired: every FullAccess approval requires a future expiration.' }
                    $identityEvidence = Get-BaselineRecordMember $delegation identityEvidence
                    if ($identityEvidence -isnot [System.Collections.IDictionary] -or (Get-BaselineRecordMember $identityEvidence resolved) -isnot [bool] -or -not (Get-BaselineRecordMember $identityEvidence resolved) -or [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $identityEvidence source)) -or [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $identityEvidence reference))) { throw "FullAccessPrincipalIdentityUnresolved: $delegate requires independently supplied resolved identity evidence." }
                    $ownershipEvidence = Get-BaselineRecordMember $delegation ownershipEvidence
                    if ($ownershipEvidence -isnot [System.Collections.IDictionary] -or (Get-BaselineRecordMember $ownershipEvidence resolved) -isnot [bool] -or -not (Get-BaselineRecordMember $ownershipEvidence resolved) -or [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $ownershipEvidence source)) -or [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $ownershipEvidence reference))) { throw "FullAccessPrincipalOwnershipUnresolved: $delegate requires independently supplied resolved ownership evidence." }
                    if (-not $approvedDelegation.Add("$mailbox|$delegate")) { throw 'FullAccessApprovalRequired: duplicate FullAccess delegation approvals are ambiguous.' }
                }
                if (-not $DesiredOnly) {
                    $mailboxes = Get-ApprovedAdapterCollection Get-Mailbox @{ ResultSize = 'Unlimited' } @('Identity','PrimarySmtpAddress','RecipientTypeDetails')
                    $applicable = @($mailboxes | Where-Object RecipientTypeDetails -Cin @('UserMailbox','SharedMailbox'))
                    foreach ($delegation in $delegations) {
                        $mailbox = ([string](Get-BaselineRecordMember $delegation mailbox)).Trim()
                        $mailboxType = [string](Get-BaselineRecordMember $delegation mailboxType)
                        $match = @($applicable | Where-Object { [string]$_.PrimarySmtpAddress -ieq $mailbox -and [string]$_.RecipientTypeDetails -ceq $mailboxType })
                        if ($match.Count -ne 1) { throw "FullAccessMailboxInventoryIncomplete: $mailbox is not present exactly once as $mailboxType." }
                    }
                    foreach ($mailbox in $applicable) {
                        if (@($delegations | Where-Object { [string]$_.mailbox -ieq [string]$mailbox.PrimarySmtpAddress }).Count -eq 0) { throw "FullAccessMailboxInventoryIncomplete: $($mailbox.PrimarySmtpAddress) is an applicable mailbox omitted from the approved inventory." }
                    }
                    $rawPermissions = @(
                        foreach ($mailbox in $applicable) {
                            & Get-MailboxPermission -Identity $mailbox.PrimarySmtpAddress -ResultSize Unlimited -ErrorAction Stop
                        }
                    )
                    $permissionIdentity = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    foreach ($permission in $rawPermissions) {
                        foreach ($field in @('Identity','Mailbox','User','AccessRights','IsInherited','Deny')) {
                            if (-not (Test-BaselineNodeMember $permission $field) -or $null -eq $permission.$field) { throw "ChangeReadIncomplete: Get-MailboxPermission omitted $field." }
                        }
                        $normalizedIdentity = ([string]$permission.Identity).Trim().ToLowerInvariant()
                        if ([string]::IsNullOrWhiteSpace($normalizedIdentity) -or -not $permissionIdentity.Add($normalizedIdentity)) { throw 'ChangeReadIncomplete: Get-MailboxPermission returned duplicate permission identity.' }
                    }
                    foreach ($permission in $rawPermissions) {
                        if ([string]$permission.User -ieq 'NT AUTHORITY\SELF' -and $permission.IsInherited -isnot [bool] -or [string]$permission.User -ieq 'NT AUTHORITY\SELF' -and -not $permission.IsInherited) { throw "FullAccessEntryClassificationInvalid: NT AUTHORITY\SELF must remain an inherited system entry." }
                        if ($permission.IsInherited -isnot [bool] -or $permission.Deny -isnot [bool]) { throw 'FullAccessEntryClassificationInvalid: permission inheritance and deny classification must be Boolean.' }
                        if (-not $permission.IsInherited -and -not $permission.Deny -and 'FullAccess' -cin @($permission.AccessRights) -and -not $approvedDelegation.Contains("$(([string]$permission.Mailbox).Trim())|$(([string]$permission.User).Trim())")) { throw "FullAccessUnauthorized: $($permission.User) has an explicit FullAccess grant to $($permission.Mailbox) without approval." }
                    }
                }
                foreach ($delegation in $delegations) {
                    $mailbox = ([string](Get-BaselineRecordMember $delegation mailbox)).Trim()
                    $delegate = ([string](Get-BaselineRecordMember $delegation delegate)).Trim()
                    $definition = New-ApprovedAdapterDefinition FullAccess MailboxPermission @{ Identity = $mailbox; User = $delegate; AccessRights = @('FullAccess') } @{ AccessRights = @('FullAccess') } @{ AccessRights = 'Strings' } -Create
                    $definition.Set = 'Add-MailboxPermission'
                    $definition.New = 'Add-MailboxPermission'
                    $definition.Remove = 'Remove-MailboxPermission'
                    $definition
                }
            }
            SendAs {
                $delegations = @($options['sendAsDelegations'] | Where-Object { $null -ne $_ })
                if ($delegations.Count -eq 0) { throw 'SendAsApprovalRequired: at least one explicitly approved SendAs delegation is required.' }
                $approvedDelegation = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                $approvedByRecipient = @{}
                foreach ($delegation in $delegations) {
                    $recipient = ([string](Get-BaselineRecordMember $delegation recipient)).Trim().ToLowerInvariant()
                    $recipientType = [string](Get-BaselineRecordMember $delegation recipientType)
                    $trustee = ([string](Get-BaselineRecordMember $delegation trustee)).Trim().ToLowerInvariant()
                    $principalType = [string](Get-BaselineRecordMember $delegation principalType)
                    if ($recipient -notmatch '^[^@\s*]+@[^@\s*]+\.[^@\s*]+$' -or $recipientType -cnotin @('UserMailbox','SharedMailbox')) { throw 'SendAsRecipientInventoryIncomplete: every delegation requires one exact applicable user or shared recipient.' }
                    if ($trustee -notmatch '^[^@\s*]+@[^@\s*]+\.[^@\s*]+$' -or $principalType -cnotin @('User','NestedGroup')) { throw "SendAsPrincipalIdentityUnresolved: $trustee requires an exact supported principal classification." }
                    if (Test-BaselineNodeMember $delegation equivalentPermission) { throw 'SendAsPermissionTypeBoundary: FullAccess and SendOnBehalf cannot authorize SendAs.' }
                    if ([string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $delegation owner))) { throw "SendAsPrincipalOwnershipUnresolved: $trustee requires a current mailbox owner." }
                    if ([string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $delegation approval))) { throw 'SendAsApprovalRequired: every SendAs delegation requires an approval reference.' }
                    $expiresOn = [datetimeoffset]::MinValue
                    if (-not [datetimeoffset]::TryParse([string](Get-BaselineRecordMember $delegation expiresOn), [ref]$expiresOn) -or $expiresOn -le [datetimeoffset]::UtcNow) { throw 'SendAsApprovalExpired: every SendAs approval requires a future expiration.' }
                    $identityEvidence = Get-BaselineRecordMember $delegation identityEvidence
                    if ($identityEvidence -isnot [System.Collections.IDictionary] -or (Get-BaselineRecordMember $identityEvidence resolved) -isnot [bool] -or -not (Get-BaselineRecordMember $identityEvidence resolved) -or [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $identityEvidence source)) -or [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $identityEvidence reference))) { throw "SendAsPrincipalIdentityUnresolved: $trustee requires independently supplied resolved identity evidence." }
                    $ownershipEvidence = Get-BaselineRecordMember $delegation ownershipEvidence
                    if ($ownershipEvidence -isnot [System.Collections.IDictionary] -or (Get-BaselineRecordMember $ownershipEvidence resolved) -isnot [bool] -or -not (Get-BaselineRecordMember $ownershipEvidence resolved) -or [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $ownershipEvidence source)) -or [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $ownershipEvidence reference))) { throw "SendAsPrincipalOwnershipUnresolved: $trustee requires independently supplied resolved ownership evidence." }
                    if (-not $approvedDelegation.Add("$recipient|$trustee") -or $approvedByRecipient.ContainsKey($recipient)) { throw 'SendAsApprovalRequired: duplicate SendAs delegation approvals are ambiguous.' }
                    $approvedByRecipient[$recipient] = $delegation
                }

                if (-not $DesiredOnly) {
                    $mailboxes = @(& Get-Mailbox -ResultSize Unlimited -ErrorAction Stop)
                    $applicable = @($mailboxes | Where-Object RecipientTypeDetails -Cin @('UserMailbox','SharedMailbox'))
                    $seenRecipient = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    foreach ($mailbox in $applicable) {
                        foreach ($field in @('Identity','PrimarySmtpAddress','RecipientTypeDetails')) {
                            if (-not (Test-BaselineNodeMember $mailbox $field) -or [string]::IsNullOrWhiteSpace([string]$mailbox.$field)) { throw "ChangeReadIncomplete: Get-Mailbox omitted $field." }
                        }
                        $recipient = ([string]$mailbox.PrimarySmtpAddress).Trim().ToLowerInvariant()
                        if (-not $seenRecipient.Add($recipient)) { throw 'ChangeReadIncomplete: Get-Mailbox returned duplicate recipient identities.' }
                        if (-not $approvedByRecipient.ContainsKey($recipient)) { throw "SendAsRecipientInventoryIncomplete: $recipient is absent from the approved inventory." }
                        if ([string]$mailbox.RecipientTypeDetails -cne [string]$approvedByRecipient[$recipient].recipientType) { throw "SendAsRecipientInventoryIncomplete: $recipient has an unexpected recipient type." }
                    }
                    foreach ($recipient in $approvedByRecipient.Keys) {
                        if (-not $seenRecipient.Contains($recipient)) { throw "SendAsRecipientInventoryIncomplete: $recipient is not present exactly once in the applicable recipient inventory." }
                    }

                    $rawPermissions = @(& Get-RecipientPermission -ResultSize Unlimited -ErrorAction Stop)
                    foreach ($mailbox in $applicable) {
                        $null = @(& Get-RecipientPermission -Identity $mailbox.PrimarySmtpAddress -ResultSize Unlimited -ErrorAction Stop)
                    }
                    $permissionIdentity = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    foreach ($permission in $rawPermissions) {
                        foreach ($field in @('Identity','TrustIdentity','Trustee','AccessRights','IsInherited')) {
                            if (-not (Test-BaselineNodeMember $permission $field) -or $null -eq $permission.$field) { throw "ChangeReadIncomplete: Get-RecipientPermission omitted $field." }
                        }
                        $recipient = ([string]$permission.TrustIdentity).Trim().ToLowerInvariant()
                        $trustee = ([string]$permission.Trustee).Trim().ToLowerInvariant()
                        if ([string]::IsNullOrWhiteSpace($recipient) -or [string]::IsNullOrWhiteSpace($trustee) -or -not $permissionIdentity.Add("$recipient|$trustee")) { throw 'ChangeReadIncomplete: Get-RecipientPermission returned duplicate normalized recipient and trustee identities.' }
                        if ($permission.IsInherited -isnot [bool]) { throw 'SendAsEntryClassificationInvalid: permission inheritance classification must be Boolean.' }
                        if ($trustee -eq 'nt authority\self' -and -not $permission.IsInherited) { throw "SendAsEntryClassificationInvalid: NT AUTHORITY\SELF must remain an inherited system entry." }
                    }
                    foreach ($permission in $rawPermissions) {
                        $recipient = ([string]$permission.TrustIdentity).Trim().ToLowerInvariant()
                        $trustee = ([string]$permission.Trustee).Trim().ToLowerInvariant()
                        if (-not $permission.IsInherited -and 'SendAs' -cin @($permission.AccessRights) -and -not $approvedDelegation.Contains("$recipient|$trustee")) { throw "SendAsUnauthorized: $trustee has an explicit SendAs grant to $recipient without approval." }
                    }
                }

                foreach ($delegation in $delegations) {
                    $recipient = ([string](Get-BaselineRecordMember $delegation recipient)).Trim().ToLowerInvariant()
                    $trustee = ([string](Get-BaselineRecordMember $delegation trustee)).Trim().ToLowerInvariant()
                    $definition = New-ApprovedAdapterDefinition SendAs RecipientPermission @{ Identity = $recipient; Trustee = $trustee; AccessRights = @('SendAs') } @{ AccessRights = @('SendAs') } @{ AccessRights = 'Strings' } -Create
                    $definition.Set = 'Add-RecipientPermission'
                    $definition.New = 'Add-RecipientPermission'
                    $definition.Remove = 'Remove-RecipientPermission'
                    $definition
                }
            }
            SendOnBehalf {
                $delegations = @($options['sendOnBehalfDelegations'] | Where-Object { $null -ne $_ })
                if ($delegations.Count -eq 0) { throw 'SendOnBehalfApprovalRequired: at least one explicitly approved SendOnBehalf delegation is required.' }
                $approvedDelegation = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                $approvedByMailbox = @{}
                foreach ($delegation in $delegations) {
                    $mailbox = ([string](Get-BaselineRecordMember $delegation mailbox)).Trim()
                    $mailboxType = [string](Get-BaselineRecordMember $delegation mailboxType)
                    $delegate = ([string](Get-BaselineRecordMember $delegation delegate)).Trim()
                    $delegateType = [string](Get-BaselineRecordMember $delegation delegateType)
                    if ($mailbox -notmatch '^[^@\s*]+@[^@\s*]+\.[^@\s*]+$' -or $mailboxType -cnotin @('UserMailbox','SharedMailbox')) { throw 'SendOnBehalfMailboxInventoryIncomplete: every delegation requires one exact applicable user or shared mailbox.' }
                    if ($delegate -notmatch '^[^@\s*]+@[^@\s*]+\.[^@\s*]+$' -or $delegateType -cnotin @('User','NestedGroup')) { throw 'SendOnBehalfPrincipalOwnershipUnresolved: every delegate requires an exact supported principal classification.' }
                    if (Test-BaselineNodeMember $delegation equivalentPermission) { throw 'SendOnBehalfPermissionTypeBoundary: FullAccess and SendAs are independent permissions and cannot authorize SendOnBehalf.' }
                    if ([string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $delegation owner))) { throw 'SendOnBehalfOwnerRequired: every SendOnBehalf delegation requires a current mailbox owner.' }
                    if ([string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $delegation approval))) { throw 'SendOnBehalfApprovalRequired: every SendOnBehalf delegation requires an approval reference.' }
                    $expiresOn = [datetimeoffset]::MinValue
                    if (-not [datetimeoffset]::TryParse([string](Get-BaselineRecordMember $delegation expiresOn), [ref]$expiresOn) -or $expiresOn -le [datetimeoffset]::UtcNow) { throw 'SendOnBehalfApprovalExpired: every SendOnBehalf approval requires a future expiration.' }
                    $identityEvidence = Get-BaselineRecordMember $delegation identityEvidence
                    if ($identityEvidence -isnot [System.Collections.IDictionary] -or (Get-BaselineRecordMember $identityEvidence resolved) -isnot [bool] -or -not (Get-BaselineRecordMember $identityEvidence resolved) -or [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $identityEvidence source)) -or [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $identityEvidence reference))) { throw "SendOnBehalfPrincipalIdentityUnresolved: $delegate requires independently supplied resolved identity evidence." }
                    $ownershipEvidence = Get-BaselineRecordMember $delegation ownershipEvidence
                    if ($ownershipEvidence -isnot [System.Collections.IDictionary] -or (Get-BaselineRecordMember $ownershipEvidence resolved) -isnot [bool] -or -not (Get-BaselineRecordMember $ownershipEvidence resolved) -or [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $ownershipEvidence source)) -or [string]::IsNullOrWhiteSpace([string](Get-BaselineRecordMember $ownershipEvidence reference))) { throw "SendOnBehalfPrincipalOwnershipUnresolved: $delegate requires independently supplied resolved ownership evidence." }
                    if (-not $approvedDelegation.Add("$mailbox|$delegate") -or $approvedByMailbox.ContainsKey($mailbox)) { throw 'SendOnBehalfApprovalRequired: duplicate SendOnBehalf delegation approvals are ambiguous.' }
                    $approvedByMailbox[$mailbox] = $delegation
                }

                $currentByMailbox = @{}
                if (-not $DesiredOnly) {
                    $mailboxes = @(& Get-Mailbox -ResultSize Unlimited -ErrorAction Stop)
                    $seenMailbox = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    foreach ($mailboxRow in $mailboxes) {
                        foreach ($field in @('Identity','PrimarySmtpAddress','RecipientTypeDetails','GrantSendOnBehalfTo')) {
                            if (-not (Test-BaselineNodeMember $mailboxRow $field) -or $null -eq $mailboxRow.$field) { throw "ChangeReadIncomplete: Get-Mailbox omitted $field." }
                        }
                        $mailboxIdentity = ([string]$mailboxRow.PrimarySmtpAddress).Trim()
                        if ([string]::IsNullOrWhiteSpace($mailboxIdentity) -or -not $seenMailbox.Add($mailboxIdentity)) { throw 'ChangeReadIncomplete: Get-Mailbox returned duplicate mailbox identities.' }
                        $delegateSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                        $currentDelegates = @(
                            foreach ($currentDelegateValue in @($mailboxRow.GrantSendOnBehalfTo)) {
                                if ($currentDelegateValue -isnot [string] -or [string]::IsNullOrWhiteSpace($currentDelegateValue)) { throw 'ChangeReadIncomplete: Get-Mailbox returned an unresolved SendOnBehalf delegate identity.' }
                                $currentDelegate = $currentDelegateValue.Trim()
                                if (-not $delegateSet.Add($currentDelegate)) { throw 'ChangeReadIncomplete: Get-Mailbox returned duplicate normalized SendOnBehalf delegate identity.' }
                                if ($currentDelegate -ieq 'NT AUTHORITY\SELF') { throw 'SendOnBehalfEntryClassificationInvalid: NT AUTHORITY\SELF is a system entry and cannot be an explicit SendOnBehalf delegate.' }
                                $currentDelegate
                            }
                        )
                        $currentByMailbox[$mailboxIdentity] = $currentDelegates
                    }
                    $applicable = @($mailboxes | Where-Object RecipientTypeDetails -Cin @('UserMailbox','SharedMailbox'))
                    foreach ($delegation in $delegations) {
                        $mailbox = ([string](Get-BaselineRecordMember $delegation mailbox)).Trim()
                        $mailboxType = [string](Get-BaselineRecordMember $delegation mailboxType)
                        $match = @($applicable | Where-Object { [string]$_.PrimarySmtpAddress -ieq $mailbox -and [string]$_.RecipientTypeDetails -ceq $mailboxType })
                        if ($match.Count -ne 1) { throw "SendOnBehalfMailboxInventoryIncomplete: $mailbox is not present exactly once as $mailboxType." }
                        $delegate = ([string](Get-BaselineRecordMember $delegation delegate)).Trim()
                        $priorDelegates = @($currentByMailbox[$mailbox] | Where-Object { $_ -ine $delegate })
                        if ($priorDelegates.Count -gt 0) { throw "SendOnBehalfUnauthorized: $($priorDelegates[0]) is an explicit SendOnBehalf delegate to $mailbox without approval." }
                    }
                    foreach ($mailboxRow in $applicable) {
                        if (-not $approvedByMailbox.ContainsKey(([string]$mailboxRow.PrimarySmtpAddress).Trim())) { throw "SendOnBehalfMailboxInventoryIncomplete: $($mailboxRow.PrimarySmtpAddress) is an applicable mailbox omitted from the approved inventory." }
                    }
                }

                foreach ($delegation in $delegations) {
                    $mailbox = ([string](Get-BaselineRecordMember $delegation mailbox)).Trim()
                    $delegate = ([string](Get-BaselineRecordMember $delegation delegate)).Trim()
                    $target = @{ Identity = $mailbox }
                    $priorDelegates = if (-not $DesiredOnly) { @($currentByMailbox[$mailbox]) } else {
                        $identity = ConvertTo-CanonicalJson $target
                        $operation = @($Approved | Where-Object { $_.Identity -ceq $identity })
                        if ($operation.Count -ne 1) { throw "ChangeOperationMismatch: approved SendOnBehalf operation is required for $mailbox." }
                        @($operation[0].Before.Value.GrantSendOnBehalfTo)
                    }
                    $desiredDelegates = @($delegate)
                    & $fixed SendOnBehalf Mailbox $target @{ GrantSendOnBehalfTo = $desiredDelegates } @{ GrantSendOnBehalfTo = 'Strings' }
                }
            }
            TransportBypass {
                $exceptions = @($options['transportSclExceptions'] | Where-Object { $null -ne $_ })
                $prefixRules = @($options['externalSubjectPrefixRules'] | Where-Object { $null -ne $_ })
                if ($exceptions.Count -eq 0) { throw 'TransportBypassAuthenticationRequired: at least one explicitly authenticated SCL exception is required.' }
                $seenException = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($exception in $exceptions) {
                    if ([string]::IsNullOrWhiteSpace([string]$exception.identity) -or -not $seenException.Add([string]$exception.identity)) { throw 'TransportBypassScopeTooBroad: every exception requires one unique exact transport rule identity.' }
                    if (@($exception.senderDomains).Count -eq 0 -or @($exception.senderIpRanges).Count -eq 0 -or
                        [string]$exception.authentication.header -cne 'Authentication-Results' -or
                        @('spf=pass','dkim=pass','dmarc=pass' | Where-Object { $_ -cnotin @($exception.authentication.requiredResults) }).Count) {
                        throw 'TransportBypassAuthenticationRequired: an exception requires sender domain, sender IP and SPF, DKIM and DMARC pass results.'
                    }
                    foreach ($range in @($exception.senderIpRanges)) {
                        $parts = [string]$range -split '/', 2
                        $address = $null
                        $prefix = 0
                        if ($parts.Count -ne 2 -or -not [Net.IPAddress]::TryParse($parts[0], [ref]$address) -or -not [int]::TryParse($parts[1], [ref]$prefix) -or
                            ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and $prefix -lt 24) -or
                            ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and $prefix -lt 64)) {
                            throw 'TransportBypassScopeTooBroad: sender IP ranges must be explicit narrow CIDR ranges.'
                        }
                    }
                    if ([string]::IsNullOrWhiteSpace([string]$exception.owner)) { throw 'TransportBypassOwnerRequired: every exception requires an accountable owner.' }
                    if ([string]::IsNullOrWhiteSpace([string]$exception.approval)) { throw 'TransportBypassApprovalRequired: every exception requires an approval reference.' }
                    $expiry = [datetimeoffset]::MinValue
                    if (-not [datetimeoffset]::TryParse([string]$exception.expiresOn, [ref]$expiry) -or $expiry -le [datetimeoffset]::UtcNow) { throw 'TransportBypassApprovalExpired: every exception requires a future expiration.' }
                    if ($exception.setScl -isnot [int] -and $exception.setScl -isnot [long] -or [long]$exception.setScl -ne -1) { throw 'TransportBypassScopeTooBroad: the approved exception action must be SCL -1.' }
                }
                foreach ($prefix in $prefixRules) {
                    if ([string]::IsNullOrWhiteSpace([string]$prefix.identity) -or [string]::IsNullOrWhiteSpace([string]$prefix.prefix) -or $prefix.action -cne 'Remove') { throw 'ChangeOptionsInvalid: external subject-prefix removal requires identity, prefix and action Remove.' }
                }
                if (-not $DesiredOnly) {
                    $transportRows = Get-ApprovedAdapterCollection Get-TransportRule @{ ResultSize = 'Unlimited' } @('Identity','SetSCL')
                    $livePrefixes = @($transportRows | Where-Object { Test-BaselineNodeMember $_ PrependSubject } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.PrependSubject) })
                    if ($livePrefixes.Count -gt 1) { throw 'ExternalSubjectPrefixDuplicate: remove redundant external subject-prefix rules before applying the approved state.' }
                }
                foreach ($exception in $exceptions) {
                    $definition = & $fixed TransportBypassScl TransportRule @{ Identity = [string]$exception.identity } @{
                        SenderDomainIs = @($exception.senderDomains)
                        SenderIpRanges = @($exception.senderIpRanges)
                        HeaderContainsMessageHeader = [string]$exception.authentication.header
                        HeaderContainsWords = @($exception.authentication.requiredResults)
                        SetSCL = [int]$exception.setScl
                    } @{ SenderDomainIs = 'Strings'; SenderIpRanges = 'Strings'; HeaderContainsMessageHeader = 'String'; HeaderContainsWords = 'Strings'; SetSCL = 'Integer' }
                    $definition.Guard = @{ State = 'Enabled'; Mode = 'Enforce' }
                    $definition
                }
                foreach ($prefix in $prefixRules) {
                    & $fixed TransportBypassPrefix TransportRule @{ Identity = [string]$prefix.identity } @{ PrependSubject = $null } @{ PrependSubject = 'NullableString' }
                }
            }
            GovernanceMailboxPolicy {
                $settings = $controls['EXO-010']
                Assert-ExchangeGovernanceApproval (Get-BaselineRecordMember $settings approval) ([datetimeoffset]::UtcNow)
                if (@($settings.mailboxPolicies).Count -eq 0) { throw 'ChangeOptionsInvalid: approved mailbox policy bindings are required.' }
                foreach ($binding in $settings.mailboxPolicies) {
                    if ([string]::IsNullOrWhiteSpace($binding.mailbox) -or [string]::IsNullOrWhiteSpace($binding.policy)) { throw 'ChangeOptionsInvalid: mailbox and role policy are required.' }
                    & $fixed GovernanceMailboxPolicy Mailbox @{ Identity = [string]$binding.mailbox } @{ RoleAssignmentPolicy = [string]$binding.policy } @{ RoleAssignmentPolicy = 'String' }
                }
            }
            GovernanceMrm {
                $settings = $controls['GOV-003']
                Assert-ExchangeGovernanceApproval (Get-BaselineRecordMember $settings approval) ([datetimeoffset]::UtcNow)
                if ($settings.policyType -cne 'ExchangeMRM') { throw 'PolicyTypeInvalid: only Exchange MRM lifecycle settings are supported.' }
                if ([string]::IsNullOrWhiteSpace($settings.policyName) -or @($settings.tags).Count -eq 0 -or @($settings.mailboxEntitlement).Count -eq 0) { throw 'ChangeOptionsInvalid: explicit policy, tags and mailbox inventory are required.' }
                foreach ($tag in $settings.tags) {
                    if ([string]::IsNullOrWhiteSpace($tag.name) -or $tag.enabled -isnot [bool] -or $tag.ageDays -lt 0 -or $tag.action -cnotin @('MoveToArchive','DeleteAndAllowRecovery','PermanentlyDelete')) { throw 'ChangeOptionsInvalid: invalid approved MRM tag semantics.' }
                    $definition = & $fixed GovernanceMrmTag RetentionPolicyTag @{ Identity = [string]$tag.name } @{ RetentionAction = $tag.action; AgeLimitForRetention = [timespan]::FromDays($tag.ageDays).ToString('c'); RetentionEnabled = $tag.enabled } @{ RetentionAction = 'String'; AgeLimitForRetention = 'Duration'; RetentionEnabled = 'Boolean' }
                    $definition.Guard = @{ Type = [string]$tag.type }
                    $definition
                }
                & $fixed GovernanceMrmPolicy RetentionPolicy @{ Identity = [string]$settings.policyName } @{ RetentionPolicyTagLinks = @($settings.tags.name) } @{ RetentionPolicyTagLinks = 'Strings' }
                foreach ($mailbox in $settings.mailboxEntitlement) {
                    if ([string]::IsNullOrWhiteSpace($mailbox.identity)) { throw 'ChangeOptionsInvalid: explicit MRM mailbox identity is required.' }
                    if (@($settings.tags | Where-Object { $_.enabled -and $_.action -ceq 'MoveToArchive' }).Count -and ($mailbox.archive -isnot [bool] -or -not $mailbox.archive)) { throw 'ArchiveNotEntitled: archive entitlement is required for every target.' }
                    & $fixed GovernanceMrmMailbox Mailbox @{ Identity = [string]$mailbox.identity } @{ RetentionPolicy = [string]$settings.policyName } @{ RetentionPolicy = 'NullableString' }
                }
            }
            GovernanceEncryption {
                $settings = $controls['GOV-005']
                Assert-ExchangeGovernanceApproval (Get-BaselineRecordMember $settings approval) ([datetimeoffset]::UtcNow)
                if ($settings.decryptionApproval.transport -cne $settings.transportDecryptionSetting -or $settings.decryptionApproval.journal -isnot [bool] -or $settings.decryptionApproval.journal -ne $settings.journalReportDecryptionEnabled) { throw 'DecryptionUnapproved: explicit matching transport and journal authorization is required.' }
                if (@($settings.messageClasses).Count -eq 0) { throw 'ChangeOptionsInvalid: approved encryption message classes are required.' }
                & $fixed GovernanceEncryptionIrm IRMConfiguration @{} @{ InternalLicensingEnabled = $settings.internalLicensingEnabled; AzureRMSLicensingEnabled = $settings.azureRmsLicensingEnabled; TransportDecryptionSetting = $settings.transportDecryptionSetting; JournalReportDecryptionEnabled = $settings.journalReportDecryptionEnabled } @{ InternalLicensingEnabled = 'Boolean'; AzureRMSLicensingEnabled = 'Boolean'; TransportDecryptionSetting = 'String'; JournalReportDecryptionEnabled = 'Boolean' }
                foreach ($class in $settings.messageClasses) {
                    if ($class.entitled -isnot [bool] -or -not $class.entitled) { throw 'EncryptionNotEntitled: each approved flow requires entitlement.' }
                    foreach ($field in @('rule','name','header','template','sender')) { if ([string]::IsNullOrWhiteSpace([string]$class[$field])) { throw "ChangeOptionsInvalid: encryption $field is required." } }
                    if (@($class.recipients).Count -eq 0) { throw 'ChangeOptionsInvalid: encryption recipients are required.' }
                    $definition = & $fixed GovernanceEncryptionRule TransportRule @{ Identity = [string]$class.rule } @{ Mode = 'Enforce'; HeaderContainsMessageHeader = $class.header; HeaderContainsWords = @($class.name); SentTo = @($class.recipients); ApplyRightsProtectionTemplate = $class.template } @{ Mode = 'String'; HeaderContainsMessageHeader = 'NullableString'; HeaderContainsWords = 'Strings'; SentTo = 'Strings'; ApplyRightsProtectionTemplate = 'NullableString' }
                    $definition.Guard = @{ State = 'Enabled'; RemoveOME = $false; RemoveOMEv2 = $false }
                    $definition
                }
            }
            Organization {
                $desired = @{ AuditDisabled = -not $controls['EXO-006'].mailboxAuditingDefault }
                $types = @{ AuditDisabled = 'Boolean'; EwsEnabled = 'NullableBoolean'; EwsApplicationAccessPolicy = 'NullableString'; EwsAllowList = 'Strings' }
                $ews = Resolve-BaselineEwsPolicy $controls['EXO-009']
                foreach ($key in $ews.Keys) { $desired[$key] = $ews[$key] }
                if ($ews.Contains('EwsAllowedAppIDs')) { $types.EwsAllowedAppIDs = 'NullableString' }
                if ($ews.EwsEnabled -and -not $DesiredOnly) {
                    $admission = Test-BaselineEwsState -DesiredState $controls['EXO-009'] -ObservedState @{ OrganizationConfig = $ews; CasMailbox = @(Get-CASMailbox -ResultSize Unlimited -ErrorAction Stop) }
                    if ($admission.Status -ne 'Pass') { throw $admission.Reason }
                }
                & $fixed Organization OrganizationConfig @{} $desired $types
            }
            Transport {
                & $fixed Transport TransportConfig @{} @{
                    SmtpClientAuthenticationDisabled = [bool]$controls['EXO-002'].smtpClientAuthenticationDisabled
                    ExternalPostmasterAddress = [string]$controls['EXO-005'].address
                } @{
                    SmtpClientAuthenticationDisabled = 'Boolean'
                    ExternalPostmasterAddress = 'String'
                }
            }
            ExternalSender { & $fixed ExternalSender ExternalInOutlook @{} @{ Enabled = $true; AllowList = @($controls['EXO-007'].allowList) } @{ Enabled = 'Boolean'; AllowList = 'Strings' } }
            OutboundSpam {
                if (-not $options.ContainsKey('outboundSpam')) {
                    & $fixed OutboundSpam HostedOutboundSpamFilterPolicy @{ Identity = 'Default' } @{ AutoForwardingMode = $controls['EXO-004'].automaticExternalForwarding } @{ AutoForwardingMode = 'String' }
                    continue
                }
                $outbound = $options.outboundSpam
                $policyIdentity = 'Contoso Strict Outbound'
                $ruleIdentity = 'Contoso Strict Outbound Rule'
                $settingTypes = [ordered]@{
                    RecipientLimitExternalPerHour = 'Integer'
                    RecipientLimitInternalPerHour = 'Integer'
                    RecipientLimitPerDay = 'Integer'
                    ActionWhenThresholdReached = 'String'
                    AutoForwardingMode = 'String'
                    BccSuspiciousOutboundMail = 'Boolean'
                    BccSuspiciousOutboundAdditionalRecipients = 'Strings'
                    NotifyOutboundSpam = 'Boolean'
                    NotifyOutboundSpamRecipients = 'Strings'
                }
                $scopeTypes = [ordered]@{
                    From = 'Strings'
                    FromMemberOf = 'Strings'
                    SenderDomainIs = 'Strings'
                    ExceptIfFrom = 'Strings'
                    ExceptIfFromMemberOf = 'Strings'
                    ExceptIfSenderDomainIs = 'Strings'
                }
                if ($null -ne $Approved) {
                    if ($outbound -isnot [System.Collections.IDictionary] -or $outbound.policyIdentity -cne $policyIdentity -or $outbound.ruleIdentity -cne $ruleIdentity -or $outbound.profile -cne 'Strict') { throw 'OutboundSpamIdentityUnapproved: only the exact approved custom Strict policy and rule are supported.' }
                    if ($outbound.settings -isnot [System.Collections.IDictionary] -or @($outbound.settings.Keys).Count -ne $settingTypes.Count -or @($settingTypes.Keys | Where-Object { -not $outbound.settings.ContainsKey($_) }).Count) { throw 'OutboundSpamSettingsIncomplete: all nine outbound settings are required.' }
                    foreach ($field in @('RecipientLimitExternalPerHour','RecipientLimitInternalPerHour','RecipientLimitPerDay')) {
                        if ($outbound.settings[$field] -isnot [int] -and $outbound.settings[$field] -isnot [long] -or [long]$outbound.settings[$field] -le 0) { throw "OutboundSpamSettingsIncomplete: $field must be a positive integer." }
                    }
                    if ($outbound.settings.ActionWhenThresholdReached -cnotin @('Alert','BlockUser') -or $outbound.settings.AutoForwardingMode -cnotin @('Automatic','On','Off') -or $outbound.settings.BccSuspiciousOutboundMail -isnot [bool] -or $outbound.settings.NotifyOutboundSpam -isnot [bool]) { throw 'OutboundSpamSettingsIncomplete: outbound actions and notification choices are invalid.' }
                    foreach ($field in @('BccSuspiciousOutboundAdditionalRecipients','NotifyOutboundSpamRecipients')) {
                        if ($null -eq $outbound.settings[$field] -or @($outbound.settings[$field] | Where-Object { $_ -isnot [string] }).Count) { throw "OutboundSpamSettingsIncomplete: $field must be a string collection." }
                    }
                    if ($outbound.senderScope -isnot [System.Collections.IDictionary] -or @($outbound.senderScope.Keys).Count -ne $scopeTypes.Count -or @($scopeTypes.Keys | Where-Object { -not $outbound.senderScope.ContainsKey($_) }).Count) { throw 'OutboundSpamSenderScopeMismatch: all approved sender conditions and exceptions are required.' }
                    foreach ($field in $scopeTypes.Keys) {
                        if ($null -eq $outbound.senderScope[$field] -or @($outbound.senderScope[$field] | Where-Object { $_ -isnot [string] }).Count) { throw "OutboundSpamSenderScopeMismatch: $field must be a string collection." }
                    }
                    $rules = Get-ApprovedAdapterCollection Get-HostedOutboundSpamFilterRule @{ Identity = $ruleIdentity } @('Identity','HostedOutboundSpamFilterPolicy','State')
                    if ($rules.Count -ne 1 -or $rules[0].HostedOutboundSpamFilterPolicy -cne $policyIdentity -or $rules[0].State -cne 'Enabled') { throw 'OutboundSpamSenderScopeMismatch: the exact enabled policy-bound rule is required.' }
                    $currentScope = [ordered]@{}
                    foreach ($field in $scopeTypes.Keys) {
                        if (-not (Test-BaselineNodeMember $rules[0] $field)) { throw "OutboundSpamSenderScopeMismatch: the rule omitted $field." }
                        $currentScope[$field] = ConvertTo-ApprovedAdapterValue $rules[0].$field Strings $field
                    }
                    $desiredScope = [ordered]@{}; foreach ($field in $scopeTypes.Keys) { $desiredScope[$field] = ConvertTo-ApprovedAdapterValue $outbound.senderScope[$field] Strings $field }
                    $legacyScope = [ordered]@{ From = @("legacy@$($parameters.PRIMARY_SMTP_DOMAIN)"); FromMemberOf = @(); SenderDomainIs = @(); ExceptIfFrom = @(); ExceptIfFromMemberOf = @(); ExceptIfSenderDomainIs = @() }
                    $currentJson = ConvertTo-CanonicalJson $currentScope
                    if ($currentJson -cne (ConvertTo-CanonicalJson $desiredScope) -and $currentJson -cne (ConvertTo-CanonicalJson $legacyScope)) { throw 'OutboundSpamSenderScopeMismatch: refusing to overwrite an unapproved sender scope.' }
                }
                $policy = & $fixed OutboundSpamPolicy HostedOutboundSpamFilterPolicy @{ Identity = $policyIdentity } @{} $settingTypes
                foreach ($field in $settingTypes.Keys) { if (Test-BaselineNodeMember $outbound.settings $field) { $policy.Desired[$field] = $outbound.settings[$field] } }
                $policy
                $rule = & $fixed OutboundSpamRule HostedOutboundSpamFilterRule @{ Identity = $ruleIdentity } @{} $scopeTypes
                foreach ($field in $scopeTypes.Keys) { if (Test-BaselineNodeMember $outbound.senderScope $field) { $rule.Desired[$field] = @($outbound.senderScope[$field]) } }
                $rule.Guard = @{ HostedOutboundSpamFilterPolicy = $policyIdentity; State = 'Enabled' }
                $rule
            }
            RemoteDomains {
                $remote = $controls['EXO-008']
                $oof = Resolve-BaselineRemoteDomainOofType $remote
                if (-not $DesiredOnly) {
                    $rows = Get-ApprovedAdapterCollection Get-RemoteDomain @{} @('Identity','DomainName','AllowedOOFType')
                    if (@($rows | Where-Object { $_.Identity -ieq 'Default' -and $_.DomainName -eq '*' }).Count -ne 1) { throw 'ChangeReadIncomplete: wildcard Default remote domain is required.' }
                    if (@($rows | Where-Object { $_.Identity -ine 'Default' -and $_.AllowedOOFType -ine $oof }).Count) { throw 'RemoteDomainOverrideConflict: resolve unapproved OOF overrides first.' }
                }
                & $fixed RemoteDomains RemoteDomain @{ Identity = 'Default' } @{ AutoForwardEnabled = $remote.autoForwardEnabled; AutoReplyEnabled = $remote.autoReplyEnabled; AllowedOOFType = $oof; DeliveryReportEnabled = $remote.deliveryReportEnabled; NDREnabled = $remote.nonDeliveryReportEnabled } @{ AutoForwardEnabled = 'Boolean'; AutoReplyEnabled = 'Boolean'; AllowedOOFType = 'String'; DeliveryReportEnabled = 'Boolean'; NDREnabled = 'Boolean' }
            }
            { $_ -cin @('MailboxProtocols','MailboxPlans') } {
                $noun = if ($area -ceq 'MailboxProtocols') { 'CASMailbox' } else { 'CASMailboxPlan' }
                foreach ($target in (& $targets $area "Get-$noun" @{ ResultSize = 'Unlimited' })) {
                    & $fixed $area $noun $target @{ PopEnabled = $controls['EXO-009'].popEnabledByDefault; ImapEnabled = $controls['EXO-009'].imapEnabledByDefault } @{ PopEnabled = 'Boolean'; ImapEnabled = 'Boolean' }
                }
            }
            AcceptedDomains {
                & $fixed AcceptedDomains AcceptedDomain @{ Identity = [string]$parameters.PRIMARY_SMTP_DOMAIN } @{ DomainType = $controls['EXO-001'].domainType } @{ DomainType = 'String' } $true @{ Name = $parameters.PRIMARY_SMTP_DOMAIN; DomainName = $parameters.PRIMARY_SMTP_DOMAIN }
            }
            ReportSubmission {
                $settings = $controls['MDO-006']
                Assert-ExchangeGovernanceApproval (Get-BaselineRecordMember $settings approval) ([datetimeoffset]::UtcNow)
                if ($settings.reportingMailbox -notmatch '^[^@\s*]+@[^@\s*]+\.[^@\s*]+$' -or $settings.reportingDestination -cne 'MicrosoftAndCustomMailbox' -or -not $settings.microsoftReportMessageButton -or -not $settings.sendCopyToSecOpsMailbox -or -not $settings.sendReportedMessagesToMicrosoft) { throw 'ChangeReportingContract: the supported workflow requires built-in email reporting to Microsoft and one exact Exchange mailbox.' }
                if (-not $DesiredOnly) {
                    $mailboxes = @(& Get-Mailbox -Identity $settings.reportingMailbox -ErrorAction Stop)
                    $mailbox = if ($mailboxes.Count -eq 1) { $mailboxes[0] } else { $null }
                    if ($null -eq $mailbox -or -not (Test-BaselineNodeMember $mailbox PrimarySmtpAddress) -or [string]$mailbox.PrimarySmtpAddress -ine $settings.reportingMailbox -or -not (Test-BaselineNodeMember $mailbox RecipientTypeDetails) -or [string]$mailbox.RecipientTypeDetails -cnotin @('UserMailbox','SharedMailbox') -or -not (Test-BaselineNodeMember $mailbox ForwardingAddress) -or $null -ne $mailbox.ForwardingAddress -or -not (Test-BaselineNodeMember $mailbox ForwardingSmtpAddress) -or $null -ne $mailbox.ForwardingSmtpAddress -or -not (Test-BaselineNodeMember $mailbox DeliverToMailboxAndForward) -or $mailbox.DeliverToMailboxAndForward -isnot [bool] -or $mailbox.DeliverToMailboxAndForward) { throw 'ChangeReportingPrerequisite: resolve exactly one unforwarded Exchange mailbox at the approved reporting address before preview.' }
                    $reportingEvidence = Get-BaselineRecordMember $parameters reportingEvidence
                    $dlp = Get-BaselineRecordMember $reportingEvidence dlp
                    if ($dlp -isnot [System.Collections.IDictionary] -or [string](Get-BaselineRecordMember $dlp mailbox) -ine $settings.reportingMailbox -or [string](Get-BaselineRecordMember $dlp status) -cnotin @('Excluded','NotApplicable') -or $null -eq (Get-BaselineRecordMember $dlp approval)) { throw 'ChangeReportingPrerequisite: provide an approved DLP-owner handoff for the exact reporting mailbox before preview.' }
                    Assert-ExchangeGovernanceApproval (Get-BaselineRecordMember $dlp approval) ([datetimeoffset]::UtcNow)
                    $policies = @(& Get-ReportSubmissionPolicy -Identity 'DefaultReportSubmissionPolicy' -ErrorAction Stop)
                    $rules = @(& Get-ReportSubmissionRule -Identity 'DefaultReportSubmissionRule' -ErrorAction Stop)
                    if ($policies.Count -ne 1 -or -not (Test-BaselineNodeMember $policies[0] Identity) -or [string]$policies[0].Identity -cne 'DefaultReportSubmissionPolicy' -or $rules.Count -ne 1 -or -not (Test-BaselineNodeMember $rules[0] Identity) -or [string]$rules[0].Identity -cne 'DefaultReportSubmissionRule' -or -not (Test-BaselineNodeMember $rules[0] ReportSubmissionPolicy) -or [string]$rules[0].ReportSubmissionPolicy -cne 'DefaultReportSubmissionPolicy') { throw 'ChangeReportingPrerequisite: initialize the exact default reporting policy and policy-bound rule before preview.' }
                }
                $desired = @{ EnableThirdPartyAddress = $false; EnableReportToMicrosoft = $true; ReportJunkToCustomizedAddress = $true; ReportNotJunkToCustomizedAddress = $true; ReportPhishToCustomizedAddress = $true; PreSubmitMessageEnabled = $settings.preSubmitMessageEnabled; PostSubmitMessageEnabled = $settings.postSubmitMessageEnabled }
                $types = @{}; foreach ($field in $desired.Keys) { $types[$field] = 'Boolean' }
                foreach ($field in @('ReportJunkAddresses','ReportNotJunkAddresses','ReportPhishAddresses')) { $desired[$field] = @($settings.reportingMailbox); $types[$field] = 'Strings' }
                & $fixed ReportSubmission ReportSubmissionPolicy @{ Identity = 'DefaultReportSubmissionPolicy' } $desired $types
                $definition = & $fixed ReportSubmissionRule ReportSubmissionRule @{ Identity = 'DefaultReportSubmissionRule' } @{ SentTo = @($settings.reportingMailbox) } @{ SentTo = 'Strings' }
                $definition.Guard = @{ ReportSubmissionPolicy = 'DefaultReportSubmissionPolicy' }
                $definition
                New-ApprovedAdapterDefinition ReportSubmissionRuleState ReportSubmissionRule @{ Identity = 'DefaultReportSubmissionRule' } @{ Enabled = $true } @{ Enabled = 'Boolean' } -Toggle
            }
            SecOpsOverride {
                $settings = $controls['MDO-006']
                Assert-ExchangeGovernanceApproval (Get-BaselineRecordMember $settings approval) ([datetimeoffset]::UtcNow)
                if ($settings.reportingMailbox -notmatch '^[^@\s*]+@[^@\s*]+\.[^@\s*]+$' -or $settings.reportingMailbox -ine $parameters.SECURITY_OPERATIONS_MAILBOX) { throw 'ChangeReportingContract: SecOps scope must be the exact approved reporting mailbox.' }
                if (-not $DesiredOnly) {
                    $rules = Get-ApprovedAdapterCollection Get-ExoSecOpsOverrideRule @{ Policy = 'SecOpsOverridePolicy' } @('Identity','Mode')
                    if ($rules.Count -ne 1 -or $rules[0].Mode -cne 'Enforce') { throw 'ChangeReportingPrerequisite: initialize and enforce the SecOps override rule in Advanced Delivery before preview.' }
                }
                & $fixed SecOpsOverride SecOpsOverridePolicy @{ Identity = 'SecOpsOverridePolicy' } @{ SentTo = @($settings.reportingMailbox) } @{ SentTo = 'Strings' }
            }
            Impersonation {
                if ('ATP_ENTERPRISE' -cnotin @($Context.Entitlement.servicePlans)) { throw 'ChangeScopeNotEntitled: Impersonation requires ATP_ENTERPRISE.' }
                $settings = $controls['MDO-009']
                $policyIdentity = 'Contoso Impersonation Protection'
                $ruleIdentity = 'Contoso Impersonation Protection Rule'
                foreach ($entry in @($settings.approvedExceptions)) {
                    $type = [string](Get-BaselineRecordMember $entry exceptionType)
                    $value = [string](Get-BaselineRecordMember $entry value)
                    $owner = [string](Get-BaselineRecordMember $entry owner)
                    $ticket = [string](Get-BaselineRecordMember $entry ticket)
                    $justification = [string](Get-BaselineRecordMember $entry justification)
                    $expiration = Get-BaselineRecordMember $entry expirationDateTime
                    if ($null -eq $expiration) { $expiration = Get-BaselineRecordMember $entry expiresOn }
                    $expirationInstant = [datetimeoffset]::MinValue
                    $expirationValid = [datetimeoffset]::TryParse([string]$expiration, [ref]$expirationInstant) -and $expirationInstant -gt [datetimeoffset]::UtcNow
                    $valueValid = switch ($type) {
                        TrustedSender { $value -match '^[^@\s*]+@[^@\s*]+\.[^@\s*]+$' }
                        TrustedDomain { $value -match '^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$' }
                        default { $false }
                    }
                    if (-not $valueValid -or [string]::IsNullOrWhiteSpace($owner) -or [string]::IsNullOrWhiteSpace($ticket) -or [string]::IsNullOrWhiteSpace($justification) -or -not $expirationValid) { throw 'ImpersonationExceptionInvalid: exceptions require a narrow sender or domain, governance metadata and a future expiry.' }
                }
                if (-not (Test-BaselineNodeMember $Context.Entitlement recipients)) { throw 'ChangeReadIncomplete: entitlement omitted recipients.' }
                $recipients = @($Context.Entitlement.recipients)
                foreach ($protectedUser in @($settings.protectedUsers)) {
                    $address = ([string]$protectedUser -split ';')[-1]
                    $recipient = @($recipients | Where-Object { [string]$_.address -ieq $address })
                    if ($recipient.Count -ne 1 -or 'ATP_ENTERPRISE' -cnotin @($recipient[0].servicePlans)) { throw "ImpersonationRecipientNotEntitled: $address requires ATP_ENTERPRISE." }
                }
                if (-not $DesiredOnly) {
                    $rules = Get-ApprovedAdapterCollection Get-AntiPhishRule @{ Identity = $ruleIdentity } @('Identity','AntiPhishPolicy','State')
                    if ($rules.Count -ne 1 -or $rules[0].AntiPhishPolicy -cne $policyIdentity -or $rules[0].State -cne 'Enabled') { throw 'ImpersonationRuleBindingInvalid: the exact enabled custom rule must bind the approved policy.' }
                    $scopeFields = @('RecipientDomainIs','SentTo','SentToMemberOf','ExceptIfSentTo','ExceptIfSentToMemberOf','ExceptIfRecipientDomainIs')
                    foreach ($field in $scopeFields) {
                        if (-not (Test-BaselineNodeMember $rules[0] $field)) { throw "ImpersonationRuleBindingInvalid: the custom rule omitted $field." }
                    }
                    $approvedDomain = @([string]$parameters.PRIMARY_SMTP_DOMAIN)
                    if ((ConvertTo-CanonicalJson (ConvertTo-ApprovedAdapterValue $rules[0].RecipientDomainIs Strings RecipientDomainIs)) -cne (ConvertTo-CanonicalJson $approvedDomain) -or @($scopeFields | Where-Object { $_ -cne 'RecipientDomainIs' -and @($rules[0].$_).Count }).Count) { throw 'ImpersonationRuleBindingInvalid: the custom rule must use only the approved recipient domain scope.' }
                    foreach ($preset in (Get-ApprovedAdapterCollection Get-ATPProtectionPolicyRule @{} @('Identity','State'))) {
                        if ($preset.State -cne 'Enabled') { continue }
                        $presetDomains = if (Test-BaselineNodeMember $preset RecipientDomainIs) { @($preset.RecipientDomainIs) } else { @() }
                        if (@($presetDomains | Where-Object { $_ -iin $approvedDomain }).Count) { throw 'ImpersonationPolicyShadowed: an enabled preset policy already matches the approved recipient domain.' }
                    }
                }
                & $fixed Impersonation AntiPhishPolicy @{ Identity = $policyIdentity } @{ EnableTargetedUserProtection = $settings.enabled; EnableTargetedDomainsProtection = $settings.enabled; TargetedUsersToProtect = @($settings.protectedUsers); TargetedDomainsToProtect = @($settings.protectedDomains); ExcludedSenders = @($settings.approvedExceptions | Where-Object exceptionType -CEQ TrustedSender | ForEach-Object value); ExcludedDomains = @($settings.approvedExceptions | Where-Object exceptionType -CEQ TrustedDomain | ForEach-Object value) } @{ EnableTargetedUserProtection = 'Boolean'; EnableTargetedDomainsProtection = 'Boolean'; TargetedUsersToProtect = 'Strings'; TargetedDomainsToProtect = 'Strings'; ExcludedSenders = 'Strings'; ExcludedDomains = 'Strings' } $true @{ Name = $policyIdentity }
            }
            { $_ -cin @('EopPresets','AtpPresets') } {
                if ($area -ceq 'AtpPresets' -and 'ATP_ENTERPRISE' -cnotin @($Context.Entitlement.servicePlans)) { throw 'ChangeScopeNotEntitled: AtpPresets requires ATP_ENTERPRISE.' }
                $standard = $controls['MDO-001']
                $strict = $controls['MDO-002']
                if (@($standard.excludedGroups).Count -ne 1 -or $standard.excludedGroups[0] -ine $parameters.MAIL_ENABLED_PRIORITY_USERS_GROUP -or @($standard.excludedSecOpsMailbox).Count -ne 1 -or $standard.excludedSecOpsMailbox[0] -ine $parameters.SECURITY_OPERATIONS_MAILBOX) { throw 'ChangePresetExclusionUnapproved: preset exclusions must match the approved priority group and security operations mailbox.' }
                if (@($standard.sentToDomains).Count -ne 1 -or $standard.sentToDomains[0] -ine $parameters.PRIMARY_SMTP_DOMAIN -or $strict.scopeGroup -ine $parameters.MAIL_ENABLED_PRIORITY_USERS_GROUP) { throw 'ChangePresetScopeUnapproved: preset assignments must match the approved domain and priority group.' }
                $noun = if ($area -ceq 'EopPresets') { 'EOPProtectionPolicyRule' } else { 'ATPProtectionPolicyRule' }
                foreach ($level in @('Standard','Strict')) {
                    $target = @{ Identity = "$level Preset Security Policy" }
                    $desired = @{ RecipientDomainIs = @(); SentTo = @(); SentToMemberOf = @(); ExceptIfRecipientDomainIs = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @() }
                    if ($level -ceq 'Standard') {
                        $desired.RecipientDomainIs = @($standard.sentToDomains)
                        $desired.ExceptIfSentToMemberOf = @($standard.excludedGroups)
                        $desired.ExceptIfSentTo = @($standard.excludedSecOpsMailbox)
                    } else { $desired.SentToMemberOf = @($strict.scopeGroup) }
                    $types = @{}; foreach ($key in $desired.Keys) { $types[$key] = 'Strings' }
                    if ($null -eq $Approved -and -not $DesiredOnly) {
                        $rows = Get-ApprovedAdapterCollection "Get-$noun" $target
                        if ($rows.Count -ne 1) { throw "ChangeReadIncomplete: $level preset must be initialized exactly once." }
                        foreach ($field in $desired.Keys) {
                            if (-not (Test-BaselineNodeMember $rows[0] $field)) {
                                if ($types[$field] -ceq 'Strings' -and @($desired[$field]).Count -eq 0) { continue }
                                throw "ChangeReadIncomplete: $level preset omitted $field."
                            }
                            if (@($desired[$field]).Count -eq 0 -and @($rows[0].$field).Count) { throw "ChangePresetScopeResidual: $level preset has residual $field assignments." }
                        }
                    }
                    & $fixed "$area$level" $noun $target $desired $types
                    New-ApprovedAdapterDefinition "$area$($level)State" $noun $target @{ Enabled = [bool]$(if ($level -ceq 'Standard') { $controls['MDO-001'].enabled } else { $controls['MDO-002'].enabled }) } @{ Enabled = 'Boolean' } -Toggle
                }
            }
            BuiltInProtection {
                if ('ATP_ENTERPRISE' -cnotin @($Context.Entitlement.servicePlans)) { throw 'ChangeScopeNotEntitled: BuiltInProtection requires ATP_ENTERPRISE.' }
                & $fixed BuiltInProtection ATPBuiltInProtectionRule @{ Identity = 'ATP Built-In Protection Rule' } @{ ExceptIfRecipientDomainIs = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @() } @{ ExceptIfRecipientDomainIs = 'Strings'; ExceptIfSentTo = 'Strings'; ExceptIfSentToMemberOf = 'Strings' }
            }
            Quarantine {
                $settings = $controls['MDO-008']
                $permission = @{ AdminOnlyAccess = 0; LimitedAccess = 106; FullAccess = 236 }
                $categories = @('Malware','HighConfidencePhish','Phish','HighConfidenceSpam','Spam','Bulk','SpoofIntelligence')
                if ($settings.endUserAccessLevel -cnotin @($permission.Keys) -or $settings.highRiskAccessLevel -cnotin @($permission.Keys)) { throw 'QuarantineCustomDeviationUnapproved: quarantine access levels must use an approved local mapping.' }
                if ($settings.endUserSpamNotificationFrequencyInDays -isnot [int] -and $settings.endUserSpamNotificationFrequencyInDays -isnot [long] -or [long]$settings.endUserSpamNotificationFrequencyInDays -le 0 -or $settings.includeMessagesFromBlockedSenderAddress -isnot [bool]) { throw 'QuarantineCustomDeviationUnapproved: notification choices must use the exact approved local mapping.' }
                $highRisk = @($settings.highRiskCategories | Sort-Object -Unique)
                if ((ConvertTo-CanonicalJson $highRisk) -cne (ConvertTo-CanonicalJson @('HighConfidencePhish','Malware'))) { throw 'QuarantineCategoryBindingInvalid: high-risk categories must match the approved mapping.' }
                $categoryPermissions = @{}
                foreach ($category in $categories) {
                    $bindings = @($settings.categoryPermissions | Where-Object category -CEQ $category)
                    if ($bindings.Count -ne 1) { throw "QuarantineCategoryBindingInvalid: $category must have exactly one quarantine tag binding." }
                    $categoryPermissions[$category] = [string]$bindings[0].accessLevel
                }
                if (@($settings.categoryPermissions).Count -ne $categories.Count -or @($settings.categoryPermissions | Where-Object { $_.category -cnotin $categories }).Count) { throw 'QuarantineCategoryBindingInvalid: only the approved message categories may be bound.' }
                foreach ($category in $highRisk) {
                    if ($settings.highRiskAccessLevel -cne 'AdminOnlyAccess' -or $categoryPermissions[$category] -cne 'AdminOnlyAccess') { throw "QuarantineHighRiskPermissionExcessive: $category must use AdminOnlyAccess." }
                }
                foreach ($category in @($categories | Where-Object { $_ -cnotin $highRisk })) {
                    if ($categoryPermissions[$category] -cne $settings.endUserAccessLevel) { throw "QuarantineCustomDeviationUnapproved: $category does not match the approved local end-user mapping." }
                }
                foreach ($level in @($categoryPermissions.Values | Sort-Object -Unique)) {
                    if (-not $permission.ContainsKey($level)) { throw 'QuarantineCustomDeviationUnapproved: unsupported quarantine permission.' }
                    & $fixed QuarantinePolicy QuarantinePolicy @{ Identity = "Baseline-$level" } @{ EndUserQuarantinePermissionsValue = $permission[$level] } @{ EndUserQuarantinePermissionsValue = 'Integer' } $true @{ Name = "Baseline-$level" }
                }
                & $fixed QuarantineGlobal QuarantinePolicy @{ Identity = 'DefaultGlobalTag' } @{ EndUserSpamNotificationFrequency = [timespan]::FromDays($settings.endUserSpamNotificationFrequencyInDays).ToString('c'); IncludeMessagesFromBlockedSenderAddress = $settings.includeMessagesFromBlockedSenderAddress } @{ EndUserSpamNotificationFrequency = 'Duration'; IncludeMessagesFromBlockedSenderAddress = 'Boolean' }
                $desired = @{}; $types = @{}
                foreach ($category in @('HighConfidencePhish','Phish','HighConfidenceSpam','Spam','Bulk')) {
                    $member = $category + 'QuarantineTag'
                    $level = $categoryPermissions[$category]
                    $desired[$member] = "Baseline-$level"; $types[$member] = 'NullableString'
                }
                $managedPolicies = @('Standard Preset Security Policy','Strict Preset Security Policy','Built-In Protection Policy')
                foreach ($target in (& $targets QuarantineContent Get-HostedContentFilterPolicy)) {
                    if ($target.Identity -in $managedPolicies) {
                        if ($null -ne $Approved) { throw 'QuarantineManagedPolicyMutationUnsupported: Microsoft-managed quarantine policies cannot be changed.' }
                        continue
                    }
                    & $fixed QuarantineContent HostedContentFilterPolicy $target $desired $types
                }
                $level = $categoryPermissions.Malware
                foreach ($target in (& $targets QuarantineMalware Get-MalwareFilterPolicy)) {
                    if ($target.Identity -in $managedPolicies) {
                        if ($null -ne $Approved) { throw 'QuarantineManagedPolicyMutationUnsupported: Microsoft-managed quarantine policies cannot be changed.' }
                        continue
                    }
                    & $fixed QuarantineMalware MalwareFilterPolicy $target @{ QuarantineTag = "Baseline-$level" } @{ QuarantineTag = 'NullableString' }
                }
                $level = $categoryPermissions.SpoofIntelligence
                foreach ($target in (& $targets QuarantinePhish Get-AntiPhishPolicy)) {
                    if ($target.Identity -in $managedPolicies) {
                        if ($null -ne $Approved) { throw 'QuarantineManagedPolicyMutationUnsupported: Microsoft-managed quarantine policies cannot be changed.' }
                        continue
                    }
                    & $fixed QuarantinePhish AntiPhishPolicy $target @{ SpoofQuarantineTag = "Baseline-$level" } @{ SpoofQuarantineTag = 'NullableString' }
                }
            }
            Dkim {
                $required = @('Identity','Domain','Enabled','Status','Selector1CNAME','Selector2CNAME','Selector1KeySize','Selector2KeySize')
                $rows = if ($DesiredOnly) { @() } else { @(& Get-DkimSigningConfig -ErrorAction Stop) }
                $byDomain = @{}
                foreach ($row in $rows) {
                    foreach ($field in $required) {
                        if (-not (Test-BaselineNodeMember $row $field) -or [string]::IsNullOrWhiteSpace([string]$row.$field)) { throw "ChangeReadIncomplete: Dkim omitted $field." }
                    }
                    $domain = ([string]$row.Identity).TrimEnd('.').ToLowerInvariant()
                    if ($byDomain.ContainsKey($domain)) { throw 'ChangeReadIncomplete: Get-DkimSigningConfig returned duplicate identities.' }
                    $byDomain[$domain] = $row
                }
                $minimumKeySize = [int]$controls['AUTH-001'].keySize
                foreach ($inventoryDomain in @($parameters.domainInventory.domains | Where-Object { $_.sending -and $_.sendingSystem -ceq 'ExchangeOnline' })) {
                    $domain = ([string]$inventoryDomain.domainName).TrimEnd('.').ToLowerInvariant()
                    $approvedOperation = @($Approved | Where-Object {
                        if ($null -eq $_ -or $_.OperationId -cnotlike 'Dkim-*') { return $false }
                        $identity = ConvertFrom-Json -InputObject $_.Identity -AsHashtable
                        ([string]$identity.Identity).TrimEnd('.') -ieq $domain
                    })
                    if ($approvedOperation.Count -eq 1) {
                        $approvedBefore = ConvertTo-BaselineHashableNode $approvedOperation[0].Before
                        $approvedAfter = ConvertTo-BaselineHashableNode $approvedOperation[0].After
                        if ($approvedBefore.Exists) {
                            foreach ($field in @('Status','Selector1CNAME','Selector2CNAME','Selector1KeySize','Selector2KeySize')) {
                                if (-not (Test-BaselineNodeMember $approvedBefore.Value $field) -or
                                    -not (Test-BaselineNodeMember $approvedAfter.Value $field) -or
                                    (ConvertTo-CanonicalJson $approvedBefore.Value[$field]) -cne (ConvertTo-CanonicalJson $approvedAfter.Value[$field])) {
                                    throw "ChangeOperationMismatch: approved Dkim mutation of $field is unsupported for existing configuration."
                                }
                            }
                        }
                    }
                    if ($DesiredOnly) {
                        if ($approvedOperation.Count -ne 1) { throw "ChangeOperationMismatch: approved Dkim operation is required for $domain." }
                        $desired = ConvertTo-BaselineHashableNode $approvedOperation[0].After.Value
                    } else {
                        if (-not $byDomain.ContainsKey($domain)) { throw "ChangeReadIncomplete: Dkim requires exactly one target for $domain." }
                        $row = $byDomain[$domain]
                        foreach ($field in @('Selector1KeySize','Selector2KeySize')) {
                            if ([int]$row.$field -lt $minimumKeySize) { throw "DkimKeyTooShort: $field is $($row.$field); minimum is $minimumKeySize." }
                        }
                        if ([bool]$row.Enabled -and [string]$row.Status -cne 'Valid') { throw "DkimSigningInvalid: enabled signing status is $($row.Status)." }
                        if ($approvedOperation.Count -gt 1) { throw "ChangeOperationMismatch: approved Dkim operation is ambiguous for $domain." }
                        $desired = if ($approvedOperation.Count -eq 1) { ConvertTo-BaselineHashableNode $approvedOperation[0].After.Value } else {
                            @{
                                Enabled = [bool]$options['enableDkim']
                                Status = [string]$row.Status
                                Selector1CNAME = [string]$row.Selector1CNAME
                                Selector2CNAME = [string]$row.Selector2CNAME
                                Selector1KeySize = [int]$row.Selector1KeySize
                                Selector2KeySize = [int]$row.Selector2KeySize
                            }
                        }
                    }
                    $types = @{ Enabled = 'Boolean'; Status = 'String'; Selector1CNAME = 'String'; Selector2CNAME = 'String'; Selector1KeySize = 'Integer'; Selector2KeySize = 'Integer' }
                    & $fixed Dkim DkimSigningConfig @{ Identity = $domain } $desired $types $true @{ DomainName = $domain; KeySize = $minimumKeySize }
                }
            }
            Forwarding {
                foreach ($target in (& $targets ForwardingMailbox Get-Mailbox @{ ResultSize = 'Unlimited' } @('Identity','PrimarySmtpAddress'))) {
                    & $fixed ForwardingMailbox Mailbox $target @{ ForwardingAddress = $null; ForwardingSmtpAddress = $null } @{ ForwardingAddress = 'NullableString'; ForwardingSmtpAddress = 'NullableString' }
                }
                $ruleTargets = @()
                if ($null -ne $Approved) {
                    $ruleTargets = @(& $targets ForwardingRule Get-InboxRule)
                } else {
                    $domains = Get-ApprovedAdapterCollection Get-AcceptedDomain @{ ResultSize = 'Unlimited' } @('Identity','DomainName')
                    if ($domains.Count -eq 0) { throw 'ChangeReadIncomplete: accepted domains are required for forwarding classification.' }
                    foreach ($mailbox in (Get-ApprovedAdapterCollection Get-Mailbox @{ ResultSize = 'Unlimited' } @('Identity','PrimarySmtpAddress'))) {
                        foreach ($rule in (Get-ApprovedAdapterCollection Get-InboxRule @{ Mailbox = [string]$mailbox.Identity; IncludeHidden = $true } @('Identity'))) {
                            foreach ($field in @('Enabled','ForwardTo','ForwardAsAttachmentTo','RedirectTo')) { if (-not (Test-BaselineNodeMember $rule $field)) { throw "ChangeReadIncomplete: inbox rule omitted $field." } }
                            $external = $false
                            foreach ($recipient in @($rule.ForwardTo) + @($rule.ForwardAsAttachmentTo) + @($rule.RedirectTo)) {
                                if ($null -eq $recipient) { continue }
                                $address = [string]$recipient
                                if ($address -match '<([^<>]+)>') { $address = $Matches[1] }
                                $address = $address -replace '^(?i)smtp:', ''
                                if ($address -notmatch '^[^@\s]+@([^@\s]+)$') { throw 'ChangeReadIncomplete: an inbox forwarding recipient is unresolved.' }
                                if (@($domains.DomainName) -inotcontains $Matches[1].TrimEnd('.')) { $external = $true }
                            }
                            if ($external) { $ruleTargets += @{ Mailbox = [string]$mailbox.Identity; Identity = [string]$rule.Identity } }
                        }
                    }
                }
                foreach ($target in $ruleTargets) { New-ApprovedAdapterDefinition ForwardingRule InboxRule $target @{ Enabled = $false } @{ Enabled = 'Boolean' } -Toggle }
            }
            AddInAcquisition {
                $assignmentTargets = @()
                if ($null -ne $Approved) { $assignmentTargets = @(& $targets AddInAcquisition Get-ManagementRoleAssignment) } else {
                    $policies = Get-ApprovedAdapterCollection Get-RoleAssignmentPolicy @{} @('Identity','IsDefault')
                    $default = @($policies | Where-Object { $_.IsDefault -is [bool] -and $_.IsDefault })
                    if ($default.Count -ne 1) { throw 'ChangeReadIncomplete: exactly one default role assignment policy is required.' }
                    foreach ($assignment in (Get-ApprovedAdapterCollection Get-ManagementRoleAssignment @{} @('Identity','Name','Role','RoleAssignee','RoleAssigneeType','Delegating'))) {
                        if ($assignment.RoleAssignee -ieq $default[0].Identity -and $assignment.Role -iin @('My Custom Apps','My Marketplace Apps','My ReadWriteMailboxApps')) {
                            if ($assignment.RoleAssigneeType -ne 'RoleAssignmentPolicy' -or $assignment.Delegating) { throw 'ChangeReadIncomplete: only regular role-assignment-policy grants can be restored.' }
                            $assignmentTargets += @{ Identity = [string]$assignment.Name }
                        }
                    }
                }
                foreach ($target in $assignmentTargets) {
                    New-ApprovedAdapterDefinition AddInAcquisition ManagementRoleAssignment $target @{} @{ Name = 'String'; Role = 'String'; RoleAssignee = 'String'; RoleAssigneeType = 'String'; Delegating = 'Boolean'; RecipientWriteScope = 'String'; ConfigWriteScope = 'String'; CustomRecipientWriteScope = 'NullableString'; CustomConfigWriteScope = 'NullableString'; ExclusiveRecipientWriteScope = 'NullableString'; ExclusiveConfigWriteScope = 'NullableString' } -Delete
                }
            }
            TenantAllowBlockList {
                $entries = @($options['tenantAllowBlockEntries'] | Where-Object { $null -ne $_ })
                if (-not $DesiredOnly) { $null = Get-ApprovedAdapterCollection Get-TenantAllowBlockListItems @{ ListType = 'Sender' } @('Identity','Value','Action') }
                $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($entry in $entries) {
                    foreach ($field in @('entryType','entryValue','action','owner','ticket','createdDateTime','expirationDateTime','justification')) { if ([string]::IsNullOrWhiteSpace([string]$entry[$field])) { throw "ChangeOptionsInvalid: TABL requires $field." } }
                    if ($entry.entryType -cnotin @('Sender','Domain','Url','File') -or $entry.action -cnotin @('Allow','Block')) { throw 'ChangeOptionsInvalid: unsupported TABL type or action.' }
                    $entryValue = [string]$entry.entryValue
                    if ($null -ne $Approved) {
                        switch -CaseSensitive ($entry.entryType) {
                            Sender {
                                $mailbox = $null
                                try { $mailbox = [Net.Mail.MailAddress]::new($entryValue) } catch {}
                                if ($entryValue -match '[*?]' -or $null -eq $mailbox -or $mailbox.Address -cne $entryValue -or $mailbox.Host -notmatch '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') { throw 'ChangeOptionsInvalid: TenantAllowBlockList Sender requires an exact mailbox address.' }
                            }
                            Domain {
                                if ($entryValue -notmatch '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') { throw 'ChangeOptionsInvalid: TenantAllowBlockList Domain requires an exact domain.' }
                            }
                            Url {
                                $absoluteUri = $null
                                if ($entryValue -match '[*]' -or -not [uri]::TryCreate($entryValue, [UriKind]::Absolute, [ref]$absoluteUri) -or $absoluteUri.Scheme -cnotin @('http','https') -or [string]::IsNullOrWhiteSpace($absoluteUri.Host)) { throw 'ChangeOptionsInvalid: TenantAllowBlockList Url requires an absolute non-wildcard HTTP or HTTPS URL.' }
                            }
                            File {
                                if ($entryValue -notmatch '^[a-f0-9]{64}$') { throw 'ChangeOptionsInvalid: TenantAllowBlockList File requires an exact SHA-256 hash.' }
                            }
                        }
                    }
                    $listType = switch ($entry.entryType) { Domain { 'Sender' } File { 'FileHash' } default { $entry.entryType } }
                    if (-not $seen.Add("$listType/$($entry.entryValue)")) { throw 'ChangeOptionsInvalid: duplicate TABL target.' }
                    $created = [datetimeoffset]$entry.createdDateTime; $expiry = [datetimeoffset]$entry.expirationDateTime
                    $days = ($expiry - $created).TotalDays
                    if ($expiry -le [datetimeoffset]::UtcNow -or $days -le 0 -or ($entry.action -ceq 'Allow' -and $days -gt $controls['MDO-007'].allowEntryMaximumDurationDays) -or ($entry.action -ceq 'Block' -and $days -ne $controls['MDO-007'].blockEntryRetentionDays)) { throw 'ChangeOptionsInvalid: TABL duration violates governance.' }
                    $notes = 'Owner={0}; Ticket={1}; Created={2}; Justification={3}' -f $entry.owner,$entry.ticket,$created.ToString('o'),$entry.justification
                    $definition = & $fixed TenantAllowBlockList TenantAllowBlockListItems @{ ListType = $listType; Entries = @([string]$entry.entryValue) } @{ Action = $entry.action; ExpirationDate = $expiry.ToUniversalTime().ToString('o'); Notes = $notes } @{ Action = 'String'; ExpirationDate = 'DateTime'; Notes = 'NullableString' } $true @{ ListType = $listType; Entries = @([string]$entry.entryValue) }
                    if ($null -ne $Approved -and $DesiredOnly) {
                        $identity = ConvertTo-CanonicalJson $definition.Target
                        $suffix = [Convert]::ToHexString(
                            [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($identity))
                        ).Substring(0,16).ToLowerInvariant()
                        $previous = @($Approved | Where-Object { $_.OperationId -ceq "TenantAllowBlockList-$suffix" })
                        if ($previous.Count -eq 1) {
                            $desiredComparison = ConvertTo-BaselineHashableNode $definition.Desired
                            $approvedComparison = ConvertTo-BaselineHashableNode $previous[0].After.Value
                            foreach ($field in @('Action','ExpirationDate','Notes')) {
                                $desiredComparison[$field] = ConvertTo-ApprovedAdapterValue $desiredComparison[$field] $definition.Types[$field] $field
                                $approvedComparison[$field] = ConvertTo-ApprovedAdapterValue $approvedComparison[$field] $definition.Types[$field] $field
                            }
                        }
                        if ($previous.Count -ne 1 -or
                            (ConvertTo-CanonicalJson $desiredComparison) -cne
                            (ConvertTo-CanonicalJson $approvedComparison)) {
                            throw 'ChangePreviewBindingMismatch: TABL governance fields differ from the approved preview.'
                        }
                    }
                    $definition
                }
            }
        }
    }
}

function Read-ApprovedAdapterState {
    param($Definition, [System.Collections.IDictionary]$Observation)
    if ($Definition.Adapter -ceq 'SendAs') {
        $rows = @(& $Definition.Get -Identity $Definition.Target.Identity -ResultSize Unlimited -ErrorAction Stop | Where-Object {
                [string]$_.TrustIdentity -ieq [string]$Definition.Target.Identity -and
                [string]$_.Trustee -ieq [string]$Definition.Target.Trustee -and
                -not $_.IsInherited -and 'SendAs' -cin @($_.AccessRights)
            })
        if ($rows.Count -gt 1) { throw 'ChangeReadIncomplete: Get-RecipientPermission returned duplicate normalized recipient and trustee identities.' }
        if ($rows.Count -eq 0) { return @{ Exists = $false; Value = $null } }
        $value = @{ AccessRights = @('SendAs') }
        if ($null -ne $Observation) {
            $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson (ConvertTo-BaselineHashableNode $rows[0])))
            $Observation.ObjectFingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        }
        return @{ Exists = $true; Value = $value }
    }
    if ($Definition.Adapter -ceq 'FullAccess') {
        $rows = @(& $Definition.Get -Identity $Definition.Target.Identity -ResultSize Unlimited -ErrorAction Stop | Where-Object {
                [string]$_.Mailbox -ieq [string]$Definition.Target.Identity -and
                [string]$_.User -ieq [string]$Definition.Target.User -and
                -not $_.IsInherited -and -not $_.Deny -and 'FullAccess' -cin @($_.AccessRights)
            })
        if ($rows.Count -gt 1) { throw 'ChangeReadIncomplete: Get-MailboxPermission returned duplicate permission identity.' }
        if ($rows.Count -eq 0) { return @{ Exists = $false; Value = $null } }
        $value = @{ AccessRights = @('FullAccess') }
        if ($null -ne $Observation) {
            $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson (ConvertTo-BaselineHashableNode $rows[0])))
            $Observation.ObjectFingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        }
        return @{ Exists = $true; Value = $value }
    }
    $arguments = $Definition.Target.Clone()
    if ($Definition.New -and -not $Definition.Delete) {
        $arguments = @{}
        if ($Definition.Adapter -ceq 'TenantAllowBlockList') { $arguments.ListType = $Definition.Target.ListType }
        $required = if ($Definition.Adapter -ceq 'TenantAllowBlockList') { @('Identity','Value','Action') } else { @('Identity') }
        $all = Get-ApprovedAdapterCollection $Definition.Get $arguments $required
        $rows = @($all | Where-Object {
            if ($Definition.Adapter -ceq 'TenantAllowBlockList') { $_.Value -ieq $Definition.Target.Entries[0] }
            elseif ($Definition.Adapter -ceq 'AcceptedDomains') { [string](Get-BaselineRecordMember $_ DomainName) -ieq $Definition.Target.Identity }
            else { [string]$_.Identity -ieq $Definition.Target.Identity -or [string](Get-BaselineRecordMember $_ Name) -ieq $Definition.Target.Identity -or [string](Get-BaselineRecordMember $_ Domain) -ieq $Definition.Target.Identity }
        })
    } elseif ($Definition.Delete) {
        $all = Get-ApprovedAdapterCollection $Definition.Get
        $rows = @($all | Where-Object { $_.Identity -ieq $Definition.Target.Identity -or $_.Name -ieq $Definition.Target.Identity })
    } else { $rows = @(& $Definition.Get @arguments -ErrorAction Stop) }
    if ($rows.Count -gt 1 -or ($rows.Count -eq 0 -and -not $Definition.New)) { throw "ChangeReadIncomplete: $($Definition.Adapter) requires exactly one target." }
    if ($rows.Count -eq 0) { return @{ Exists = $false; Value = $null } }
    $row = $rows[0]
    if ($Definition.Adapter -ceq 'ApplicationManagementScope' -and (Test-BaselineNodeMember $row ObservedAtUtc)) {
        $observedAt = [datetimeoffset]::MinValue
        if (-not [datetimeoffset]::TryParse([string]$row.ObservedAtUtc, [ref]$observedAt) -or $observedAt -gt [datetimeoffset]::UtcNow -or $observedAt -lt [datetimeoffset]::UtcNow.AddDays(-1)) { throw 'ApplicationAssignmentScopeReadbackStale: independent raw scope readback is older than 24 hours.' }
    }
    $guards = Get-BaselineRecordMember $Definition Guard
    if ($null -ne $guards) {
        foreach ($field in $guards.Keys) {
            if (-not (Test-BaselineNodeMember $row $field) -or [string](Get-BaselineRecordMember $row $field) -cne [string]$guards[$field]) { throw "ChangeGovernancePrerequisite: '$field' must already match the approved prerequisite." }
        }
    }
    if ($Definition.Adapter -ceq 'GovernanceEncryptionRule') {
        if (-not (Test-BaselineNodeMember $row Conditions) -or -not (Test-BaselineNodeMember $row Exceptions) -or @($row.Exceptions).Count) { throw 'ChangeGovernancePrerequisite: complete encryption predicates with no exceptions are required.' }
        try { Assert-ExchangeGovernanceSet @($row.Conditions | ForEach-Object { Get-BaselineRecordMember $_ Name }) @('HeaderContains','SentTo') 'Encryption predicates' }
        catch { throw "ChangeGovernancePrerequisite: $($_.Exception.Message)" }
    }
    if ($Definition.Target.ContainsKey('Identity') -and -not $Definition.New) {
        if (-not (Test-BaselineNodeMember $row Identity) -or [string]$row.Identity -ine $Definition.Target.Identity) { throw 'ChangeReadIncomplete: read returned another target.' }
    }
    $value = @{}
    foreach ($field in $Definition.Types.Keys) {
        $source = if ($Definition.Adapter -clike 'SharingPolicyBinding*' -and $field -ceq 'Default') { 'IsDefault' } elseif ($Definition.Toggle -and $Definition.Noun -ne 'InboxRule') { 'State' } else { $field }
        if (-not (Test-BaselineNodeMember $row $source)) {
            if ($Definition.Adapter -cmatch '^(?:Eop|Atp)Presets(?:Standard|Strict)$' -and $Definition.Types[$field] -ceq 'Strings' -and @($Definition.Desired[$field]).Count -eq 0) { $actual = @() }
            else { throw "ChangeReadIncomplete: $($Definition.Adapter) omitted $source." }
        } else { $actual = $row.$source }
        if ($source -ceq 'State') {
            if ($actual -cnotin @('Enabled','Disabled')) { throw 'ChangeReadIncomplete: preset State must be Enabled or Disabled.' }
            $actual = $actual -ceq 'Enabled'
        }
        $value[$field] = ConvertTo-ApprovedAdapterValue $actual $Definition.Types[$field] $field
    }
    if ($Definition.Adapter -ceq 'TenantAllowBlockList') {
        $normalizedDesired = @{}
        foreach ($field in $Definition.Types.Keys) {
            $normalizedDesired[$field] = ConvertTo-ApprovedAdapterValue $Definition.Desired[$field] $Definition.Types[$field] $field
        }
        if ((ConvertTo-CanonicalJson $value) -ceq (ConvertTo-CanonicalJson $normalizedDesired)) {
            $value = $normalizedDesired
        }
    }
    if ($Definition.Delete) {
        if ($value.RoleAssigneeType -cne 'RoleAssignmentPolicy' -or $value.Delegating -or $value.Role -cnotin @('My Custom Apps','My Marketplace Apps','My ReadWriteMailboxApps') -or $value.RecipientWriteScope -cne 'Self' -or $value.ConfigWriteScope -cne 'None' -or $value.CustomRecipientWriteScope -or $value.CustomConfigWriteScope -or $value.ExclusiveRecipientWriteScope -or $value.ExclusiveConfigWriteScope) { throw 'ChangeReadIncomplete: role grant has unsupported restoration scope.' }
    }
    if ($null -ne $Observation) {
        $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson (ConvertTo-BaselineHashableNode $row)))
        $Observation.ObjectFingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    }
    $lifecycle = @{}
    foreach ($scopeNumber in 1..4) {
        foreach ($name in @('Stage','ArtifactRoot','ChangeId')) {
            if (-not $lifecycle.ContainsKey($name)) {
                $variable = Get-Variable -Name $name -Scope $scopeNumber -ErrorAction SilentlyContinue
                if ($null -ne $variable) { $lifecycle[$name] = $variable.Value }
            }
        }
    }
    if ($Definition.New -and -not $Definition.Delete -and $lifecycle.Stage -eq 'Rollback') {
        $applyPath = Join-Path $lifecycle.ArtifactRoot "apply-$($lifecycle.ChangeId).json"
        if (Test-Path -LiteralPath $applyPath) {
            $applyReceipt = Get-Content -LiteralPath $applyPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $identity = ConvertTo-CanonicalJson $Definition.Target
            $suffix = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($identity))
            ).Substring(0,16).ToLowerInvariant()
            $operationId = "$($Definition.Adapter)-$suffix"
            $created = @($applyReceipt.Operation | Where-Object {
                    $_.OperationId -ceq $operationId -and $_.State -ceq 'Succeeded' -and
                    -not [string]::IsNullOrWhiteSpace([string]$_.ObjectFingerprint)
                })
            if ($created.Count -eq 1) {
                $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson (ConvertTo-BaselineHashableNode $row)))
                $fingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
                if ($fingerprint -cne [string]$created[0].ObjectFingerprint) {
                    throw 'ChangeStateDrift: a created object changed after its approved creation.'
                }
            }
        }
    }
    @{ Exists = $true; Value = $value }
}

function Get-BaselineConcreteOperation {
    param($Context, [string[]]$Scope, [switch]$DesiredOnly, $Approved)
    foreach ($definition in @(Get-ApprovedAdapterDefinitions $Context $Scope $Approved -DesiredOnly:$DesiredOnly)) {
        $identity = ConvertTo-CanonicalJson $definition.Target
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($identity))).Substring(0,16).ToLowerInvariant()
        $operationId = "$($definition.Adapter)-$hash"
        $previous = @($Approved | Where-Object { $null -ne $_ -and $_.OperationId -ceq $operationId })
        $before = if ($DesiredOnly) { if ($previous.Count -eq 1) { ConvertTo-BaselineHashableNode $previous[0].Before } else { @{ Exists = $true; Value = $definition.Desired } } } else { Read-ApprovedAdapterState $definition }
        $after = @{ Exists = -not $definition.Delete; Value = $null }
        if (-not $definition.Delete) {
            $after.Value = @{}
            foreach ($field in $definition.Desired.Keys) { $after.Value[$field] = ConvertTo-ApprovedAdapterValue $definition.Desired[$field] $definition.Types[$field] $field }
        }
        $origin = if ($previous.Count -eq 1) { $previous[0].Before } else { $before }
        $command = if ($definition.Delete -or $definition.Adapter -ceq 'TenantAllowBlockList' -and $origin.Exists) { $definition.Remove } elseif ($definition.Toggle) { "$(if ($after.Value.Enabled) { 'Enable' } else { 'Disable' })-$($definition.Noun)" } elseif (-not $origin.Exists) { $definition.New } else { $definition.Set }
        @{ OperationId = $operationId; Command = $command; Identity = $identity; Before = $before; After = $after; DependsOn = @(); Sequence = 0 }
    }
}

function Test-ApprovedPresetFieldOmission {
    param($Definition, [string]$Field, $DesiredValue, $Current)
    $Definition.Adapter -cmatch '^(?:Eop|Atp)Presets(?:Standard|Strict)$' -and
        $Definition.Types.ContainsKey($Field) -and $Definition.Types[$Field] -ceq 'Strings' -and
        (Test-BaselineNodeMember $DesiredValue $Field) -and @($DesiredValue[$Field]).Count -eq 0 -and
        $Current.Exists -and (Test-BaselineNodeMember $Current.Value $Field) -and @($Current.Value[$Field]).Count -eq 0
}

function Assert-ApprovedAdapterCommands {
    param($Definitions)
    foreach ($definition in $Definitions) {
        if ($definition.Adapter -ceq 'ApplicationRoleAssignment') {
            foreach ($contract in @(
                    @{ Command = $definition.Get; Fields = @('Identity') },
                    @{ Command = $definition.New; Fields = @('Name','Role','App','CustomResourceScope') },
                    @{ Command = $definition.Remove; Fields = @('Identity') }
                )) {
                $command = Get-Command -Name $contract.Command -ErrorAction SilentlyContinue
                if ($null -eq $command) { throw "ChangeCommandUnavailable: $($contract.Command) is required for apply and restoration." }
                foreach ($field in $contract.Fields) { if (-not $command.Parameters.ContainsKey($field)) { throw "ChangeCommandUnavailable: $($contract.Command) has no $field parameter." } }
            }
            continue
        }
        $contracts = @(@{ Command = $definition.Get; Fields = @() })
        if ($definition.Toggle) {
            foreach ($verb in @('Enable','Disable')) { $contracts += @{ Command = "$verb-$($definition.Noun)"; Fields = @($definition.Target.Keys) } }
        } else {
            if (-not $definition.Delete -and $definition.Adapter -cne 'TenantAllowBlockList') {
                $fields = if ($definition.Adapter -ceq 'SecOpsOverride') { @('Identity','AddSentTo','RemoveSentTo') } elseif ($definition.Adapter -ceq 'Dkim') { @($definition.Target.Keys) + @('Enabled') } else { @($definition.Target.Keys) + @($definition.Desired.Keys) }
                $contracts += @{ Command = $definition.Set; Fields = $fields }
            }
            if ($definition.New) {
                $fields = if ($definition.Delete) { @('Name','Role','Policy') } elseif ($definition.Adapter -ceq 'TenantAllowBlockList') { @('Entries','ListType','ExpirationDate','Notes','Allow','Block') } elseif ($definition.Adapter -ceq 'Dkim') { @($definition.CreateTarget.Keys) + @('Enabled') } else { @($definition.CreateTarget.Keys) + @($definition.Desired.Keys) }
                $contracts += @{ Command = $definition.New; Fields = $fields }
                $contracts += @{ Command = $definition.Remove; Fields = @($definition.Target.Keys) }
            }
        }
        foreach ($contract in $contracts) {
            $command = Get-Command -Name $contract.Command -ErrorAction SilentlyContinue
            if ($null -eq $command) { throw "ChangeCommandUnavailable: $($contract.Command) is required for apply and restoration." }
            $current = $null
            foreach ($field in $contract.Fields) {
                if (-not $command.Parameters.ContainsKey($field)) {
                    if ($null -eq $current) { $current = Read-ApprovedAdapterState $definition }
                    if (Test-ApprovedPresetFieldOmission $definition $field $definition.Desired $current) { continue }
                    throw "ChangeCommandUnavailable: $($contract.Command) has no $field parameter."
                }
            }
        }
    }
}

function Invoke-BaselineConcreteOperation {
    param($Definition, $Current, $Desired, $Journal)
    if ((ConvertTo-CanonicalJson $Current) -ceq (ConvertTo-CanonicalJson $Desired)) { return }
    if ($Definition.Adapter -ceq 'SendAs') {
        $arguments = @{ Identity = $Definition.Target.Identity; Trustee = $Definition.Target.Trustee; AccessRights = @('SendAs') }
        if ($Desired.Exists) {
            $null = Add-RecipientPermission @arguments -Confirm:$false -ErrorAction Stop
            $null = Read-ApprovedAdapterState $Definition -Observation $Journal
        } else {
            $null = Remove-RecipientPermission @arguments -Confirm:$false -ErrorAction Stop
        }
        return
    }
    if ($Definition.Adapter -ceq 'ApplicationRoleAssignment') {
        if ($Current.Exists -and $Desired.Exists) { throw 'ApplicationAssignmentUnsupported: an existing application assignment cannot be expanded or rewritten.' }
        if ($Desired.Exists) {
            $null = New-ManagementRoleAssignment -Name $Desired.Value.Name -Role $Desired.Value.Role -App $Desired.Value.RoleAssignee -CustomResourceScope $Desired.Value.CustomResourceScope -Confirm:$false -ErrorAction Stop
            $null = Read-ApprovedAdapterState $Definition -Observation $Journal
        } else {
            $null = Remove-ManagementRoleAssignment -Identity $Definition.Target.Identity -Confirm:$false -ErrorAction Stop
        }
        return
    }
    if ($Definition.Adapter -ceq 'FullAccess') {
        $arguments = @{ Identity = $Definition.Target.Identity; User = $Definition.Target.User; AccessRights = @('FullAccess') }
        if ($Desired.Exists) {
            $null = Add-MailboxPermission @arguments -Confirm:$false -ErrorAction Stop
            $null = Read-ApprovedAdapterState $Definition -Observation $Journal
        } else {
            $null = Remove-MailboxPermission @arguments -Confirm:$false -ErrorAction Stop
        }
        return
    }
    if ($Definition.Adapter -ceq 'SecOpsOverride') {
        if (-not $Current.Exists -or -not $Desired.Exists) { throw 'ChangeReportingPrerequisite: SecOps policy creation and removal are not supported by this scoped adapter.' }
        $arguments = $Definition.Target.Clone()
        $add = @($Desired.Value.SentTo | Where-Object { $_ -notin $Current.Value.SentTo })
        $remove = @($Current.Value.SentTo | Where-Object { $_ -notin $Desired.Value.SentTo })
        if ($add.Count) { $arguments.AddSentTo = $add }
        if ($remove.Count) { $arguments.RemoveSentTo = $remove }
        $null = Set-SecOpsOverridePolicy @arguments -Confirm:$false -ErrorAction Stop
        return
    }
    if ($Definition.Adapter -ceq 'TenantAllowBlockList') {
        $target = $Definition.Target
        if ($Current.Exists) {
            $null = Remove-TenantAllowBlockListItems @target -ErrorAction Stop
            $Journal.Progress = 'Removed'
            if ((Read-ApprovedAdapterState $Definition).Exists) { throw 'ChangePostStateMismatch: TABL removal was not confirmed.' }
        }
        if ($Desired.Exists) {
            $arguments = $Definition.CreateTarget.Clone()
            $arguments[$Desired.Value.Action] = $true
            $arguments.ExpirationDate = ([datetimeoffset]$Desired.Value.ExpirationDate).UtcDateTime
            $arguments.Notes = $Desired.Value.Notes
            $null = New-TenantAllowBlockListItems @arguments -ErrorAction Stop
            $Journal.Progress = 'Created'
            $null = Read-ApprovedAdapterState $Definition -Observation $Journal
        }
        return
    }
    $arguments = $Definition.Target.Clone()
    $command = $Definition.Set
    if (-not $Desired.Exists) { $command = $Definition.Remove }
    elseif (-not $Current.Exists) {
        $command = $Definition.New
        $arguments = $Definition.CreateTarget.Clone()
        if ($Definition.Delete) {
            $arguments = @{ Name = $Desired.Value.Name; Role = $Desired.Value.Role; Policy = $Desired.Value.RoleAssignee }
        }
    }
    if ($Definition.Toggle) { $command = "$(if ($Desired.Value.Enabled) { 'Enable' } else { 'Disable' })-$($Definition.Noun)" }
    elseif ($Desired.Exists -and -not $Definition.Delete) {
        $commandInfo = Get-Command -Name $command -ErrorAction SilentlyContinue
        if ($null -eq $commandInfo) { throw "ChangeCommandUnavailable: $command is required for apply and restoration." }
        $mutationFields = if ($Definition.Adapter -ceq 'Dkim') { @('Enabled') } else { @($Desired.Value.Keys) }
        foreach ($field in $mutationFields) {
            if (Test-ApprovedPresetFieldOmission $Definition $field $Desired.Value $Current) { continue }
            if (-not $commandInfo.Parameters.ContainsKey($field)) {
                throw "ChangeCommandUnavailable: $command has no $field parameter."
            }
            $arguments[$field] = $Desired.Value[$field]
            if ($Definition.Types[$field] -ceq 'Duration') { $arguments[$field] = [timespan]$Desired.Value[$field] }
            if ($Definition.Types[$field] -ceq 'DateTime') { $arguments[$field] = [datetimeoffset]$Desired.Value[$field] }
        }
    }
    if ([string]::IsNullOrWhiteSpace($command)) { throw 'ChangeOperationMismatch: no concrete mutation adapter exists.' }
    $null = & $command @arguments -Confirm:$false -ErrorAction Stop
    if (-not $Current.Exists -and $Desired.Exists) {
        $null = Read-ApprovedAdapterState $Definition -Observation $Journal
    }
}

function Complete-ApprovedApplicationAssignmentScope {
    param($Context, [string]$Stage, $Journal)
    $settings = $Context.Parameters['workflowOptions']['applicationAssignmentScope']
    if ($Stage -eq 'Rollback') { return @{ Status = 'RolledBack' } }

    $applicationId = [string]$settings.applicationId
    $allowedMailbox = [string]@($settings.allowedMailboxes)[0]
    $deniedMailbox = [string]@($settings.deniedMailboxes)[0]
    $allowed = @(Test-ServicePrincipalAuthorization -Identity $applicationId -Resource $allowedMailbox -ErrorAction Stop)
    if ($allowed.Count -ne 1) { throw "AllowedMailboxReprobeMissing: $allowedMailbox returned no single conclusive authorization result." }
    if (-not (Test-BaselineNodeMember $allowed[0] Authorized) -or $allowed[0].Authorized -isnot [bool] -or -not $allowed[0].Authorized -or [string]$allowed[0].ApplicationId -cne $applicationId -or [string]$allowed[0].Resource -cne $allowedMailbox) { throw "AllowedMailboxReprobeMissing: $allowedMailbox was not conclusively authorized." }
    $denied = @(Test-ServicePrincipalAuthorization -Identity $applicationId -Resource $deniedMailbox -ErrorAction Stop)
    if ($denied.Count -ne 1) { throw "DeniedMailboxReprobeMissing: $deniedMailbox returned no single conclusive authorization result." }
    if (-not (Test-BaselineNodeMember $denied[0] Authorized) -or $denied[0].Authorized -isnot [bool] -or [string]$denied[0].ApplicationId -cne $applicationId -or [string]$denied[0].Resource -cne $deniedMailbox) { throw "DeniedMailboxReprobeMissing: $deniedMailbox was not conclusively denied." }
    if ($denied[0].Authorized) { throw "UnintendedMailboxAuthorization: $deniedMailbox was authorized outside the approved custom recipient scope." }

    $changed = @($Journal | Where-Object State -CEQ 'Succeeded').Count
    @{
        Status = $(if ($changed) { 'Applied' } else { 'NoOp' })
        ExternalReadiness = 'Unverified'
        ReleaseReady = $false
        Propagation = @{ Statement = [string]$settings.propagation.statement; MaximumDelay = [string]$settings.propagation.maximumDelay }
        Limitations = @('Exchange probes cannot prove absence of tenant-wide Entra grants.')
    }
}

function Get-ApprovedSendOnBehalfOperationEvidence {
    param($Context)
    foreach ($delegation in @($Context.Parameters['workflowOptions']['sendOnBehalfDelegations'])) {
        [pscustomobject]@{
            ControlId = 'EXR-007-A05-T03'
            Source = 'Get-Mailbox'
            Evidence = "GrantSendOnBehalfTo read independently for $([string]$delegation.mailbox)."
            Runbook = 'docs/EXCHANGE-ADMINISTRATOR-JOURNEY.md'
        }
    }
}

function Get-ApprovedSendAsOperationEvidence {
    param($Context)
    foreach ($delegation in @($Context.Parameters['workflowOptions']['sendAsDelegations'])) {
        [pscustomobject]@{
            ControlId = 'EXR-007-A05-T02'
            Source = 'Get-RecipientPermission'
            Evidence = "SendAs read independently for $([string]$delegation.recipient)."
            Runbook = 'docs/EXCHANGE-ADMINISTRATOR-JOURNEY.md'
        }
    }
}