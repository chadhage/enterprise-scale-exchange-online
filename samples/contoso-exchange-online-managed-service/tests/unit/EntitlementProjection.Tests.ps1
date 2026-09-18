#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph is not installed and must never be imported. Every inventory here is canned,
    # exactly as Get-BaselineTenantServicePlan would have returned it from subscribedSkus.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ExchangePlanId = 'efb87545-963c-4e0d-99df-69c6916d9eb0'
    $script:AtpPlanId = 'f20fedf3-f3c3-43c3-8267-2bfdd51c0939'
    $script:ThreatIntelligencePlanId = '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'
    $script:SafeDocumentsPlanId = 'bf6f5520-59e3-4f82-974b-7dbbc4fd27c7'
    $script:AdvancedAuditingPlanId = '2f442157-a11c-46b9-ae5b-6e39ff4e5849'

    function New-RequiredServicePlan {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ServicePlanId,

            [Parameter(Mandatory)]
            [string]$ServicePlanName,

            [string[]]$Omit = @()
        )

        $member = [ordered]@{
            servicePlanId   = $ServicePlanId
            servicePlanName = $ServicePlanName
            controls        = @('MDO-005')
        }

        foreach ($name in $Omit) { $member.Remove($name) }

        return [pscustomobject]$member
    }

    # The baseline the tenant is measured against. The tiers are planning metadata: they are
    # carried so an operator can see what was expected, never so a capability can be inferred.
    function New-BaselineConfiguration {
        [CmdletBinding()]
        param(
            [string]$MessagingTier = 'MDO_P2',
            [string]$ComplianceTier = 'E5Compliance',

            [AllowNull()]
            [object[]]$RequiredServicePlan,

            [switch]$OmitLicensing,
            [switch]$OmitRequiredServicePlan
        )

        if (-not $PSBoundParameters.ContainsKey('RequiredServicePlan')) {
            $RequiredServicePlan = @(
                New-RequiredServicePlan -ServicePlanId $script:ExchangePlanId -ServicePlanName 'EXCHANGE_S_ENTERPRISE'
                New-RequiredServicePlan -ServicePlanId $script:AtpPlanId -ServicePlanName 'ATP_ENTERPRISE'
                New-RequiredServicePlan -ServicePlanId $script:ThreatIntelligencePlanId -ServicePlanName 'THREAT_INTELLIGENCE'
                New-RequiredServicePlan -ServicePlanId $script:SafeDocumentsPlanId -ServicePlanName 'SAFEDOCS'
                New-RequiredServicePlan -ServicePlanId $script:AdvancedAuditingPlanId -ServicePlanName 'M365_ADVANCED_AUDITING'
            )
        }

        if ($OmitLicensing) { return [pscustomobject]@{ metadata = [pscustomobject]@{ name = 'fixture' } } }

        $licensing = [ordered]@{
            messagingTier  = $MessagingTier
            complianceTier = $ComplianceTier
        }

        if (-not $OmitRequiredServicePlan) { $licensing['requiredServicePlans'] = @($RequiredServicePlan) }

        return [pscustomobject]@{ licensing = [pscustomobject]$licensing }
    }

    # The shape Get-BaselineTenantServicePlan returns: every observed plan with its state, and the
    # identifiers of the enabled ones.
    function New-TenantServicePlan {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [AllowEmptyCollection()]
            [string[]]$EnabledServicePlanId = @(),

            [AllowNull()]
            [AllowEmptyCollection()]
            [object[]]$Plan = @(),

            [AllowNull()]
            [AllowEmptyCollection()]
            [string[]]$ServicePlanName = @(),

            [switch]$OmitServicePlanId
        )

        $member = [ordered]@{
            Source          = 'GraphSubscribedSkus'
            Sku             = @()
            Plan            = @($Plan)
            ServicePlanId   = @($EnabledServicePlanId)
            ServicePlanName = @($ServicePlanName)
        }

        if ($OmitServicePlanId) { $member.Remove('ServicePlanId') }

        return [pscustomobject]$member
    }

    # Defender for Office 365 Plan 2 with no Safe Documents service plan. This is the tenant shape
    # the live defect misreads as entitled to Safe Documents because the baseline says MDO_P2.
    function New-DefenderPlan2Inventory {
        [CmdletBinding()]
        param()

        return New-TenantServicePlan -EnabledServicePlanId @(
            $script:ExchangePlanId
            $script:AtpPlanId
            $script:ThreatIntelligencePlanId
        ) -ServicePlanName @('EXCHANGE_S_ENTERPRISE', 'ATP_ENTERPRISE', 'THREAT_INTELLIGENCE')
    }

    function New-FullyLicensedInventory {
        [CmdletBinding()]
        param()

        return New-TenantServicePlan -EnabledServicePlanId @(
            $script:ExchangePlanId
            $script:AtpPlanId
            $script:ThreatIntelligencePlanId
            $script:SafeDocumentsPlanId
            $script:AdvancedAuditingPlanId
        ) -ServicePlanName @('EXCHANGE_S_ENTERPRISE', 'ATP_ENTERPRISE', 'THREAT_INTELLIGENCE', 'SAFEDOCS', 'M365_ADVANCED_AUDITING')
    }

    function Get-CapabilityVerdict {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Entitlement,

            [Parameter(Mandatory)]
            [string]$Name
        )

        $match = @($Entitlement.Capability | Where-Object { $_.Name -eq $Name })
        if ($match.Count -ne 1) { return "NoSingleVerdict($($match.Count))" }

        return [string]$match[0].Entitled
    }

    function Get-CapabilityReason {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Entitlement,

            [Parameter(Mandatory)]
            [string]$Name
        )

        $match = @($Entitlement.Capability | Where-Object { $_.Name -eq $Name })
        if ($match.Count -ne 1) { return "NoSingleVerdict($($match.Count))" }

        return [string]$match[0].Reason
    }

    function Get-EntitlementFold {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Entitlement
        )

        $row = @($Entitlement.Capability | ForEach-Object {
                '{0}={1}({2}):{3}:{4}' -f $_.Name, $_.RequiredServicePlanName, $_.RequiredServicePlanId, $_.Entitled,
                $(if ([string]::IsNullOrWhiteSpace($_.Reason)) { 'unreasoned' } else { 'reasoned' })
            })

        return '{0}|{1}|{2}' -f $Entitlement.Source, $Entitlement.Determined, ($row -join ' ')
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'LIC-008-A1 Graph-derived entitlement projection' {

    Context 'Negative: the projection inputs must be usable' {

        It 'refuses a projection with no configuration' {
            # Arrange
            $noConfiguration = $null

            # Act
            $project = { Resolve-BaselineEntitlement -Configuration $noConfiguration -TenantServicePlan (New-FullyLicensedInventory) }

            # Assert
            $project | Should -Throw -ExpectedMessage 'ConfigurationRequired*' -Because 'without the baseline nothing declares which service plan a capability needs'
        }

        It 'refuses a configuration that declares no licensing section' {
            # Arrange
            $noLicensing = New-BaselineConfiguration -OmitLicensing

            # Act
            $project = { Resolve-BaselineEntitlement -Configuration $noLicensing -TenantServicePlan (New-FullyLicensedInventory) }

            # Assert
            $project | Should -Throw -ExpectedMessage 'LicensingRequirementMissing*' -Because 'a baseline that declares no service plans would report every capability entitled to nothing'
        }

        It 'refuses a configuration that declares no required service plans' {
            # Arrange
            $noRequirement = New-BaselineConfiguration -OmitRequiredServicePlan

            # Act
            $project = { Resolve-BaselineEntitlement -Configuration $noRequirement -TenantServicePlan (New-FullyLicensedInventory) }

            # Assert
            $project | Should -Throw -ExpectedMessage 'LicensingRequirementMissing*' -Because 'an empty requirement set cannot be told from a tenant that holds everything'
        }

        It 'refuses a required service plan that declares no service-plan identifier' {
            # Arrange
            $unidentified = New-BaselineConfiguration -RequiredServicePlan @(
                New-RequiredServicePlan -ServicePlanId $script:SafeDocumentsPlanId -ServicePlanName 'SAFEDOCS' -Omit @('servicePlanId')
            )

            # Act
            $project = { Resolve-BaselineEntitlement -Configuration $unidentified -TenantServicePlan (New-FullyLicensedInventory) }

            # Assert
            $project | Should -Throw -ExpectedMessage 'RequiredServicePlanContractViolation*servicePlanId*' -Because 'the tenant inventory carries identifiers, so a requirement without one can never be matched'
        }

        It 'refuses a required service plan that declares no service-plan name' {
            # Arrange
            $unnamed = New-BaselineConfiguration -RequiredServicePlan @(
                New-RequiredServicePlan -ServicePlanId $script:SafeDocumentsPlanId -ServicePlanName 'SAFEDOCS' -Omit @('servicePlanName')
            )

            # Act
            $project = { Resolve-BaselineEntitlement -Configuration $unnamed -TenantServicePlan (New-FullyLicensedInventory) }

            # Assert
            $project | Should -Throw -ExpectedMessage 'RequiredServicePlanContractViolation*servicePlanName*' -Because 'a capability names the plan it needs, so an unnamed declaration can never be bound to one'
        }

        It 'refuses one service-plan name declared with two different identifiers' {
            # Arrange
            $ambiguous = New-BaselineConfiguration -RequiredServicePlan @(
                New-RequiredServicePlan -ServicePlanId $script:SafeDocumentsPlanId -ServicePlanName 'SAFEDOCS'
                New-RequiredServicePlan -ServicePlanId $script:AtpPlanId -ServicePlanName 'SAFEDOCS'
            )

            # Act
            $project = { Resolve-BaselineEntitlement -Configuration $ambiguous -TenantServicePlan (New-FullyLicensedInventory) }

            # Assert
            $project | Should -Throw -ExpectedMessage 'RequiredServicePlanAmbiguous*SAFEDOCS*' -Because 'two identifiers for one plan name make the verdict depend on the declaration order'
        }

        It 'refuses a projection with no tenant service-plan inventory' {
            # Arrange
            $noInventory = $null

            # Act
            $project = { Resolve-BaselineEntitlement -Configuration (New-BaselineConfiguration) -TenantServicePlan $noInventory }

            # Assert
            $project | Should -Throw -ExpectedMessage 'TenantServicePlanRequired*' -Because 'entitlement that was never collected must never be assumed'
        }

        It 'refuses an inventory that does not declare its enabled service-plan identifiers' {
            # Arrange
            $notAnInventory = New-TenantServicePlan -OmitServicePlanId

            # Act
            $project = { Resolve-BaselineEntitlement -Configuration (New-BaselineConfiguration) -TenantServicePlan $notAnInventory }

            # Assert
            $project | Should -Throw -ExpectedMessage 'TenantServicePlanContractViolation*ServicePlanId*' -Because 'an inventory without identifiers is not the evidence a verdict is built from'
        }
    }

    Context 'Negative: the declared tier is never the entitlement authority' {

        It 'does not report Safe Documents entitled for an MDO_P2 baseline whose tenant holds no SAFEDOCS plan' {
            # Arrange
            $configuration = New-BaselineConfiguration -MessagingTier 'MDO_P2'

            # Act
            $entitlement = Resolve-BaselineEntitlement -Configuration $configuration -TenantServicePlan (New-DefenderPlan2Inventory)

            # Assert
            Get-CapabilityVerdict -Entitlement $entitlement -Name 'SafeDocuments' |
                Should -Be 'False' -Because 'Defender for Office 365 Plan 2 does not grant Safe Documents; the SAFEDOCS service plan does'
        }

        It 'does not report Safe Documents entitled when the SAFEDOCS plan is assigned but not enabled' {
            # Arrange
            $notEnabled = New-TenantServicePlan -EnabledServicePlanId @($script:ExchangePlanId, $script:AtpPlanId) -Plan @(
                [pscustomobject]@{ ServicePlanId = $script:SafeDocumentsPlanId; ServicePlanName = 'SAFEDOCS'; State = 'Disabled'; Enabled = $false }
            ) -ServicePlanName @('EXCHANGE_S_ENTERPRISE', 'ATP_ENTERPRISE')

            # Act
            $entitlement = Resolve-BaselineEntitlement -Configuration (New-BaselineConfiguration) -TenantServicePlan $notEnabled

            # Assert
            Get-CapabilityVerdict -Entitlement $entitlement -Name 'SafeDocuments' |
                Should -Be 'False' -Because 'a plan that is present but not enabled is not a plan the tenant can use'
        }

        It 'does not report the Defender presets entitled for an MDO_P2 baseline whose tenant holds no ATP_ENTERPRISE plan' {
            # Arrange
            $eopOnly = New-TenantServicePlan -EnabledServicePlanId @($script:ExchangePlanId) -ServicePlanName @('EXCHANGE_S_ENTERPRISE')

            # Act
            $entitlement = Resolve-BaselineEntitlement -Configuration (New-BaselineConfiguration -MessagingTier 'MDO_P2') -TenantServicePlan $eopOnly

            # Assert
            Get-CapabilityVerdict -Entitlement $entitlement -Name 'AtpPresets' |
                Should -Be 'False' -Because 'a tier the tenant does not hold must never grant the presets it names'
        }

        It 'does not let a declared EOP tier suppress a capability the tenant inventory grants' {
            # Arrange
            $understatedTier = New-BaselineConfiguration -MessagingTier 'EOP'

            # Act
            $entitlement = Resolve-BaselineEntitlement -Configuration $understatedTier -TenantServicePlan (New-FullyLicensedInventory)

            # Assert
            Get-CapabilityVerdict -Entitlement $entitlement -Name 'AtpPresets' |
                Should -Be 'True' -Because 'the runtime inventory overrides the declared tier in both directions'
        }

        It 'does not report the declared tier as the authority the projection was decided from' {
            # Arrange
            $configuration = New-BaselineConfiguration -MessagingTier 'MDO_P2'

            # Act
            $entitlement = Resolve-BaselineEntitlement -Configuration $configuration -TenantServicePlan (New-DefenderPlan2Inventory)

            # Assert
            $entitlement.Source | Should -Be 'GraphSubscribedSkus' -Because 'the evidence must name the tenant inventory as the authority, not the planning metadata'
        }

        It 'keeps the declared tiers as planning metadata rather than as a verdict' {
            # Arrange
            $configuration = New-BaselineConfiguration -MessagingTier 'MDO_P2' -ComplianceTier 'E5Compliance'

            # Act
            $entitlement = Resolve-BaselineEntitlement -Configuration $configuration -TenantServicePlan (New-DefenderPlan2Inventory)

            # Assert
            '{0}/{1}' -f $entitlement.DeclaredMessagingTier, $entitlement.DeclaredComplianceTier |
                Should -Be 'MDO_P2/E5Compliance' -Because 'what was planned is still worth reporting, under a name no consumer can mistake for a verdict'
        }
    }

    Context 'Negative: a required plan is matched on its identifier alone' {

        It 'does not report Safe Documents entitled for a different plan carrying the SAFEDOCS display name' {
            # Arrange
            $nameOnly = New-TenantServicePlan -EnabledServicePlanId @($script:ExchangePlanId, $script:AtpPlanId) -ServicePlanName @('EXCHANGE_S_ENTERPRISE', 'ATP_ENTERPRISE', 'SAFEDOCS')

            # Act
            $entitlement = Resolve-BaselineEntitlement -Configuration (New-BaselineConfiguration) -TenantServicePlan $nameOnly

            # Assert
            Get-CapabilityVerdict -Entitlement $entitlement -Name 'SafeDocuments' |
                Should -Be 'False' -Because 'a bundle that carries the same display name is not the plan the capability requires'
        }

        It 'does not treat a differently-cased service-plan identifier as a different plan' {
            # Arrange
            $upperCased = New-TenantServicePlan -EnabledServicePlanId @($script:SafeDocumentsPlanId.ToUpperInvariant()) -ServicePlanName @('SAFEDOCS')

            # Act
            $entitlement = Resolve-BaselineEntitlement -Configuration (New-BaselineConfiguration) -TenantServicePlan $upperCased

            # Assert
            Get-CapabilityVerdict -Entitlement $entitlement -Name 'SafeDocuments' |
                Should -Be 'True' -Because 'a service-plan identifier is the same identifier whatever case Graph returned it in'
        }
    }

    Context 'Negative: a capability the baseline never declared is never entitled' {

        It 'does not report a capability entitled when the baseline declares no service plan for it' {
            # Arrange
            $undeclared = New-BaselineConfiguration -RequiredServicePlan @(
                New-RequiredServicePlan -ServicePlanId $script:ExchangePlanId -ServicePlanName 'EXCHANGE_S_ENTERPRISE'
            )

            # Act
            $entitlement = Resolve-BaselineEntitlement -Configuration $undeclared -TenantServicePlan (New-FullyLicensedInventory)

            # Assert
            Get-CapabilityVerdict -Entitlement $entitlement -Name 'SafeDocuments' |
                Should -Be 'False' -Because 'a requirement nobody declared cannot have been checked against the tenant'
        }

        It 'names the service plan the baseline failed to declare' {
            # Arrange
            $undeclared = New-BaselineConfiguration -RequiredServicePlan @(
                New-RequiredServicePlan -ServicePlanId $script:ExchangePlanId -ServicePlanName 'EXCHANGE_S_ENTERPRISE'
            )

            # Act
            $entitlement = Resolve-BaselineEntitlement -Configuration $undeclared -TenantServicePlan (New-FullyLicensedInventory)

            # Assert
            Get-CapabilityReason -Entitlement $entitlement -Name 'SafeDocuments' |
                Should -BeLike '*SAFEDOCS*' -Because 'the operator must be told which declaration is missing, not merely that a capability is off'
        }

        It 'reports the capabilities the tenant is not entitled to' {
            # Arrange
            $configuration = New-BaselineConfiguration

            # Act
            $entitlement = Resolve-BaselineEntitlement -Configuration $configuration -TenantServicePlan (New-DefenderPlan2Inventory)

            # Assert
            @($entitlement.NotEntitled) | Should -Be @('SafeDocuments', 'AuditPremium') -Because 'a gate that cannot say what is missing cannot be acted on'
        }
    }

    Context 'Negative: the projection stays offline' {

        It 'reaches Graph and Exchange Online only through the inventory it was given' {
            # Arrange
            $script:ProjectionCommandInvocation = [System.Collections.Generic.List[string]]::new()
            function global:Connect-MgGraph { $script:ProjectionCommandInvocation.Add('Connect-MgGraph') }
            function global:Get-MgSubscribedSku { $script:ProjectionCommandInvocation.Add('Get-MgSubscribedSku') }
            function global:Get-AtpPolicyForO365 { $script:ProjectionCommandInvocation.Add('Get-AtpPolicyForO365') }

            # Act
            $null = Resolve-BaselineEntitlement -Configuration (New-BaselineConfiguration) -TenantServicePlan (New-FullyLicensedInventory)

            # Assert
            try {
                $script:ProjectionCommandInvocation | Should -BeNullOrEmpty -Because 'the projection must never contact a tenant of its own accord'
            }
            finally {
                Remove-Item -Path 'function:global:Connect-MgGraph', 'function:global:Get-MgSubscribedSku', 'function:global:Get-AtpPolicyForO365' -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Positive: a fully licensed tenant is entitled from its inventory alone' {

        It 'reports one verdict per capability, each naming its required plan, identifier and reason' {
            # Arrange
            $configuration = New-BaselineConfiguration -MessagingTier 'MDO_P2' -ComplianceTier 'E5Compliance'

            # Act
            $entitlement = Resolve-BaselineEntitlement -Configuration $configuration -TenantServicePlan (New-FullyLicensedInventory)

            # Assert
            Get-EntitlementFold -Entitlement $entitlement | Should -Be (
                'GraphSubscribedSkus|True|' + (@(
                    "EopPresets=EXCHANGE_S_ENTERPRISE($script:ExchangePlanId):True:reasoned"
                    "AtpPresets=ATP_ENTERPRISE($script:AtpPlanId):True:reasoned"
                    "BuiltInProtection=ATP_ENTERPRISE($script:AtpPlanId):True:reasoned"
                    "SafeAttachmentsSpo=ATP_ENTERPRISE($script:AtpPlanId):True:reasoned"
                    "SafeDocuments=SAFEDOCS($script:SafeDocumentsPlanId):True:reasoned"
                    "PurviewRetention=EXCHANGE_S_ENTERPRISE($script:ExchangePlanId):True:reasoned"
                    "AuditPremium=M365_ADVANCED_AUDITING($script:AdvancedAuditingPlanId):True:reasoned"
                ) -join ' ')
            ) -Because 'every capability is decided from the enabled tenant inventory, on identifiers alone'
        }
    }
}
