#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph is not installed and must never be imported. The collector reaches Graph
    # only through an injected request seam, so every test supplies a canned response.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ExchangePlanId = 'efb87545-963c-4e0d-99df-69c6916d9eb0'
    $script:AtpPlanId = 'f20fedf3-f3c3-43c3-8267-2bfdd51c0939'
    $script:ThreatIntelligencePlanId = '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'
    $script:SafeDocumentsPlanId = 'bf6f5520-59e3-4f82-974b-7dbbc4fd27c7'

    function New-ServicePlan {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ServicePlanId,

            [Parameter(Mandatory)]
            [string]$ServicePlanName,

            [string]$ProvisioningStatus = 'Success',

            [string[]]$Omit = @()
        )

        $member = [ordered]@{
            servicePlanId      = $ServicePlanId
            servicePlanName    = $ServicePlanName
            provisioningStatus = $ProvisioningStatus
            appliesTo          = 'User'
        }

        foreach ($name in $Omit) { $member.Remove($name) }

        return [pscustomobject]$member
    }

    function New-SubscribedSku {
        [CmdletBinding()]
        param(
            [string]$SkuId = '05e9a617-0261-4cee-bb44-138d3ef5d965',
            [string]$SkuPartNumber = 'SPE_E3',
            [string]$CapabilityStatus = 'Enabled',

            [AllowEmptyCollection()]
            [object[]]$ServicePlan = @(),

            [string[]]$Omit = @()
        )

        $member = [ordered]@{
            skuId            = $SkuId
            skuPartNumber    = $SkuPartNumber
            capabilityStatus = $CapabilityStatus
            servicePlans     = @($ServicePlan)
        }

        foreach ($name in $Omit) { $member.Remove($name) }

        return [pscustomobject]$member
    }

    function New-GraphRequestSeam {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Response
        )

        $captured = $Response
        return { param($Resource) return $captured }.GetNewClosure()
    }

    function New-SubscribedSkuSeam {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]]$Sku
        )

        return New-GraphRequestSeam -Response ([pscustomobject]@{ value = @($Sku) })
    }

    # The inventory the shipped baseline needs, spread over three subscriptions so the positive
    # test exercises deduplication, a non-enabled plan and a non-enabled subscription at once.
    function New-RepresentativeSubscribedSku {
        [CmdletBinding()]
        param()

        return @(
            New-SubscribedSku -SkuId '05e9a617-0261-4cee-bb44-138d3ef5d965' -SkuPartNumber 'SPE_E3' -CapabilityStatus 'Enabled' -ServicePlan @(
                New-ServicePlan -ServicePlanId $script:ExchangePlanId -ServicePlanName 'EXCHANGE_S_ENTERPRISE'
                New-ServicePlan -ServicePlanId $script:AtpPlanId -ServicePlanName 'ATP_ENTERPRISE' -ProvisioningStatus 'PendingProvisioning'
            )
            New-SubscribedSku -SkuId 'c7df2760-2c81-4ef7-b578-5b5392b571df' -SkuPartNumber 'ENTERPRISEPREMIUM' -CapabilityStatus 'Enabled' -ServicePlan @(
                New-ServicePlan -ServicePlanId $script:ExchangePlanId -ServicePlanName 'EXCHANGE_S_ENTERPRISE'
                New-ServicePlan -ServicePlanId $script:AtpPlanId -ServicePlanName 'ATP_ENTERPRISE'
                New-ServicePlan -ServicePlanId $script:ThreatIntelligencePlanId -ServicePlanName 'THREAT_INTELLIGENCE'
                New-ServicePlan -ServicePlanId $script:SafeDocumentsPlanId -ServicePlanName 'SAFEDOCS' -ProvisioningStatus 'Disabled'
            )
            New-SubscribedSku -SkuId '26124093-3d78-432b-b5dc-48bf992543d5' -SkuPartNumber 'IDENTITY_THREAT_PROTECTION' -CapabilityStatus 'Suspended' -ServicePlan @(
                New-ServicePlan -ServicePlanId $script:SafeDocumentsPlanId -ServicePlanName 'SAFEDOCS'
            )
        )
    }

    function Get-PlanState {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Inventory,

            [Parameter(Mandatory)]
            [string]$ServicePlanId
        )

        return @(@($Inventory.Plan) | Where-Object { $_.ServicePlanId -eq $ServicePlanId } | ForEach-Object { $_.State } | Sort-Object -Unique)
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'LIC-002-A tenant service-plan inventory collection' {

    Context 'Negative: the Graph request seam and its response must be usable' {

        It 'refuses to collect without a Graph request seam' {
            # Arrange
            $absentSeam = $null

            # Act
            $collect = { Get-BaselineTenantServicePlan -GraphRequest $absentSeam }

            # Assert
            $collect | Should -Throw -ExpectedMessage 'GraphRequestRequired*' -Because 'the inventory must never be assumed when Graph cannot be reached'
        }

        It 'refuses a null Graph response' {
            # Arrange
            $seam = New-GraphRequestSeam -Response $null

            # Act
            $collect = { Get-BaselineTenantServicePlan -GraphRequest $seam }

            # Assert
            $collect | Should -Throw -ExpectedMessage 'GraphResponseMissing*' -Because 'an absent response is not an empty inventory'
        }

        It 'refuses a Graph response that carries no value member' {
            # Arrange
            $seam = New-GraphRequestSeam -Response ([pscustomobject]@{ '@odata.context' = 'subscribedSkus' })

            # Act
            $collect = { Get-BaselineTenantServicePlan -GraphRequest $seam }

            # Assert
            $collect | Should -Throw -ExpectedMessage 'GraphResponseContractViolation*' -Because 'a subscribedSkus response the collector cannot read must not be silently treated as empty'
        }

        It 'refuses a Graph response whose value is not a collection' {
            # Arrange
            $seam = New-GraphRequestSeam -Response ([pscustomobject]@{ value = 'SPE_E3' })

            # Act
            $collect = { Get-BaselineTenantServicePlan -GraphRequest $seam }

            # Assert
            $collect | Should -Throw -ExpectedMessage 'GraphResponseValueNotACollection*' -Because 'a scalar value cannot be enumerated into subscriptions'
        }
    }

    Context 'Negative: a subscribed SKU must declare its contract' {

        It 'refuses a subscribed SKU that omits a required member' -ForEach @(
            @{ Member = 'skuId' }
            @{ Member = 'skuPartNumber' }
            @{ Member = 'capabilityStatus' }
            @{ Member = 'servicePlans' }
        ) {
            # Arrange
            $seam = New-SubscribedSkuSeam -Sku @(New-SubscribedSku -Omit @($Member) -ServicePlan @(New-ServicePlan -ServicePlanId $script:ExchangePlanId -ServicePlanName 'EXCHANGE_S_ENTERPRISE'))

            # Act
            $collect = { Get-BaselineTenantServicePlan -GraphRequest $seam }

            # Assert
            $collect | Should -Throw -ExpectedMessage "SubscribedSkuContractViolation*$Member*" -Because "a SKU without '$Member' cannot be judged"
        }

        It 'refuses a SKU capability status outside the Graph vocabulary' {
            # Arrange
            $seam = New-SubscribedSkuSeam -Sku @(New-SubscribedSku -CapabilityStatus 'Frobnicated' -ServicePlan @(New-ServicePlan -ServicePlanId $script:ExchangePlanId -ServicePlanName 'EXCHANGE_S_ENTERPRISE'))

            # Act
            $collect = { Get-BaselineTenantServicePlan -GraphRequest $seam }

            # Assert
            $collect | Should -Throw -ExpectedMessage 'UnknownSkuCapabilityStatus*' -Because 'an unrecognized capability status must never be guessed into an entitlement'
        }
    }

    Context 'Negative: a service plan must declare its contract' {

        It 'refuses a service plan that omits a required member' -ForEach @(
            @{ Member = 'servicePlanId' }
            @{ Member = 'servicePlanName' }
            @{ Member = 'provisioningStatus' }
        ) {
            # Arrange
            $seam = New-SubscribedSkuSeam -Sku @(New-SubscribedSku -ServicePlan @(New-ServicePlan -ServicePlanId $script:ExchangePlanId -ServicePlanName 'EXCHANGE_S_ENTERPRISE' -Omit @($Member)))

            # Act
            $collect = { Get-BaselineTenantServicePlan -GraphRequest $seam }

            # Assert
            $collect | Should -Throw -ExpectedMessage "ServicePlanContractViolation*$Member*" -Because "a service plan without '$Member' cannot be matched by identifier"
        }

        It 'refuses a provisioning status outside the Graph vocabulary' {
            # Arrange
            $seam = New-SubscribedSkuSeam -Sku @(New-SubscribedSku -ServicePlan @(New-ServicePlan -ServicePlanId $script:ExchangePlanId -ServicePlanName 'EXCHANGE_S_ENTERPRISE' -ProvisioningStatus 'Frobnicated'))

            # Act
            $collect = { Get-BaselineTenantServicePlan -GraphRequest $seam }

            # Assert
            $collect | Should -Throw -ExpectedMessage 'UnknownProvisioningStatus*' -Because 'an unrecognized provisioning status must never be guessed into an entitlement'
        }
    }

    Context 'Negative: only an enabled plan on an enabled subscription is entitled' {

        It 'does not report a disabled service plan as enabled' {
            # Arrange
            $seam = New-SubscribedSkuSeam -Sku @(New-SubscribedSku -ServicePlan @(New-ServicePlan -ServicePlanId $script:SafeDocumentsPlanId -ServicePlanName 'SAFEDOCS' -ProvisioningStatus 'Disabled'))

            # Act
            $inventory = Get-BaselineTenantServicePlan -GraphRequest $seam

            # Assert
            $inventory.ServicePlanId | Should -Not -Contain $script:SafeDocumentsPlanId -Because 'an assigned but disabled plan grants nothing'
        }

        It 'does not report a pending service plan as enabled' -ForEach @(
            @{ ProvisioningStatus = 'PendingInput' }
            @{ ProvisioningStatus = 'PendingActivation' }
            @{ ProvisioningStatus = 'PendingProvisioning' }
        ) {
            # Arrange
            $seam = New-SubscribedSkuSeam -Sku @(New-SubscribedSku -ServicePlan @(New-ServicePlan -ServicePlanId $script:SafeDocumentsPlanId -ServicePlanName 'SAFEDOCS' -ProvisioningStatus $ProvisioningStatus))

            # Act
            $inventory = Get-BaselineTenantServicePlan -GraphRequest $seam

            # Assert
            $inventory.ServicePlanId | Should -Not -Contain $script:SafeDocumentsPlanId -Because "a '$ProvisioningStatus' plan is not yet usable"
        }

        It 'does not report a plan as enabled when its subscription is not enabled' -ForEach @(
            @{ CapabilityStatus = 'Suspended' }
            @{ CapabilityStatus = 'Deleted' }
            @{ CapabilityStatus = 'LockedOut' }
        ) {
            # Arrange
            $seam = New-SubscribedSkuSeam -Sku @(New-SubscribedSku -CapabilityStatus $CapabilityStatus -ServicePlan @(New-ServicePlan -ServicePlanId $script:SafeDocumentsPlanId -ServicePlanName 'SAFEDOCS'))

            # Act
            $inventory = Get-BaselineTenantServicePlan -GraphRequest $seam

            # Assert
            $inventory.ServicePlanId | Should -Not -Contain $script:SafeDocumentsPlanId -Because "a plan on a '$CapabilityStatus' subscription grants nothing"
        }

        It 'records why a plan is not enabled rather than dropping it from the inventory' {
            # Arrange
            $seam = New-SubscribedSkuSeam -Sku @(New-SubscribedSku -ServicePlan @(New-ServicePlan -ServicePlanId $script:SafeDocumentsPlanId -ServicePlanName 'SAFEDOCS' -ProvisioningStatus 'Disabled'))

            # Act
            $inventory = Get-BaselineTenantServicePlan -GraphRequest $seam

            # Assert
            Get-PlanState -Inventory $inventory -ServicePlanId $script:SafeDocumentsPlanId | Should -Be @('Disabled') -Because 'the licensing matrix must be able to say why a control is not entitled'
        }

        It 'does not report a plan name as enabled when no instance of that plan is enabled' {
            # Arrange
            $seam = New-SubscribedSkuSeam -Sku @(
                New-SubscribedSku -SkuId '05e9a617-0261-4cee-bb44-138d3ef5d965' -SkuPartNumber 'SPE_E3' -CapabilityStatus 'Enabled' -ServicePlan @(New-ServicePlan -ServicePlanId $script:SafeDocumentsPlanId -ServicePlanName 'SAFEDOCS' -ProvisioningStatus 'Disabled')
                New-SubscribedSku -SkuId '26124093-3d78-432b-b5dc-48bf992543d5' -SkuPartNumber 'IDENTITY_THREAT_PROTECTION' -CapabilityStatus 'Suspended' -ServicePlan @(New-ServicePlan -ServicePlanId $script:SafeDocumentsPlanId -ServicePlanName 'SAFEDOCS')
            )

            # Act
            $inventory = Get-BaselineTenantServicePlan -GraphRequest $seam

            # Assert
            $inventory.ServicePlanName | Should -Not -Contain 'SAFEDOCS' -Because 'two non-enabled occurrences of a plan do not add up to one enabled occurrence'
        }

        It 'reports an empty inventory when the tenant holds no subscription' {
            # Arrange
            $seam = New-SubscribedSkuSeam -Sku @()

            # Act
            $inventory = Get-BaselineTenantServicePlan -GraphRequest $seam

            # Assert
            @($inventory.ServicePlanId).Count | Should -Be 0 -Because 'a tenant with no subscription grants no service plan'
        }
    }

    Context 'Negative: collection stays offline' {

        It 'reaches Graph and Exchange Online only through the injected seam' {
            # Arrange
            $script:TenantCommandInvocation = [System.Collections.Generic.List[string]]::new()
            function global:Connect-MgGraph { $script:TenantCommandInvocation.Add('Connect-MgGraph') }
            function global:Get-MgSubscribedSku { $script:TenantCommandInvocation.Add('Get-MgSubscribedSku') }
            function global:Connect-ExchangeOnline { $script:TenantCommandInvocation.Add('Connect-ExchangeOnline') }
            $seam = New-SubscribedSkuSeam -Sku (New-RepresentativeSubscribedSku)

            # Act
            $null = Get-BaselineTenantServicePlan -GraphRequest $seam

            # Assert
            try {
                $script:TenantCommandInvocation | Should -BeNullOrEmpty -Because 'the collector must never contact a tenant of its own accord'
            }
            finally {
                Remove-Item -Path 'function:global:Connect-MgGraph', 'function:global:Get-MgSubscribedSku', 'function:global:Connect-ExchangeOnline' -ErrorAction SilentlyContinue
            }
        }

        It 'asks the seam for the subscribedSkus resource' {
            # Arrange
            $requested = [System.Collections.Generic.List[string]]::new()
            $seam = { param($Resource) $requested.Add([string]$Resource); return [pscustomobject]@{ value = @() } }.GetNewClosure()

            # Act
            $null = Get-BaselineTenantServicePlan -GraphRequest $seam

            # Assert
            $requested | Should -Be @('subscribedSkus') -Because 'the tenant inventory comes from subscribedSkus and nothing else'
        }
    }

    Context 'Positive: the tenant inventory reports the enabled service plans' {

        It 'reports exactly the deduplicated enabled service plans and the state of every observed plan' {
            # Arrange
            $seam = New-SubscribedSkuSeam -Sku (New-RepresentativeSubscribedSku)

            # Act
            $inventory = Get-BaselineTenantServicePlan -GraphRequest $seam

            # Assert
            $summary = @(
                'Enabled=' + (@($inventory.ServicePlanId) -join ',')
                'Names=' + (@($inventory.ServicePlanName) -join ',')
                'Exchange=' + ((Get-PlanState -Inventory $inventory -ServicePlanId $script:ExchangePlanId) -join '|')
                'Atp=' + ((Get-PlanState -Inventory $inventory -ServicePlanId $script:AtpPlanId) -join '|')
                'ThreatIntelligence=' + ((Get-PlanState -Inventory $inventory -ServicePlanId $script:ThreatIntelligencePlanId) -join '|')
                'SafeDocuments=' + ((Get-PlanState -Inventory $inventory -ServicePlanId $script:SafeDocumentsPlanId) -join '|')
            ) -join '; '

            $summary | Should -Be (@(
                    'Enabled=' + (@($script:ThreatIntelligencePlanId, $script:AtpPlanId, $script:ExchangePlanId | Sort-Object) -join ',')
                    'Names=ATP_ENTERPRISE,EXCHANGE_S_ENTERPRISE,THREAT_INTELLIGENCE'
                    'Exchange=Enabled'
                    'Atp=Enabled|Pending'
                    'ThreatIntelligence=Enabled'
                    'SafeDocuments=Disabled|Suspended'
                ) -join '; ') -Because 'the inventory is the deduplicated set of plans the tenant actually grants, with every observed occurrence still accounted for'
        }
    }
}
