#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph and ExchangeOnlineManagement are not installed and must never be imported.
    # Every tenant inventory, population and per-user entitlement here is canned, exactly as the
    # LIC-002, LIC-005 and LIC-003 collectors would have returned it.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ExchangePlanId = 'efb87545-963c-4e0d-99df-69c6916d9eb0'
    $script:AtpPlanId = 'f20fedf3-f3c3-43c3-8267-2bfdd51c0939'
    $script:SafeDocumentsPlanId = 'bf6f5520-59e3-4f82-974b-7dbbc4fd27c7'

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
        }

        foreach ($name in $Omit) { $member.Remove($name) }

        return [pscustomobject]$member
    }

    # The baseline the preflight reads the SAFEDOCS identifier from. The declared tier is carried
    # only so an operator can see what was expected; it never decides anything here.
    function New-BaselineConfiguration {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [object[]]$RequiredServicePlan,

            [switch]$OmitLicensing,
            [switch]$OmitRequiredServicePlan,
            [switch]$OmitSafeDocuments,
            [switch]$OmitSafeDocumentsIdentifier
        )

        if (-not $PSBoundParameters.ContainsKey('RequiredServicePlan')) {
            $RequiredServicePlan = @(
                New-RequiredServicePlan -ServicePlanId $script:ExchangePlanId -ServicePlanName 'EXCHANGE_S_ENTERPRISE'
                New-RequiredServicePlan -ServicePlanId $script:AtpPlanId -ServicePlanName 'ATP_ENTERPRISE'
            )

            if ($OmitSafeDocumentsIdentifier) {
                $RequiredServicePlan += New-RequiredServicePlan -ServicePlanId $script:SafeDocumentsPlanId -ServicePlanName 'SAFEDOCS' -Omit @('servicePlanId')
            }
            elseif (-not $OmitSafeDocuments) {
                $RequiredServicePlan += New-RequiredServicePlan -ServicePlanId $script:SafeDocumentsPlanId -ServicePlanName 'SAFEDOCS'
            }
        }

        if ($OmitLicensing) { return [pscustomobject]@{ metadata = [pscustomobject]@{ name = 'fixture' } } }

        $licensing = [ordered]@{
            messagingTier  = 'MDO_P2'
            complianceTier = 'E5Compliance'
        }

        if (-not $OmitRequiredServicePlan) { $licensing['requiredServicePlans'] = @($RequiredServicePlan) }

        return [pscustomobject]@{ licensing = [pscustomobject]$licensing }
    }

    # The shape Resolve-BaselineEntitlement returns: one verdict per capability, each naming the
    # service plan it was decided on.
    function New-TenantEntitlement {
        [CmdletBinding()]
        param(
            [switch]$SafeDocumentsEntitled,
            [switch]$OmitSafeDocumentsCapability
        )

        $capability = [System.Collections.Generic.List[object]]::new()
        $capability.Add([pscustomobject]@{
                Name                    = 'AtpPresets'
                RequiredServicePlanName = 'ATP_ENTERPRISE'
                RequiredServicePlanId   = $script:AtpPlanId
                Entitled                = $true
                Reason                  = "'AtpPresets' is entitled because the tenant service plan 'ATP_ENTERPRISE' is enabled."
            })

        if (-not $OmitSafeDocumentsCapability) {
            $capability.Add([pscustomobject]@{
                    Name                    = 'SafeDocuments'
                    RequiredServicePlanName = 'SAFEDOCS'
                    RequiredServicePlanId   = $script:SafeDocumentsPlanId
                    Entitled                = [bool]$SafeDocumentsEntitled
                    Reason                  = if ($SafeDocumentsEntitled) {
                        "'SafeDocuments' is entitled because the tenant service plan 'SAFEDOCS' ($script:SafeDocumentsPlanId) is enabled."
                    }
                    else {
                        "'SafeDocuments' is not entitled because the tenant has no enabled service plan 'SAFEDOCS' ($script:SafeDocumentsPlanId)."
                    }
                })
        }

        return [pscustomobject]@{
            Source        = 'GraphSubscribedSkus'
            Determined    = $true
            Capability    = @($capability)
            SafeDocuments = [bool]$SafeDocumentsEntitled
        }
    }

    # The shape Get-BaselineTargetPopulation returns, reduced to the members the preflight reads.
    function New-PopulationRecipient {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$UserPrincipalName,

            [string]$Classification = 'StandardDomain',
            [string]$ProfileName = 'Standard',
            [bool]$LicensingRequired = $true
        )

        return [pscustomobject]@{
            UserPrincipalName    = $UserPrincipalName
            PrimarySmtpAddress   = $UserPrincipalName
            RecipientTypeDetails = 'UserMailbox'
            Classification       = $Classification
            Profile              = $ProfileName
            InScope              = $true
            LicensingRequired    = $LicensingRequired
            Reason               = 'fixture'
        }
    }

    function New-TargetPopulation {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [AllowEmptyCollection()]
            [object[]]$Recipient,

            [switch]$OmitRecipient
        )

        if (-not $PSBoundParameters.ContainsKey('Recipient')) {
            $Recipient = @(
                New-PopulationRecipient -UserPrincipalName 'analyst@contoso.com'
                New-PopulationRecipient -UserPrincipalName 'director@contoso.com' -Classification 'StrictPriority' -ProfileName 'Strict'
            )
        }

        $member = [ordered]@{
            Recipient       = @($Recipient)
            LicensingTarget = @(@($Recipient) | Where-Object { $_.LicensingRequired } | ForEach-Object { $_.UserPrincipalName })
            Exception       = @()
        }

        if ($OmitRecipient) { $member.Remove('Recipient') }

        return [pscustomobject]$member
    }

    # The shape Get-BaselineTargetEntitlement returns: one verdict per target per required plan.
    function New-Assignment {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$UserPrincipalName,

            [string]$ServicePlanId = $script:SafeDocumentsPlanId,

            [string]$ServicePlanName = 'SAFEDOCS',

            [Parameter(Mandatory)]
            [ValidateSet('Enabled', 'Suspended', 'Disabled', 'NotAssigned')]
            [string]$State
        )

        return [pscustomobject]@{
            UserPrincipalName = $UserPrincipalName
            ServicePlanId     = $ServicePlanId
            ServicePlanName   = $ServicePlanName
            State             = $State
            Entitled          = ($State -eq 'Enabled')
        }
    }

    function New-TargetEntitlement {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [AllowEmptyCollection()]
            [object[]]$Assignment,

            [switch]$OmitAssignment
        )

        if (-not $PSBoundParameters.ContainsKey('Assignment')) {
            $Assignment = @(
                New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'Enabled'
                New-Assignment -UserPrincipalName 'director@contoso.com' -State 'Enabled'
            )
        }

        $member = [ordered]@{
            Source     = 'GraphUserAssignedPlans'
            Assignment = @($Assignment)
        }

        if ($OmitAssignment) { $member.Remove('Assignment') }

        return [pscustomobject]$member
    }

    function Get-TargetRow {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Preflight,

            [Parameter(Mandatory)]
            [string]$UserPrincipalName
        )

        $match = @($Preflight.Target | Where-Object { $_.UserPrincipalName -eq $UserPrincipalName })
        if ($match.Count -ne 1) { return "NoSingleRow($($match.Count))" }

        return '{0}:{1}' -f $match[0].State, $match[0].Entitled
    }

    function Get-PreflightFold {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Preflight
        )

        $row = @($Preflight.Target | ForEach-Object {
                '{0}={1}({2}):{3}:{4}' -f $_.UserPrincipalName, $_.ServicePlanName, $_.ServicePlanId, $_.State, $_.Entitled
            })

        return '{0}|tenant={1}|status={2}|apply={3}|gaps={4}|{5}' -f `
            $Preflight.Source, $Preflight.TenantEntitled, $Preflight.Status, $Preflight.MayApply,
        @($Preflight.Gap).Count, ($row -join ' ')
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'LIC-009-A1 Safe Documents preflight decision' {

    Context 'Negative: the preflight inputs must be usable' {

        It 'refuses a preflight with no configuration' {
            # Arrange
            $noConfiguration = $null

            # Act
            $preflight = { Test-BaselineSafeDocumentsPreflight -Configuration $noConfiguration -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement (New-TargetEntitlement) }

            # Assert
            $preflight | Should -Throw -ExpectedMessage 'ConfigurationRequired*' -Because 'without the baseline nothing declares the service-plan identifier Safe Documents is decided on'
        }

        It 'refuses a configuration that declares no required service plans' {
            # Arrange
            $noRequirement = New-BaselineConfiguration -OmitRequiredServicePlan

            # Act
            $preflight = { Test-BaselineSafeDocumentsPreflight -Configuration $noRequirement -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement (New-TargetEntitlement) }

            # Assert
            $preflight | Should -Throw -ExpectedMessage 'LicensingRequirementMissing*' -Because 'an empty requirement set cannot be told from a tenant that holds everything'
        }

        It 'refuses a configuration that declares no SAFEDOCS service plan' {
            # Arrange
            $noSafeDocuments = New-BaselineConfiguration -OmitSafeDocuments

            # Act
            $preflight = { Test-BaselineSafeDocumentsPreflight -Configuration $noSafeDocuments -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement (New-TargetEntitlement) }

            # Assert
            $preflight | Should -Throw -ExpectedMessage 'SafeDocumentsServicePlanUndeclared*SAFEDOCS*' -Because 'a requirement nobody declared cannot have been checked against the tenant'
        }

        It 'refuses a SAFEDOCS declaration that carries no service-plan identifier' {
            # Arrange
            $unidentified = New-BaselineConfiguration -OmitSafeDocumentsIdentifier

            # Act
            $preflight = { Test-BaselineSafeDocumentsPreflight -Configuration $unidentified -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement (New-TargetEntitlement) }

            # Assert
            $preflight | Should -Throw -ExpectedMessage 'RequiredServicePlanContractViolation*servicePlanId*' -Because 'assignedPlans carries no display name, so a requirement without an identifier can never be matched'
        }

        It 'refuses a preflight with no tenant entitlement' {
            # Arrange
            $noEntitlement = $null

            # Act
            $preflight = { Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement $noEntitlement -TargetPopulation (New-TargetPopulation) -TargetEntitlement (New-TargetEntitlement) }

            # Assert
            $preflight | Should -Throw -ExpectedMessage 'EntitlementRequired*' -Because 'a tenant verdict that was never collected must never be assumed'
        }

        It 'refuses a tenant entitlement that carries no Safe Documents verdict' {
            # Arrange
            $noVerdict = New-TenantEntitlement -OmitSafeDocumentsCapability

            # Act
            $preflight = { Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement $noVerdict -TargetPopulation (New-TargetPopulation) -TargetEntitlement (New-TargetEntitlement) }

            # Assert
            $preflight | Should -Throw -ExpectedMessage 'SafeDocumentsCapabilityMissing*' -Because 'an entitlement silent about Safe Documents is not an entitlement that cleared it'
        }

        It 'refuses a preflight with no target population' {
            # Arrange
            $noPopulation = $null

            # Act
            $preflight = { Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation $noPopulation -TargetEntitlement (New-TargetEntitlement) }

            # Assert
            $preflight | Should -Throw -ExpectedMessage 'TargetPopulationRequired*' -Because 'a preflight run over nobody reports every target covered'
        }

        It 'refuses a population that does not declare its recipients' {
            # Arrange
            $notAPopulation = New-TargetPopulation -OmitRecipient

            # Act
            $preflight = { Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation $notAPopulation -TargetEntitlement (New-TargetEntitlement) }

            # Assert
            $preflight | Should -Throw -ExpectedMessage 'TargetPopulationContractViolation*Recipient*' -Because 'only a classified population carries the licensing decision each row is scoped by'
        }

        It 'refuses a preflight with no target entitlement' {
            # Arrange
            $noTargetEntitlement = $null

            # Act
            $preflight = { Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement $noTargetEntitlement }

            # Assert
            $preflight | Should -Throw -ExpectedMessage 'TargetEntitlementRequired*' -Because 'without the per-user verdicts the preflight has no target state to report'
        }

        It 'refuses a target entitlement that does not declare its assignments' {
            # Arrange
            $notAnEntitlement = New-TargetEntitlement -OmitAssignment

            # Act
            $preflight = { Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement $notAnEntitlement }

            # Assert
            $preflight | Should -Throw -ExpectedMessage 'TargetEntitlementContractViolation*Assignment*' -Because 'a summary verdict is not the per-user evidence a target row is built from'
        }

        It 'refuses a population that holds no licensing target at all' {
            # Arrange
            $noTarget = New-TargetPopulation -Recipient @(
                New-PopulationRecipient -UserPrincipalName 'room@contoso.com' -Classification 'ResourceMailbox' -LicensingRequired $false
            )

            # Act
            $preflight = { Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation $noTarget -TargetEntitlement (New-TargetEntitlement) }

            # Assert
            $preflight | Should -Throw -ExpectedMessage 'LicensingTargetRequired*' -Because 'a preflight with nobody to cover would clear Safe Documents vacuously'
        }

        It 'refuses a target that has no recorded SAFEDOCS assignment' {
            # Arrange
            $unrecorded = New-TargetEntitlement -Assignment @(
                New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'Enabled'
            )

            # Act
            $preflight = { Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement $unrecorded }

            # Assert
            $preflight | Should -Throw -ExpectedMessage "TargetEntitlementIncomplete*director@contoso.com*" -Because 'a target that reads covered because nobody looked cannot be told from one that is genuinely covered'
        }
    }

    Context 'Negative: Safe Documents is never cleared without every target' {

        It 'does not permit Safe Documents when the tenant holds no enabled SAFEDOCS plan' {
            # Arrange
            $unlicensedTenant = New-TenantEntitlement

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement $unlicensedTenant -TargetPopulation (New-TargetPopulation) -TargetEntitlement (New-TargetEntitlement -Assignment @(
                    New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'NotAssigned'
                    New-Assignment -UserPrincipalName 'director@contoso.com' -State 'NotAssigned'
                ))

            # Assert
            $preflight.MayApply | Should -BeFalse -Because 'a tenant without the SAFEDOCS plan has no Safe Documents to apply'
        }

        It 'does not report a preflight failure when neither the tenant nor any target holds SAFEDOCS' {
            # Arrange
            $unlicensedTenant = New-TenantEntitlement

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement $unlicensedTenant -TargetPopulation (New-TargetPopulation) -TargetEntitlement (New-TargetEntitlement -Assignment @(
                    New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'NotAssigned'
                    New-Assignment -UserPrincipalName 'director@contoso.com' -State 'NotAssigned'
                ))

            # Assert
            $preflight.Status | Should -Be 'NotEntitled' -Because 'a capability nobody in the tenant holds is absent, not misconfigured'
        }

        It 'does not permit Safe Documents when the tenant is entitled but one target is not' {
            # Arrange
            $oneGap = New-TargetEntitlement -Assignment @(
                New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'Enabled'
                New-Assignment -UserPrincipalName 'director@contoso.com' -State 'NotAssigned'
            )

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement $oneGap

            # Assert
            $preflight.MayApply | Should -BeFalse -Because 'Safe Documents applied over a target that holds no SAFEDOCS plan is an unlicensed configuration'
        }

        It 'reports a tenant entitled over an uncovered target as a preflight failure' {
            # Arrange
            $oneGap = New-TargetEntitlement -Assignment @(
                New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'Enabled'
                New-Assignment -UserPrincipalName 'director@contoso.com' -State 'NotAssigned'
            )

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement $oneGap

            # Assert
            $preflight.Status | Should -Be 'Fail' -Because 'a tenant that holds the plan while a target does not is a licensing mismatch the operator must resolve'
        }

        It 'reports a target holding SAFEDOCS in a tenant that does not as a preflight failure' {
            # Arrange
            $unlicensedTenant = New-TenantEntitlement

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement $unlicensedTenant -TargetPopulation (New-TargetPopulation) -TargetEntitlement (New-TargetEntitlement -Assignment @(
                    New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'Enabled'
                    New-Assignment -UserPrincipalName 'director@contoso.com' -State 'NotAssigned'
                ))

            # Assert
            $preflight.Status | Should -Be 'Fail' -Because 'a tenant verdict that contradicts the per-user evidence is a mismatch, not an absence'
        }

        It 'does not treat a suspended SAFEDOCS plan as an entitled target' {
            # Arrange
            $suspended = New-TargetEntitlement -Assignment @(
                New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'Enabled'
                New-Assignment -UserPrincipalName 'director@contoso.com' -State 'Suspended'
            )

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement $suspended

            # Assert
            Get-TargetRow -Preflight $preflight -UserPrincipalName 'director@contoso.com' |
                Should -Be 'Suspended:False' -Because 'a suspended plan is not a plan the target can use'
        }

        It 'does not treat a disabled SAFEDOCS plan as an entitled target' {
            # Arrange
            $disabled = New-TargetEntitlement -Assignment @(
                New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'Enabled'
                New-Assignment -UserPrincipalName 'director@contoso.com' -State 'Disabled'
            )

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement $disabled

            # Assert
            Get-TargetRow -Preflight $preflight -UserPrincipalName 'director@contoso.com' |
                Should -Be 'Disabled:False' -Because 'a plan that is present but disabled grants the target nothing'
        }

        It 'does not treat an unassigned SAFEDOCS plan as an entitled target' {
            # Arrange
            $unassigned = New-TargetEntitlement -Assignment @(
                New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'Enabled'
                New-Assignment -UserPrincipalName 'director@contoso.com' -State 'NotAssigned'
            )

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement $unassigned

            # Assert
            Get-TargetRow -Preflight $preflight -UserPrincipalName 'director@contoso.com' |
                Should -Be 'NotAssigned:False' -Because 'a target who was never assigned the plan is the exact case the preflight exists to catch'
        }

        It 'does not match a target assignment by service-plan name instead of identifier' {
            # Arrange
            $misnamed = New-TargetEntitlement -Assignment @(
                New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'Enabled'
                New-Assignment -UserPrincipalName 'director@contoso.com' -ServicePlanId $script:AtpPlanId -ServicePlanName 'SAFEDOCS' -State 'Enabled'
                New-Assignment -UserPrincipalName 'director@contoso.com' -State 'Disabled'
            )

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement $misnamed

            # Assert
            Get-TargetRow -Preflight $preflight -UserPrincipalName 'director@contoso.com' |
                Should -Be 'Disabled:False' -Because 'a bundle carrying the SAFEDOCS display name under another identifier is not the SAFEDOCS plan'
        }

        It 'does not report a pass while any target gap exists' {
            # Arrange
            $oneGap = New-TargetEntitlement -Assignment @(
                New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'Enabled'
                New-Assignment -UserPrincipalName 'director@contoso.com' -State 'Suspended'
            )

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement $oneGap

            # Assert
            @($preflight.Gap).Count | Should -Be 1 -Because 'the uncovered target must survive into the gap set rather than be folded into a tenant-wide verdict'
        }

        It 'does not record a gap without naming the target, the plan and the observed state' {
            # Arrange
            $oneGap = New-TargetEntitlement -Assignment @(
                New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'Enabled'
                New-Assignment -UserPrincipalName 'director@contoso.com' -State 'Suspended'
            )

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement $oneGap

            # Assert
            [string]@($preflight.Gap)[0].Reason |
                Should -BeLike "*director@contoso.com*SAFEDOCS*$script:SafeDocumentsPlanId*Suspended*" -Because 'an operator cannot act on a gap that does not name the user, the plan and what was observed'
        }

        It 'does not fold one target assignment onto another target' {
            # Arrange
            $onlyAnalystCovered = New-TargetEntitlement -Assignment @(
                New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'Enabled'
                New-Assignment -UserPrincipalName 'director@contoso.com' -State 'NotAssigned'
            )

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement $onlyAnalystCovered

            # Assert
            @($preflight.Gap | ForEach-Object { $_.UserPrincipalName }) -join ',' |
                Should -Be 'director@contoso.com' -Because 'one target holding the plan must never cover a different target who does not'
        }

        It 'does not treat a differently-cased user principal name as a different target' {
            # Arrange
            $mixedCase = New-TargetPopulation -Recipient @(
                New-PopulationRecipient -UserPrincipalName 'Director@Contoso.com' -Classification 'StrictPriority' -ProfileName 'Strict'
            )

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation $mixedCase -TargetEntitlement (New-TargetEntitlement -Assignment @(
                    New-Assignment -UserPrincipalName 'director@contoso.com' -State 'Disabled'
                ))

            # Assert
            Get-TargetRow -Preflight $preflight -UserPrincipalName 'Director@Contoso.com' |
                Should -Be 'Disabled:False' -Because 'a user principal name is case-insensitive, so casing must neither hide a gap nor invent a missing record'
        }

        It 'does not demand a SAFEDOCS assignment from a recipient that is not a licensing target' {
            # Arrange
            $withResourceMailbox = New-TargetPopulation -Recipient @(
                New-PopulationRecipient -UserPrincipalName 'analyst@contoso.com'
                New-PopulationRecipient -UserPrincipalName 'room@contoso.com' -Classification 'ResourceMailbox' -LicensingRequired $false
            )

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation $withResourceMailbox -TargetEntitlement (New-TargetEntitlement -Assignment @(
                    New-Assignment -UserPrincipalName 'analyst@contoso.com' -State 'Enabled'
                ))

            # Assert
            @($preflight.Target | ForEach-Object { $_.UserPrincipalName }) |
                Should -Not -Contain 'room@contoso.com' -Because 'a resource mailbox holds no per-user licence, so demanding one would fail the gate on a fact that is not a finding'
        }
    }

    Context 'Negative: the preflight stays offline' {

        # The stubs are global, so cleanup must survive an Act that throws; otherwise a failing
        # run leaks them into the session and every later test resolves them instead of failing.
        AfterEach {
            Remove-Item -Path 'function:global:Connect-MgGraph', 'function:global:Get-MgUser', 'function:global:Get-MgSubscribedSku', 'function:global:Get-AtpPolicyForO365' -ErrorAction SilentlyContinue
        }

        It 'decides Safe Documents only from the evidence it was handed' {
            # Arrange
            $script:PreflightCommandInvocation = [System.Collections.Generic.List[string]]::new()
            function global:Connect-MgGraph { $script:PreflightCommandInvocation.Add('Connect-MgGraph') }
            function global:Get-MgUser { $script:PreflightCommandInvocation.Add('Get-MgUser') }
            function global:Get-MgSubscribedSku { $script:PreflightCommandInvocation.Add('Get-MgSubscribedSku') }
            function global:Get-AtpPolicyForO365 { $script:PreflightCommandInvocation.Add('Get-AtpPolicyForO365') }

            # Act
            $null = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation (New-TargetPopulation) -TargetEntitlement (New-TargetEntitlement)

            # Assert
            $script:PreflightCommandInvocation | Should -BeNullOrEmpty -Because 'the preflight is a decision over collected evidence and must never collect more of its own accord'
        }
    }

    Context 'Positive: a fully covered tenant clears Safe Documents' {

        It 'yields one entitled row per licensing target and a verdict that permits Safe Documents' {
            # Arrange
            $coveredPopulation = New-TargetPopulation -Recipient @(
                New-PopulationRecipient -UserPrincipalName 'analyst@contoso.com'
                New-PopulationRecipient -UserPrincipalName 'director@contoso.com' -Classification 'StrictPriority' -ProfileName 'Strict'
                New-PopulationRecipient -UserPrincipalName 'room@contoso.com' -Classification 'ResourceMailbox' -LicensingRequired $false
            )

            # Act
            $preflight = Test-BaselineSafeDocumentsPreflight -Configuration (New-BaselineConfiguration) -Entitlement (New-TenantEntitlement -SafeDocumentsEntitled) -TargetPopulation $coveredPopulation -TargetEntitlement (New-TargetEntitlement)

            # Assert
            Get-PreflightFold -Preflight $preflight |
                Should -Be ("BaselineSafeDocumentsPreflight|tenant=True|status=Pass|apply=True|gaps=0|" +
                    "analyst@contoso.com=SAFEDOCS($script:SafeDocumentsPlanId):Enabled:True " +
                    "director@contoso.com=SAFEDOCS($script:SafeDocumentsPlanId):Enabled:True") -Because 'Safe Documents may be applied only when the tenant and every licensing target hold an enabled SAFEDOCS plan'
        }
    }
}
