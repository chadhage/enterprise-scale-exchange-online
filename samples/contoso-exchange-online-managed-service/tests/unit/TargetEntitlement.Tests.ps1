#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph is not installed and must never be imported. Every user response is canned
    # and handed to the collector through the injected request seam.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ExchangePlanId = 'efb87545-963c-4e0d-99df-69c6916d9eb0'
    $script:AtpPlanId = 'f20fedf3-f3c3-43c3-8267-2bfdd51c0939'
    $script:ThreatIntelligencePlanId = '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'
    $script:SafeDocumentsPlanId = 'bf6f5520-59e3-4f82-974b-7dbbc4fd27c7'

    # The Safe Documents plan is required in its own right, exactly as the shipped baseline
    # declares it, so it can never be inferred from the Defender entries beside it.
    $script:RequiredServicePlan = @(
        [pscustomobject]@{ servicePlanId = $script:ExchangePlanId; servicePlanName = 'EXCHANGE_S_ENTERPRISE' }
        [pscustomobject]@{ servicePlanId = $script:AtpPlanId; servicePlanName = 'ATP_ENTERPRISE' }
        [pscustomobject]@{ servicePlanId = $script:ThreatIntelligencePlanId; servicePlanName = 'THREAT_INTELLIGENCE' }
        [pscustomobject]@{ servicePlanId = $script:SafeDocumentsPlanId; servicePlanName = 'SAFEDOCS' }
    )

    $script:PriorityUser = 'priority.user@contoso.example'
    $script:StandardUser = 'standard.user@contoso.example'

    function New-AssignedPlan {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ServicePlanId,

            [string]$CapabilityStatus = 'Enabled',
            [string]$Service = 'exchange',
            [string[]]$Omit = @()
        )

        $member = [ordered]@{
            servicePlanId    = $ServicePlanId
            capabilityStatus = $CapabilityStatus
            service          = $Service
            assignedDateTime = '2026-01-04T00:00:00Z'
        }

        foreach ($name in $Omit) { $member.Remove($name) }

        return [pscustomobject]$member
    }

    # Defender for Office 365 Plan 2 without the Safe Documents service plan. This is the licence
    # shape the critical defect misreads as entitled to Safe Documents.
    function New-DefenderPlan2AssignedPlan {
        [CmdletBinding()]
        param()

        return @(
            New-AssignedPlan -ServicePlanId $script:ExchangePlanId
            New-AssignedPlan -ServicePlanId $script:AtpPlanId
            New-AssignedPlan -ServicePlanId $script:ThreatIntelligencePlanId
        )
    }

    function New-FullyLicensedAssignedPlan {
        [CmdletBinding()]
        param()

        return @(New-DefenderPlan2AssignedPlan) + @(New-AssignedPlan -ServicePlanId $script:SafeDocumentsPlanId)
    }

    function New-UserSeam {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [hashtable]$ResponseByUser
        )

        $captured = $ResponseByUser
        return {
            param($Resource)

            foreach ($key in $captured.Keys) {
                if ($Resource -like "*$key*") { return $captured[$key] }
            }

            return $null
        }.GetNewClosure()
    }

    function New-AssignedPlanSeam {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$UserPrincipalName,

            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]]$AssignedPlan
        )

        return New-UserSeam -ResponseByUser @{ $UserPrincipalName = [pscustomobject]@{ userPrincipalName = $UserPrincipalName; assignedPlans = @($AssignedPlan) } }
    }

    function Get-PlanVerdict {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Entitlement,

            [Parameter(Mandatory)]
            [string]$UserPrincipalName,

            [Parameter(Mandatory)]
            [string]$ServicePlanId
        )

        $match = @($Entitlement.Assignment | Where-Object { $_.UserPrincipalName -eq $UserPrincipalName -and $_.ServicePlanId -eq $ServicePlanId })
        if ($match.Count -ne 1) { return "NoSingleVerdict($($match.Count))" }

        return '{0}:{1}' -f $match[0].State, $match[0].Entitled
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'LIC-003-A targeted-user service-plan entitlement' {

    Context 'Negative: the evaluation inputs must be usable' {

        It 'refuses to evaluate with no target' {
            # Arrange
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan (New-FullyLicensedAssignedPlan)

            # Act
            $evaluate = { Get-BaselineTargetEntitlement -UserPrincipalName @() -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam }

            # Assert
            $evaluate | Should -Throw -ExpectedMessage 'TargetRequired*' -Because 'an empty target population must never be read as a population that is fully entitled'
        }

        It 'refuses a target that is not a user principal name' {
            # Arrange
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan (New-FullyLicensedAssignedPlan)

            # Act
            $evaluate = { Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser, '   ') -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam }

            # Assert
            $evaluate | Should -Throw -ExpectedMessage 'TargetNotAUserPrincipalName*' -Because 'a blank target cannot be looked up and must not be skipped silently'
        }

        It 'refuses to evaluate with no required service plan' {
            # Arrange
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan (New-FullyLicensedAssignedPlan)

            # Act
            $evaluate = { Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan @() -GraphRequest $seam }

            # Assert
            $evaluate | Should -Throw -ExpectedMessage 'RequiredServicePlanMissing*' -Because 'an empty requirement list would declare every user entitled to everything'
        }

        It 'refuses a required service plan that carries no service-plan identifier' {
            # Arrange
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan (New-FullyLicensedAssignedPlan)
            $nameOnlyRequirement = @([pscustomobject]@{ servicePlanName = 'SAFEDOCS' })

            # Act
            $evaluate = { Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $nameOnlyRequirement -GraphRequest $seam }

            # Assert
            $evaluate | Should -Throw -ExpectedMessage 'RequiredServicePlanContractViolation*servicePlanId*' -Because 'assignedPlans carries no service-plan name, so a name-only requirement can never be evaluated'
        }

        It 'refuses to evaluate without a Graph request seam' {
            # Arrange
            $absentSeam = $null

            # Act
            $evaluate = { Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $absentSeam }

            # Assert
            $evaluate | Should -Throw -ExpectedMessage 'GraphRequestRequired*' -Because 'entitlement must never be assumed when Graph cannot be reached'
        }
    }

    Context 'Negative: the user response must be usable' {

        It 'refuses a null user response' {
            # Arrange
            $seam = New-UserSeam -ResponseByUser @{}

            # Act
            $evaluate = { Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam }

            # Assert
            $evaluate | Should -Throw -ExpectedMessage 'GraphResponseMissing*' -Because 'a target Graph cannot return is an error, not an unlicensed user'
        }

        It 'refuses a user response that declares no assigned plans' {
            # Arrange
            $seam = New-UserSeam -ResponseByUser @{ $script:PriorityUser = [pscustomobject]@{ userPrincipalName = $script:PriorityUser } }

            # Act
            $evaluate = { Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam }

            # Assert
            $evaluate | Should -Throw -ExpectedMessage 'GraphResponseContractViolation*assignedPlans*' -Because 'a response missing assignedPlans is unreadable, not empty'
        }

        It 'refuses assigned plans that are not a collection' {
            # Arrange
            $seam = New-UserSeam -ResponseByUser @{ $script:PriorityUser = [pscustomobject]@{ userPrincipalName = $script:PriorityUser; assignedPlans = 'SAFEDOCS' } }

            # Act
            $evaluate = { Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam }

            # Assert
            $evaluate | Should -Throw -ExpectedMessage 'AssignedPlansNotACollection*' -Because 'a scalar cannot be enumerated into plan assignments'
        }

        It 'refuses an assigned plan that omits a required member' -ForEach @(
            @{ Member = 'servicePlanId' }
            @{ Member = 'capabilityStatus' }
        ) {
            # Arrange
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan @(New-AssignedPlan -ServicePlanId $script:SafeDocumentsPlanId -Omit @($Member))

            # Act
            $evaluate = { Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam }

            # Assert
            $evaluate | Should -Throw -ExpectedMessage "AssignedPlanContractViolation*$Member*" -Because "an assigned plan without '$Member' cannot be judged"
        }

        It 'refuses a capability status outside the Graph vocabulary' {
            # Arrange
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan @(New-AssignedPlan -ServicePlanId $script:SafeDocumentsPlanId -CapabilityStatus 'Frobnicated')

            # Act
            $evaluate = { Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam }

            # Assert
            $evaluate | Should -Throw -ExpectedMessage 'UnknownAssignedPlanCapabilityStatus*' -Because 'an unrecognized capability status must never be guessed into an entitlement'
        }
    }

    Context 'Negative: Safe Documents is entitled only by an enabled SAFEDOCS plan' {

        It 'does not entitle Safe Documents for a user holding Defender for Office 365 Plan 2 without SAFEDOCS' {
            # Arrange
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan (New-DefenderPlan2AssignedPlan)

            # Act
            $entitlement = Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam

            # Assert
            Get-PlanVerdict -Entitlement $entitlement -UserPrincipalName $script:PriorityUser -ServicePlanId $script:SafeDocumentsPlanId |
                Should -Be 'NotAssigned:False' -Because 'Safe Documents is granted by the SAFEDOCS service plan, and Defender for Office 365 Plan 2 does not carry it'
        }

        It 'still entitles the Defender plans the same user does hold' {
            # Arrange
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan (New-DefenderPlan2AssignedPlan)

            # Act
            $entitlement = Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam

            # Assert
            Get-PlanVerdict -Entitlement $entitlement -UserPrincipalName $script:PriorityUser -ServicePlanId $script:ThreatIntelligencePlanId |
                Should -Be 'Enabled:True' -Because 'a missing Safe Documents plan must not suppress the entitlements the user genuinely holds'
        }

        It 'reports the whole target as not entitled when SAFEDOCS is absent' {
            # Arrange
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan (New-DefenderPlan2AssignedPlan)

            # Act
            $entitlement = Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam

            # Assert
            $entitlement.Entitled | Should -BeFalse -Because 'one missing required service plan is enough to stop the licensing gate'
        }

        It 'names the missing service plan' {
            # Arrange
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan (New-DefenderPlan2AssignedPlan)

            # Act
            $entitlement = Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam

            # Assert
            @($entitlement.Missing | ForEach-Object { $_.ServicePlanName }) | Should -Be @('SAFEDOCS') -Because 'the operator must be told which plan to buy, not merely that something is missing'
        }

        It 'does not entitle a SAFEDOCS plan that is assigned but not enabled' -ForEach @(
            @{ CapabilityStatus = 'Suspended'; Expected = 'Suspended:False' }
            @{ CapabilityStatus = 'Deleted'; Expected = 'Disabled:False' }
        ) {
            # Arrange
            $assignedPlan = @(New-DefenderPlan2AssignedPlan) + @(New-AssignedPlan -ServicePlanId $script:SafeDocumentsPlanId -CapabilityStatus $CapabilityStatus)
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan $assignedPlan

            # Act
            $entitlement = Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam

            # Assert
            Get-PlanVerdict -Entitlement $entitlement -UserPrincipalName $script:PriorityUser -ServicePlanId $script:SafeDocumentsPlanId |
                Should -Be $Expected -Because "an assigned but '$CapabilityStatus' plan grants nothing"
        }

        It 'does not match a required plan by a near-miss identifier' {
            # Arrange
            $nearMissPlanId = $script:SafeDocumentsPlanId -replace '^bf6f5520', 'bf6f5521'
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan (@(New-DefenderPlan2AssignedPlan) + @(New-AssignedPlan -ServicePlanId $nearMissPlanId))

            # Act
            $entitlement = Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam

            # Assert
            Get-PlanVerdict -Entitlement $entitlement -UserPrincipalName $script:PriorityUser -ServicePlanId $script:SafeDocumentsPlanId |
                Should -Be 'NotAssigned:False' -Because 'a service plan is matched on its exact identifier and nothing else'
        }

        It 'does not match a required plan by the service name beside it' {
            # Arrange
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan (@(New-DefenderPlan2AssignedPlan) + @(New-AssignedPlan -ServicePlanId $script:AtpPlanId -Service 'SafeDocs'))

            # Act
            $entitlement = Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam

            # Assert
            Get-PlanVerdict -Entitlement $entitlement -UserPrincipalName $script:PriorityUser -ServicePlanId $script:SafeDocumentsPlanId |
                Should -Be 'NotAssigned:False' -Because 'the service label on an assignment is not a service-plan identifier'
        }
    }

    Context 'Negative: entitlement is decided per target' {

        It 'does not extend one target entitlement to another target' {
            # Arrange
            $seam = New-UserSeam -ResponseByUser @{
                $script:PriorityUser = [pscustomobject]@{ userPrincipalName = $script:PriorityUser; assignedPlans = @(New-FullyLicensedAssignedPlan) }
                $script:StandardUser = [pscustomobject]@{ userPrincipalName = $script:StandardUser; assignedPlans = @(New-DefenderPlan2AssignedPlan) }
            }

            # Act
            $entitlement = Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser, $script:StandardUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam

            # Assert
            Get-PlanVerdict -Entitlement $entitlement -UserPrincipalName $script:StandardUser -ServicePlanId $script:SafeDocumentsPlanId |
                Should -Be 'NotAssigned:False' -Because 'a licensed colleague does not license this user'
        }

        It 'reports the target that is short of a required plan' {
            # Arrange
            $seam = New-UserSeam -ResponseByUser @{
                $script:PriorityUser = [pscustomobject]@{ userPrincipalName = $script:PriorityUser; assignedPlans = @(New-FullyLicensedAssignedPlan) }
                $script:StandardUser = [pscustomobject]@{ userPrincipalName = $script:StandardUser; assignedPlans = @(New-DefenderPlan2AssignedPlan) }
            }

            # Act
            $entitlement = Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser, $script:StandardUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam

            # Assert
            @($entitlement.Missing | ForEach-Object { $_.UserPrincipalName }) | Should -Be @($script:StandardUser) -Because 'the licensing matrix must name who is short, not only what is short'
        }
    }

    Context 'Negative: evaluation stays offline' {

        It 'reaches Graph and Exchange Online only through the injected seam' {
            # Arrange
            $script:TargetCommandInvocation = [System.Collections.Generic.List[string]]::new()
            function global:Connect-MgGraph { $script:TargetCommandInvocation.Add('Connect-MgGraph') }
            function global:Get-MgUser { $script:TargetCommandInvocation.Add('Get-MgUser') }
            function global:Get-Mailbox { $script:TargetCommandInvocation.Add('Get-Mailbox') }
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan (New-FullyLicensedAssignedPlan)

            # Act
            $null = Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam

            # Assert
            try {
                $script:TargetCommandInvocation | Should -BeNullOrEmpty -Because 'the evaluator must never contact a tenant of its own accord'
            }
            finally {
                Remove-Item -Path 'function:global:Connect-MgGraph', 'function:global:Get-MgUser', 'function:global:Get-Mailbox' -ErrorAction SilentlyContinue
            }
        }

        It 'asks the seam for each target exactly once' {
            # Arrange
            $requested = [System.Collections.Generic.List[string]]::new()
            $fullyLicensed = @(New-FullyLicensedAssignedPlan)
            $seam = {
                param($Resource)

                $requested.Add([string]$Resource)
                return [pscustomobject]@{ assignedPlans = $fullyLicensed }
            }.GetNewClosure()

            # Act
            $null = Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser, $script:StandardUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam

            # Assert
            @($requested) | Should -Be @("users/$($script:PriorityUser)", "users/$($script:StandardUser)") -Because 'each target is read once, by user principal name'
        }
    }

    Context 'Positive: a fully licensed target is entitled to every required plan' {

        It 'reports every required service plan enabled and entitled, Safe Documents on its own identifier' {
            # Arrange
            $seam = New-AssignedPlanSeam -UserPrincipalName $script:PriorityUser -AssignedPlan (New-FullyLicensedAssignedPlan)

            # Act
            $entitlement = Get-BaselineTargetEntitlement -UserPrincipalName @($script:PriorityUser) -RequiredServicePlan $script:RequiredServicePlan -GraphRequest $seam

            # Assert
            $summary = @(
                'Entitled=' + $entitlement.Entitled
                'Missing=' + @($entitlement.Missing).Count
                'Exchange=' + (Get-PlanVerdict -Entitlement $entitlement -UserPrincipalName $script:PriorityUser -ServicePlanId $script:ExchangePlanId)
                'Atp=' + (Get-PlanVerdict -Entitlement $entitlement -UserPrincipalName $script:PriorityUser -ServicePlanId $script:AtpPlanId)
                'ThreatIntelligence=' + (Get-PlanVerdict -Entitlement $entitlement -UserPrincipalName $script:PriorityUser -ServicePlanId $script:ThreatIntelligencePlanId)
                'SafeDocuments=' + (Get-PlanVerdict -Entitlement $entitlement -UserPrincipalName $script:PriorityUser -ServicePlanId $script:SafeDocumentsPlanId)
            ) -join '; '

            $summary | Should -Be (@(
                    'Entitled=True'
                    'Missing=0'
                    'Exchange=Enabled:True'
                    'Atp=Enabled:True'
                    'ThreatIntelligence=Enabled:True'
                    'SafeDocuments=Enabled:True'
                ) -join '; ') -Because 'a target holding every required plan with an enabled capability status is entitled to every required plan'
        }
    }
}
