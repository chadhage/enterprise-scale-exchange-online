#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement and Microsoft.Graph are not installed and must never be imported.
    # The population, the controls and the entitlement are all canned, exactly as LIC-005 and
    # LIC-003 hand them over.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:PriorityUser = 'priority.user@contoso.example'
    $script:StandardUser = 'standard.user@contoso.example'
    $script:SharedMailbox = 'shared.mailbox@contoso.example'
    $script:ExcludedUser = 'excluded.user@contoso.example'

    $script:AtpPlanId = '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'
    $script:SafeDocsPlanId = '3d957427-ecdc-4df2-aacd-01cc9d519da8'
    $script:MdoP2PlanId = '8e0c0a52-6a6c-4d40-8370-dd62790dcd71'

    function New-Recipient {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$UserPrincipalName,

            [string]$RecipientProfile = 'Standard',
            [bool]$LicensingRequired = $true
        )

        return [pscustomobject]@{
            UserPrincipalName = $UserPrincipalName
            Profile           = $RecipientProfile
            LicensingRequired = $LicensingRequired
        }
    }

    # The licensing targets are the priority user and the standard user. The shared mailbox and the
    # explicit exclusion are carried so the matrix can be caught emitting rows for them.
    function New-Population {
        [CmdletBinding()]
        param([object[]]$Recipient)

        if (-not $PSBoundParameters.ContainsKey('Recipient')) {
            $Recipient = @(
                New-Recipient -UserPrincipalName $script:PriorityUser -RecipientProfile 'Strict'
                New-Recipient -UserPrincipalName $script:StandardUser -RecipientProfile 'Standard'
                New-Recipient -UserPrincipalName $script:SharedMailbox -RecipientProfile 'Standard' -LicensingRequired $false
                New-Recipient -UserPrincipalName $script:ExcludedUser -RecipientProfile 'None' -LicensingRequired $false
            )
        }

        return [pscustomobject]@{ Recipient = @($Recipient) }
    }

    function New-Control {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ControlId,

            [string[]]$ApplicableProfile = @('Standard', 'Strict'),
            [object[]]$RequiredServicePlan = @(),
            [string[]]$Omit = @()
        )

        $record = [ordered]@{
            controlId           = $ControlId
            applicableProfiles  = @($ApplicableProfile)
            requiredServicePlan = @($RequiredServicePlan)
        }

        foreach ($name in $Omit) { $record.Remove($name) }

        return [pscustomobject]$record
    }

    function New-RequiredPlan {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$ServicePlanId,

            [string]$ServicePlanName = 'ATP_ENTERPRISE'
        )

        return [pscustomobject]@{ servicePlanId = $ServicePlanId; servicePlanName = $ServicePlanName }
    }

    # MDO-001 needs ATP for every target, MDO-006 needs SAFEDOCS for every target, and EXO-002
    # needs no service plan at all, which is why a control is allowed to require nothing.
    function New-ControlSet {
        [CmdletBinding()]
        param()

        return @(
            New-Control -ControlId 'MDO-PRESET' -RequiredServicePlan @(New-RequiredPlan -ServicePlanId $script:AtpPlanId -ServicePlanName 'ATP_ENTERPRISE')
            New-Control -ControlId 'MDO-SAFEDOCS' -ApplicableProfile @('Strict') -RequiredServicePlan @(New-RequiredPlan -ServicePlanId $script:SafeDocsPlanId -ServicePlanName 'SAFEDOCS')
            New-Control -ControlId 'EXO-SMTPAUTH'
        )
    }

    function New-Assignment {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$UserPrincipalName,

            [Parameter(Mandatory)]
            [string]$ServicePlanId,

            [string]$ServicePlanName = 'ATP_ENTERPRISE',
            [string]$State = 'Enabled',
            [string[]]$Omit = @()
        )

        $record = [ordered]@{
            UserPrincipalName = $UserPrincipalName
            ServicePlanId     = $ServicePlanId
            ServicePlanName   = $ServicePlanName
            State             = $State
            Entitled          = ($State -eq 'Enabled')
        }

        foreach ($name in $Omit) { $record.Remove($name) }

        return [pscustomobject]$record
    }

    function New-Entitlement {
        [CmdletBinding()]
        param([object[]]$Assignment)

        if (-not $PSBoundParameters.ContainsKey('Assignment')) {
            $Assignment = @(
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:AtpPlanId
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:SafeDocsPlanId -ServicePlanName 'SAFEDOCS'
                New-Assignment -UserPrincipalName $script:StandardUser -ServicePlanId $script:AtpPlanId
            )
        }

        return [pscustomobject]@{ Assignment = @($Assignment) }
    }

    function Get-MatrixRowKey {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Matrix
        )

        return @($Matrix.Row | ForEach-Object { '{0}|{1}|{2}' -f $_.UserPrincipalName, $_.ControlId, $_.RequiredServicePlanId })
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'LIC-006-A licensing matrix' {

    BeforeEach {
        $script:Population = New-Population
        $script:Control = New-ControlSet
        $script:Entitlement = New-Entitlement
    }

    Context 'Negative: the matrix inputs must be usable' {

        It 'refuses a matrix with no target population' {
            # Arrange
            $noPopulation = $null

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $noPopulation -Control $script:Control -Entitlement $script:Entitlement }

            # Assert
            $build | Should -Throw -ExpectedMessage 'TargetPopulationRequired*' -Because 'a matrix built over nobody would report every control satisfied'
        }

        It 'refuses a target population that does not declare its recipients' {
            # Arrange
            $notAPopulation = [pscustomobject]@{ Strict = @($script:PriorityUser) }

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $notAPopulation -Control $script:Control -Entitlement $script:Entitlement }

            # Assert
            $build | Should -Throw -ExpectedMessage 'TargetPopulationContractViolation*Recipient*' -Because 'only a classified population carries the profile each row is scoped by'
        }

        It 'refuses a matrix with no control' {
            # Arrange
            $noControl = @()

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $noControl -Entitlement $script:Entitlement }

            # Assert
            $build | Should -Throw -ExpectedMessage 'ControlRequired*' -Because 'an empty control set produces an empty matrix that would read as a fully licensed tenant'
        }

        It 'refuses a control that omits a required member' -ForEach @(
            @{ Member = 'controlId' }
            @{ Member = 'applicableProfiles' }
            @{ Member = 'requiredServicePlan' }
        ) {
            # Arrange
            $incomplete = @(New-Control -ControlId 'MDO-PRESET' -Omit @($Member))

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $incomplete -Entitlement $script:Entitlement }

            # Assert
            $build | Should -Throw -ExpectedMessage "ControlContractViolation*$Member*" -Because "a control without '$Member' cannot be paired with a target"
        }

        It 'refuses a duplicated control identifier' {
            # Arrange
            $duplicated = @($script:Control) + @(New-Control -ControlId 'MDO-PRESET' -RequiredServicePlan @(New-RequiredPlan -ServicePlanId $script:AtpPlanId))

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $duplicated -Entitlement $script:Entitlement }

            # Assert
            $build | Should -Throw -ExpectedMessage 'ControlDuplicated*MDO-PRESET*' -Because 'one control counted twice makes the gap count depend on the registry order'
        }

        It 'refuses a control profile outside the declared vocabulary' {
            # Arrange
            $unknownProfile = @(New-Control -ControlId 'MDO-PRESET' -ApplicableProfile @('Paranoid'))

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $unknownProfile -Entitlement $script:Entitlement }

            # Assert
            $build | Should -Throw -ExpectedMessage 'UnknownControlProfile*Paranoid*' -Because 'a profile nothing assigns would silently scope the control to nobody'
        }

        It 'refuses a control whose applicable profiles are empty' {
            # Arrange
            $noProfile = @(New-Control -ControlId 'MDO-PRESET' -ApplicableProfile @())

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $noProfile -Entitlement $script:Entitlement }

            # Assert
            $build | Should -Throw -ExpectedMessage 'ControlContractViolation*applicableProfiles*' -Because 'a control that applies to no profile is never evaluated and never reported'
        }

        It 'refuses a required service plan without a service-plan identifier' {
            # Arrange
            $unidentified = @(New-Control -ControlId 'MDO-PRESET' -RequiredServicePlan @(New-RequiredPlan -ServicePlanId '' -ServicePlanName 'ATP_ENTERPRISE'))

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $unidentified -Entitlement $script:Entitlement }

            # Assert
            $build | Should -Throw -ExpectedMessage 'RequiredServicePlanContractViolation*servicePlanId*' -Because 'an assignment carries no service-plan name to match on, so a requirement without an identifier can never be satisfied'
        }

        It 'refuses a matrix with no entitlement' {
            # Arrange
            $noEntitlement = $null

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $script:Control -Entitlement $noEntitlement }

            # Assert
            $build | Should -Throw -ExpectedMessage 'EntitlementRequired*' -Because 'without the per-user verdicts the matrix has no assigned state to report'
        }

        It 'refuses an entitlement that does not declare its assignments' {
            # Arrange
            $notAnEntitlement = [pscustomobject]@{ Entitled = $true }

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $script:Control -Entitlement $notAnEntitlement }

            # Assert
            $build | Should -Throw -ExpectedMessage 'EntitlementContractViolation*Assignment*' -Because 'a summary verdict is not the per-user evidence a row is built from'
        }

        It 'refuses an assignment that omits a required member' -ForEach @(
            @{ Member = 'UserPrincipalName' }
            @{ Member = 'ServicePlanId' }
            @{ Member = 'State' }
        ) {
            # Arrange
            $incomplete = New-Entitlement -Assignment @(New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:AtpPlanId -Omit @($Member))

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $script:Control -Entitlement $incomplete }

            # Assert
            $build | Should -Throw -ExpectedMessage "EntitlementAssignmentContractViolation*$Member*" -Because "an assignment without '$Member' cannot be attributed to a row"
        }

        It 'refuses an assignment state outside the declared vocabulary' {
            # Arrange
            $unknownState = New-Entitlement -Assignment @(New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:AtpPlanId -State 'Provisioning')

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $script:Control -Entitlement $unknownState }

            # Assert
            $build | Should -Throw -ExpectedMessage 'UnknownAssignmentState*Provisioning*' -Because 'a state the matrix does not know must never be guessed into an entitlement'
        }
    }

    Context 'Negative: the matrix never invents an answer it was not given' {

        It 'refuses a target and plan pair with no recorded assignment instead of reporting it entitled' {
            # Arrange
            $missingStandardUser = New-Entitlement -Assignment @(
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:AtpPlanId
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:SafeDocsPlanId -ServicePlanName 'SAFEDOCS'
            )

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $script:Control -Entitlement $missingStandardUser }

            # Assert
            $build | Should -Throw -ExpectedMessage "EntitlementIncomplete*$script:StandardUser*" -Because 'a row that reads entitled because nobody looked cannot be told from one that reads entitled because the licence is held'
        }

        It 'does not match a required plan by its service-plan name' {
            # Arrange
            $nameOnly = New-Entitlement -Assignment @(
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:MdoP2PlanId -ServicePlanName 'ATP_ENTERPRISE'
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:SafeDocsPlanId -ServicePlanName 'SAFEDOCS'
                New-Assignment -UserPrincipalName $script:StandardUser -ServicePlanId $script:AtpPlanId
            )

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $script:Control -Entitlement $nameOnly }

            # Assert
            $build | Should -Throw -ExpectedMessage "EntitlementIncomplete*$script:AtpPlanId*" -Because 'a plan bundle that carries the same display name is not the plan the control requires'
        }

        It 'does not fold one target assignment onto another target' {
            # Arrange
            $priorityOnly = New-Entitlement -Assignment @(
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:AtpPlanId
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:SafeDocsPlanId -ServicePlanName 'SAFEDOCS'
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:MdoP2PlanId -ServicePlanName 'THREAT_INTELLIGENCE'
            )

            # Act
            $build = { Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $script:Control -Entitlement $priorityOnly }

            # Assert
            $build | Should -Throw -ExpectedMessage "EntitlementIncomplete*$script:StandardUser*" -Because "one target's licence never covers another target"
        }
    }

    Context 'Negative: only a target and an applicable control produce a row' {

        It 'does not emit a row for a recipient that is not a licensing target' -ForEach @(
            @{ Recipient = 'shared.mailbox@contoso.example' }
            @{ Recipient = 'excluded.user@contoso.example' }
        ) {
            # Arrange
            $population = $script:Population

            # Act
            $matrix = Get-BaselineLicensingMatrix -TargetPopulation $population -Control $script:Control -Entitlement $script:Entitlement

            # Assert
            @($matrix.Row | ForEach-Object { $_.UserPrincipalName }) | Should -Not -Contain $Recipient -Because 'a recipient the baseline never asks to hold a licence must not appear as a licensing gap'
        }

        It 'does not emit a row for a control outside the profile of the target' {
            # Arrange
            $control = $script:Control

            # Act
            $matrix = Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $control -Entitlement $script:Entitlement

            # Assert
            Get-MatrixRowKey -Matrix $matrix |
                Should -Not -Contain "$script:StandardUser|MDO-SAFEDOCS|$script:SafeDocsPlanId" -Because 'a Strict-only control is never applied to a Standard target, so it can never be a gap for one'
        }

        It 'does not emit more than one row for a target, control and required-plan triple' {
            # Arrange
            $duplicatedAssignment = New-Entitlement -Assignment @(
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:AtpPlanId
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:AtpPlanId -State 'Suspended'
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:SafeDocsPlanId -ServicePlanName 'SAFEDOCS'
                New-Assignment -UserPrincipalName $script:StandardUser -ServicePlanId $script:AtpPlanId
            )

            # Act
            $matrix = Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $script:Control -Entitlement $duplicatedAssignment

            # Assert
            @(Get-MatrixRowKey -Matrix $matrix | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name }) |
                Should -BeNullOrEmpty -Because 'a duplicated assignment must not double the rows and double the gap count'
        }
    }

    Context 'Negative: a row is entitled only when the plan actually is' {

        It 'does not report a row entitled when the assigned state is not enabled' -ForEach @(
            @{ State = 'NotAssigned' }
            @{ State = 'Suspended' }
            @{ State = 'Disabled' }
        ) {
            # Arrange
            $degraded = New-Entitlement -Assignment @(
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:AtpPlanId
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:SafeDocsPlanId -ServicePlanName 'SAFEDOCS'
                New-Assignment -UserPrincipalName $script:StandardUser -ServicePlanId $script:AtpPlanId -State $State
            )

            # Act
            $matrix = Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $script:Control -Entitlement $degraded

            # Assert
            @($matrix.Row | Where-Object { $_.UserPrincipalName -eq $script:StandardUser -and $_.ControlId -eq 'MDO-PRESET' } | ForEach-Object { '{0}:{1}' -f $_.AssignedState, $_.Entitled }) |
                Should -Be @("${State}:False") -Because "a plan in the '$State' state is not a plan the tenant can use"
        }

        It 'does not leave a non-entitled row without a reason naming the target, the control and the required plan' {
            # Arrange
            $suspended = New-Entitlement -Assignment @(
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:AtpPlanId
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:SafeDocsPlanId -ServicePlanName 'SAFEDOCS'
                New-Assignment -UserPrincipalName $script:StandardUser -ServicePlanId $script:AtpPlanId -State 'Suspended'
            )

            # Act
            $matrix = Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $script:Control -Entitlement $suspended

            # Assert
            @($matrix.Gap | ForEach-Object { $_.Reason }) |
                Should -Be @("'$script:StandardUser' is not entitled to 'MDO-PRESET' because the required service plan 'ATP_ENTERPRISE' ($script:AtpPlanId) is Suspended.") -Because 'a gap nobody can act on is a gap nobody will close'
        }

        It 'does not report the matrix complete while any row is not entitled' {
            # Arrange
            $suspended = New-Entitlement -Assignment @(
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:AtpPlanId
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:SafeDocsPlanId -ServicePlanName 'SAFEDOCS'
                New-Assignment -UserPrincipalName $script:StandardUser -ServicePlanId $script:AtpPlanId -State 'Suspended'
            )

            # Act
            $matrix = Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $script:Control -Entitlement $suspended

            # Assert
            $matrix.Complete | Should -BeFalse -Because 'a matrix reported complete is the fact the go-live gate lets a deployment through on'
        }
    }

    Context 'Negative: matching is case-insensitive' {

        It 'does not treat a differently-cased user principal name as a different target' {
            # Arrange
            $mixedCase = New-Entitlement -Assignment @(
                New-Assignment -UserPrincipalName 'PRIORITY.User@Contoso.Example' -ServicePlanId $script:AtpPlanId
                New-Assignment -UserPrincipalName 'PRIORITY.User@Contoso.Example' -ServicePlanId $script:SafeDocsPlanId -ServicePlanName 'SAFEDOCS'
                New-Assignment -UserPrincipalName 'Standard.USER@contoso.example' -ServicePlanId $script:AtpPlanId
            )

            # Act
            $matrix = Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $script:Control -Entitlement $mixedCase

            # Assert
            $matrix.Complete | Should -BeTrue -Because 'a user principal name is case-insensitive, so casing alone must not invent a licensing gap'
        }
    }

    Context 'Negative: the matrix stays offline' {

        # The stubs are global, so cleanup must survive an Act that throws; otherwise a failing run
        # leaks them into the session and every later test resolves them instead of failing.
        AfterEach {
            Remove-Item -Path 'function:global:Connect-MgGraph', 'function:global:Get-MgUser', 'function:global:Get-MgSubscribedSku', 'function:global:Get-Mailbox' -ErrorAction SilentlyContinue
        }

        It 'reaches Graph and Exchange Online only through the supplied evidence' {
            # Arrange
            $script:MatrixCommandInvocation = [System.Collections.Generic.List[string]]::new()
            function global:Connect-MgGraph { $script:MatrixCommandInvocation.Add('Connect-MgGraph') }
            function global:Get-MgUser { $script:MatrixCommandInvocation.Add('Get-MgUser') }
            function global:Get-MgSubscribedSku { $script:MatrixCommandInvocation.Add('Get-MgSubscribedSku') }
            function global:Get-Mailbox { $script:MatrixCommandInvocation.Add('Get-Mailbox') }

            # Act
            $null = Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $script:Control -Entitlement $script:Entitlement

            # Assert
            $script:MatrixCommandInvocation | Should -BeNullOrEmpty -Because 'the matrix reports the evidence it was handed and never collects more of its own accord'
        }
    }

    Context 'Positive: a representative population and control set fold into one matrix' {

        It 'yields one row per target per applicable control per required plan, each naming its user, control, plan, state, entitlement and reason' {
            # Arrange
            $entitlement = New-Entitlement -Assignment @(
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:AtpPlanId
                New-Assignment -UserPrincipalName $script:PriorityUser -ServicePlanId $script:SafeDocsPlanId -ServicePlanName 'SAFEDOCS' -State 'Suspended'
                New-Assignment -UserPrincipalName $script:StandardUser -ServicePlanId $script:AtpPlanId
            )

            # Act
            $matrix = Get-BaselineLicensingMatrix -TargetPopulation $script:Population -Control $script:Control -Entitlement $entitlement

            # Assert
            $summary = @(
                @($matrix.Row | ForEach-Object { '{0}/{1}/{2}/{3}/{4}/{5}/{6}/{7}' -f $_.UserPrincipalName, $_.Profile, $_.ControlId, $_.RequiredServicePlanId, $_.RequiredServicePlanName, $_.AssignedState, $_.Entitled, $_.Reason }) -join '|'
                'Gap=' + (@($matrix.Gap | ForEach-Object { '{0}/{1}/{2}' -f $_.UserPrincipalName, $_.ControlId, $_.RequiredServicePlanId }) -join ',')
                'Complete=' + $matrix.Complete
            ) -join '; '

            $summary | Should -Be (@(
                    @(
                        "priority.user@contoso.example/Strict/MDO-PRESET/$script:AtpPlanId/ATP_ENTERPRISE/Enabled/True/'priority.user@contoso.example' is entitled to 'MDO-PRESET' because the required service plan 'ATP_ENTERPRISE' ($script:AtpPlanId) is Enabled."
                        "priority.user@contoso.example/Strict/MDO-SAFEDOCS/$script:SafeDocsPlanId/SAFEDOCS/Suspended/False/'priority.user@contoso.example' is not entitled to 'MDO-SAFEDOCS' because the required service plan 'SAFEDOCS' ($script:SafeDocsPlanId) is Suspended."
                        "priority.user@contoso.example/Strict/EXO-SMTPAUTH///NotRequired/True/'priority.user@contoso.example' is entitled to 'EXO-SMTPAUTH' because the control requires no service plan."
                        "standard.user@contoso.example/Standard/MDO-PRESET/$script:AtpPlanId/ATP_ENTERPRISE/Enabled/True/'standard.user@contoso.example' is entitled to 'MDO-PRESET' because the required service plan 'ATP_ENTERPRISE' ($script:AtpPlanId) is Enabled."
                        "standard.user@contoso.example/Standard/EXO-SMTPAUTH///NotRequired/True/'standard.user@contoso.example' is entitled to 'EXO-SMTPAUTH' because the control requires no service plan."
                    ) -join '|'
                    "Gap=priority.user@contoso.example/MDO-SAFEDOCS/$script:SafeDocsPlanId"
                    'Complete=False'
                ) -join '; ') -Because 'every target is paired with every control that applies to its profile, once per plan that control requires, in the order the population and the registry were supplied'
        }
    }
}
