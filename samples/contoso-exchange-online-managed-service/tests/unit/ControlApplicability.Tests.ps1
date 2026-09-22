#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:TenantServicePlan = @('EXCHANGE_S_ENTERPRISE', 'ATP_ENTERPRISE', 'SAFEDOCS')
    $script:PriorityInScope = @('Critical', 'High')

    function New-CatalogControl {
        [CmdletBinding()]
        param(
            [string]$Id = 'MDO-006',
            [string[]]$DeploymentProfile = @('MicrosoftNative', 'ThirdPartyGateway'),
            [string[]]$RequiredServicePlan = @('ATP_ENTERPRISE', 'SAFEDOCS'),
            [string]$Priority = 'Critical',
            [string[]]$Omit = @(),
            [bool]$DeclaredEntitled = $true
        )

        $member = [ordered]@{
            Id                   = $Id
            DeploymentProfile    = $DeploymentProfile
            RequiredServicePlan  = $RequiredServicePlan
            Priority             = $Priority
            DeclaredEntitled     = $DeclaredEntitled
        }

        foreach ($name in $Omit) {
            $member.Remove($name)
        }

        return [pscustomobject]$member
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'COM-005-A2 control applicability and entitlement authority' {

    Context 'Negative: the decision must refuse input it cannot trust' {

        It 'fails with ControlNotProvided when the control is null' {
            # Arrange
            $missingControl = $null

            # Act
            $act = { Get-ControlApplicability -Control $missingControl -DeploymentProfile 'ThirdPartyGateway' -TenantServicePlan $script:TenantServicePlan -PriorityInScope $script:PriorityInScope }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ControlNotProvided*'
        }

        It 'fails with ControlContractViolation when the control carries no identifier' {
            # Arrange
            $control = New-CatalogControl -Omit @('Id')

            # Act
            $act = { Get-ControlApplicability -Control $control -DeploymentProfile 'ThirdPartyGateway' -TenantServicePlan $script:TenantServicePlan -PriorityInScope $script:PriorityInScope }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ControlContractViolation*'
        }

        It 'fails with ControlContractViolation when the control declares no applicable profiles' {
            # Arrange
            $control = New-CatalogControl -Omit @('DeploymentProfile')

            # Act
            $act = { Get-ControlApplicability -Control $control -DeploymentProfile 'ThirdPartyGateway' -TenantServicePlan $script:TenantServicePlan -PriorityInScope $script:PriorityInScope }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ControlContractViolation*'
        }

        It 'fails with ControlContractViolation when the control declares no required service plans' {
            # Arrange
            $control = New-CatalogControl -Omit @('RequiredServicePlan')

            # Act
            $act = { Get-ControlApplicability -Control $control -DeploymentProfile 'ThirdPartyGateway' -TenantServicePlan $script:TenantServicePlan -PriorityInScope $script:PriorityInScope }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ControlContractViolation*'
        }

        It 'fails with ControlContractViolation when the control declares no priority' {
            # Arrange
            $control = New-CatalogControl -Omit @('Priority')

            # Act
            $act = { Get-ControlApplicability -Control $control -DeploymentProfile 'ThirdPartyGateway' -TenantServicePlan $script:TenantServicePlan -PriorityInScope $script:PriorityInScope }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ControlContractViolation*'
        }

        It 'fails with UnknownDeploymentProfile when the selected profile is not a declared profile' {
            # Arrange
            $control = New-CatalogControl

            # Act
            $act = { Get-ControlApplicability -Control $control -DeploymentProfile 'HybridOnPremises' -TenantServicePlan $script:TenantServicePlan -PriorityInScope $script:PriorityInScope }

            # Assert
            $act | Should -Throw -ExpectedMessage '*UnknownDeploymentProfile*'
        }

        It 'fails with ServicePlanInventoryRequired when no tenant service-plan inventory is supplied' {
            # Arrange
            $control = New-CatalogControl

            # Act
            $act = { Get-ControlApplicability -Control $control -DeploymentProfile 'ThirdPartyGateway' -TenantServicePlan $null -PriorityInScope $script:PriorityInScope }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ServicePlanInventoryRequired*'
        }
    }

    Context 'Negative: a control out of scope must never be reported applicable' {

        It 'reports a control outside the selected profile as not applicable' {
            # Arrange
            $control = New-CatalogControl -DeploymentProfile @('MicrosoftNative')

            # Act
            $applicability = Get-ControlApplicability -Control $control -DeploymentProfile 'ThirdPartyGateway' -TenantServicePlan $script:TenantServicePlan -PriorityInScope $script:PriorityInScope

            # Assert
            $applicability.Applicable | Should -BeFalse
        }

        It 'reports a control outside the priorities in scope as not applicable' {
            # Arrange
            $control = New-CatalogControl -Priority 'Low'

            # Act
            $applicability = Get-ControlApplicability -Control $control -DeploymentProfile 'ThirdPartyGateway' -TenantServicePlan $script:TenantServicePlan -PriorityInScope $script:PriorityInScope

            # Assert
            $applicability.Applicable | Should -BeFalse
        }
    }

    Context 'Negative: the tenant decides entitlement' {

        It 'reports a control as not entitled when the tenant does not grant a required service plan' {
            # Arrange
            $control = New-CatalogControl -RequiredServicePlan @('ATP_ENTERPRISE', 'THREAT_INTELLIGENCE')

            # Act
            $applicability = Get-ControlApplicability -Control $control -DeploymentProfile 'ThirdPartyGateway' -TenantServicePlan $script:TenantServicePlan -PriorityInScope $script:PriorityInScope

            # Assert
            $applicability.Status | Should -BeExactly 'NotEntitled'
        }

        It 'does not let declared licensing metadata override the tenant inventory' {
            # Arrange
            $control = New-CatalogControl -RequiredServicePlan @('THREAT_INTELLIGENCE') -DeclaredEntitled $true

            # Act
            $applicability = Get-ControlApplicability -Control $control -DeploymentProfile 'ThirdPartyGateway' -TenantServicePlan $script:TenantServicePlan -PriorityInScope $script:PriorityInScope

            # Assert
            $applicability.Entitled | Should -BeFalse
        }

        It 'names the service plan the tenant does not grant' {
            # Arrange
            $control = New-CatalogControl -RequiredServicePlan @('ATP_ENTERPRISE', 'THREAT_INTELLIGENCE')

            # Act
            $applicability = Get-ControlApplicability -Control $control -DeploymentProfile 'ThirdPartyGateway' -TenantServicePlan $script:TenantServicePlan -PriorityInScope $script:PriorityInScope

            # Assert
            $applicability.MissingServicePlan | Should -Be @('THREAT_INTELLIGENCE')
        }
    }

    Context 'Positive: a control in scope and granted every plan is evaluated' {

        It 'reports a control in profile, in priority scope and fully entitled as applicable and entitled' {
            # Arrange
            $control = New-CatalogControl

            # Act
            $applicability = Get-ControlApplicability -Control $control -DeploymentProfile 'ThirdPartyGateway' -TenantServicePlan $script:TenantServicePlan -PriorityInScope $script:PriorityInScope

            # Assert
            ('{0}:Applicable={1}:Entitled={2}:Status={3}:Missing={4}' -f $applicability.ControlId, $applicability.Applicable, $applicability.Entitled, $applicability.Status, @($applicability.MissingServicePlan).Count) |
                Should -BeExactly 'MDO-006:Applicable=True:Entitled=True:Status=Applicable:Missing=0'
        }
    }
}
