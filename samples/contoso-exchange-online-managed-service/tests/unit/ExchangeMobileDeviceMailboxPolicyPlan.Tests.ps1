#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psd1'

    if (-not (Test-Path -LiteralPath $script:CommonModulePath -PathType Leaf)) {
        throw "Common module manifest is required: $script:CommonModulePath"
    }
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-SyntheticMobilePolicyAuthority {
        # Deliberately synthetic and non-authoritative: test input is not tenant policy or approval.
        return [pscustomobject][ordered]@{
            FixtureAuthority = 'SyntheticNonAuthoritative'
            ContractVersion = '1.0'
            PolicyVersion = '2026-09-29.1'
            SemanticAuthority = [pscustomobject][ordered]@{
                AuthorityId = 'synthetic-mobile-policy-authority'
                Decision = 'Approved'
            }
            Approval = [pscustomobject][ordered]@{
                ApprovalId = 'synthetic-mobile-policy-approval'
                ApprovedBy = 'fixture-owner@example.invalid'
                ApprovedUtc = '2026-09-28T12:00:00Z'
                ExpiresUtc = '2026-10-31T00:00:00Z'
            }
            EffectiveUtc = '2026-09-29T00:00:00Z'
            EvidenceBinding = [pscustomobject][ordered]@{
                EvidenceId = 'synthetic-mobile-policy-evidence'
                ContentHash = 'SHA256:SYNTHETIC-MOBILE-POLICY-V1'
            }
            Settings = @(
                [pscustomobject][ordered]@{ Name = 'AllowNonProvisionableDevices'; Type = 'Boolean'; Value = $false }
                [pscustomobject][ordered]@{ Name = 'AlphanumericPasswordRequired'; Type = 'Boolean'; Value = $true }
                [pscustomobject][ordered]@{ Name = 'DeviceEncryptionEnabled'; Type = 'Boolean'; Value = $true }
                [pscustomobject][ordered]@{ Name = 'MinPasswordLength'; Type = 'Int32'; Value = 8 }
            )
            PolicyDisposition = @(
                [pscustomobject][ordered]@{ PolicyIdentity = 'Synthetic-Managed-Mobile-Policy'; Disposition = 'Approved' }
                [pscustomobject][ordered]@{ PolicyIdentity = 'Synthetic-Preserved-Mobile-Policy'; Disposition = 'Preserve' }
            )
            BindingDisposition = @(
                [pscustomobject][ordered]@{
                    MailboxIdentity = 'alex.wilber@contoso.example'
                    Disposition = 'ManageBinding'
                    DesiredPolicyIdentity = 'Synthetic-Managed-Mobile-Policy'
                }
                [pscustomobject][ordered]@{
                    MailboxIdentity = 'shared.operations@contoso.example'
                    Disposition = 'PreserveBinding'
                    DesiredPolicyIdentity = $null
                }
                [pscustomobject][ordered]@{
                    MailboxIdentity = 'room@contoso.example'
                    Disposition = 'Exclude'
                    DesiredPolicyIdentity = $null
                }
            )
            VerificationBoundary = [pscustomobject][ordered]@{
                ActualDeviceBehavior = 'Unverified'
                MobileDeviceManagement = 'Unverified'
                ConditionalAccess = 'Unverified'
            }
        }
    }

    function New-SyntheticMobilePolicyEvidence {
        # Exact projection of the preceding Evidence contract's successful synthetic output.
        return [pscustomobject][ordered]@{
            FixtureAuthority = 'SyntheticNonAuthoritative'
            Collector = 'Get-ExchangeMobileDeviceMailboxPolicyEvidence'
            EvidenceId = 'synthetic-mobile-policy-evidence'
            ContentHash = 'SHA256:SYNTHETIC-MOBILE-POLICY-V1'
            CollectedUtc = '2026-09-29T11:30:00Z'
            Collected = $true
            Complete = $true
            Policies = New-SyntheticDiscoveredPolicies
            MailboxBindings = New-SyntheticDiscoveredMailboxes
            BindingDecisions = @(
                [pscustomobject][ordered]@{
                    MailboxIdentity = 'alex.wilber@contoso.example'
                    Disposition = 'ManageBinding'
                    PolicyIdentity = 'Synthetic-Managed-Mobile-Policy'
                    ImpactAssessment = 'Synthetic offline Exchange policy assessment only'
                    ExternalDeviceOwnerEvidence = 'Unverified'
                    Authority = 'SyntheticNonAuthoritativeFixture'
                }
                [pscustomobject][ordered]@{
                    MailboxIdentity = 'shared.operations@contoso.example'
                    Disposition = 'PreserveBinding'
                    PolicyIdentity = $null
                    ImpactAssessment = 'Synthetic offline Exchange policy assessment only'
                    ExternalDeviceOwnerEvidence = 'Unverified'
                    Authority = 'SyntheticNonAuthoritativeFixture'
                }
                [pscustomobject][ordered]@{
                    MailboxIdentity = 'room@contoso.example'
                    Disposition = 'Exclude'
                    PolicyIdentity = $null
                    ImpactAssessment = 'Synthetic offline Exchange policy assessment only'
                    ExternalDeviceOwnerEvidence = 'Unverified'
                    Authority = 'SyntheticNonAuthoritativeFixture'
                }
            )
            ActualDeviceBehavior = 'Unverified'
            MobileDeviceManagement = 'Unverified'
            ConditionalAccess = 'Unverified'
            Authoritative = $false
        }
    }

    function New-SyntheticDiscoveredPolicies {
        # Exact policy rows projected by the preceding synthetic Evidence contract.
        return @(
            [pscustomobject][ordered]@{
                Identity = 'Synthetic-Managed-Mobile-Policy'
                IsDefault = $false
                Settings = @(
                    [pscustomobject][ordered]@{ Name = 'AllowNonProvisionableDevices'; Type = 'Boolean'; Value = $false; Authority = 'SyntheticNonAuthoritativeFixture' }
                    [pscustomobject][ordered]@{ Name = 'AlphanumericPasswordRequired'; Type = 'Boolean'; Value = $true; Authority = 'SyntheticNonAuthoritativeFixture' }
                    [pscustomobject][ordered]@{ Name = 'DeviceEncryptionEnabled'; Type = 'Boolean'; Value = $true; Authority = 'SyntheticNonAuthoritativeFixture' }
                    [pscustomobject][ordered]@{ Name = 'MinPasswordLength'; Type = 'Int32'; Value = 8; Authority = 'SyntheticNonAuthoritativeFixture' }
                )
                Authority = 'SyntheticNonAuthoritativeFixture'
            }
            [pscustomobject][ordered]@{
                Identity = 'Synthetic-Preserved-Mobile-Policy'
                IsDefault = $false
                Settings = @(
                    [pscustomobject][ordered]@{ Name = 'AllowNonProvisionableDevices'; Type = 'Boolean'; Value = $false; Authority = 'SyntheticNonAuthoritativeFixture' }
                    [pscustomobject][ordered]@{ Name = 'AlphanumericPasswordRequired'; Type = 'Boolean'; Value = $true; Authority = 'SyntheticNonAuthoritativeFixture' }
                    [pscustomobject][ordered]@{ Name = 'DeviceEncryptionEnabled'; Type = 'Boolean'; Value = $true; Authority = 'SyntheticNonAuthoritativeFixture' }
                    [pscustomobject][ordered]@{ Name = 'MinPasswordLength'; Type = 'Int32'; Value = 8; Authority = 'SyntheticNonAuthoritativeFixture' }
                )
                Authority = 'SyntheticNonAuthoritativeFixture'
            }
        )
    }

    function New-SyntheticDiscoveredMailboxes {
        # Exact mailbox-binding rows projected by the preceding synthetic Evidence contract.
        return @(
            [pscustomobject][ordered]@{
                MailboxIdentity = 'alex.wilber@contoso.example'
                RecipientTypeDetails = 'UserMailbox'
                ActiveSyncEnabled = $true
                PolicyIdentity = 'Synthetic-Managed-Mobile-Policy'
                Authority = 'SyntheticNonAuthoritativeFixture'
            }
            [pscustomobject][ordered]@{
                MailboxIdentity = 'shared.operations@contoso.example'
                RecipientTypeDetails = 'SharedMailbox'
                ActiveSyncEnabled = $true
                PolicyIdentity = 'Synthetic-Preserved-Mobile-Policy'
                Authority = 'SyntheticNonAuthoritativeFixture'
            }
            [pscustomobject][ordered]@{
                MailboxIdentity = 'room@contoso.example'
                RecipientTypeDetails = 'RoomMailbox'
                ActiveSyncEnabled = $true
                PolicyIdentity = 'Synthetic-Preserved-Mobile-Policy'
                Authority = 'SyntheticNonAuthoritativeFixture'
            }
        )
    }

    function Invoke-SyntheticMobilePolicyPlan {
        param(
            [object]$Policy = (New-SyntheticMobilePolicyAuthority),
            [object]$Evidence = (New-SyntheticMobilePolicyEvidence),
            [object[]]$DiscoveredPolicy = (New-SyntheticDiscoveredPolicies),
            [object[]]$Mailbox = (New-SyntheticDiscoveredMailboxes)
        )

        New-ExchangeMobileDeviceMailboxPolicyPlan `
            -Policy $Policy `
            -Evidence $Evidence `
            -DiscoveredPolicy $DiscoveredPolicy `
            -Mailbox $Mailbox `
            -AsOfUtc '2026-09-29T12:00:00Z'
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-007-A08-T02 approved mobile-device mailbox-policy planning' {
    Context 'Negative: authority, approval, and currentness are mandatory' {
        It 'refuses policy without semantic authority' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.PSObject.Properties.Remove('SemanticAuthority')

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicySemanticAuthorityRequired*'
        }

        It 'refuses semantic authority whose decision is not Approved' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.SemanticAuthority.Decision = 'Draft'

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyAuthorityDecisionInvalid*Draft*'
        }

        It 'refuses policy without approval' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.PSObject.Properties.Remove('Approval')

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyApprovalRequired*'
        }

        It 'refuses expired approval at the planning instant' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.Approval.ExpiresUtc = '2026-09-29T11:59:59Z'

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyApprovalExpired*'
        }

        It 'refuses policy not yet effective at the planning instant' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.EffectiveUtc = '2026-09-29T12:00:01Z'

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyNotYetEffective*'
        }
    }

    Context 'Negative: evidence is bound to approved policy content' {
        It 'refuses evidence whose identity does not match the approval binding' {
            # Arrange
            $evidence = New-SyntheticMobilePolicyEvidence
            $evidence.EvidenceId = 'synthetic-other-evidence'

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Evidence $evidence }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyEvidenceIdMismatch*'
        }

        It 'refuses evidence whose content hash does not match the approval binding' {
            # Arrange
            $evidence = New-SyntheticMobilePolicyEvidence
            $evidence.ContentHash = 'SHA256:SYNTHETIC-OTHER-CONTENT'

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Evidence $evidence }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyEvidenceContentHashMismatch*'
        }
    }

    Context 'Negative: settings have a closed schema and typed values' {
        It 'refuses an unsupported setting name' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.Settings += [pscustomobject]@{
                Name = 'InventedTenantDefault'
                Type = 'Boolean'
                Value = $true
            }

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicySettingUnsupported*InventedTenantDefault*'
        }

        It 'refuses a non-Boolean value for a Boolean setting' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            ($policy.Settings | Where-Object Name -eq 'DeviceEncryptionEnabled').Value = 'true'

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicySettingTypeInvalid*DeviceEncryptionEnabled*Boolean*'
        }

        It 'refuses duplicate setting rows even when values agree' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.Settings += [pscustomobject]@{
                Name = 'DeviceEncryptionEnabled'
                Type = 'Boolean'
                Value = $true
            }

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicySettingDuplicate*DeviceEncryptionEnabled*'
        }

        It 'refuses missing observed settings rather than inventing tenant defaults' {
            # Arrange
            $discoveredPolicy = New-SyntheticDiscoveredPolicies
            $discoveredPolicy[0].Settings = @(
                $discoveredPolicy[0].Settings | Where-Object Name -ne 'MinPasswordLength'
            )

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -DiscoveredPolicy $discoveredPolicy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyObservedSettingMissing*Synthetic-Managed-Mobile-Policy*MinPasswordLength*'
        }
    }

    Context 'Negative: policy dispositions use exact discovered identities' {
        It 'refuses duplicate policy disposition rows' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.PolicyDisposition += [pscustomobject]@{
                PolicyIdentity = 'Synthetic-Managed-Mobile-Policy'
                Disposition = 'Approved'
            }

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyDispositionDuplicate*Synthetic-Managed-Mobile-Policy*'
        }

        It 'refuses an unsupported policy disposition' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.PolicyDisposition[0].Disposition = 'CreateAsDefault'

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyDispositionUnsupported*CreateAsDefault*'
        }

        It 'refuses a policy row for an identity absent from discovery' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.PolicyDisposition += [pscustomobject]@{
                PolicyIdentity = 'Universal Mobile Default'
                Disposition = 'Approved'
            }

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyIdentityNotDiscovered*Universal Mobile Default*'
        }

        It 'refuses a discovered policy without an exact disposition row' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.PolicyDisposition = @(
                $policy.PolicyDisposition | Where-Object PolicyIdentity -ne 'Synthetic-Preserved-Mobile-Policy'
            )

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyDispositionMissing*Synthetic-Preserved-Mobile-Policy*'
        }

    }

    Context 'Negative: mailbox identities and bindings are exact and unique' {
        It 'refuses PreserveBinding with a desired replacement policy' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $preserve = $policy.BindingDisposition | Where-Object Disposition -eq 'PreserveBinding'
            $preserve.DesiredPolicyIdentity = 'Synthetic-Managed-Mobile-Policy'

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyPreserveTargetForbidden*shared.operations@contoso.example*'
        }

        It 'refuses duplicate binding rows for one mailbox' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.BindingDisposition += [pscustomobject]@{
                MailboxIdentity = 'alex.wilber@contoso.example'
                Disposition = 'ManageBinding'
                DesiredPolicyIdentity = 'Synthetic-Managed-Mobile-Policy'
            }

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyBindingDuplicate*alex.wilber@contoso.example*'
        }

        It 'refuses a binding disposition outside ManageBinding PreserveBinding and Exclude' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.BindingDisposition[0].Disposition = 'ReplaceBinding'

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyBindingDispositionUnsupported*ReplaceBinding*'
        }

        It 'refuses a binding row for a mailbox identity absent from discovery' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.BindingDisposition += [pscustomobject]@{
                MailboxIdentity = 'invented@example.invalid'
                Disposition = 'Exclude'
                DesiredPolicyIdentity = $null
            }

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyBindingMailboxNotDiscovered*invented@example.invalid*'
        }

        It 'refuses ManageBinding to a policy identity absent from discovery' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.BindingDisposition[0].DesiredPolicyIdentity = 'Invented Mobile Default'

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyBindingTargetNotDiscovered*Invented Mobile Default*'
        }

        It 'refuses Exclude with a desired replacement policy' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $exclude = $policy.BindingDisposition | Where-Object Disposition -eq 'Exclude'
            $exclude.DesiredPolicyIdentity = 'Synthetic-Managed-Mobile-Policy'

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyExcludeTargetForbidden*room@contoso.example*'
        }
    }

    Context 'Negative: planning does not verify adjacent enforcement systems' {
        It 'refuses policy content that claims actual device behavior is verified' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.VerificationBoundary.ActualDeviceBehavior = 'Verified'

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyActualDeviceBehaviorMustRemainUnverified*'
        }

        It 'refuses policy content that claims mobile-device management is verified' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.VerificationBoundary.MobileDeviceManagement = 'Verified'

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyMobileDeviceManagementMustRemainUnverified*'
        }

        It 'refuses policy content that claims conditional access is verified' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $policy.VerificationBoundary.ConditionalAccess = 'Verified'

            # Act
            $act = { Invoke-SyntheticMobilePolicyPlan -Policy $policy }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDevicePolicyConditionalAccessMustRemainUnverified*'
        }
    }

    Context 'Positive: one deterministic plan exactly projects no-op preserved and excluded Evidence rows' {
        It 'plans only approved settings and exact bindings while preserving boundaries' {
            # Arrange
            $policy = New-SyntheticMobilePolicyAuthority
            $evidence = New-SyntheticMobilePolicyEvidence
            $discoveredPolicy = @($evidence.Policies)
            $mailbox = @($evidence.MailboxBindings)

            # Act
            $result = Invoke-SyntheticMobilePolicyPlan `
                -Policy $policy `
                -Evidence $evidence `
                -DiscoveredPolicy $discoveredPolicy `
                -Mailbox $mailbox

            # Assert
            @($result.PSObject.Properties.Name) |
                Should -Be @('EvidenceId', 'ContentHash', 'PolicyPlan', 'BindingPlan', 'VerificationBoundary')
            @($result.PolicyPlan).Count | Should -Be 2
            @($result.BindingPlan).Count | Should -Be 3
            foreach ($policyPlanRow in @($result.PolicyPlan)) {
                @($policyPlanRow.PSObject.Properties.Name) |
                    Should -Be @('Identity', 'Decision', 'Settings')
            }
            foreach ($bindingPlanRow in @($result.BindingPlan)) {
                @($bindingPlanRow.PSObject.Properties.Name) |
                    Should -Be @('MailboxIdentity', 'Decision', 'PolicyIdentity')
            }
            @($result.PolicyPlan.Identity) | Should -BeExactly @($evidence.Policies.Identity)
            @($result.BindingPlan.MailboxIdentity) | Should -BeExactly @($evidence.MailboxBindings.MailboxIdentity)
            $managedPolicyPlan = @($result.PolicyPlan | Where-Object Identity -eq 'Synthetic-Managed-Mobile-Policy')
            $managedPolicyPlan.Count | Should -Be 1
            $managedPolicyPlan[0].Decision | Should -Be 'NoOp'
            @($managedPolicyPlan[0].Settings.Name | Sort-Object) |
                Should -Be @(
                    'AllowNonProvisionableDevices'
                    'AlphanumericPasswordRequired'
                    'DeviceEncryptionEnabled'
                    'MinPasswordLength'
                )
            $expectedSetting = [ordered]@{
                AllowNonProvisionableDevices = [pscustomobject]@{ Value = $false; Type = 'Boolean' }
                AlphanumericPasswordRequired = [pscustomobject]@{ Value = $true; Type = 'Boolean' }
                DeviceEncryptionEnabled = [pscustomobject]@{ Value = $true; Type = 'Boolean' }
                MinPasswordLength = [pscustomobject]@{ Value = 8; Type = 'Int32' }
            }
            foreach ($settingName in $expectedSetting.Keys) {
                $setting = @($managedPolicyPlan[0].Settings | Where-Object Name -eq $settingName)
                $setting.Count | Should -Be 1
                @($setting[0].PSObject.Properties.Name | Sort-Object) |
                    Should -Be @('Name', 'Type', 'Value')
                $setting[0].Name | Should -BeExactly $settingName
                $setting[0].Value | Should -BeExactly $expectedSetting[$settingName].Value
                $setting[0].Type | Should -BeExactly $expectedSetting[$settingName].Type
                $setting[0].Value.GetType().Name | Should -BeExactly $expectedSetting[$settingName].Type
            }
            $preservedPolicyPlan = @($result.PolicyPlan | Where-Object Identity -eq 'Synthetic-Preserved-Mobile-Policy')
            $preservedPolicyPlan.Count | Should -Be 1
            $preservedPolicyPlan[0].Identity | Should -BeExactly 'Synthetic-Preserved-Mobile-Policy'
            $preservedPolicyPlan[0].Decision | Should -BeExactly 'Preserve'
            @($preservedPolicyPlan[0].Settings).Count | Should -Be 4
            @($preservedPolicyPlan[0].Settings.Name | Sort-Object) |
                Should -Be @(
                    'AllowNonProvisionableDevices'
                    'AlphanumericPasswordRequired'
                    'DeviceEncryptionEnabled'
                    'MinPasswordLength'
                )
            foreach ($settingName in $expectedSetting.Keys) {
                $setting = @($preservedPolicyPlan[0].Settings | Where-Object Name -eq $settingName)
                $setting.Count | Should -Be 1
                @($setting[0].PSObject.Properties.Name | Sort-Object) |
                    Should -Be @('Name', 'Type', 'Value')
                $setting[0].Name | Should -BeExactly $settingName
                $setting[0].Value | Should -BeExactly $expectedSetting[$settingName].Value
                $setting[0].Type | Should -BeExactly $expectedSetting[$settingName].Type
                $setting[0].Value.GetType().Name | Should -BeExactly $expectedSetting[$settingName].Type
            }
            @($result.BindingPlan | Where-Object MailboxIdentity -eq 'alex.wilber@contoso.example').Decision |
                Should -Be 'NoOp'
            @($result.BindingPlan | Where-Object MailboxIdentity -eq 'alex.wilber@contoso.example').PolicyIdentity |
                Should -BeExactly 'Synthetic-Managed-Mobile-Policy'
            @($result.BindingPlan | Where-Object MailboxIdentity -eq 'shared.operations@contoso.example').Decision |
                Should -Be 'PreserveBinding'
            @($result.BindingPlan | Where-Object MailboxIdentity -eq 'shared.operations@contoso.example').PolicyIdentity |
                Should -Be 'Synthetic-Preserved-Mobile-Policy'
            @($result.BindingPlan | Where-Object MailboxIdentity -eq 'room@contoso.example').Decision |
                Should -Be 'Exclude'
            @($result.BindingPlan | Where-Object MailboxIdentity -eq 'room@contoso.example').PolicyIdentity |
                Should -Be 'Synthetic-Preserved-Mobile-Policy'
            $result.EvidenceId | Should -Be 'synthetic-mobile-policy-evidence'
            $result.ContentHash | Should -Be 'SHA256:SYNTHETIC-MOBILE-POLICY-V1'
            @($result.VerificationBoundary.PSObject.Properties.Name) |
                Should -Be @('ActualDeviceBehavior', 'MobileDeviceManagement', 'ConditionalAccess')
            $result.VerificationBoundary.ActualDeviceBehavior | Should -Be 'Unverified'
            $result.VerificationBoundary.MobileDeviceManagement | Should -Be 'Unverified'
            $result.VerificationBoundary.ConditionalAccess | Should -Be 'Unverified'
        }
    }
}
