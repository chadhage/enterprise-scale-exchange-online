#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModuleManifestPath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psd1'

    # These contract tests intentionally import the manifest so export wiring is part of the contract.
    if (-not (Test-Path -LiteralPath $script:CommonModuleManifestPath -PathType Leaf)) {
        throw "Common module manifest is required: $script:CommonModuleManifestPath"
    }
    Import-Module -Name $script:CommonModuleManifestPath -Force -DisableNameChecking -ErrorAction Stop

    function New-SyntheticOwaPolicyContract {
        [CmdletBinding()]
        param()

        # SyntheticNonAuthoritative marks this fixture as test evidence only, never a tenant
        # observation, approved production configuration, or authority to mutate anything.
        return [pscustomobject][ordered]@{
            FixtureAuthority = 'SyntheticNonAuthoritative'
            ContractVersion = '1.0'
            ApprovedPolicyIdentities = @(
                'OwaMailboxPolicy-Synthetic-Standard'
                'OwaMailboxPolicy-Synthetic-Restricted'
            )
            ApprovedSettings = @(
                [pscustomobject][ordered]@{
                    Name = 'DirectFileAccessOnPublicComputersEnabled'
                    OperandType = 'Boolean'
                    DesiredValue = $false
                }
                [pscustomobject][ordered]@{
                    Name = 'UserContextTimeout'
                    OperandType = 'Int32'
                    DesiredValue = [int32]60
                }
                [pscustomobject][ordered]@{
                    Name = 'DefaultTheme'
                    OperandType = 'String'
                    DesiredValue = [string]'SyntheticTheme'
                }
                [pscustomobject][ordered]@{
                    Name = 'AllowedFileTypes'
                    OperandType = 'StringArray'
                    DesiredValue = [string[]]@('.pdf', '.docx')
                }
            )
            Approval = [pscustomobject][ordered]@{
                ApprovalId = 'synthetic-owa-approval'
                EvidenceId = 'synthetic-owa-evidence'
                ContentHash = 'SHA256:SYNTHETIC-OWA-POLICY-V1'
                Decision = 'Approved'
                ApprovedBy = 'fixture-owner@example.invalid'
                ApprovedUtc = '2026-09-28T12:00:00Z'
                ExpiresUtc = '2026-10-31T00:00:00Z'
            }
            Evidence = [pscustomobject][ordered]@{
                ApprovalId = 'synthetic-owa-approval'
                EvidenceId = 'synthetic-owa-evidence'
                Complete = $true
                ContentHash = 'SHA256:SYNTHETIC-OWA-POLICY-V1'
            }
            ClientImpact = [pscustomobject][ordered]@{
                OutlookOnTheWeb = [pscustomobject][ordered]@{
                    Impact = 'PolicySettingsChanged'
                    Explicit = $true
                }
                NewOutlookForWindows = [pscustomobject][ordered]@{
                    Impact = 'NoDirectPolicyEffect'
                    Explicit = $true
                }
                LiveClientObservation = [pscustomobject][ordered]@{
                    Impact = 'Excluded'
                    Explicit = $true
                }
            }
            ActualBehavior = 'Unverified'
            AssignmentProvenance = 'Unverified'
            DependencyAssessment = [pscustomobject][ordered]@{
                Status = 'Complete'
                ConditionalAccess = 'Excluded'
            }
            PlanSafety = [pscustomobject][ordered]@{
                MutationCommand = 'Set-OwaMailboxPolicy'
                Apply = $false
                CapturePriorState = $true
                TypedOperands = $true
            }
        }
    }

    function New-SyntheticOwaPolicyBindings {
        [CmdletBinding()]
        param()

        # Every row is synthetic, non-authoritative evidence and never a mutable assignment.
        return @(
            [pscustomobject][ordered]@{
                FixtureAuthority = 'SyntheticNonAuthoritative'
                PolicyIdentity = 'OwaMailboxPolicy-Synthetic-Standard'
                SettingName = 'DirectFileAccessOnPublicComputersEnabled'
                EvidenceId = 'synthetic-owa-evidence'
                Mutable = $false
            }
            [pscustomobject][ordered]@{
                FixtureAuthority = 'SyntheticNonAuthoritative'
                PolicyIdentity = 'OwaMailboxPolicy-Synthetic-Standard'
                SettingName = 'UserContextTimeout'
                EvidenceId = 'synthetic-owa-evidence'
                Mutable = $false
            }
            [pscustomobject][ordered]@{
                FixtureAuthority = 'SyntheticNonAuthoritative'
                PolicyIdentity = 'OwaMailboxPolicy-Synthetic-Restricted'
                SettingName = 'DefaultTheme'
                EvidenceId = 'synthetic-owa-evidence'
                Mutable = $false
            }
            [pscustomobject][ordered]@{
                FixtureAuthority = 'SyntheticNonAuthoritative'
                PolicyIdentity = 'OwaMailboxPolicy-Synthetic-Restricted'
                SettingName = 'AllowedFileTypes'
                EvidenceId = 'synthetic-owa-evidence'
                Mutable = $false
            }
        )
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-007-A08-T03 approved OWA mailbox-policy planning' {
    Context 'Negative: policy and binding inputs are complete and structurally valid' {
        It 'refuses a missing policy contract' {
            # Arrange
            $bindings = New-SyntheticOwaPolicyBindings

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $null -Binding $bindings -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyContractRequired*'
        }

        It 'refuses missing binding evidence' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding @() -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyBindingRequired*'
        }

        It 'refuses a binding to an unapproved OWA policy identity' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $bindings = New-SyntheticOwaPolicyBindings
            $bindings[0].PolicyIdentity = 'OwaMailboxPolicy-Synthetic-Unapproved'

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding $bindings -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyIdentityNotApproved*OwaMailboxPolicy-Synthetic-Unapproved*'
        }

        It 'refuses a binding to an unapproved setting' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $bindings = New-SyntheticOwaPolicyBindings
            $bindings[0].SettingName = 'ConditionalAccessPolicy'

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding $bindings -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicySettingNotApproved*ConditionalAccessPolicy*'
        }

        It 'refuses a binding presented as mutable input' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $bindings = New-SyntheticOwaPolicyBindings
            $bindings[0].Mutable = $true

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding $bindings -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyBindingMustBeEvidenceOnly*'
        }

        It 'refuses <Target> FixtureAuthority that is not synthetic and non-authoritative' -ForEach @(
            @{ Target = 'policy'; Error = 'OwaPolicyFixtureAuthorityInvalid' }
            @{ Target = 'binding'; Error = 'OwaPolicyBindingFixtureAuthorityInvalid' }
        ) {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $bindings = New-SyntheticOwaPolicyBindings
            if ($Target -eq 'policy') {
                $policy.FixtureAuthority = 'TenantAuthoritative'
            }
            else {
                $bindings[0].FixtureAuthority = 'TenantAuthoritative'
            }

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding $bindings -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage "$Error*"
        }

        It 'refuses a binding EvidenceId that differs from the approved evidence' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $bindings = New-SyntheticOwaPolicyBindings
            $bindings[0].EvidenceId = 'synthetic-different-evidence'

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding $bindings -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyBindingEvidenceIdMismatch*synthetic-owa-evidence*synthetic-different-evidence*'
        }

    }

    Context 'Negative: approval and evidence are authoritative, current, and complete' {
        It 'refuses a contract without approval evidence' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $policy.Approval = $null

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding (New-SyntheticOwaPolicyBindings) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyApprovalRequired*'
        }

        It 'refuses an evidence ID not linked to its explicit approval' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $policy.Evidence.EvidenceId = 'synthetic-different-evidence'

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding (New-SyntheticOwaPolicyBindings) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyEvidenceApprovalLinkMismatch*synthetic-owa-evidence*synthetic-different-evidence*'
        }

        It 'refuses an Evidence ApprovalId that differs from its explicit approval' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $policy.Evidence.ApprovalId = 'synthetic-different-approval'

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding (New-SyntheticOwaPolicyBindings) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyEvidenceApprovalLinkMismatch*synthetic-owa-approval*synthetic-different-approval*'
        }

        It 'refuses an expired approval' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $policy.Approval.ExpiresUtc = '2026-09-29T11:59:59Z'

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding (New-SyntheticOwaPolicyBindings) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyApprovalExpired*'
        }

        It 'refuses a contract without its evidence record' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $policy.Evidence = $null

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding (New-SyntheticOwaPolicyBindings) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyEvidenceRequired*'
        }

        It 'refuses evidence explicitly marked incomplete' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $policy.Evidence.Complete = $false

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding (New-SyntheticOwaPolicyBindings) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyEvidenceIncomplete*'
        }

        It 'refuses evidence whose content hash differs from approved content' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $policy.Evidence.ContentHash = 'SHA256:SYNTHETIC-TAMPERED'

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding (New-SyntheticOwaPolicyBindings) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyEvidenceHashMismatch*'
        }
    }

    Context 'Negative: actual behavior and provenance remain explicitly Unverified' {
        It 'refuses a synthetic contract that claims actual behavior is Verified' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $policy.ActualBehavior = 'Verified'

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding (New-SyntheticOwaPolicyBindings) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyActualBehaviorMustBeUnverified*'
        }

        It 'refuses assignment provenance that claims tenant verification' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $policy.AssignmentProvenance = 'Verified'

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding (New-SyntheticOwaPolicyBindings) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyAssignmentProvenanceMustBeUnverified*'
        }
    }

    Context 'Negative: client impact and dependency boundaries are explicit' {
        It 'refuses Conditional Access as an included dependency or mutation scope' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $policy.DependencyAssessment.ConditionalAccess = 'Included'

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding (New-SyntheticOwaPolicyBindings) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyConditionalAccessMustBeExcluded*'
        }
    }

    Context 'Negative: plans are typed, inert, reversible, and limited to Set-OwaMailboxPolicy' {
        It 'refuses a <OperandType> approved setting whose desired operand has the wrong runtime type' -ForEach @(
            @{ SettingIndex = 0; SettingName = 'DirectFileAccessOnPublicComputersEnabled'; OperandType = 'Boolean'; InvalidValue = 'false' }
            @{ SettingIndex = 1; SettingName = 'UserContextTimeout'; OperandType = 'Int32'; InvalidValue = '60' }
            @{ SettingIndex = 2; SettingName = 'DefaultTheme'; OperandType = 'String'; InvalidValue = 1 }
            @{ SettingIndex = 3; SettingName = 'AllowedFileTypes'; OperandType = 'StringArray'; InvalidValue = '.pdf' }
        ) {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $policy.ApprovedSettings[$SettingIndex].DesiredValue = $InvalidValue

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding (New-SyntheticOwaPolicyBindings) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage "OwaPolicyOperandTypeMismatch*$SettingName*$OperandType*"
        }

        It 'refuses a plan safety contract whose Apply value is true' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $policy.PlanSafety.Apply = $true

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding (New-SyntheticOwaPolicyBindings) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyPlanApplyMustBeFalse*'
        }

        It 'refuses a plan safety contract whose CapturePriorState value is false' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $policy.PlanSafety.CapturePriorState = $false

            # Act
            $act = { New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding (New-SyntheticOwaPolicyBindings) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaPolicyPlanPriorStateCaptureRequired*'
        }
    }

    Context 'Positive: approved identities and settings produce an inert typed evidence plan' {
        It 'returns the exact approved affected set in the closed inert plan schema' {
            # Arrange
            $policy = New-SyntheticOwaPolicyContract
            $bindings = New-SyntheticOwaPolicyBindings
            $expectedPropertyNames = @(
                'FixtureAuthority'
                'PolicyIdentity'
                'SettingName'
                'OperandType'
                'DesiredValue'
                'BindingMutable'
                'MutationCommand'
                'Apply'
                'CapturePriorState'
                'ApprovalId'
                'EvidenceId'
                'ContentHash'
                'ClientImpact'
                'ActualBehavior'
                'AssignmentProvenance'
                'DependencyAssessment'
            )
            $expectedAffectedSet = @(
                'OwaMailboxPolicy-Synthetic-Restricted|AllowedFileTypes'
                'OwaMailboxPolicy-Synthetic-Restricted|DefaultTheme'
                'OwaMailboxPolicy-Synthetic-Standard|DirectFileAccessOnPublicComputersEnabled'
                'OwaMailboxPolicy-Synthetic-Standard|UserContextTimeout'
            )
            $expectedRows = @(
                'SyntheticNonAuthoritative|OwaMailboxPolicy-Synthetic-Restricted|AllowedFileTypes|StringArray|System.String[]|False|Set-OwaMailboxPolicy|False|True|synthetic-owa-approval|synthetic-owa-evidence|SHA256:SYNTHETIC-OWA-POLICY-V1|PolicySettingsChanged|True|NoDirectPolicyEffect|True|Excluded|True|Unverified|Unverified|Complete|Excluded'
                'SyntheticNonAuthoritative|OwaMailboxPolicy-Synthetic-Restricted|DefaultTheme|String|System.String|False|Set-OwaMailboxPolicy|False|True|synthetic-owa-approval|synthetic-owa-evidence|SHA256:SYNTHETIC-OWA-POLICY-V1|PolicySettingsChanged|True|NoDirectPolicyEffect|True|Excluded|True|Unverified|Unverified|Complete|Excluded'
                'SyntheticNonAuthoritative|OwaMailboxPolicy-Synthetic-Standard|DirectFileAccessOnPublicComputersEnabled|Boolean|System.Boolean|False|Set-OwaMailboxPolicy|False|True|synthetic-owa-approval|synthetic-owa-evidence|SHA256:SYNTHETIC-OWA-POLICY-V1|PolicySettingsChanged|True|NoDirectPolicyEffect|True|Excluded|True|Unverified|Unverified|Complete|Excluded'
                'SyntheticNonAuthoritative|OwaMailboxPolicy-Synthetic-Standard|UserContextTimeout|Int32|System.Int32|False|Set-OwaMailboxPolicy|False|True|synthetic-owa-approval|synthetic-owa-evidence|SHA256:SYNTHETIC-OWA-POLICY-V1|PolicySettingsChanged|True|NoDirectPolicyEffect|True|Excluded|True|Unverified|Unverified|Complete|Excluded'
            )
            $expectedDesiredValues = [ordered]@{
                AllowedFileTypes = [pscustomobject]@{
                    TypeName = 'System.String[]'
                    Value = [string[]]@('.pdf', '.docx')
                }
                DefaultTheme = [pscustomobject]@{
                    TypeName = 'System.String'
                    Value = [string]'SyntheticTheme'
                }
                DirectFileAccessOnPublicComputersEnabled = [pscustomobject]@{
                    TypeName = 'System.Boolean'
                    Value = [bool]$false
                }
                UserContextTimeout = [pscustomobject]@{
                    TypeName = 'System.Int32'
                    Value = [int32]60
                }
            }

            # Act
            $actual = @(New-ExchangeOwaMailboxPolicyPlan -Policy $policy -Binding $bindings -AsOfUtc '2026-09-29T12:00:00Z' |
                Sort-Object PolicyIdentity, SettingName)

            # Assert
            foreach ($row in $actual) {
                @($row.PSObject.Properties.Name) | Should -BeExactly $expectedPropertyNames
                @($row.ClientImpact.PSObject.Properties.Name) |
                    Should -BeExactly @('OutlookOnTheWeb', 'NewOutlookForWindows', 'LiveClientObservation')
                @($row.ClientImpact.OutlookOnTheWeb.PSObject.Properties.Name) |
                    Should -BeExactly @('Impact', 'Explicit')
                @($row.ClientImpact.NewOutlookForWindows.PSObject.Properties.Name) |
                    Should -BeExactly @('Impact', 'Explicit')
                @($row.ClientImpact.LiveClientObservation.PSObject.Properties.Name) |
                    Should -BeExactly @('Impact', 'Explicit')
                @($row.DependencyAssessment.PSObject.Properties.Name) |
                    Should -BeExactly @('Status', 'ConditionalAccess')
                $expectedDesired = $expectedDesiredValues[$row.SettingName]
                $row.DesiredValue.GetType().FullName | Should -BeExactly $expectedDesired.TypeName
                if ($row.OperandType -eq 'StringArray') {
                    @($row.DesiredValue) | Should -BeExactly @($expectedDesired.Value)
                }
                else {
                    $row.DesiredValue | Should -BeExactly $expectedDesired.Value
                }
            }
            @($actual | ForEach-Object { '{0}|{1}' -f $_.PolicyIdentity, $_.SettingName }) |
                Should -BeExactly $expectedAffectedSet
            @($actual | ForEach-Object {
                    '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}|{9}|{10}|{11}|{12}|{13}|{14}|{15}|{16}|{17}|{18}|{19}|{20}|{21}' -f
                        $_.FixtureAuthority,
                        $_.PolicyIdentity,
                        $_.SettingName,
                        $_.OperandType,
                        $_.DesiredValue.GetType().FullName,
                        $_.BindingMutable,
                        $_.MutationCommand,
                        $_.Apply,
                        $_.CapturePriorState,
                        $_.ApprovalId,
                        $_.EvidenceId,
                        $_.ContentHash,
                        $_.ClientImpact.OutlookOnTheWeb.Impact,
                        $_.ClientImpact.OutlookOnTheWeb.Explicit,
                        $_.ClientImpact.NewOutlookForWindows.Impact,
                        $_.ClientImpact.NewOutlookForWindows.Explicit,
                        $_.ClientImpact.LiveClientObservation.Impact,
                        $_.ClientImpact.LiveClientObservation.Explicit,
                        $_.ActualBehavior,
                        $_.AssignmentProvenance,
                        $_.DependencyAssessment.Status,
                        $_.DependencyAssessment.ConditionalAccess
                }) | Should -BeExactly $expectedRows
        }
    }
}
