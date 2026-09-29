#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonManifestPath = Join-Path $script:SampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1'
    Import-Module -Name $script:CommonManifestPath -Force -DisableNameChecking -ErrorAction Stop

    function New-OwaNoOpFixture {
        # Synthetic, non-authoritative fixture: never tenant policy, assignment authority, or permission to mutate.
        $settings = [ordered]@{
            DirectFileAccessOnPublicComputersEnabled = [bool]$false
            UserContextTimeout = [int]15
            DefaultTheme = [string]'base'
            AllowedFileTypes = [string[]]@('.docx', '.xlsx')
        }
        $policyContentHash = 'SHA256:SYNTHETIC-OWA-POLICY-V1'
        $approvalId = 'synthetic-owa-approval@example.invalid'
        $evidenceId = 'synthetic-owa-evidence-noop'
        $impact = [ordered]@{
            OutlookOnTheWeb = [ordered]@{
                Impact = 'PolicySettingsOnly'
                ActualBehavior = 'Unverified'
                Exclusions = [string[]]@('LiveClientValidation', 'AssignmentAuthority')
            }
            NewOutlookForWindows = [ordered]@{
                Impact = 'PolicySettingsOnly'
                ActualBehavior = 'Unverified'
                Exclusions = [string[]]@('LiveClientValidation', 'AssignmentAuthority')
            }
        }
        $policy = [ordered]@{
            FixtureAuthority = 'SyntheticNonAuthoritative'
            IsAuthoritative = $false
            ContentHash = $policyContentHash
            Approval = [ordered]@{
                ApprovalId = $approvalId
                Decision = 'Approved'
                ExpiresUtc = '2026-10-31T00:00:00Z'
            }
            Evidence = [ordered]@{
                EvidenceId = $evidenceId
                ApprovalId = $approvalId
                ContentHash = $policyContentHash
            }
            ApprovedIdentities = [string[]]@('OWA-Approved')
            ApprovedSettings = [string[]]@(
                'DirectFileAccessOnPublicComputersEnabled',
                'UserContextTimeout',
                'DefaultTheme',
                'AllowedFileTypes'
            )
            OperandTypes = [ordered]@{
                DirectFileAccessOnPublicComputersEnabled = 'Boolean'
                UserContextTimeout = 'Int32'
                DefaultTheme = 'String'
                AllowedFileTypes = 'StringArray'
            }
            ConditionalAccess = [ordered]@{ Included = $false; Reason = 'ExcludedFromExchangeOwaMailboxPolicyLifecycle' }
            ClientImpact = $impact
        }
        $plan = @(
            [ordered]@{
                Identity = 'OWA-Approved'
                Decision = 'NoOp'
                CurrentSettings = [ordered]@{} + $settings
                DesiredSettings = [ordered]@{} + $settings
                ActualClientBehavior = 'Unverified'
                AssignmentProvenance = 'Unverified'
                ApprovalId = $approvalId
                EvidenceId = $evidenceId
                ContentHash = $policyContentHash
                ClientImpact = $impact
            }
        )
        $bindings = @(
            [ordered]@{
                Mailbox = 'alex.wilber@contoso.example'
                Policy = 'OWA-Approved'
                EvidenceOnly = $true
                Mutable = $false
                AssignmentProvenance = 'Unverified'
                FixtureAuthority = 'SyntheticNonAuthoritative'
                ApprovalId = $approvalId
                EvidenceId = $evidenceId
                ContentHash = $policyContentHash
            }
        )
        $calls = [Collections.Generic.List[string]]::new()

        [ordered]@{
            Policy = $policy
            Plan = $plan
            BindingEvidence = $bindings
            CollectionComplete = $true
            AsOfUtc = '2026-09-29T12:00:00Z'
            Calls = $calls
            Read = {
                $calls.Add('Read')
                [ordered]@{
                    Complete = $true
                    Policies = @(
                        [ordered]@{
                            Identity = 'OWA-Approved'
                            Settings = [ordered]@{} + $settings
                        }
                    )
                }
            }.GetNewClosure()
            PolicyWriter = {
                param($Identity, $Settings)
                $calls.Add("PolicyWriter:$Identity")
            }.GetNewClosure()
        }
    }

    function Get-OwaNoOpArguments {
        param([Parameter(Mandatory)][hashtable]$Fixture)

        @{
            Policy = $Fixture.Policy
            Plan = $Fixture.Plan
            BindingEvidence = $Fixture.BindingEvidence
            CollectionComplete = $Fixture.CollectionComplete
            AsOfUtc = $Fixture.AsOfUtc
            Read = $Fixture.Read
            PolicyWriter = $Fixture.PolicyWriter
        }
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-007-A08-T03 exact OWA mailbox policy no-op lifecycle' {
    Context 'Negative: no-op execution remains inside approved non-binding boundaries' {
        It '01 rejects a changed row presented to the no-op lifecycle' {
            # Arrange
            $fixture = New-OwaNoOpFixture
            $fixture.Plan[0].Decision = 'Changed'
            $arguments = Get-OwaNoOpArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyNoOpDecisionRequired*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '02 rejects binding evidence that claims it is mutable' {
            # Arrange
            $fixture = New-OwaNoOpFixture
            $fixture.BindingEvidence[0].Mutable = $true
            $arguments = Get-OwaNoOpArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyBindingMustBeEvidenceOnlyNonMutable*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '03 rejects a desired setting outside the approved setting allow-list' {
            # Arrange
            $fixture = New-OwaNoOpFixture
            $fixture.Plan[0].DesiredSettings['UnapprovedSetting'] = 'synthetic'
            $arguments = Get-OwaNoOpArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicySettingNotApproved*UnapprovedSetting*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '04 rejects an identity outside the approved identity allow-list' {
            # Arrange
            $fixture = New-OwaNoOpFixture
            $fixture.Plan[0].Identity = 'OWA-Unapproved'
            $arguments = Get-OwaNoOpArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyIdentityNotApproved*OWA-Unapproved*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '05 rejects operands that do not conform to the declared typed contract' {
            # Arrange
            $fixture = New-OwaNoOpFixture
            $fixture.Plan[0].DesiredSettings.DirectFileAccessOnPublicComputersEnabled = 'false'
            $arguments = Get-OwaNoOpArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyOperandTypeMismatch*Boolean*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '06 refuses observed no-op drift without invoking any writer' {
            # Arrange
            $fixture = New-OwaNoOpFixture
            $fixture.Read = {
                $fixture.Calls.Add('Read')
                $snapshot = [ordered]@{
                    Complete = $true
                    Policies = @(
                        [ordered]@{
                            Identity = 'OWA-Approved'
                            Settings = [ordered]@{} + $fixture.Plan[0].CurrentSettings
                        }
                    )
                }
                $snapshot.Policies[0].Settings.DefaultTheme = 'observed-drift'
                $snapshot
            }.GetNewClosure()
            $arguments = Get-OwaNoOpArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyDriftRefused*'
            @($fixture.Calls) | Should -Be @('Read')
            @($fixture.Calls | Where-Object { $_ -like 'PolicyWriter:*' }).Count | Should -Be 0
        }

        It '07 rejects inclusion of Conditional Access in the Exchange policy lifecycle' {
            # Arrange
            $fixture = New-OwaNoOpFixture
            $fixture.Policy.ConditionalAccess.Included = $true
            $arguments = Get-OwaNoOpArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyConditionalAccessExcluded*'
            @($fixture.Calls).Count | Should -Be 0
        }
    }

    Context 'Positive: exact no-op performs evidence read only' {
        It '08 returns exact unverified no-op evidence without invoking a writer' {
            # Arrange
            $fixture = New-OwaNoOpFixture
            $arguments = Get-OwaNoOpArguments -Fixture $fixture

            # Act
            $result = Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments

            # Assert
            @($fixture.Calls) | Should -Be @('Read')
            @($result.PSObject.Properties.Name) | Should -Be @(
                'Decision',
                'Changed',
                'Identity',
                'AfterSettings',
                'ApprovalId',
                'EvidenceId',
                'ContentHash',
                'ActualClientBehavior',
                'AssignmentProvenance',
                'ClientImpact',
                'ConditionalAccess'
            )
            $result.Decision | Should -BeExactly 'NoOp'
            $result.Changed | Should -BeFalse
            $result.Identity | Should -BeExactly 'OWA-Approved'
            @($result.AfterSettings.PSObject.Properties.Name) | Should -Be @(
                'DirectFileAccessOnPublicComputersEnabled',
                'UserContextTimeout',
                'DefaultTheme',
                'AllowedFileTypes'
            )
            $result.AfterSettings.DirectFileAccessOnPublicComputersEnabled | Should -BeOfType ([bool])
            $result.AfterSettings.DirectFileAccessOnPublicComputersEnabled | Should -BeFalse
            $result.AfterSettings.UserContextTimeout | Should -BeOfType ([int])
            $result.AfterSettings.UserContextTimeout | Should -BeExactly 15
            $result.AfterSettings.DefaultTheme | Should -BeOfType ([string])
            $result.AfterSettings.DefaultTheme | Should -BeExactly 'base'
            ,$result.AfterSettings.AllowedFileTypes | Should -BeOfType ([string[]])
            $result.AfterSettings.AllowedFileTypes | Should -BeExactly ([string[]]@('.docx', '.xlsx'))
            $result.ApprovalId | Should -BeExactly $fixture.Policy.Approval.ApprovalId
            $result.EvidenceId | Should -BeExactly $fixture.Policy.Evidence.EvidenceId
            $result.ContentHash | Should -BeExactly $fixture.Policy.ContentHash
            $result.ApprovalId | Should -BeExactly $fixture.Policy.Evidence.ApprovalId
            $result.ContentHash | Should -BeExactly $fixture.Policy.Evidence.ContentHash
            $result.ApprovalId | Should -BeExactly $fixture.Plan[0].ApprovalId
            $result.EvidenceId | Should -BeExactly $fixture.Plan[0].EvidenceId
            $result.ContentHash | Should -BeExactly $fixture.Plan[0].ContentHash
            $result.ApprovalId | Should -BeExactly $fixture.BindingEvidence[0].ApprovalId
            $result.EvidenceId | Should -BeExactly $fixture.BindingEvidence[0].EvidenceId
            $result.ContentHash | Should -BeExactly $fixture.BindingEvidence[0].ContentHash
            $result.ActualClientBehavior | Should -BeExactly 'Unverified'
            $result.AssignmentProvenance | Should -BeExactly 'Unverified'
            @($result.ClientImpact.PSObject.Properties.Name) | Should -Be @(
                'OutlookOnTheWeb',
                'NewOutlookForWindows'
            )
            @($result.ClientImpact.OutlookOnTheWeb.PSObject.Properties.Name) | Should -Be @(
                'Impact',
                'ActualBehavior',
                'Exclusions'
            )
            @($result.ClientImpact.NewOutlookForWindows.PSObject.Properties.Name) | Should -Be @(
                'Impact',
                'ActualBehavior',
                'Exclusions'
            )
            $result.ClientImpact.OutlookOnTheWeb.Impact | Should -BeExactly 'PolicySettingsOnly'
            $result.ClientImpact.OutlookOnTheWeb.ActualBehavior | Should -BeExactly 'Unverified'
            $result.ClientImpact.OutlookOnTheWeb.Exclusions |
                Should -BeExactly ([string[]]@('LiveClientValidation', 'AssignmentAuthority'))
            $result.ClientImpact.NewOutlookForWindows.Impact | Should -BeExactly 'PolicySettingsOnly'
            $result.ClientImpact.NewOutlookForWindows.ActualBehavior | Should -BeExactly 'Unverified'
            $result.ClientImpact.NewOutlookForWindows.Exclusions |
                Should -BeExactly ([string[]]@('LiveClientValidation', 'AssignmentAuthority'))
            @($result.ConditionalAccess.PSObject.Properties.Name) | Should -Be @('Included', 'Reason')
            $result.ConditionalAccess.Included | Should -BeFalse
            $result.ConditionalAccess.Reason | Should -BeExactly 'ExcludedFromExchangeOwaMailboxPolicyLifecycle'
            $fixture.BindingEvidence[0].EvidenceOnly | Should -BeTrue
            $fixture.BindingEvidence[0].Mutable | Should -BeFalse
        }
    }
}
