#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonManifestPath = Join-Path $script:SampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1'
    Import-Module -Name $script:CommonManifestPath -Force -DisableNameChecking -ErrorAction Stop

    function New-OwaChangedLifecycleFixture {
        # Synthetic, non-authoritative fixture: evidence and approval below grant no tenant authority.
        $before = [ordered]@{
            DirectFileAccessOnPublicComputersEnabled = [bool]$true
            UserContextTimeout = [int]30
            DefaultTheme = [string]'legacy'
            AllowedFileTypes = [string[]]@('.docx')
        }
        $desired = [ordered]@{
            DirectFileAccessOnPublicComputersEnabled = [bool]$false
            UserContextTimeout = [int]15
            DefaultTheme = [string]'base'
            AllowedFileTypes = [string[]]@('.docx', '.xlsx')
        }
        $policyContentHash = 'SHA256:SYNTHETIC-OWA-POLICY-V1'
        $approvalId = 'synthetic-owa-approval@example.invalid'
        $evidenceId = 'synthetic-owa-evidence-changed'
        $policyImpact = [ordered]@{
            OutlookOnTheWeb = [ordered]@{
                Impact = 'PolicySettingsChanged'
                ActualBehavior = 'Unverified'
                Exclusions = [string[]]@('LiveClientValidation', 'AssignmentAuthority')
            }
            NewOutlookForWindows = [ordered]@{
                Impact = 'PolicySettingsChanged'
                ActualBehavior = 'Unverified'
                Exclusions = [string[]]@('LiveClientValidation', 'AssignmentAuthority')
            }
        }
        # Deliberately independent from policy metadata so a malformed plan cannot mutate policy evidence.
        $planImpact = [ordered]@{
            OutlookOnTheWeb = [ordered]@{
                Impact = 'PolicySettingsChanged'
                ActualBehavior = 'Unverified'
                Exclusions = [string[]]@('LiveClientValidation', 'AssignmentAuthority')
            }
            NewOutlookForWindows = [ordered]@{
                Impact = 'PolicySettingsChanged'
                ActualBehavior = 'Unverified'
                Exclusions = [string[]]@('LiveClientValidation', 'AssignmentAuthority')
            }
        }
        $state = [ordered]@{
            Complete = $true
            Identity = 'OWA-Approved'
            Settings = [ordered]@{} + $before
        }
        $calls = [Collections.Generic.List[string]]::new()
        $readHistory = [Collections.Generic.List[object]]::new()
        $policy = [ordered]@{
            FixtureAuthority = 'SyntheticNonAuthoritative'
            IsAuthoritative = $false
            ContentHash = $policyContentHash
            Approval = [ordered]@{
                ApprovalId = $approvalId
                Decision = 'Approved'
                ApprovedBy = 'fixture-owner@example.invalid'
                ApprovedUtc = '2026-09-28T12:00:00Z'
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
            ClientImpact = $policyImpact
        }
        $plan = @(
            [ordered]@{
                Identity = 'OWA-Approved'
                Decision = 'Changed'
                CurrentSettings = [ordered]@{} + $before
                DesiredSettings = [ordered]@{} + $desired
                ActualClientBehavior = 'Unverified'
                AssignmentProvenance = 'Unverified'
                ApprovalId = $approvalId
                EvidenceId = $evidenceId
                ContentHash = $policyContentHash
                ClientImpact = $planImpact
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

        [ordered]@{
            Policy = $policy
            Plan = $plan
            BindingEvidence = $bindings
            CollectionComplete = $true
            AsOfUtc = '2026-09-29T12:00:00Z'
            State = $state
            Calls = $calls
            ReadHistory = $readHistory
            Read = {
                $calls.Add('Read')
                $snapshot = [ordered]@{
                    Complete = $state.Complete
                    Policies = @([ordered]@{ Identity = $state.Identity; Settings = [ordered]@{} + $state.Settings })
                }
                $readHistory.Add($snapshot)
                $snapshot
            }.GetNewClosure()
            PolicyWriter = {
                param($Operation, $Identity, $Settings)
                $calls.Add("PolicyWriter:${Operation}:$Identity")
                $state.Settings = [ordered]@{} + $Settings
            }.GetNewClosure()
        }
    }

    function Get-OwaChangedLifecycleArguments {
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

Describe 'EXR-007-A08-T03 changed OWA mailbox policy lifecycle' {
    Context 'Negative: authority, collection, and mutation boundaries fail closed' {
        It '01 rejects missing approval before collection or mutation' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $fixture.Policy.Remove('Approval')
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyApprovalRequired*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '02 rejects an incomplete raw collection before mutation' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $fixture.CollectionComplete = $false
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyCollectionIncomplete*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '03 rejects a plan approval ID that is not linked to the otherwise valid evidence' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $fixture.Plan[0].ApprovalId = 'synthetic-unlinked-approval@example.invalid'
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyEvidenceLinkageMismatch*ApprovalId*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '04 rejects a desired setting outside the approved setting allow-list' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $fixture.Plan[0].DesiredSettings['UnapprovedSetting'] = 'synthetic'
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicySettingNotApproved*UnapprovedSetting*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '05 rejects binding evidence that claims mutation authority' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $fixture.BindingEvidence[0].EvidenceOnly = $false
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyBindingMustBeEvidenceOnlyNonMutable*'
            @($fixture.Calls).Count | Should -Be 0
        }
    }

    Context 'Negative: every approved operand retains its declared type' {
        It '06 rejects a String operand for a Boolean setting' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $fixture.Plan[0].DesiredSettings.DirectFileAccessOnPublicComputersEnabled = 'false'
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyOperandTypeMismatch*Boolean*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '07 rejects a String operand for an Int32 setting' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $fixture.Plan[0].DesiredSettings.UserContextTimeout = '15'
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyOperandTypeMismatch*Int32*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '08 rejects an Int32 operand for a String setting' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $fixture.Plan[0].DesiredSettings.DefaultTheme = [int]7
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyOperandTypeMismatch*String*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '09 rejects a scalar String operand for a StringArray setting' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $fixture.Plan[0].DesiredSettings.AllowedFileTypes = '.docx'
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyOperandTypeMismatch*StringArray*'
            @($fixture.Calls).Count | Should -Be 0
        }
    }

    Context 'Negative: client impact, provenance, exclusion, and readback are explicit' {
        It '10 rejects missing Outlook on the web impact' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $fixture.Plan[0].ClientImpact.Remove('OutlookOnTheWeb')
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyClientImpactIncomplete*OutlookOnTheWeb*'
            @($fixture.Calls).Count | Should -Be 0
            $fixture.Policy.ClientImpact.Contains('OutlookOnTheWeb') | Should -BeTrue
            $fixture.Policy.ClientImpact.OutlookOnTheWeb.Impact | Should -BeExactly 'PolicySettingsChanged'
            $fixture.Policy.ClientImpact.OutlookOnTheWeb.ActualBehavior | Should -BeExactly 'Unverified'
            $fixture.Policy.ClientImpact.OutlookOnTheWeb.Exclusions |
                Should -BeExactly ([string[]]@('LiveClientValidation', 'AssignmentAuthority'))
        }

        It '11 rejects verified assignment provenance while behavior and all other fields remain valid' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $fixture.Plan[0].AssignmentProvenance = 'Verified'
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyUnverifiedEvidenceRequired*AssignmentProvenance*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '12 rejects verified client behavior while provenance and all other fields remain valid' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $fixture.Plan[0].ActualClientBehavior = 'Verified'
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyUnverifiedEvidenceRequired*ActualClientBehavior*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '13 rejects inclusion of Conditional Access in the Exchange policy lifecycle' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $fixture.Policy.ConditionalAccess.Included = $true
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'OwaMailboxPolicyConditionalAccessExcluded*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It '14 preserves the primary mismatch and adds a distinct diagnostic when the rollback writer fails' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $fixture.PolicyWriter = {
                param($Operation, $Identity, $Settings)
                $fixture.Calls.Add("PolicyWriter:${Operation}:$Identity")
                if ($Operation -eq 'Rollback') {
                    throw 'synthetic rollback writer failure'
                }
                $fixture.State.Settings = [ordered]@{} + $Settings
                if ($Operation -eq 'Apply') {
                    $fixture.State.Settings.DefaultTheme = 'unexpected'
                }
            }.GetNewClosure()
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $caught = try {
                Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments
                $null
            }
            catch {
                $_
            }

            # Assert
            $caught | Should -BeOfType ([System.Management.Automation.ErrorRecord])
            $caught.Exception.Message | Should -Match 'OwaMailboxPolicyReadbackMismatch'
            $caught.Exception.Message | Should -Match 'OwaMailboxPolicyRestorationFailed'
            $caught.Exception.Message | Should -Match 'synthetic rollback writer failure'
            @($fixture.Calls) | Should -Be @(
                'Read',
                'PolicyWriter:Apply:OWA-Approved',
                'Read',
                'PolicyWriter:Rollback:OWA-Approved'
            )
            @($fixture.ReadHistory).Count | Should -Be 2
        }
    }

    Context 'Positive: changed lifecycle mutates only approved policy settings' {
        It '15 applies typed settings exactly and reports non-authoritative impact evidence' {
            # Arrange
            $fixture = New-OwaChangedLifecycleFixture
            $arguments = Get-OwaChangedLifecycleArguments -Fixture $fixture

            # Act
            $result = Invoke-ExchangeOwaMailboxPolicyLifecycle @arguments

            # Assert
            @($fixture.Calls) | Should -Be @(
                'Read',
                'PolicyWriter:Apply:OWA-Approved',
                'Read',
                'PolicyWriter:Rollback:OWA-Approved',
                'Read'
            )
            @($result.PSObject.Properties.Name) | Should -Be @(
                'Decision',
                'Changed',
                'ReadbackVerified',
                'NoOpVerified',
                'DriftRefusalVerified',
                'TypedRollbackVerified',
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
            $result.Decision | Should -BeExactly 'Changed'
            $result.Changed | Should -BeTrue
            $result.ReadbackVerified | Should -BeTrue
            $result.NoOpVerified | Should -BeTrue
            $result.DriftRefusalVerified | Should -BeTrue
            $result.TypedRollbackVerified | Should -BeTrue
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
            $result.ClientImpact.OutlookOnTheWeb.Impact | Should -BeExactly 'PolicySettingsChanged'
            $result.ClientImpact.OutlookOnTheWeb.ActualBehavior | Should -BeExactly 'Unverified'
            $result.ClientImpact.OutlookOnTheWeb.Exclusions |
                Should -BeExactly ([string[]]@('LiveClientValidation', 'AssignmentAuthority'))
            $result.ClientImpact.NewOutlookForWindows.Impact | Should -BeExactly 'PolicySettingsChanged'
            $result.ClientImpact.NewOutlookForWindows.ActualBehavior | Should -BeExactly 'Unverified'
            $result.ClientImpact.NewOutlookForWindows.Exclusions |
                Should -BeExactly ([string[]]@('LiveClientValidation', 'AssignmentAuthority'))
            @($result.ConditionalAccess.PSObject.Properties.Name) | Should -Be @('Included', 'Reason')
            $result.ConditionalAccess.Included | Should -BeFalse
            $result.ConditionalAccess.Reason | Should -BeExactly 'ExcludedFromExchangeOwaMailboxPolicyLifecycle'
            $fixture.BindingEvidence[0].EvidenceOnly | Should -BeTrue
            $fixture.BindingEvidence[0].Mutable | Should -BeFalse
            @($fixture.ReadHistory).Count | Should -Be 3
            $restored = $fixture.ReadHistory[2].Policies[0].Settings
            $restored.DirectFileAccessOnPublicComputersEnabled | Should -BeOfType ([bool])
            $restored.DirectFileAccessOnPublicComputersEnabled | Should -BeExactly $fixture.Plan[0].CurrentSettings.DirectFileAccessOnPublicComputersEnabled
            $restored.UserContextTimeout | Should -BeOfType ([int])
            $restored.UserContextTimeout | Should -BeExactly $fixture.Plan[0].CurrentSettings.UserContextTimeout
            $restored.DefaultTheme | Should -BeOfType ([string])
            $restored.DefaultTheme | Should -BeExactly $fixture.Plan[0].CurrentSettings.DefaultTheme
            ,$restored.AllowedFileTypes | Should -BeOfType ([string[]])
            $restored.AllowedFileTypes | Should -BeExactly $fixture.Plan[0].CurrentSettings.AllowedFileTypes
            @($restored.Keys) | Should -Be @($fixture.Plan[0].CurrentSettings.Keys)
            $projectSettings = {
                param($Settings)

                @(
                    foreach ($key in $Settings.Keys) {
                        $value = $Settings[$key]
                        [ordered]@{
                            Key = [string]$key
                            RuntimeType = $value.GetType().FullName
                            Value = if ($value -is [string[]]) {
                                [ordered]@{
                                    Cardinality = $value.Count
                                    Items = [string[]]@($value)
                                }
                            }
                            else {
                                $value
                            }
                        }
                    }
                ) | ConvertTo-Json -Depth 5 -Compress
            }
            $stateSettingsProjection = & $projectSettings $fixture.State.Settings
            $restoredProjection = & $projectSettings $restored
            $stateSettingsProjection | Should -BeExactly $restoredProjection
        }
    }
}
