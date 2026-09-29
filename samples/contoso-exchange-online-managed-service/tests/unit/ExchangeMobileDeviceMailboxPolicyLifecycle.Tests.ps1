#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psd1'
    if (-not (Test-Path -LiteralPath $script:CommonModulePath -PathType Leaf)) {
        throw "Common module manifest is required: $script:CommonModulePath"
    }
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function Get-MobilePolicyTestHash {
        param([Parameter(Mandatory)][AllowNull()][object]$InputObject)

        function ConvertTo-MobilePolicyCanonicalNode {
            param([AllowNull()][object]$Node)

            if ($null -eq $Node) { return $null }
            if ($Node -is [string] -or $Node -is [bool] -or $Node -is [decimal] -or $Node.GetType().IsPrimitive) {
                return $Node
            }
            if ($Node -is [System.Collections.IDictionary]) {
                $names = [string[]]@($Node.Keys)
                [Array]::Sort($names, [StringComparer]::Ordinal)
                $result = [ordered]@{}
                foreach ($name in $names) {
                    $result[$name] = ConvertTo-MobilePolicyCanonicalNode -Node $Node[$name]
                }
                return $result
            }
            if ($Node -is [Management.Automation.PSCustomObject]) {
                $names = [string[]]@($Node.PSObject.Properties.Name)
                [Array]::Sort($names, [StringComparer]::Ordinal)
                $result = [ordered]@{}
                foreach ($name in $names) {
                    $result[$name] = ConvertTo-MobilePolicyCanonicalNode -Node $Node.PSObject.Properties[$name].Value
                }
                return $result
            }
            if ($Node -is [Collections.IList]) {
                return , @(foreach ($item in $Node) {
                    ConvertTo-MobilePolicyCanonicalNode -Node $item
                })
            }
            throw "Unsupported synthetic hash value: $($Node.GetType().FullName)"
        }

        $canonical = ConvertTo-MobilePolicyCanonicalNode -Node $InputObject
        $json = $canonical | ConvertTo-Json -Depth 64 -Compress
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    }

    function New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture {
        # Every value is synthetic and non-authoritative. No fixture grants tenant mutation authority.
        $approvedSettings = [ordered]@{
            AllowNonProvisionableDevices = $false
            AlphanumericPasswordRequired = $true
            DeviceEncryptionEnabled = $true
            MinPasswordLength = 6
        }
        $currentSettings = [ordered]@{
            AllowNonProvisionableDevices = $true
            AlphanumericPasswordRequired = $false
            DeviceEncryptionEnabled = $false
            MinPasswordLength = 4
        }
        $evidence = [ordered]@{
            FixtureAuthority = 'SyntheticNonAuthoritative'
            SourceCommand = 'Get-ExchangeMobileDeviceMailboxPolicyEvidence'
            Complete = $true
            EvidenceId = 'synthetic-mobile-policy-evidence'
            PolicyIdentity = 'Synthetic Default Mobile Policy'
            CurrentSettings = [ordered]@{} + $currentSettings
            ActualDeviceBehavior = 'Unverified'
            MobileDeviceManagement = 'Unverified'
            ConditionalAccess = 'Unverified'
        }
        $plan = [ordered]@{
            FixtureAuthority = 'SyntheticNonAuthoritative'
            SourceCommand = 'New-ExchangeMobileDeviceMailboxPolicyPlan'
            PolicyIdentity = $evidence.PolicyIdentity
            EvidenceHash = Get-MobilePolicyTestHash -InputObject $evidence
            BindingDisposition = 'ManageBinding'
            BindingDecisions = @(
                [ordered]@{ MailboxIdentity = 'managed@contoso.example'; Disposition = 'ManageBinding' }
                [ordered]@{ MailboxIdentity = 'preserved@contoso.example'; Disposition = 'PreserveBinding' }
                [ordered]@{ MailboxIdentity = 'excluded@contoso.example'; Disposition = 'Exclude' }
            )
            ApprovedSettingTypes = [ordered]@{
                AllowNonProvisionableDevices = 'Boolean'
                AlphanumericPasswordRequired = 'Boolean'
                DeviceEncryptionEnabled = 'Boolean'
                MinPasswordLength = 'Int32'
            }
            ApprovedSettings = [ordered]@{} + $approvedSettings
            CurrentSettings = [ordered]@{} + $evidence.CurrentSettings
            ActualDeviceBehavior = $evidence.ActualDeviceBehavior
            MobileDeviceManagement = $evidence.MobileDeviceManagement
            ConditionalAccess = $evidence.ConditionalAccess
        }
        $state = [ordered]@{
            Complete = $true
            Rows = @(
                [ordered]@{
                    Identity = 'Synthetic Default Mobile Policy'
                    Settings = [ordered]@{} + $currentSettings
                }
            )
        }
        $calls = [Collections.Generic.List[string]]::new()
        $completeRead = {
            param($phase)
            $calls.Add("CompleteRead:$phase")
            [ordered]@{
                Complete = $state.Complete
                Rows = @($state.Rows | ForEach-Object {
                    [ordered]@{
                        Identity = $_.Identity
                        Settings = [ordered]@{} + $_.Settings
                    }
                })
            }
        }.GetNewClosure()
        $writer = {
            param($operation, $row)
            $calls.Add("Writer:$operation`:$($row.PolicyIdentity)")
            $target = @($state.Rows | Where-Object Identity -CEQ $row.PolicyIdentity)
            if ($target.Count -ne 1) { throw "Synthetic target is not unique: $($row.PolicyIdentity)" }
            $target[0].Settings = if ($operation -eq 'Apply') {
                [ordered]@{} + $row.ApprovedSettings
            }
            else {
                [ordered]@{} + $row.CurrentSettings
            }
        }.GetNewClosure()

        [ordered]@{
            Evidence = $evidence
            Plan = $plan
            EvidenceHash = Get-MobilePolicyTestHash -InputObject $evidence
            PlanHash = Get-MobilePolicyTestHash -InputObject $plan
            State = $state
            Calls = $calls
            CompleteRead = $completeRead
            Writer = $writer
        }
    }

    function Get-MobileDeviceMailboxPolicyLifecycleArguments {
        param([Parameter(Mandatory)]$Fixture)

        @{
            Evidence = $Fixture.Evidence
            Plan = $Fixture.Plan
            EvidenceHash = $Fixture.EvidenceHash
            PlanHash = $Fixture.PlanHash
            CompleteRead = $Fixture.CompleteRead
            Writer = $Fixture.Writer
        }
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-007-A08-T02 mobile device mailbox policy lifecycle contract' {
    Context 'Negative: evidence and plan hashes are immutable bindings' {
        It 'rejects a changed evidence payload against its bound hash before reading or writing' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $fixture.Evidence.EvidenceId = 'synthetic-tampered-evidence'
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyEvidenceHashMismatch*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects a changed plan payload against its bound hash before reading or writing' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $fixture.Plan.ApprovedSettings.MinPasswordLength = 5
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyPlanHashMismatch*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects a plan whose evidence hash does not bind its evidence output' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $fixture.Plan.EvidenceHash = 'synthetic-wrong-evidence-hash'
            $fixture.PlanHash = Get-MobilePolicyTestHash -InputObject $fixture.Plan
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyEvidenceBindingMismatch*'
            @($fixture.Calls).Count | Should -Be 0
        }
    }

    Context 'Negative: identity settings and disposition remain approved' {
        It 'rejects a plan identity different from the evidence identity' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $fixture.Plan.PolicyIdentity = 'Synthetic Other Mobile Policy'
            $fixture.PlanHash = Get-MobilePolicyTestHash -InputObject $fixture.Plan
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyIdentityBindingMismatch*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects a missing binding disposition before reading or writing' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $fixture.Plan.Remove('BindingDisposition')
            $fixture.PlanHash = Get-MobilePolicyTestHash -InputObject $fixture.Plan
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyBindingDispositionRequired*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects a disposition not explicitly approved before reading or writing' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $fixture.Plan.BindingDisposition = 'Pending'
            $fixture.PlanHash = Get-MobilePolicyTestHash -InputObject $fixture.Plan
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyBindingNotApproved*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects approved settings that do not contain the exact required setting set' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $fixture.Plan.ApprovedSettings.Remove('DeviceEncryptionEnabled')
            $fixture.PlanHash = Get-MobilePolicyTestHash -InputObject $fixture.Plan
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyApprovedSettingsIncomplete*DeviceEncryptionEnabled*'
            @($fixture.Calls).Count | Should -Be 0
        }
    }

    Context 'Negative: adjacent enforcement claims stay explicitly unverified' {
        It 'rejects a claim that actual device behavior was verified' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $fixture.Plan.ActualDeviceBehavior = 'Verified'
            $fixture.PlanHash = Get-MobilePolicyTestHash -InputObject $fixture.Plan
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyActualDeviceBehaviorMustRemainUnverified*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects a claim that MobileDeviceManagement was verified' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $fixture.Plan.MobileDeviceManagement = 'Verified'
            $fixture.PlanHash = Get-MobilePolicyTestHash -InputObject $fixture.Plan
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyMobileDeviceManagementMustRemainUnverified*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects a claim that ConditionalAccess was verified' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $fixture.Plan.ConditionalAccess = 'Verified'
            $fixture.PlanHash = Get-MobilePolicyTestHash -InputObject $fixture.Plan
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyConditionalAccessMustRemainUnverified*'
            @($fixture.Calls).Count | Should -Be 0
        }
    }

    Context 'Negative: initial state read is complete and exact' {
        It 'rejects an incomplete initial read before any write' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $fixture.State.Complete = $false
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyInitialReadIncomplete*'
            @($fixture.Calls | Where-Object { $_ -like 'Writer:*' }).Count | Should -Be 0
        }

        It 'rejects duplicate identities in the initial complete read' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $fixture.State.Rows += [ordered]@{
                Identity = 'Synthetic Default Mobile Policy'
                Settings = [ordered]@{} + $fixture.Plan.CurrentSettings
            }
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyInitialIdentityNotUnique*Synthetic Default Mobile Policy*'
            @($fixture.Calls | Where-Object { $_ -like 'Writer:*' }).Count | Should -Be 0
        }

        It 'rejects a planned identity absent from the initial complete read' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $fixture.State.Rows = @()
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyInitialIdentityMissing*Synthetic Default Mobile Policy*'
            @($fixture.Calls | Where-Object { $_ -like 'Writer:*' }).Count | Should -Be 0
        }

        It 'rejects current setting drift from the bound plan before any write' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $fixture.State.Rows[0].Settings.MinPasswordLength = 5
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyInitialStateMismatch*MinPasswordLength*'
            @($fixture.Calls | Where-Object { $_ -like 'Writer:*' }).Count | Should -Be 0
        }
    }

    Context 'Negative: apply readback failure always rolls back and reads restoration' {
        It 'reverse-compensates a writer that mutates then throws and completes rollback readback' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $expectedRestoration = @($fixture.Plan.CurrentSettings.GetEnumerator() | ForEach-Object {
                "$($_.Key)|$($_.Value.GetType().Name)|$($_.Value)"
            })
            $originalWriter = $fixture.Writer
            $fixture.Writer = {
                param($operation, $row)
                & $originalWriter $operation $row
                if ($operation -eq 'Apply') { throw 'SyntheticMobilePolicyApplyWriteFailure' }
            }.GetNewClosure()
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyApplyFailed*SyntheticMobilePolicyApplyWriteFailure*'
            @($fixture.Calls) | Should -BeExactly @(
                'CompleteRead:Initial'
                'Writer:Apply:Synthetic Default Mobile Policy'
                'Writer:Rollback:Synthetic Default Mobile Policy'
                'CompleteRead:Rollback'
            )
            @($fixture.State.Rows[0].Settings.GetEnumerator() | ForEach-Object {
                "$($_.Key)|$($_.Value.GetType().Name)|$($_.Value)"
            }) | Should -BeExactly $expectedRestoration
        }

        It 'rolls back after an incomplete apply readback and then completes rollback readback' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $expectedRestoration = @($fixture.Plan.CurrentSettings.GetEnumerator() | ForEach-Object {
                "$($_.Key)|$($_.Value.GetType().Name)|$($_.Value)"
            })
            $originalRead = $fixture.CompleteRead
            $fixture.CompleteRead = {
                param($phase)
                $result = & $originalRead $phase
                if ($phase -eq 'Apply') { $result.Complete = $false }
                $result
            }.GetNewClosure()
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyApplyReadIncomplete*'
            @($fixture.Calls) | Should -BeExactly @(
                'CompleteRead:Initial'
                'Writer:Apply:Synthetic Default Mobile Policy'
                'CompleteRead:Apply'
                'Writer:Rollback:Synthetic Default Mobile Policy'
                'CompleteRead:Rollback'
            )
            @($fixture.State.Rows[0].Settings.GetEnumerator() | ForEach-Object {
                "$($_.Key)|$($_.Value.GetType().Name)|$($_.Value)"
            }) | Should -BeExactly $expectedRestoration
        }

        It 'rolls back after any exact approved-setting mismatch and reads restoration' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $expectedRestoration = @($fixture.Plan.CurrentSettings.GetEnumerator() | ForEach-Object {
                "$($_.Key)|$($_.Value.GetType().Name)|$($_.Value)"
            })
            $originalRead = $fixture.CompleteRead
            $fixture.CompleteRead = {
                param($phase)
                $result = & $originalRead $phase
                if ($phase -eq 'Apply') { $result.Rows[0].Settings.DeviceEncryptionEnabled = $false }
                $result
            }.GetNewClosure()
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyApplyReadbackMismatch*DeviceEncryptionEnabled*'
            @($fixture.Calls)[-2..-1] | Should -BeExactly @(
                'Writer:Rollback:Synthetic Default Mobile Policy'
                'CompleteRead:Rollback'
            )
            @($fixture.State.Rows[0].Settings.GetEnumerator() | ForEach-Object {
                "$($_.Key)|$($_.Value.GetType().Name)|$($_.Value)"
            }) | Should -BeExactly $expectedRestoration
        }

        It 'preserves the typed apply-readback failure when rollback itself fails' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $originalWriter = $fixture.Writer
            $fixture.Writer = {
                param($operation, $row)
                if ($operation -eq 'Rollback') { throw 'Synthetic rollback write failure.' }
                & $originalWriter $operation $row
            }.GetNewClosure()
            $originalRead = $fixture.CompleteRead
            $fixture.CompleteRead = {
                param($phase)
                $result = & $originalRead $phase
                if ($phase -eq 'Apply') { $result.Rows[0].Settings.MinPasswordLength = 5 }
                $result
            }.GetNewClosure()
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            try { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments; $caught = $null } catch { $caught = $_ }

            # Assert
            $caught.FullyQualifiedErrorId | Should -Match '^MobileDeviceMailboxPolicyApplyReadbackMismatch'
            $caught.Exception.Message | Should -Match 'MinPasswordLength'
            $caught.Exception.Message | Should -Match 'MobileDeviceMailboxPolicyRollbackFailed'
            $caught.Exception.Message | Should -Match 'Synthetic rollback write failure'
            @($fixture.Calls)[-1] | Should -BeExactly 'CompleteRead:Rollback'
        }

        It 'preserves the typed apply-readback failure when rollback readback is incomplete' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $expectedRestoration = @($fixture.Plan.CurrentSettings.GetEnumerator() | ForEach-Object {
                "$($_.Key)|$($_.Value.GetType().Name)|$($_.Value)"
            })
            $originalRead = $fixture.CompleteRead
            $fixture.CompleteRead = {
                param($phase)
                $result = & $originalRead $phase
                if ($phase -eq 'Apply') { $result.Rows[0].Settings.AlphanumericPasswordRequired = $false }
                if ($phase -eq 'Rollback') { $result.Complete = $false }
                $result
            }.GetNewClosure()
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            try { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments; $caught = $null } catch { $caught = $_ }

            # Assert
            $caught.FullyQualifiedErrorId | Should -Match '^MobileDeviceMailboxPolicyApplyReadbackMismatch'
            $caught.Exception.Message | Should -Match 'AlphanumericPasswordRequired'
            $caught.Exception.Message | Should -Match 'MobileDeviceMailboxPolicyRollbackReadIncomplete'
            @($fixture.Calls)[-1] | Should -BeExactly 'CompleteRead:Rollback'
            @($fixture.State.Rows[0].Settings.GetEnumerator() | ForEach-Object {
                "$($_.Key)|$($_.Value.GetType().Name)|$($_.Value)"
            }) | Should -BeExactly $expectedRestoration
        }

        It 'preserves the typed apply-readback failure when rollback readback is not restored exactly' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $expectedRestoration = @($fixture.Plan.CurrentSettings.GetEnumerator() | ForEach-Object {
                "$($_.Key)|$($_.Value.GetType().Name)|$($_.Value)"
            })
            $originalRead = $fixture.CompleteRead
            $fixture.CompleteRead = {
                param($phase)
                $result = & $originalRead $phase
                if ($phase -eq 'Apply') { $result.Rows[0].Settings.AllowNonProvisionableDevices = $true }
                if ($phase -eq 'Rollback') { $result.Rows[0].Settings.MinPasswordLength = 99 }
                $result
            }.GetNewClosure()
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            try { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments; $caught = $null } catch { $caught = $_ }

            # Assert
            $caught.FullyQualifiedErrorId | Should -Match '^MobileDeviceMailboxPolicyApplyReadbackMismatch'
            $caught.Exception.Message | Should -Match 'AllowNonProvisionableDevices'
            $caught.Exception.Message | Should -Match 'MobileDeviceMailboxPolicyRollbackReadbackMismatch'
            $caught.Exception.Message | Should -Match 'MinPasswordLength'
            @($fixture.Calls)[-1] | Should -BeExactly 'CompleteRead:Rollback'
            @($fixture.State.Rows[0].Settings.GetEnumerator() | ForEach-Object {
                "$($_.Key)|$($_.Value.GetType().Name)|$($_.Value)"
            }) | Should -BeExactly $expectedRestoration
        }
    }

    Context 'Positive: one exact synthetic lifecycle' {
        It 'binds evidence plan identity settings and disposition then applies verifies and reports adjacent controls unverified' {
            # Arrange
            $fixture = New-SyntheticMobileDeviceMailboxPolicyLifecycleFixture
            $arguments = Get-MobileDeviceMailboxPolicyLifecycleArguments -Fixture $fixture

            # Act
            $actual = Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments

            # Assert
            $actual.EvidenceHash | Should -BeExactly $fixture.EvidenceHash
            $actual.PlanHash | Should -BeExactly $fixture.PlanHash
            $fixture.Plan.PolicyIdentity | Should -BeExactly $fixture.Evidence.PolicyIdentity
            @($fixture.Plan.CurrentSettings.Keys | ForEach-Object {
                "$_|$($fixture.Plan.CurrentSettings[$_].GetType().FullName)|$($fixture.Plan.CurrentSettings[$_])"
            }) | Should -BeExactly @(
                'AllowNonProvisionableDevices|System.Boolean|True'
                'AlphanumericPasswordRequired|System.Boolean|False'
                'DeviceEncryptionEnabled|System.Boolean|False'
                'MinPasswordLength|System.Int32|4'
            )
            $fixture.Plan.ActualDeviceBehavior | Should -BeExactly $fixture.Evidence.ActualDeviceBehavior
            $fixture.Plan.MobileDeviceManagement | Should -BeExactly $fixture.Evidence.MobileDeviceManagement
            $fixture.Plan.ConditionalAccess | Should -BeExactly $fixture.Evidence.ConditionalAccess
            $actual.PolicyIdentity | Should -BeExactly $fixture.Plan.PolicyIdentity
            $actual.BindingDisposition | Should -BeExactly $fixture.Plan.BindingDisposition
            @($actual.BindingDecisions | ForEach-Object { "$($_.MailboxIdentity)|$($_.Disposition)" }) |
                Should -BeExactly @($fixture.Plan.BindingDecisions | ForEach-Object {
                    "$($_.MailboxIdentity)|$($_.Disposition)"
                })
            @($actual.ApprovedSettingTypes.Keys | ForEach-Object {
                "$_|$($actual.ApprovedSettingTypes[$_].GetType().FullName)|$($actual.ApprovedSettingTypes[$_])"
            }) | Should -BeExactly @(
                'AllowNonProvisionableDevices|System.String|Boolean'
                'AlphanumericPasswordRequired|System.String|Boolean'
                'DeviceEncryptionEnabled|System.String|Boolean'
                'MinPasswordLength|System.String|Int32'
            )
            @($actual.ApprovedSettings.Keys | ForEach-Object {
                "$_|$($actual.ApprovedSettings[$_].GetType().FullName)|$($actual.ApprovedSettings[$_])"
            }) | Should -BeExactly @(
                'AllowNonProvisionableDevices|System.Boolean|False'
                'AlphanumericPasswordRequired|System.Boolean|True'
                'DeviceEncryptionEnabled|System.Boolean|True'
                'MinPasswordLength|System.Int32|6'
            )
            @($actual.ApprovedSettings.Keys) | Should -BeExactly @(
                'AllowNonProvisionableDevices'
                'AlphanumericPasswordRequired'
                'DeviceEncryptionEnabled'
                'MinPasswordLength'
            )
            $actual.ApprovedSettings.AllowNonProvisionableDevices.GetType().Name | Should -BeExactly 'Boolean'
            $actual.ApprovedSettings.AlphanumericPasswordRequired.GetType().Name | Should -BeExactly 'Boolean'
            $actual.ApprovedSettings.DeviceEncryptionEnabled.GetType().Name | Should -BeExactly 'Boolean'
            $actual.ApprovedSettings.MinPasswordLength.GetType().Name | Should -BeExactly 'Int32'
            $actual.Applied | Should -BeTrue
            $actual.ReadbackVerified | Should -BeTrue
            $actual.ActualDeviceBehavior | Should -BeExactly $fixture.Plan.ActualDeviceBehavior
            $actual.MobileDeviceManagement | Should -BeExactly $fixture.Plan.MobileDeviceManagement
            $actual.ConditionalAccess | Should -BeExactly $fixture.Plan.ConditionalAccess
            @($fixture.Calls) | Should -BeExactly @(
                'CompleteRead:Initial'
                'Writer:Apply:Synthetic Default Mobile Policy'
                'CompleteRead:Apply'
            )
        }
    }
}
