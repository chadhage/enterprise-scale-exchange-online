#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonManifestPath = Join-Path $script:SampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1'
    Import-Module -Name $script:CommonManifestPath -Force -DisableNameChecking -ErrorAction Stop

    function Get-SyntheticMobilePolicyHash {
        param([Parameter(Mandatory)][AllowNull()][object]$InputObject)

        function ConvertTo-SyntheticMobilePolicyCanonicalNode {
            param([AllowNull()][object]$Node)
            if ($null -eq $Node) { return $null }
            if ($Node -is [string] -or $Node -is [bool] -or $Node -is [decimal] -or $Node.GetType().IsPrimitive) {
                return $Node
            }
            if ($Node -is [Collections.IDictionary]) {
                $names = [string[]]@($Node.Keys)
                [Array]::Sort($names, [StringComparer]::Ordinal)
                $canonical = [ordered]@{}
                foreach ($name in $names) {
                    $canonical[$name] = ConvertTo-SyntheticMobilePolicyCanonicalNode -Node $Node[$name]
                }
                return $canonical
            }
            if ($Node -is [Management.Automation.PSCustomObject]) {
                $names = [string[]]@($Node.PSObject.Properties.Name)
                [Array]::Sort($names, [StringComparer]::Ordinal)
                $canonical = [ordered]@{}
                foreach ($name in $names) {
                    $canonical[$name] = ConvertTo-SyntheticMobilePolicyCanonicalNode -Node $Node.PSObject.Properties[$name].Value
                }
                return $canonical
            }
            if ($Node -is [Collections.IList]) {
                return , @(foreach ($item in $Node) {
                    ConvertTo-SyntheticMobilePolicyCanonicalNode -Node $item
                })
            }
            throw "Unsupported synthetic hash value: $($Node.GetType().FullName)"
        }

        $json = ConvertTo-SyntheticMobilePolicyCanonicalNode -Node $InputObject |
            ConvertTo-Json -Depth 64 -Compress
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    }

    function New-SyntheticMobilePolicyNoOpFixture {
        # Synthetic, non-authoritative fixture; not tenant policy and not mutation authority.
        $evidence = [ordered]@{
            FixtureAuthority = 'SyntheticNonAuthoritative'
            SourceCommand = 'Get-ExchangeMobileDeviceMailboxPolicyEvidence'
            Complete = $true
            EvidenceId = 'synthetic-mobile-policy-no-op-evidence'
            PolicyIdentity = 'Synthetic Default Mobile Policy'
            CurrentSettings = [ordered]@{ AllowNonProvisionableDevices = $false; AlphanumericPasswordRequired = $true; DeviceEncryptionEnabled = $true; MinPasswordLength = 6 }
            ActualDeviceBehavior = 'Unverified'
            MobileDeviceManagement = 'Unverified'
            ConditionalAccess = 'Unverified'
        }
        $plan = [ordered]@{
            FixtureAuthority = 'SyntheticNonAuthoritative'
            SourceCommand = 'New-ExchangeMobileDeviceMailboxPolicyPlan'
            PolicyIdentity = $evidence.PolicyIdentity
            EvidenceHash = Get-SyntheticMobilePolicyHash -InputObject $evidence
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
            ApprovedSettings = [ordered]@{} + $evidence.CurrentSettings
            CurrentSettings = [ordered]@{} + $evidence.CurrentSettings
            Decision = 'NoOp'
            ActualDeviceBehavior = $evidence.ActualDeviceBehavior
            MobileDeviceManagement = $evidence.MobileDeviceManagement
            ConditionalAccess = $evidence.ConditionalAccess
        }
        $state = [ordered]@{
            Complete = $true
            Rows = @([ordered]@{ Identity = 'Synthetic Default Mobile Policy'; Settings = [ordered]@{} + $evidence.CurrentSettings })
        }
        $calls = [Collections.Generic.List[string]]::new()
        [ordered]@{
            Evidence = $evidence
            Plan = $plan
            EvidenceHash = Get-SyntheticMobilePolicyHash -InputObject $evidence
            PlanHash = Get-SyntheticMobilePolicyHash -InputObject $plan
            State = $state
            Calls = $calls
            CompleteRead = {
                param($phase)
                $calls.Add("CompleteRead:$phase")
                [ordered]@{
                    Complete = $state.Complete
                    Rows = @($state.Rows | ForEach-Object {
                        [ordered]@{ Identity = $_.Identity; Settings = [ordered]@{} + $_.Settings }
                    })
                }
            }.GetNewClosure()
            Writer = {
                param($operation, $row)
                $calls.Add("Writer:$operation`:$($row.PolicyIdentity)")
                throw 'Synthetic no-op writer must never execute'
            }.GetNewClosure()
        }
    }

    function Get-SyntheticMobileNoOpArguments {
        param([Parameter(Mandatory)]$Fixture)
        @{
            Evidence = $Fixture.Evidence
            Plan = $Fixture.Plan
            EvidenceHash = $Fixture.EvidenceHash
            PlanHash = $Fixture.PlanHash
            CompleteRead = $Fixture.CompleteRead
            Writer = $Fixture.Writer
            RequireNoOp = $true
        }
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-007-A08-T02 mobile-device mailbox-policy exact no-op contract' {
    Context 'Negative: hashes, complete reads, exact identities, and mutation suppression' {
        It '01 rejects a stale evidence hash before any apply or rollback attempt' {
            # Arrange
            $fixture = New-SyntheticMobilePolicyNoOpFixture
            $arguments = Get-SyntheticMobileNoOpArguments -Fixture $fixture
            $arguments.EvidenceHash = 'sha256:stale-evidence'
            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }
            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyEvidenceHashMismatch*'
            @($fixture.Calls | Where-Object { $_ -like 'Writer:*' }).Count | Should -Be 0
        }

        It '02 rejects a mismatched plan hash before any apply or rollback attempt' {
            # Arrange
            $fixture = New-SyntheticMobilePolicyNoOpFixture
            $arguments = Get-SyntheticMobileNoOpArguments -Fixture $fixture
            $arguments.PlanHash = 'sha256:mismatched-plan'
            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }
            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyPlanHashMismatch*'
            @($fixture.Calls | Where-Object { $_ -like 'Writer:*' }).Count | Should -Be 0
        }

        It '03 rejects an incomplete current-state read and suppresses mutation' {
            # Arrange
            $fixture = New-SyntheticMobilePolicyNoOpFixture
            $fixture.State.Complete = $false
            $arguments = Get-SyntheticMobileNoOpArguments -Fixture $fixture
            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }
            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyInitialReadIncomplete*'
            @($fixture.Calls | Where-Object { $_ -like 'Writer:*' }).Count | Should -Be 0
        }

        It '04 rejects identity drift when a planned mailbox is missing from the complete read' {
            # Arrange
            $fixture = New-SyntheticMobilePolicyNoOpFixture
            $fixture.State.Rows = @()
            $arguments = Get-SyntheticMobileNoOpArguments -Fixture $fixture
            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }
            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyInitialIdentityMissing*Synthetic Default Mobile Policy*'
            @($fixture.Calls | Where-Object { $_ -like 'Writer:*' }).Count | Should -Be 0
        }

        It '05 rejects approved typed policy-setting drift in an otherwise complete read' {
            # Arrange
            $fixture = New-SyntheticMobilePolicyNoOpFixture
            $fixture.State.Rows[0].Settings.MinPasswordLength = 99
            $arguments = Get-SyntheticMobileNoOpArguments -Fixture $fixture
            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }
            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyInitialStateMismatch*MinPasswordLength*'
            @($fixture.Calls | Where-Object { $_ -like 'Writer:*' }).Count | Should -Be 0
        }

        It '06 rejects a purported no-op plan containing a non-no-op row' {
            # Arrange
            $fixture = New-SyntheticMobilePolicyNoOpFixture
            $fixture.Plan.Decision = 'Changed'
            $fixture.Plan.ApprovedSettings.MinPasswordLength = 8
            $fixture.PlanHash = Get-SyntheticMobilePolicyHash -InputObject $fixture.Plan
            $arguments = Get-SyntheticMobileNoOpArguments -Fixture $fixture
            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }
            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyPlanNotNoOp*Synthetic Default Mobile Policy*'
            @($fixture.Calls | Where-Object { $_ -like 'Writer:*' }).Count | Should -Be 0
        }

        It '07 rejects an explicit mutation attempt against a no-op plan' {
            # Arrange
            $fixture = New-SyntheticMobilePolicyNoOpFixture
            $arguments = Get-SyntheticMobileNoOpArguments -Fixture $fixture
            $arguments.MutationAttempt = 'Apply'
            # Act
            $act = { Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments }
            # Assert
            $act | Should -Throw -ExpectedMessage 'MobileDeviceMailboxPolicyNoOpMutationAttempt*'
            @($fixture.Calls | Where-Object { $_ -like 'Writer:*' }).Count | Should -Be 0
        }
    }

    Context 'Positive: exact current state performs zero apply and rollback operations' {
        It '08 returns the exact no-op state with device behavior MDM and Conditional Access unverified' {
            # Arrange
            $fixture = New-SyntheticMobilePolicyNoOpFixture
            $arguments = Get-SyntheticMobileNoOpArguments -Fixture $fixture
            # Act
            $actual = Invoke-ExchangeMobileDeviceMailboxPolicyLifecycle @arguments
            # Assert
            $actual.NoOp | Should -BeTrue
            $actual.EvidenceHash | Should -BeExactly $fixture.EvidenceHash
            $actual.PlanHash | Should -BeExactly $fixture.PlanHash
            $fixture.Plan.PolicyIdentity | Should -BeExactly $fixture.Evidence.PolicyIdentity
            @($fixture.Plan.CurrentSettings.Keys | ForEach-Object {
                "$_|$($fixture.Plan.CurrentSettings[$_].GetType().FullName)|$($fixture.Plan.CurrentSettings[$_])"
            }) | Should -BeExactly @(
                'AllowNonProvisionableDevices|System.Boolean|False'
                'AlphanumericPasswordRequired|System.Boolean|True'
                'DeviceEncryptionEnabled|System.Boolean|True'
                'MinPasswordLength|System.Int32|6'
            )
            @($fixture.Plan.ApprovedSettings.Keys | ForEach-Object {
                "$_|$($fixture.Plan.ApprovedSettings[$_].GetType().FullName)|$($fixture.Plan.ApprovedSettings[$_])"
            }) | Should -BeExactly @(
                'AllowNonProvisionableDevices|System.Boolean|False'
                'AlphanumericPasswordRequired|System.Boolean|True'
                'DeviceEncryptionEnabled|System.Boolean|True'
                'MinPasswordLength|System.Int32|6'
            )
            $fixture.Plan.ActualDeviceBehavior | Should -BeExactly $fixture.Evidence.ActualDeviceBehavior
            $fixture.Plan.MobileDeviceManagement | Should -BeExactly $fixture.Evidence.MobileDeviceManagement
            $fixture.Plan.ConditionalAccess | Should -BeExactly $fixture.Evidence.ConditionalAccess
            $actual.Applied | Should -BeFalse
            $actual.RolledBack | Should -BeFalse
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
            $actual.ActualDeviceBehavior | Should -BeExactly $fixture.Plan.ActualDeviceBehavior
            $actual.MobileDeviceManagement | Should -BeExactly $fixture.Plan.MobileDeviceManagement
            $actual.ConditionalAccess | Should -BeExactly $fixture.Plan.ConditionalAccess
            @($fixture.Calls) | Should -BeExactly @('CompleteRead:Initial')
        }
    }
}
