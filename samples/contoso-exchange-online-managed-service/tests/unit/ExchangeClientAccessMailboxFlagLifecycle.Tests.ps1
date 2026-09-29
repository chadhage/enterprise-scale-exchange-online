#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1'
    if (-not (Test-Path -LiteralPath $script:CommonModulePath -PathType Leaf)) {
        throw "Common module manifest is required: $script:CommonModulePath"
    }
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function Get-TestLocalDeterministicHash {
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$InputObject
        )

        function ConvertTo-TestLocalCanonicalNode {
            param(
                [AllowNull()]
                [object]$Node
            )

            if ($null -eq $Node) {
                return $null
            }

            if ($Node -is [string] -or $Node -is [bool] -or $Node -is [decimal] -or $Node.GetType().IsPrimitive) {
                return $Node
            }

            if ($Node -is [System.Collections.IDictionary]) {
                $names = [string[]]@($Node.Keys)
                [System.Array]::Sort($names, [System.StringComparer]::Ordinal)
                $canonical = [ordered]@{}
                foreach ($name in $names) {
                    $canonical[$name] = ConvertTo-TestLocalCanonicalNode -Node $Node[$name]
                }
                return $canonical
            }

            if ($Node -is [System.Management.Automation.PSCustomObject]) {
                $names = [string[]]@($Node.PSObject.Properties.Name)
                [System.Array]::Sort($names, [System.StringComparer]::Ordinal)
                $canonical = [ordered]@{}
                foreach ($name in $names) {
                    $canonical[$name] = ConvertTo-TestLocalCanonicalNode -Node $Node.PSObject.Properties[$name].Value
                }
                return $canonical
            }

            if ($Node -is [System.Collections.IList]) {
                return , @(foreach ($item in $Node) {
                    ConvertTo-TestLocalCanonicalNode -Node $item
                })
            }

            throw "UnsupportedTestLocalHashValue: $($Node.GetType().FullName)"
        }

        $canonical = ConvertTo-TestLocalCanonicalNode -Node $InputObject
        $json = if ($canonical -is [System.Collections.IList] -and $canonical.Count -eq 0) {
            '[]'
        }
        else {
            $canonical | ConvertTo-Json -Depth 64 -Compress
        }
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
        [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    }

    function New-ClientAccessMailboxFlagPolicy {
        # Synthetic contract input only. It is neither tenant policy nor authority to mutate a tenant.
        [ordered]@{
            FixtureAuthority = 'SyntheticNonAuthoritative'
            ContractVersion = '1.0'
            PolicyVersion = '2026-09-29.1'
            SemanticAuthority = [ordered]@{
                AuthorityId = 'synthetic-authority-for-tests-only'
                Decision = 'Approved'
            }
            Approval = [ordered]@{
                ApprovalId = 'synthetic-approval-for-tests-only'
                ApprovedBy = 'fixture-owner@example.invalid'
                ApprovedUtc = '2026-09-28T12:00:00Z'
                ExpiresUtc = '2026-10-31T00:00:00Z'
            }
            EffectiveUtc = '2026-09-29T00:00:00Z'
            ContentHash = 'SHA256:SYNTHETIC-CLIENT-ACCESS-POLICY-V1'
            Evidence = [ordered]@{
                EvidenceId = 'synthetic-evidence-for-tests-only'
                ContentHash = 'SHA256:SYNTHETIC-CLIENT-ACCESS-POLICY-V1'
            }
            ClassDisposition = @(
                [ordered]@{ RecipientTypeDetails = 'UserMailbox'; Disposition = 'Included' }
                [ordered]@{ RecipientTypeDetails = 'SharedMailbox'; Disposition = 'Included' }
                [ordered]@{ RecipientTypeDetails = 'RoomMailbox'; Disposition = 'Excluded' }
                [ordered]@{ RecipientTypeDetails = 'EquipmentMailbox'; Disposition = 'Excluded' }
            )
            PlanDisposition = @(
                [ordered]@{ MailboxPlan = 'Tenant-Frontline'; Disposition = 'Included' }
                [ordered]@{ MailboxPlan = 'Tenant-Enterprise'; Disposition = 'Included' }
            )
            DesiredFlags = [ordered]@{
                ActiveSyncEnabled = $false
                MAPIEnabled = $true
                OWAEnabled = $false
            }
            ClientImpact = [ordered]@{
                OutlookOnTheWeb = [ordered]@{ Impact = 'Disabled' }
                NewOutlookForWindows = [ordered]@{ Impact = 'Disabled' }
                OtherClients = [ordered]@{
                    Inventory = @('OutlookForWindowsMAPI')
                    ExplicitNone = $false
                    MAPIWhenTrue = 'Enabled'
                }
                OwnerAcceptance = [ordered]@{
                    Decision = 'Accepted'
                    AcceptedBy = 'fixture-owner@example.invalid'
                    AcceptedUtc = '2026-09-28T12:00:00Z'
                }
            }
        }
    }

    function New-ClientAccessMailboxFlagPlanRow {
        param(
            [string]$Identity,
            [string]$RecipientTypeDetails,
            [string]$MailboxPlan,
            [bool]$ActiveSyncEnabled = $true,
            [bool]$MAPIEnabled = $false,
            [bool]$OWAEnabled = $true
        )

        [ordered]@{
            Identity = $Identity
            RecipientTypeDetails = $RecipientTypeDetails
            MailboxPlan = $MailboxPlan
            Disposition = 'Included'
            CurrentFlags = [ordered]@{
                ActiveSyncEnabled = $ActiveSyncEnabled
                MAPIEnabled = $MAPIEnabled
                OWAEnabled = $OWAEnabled
            }
            DesiredFlags = [ordered]@{
                ActiveSyncEnabled = $false
                MAPIEnabled = $true
                OWAEnabled = $false
            }
            Decision = 'Changed'
            ActualClientBehavior = 'Unverified'
            ClientImpact = [ordered]@{
                OutlookOnTheWeb = [ordered]@{ Impact = 'Disabled' }
                NewOutlookForWindows = [ordered]@{ Impact = 'Disabled' }
                OtherClients = [ordered]@{
                    Inventory = @('OutlookForWindowsMAPI')
                    ExplicitNone = $false
                    MAPIWhenTrue = 'Enabled'
                }
                OwnerAcceptance = [ordered]@{
                    Decision = 'Accepted'
                    AcceptedBy = 'fixture-owner@example.invalid'
                    AcceptedUtc = '2026-09-28T12:00:00Z'
                }
            }
        }
    }

    function New-ClientAccessMailboxFlagLifecycleFixture {
        $policy = New-ClientAccessMailboxFlagPolicy
        $plan = @(
            New-ClientAccessMailboxFlagPlanRow -Identity 'user@contoso.example' -RecipientTypeDetails 'UserMailbox' -MailboxPlan 'Tenant-Enterprise'
            New-ClientAccessMailboxFlagPlanRow -Identity 'shared@contoso.example' -RecipientTypeDetails 'SharedMailbox' -MailboxPlan 'Tenant-Frontline'
        )
        $state = [ordered]@{
            Complete = $true
            Rows = @(
                [ordered]@{ Identity = 'user@contoso.example'; RecipientTypeDetails = 'UserMailbox'; MailboxPlan = 'Tenant-Enterprise'; ActiveSyncEnabled = $true; MAPIEnabled = $false; OWAEnabled = $true }
                [ordered]@{ Identity = 'shared@contoso.example'; RecipientTypeDetails = 'SharedMailbox'; MailboxPlan = 'Tenant-Frontline'; ActiveSyncEnabled = $true; MAPIEnabled = $false; OWAEnabled = $true }
            )
        }
        $calls = [Collections.Generic.List[string]]::new()

        [ordered]@{
            Policy = $policy
            Plan = $plan
            PolicyHash = Get-TestLocalDeterministicHash -InputObject $policy
            PlanHash = Get-TestLocalDeterministicHash -InputObject $plan
            AsOfUtc = '2026-09-29T12:00:00Z'
            State = $state
            Calls = $calls
            CompleteRead = {
                $calls.Add('CompleteRead')
                [ordered]@{
                    Complete = $state.Complete
                    Rows = @($state.Rows | ForEach-Object { [ordered]@{} + $_ })
                }
            }.GetNewClosure()
            MailboxWriter = {
                param($operation, $row)
                $calls.Add("MailboxWriter:${operation}:$($row.Identity)")
                $target = @($state.Rows | Where-Object Identity -CEQ $row.Identity)
                if ($target.Count -ne 1) { throw "Synthetic mailbox target is not unique: $($row.Identity)" }
                $flags = if ($operation -eq 'Apply') { $row.DesiredFlags } else { $row.CurrentFlags }
                $target[0].ActiveSyncEnabled = $flags.ActiveSyncEnabled
                $target[0].MAPIEnabled = $flags.MAPIEnabled
                $target[0].OWAEnabled = $flags.OWAEnabled
            }.GetNewClosure()
            PlanWriter = {
                param($operation, $payload)
                $calls.Add("PlanWriter:$operation")
            }.GetNewClosure()
        }
    }

    function Get-ClientAccessMailboxFlagLifecycleArguments {
        param([Parameter(Mandatory)]$Fixture)

        @{
            Policy = $Fixture.Policy
            Plan = $Fixture.Plan
            PolicyHash = $Fixture.PolicyHash
            PlanHash = $Fixture.PlanHash
            AsOfUtc = $Fixture.AsOfUtc
            CompleteRead = $Fixture.CompleteRead
            MailboxWriter = $Fixture.MailboxWriter
            PlanWriter = $Fixture.PlanWriter
        }
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-007-A08-T01 client access mailbox flag lifecycle contract' {
    Context 'Negative: mutation-time semantic authority approval and evidence objects are complete' {
        It 'rejects a missing mutation-time semantic authority object before any read or write' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.Policy.Remove('SemanticAuthority')
            $fixture.PolicyHash = Get-TestLocalDeterministicHash -InputObject $fixture.Policy
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessPolicySemanticAuthorityRequired*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects an incomplete mutation-time semantic authority object before any read or write' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.Policy.SemanticAuthority.Remove('AuthorityId')
            $fixture.PolicyHash = Get-TestLocalDeterministicHash -InputObject $fixture.Policy
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessPolicySemanticAuthorityIncomplete*AuthorityId*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects a missing mutation-time approval object before any read or write' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.Policy.Remove('Approval')
            $fixture.PolicyHash = Get-TestLocalDeterministicHash -InputObject $fixture.Policy
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessPolicyApprovalRequired*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects an incomplete mutation-time approval object before any read or write' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.Policy.Approval.Remove('ApprovedBy')
            $fixture.PolicyHash = Get-TestLocalDeterministicHash -InputObject $fixture.Policy
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessPolicyApprovalIncomplete*ApprovedBy*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects a missing mutation-time evidence object before any read or write' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.Policy.Remove('Evidence')
            $fixture.PolicyHash = Get-TestLocalDeterministicHash -InputObject $fixture.Policy
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessPolicyEvidenceRequired*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects an incomplete mutation-time evidence object before any read or write' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.Policy.Evidence.Remove('EvidenceId')
            $fixture.PolicyHash = Get-TestLocalDeterministicHash -InputObject $fixture.Policy
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessPolicyEvidenceIncomplete*EvidenceId*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects semantic authority that is no longer approved at mutation time' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.Policy.SemanticAuthority.Decision = 'Pending'
            $fixture.PolicyHash = Get-TestLocalDeterministicHash -InputObject $fixture.Policy
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessPolicySemanticAuthorityNotApproved*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects approval expired as of the mutation instant' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.Policy.Approval.ExpiresUtc = '2026-09-29T11:59:59Z'
            $fixture.PolicyHash = Get-TestLocalDeterministicHash -InputObject $fixture.Policy
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessPolicyApprovalExpired*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects evidence whose content hash no longer binds the policy' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.Policy.Evidence.ContentHash = 'SHA256:DIFFERENT'
            $fixture.PolicyHash = Get-TestLocalDeterministicHash -InputObject $fixture.Policy
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessPolicyEvidenceHashMismatch*'
            @($fixture.Calls).Count | Should -Be 0
        }
    }

    Context 'Negative: mutation-time effective policy and approved hashes are revalidated' {
        It 'rejects a policy not yet effective as of the mutation instant' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.Policy.EffectiveUtc = '2026-09-29T12:00:01Z'
            $fixture.PolicyHash = Get-TestLocalDeterministicHash -InputObject $fixture.Policy
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessPolicyNotEffective*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects a policy whose canonical hash differs from its approved hash' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.Policy.PolicyVersion = 'tampered'
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxFlagPolicyHashMismatch*'
            @($fixture.Calls).Count | Should -Be 0
        }

        It 'rejects a planner row whose canonical hash differs from its approved plan hash' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.Plan[0].DesiredFlags.ActiveSyncEnabled = $true
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxFlagPlanHashMismatch*'
            @($fixture.Calls).Count | Should -Be 0
        }
    }

    Context 'Negative: affected identities and all planned prestate flags remain exact' {
        It 'rejects ActiveSync MAPI or OWA prestate drift before any write' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.State.Rows[0].ActiveSyncEnabled = $false
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxFlagImmediateDrift*user@contoso.example*'
            @($fixture.Calls | Where-Object { $_ -like '*Writer:*' }).Count | Should -Be 0
        }

        It 'rejects an affected mailbox-plan identity changed since planning' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.State.Rows[1].MailboxPlan = 'Tenant-Enterprise'
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxFlagMailboxPlanChanged*shared@contoso.example*'
            @($fixture.Calls | Where-Object { $_ -like '*Writer:*' }).Count | Should -Be 0
        }
    }

    Context 'Negative: apply and readback are transactional' {
        It 'reverse-compensates a later target that mutates then throws plus prior targets and suppresses subsequent writes' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $fixture.Plan += New-ClientAccessMailboxFlagPlanRow -Identity 'later@contoso.example' -RecipientTypeDetails 'UserMailbox' -MailboxPlan 'Tenant-Enterprise'
            $fixture.Plan += New-ClientAccessMailboxFlagPlanRow -Identity 'suppressed@contoso.example' -RecipientTypeDetails 'SharedMailbox' -MailboxPlan 'Tenant-Frontline'
            $fixture.State.Rows += [ordered]@{ Identity = 'later@contoso.example'; RecipientTypeDetails = 'UserMailbox'; MailboxPlan = 'Tenant-Enterprise'; ActiveSyncEnabled = $true; MAPIEnabled = $false; OWAEnabled = $true }
            $fixture.State.Rows += [ordered]@{ Identity = 'suppressed@contoso.example'; RecipientTypeDetails = 'SharedMailbox'; MailboxPlan = 'Tenant-Frontline'; ActiveSyncEnabled = $true; MAPIEnabled = $false; OWAEnabled = $true }
            $fixture.PlanHash = Get-TestLocalDeterministicHash -InputObject $fixture.Plan
            $originalWriter = $fixture.MailboxWriter
            $fixture.MailboxWriter = {
                param($operation, $row)
                if ($operation -eq 'Apply' -and $row.Identity -eq 'later@contoso.example') {
                    & $originalWriter $operation $row
                    throw 'Synthetic later mailbox write failed.'
                }
                & $originalWriter $operation $row
            }.GetNewClosure()
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxFlagApplyFailed*later@contoso.example*'
            @($fixture.Calls | Where-Object { $_ -like 'MailboxWriter:*' }) | Should -BeExactly @(
                'MailboxWriter:Apply:user@contoso.example'
                'MailboxWriter:Apply:shared@contoso.example'
                'MailboxWriter:Apply:later@contoso.example'
                'MailboxWriter:Rollback:later@contoso.example'
                'MailboxWriter:Rollback:shared@contoso.example'
                'MailboxWriter:Rollback:user@contoso.example'
            )
            @($fixture.Calls | Where-Object { $_ -eq 'MailboxWriter:Apply:suppressed@contoso.example' }).Count | Should -Be 0
            @($fixture.State.Rows | ForEach-Object { "$($_.Identity)|$($_.ActiveSyncEnabled),$($_.MAPIEnabled),$($_.OWAEnabled)" }) |
                Should -BeExactly @(
                    'user@contoso.example|True,False,True'
                    'shared@contoso.example|True,False,True'
                    'later@contoso.example|True,False,True'
                    'suppressed@contoso.example|True,False,True'
                )
        }

        It 'rejects any ActiveSync MAPI or OWA mismatch in immediate apply readback' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $originalWriter = $fixture.MailboxWriter
            $fixture.MailboxWriter = {
                param($operation, $row)
                & $originalWriter $operation $row
                if ($operation -eq 'Apply' -and $row.Identity -eq 'user@contoso.example') {
                    $fixture.State.Rows[0].ActiveSyncEnabled = $true
                }
            }.GetNewClosure()
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxFlagApplyReadbackMismatch*ActiveSyncEnabled*'
        }
    }

    Context 'Negative: rollback restores the exact three-flag prestate' {
        It 'rejects rollback unless ActiveSync MAPI and OWA are restored exactly' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $originalWriter = $fixture.MailboxWriter
            $fixture.MailboxWriter = {
                param($operation, $row)
                & $originalWriter $operation $row
                if ($operation -eq 'Rollback' -and $row.Identity -eq 'user@contoso.example') {
                    $fixture.State.Rows[0].OWAEnabled = $false
                }
            }.GetNewClosure()
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxFlagRestorationMismatch*OWAEnabled*'
        }
    }

    Context 'Positive: one deterministic apply readback rollback and restoration lifecycle' {
        It 'uses exact planner rows and returns the verified three-flag lifecycle trace' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagLifecycleFixture
            $arguments = Get-ClientAccessMailboxFlagLifecycleArguments -Fixture $fixture
            $expectedOperations = @(
                'CompleteReadBefore'
                'PlanWriterApply'
                'MailboxWriterApply:user@contoso.example'
                'MailboxWriterApply:shared@contoso.example'
                'CompleteReadAfterApply'
                'PlanWriterRollback'
                'MailboxWriterRollback:shared@contoso.example'
                'MailboxWriterRollback:user@contoso.example'
                'CompleteReadAfterRollback'
            )

            # Act
            $actual = Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments

            # Assert
            $actual.PolicyHash | Should -BeExactly $fixture.PolicyHash
            $actual.PlanHash | Should -BeExactly $fixture.PlanHash
            @($actual.Affected | ForEach-Object { "$($_.Identity)|$($_.RecipientTypeDetails)|$($_.MailboxPlan)|$($_.Disposition)|$($_.Decision)" }) |
                Should -BeExactly @(
                    'user@contoso.example|UserMailbox|Tenant-Enterprise|Included|Changed'
                    'shared@contoso.example|SharedMailbox|Tenant-Frontline|Included|Changed'
                )
            $actual.Applied | Should -BeTrue
            $actual.ReadbackVerified | Should -BeTrue
            $actual.RolledBack | Should -BeTrue
            $actual.RestorationVerified | Should -BeTrue
            @($actual.Operations) | Should -BeExactly $expectedOperations
            @($fixture.State.Rows | ForEach-Object { "$($_.ActiveSyncEnabled),$($_.MAPIEnabled),$($_.OWAEnabled)" }) |
                Should -BeExactly @('True,False,True','True,False,True')
        }
    }
}
