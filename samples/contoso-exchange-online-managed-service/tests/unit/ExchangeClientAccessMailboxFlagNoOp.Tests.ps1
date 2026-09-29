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

    function New-ClientAccessMailboxFlagNoOpFixture {
        # Exact synthetic planner contract input; never tenant policy or mutation authority.
        $policy = [ordered]@{
            FixtureAuthority = 'SyntheticNonAuthoritative'
            ContractVersion = '1.0'
            PolicyVersion = '2026-09-29.1'
            SemanticAuthority = [ordered]@{ AuthorityId = 'synthetic-authority-for-tests-only'; Decision = 'Approved' }
            Approval = [ordered]@{
                ApprovalId = 'synthetic-approval-for-tests-only'
                ApprovedBy = 'fixture-owner@example.invalid'
                ApprovedUtc = '2026-09-28T12:00:00Z'
                ExpiresUtc = '2026-10-31T00:00:00Z'
            }
            EffectiveUtc = '2026-09-29T00:00:00Z'
            ContentHash = 'SHA256:SYNTHETIC-CLIENT-ACCESS-POLICY-V1'
            Evidence = [ordered]@{ EvidenceId = 'synthetic-evidence-for-tests-only'; ContentHash = 'SHA256:SYNTHETIC-CLIENT-ACCESS-POLICY-V1' }
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
            DesiredFlags = [ordered]@{ ActiveSyncEnabled = $false; MAPIEnabled = $true; OWAEnabled = $false }
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
        $clientImpact = [ordered]@{
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
        $plan = @(
            [ordered]@{
                Identity = 'user@contoso.example'
                RecipientTypeDetails = 'UserMailbox'
                MailboxPlan = 'Tenant-Enterprise'
                Disposition = 'Included'
                CurrentFlags = [ordered]@{ ActiveSyncEnabled = $false; MAPIEnabled = $true; OWAEnabled = $false }
                DesiredFlags = [ordered]@{ ActiveSyncEnabled = $false; MAPIEnabled = $true; OWAEnabled = $false }
                Decision = 'NoOp'
                ActualClientBehavior = 'Unverified'
                ClientImpact = $clientImpact
            }
            [ordered]@{
                Identity = 'shared@contoso.example'
                RecipientTypeDetails = 'SharedMailbox'
                MailboxPlan = 'Tenant-Frontline'
                Disposition = 'Included'
                CurrentFlags = [ordered]@{ ActiveSyncEnabled = $false; MAPIEnabled = $true; OWAEnabled = $false }
                DesiredFlags = [ordered]@{ ActiveSyncEnabled = $false; MAPIEnabled = $true; OWAEnabled = $false }
                Decision = 'NoOp'
                ActualClientBehavior = 'Unverified'
                ClientImpact = $clientImpact
            }
        )
        $state = [ordered]@{
            Complete = $true
            Rows = @(
                [ordered]@{ Identity = 'user@contoso.example'; RecipientTypeDetails = 'UserMailbox'; MailboxPlan = 'Tenant-Enterprise'; ActiveSyncEnabled = $false; MAPIEnabled = $true; OWAEnabled = $false }
                [ordered]@{ Identity = 'shared@contoso.example'; RecipientTypeDetails = 'SharedMailbox'; MailboxPlan = 'Tenant-Frontline'; ActiveSyncEnabled = $false; MAPIEnabled = $true; OWAEnabled = $false }
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
                [ordered]@{ Complete = $state.Complete; Rows = @($state.Rows | ForEach-Object { [ordered]@{} + $_ }) }
            }.GetNewClosure()
            MailboxWriter = {
                param($operation, $row)
                $calls.Add("MailboxWriter:${operation}:$($row.Identity)")
                throw 'No-op mailbox writer must never be called.'
            }.GetNewClosure()
            PlanWriter = {
                param($operation, $payload)
                $calls.Add("PlanWriter:$operation")
                throw 'No-op plan writer must never be called.'
            }.GetNewClosure()
        }
    }

    function Get-ClientAccessMailboxFlagNoOpArguments {
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

Describe 'EXR-007-A08-T01 client access mailbox flag no-op contract' {
    Context 'Negative: no-op requires one complete and exact affected set' {
        It 'rejects an incomplete no-op read and suppresses both writers' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagNoOpFixture
            $fixture.State.Complete = $false
            $arguments = Get-ClientAccessMailboxFlagNoOpArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxFlagReadIncomplete*'
            @($fixture.Calls | Where-Object { $_ -like '*Writer:*' }).Count | Should -Be 0
        }

        It 'rejects a planned affected identity missing from the complete no-op read and suppresses both writers' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagNoOpFixture
            $fixture.State.Rows = @($fixture.State.Rows | Where-Object Identity -CNE 'shared@contoso.example')
            $arguments = Get-ClientAccessMailboxFlagNoOpArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxFlagAffectedSetMismatch*shared@contoso.example*'
            @($fixture.Calls | Where-Object { $_ -like '*Writer:*' }).Count | Should -Be 0
        }

        It 'rejects an unexpected affected identity in the complete no-op read and suppresses both writers' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagNoOpFixture
            $fixture.State.Rows += [ordered]@{
                Identity = 'room@contoso.example'
                RecipientTypeDetails = 'RoomMailbox'
                MailboxPlan = 'Tenant-Enterprise'
                ActiveSyncEnabled = $false
                MAPIEnabled = $true
                OWAEnabled = $false
            }
            $arguments = Get-ClientAccessMailboxFlagNoOpArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxFlagAffectedSetMismatch*room@contoso.example*'
            @($fixture.Calls | Where-Object { $_ -like '*Writer:*' }).Count | Should -Be 0
        }

        It 'rejects a no-op three-flag prestate mismatch and suppresses both writers' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagNoOpFixture
            $fixture.State.Rows[0].ActiveSyncEnabled = $true
            $fixture.State.Rows[0].MAPIEnabled = $false
            $fixture.State.Rows[0].OWAEnabled = $true
            $arguments = Get-ClientAccessMailboxFlagNoOpArguments -Fixture $fixture

            # Act
            $act = { Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxFlagImmediateDrift*user@contoso.example*'
            @($fixture.Calls | Where-Object { $_ -like '*Writer:*' }).Count | Should -Be 0
        }
    }

    Context 'Positive: one complete exact no-op suppresses every writer' {
        It 'returns exact planner rows and performs no mailbox plan apply or rollback write' {
            # Arrange
            $fixture = New-ClientAccessMailboxFlagNoOpFixture
            $arguments = Get-ClientAccessMailboxFlagNoOpArguments -Fixture $fixture
            $expectedOperations = @('CompleteReadBefore','NoOp')

            # Act
            $actual = Invoke-ExchangeClientAccessMailboxFlagLifecycle @arguments

            # Assert
            $actual.PolicyHash | Should -BeExactly $fixture.PolicyHash
            $actual.PlanHash | Should -BeExactly $fixture.PlanHash
            $actual.NoOp | Should -BeTrue
            @($actual.Affected | ForEach-Object { "$($_.Identity)|$($_.RecipientTypeDetails)|$($_.MailboxPlan)|$($_.Disposition)|$($_.Decision)|$($_.CurrentFlags.ActiveSyncEnabled),$($_.CurrentFlags.MAPIEnabled),$($_.CurrentFlags.OWAEnabled)" }) |
                Should -BeExactly @(
                    'user@contoso.example|UserMailbox|Tenant-Enterprise|Included|NoOp|False,True,False'
                    'shared@contoso.example|SharedMailbox|Tenant-Frontline|Included|NoOp|False,True,False'
                )
            @($actual.Operations) | Should -BeExactly $expectedOperations
            @($fixture.Calls) | Should -BeExactly @('CompleteRead')
            @($fixture.Calls | Where-Object { $_ -like 'MailboxWriter:*' }).Count | Should -Be 0
            @($fixture.Calls | Where-Object { $_ -like 'PlanWriter:*' }).Count | Should -Be 0
        }
    }
}
