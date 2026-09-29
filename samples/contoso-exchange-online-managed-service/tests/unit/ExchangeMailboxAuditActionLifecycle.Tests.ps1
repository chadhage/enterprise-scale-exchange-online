#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $script:SampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force -ErrorAction Stop
    $script:CatalogPath = Join-Path $script:SampleRoot 'config/mailbox-audit-actions.catalog.v1.json'
    $script:Catalog = Get-Content -LiteralPath $script:CatalogPath -Raw |
        ConvertFrom-Json -AsHashtable -DateKind String

    function New-MailboxAuditLifecycleFixture {
        $state = [ordered]@{
            DefaultAuditSet = @('Admin','Delegate')
            AuditAdmin = @('Create')
            AuditDelegate = @('Create')
            AuditOwner = @('Create')
            AuditBypassEnabled = $false
            PremiumEntitlement = 'Verified'
        }
        $calls = [Collections.Generic.List[string]]::new()
        [ordered]@{
            Catalog = $script:Catalog
            Scope = 'MailboxAuditActions'
            Identity = 'user@contoso.example'
            RecipientTypeDetails = 'UserMailbox'
            Approval = 'CHG-EXO013-001'
            Complete = $true
            State = $state
            Calls = $calls
            Read = {
                $calls.Add('Read')
                [ordered]@{
                    Complete = $true
                    Identity = 'user@contoso.example'
                    RecipientTypeDetails = 'UserMailbox'
                    DefaultAuditSet = @($state.DefaultAuditSet)
                    AuditAdmin = @($state.AuditAdmin)
                    AuditDelegate = @($state.AuditDelegate)
                    AuditOwner = @($state.AuditOwner)
                    AuditBypassEnabled = $state.AuditBypassEnabled
                    PremiumEntitlement = $state.PremiumEntitlement
                }
            }.GetNewClosure()
            Apply = {
                param($desired)
                $calls.Add('Apply')
                $state.DefaultAuditSet = @($desired.DefaultAuditSet)
                $state.AuditAdmin = @($desired.AuditAdmin)
                $state.AuditDelegate = @($desired.AuditDelegate)
                $state.AuditOwner = @($desired.AuditOwner)
            }.GetNewClosure()
            Rollback = {
                param($before)
                $calls.Add('Rollback')
                $state.DefaultAuditSet = @($before.DefaultAuditSet)
                $state.AuditAdmin = @($before.AuditAdmin)
                $state.AuditDelegate = @($before.AuditDelegate)
                $state.AuditOwner = @($before.AuditOwner)
            }.GetNewClosure()
        }
    }
}

BeforeDiscovery {
    $script:LifecycleNegativeCases = @(
        @{
            Name = 'rejects a missing catalog'; Expected = 'MailboxAuditActionCatalogRequired*'
            Arrange = { $f = New-MailboxAuditLifecycleFixture; $f.Catalog = $null; $f }
        }
        @{
            Name = 'rejects a noncanonical scope'; Expected = 'MailboxAuditActionScopeInvalid*'
            Arrange = { $f = New-MailboxAuditLifecycleFixture; $f.Scope = 'MailboxAuditing'; $f }
        }
        @{
            Name = 'rejects a missing change approval'; Expected = 'MailboxAuditActionApprovalRequired*'
            Arrange = { $f = New-MailboxAuditLifecycleFixture; $f.Approval = ''; $f }
        }
        @{
            Name = 'rejects an incomplete raw collection before mutation'; Expected = 'MailboxAuditActionCollectionIncomplete*'
            Arrange = { $f = New-MailboxAuditLifecycleFixture; $f.Complete = $false; $f }
        }
        @{
            Name = 'rejects an audit bypass before mutation'; Expected = 'MailboxAuditActionBypassEnabled*'
            Arrange = { $f = New-MailboxAuditLifecycleFixture; $f.State.AuditBypassEnabled = $true; $f }
        }
        @{
            Name = 'rejects customization without explicit authorization'; Expected = 'MailboxAuditActionCustomizationUnauthorized*'
            Arrange = { $f = New-MailboxAuditLifecycleFixture; $f.Approval = 'UNAUTHORIZED'; $f }
        }
        @{
            Name = 'rejects an unresolved premium entitlement'; Expected = 'MailboxAuditActionPremiumEntitlementUnresolved*'
            Arrange = { $f = New-MailboxAuditLifecycleFixture; $f.State.PremiumEntitlement = 'Unverified'; $f }
        }
        @{
            Name = 'surfaces an apply dependency failure'; Expected = 'MailboxAuditActionApplyFailed*'
            Arrange = { $f = New-MailboxAuditLifecycleFixture; $f.Apply = { param($desired) throw 'Set-Mailbox failed' }; $f }
        }
        @{
            Name = 'rejects incomplete apply readback'; Expected = 'MailboxAuditActionReadbackIncomplete*'
            Arrange = {
                $f = New-MailboxAuditLifecycleFixture
                $originalRead = $f.Read
                $readCount = [ref] 0
                $f.Read = { $readCount.Value++; $row = & $originalRead; if ($readCount.Value -eq 2) { $row.Complete = $false }; $row }.GetNewClosure()
                $f
            }
        }
        @{
            Name = 'rejects apply readback drift'; Expected = 'MailboxAuditActionReadbackMismatch*'
            Arrange = {
                $f = New-MailboxAuditLifecycleFixture
                $f.Apply = { param($desired) $f.Calls.Add('Apply') }.GetNewClosure()
                $f
            }
        }
        @{
            Name = 'surfaces a rollback dependency failure'; Expected = 'MailboxAuditActionRollbackFailed*'
            Arrange = { $f = New-MailboxAuditLifecycleFixture; $f.Rollback = { param($before) throw 'Set-Mailbox rollback failed' }; $f }
        }
        @{
            Name = 'rejects rollback readback drift'; Expected = 'MailboxAuditActionRollbackMismatch*'
            Arrange = {
                $f = New-MailboxAuditLifecycleFixture
                $originalRollback = $f.Rollback
                $f.Rollback = { param($before) & $originalRollback $before; $f.State.AuditOwner = @('Unexpected') }.GetNewClosure()
                $f
            }
        }
        @{
            Name = 'rejects a non-injectable read dependency'; Expected = 'MailboxAuditActionReadRequired*'
            Arrange = { $f = New-MailboxAuditLifecycleFixture; $f.Read = $null; $f }
        }
    )
}

Describe 'EXR-007-A07 mailbox audit action lifecycle contract' {
    Context 'Negative: apply readback and rollback fail closed without tenant side effects' {
        It '<Name>' -ForEach $script:LifecycleNegativeCases {
            # Arrange
            $fixture = & $Arrange
            $arguments = @{
                Catalog = $fixture.Catalog
                Scope = $fixture.Scope
                Identity = $fixture.Identity
                RecipientTypeDetails = $fixture.RecipientTypeDetails
                Approval = $fixture.Approval
                CollectionComplete = $fixture.Complete
                Read = $fixture.Read
                Apply = $fixture.Apply
                Rollback = $fixture.Rollback
            }

            # Act
            $act = { Invoke-ExchangeMailboxAuditActionLifecycle @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage $Expected
        }
    }

    Context 'Positive: injected apply readback and rollback are exact and deterministic' {
        It 'applies the catalog action sets verifies readback and restores the exact before state' {
            # Arrange
            $fixture = New-MailboxAuditLifecycleFixture
            $arguments = @{
                Catalog = $fixture.Catalog
                Scope = $fixture.Scope
                Identity = $fixture.Identity
                RecipientTypeDetails = $fixture.RecipientTypeDetails
                Approval = $fixture.Approval
                CollectionComplete = $fixture.Complete
                Read = $fixture.Read
                Apply = $fixture.Apply
                Rollback = $fixture.Rollback
            }
            $expected = [ordered]@{
                Scope = 'MailboxAuditActions'
                Identity = 'user@contoso.example'
                RecipientTypeDetails = 'UserMailbox'
                Applied = $true
                ReadbackVerified = $true
                RolledBack = $true
                RollbackVerified = $true
                GlobalAuditIngestion = 'Unverified'
                GlobalAuditRetention = 'Unverified'
                Operations = @('ReadBefore','Apply','ReadAfterApply','Rollback','ReadAfterRollback')
            }

            # Act
            $actual = Invoke-ExchangeMailboxAuditActionLifecycle @arguments

            # Assert
            ($actual | ConvertTo-Json -Depth 20 -Compress) |
                Should -BeExactly ($expected | ConvertTo-Json -Depth 20 -Compress)
            @($fixture.Calls) | Should -BeExactly @('Read','Apply','Read','Rollback','Read')
            $fixture.State.DefaultAuditSet | Should -BeExactly @('Admin','Delegate')
            $fixture.State.AuditAdmin | Should -BeExactly @('Create')
            $fixture.State.AuditDelegate | Should -BeExactly @('Create')
            $fixture.State.AuditOwner | Should -BeExactly @('Create')
        }
    }
}
