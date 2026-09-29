#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $script:SampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force -ErrorAction Stop
    $script:CatalogPath = Join-Path $script:SampleRoot 'config/mailbox-audit-actions.catalog.v1.json'
    $script:Catalog = Get-Content -LiteralPath $script:CatalogPath -Raw |
        ConvertFrom-Json -AsHashtable -DateKind String

    function New-MailboxAuditRawRecord {
        param(
            [string]$Identity = 'user@contoso.example',
            [string]$RecipientTypeDetails = 'UserMailbox',
            [string[]]$DefaultAuditSet = @('Admin','Delegate','Owner'),
            [string[]]$AuditAdmin = @('ApplyRecord','Copy','Create','FolderBind','HardDelete','Move','MoveToDeletedItems','SendAs','SendOnBehalf','SoftDelete','Update','UpdateCalendarDelegation','UpdateFolderPermissions','UpdateInboxRules'),
            [string[]]$AuditDelegate = @('ApplyRecord','Create','FolderBind','HardDelete','Move','MoveToDeletedItems','SendAs','SendOnBehalf','SoftDelete','Update','UpdateFolderPermissions','UpdateInboxRules'),
            [string[]]$AuditOwner = @('ApplyRecord','Create','HardDelete','MailboxLogin','Move','MoveToDeletedItems','SoftDelete','Update','UpdateCalendarDelegation','UpdateFolderPermissions','UpdateInboxRules'),
            [bool]$AuditBypassEnabled = $false,
            [ValidateSet('Verified','Unverified','Missing')][string]$PremiumEntitlement = 'Unverified'
        )
        [ordered]@{
            Identity = $Identity
            RecipientTypeDetails = $RecipientTypeDetails
            DefaultAuditSet = @($DefaultAuditSet)
            AuditAdmin = @($AuditAdmin)
            AuditDelegate = @($AuditDelegate)
            AuditOwner = @($AuditOwner)
            AuditBypassEnabled = $AuditBypassEnabled
            PremiumEntitlement = $PremiumEntitlement
        }
    }

    function New-MailboxAuditCollection {
        param(
            [object[]]$Records = @((New-MailboxAuditRawRecord)),
            [bool]$Complete = $true,
            [string]$FailureReason = ''
        )
        [ordered]@{ Complete = $Complete; FailureReason = $FailureReason; Records = @($Records) }
    }
}

BeforeDiscovery {
    $script:NormalizationNegativeCases = @(
        @{
            Name = 'rejects a missing catalog'; Expected = 'MailboxAuditActionCatalogRequired*'
            Arrange = { @{ Catalog = $null; RawCollection = New-MailboxAuditCollection } }
        }
        @{
            Name = 'rejects an unsupported catalog version'; Expected = 'MailboxAuditActionCatalogVersionUnsupported*'
            Arrange = {
                $catalog = $script:Catalog | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
                $catalog.catalogVersion = '9.0.0'
                @{ Catalog = $catalog; RawCollection = New-MailboxAuditCollection }
            }
        }
        @{
            Name = 'rejects a missing raw collection'; Expected = 'MailboxAuditActionRawCollectionRequired*'
            Arrange = { @{ Catalog = $script:Catalog; RawCollection = $null } }
        }
        @{
            Name = 'rejects an explicitly incomplete raw collection'; Expected = 'MailboxAuditActionCollectionIncomplete*'
            Arrange = { @{ Catalog = $script:Catalog; RawCollection = New-MailboxAuditCollection -Complete $false } }
        }
        @{
            Name = 'rejects a raw collection with a dependency failure'; Expected = 'MailboxAuditActionCollectionFailed*'
            Arrange = { @{ Catalog = $script:Catalog; RawCollection = New-MailboxAuditCollection -Complete $false -FailureReason 'Get-EXOMailbox throttled' } }
        }
        @{
            Name = 'rejects duplicate mailbox identities after normalization'; Expected = 'MailboxAuditActionIdentityDuplicate*'
            Arrange = { @{ Catalog = $script:Catalog; RawCollection = New-MailboxAuditCollection -Records @((New-MailboxAuditRawRecord),(New-MailboxAuditRawRecord -Identity 'USER@CONTOSO.EXAMPLE')) } }
        }
        @{
            Name = 'rejects a recipient type outside the canonical denominator'; Expected = 'MailboxAuditActionRecipientTypeUnsupported*'
            Arrange = { @{ Catalog = $script:Catalog; RawCollection = New-MailboxAuditCollection -Records @((New-MailboxAuditRawRecord -RecipientTypeDetails 'DiscoveryMailbox')) } }
        }
        @{
            Name = 'rejects an unknown DefaultAuditSet token'; Expected = 'MailboxAuditActionDefaultAuditSetInvalid*'
            Arrange = { @{ Catalog = $script:Catalog; RawCollection = New-MailboxAuditCollection -Records @((New-MailboxAuditRawRecord -DefaultAuditSet @('Admin','Delegate','Owner','Unknown'))) } }
        }
        @{
            Name = 'rejects missing managed DefaultAuditSet tokens as unauthorized customization'; Expected = 'MailboxAuditActionCustomizationUnauthorized*'
            Arrange = { @{ Catalog = $script:Catalog; RawCollection = New-MailboxAuditCollection -Records @((New-MailboxAuditRawRecord -DefaultAuditSet @('Admin','Delegate'))) } }
        }
        @{
            Name = 'rejects an audit bypass enabled mailbox'; Expected = 'MailboxAuditActionBypassEnabled*'
            Arrange = { @{ Catalog = $script:Catalog; RawCollection = New-MailboxAuditCollection -Records @((New-MailboxAuditRawRecord -AuditBypassEnabled $true)) } }
        }
        @{
            Name = 'rejects a missing required AuditAdmin action'; Expected = 'MailboxAuditActionCoverageIncomplete*'
            Arrange = { @{ Catalog = $script:Catalog; RawCollection = New-MailboxAuditCollection -Records @((New-MailboxAuditRawRecord -AuditAdmin @('Create'))) } }
        }
        @{
            Name = 'rejects a missing required AuditDelegate or AuditOwner action list'; Expected = 'MailboxAuditActionCoverageIncomplete*'
            Arrange = { @{ Catalog = $script:Catalog; RawCollection = New-MailboxAuditCollection -Records @((New-MailboxAuditRawRecord -AuditDelegate @() -AuditOwner @())) } }
        }
        @{
            Name = 'rejects premium actions when entitlement is not verified'; Expected = 'MailboxAuditActionPremiumEntitlementUnresolved*'
            Arrange = {
                $record = New-MailboxAuditRawRecord
                $record.AuditOwner += @('MailItemsAccessed','SearchQueryInitiated','Send')
                @{ Catalog = $script:Catalog; RawCollection = New-MailboxAuditCollection -Records @($record) }
            }
        }
    )
}

Describe 'EXR-007-A07 mailbox audit action normalization contract' {
    Context 'Negative: unresolved or unsafe mailbox observations are never normalized as compliant' {
        It '<Name>' -ForEach $script:NormalizationNegativeCases {
            # Arrange
            $arguments = & $Arrange

            # Act
            $act = { ConvertTo-ExchangeMailboxAuditActionAssessment @arguments }

            # Assert
            $act | Should -Throw -ExpectedMessage $Expected
        }
    }

    Context 'Positive: complete raw observations normalize to one exact deterministic result shape' {
        It 'normalizes User Shared Room and Equipment mailboxes while excluding GroupMailbox' {
            # Arrange
            $records = @(
                (New-MailboxAuditRawRecord -Identity 'room@contoso.example' -RecipientTypeDetails 'RoomMailbox')
                (New-MailboxAuditRawRecord -Identity 'group@contoso.example' -RecipientTypeDetails 'GroupMailbox')
                (New-MailboxAuditRawRecord -Identity 'user@contoso.example' -RecipientTypeDetails 'UserMailbox')
                (New-MailboxAuditRawRecord -Identity 'equipment@contoso.example' -RecipientTypeDetails 'EquipmentMailbox')
                (New-MailboxAuditRawRecord -Identity 'shared@contoso.example' -RecipientTypeDetails 'SharedMailbox')
            )
            $expectedIdentities = @('equipment@contoso.example','room@contoso.example','shared@contoso.example','user@contoso.example')
            $arguments = @{
                Catalog = $script:Catalog
                RawCollection = New-MailboxAuditCollection -Records $records
            }

            # Act
            $actual = ConvertTo-ExchangeMailboxAuditActionAssessment @arguments

            # Assert
            [string[]]@($actual.Keys) | Should -BeExactly @('Scope','CatalogVersion','Complete','FailureReason','Results')
            $actual.Scope | Should -BeExactly 'MailboxAuditActions'
            $actual.CatalogVersion | Should -BeExactly '1.0.0'
            $actual.Complete | Should -BeTrue
            $actual.FailureReason | Should -BeExactly ''
            @($actual.Results).Count | Should -Be 4
            @($actual.Results.Identity) | Should -BeExactly $expectedIdentities
            foreach ($result in @($actual.Results)) {
                [string[]]@($result.Keys) | Should -BeExactly @(
                    'Identity','RecipientTypeDetails','DefaultAuditSet','AuditAdmin','AuditDelegate','AuditOwner',
                    'PremiumEntitlement','AuditBypassEnabled','Status','Findings',
                    'GlobalAuditIngestion','GlobalAuditRetention'
                )
                $result.Status | Should -BeExactly 'Compliant'
                @($result.Findings).Count | Should -Be 0
                $result.GlobalAuditIngestion | Should -BeExactly 'Unverified'
                $result.GlobalAuditRetention | Should -BeExactly 'Unverified'
            }
        }
    }
}
