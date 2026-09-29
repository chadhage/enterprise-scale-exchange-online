#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $script:SampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force -ErrorAction Stop
    $script:CatalogPath = Join-Path $script:SampleRoot 'config/mailbox-audit-actions.catalog.v1.json'
    $script:Catalog = Get-Content -LiteralPath $script:CatalogPath -Raw |
        ConvertFrom-Json -AsHashtable -DateKind String

    function Copy-MailboxAuditCatalog {
        $script:Catalog | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable -DateKind String
    }
}

BeforeDiscovery {
    $script:CatalogNegativeCases = @(
        @{
            Name = 'rejects a catalog without catalogVersion'
            Expected = 'MailboxAuditActionCatalogVersionUnsupported*'
            Arrange = { $candidate = Copy-MailboxAuditCatalog; $candidate.Remove('catalogVersion'); $candidate }
        }
        @{
            Name = 'rejects an unsupported catalog version'
            Expected = 'MailboxAuditActionCatalogVersionUnsupported*'
            Arrange = { $candidate = Copy-MailboxAuditCatalog; $candidate.catalogVersion = '2.0.0'; $candidate }
        }
        @{
            Name = 'rejects a catalog not bound to EXO-013'
            Expected = 'MailboxAuditActionCatalogContractInvalid*'
            Arrange = { $candidate = Copy-MailboxAuditCatalog; $candidate.contractId = 'EXO-006'; $candidate }
        }
        @{
            Name = 'rejects a catalog with a noncanonical scope'
            Expected = 'MailboxAuditActionCatalogScopeInvalid*'
            Arrange = { $candidate = Copy-MailboxAuditCatalog; $candidate.scope = 'MailboxAuditing'; $candidate }
        }
        @{
            Name = 'rejects fixtures presented as authority'
            Expected = 'MailboxAuditActionCatalogAuthorityInvalid*'
            Arrange = { $candidate = Copy-MailboxAuditCatalog; $candidate.authority.fixturesAreAuthority = $true; $candidate }
        }
        @{
            Name = 'rejects an unpinned Microsoft Learn source set'
            Expected = 'MailboxAuditActionCatalogSourcesInvalid*'
            Arrange = { $candidate = Copy-MailboxAuditCatalog; $candidate.authority.sources[0].url = 'https://example.invalid/audit'; $candidate }
        }
        @{
            Name = 'rejects a retrieval date other than 2026-09-29'
            Expected = 'MailboxAuditActionCatalogRetrievalDateInvalid*'
            Arrange = { $candidate = Copy-MailboxAuditCatalog; $candidate.retrievedOn = '2026-09-28'; $candidate }
        }
        @{
            Name = 'rejects a denominator that omits an applicable mailbox type'
            Expected = 'MailboxAuditActionCatalogApplicabilityInvalid*'
            Arrange = { $candidate = Copy-MailboxAuditCatalog; $candidate.applicability.includedRecipientTypeDetails = @('UserMailbox','SharedMailbox','RoomMailbox'); $candidate }
        }
        @{
            Name = 'rejects GroupMailbox in the denominator'
            Expected = 'MailboxAuditActionCatalogApplicabilityInvalid*'
            Arrange = { $candidate = Copy-MailboxAuditCatalog; $candidate.applicability.includedRecipientTypeDetails += 'GroupMailbox'; $candidate }
        }
        @{
            Name = 'rejects an incomplete AuditAdmin AuditDelegate AuditOwner mapping'
            Expected = 'MailboxAuditActionCatalogSignInTypesInvalid*'
            Arrange = { $candidate = Copy-MailboxAuditCatalog; $candidate.signInTypes = @($candidate.signInTypes | Where-Object property -NE 'AuditOwner'); $candidate }
        }
        @{
            Name = 'rejects DefaultAuditSet semantics that authorize customization'
            Expected = 'MailboxAuditActionCatalogCustomizationPolicyInvalid*'
            Arrange = { $candidate = Copy-MailboxAuditCatalog; $candidate.defaultAuditSetSemantics.customizationPolicy = 'Customization is automatically approved.'; $candidate }
        }
        @{
            Name = 'rejects premium actions without independent entitlement'
            Expected = 'MailboxAuditActionCatalogPremiumEntitlementInvalid*'
            Arrange = { $candidate = Copy-MailboxAuditCatalog; $candidate.premiumEntitlement.requiredEvidence = 'DefaultAuditSet'; $candidate }
        }
        @{
            Name = 'rejects global ingestion or retention represented as verified'
            Expected = 'MailboxAuditActionCatalogGlobalAuditInvalid*'
            Arrange = { $candidate = Copy-MailboxAuditCatalog; $candidate.globalAudit.ingestion = 'Enabled'; $candidate }
        }
    )
}

Describe 'EXR-007-A07 mailbox audit action catalog contract' {
    Context 'Negative: malformed or unauthorized authority contracts are refused' {
        It '<Name>' -ForEach $script:CatalogNegativeCases {
            # Arrange
            $candidate = & $Arrange

            # Act
            $act = { Test-ExchangeMailboxAuditActionCatalog -Catalog $candidate }

            # Assert
            $act | Should -Throw -ExpectedMessage $Expected
        }
    }

    Context 'Positive: the repository-pinned EXO-013 catalog is the sole authority contract' {
        It 'accepts version 1.0.0 with the pinned Microsoft Learn sources and exact canonical shape' {
            # Arrange
            $expected = [ordered]@{
                ContractId = 'EXO-013'
                CatalogVersion = '1.0.0'
                Scope = 'MailboxAuditActions'
                RetrievedOn = '2026-09-29'
                IsValid = $true
                AuthorityKind = 'MicrosoftLearn'
                SourceUrls = @(
                    'https://learn.microsoft.com/en-us/purview/audit-mailboxes'
                    'https://learn.microsoft.com/en-us/purview/audit-premium'
                    'https://learn.microsoft.com/en-us/purview/audit-log-activities'
                )
                IncludedRecipientTypeDetails = @('UserMailbox','SharedMailbox','RoomMailbox','EquipmentMailbox')
                ExcludedRecipientTypeDetails = @('GroupMailbox')
                SignInProperties = @('AuditAdmin','AuditDelegate','AuditOwner')
                GlobalAuditIngestion = 'Unverified'
                GlobalAuditRetention = 'Unverified'
            }

            # Act
            $actual = Test-ExchangeMailboxAuditActionCatalog -Catalog $script:Catalog

            # Assert
            ($actual | ConvertTo-Json -Depth 20 -Compress) |
                Should -BeExactly ($expected | ConvertTo-Json -Depth 20 -Compress)
        }
    }
}
