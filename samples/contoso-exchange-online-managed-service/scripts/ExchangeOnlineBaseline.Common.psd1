@{
    RootModule           = 'ExchangeOnlineBaseline.Common.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = '7a2c0d1e-4b6f-4f23-9c0a-8d5e1b3f6a41'
    Author               = 'Contoso Exchange Online managed service'
    CompanyName          = 'Contoso'
    Copyright            = '(c) Contoso. All rights reserved.'
    Description          = 'Shared ownership of Exchange Online baseline configuration resolution, canonical serialization, hashing, schema validation, licensing and entitlement decisions, normalized control evaluation, risk acceptance, and evidence artifacts.'
    PowerShellVersion    = '7.0'

    # ARC-001 and COM-001: the public API is declared explicitly so callers cannot bind to
    # internal helpers and so manifest drift from the module is a test failure.
    FunctionsToExport    = @(
        'Resolve-BaselineConfiguration'
        'Assert-BaselineConfiguration'
        'Assert-BaselineDesiredState'
        'Get-BaselineContext'
        'Resolve-BaselineEntitlement'
        'Get-BaselineTenantServicePlan'
        'Get-BaselineTargetEntitlement'
        'Invoke-BaselineGraphRequest'
        'Get-BaselineGraphDiscovery'
        'Get-BaselineTargetPopulation'
        'Get-BaselineLicensingMatrix'
        'Test-BaselineSafeDocumentsPreflight'
        'ConvertTo-CanonicalJson'
        'Get-BaselineConfigurationHash'
        'Compare-NormalizedCollection'
        'Get-ControlApplicability'
        'Test-RiskAcceptance'
        'New-ControlResult'
        'New-BaselineEvidence'
        'Get-BaselineEvidence'
        'New-BaselineControlRegistry'
        'Get-BaselineControlRegistry'
        'Get-BaselineControlCatalog'
        'Test-BaselineControlCoverage'
        'Test-BaselineEvidenceFramework'
        'Get-ConditionalAccessEvidence'
        'Test-ConditionalAccessControl'
        'Get-AcceptedDomainEvidence'
        'Test-AcceptedDomainControl'
        'Get-OutboundForwardingEvidence'
        'Test-OutboundForwardingControl'
        'Get-ExternalPostmasterEvidence'
        'Test-ExternalPostmasterControl'
        'Get-MailboxAuditingEvidence'
        'Test-MailboxAuditingControl'
        'Get-ExternalSenderTagEvidence'
        'Test-ExternalSenderTagControl'
        'Get-RemoteDomainEvidence'
        'Get-ExchangeRoleAssignmentEvidence'
        'Test-ExchangeRoleAssignmentControl'
        'Get-SmtpAuthenticationEvidence'
        'Test-SmtpAuthenticationControl'
        'Get-BaselineParameterHash'
        'New-BaselineEvidenceEnvelope'
        'Test-BaselineControl'
        'Get-BaselineResultContract'
        'Get-CanonicalComparisonContract'
        'Get-ApplicabilityAuthorityContract'
        'Get-ArtifactVersionContract'
        'Get-ApprovalSignatureContract'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags = @('ExchangeOnline', 'DefenderForOffice365', 'SecureBaseline')
        }
    }
}
