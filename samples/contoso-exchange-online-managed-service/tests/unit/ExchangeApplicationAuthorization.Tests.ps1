#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    Import-Module $script:ModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:AsOfUtc = [datetimeoffset]'2026-09-26T12:00:00Z'
    $script:TenantId = '00000000-0000-0000-0000-000000000001'
    $script:ApplicationId = '11111111-2222-3333-4444-555555555555'
    $script:ServicePrincipalObjectId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    $script:CurrentInputHash = '0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF'

    function Copy-ApplicationAuthorizationFixture {
        param([Parameter(Mandatory)][object]$InputObject)

        $InputObject | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
    }

    function New-ApplicationAuthorizationFixture {
        $application = [pscustomobject]@{
            ApplicationId = $script:ApplicationId
            DisplayName = 'Contoso Scoped Mail Reader'
            TenantId = $script:TenantId
            SuppliedAtUtc = '2026-09-26T08:00:00Z'
            SourceReference = 'fixture:application-owner:change-431'
            InputHash = $script:CurrentInputHash
        }
        $additiveEntraEvidence = [pscustomobject]@{
            ApplicationId = $script:ApplicationId
            ServicePrincipalObjectId = $script:ServicePrincipalObjectId
            TenantId = $script:TenantId
            ApplicationRoles = @('Exchange.ManageAsApp')
            ConsentedPermissions = @('Exchange.ManageAsApp')
            ConsentType = 'AdminConsent'
            Complete = $true
            SuppliedAtUtc = '2026-09-26T09:00:00Z'
            SourceReference = 'fixture:independent-entra-review:change-431'
            InputHash = $script:CurrentInputHash
        }
        $roles = [pscustomobject]@{
            Items = @(
                [pscustomobject]@{
                    Identity = 'Application Mail.Read'
                    Name = 'Application Mail.Read'
                    RoleType = 'Application'
                    AllowsMailboxAccess = $true
                }
            )
            Complete = $true
            NextLink = $null
        }
        $servicePrincipals = [pscustomobject]@{
            Items = @(
                [pscustomobject]@{
                    Identity = $script:ServicePrincipalObjectId
                    ObjectId = $script:ServicePrincipalObjectId
                    AppId = $script:ApplicationId
                    DisplayName = 'Contoso Scoped Mail Reader'
                }
            )
            Complete = $true
            NextLink = $null
        }
        $assignments = [pscustomobject]@{
            Items = @(
                [pscustomobject]@{
                    Identity = 'Application Mail.Read-Contoso Scoped Mail Reader'
                    Role = 'Application Mail.Read'
                    RoleAssignee = $script:ServicePrincipalObjectId
                    RoleAssigneeType = 'ServicePrincipal'
                    Enabled = $true
                    RecipientReadScope = 'CustomRecipientScope'
                    RecipientWriteScope = 'None'
                    CustomResourceScope = 'Scope-Approved-Mailboxes'
                }
            )
            Complete = $true
            NextLink = $null
        }
        $managementScopes = [pscustomobject]@{
            Items = @(
                [pscustomobject]@{
                    Identity = 'Scope-Approved-Mailboxes'
                    RecipientRoot = 'contoso.example/Users'
                    RecipientRestrictionFilter = "CustomAttribute1 -eq 'ApprovedApp'"
                    ServerRestrictionFilter = $null
                    Exclusive = $false
                }
            )
            Complete = $true
            NextLink = $null
        }
        $authorizationProbes = [pscustomobject]@{
            Items = @(
                [pscustomobject]@{
                    ApplicationId = $script:ApplicationId
                    Mailbox = 'approved@contoso.example'
                    Expected = 'Allowed'
                    Authorized = $true
                    AssignmentIdentity = 'Application Mail.Read-Contoso Scoped Mail Reader'
                    ScopeIdentity = 'Scope-Approved-Mailboxes'
                    TestedAtUtc = '2026-09-26T10:00:00Z'
                    InputHash = $script:CurrentInputHash
                }
                [pscustomobject]@{
                    ApplicationId = $script:ApplicationId
                    Mailbox = 'denied@contoso.example'
                    Expected = 'Denied'
                    Authorized = $false
                    AssignmentIdentity = 'Application Mail.Read-Contoso Scoped Mail Reader'
                    ScopeIdentity = 'Scope-Approved-Mailboxes'
                    TestedAtUtc = '2026-09-26T10:05:00Z'
                    InputHash = $script:CurrentInputHash
                }
            )
            Complete = $true
            NextLink = $null
        }
        $propagation = [pscustomobject]@{
            Statement = 'Exchange assignment and scope changes may require propagation before authorization probes are conclusive.'
            MaximumDelay = 'PT2H'
            ObservedAfter = 'PT2H'
            CheckedAtUtc = '2026-09-26T10:05:00Z'
            SourceReference = 'fixture:exchange-propagation-limit'
        }
        $approved = @(
            [pscustomobject]@{
                ApplicationId = $script:ApplicationId
                ServicePrincipalObjectId = $script:ServicePrincipalObjectId
                Roles = @('Application Mail.Read')
                AssignmentIdentities = @('Application Mail.Read-Contoso Scoped Mail Reader')
                ManagementScopes = @('Scope-Approved-Mailboxes')
                AllowedMailboxes = @('approved@contoso.example')
                DeniedMailboxes = @('denied@contoso.example')
                InputHash = $script:CurrentInputHash
                ApprovalReference = 'fixture:exchange-approval:change-431'
            }
        )

        [pscustomobject]@{
            Application = $application
            AdditiveEntraEvidence = $additiveEntraEvidence
            Roles = $roles
            ServicePrincipals = $servicePrincipals
            Assignments = $assignments
            ManagementScopes = $managementScopes
            AuthorizationProbes = $authorizationProbes
            Propagation = $propagation
            Approved = $approved
        }
    }

    function Invoke-ApplicationAuthorizationFixture {
        param([Parameter(Mandatory)][object]$Fixture)

        $evidence = Get-ExchangeApplicationAuthorizationEvidence `
            -ApplicationEvidence $Fixture.Application `
            -AdditiveEntraEvidence $Fixture.AdditiveEntraEvidence `
            -RoleCollection { $Fixture.Roles }.GetNewClosure() `
            -ServicePrincipalCollection { $Fixture.ServicePrincipals }.GetNewClosure() `
            -AssignmentCollection { $Fixture.Assignments }.GetNewClosure() `
            -ManagementScopeCollection { $Fixture.ManagementScopes }.GetNewClosure() `
            -AuthorizationProbeCollection { $Fixture.AuthorizationProbes }.GetNewClosure() `
            -PropagationEvidence $Fixture.Propagation

        Test-ExchangeApplicationAuthorizationControl -Evidence $evidence `
            -ApprovedApplications $Fixture.Approved -TenantId $script:TenantId `
            -AsOfUtc $script:AsOfUtc -MaximumEvidenceAge ([timespan]::FromHours(24))
    }
}

AfterAll {
    Remove-Module ExchangeOnlineBaseline.Common -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-007-A03-T01 effective Exchange application authorization assessment' {
    It 'fails closed for <Case>' -ForEach @(
        @{
            Case = 'missing application-owner evidence'
            Reason = 'ApplicationEvidenceMissing'
            Change = { param($fixture) $fixture.Application = $null }
        }
        @{
            Case = 'stale application-owner evidence'
            Reason = 'ApplicationEvidenceStale'
            Change = { param($fixture) $fixture.Application.SuppliedAtUtc = '2026-09-20T08:00:00Z' }
        }
        @{
            Case = 'missing independent additive Entra and consent evidence'
            Reason = 'AdditiveEntraEvidenceMissing'
            Change = { param($fixture) $fixture.AdditiveEntraEvidence = $null }
        }
        @{
            Case = 'stale independent additive Entra and consent evidence'
            Reason = 'AdditiveEntraEvidenceStale'
            Change = { param($fixture) $fixture.AdditiveEntraEvidence.SuppliedAtUtc = '2026-09-20T09:00:00Z' }
        }
        @{
            Case = 'incomplete application-role inventory'
            Reason = 'ApplicationRoleInventoryIncomplete'
            Change = { param($fixture) $fixture.Roles.Complete = $false; $fixture.Roles.NextLink = 'fixture:roles:page-2' }
        }
        @{
            Case = 'incomplete service-principal inventory'
            Reason = 'ServicePrincipalInventoryIncomplete'
            Change = { param($fixture) $fixture.ServicePrincipals.Complete = $false; $fixture.ServicePrincipals.NextLink = 'fixture:service-principals:page-2' }
        }
        @{
            Case = 'incomplete application-assignment inventory'
            Reason = 'ApplicationAssignmentInventoryIncomplete'
            Change = { param($fixture) $fixture.Assignments.Complete = $false; $fixture.Assignments.NextLink = 'fixture:assignments:page-2' }
        }
        @{
            Case = 'incomplete management-resource-scope inventory'
            Reason = 'ManagementResourceScopeInventoryIncomplete'
            Change = { param($fixture) $fixture.ManagementScopes.Complete = $false; $fixture.ManagementScopes.NextLink = 'fixture:scopes:page-2' }
        }
        @{
            Case = 'application role beyond the approved least-privilege set'
            Reason = 'ApplicationAccessExcessive'
            Change = { param($fixture) $fixture.Roles.Items += [pscustomobject]@{ Identity = 'Application Mail.ReadWrite'; Name = 'Application Mail.ReadWrite'; RoleType = 'Application'; AllowsMailboxAccess = $true } }
        }
        @{
            Case = 'organization-wide assignment without a declared resource scope'
            Reason = 'ApplicationAccessUnscoped'
            Change = { param($fixture) $fixture.Assignments.Items[0].RecipientReadScope = 'Organization'; $fixture.Assignments.Items[0].CustomResourceScope = $null }
        }
        @{
            Case = 'authorization of a mailbox declared denied'
            Reason = 'UnintendedMailboxAuthorization'
            Change = { param($fixture) $fixture.AuthorizationProbes.Items[1].Authorized = $true }
        }
        @{
            Case = 'missing allowed-mailbox authorization probe'
            Reason = 'AllowedMailboxProbeMissing'
            Change = { param($fixture) $fixture.AuthorizationProbes.Items = @($fixture.AuthorizationProbes.Items | Where-Object Expected -ne 'Allowed') }
        }
        @{
            Case = 'missing denied-mailbox authorization probe'
            Reason = 'DeniedMailboxProbeMissing'
            Change = { param($fixture) $fixture.AuthorizationProbes.Items = @($fixture.AuthorizationProbes.Items | Where-Object Expected -ne 'Denied') }
        }
        @{
            Case = 'authorization probes bound to superseded inputs'
            Reason = 'AuthorizationProbeInputMismatch'
            Change = { param($fixture) $fixture.AuthorizationProbes.Items[0].InputHash = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' }
        }
        @{
            Case = 'unstated assignment and scope propagation limits'
            Reason = 'AuthorizationPropagationLimitMissing'
            Change = { param($fixture) $fixture.Propagation = $null }
        }
    ) {
        # Arrange
        $fixture = New-ApplicationAuthorizationFixture
        & $_.Change $fixture

        # Act
        $result = Invoke-ApplicationAuthorizationFixture -Fixture $fixture

        # Assert
        $result.Status | Should -BeExactly 'Fail'
        $result.Reason | Should -BeLike "$($_.Reason):*"
        $result.ExternalReadiness | Should -BeExactly 'Unverified'
        $result.ReleaseReady | Should -BeFalse
    }

    It 'accepts one approved scoped application bound to current inputs while tenant-wide Entra access remains Unverified' {
        # Arrange
        $fixture = New-ApplicationAuthorizationFixture

        # Act
        $result = Invoke-ApplicationAuthorizationFixture -Fixture $fixture

        # Assert
        $result.Status | Should -BeExactly 'Pass'
        $result.Reason | Should -BeLike 'ApplicationAuthorizationScoped:*'
        $result.ExternalReadiness | Should -BeExactly 'Unverified'
        $result.ReleaseReady | Should -BeFalse
        $result.InputHash | Should -BeExactly $script:CurrentInputHash
        @($result.Normalized.Roles).Count | Should -Be 1
        @($result.Normalized.ServicePrincipals).Count | Should -Be 1
        @($result.Normalized.Assignments).Count | Should -Be 1
        @($result.Normalized.ManagementScopes).Count | Should -Be 1
        @($result.Normalized.AuthorizationProbes | Where-Object Expected -eq 'Allowed').Authorized | Should -Be @($true)
        @($result.Normalized.AuthorizationProbes | Where-Object Expected -eq 'Denied').Authorized | Should -Be @($false)
        $result.Propagation.MaximumDelay | Should -BeExactly 'PT2H'
        $result.Limitations | Should -Contain 'Exchange probes cannot prove absence of tenant-wide Entra grants.'
    }
}