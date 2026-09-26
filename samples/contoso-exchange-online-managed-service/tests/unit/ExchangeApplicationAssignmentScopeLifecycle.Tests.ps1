#requires -Version 7.0

BeforeAll {
    $script:adapterRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:changeCommand = Join-Path $script:adapterRoot 'scripts/Invoke-ExchangeOnlineChange.ps1'
    Import-Module (Join-Path $script:adapterRoot 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking
    . (Join-Path $PSScriptRoot '../helpers/ApprovedAdapterDoubles.ps1')

    $script:tenantId = '00000000-0000-0000-0000-000000000001'
    $script:applicationId = '11111111-2222-3333-4444-555555555555'
    $script:servicePrincipalObjectId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    $script:inputHash = '0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF'
    $script:approvedAssignment = 'Application Mail.Read-Contoso Scoped Mail Reader'
    $script:approvedScope = 'Scope-Approved-Mailboxes'
    $script:adapterKey = [Security.Cryptography.RSA]::Create(2048)
    $certificateRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Offline Adapter',
        $script:adapterKey,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $script:adapterCertificate = $certificateRequest.CreateSelfSigned(
        [datetimeoffset]::UtcNow.AddMinutes(-1),
        [datetimeoffset]::UtcNow.AddDays(1)
    )

    function New-ApplicationScopeAssessment {
        param(
            [string]$Status = 'Pass',
            [string]$InputHash = $script:inputHash,
            [string]$AssessedAtUtc = [datetimeoffset]::UtcNow.AddMinutes(-10).ToString('o')
        )

        @{
            ControlId = 'EXR-007-A03-T01'
            Status = $Status
            Reason = 'ApplicationAuthorizationScoped: bounded offline assessment.'
            AssessedAtUtc = $AssessedAtUtc
            InputHash = $InputHash
            ExternalReadiness = 'Unverified'
            ReleaseReady = $false
            Normalized = @{
                Assignments = @(@{
                    Identity = $script:approvedAssignment
                    Role = 'Application Mail.Read'
                    RoleAssignee = $script:servicePrincipalObjectId
                    RoleAssigneeType = 'ServicePrincipal'
                    Enabled = $true
                    RecipientReadScope = 'CustomRecipientScope'
                    RecipientWriteScope = 'None'
                    CustomResourceScope = $script:approvedScope
                })
                ManagementScopes = @(@{
                    Identity = $script:approvedScope
                    RecipientRoot = 'contoso.example/Users'
                    RecipientRestrictionFilter = "CustomAttribute1 -eq 'ApprovedApp'"
                    ServerRestrictionFilter = $null
                    Exclusive = $false
                })
            }
            Limitations = @('Exchange probes cannot prove absence of tenant-wide Entra grants.')
        }
    }

    function New-AdditiveApplicationEvidence {
        param([string]$InputHash = $script:inputHash)

        @{
            ApplicationId = $script:applicationId
            ServicePrincipalObjectId = $script:servicePrincipalObjectId
            TenantId = $script:tenantId
            ApplicationRoles = @('Exchange.ManageAsApp')
            ConsentedPermissions = @('Exchange.ManageAsApp')
            ConsentType = 'AdminConsent'
            Complete = $true
            SuppliedAtUtc = [datetimeoffset]::UtcNow.AddMinutes(-15).ToString('o')
            SourceReference = 'fixture:independent-entra-review:change-432'
            InputHash = $InputHash
        }
    }

    function New-ApplicationAssignmentScopeOptions {
        @{
            tenantId = $script:tenantId
            applicationId = $script:applicationId
            servicePrincipalObjectId = $script:servicePrincipalObjectId
            inputHash = $script:inputHash
            assessment = New-ApplicationScopeAssessment
            additiveEntraEvidence = New-AdditiveApplicationEvidence
            assignments = @(@{
                identity = $script:approvedAssignment
                role = 'Application Mail.Read'
                roleAssignee = $script:servicePrincipalObjectId
                roleAssigneeType = 'ServicePrincipal'
                enabled = $true
                recipientReadScope = 'CustomRecipientScope'
                recipientWriteScope = 'None'
                customResourceScope = $script:approvedScope
            })
            managementScopes = @(@{
                identity = $script:approvedScope
                recipientRoot = 'contoso.example/Users'
                recipientRestrictionFilter = "CustomAttribute1 -eq 'ApprovedApp'"
                serverRestrictionFilter = $null
                exclusive = $false
            })
            allowedMailboxes = @('approved@contoso.example')
            deniedMailboxes = @('denied@contoso.example')
            propagation = @{
                statement = 'Exchange assignment and scope changes may require propagation before authorization probes are conclusive.'
                maximumDelay = 'PT2H'
            }
        }
    }

    function Set-ApplicationAssignmentScopeOptions {
        param($Arguments, [Parameter(Mandatory)][hashtable]$Options)

        $parameters = Get-Content $Arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.MICROSOFT_ENTRA_TENANT_GUID = $script:tenantId
        $parameters.entitlement.tenantId = $script:tenantId
        $parameters.domainInventory.tenantId = $script:tenantId
        $parameters.workflowOptions.applicationAssignmentScope = $Options
        $parameters | ConvertTo-Json -Depth 40 | Set-Content $Arguments.ParameterPath
    }

    function New-ApplicationAssignmentScopeFixture {
        param([string]$ChangeId = 'APP-SCOPE-T02')

        $arguments = New-StatefulAdapterFixture -Scope ApplicationAssignmentScope
        $arguments.ChangeId = $ChangeId
        $arguments.PreviewPath = Join-Path $arguments.ArtifactRoot "preview-$ChangeId.json"
        $arguments.ApprovalPath = Join-Path $arguments.ArtifactRoot "approval-$ChangeId.json"
        Set-ApplicationAssignmentScopeOptions -Arguments $arguments -Options (New-ApplicationAssignmentScopeOptions)
        $arguments
    }

    function Initialize-ApplicationAssignmentScopeDoubles {
        Initialize-AdapterDoubles
        function global:Get-ConnectionInformation { [pscustomobject]@{ TenantID = '00000000-0000-0000-0000-000000000001'; State = 'Connected' } }
        $global:adapterState.ServicePrincipal = @(@{
            Identity = $script:servicePrincipalObjectId
            ObjectId = $script:servicePrincipalObjectId
            AppId = $script:applicationId
            DisplayName = 'Contoso Scoped Mail Reader'
        })
        $global:adapterState.ManagementScope = @(@{
            Identity = $script:approvedScope
            RecipientRoot = 'contoso.example/Users'
            RecipientRestrictionFilter = "CustomAttribute1 -eq 'LegacyApp'"
            ServerRestrictionFilter = $null
            Exclusive = $false
        })
        $global:adapterState.ManagementRoleAssignment = @(@{
            Identity = $script:approvedAssignment
            Name = $script:approvedAssignment
            Role = 'Application Mail.Read'
            RoleAssignee = $script:servicePrincipalObjectId
            RoleAssigneeType = 'ServicePrincipal'
            Enabled = $true
            RecipientReadScope = 'CustomRecipientScope'
            RecipientWriteScope = 'None'
            CustomResourceScope = $script:approvedScope
        })
        $global:applicationScopeReads = [Collections.Generic.List[object]]::new()
        $global:applicationScopeProbes = [Collections.Generic.List[object]]::new()
        $global:applicationScopeCollectionPartial = ''
        $global:applicationScopeReadbackStale = $false
        $global:applicationScopeReadbackMismatch = $false
        $global:applicationScopeProbeOmission = ''
        $global:applicationScopeProbeOverride = @{}

        function global:Get-ServicePrincipal {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            foreach ($row in @($global:adapterState.ServicePrincipal | Where-Object {
                        [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -eq $Identity
                    })) {
                [pscustomobject]$row.Clone()
            }
        }
        function global:Get-ManagementScope {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            $global:applicationScopeReads.Add(@{ Command = 'Get-ManagementScope'; Parameters = @{} + $PSBoundParameters })
            $rows = @($global:adapterState.ManagementScope | Where-Object {
                    [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -eq $Identity
                })
            if ($global:applicationScopeCollectionPartial -eq 'ManagementScope' -and $rows.Count) {
                [pscustomobject]$rows[0].Clone()
                throw 'ChangeReadIncomplete: Get-ManagementScope returned a partial paged result.'
            }
            foreach ($row in $rows) {
                $copy = $row.Clone()
                if ($global:applicationScopeReadbackStale -and $global:adapterCalls.Count) { $copy.ObservedAtUtc = [datetimeoffset]::UtcNow.AddDays(-2).ToString('o') }
                if ($global:applicationScopeReadbackMismatch -and $global:adapterCalls.Count) { $copy.RecipientRestrictionFilter = "CustomAttribute1 -eq 'Mismatch'" }
                [pscustomobject]$copy
            }
        }
        function global:New-ManagementScope {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Name,
                [string]$RecipientRoot,
                [string]$RecipientRestrictionFilter,
                [string]$ServerRestrictionFilter,
                [switch]$Exclusive
            )

            $global:adapterCalls.Add(@{ Command = 'New-ManagementScope'; Parameters = @{} + $PSBoundParameters })
            if ($global:adapterWriteFault -eq 'New-ManagementScope') { throw 'Offline write refused: New-ManagementScope' }
            $global:adapterState.ManagementScope += @{
                Identity = $Name
                RecipientRoot = $RecipientRoot
                RecipientRestrictionFilter = $RecipientRestrictionFilter
                ServerRestrictionFilter = $ServerRestrictionFilter
                Exclusive = [bool]$Exclusive
            }
        }
        function global:Set-ManagementScope {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [string]$RecipientRoot,
                [string]$RecipientRestrictionFilter,
                [string]$ServerRestrictionFilter,
                [bool]$Exclusive
            )

            $global:adapterCalls.Add(@{ Command = 'Set-ManagementScope'; Parameters = @{} + $PSBoundParameters })
            if ($global:adapterWriteFault -eq 'Set-ManagementScope') { throw 'Offline write refused: Set-ManagementScope' }
            $target = @($global:adapterState.ManagementScope | Where-Object Identity -EQ $Identity)
            if ($target.Count -ne 1) { throw "Offline target not unique: Set-ManagementScope ($($target.Count))." }
            foreach ($field in @('RecipientRoot','RecipientRestrictionFilter','ServerRestrictionFilter','Exclusive')) {
                if ($PSBoundParameters.ContainsKey($field)) { $target[0][$field] = $PSBoundParameters[$field] }
            }
        }
        function global:Remove-ManagementScope {
            [CmdletBinding(SupportsShouldProcess)]
            param([Parameter(Mandatory)][string]$Identity)

            $global:adapterCalls.Add(@{ Command = 'Remove-ManagementScope'; Parameters = @{} + $PSBoundParameters })
            if ($global:adapterWriteFault -eq 'Remove-ManagementScope') { throw 'Offline write refused: Remove-ManagementScope' }
            $global:adapterState.ManagementScope = @($global:adapterState.ManagementScope | Where-Object Identity -NE $Identity)
        }
        function global:Get-ManagementRoleAssignment {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            $global:applicationScopeReads.Add(@{ Command = 'Get-ManagementRoleAssignment'; Parameters = @{} + $PSBoundParameters })
            $rows = @($global:adapterState.ManagementRoleAssignment | Where-Object {
                    [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -eq $Identity
                })
            if ($global:applicationScopeCollectionPartial -eq 'ManagementRoleAssignment' -and $rows.Count) {
                [pscustomobject]$rows[0].Clone()
                throw 'ChangeReadIncomplete: Get-ManagementRoleAssignment returned a partial paged result.'
            }
            foreach ($row in $rows) { [pscustomobject]$row.Clone() }
        }
        function global:New-ManagementRoleAssignment {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Name,
                [Parameter(Mandatory)][string]$Role,
                [Parameter(Mandatory)][string]$App,
                [Parameter(Mandatory)][string]$CustomResourceScope
            )

            $global:adapterCalls.Add(@{ Command = 'New-ManagementRoleAssignment'; Parameters = @{} + $PSBoundParameters })
            if ($global:adapterWriteFault -eq 'New-ManagementRoleAssignment') { throw 'Offline write refused: New-ManagementRoleAssignment' }
            $global:adapterState.ManagementRoleAssignment += @{
                Identity = $Name
                Name = $Name
                Role = $Role
                RoleAssignee = $App
                RoleAssigneeType = 'ServicePrincipal'
                Enabled = $true
                RecipientReadScope = 'CustomRecipientScope'
                RecipientWriteScope = 'None'
                CustomResourceScope = $CustomResourceScope
            }
        }
        function global:Remove-ManagementRoleAssignment {
            [CmdletBinding(SupportsShouldProcess)]
            param([Parameter(Mandatory)][string]$Identity)

            $global:adapterCalls.Add(@{ Command = 'Remove-ManagementRoleAssignment'; Parameters = @{} + $PSBoundParameters })
            if ($global:adapterWriteFault -eq 'Remove-ManagementRoleAssignment') { throw 'Offline write refused: Remove-ManagementRoleAssignment' }
            $global:adapterState.ManagementRoleAssignment = @($global:adapterState.ManagementRoleAssignment | Where-Object Identity -NE $Identity)
        }
        function global:Test-ServicePrincipalAuthorization {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [Parameter(Mandatory)][string]$Resource
            )

            $global:applicationScopeProbes.Add(@{} + $PSBoundParameters)
            if ($global:applicationScopeProbeOmission -eq $Resource) { return }
            $authorized = $Resource -eq 'approved@contoso.example'
            if ($global:applicationScopeProbeOverride.ContainsKey($Resource)) { $authorized = [bool]$global:applicationScopeProbeOverride[$Resource] }
            [pscustomobject]@{
                ApplicationId = $Identity
                Resource = $Resource
                Authorized = $authorized
                TestedAtUtc = [datetimeoffset]::UtcNow.ToString('o')
            }
        }
        foreach ($command in @(
                'Get-ServicePrincipal',
                'Get-ManagementScope',
                'New-ManagementScope',
                'Set-ManagementScope',
                'Remove-ManagementScope',
                'Get-ManagementRoleAssignment',
                'New-ManagementRoleAssignment',
                'Remove-ManagementRoleAssignment',
                'Test-ServicePrincipalAuthorization'
            )) {
            if ($command -notin $global:adapterCommands) { $global:adapterCommands.Add($command) }
        }
    }

    function Approve-ApplicationAssignmentScopeFixture {
        param($Arguments)

        & $script:changeCommand -Stage Preview @Arguments -Scope ApplicationAssignmentScope -Confirm:$false | Out-Null
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:adapterCertificate -Confirm:$false | Out-Null
    }

    function Invoke-ApplicationAssignmentScopePreview {
        param($Arguments)

        & $script:changeCommand -Stage Preview @Arguments -Scope ApplicationAssignmentScope -Confirm:$false
    }

    function Get-ApplicationAssignmentScopeSnapshot {
        ConvertTo-CanonicalJson ([ordered]@{
            Assignments = @($global:adapterState.ManagementRoleAssignment)
            ManagementScopes = @($global:adapterState.ManagementScope)
        })
    }

    function Invoke-ApplicationAssignmentScopeLifecycle {
        param($Arguments)

        $before = Get-ApplicationAssignmentScopeSnapshot
        Approve-ApplicationAssignmentScopeFixture -Arguments $Arguments
        $previewHash = (Get-FileHash -LiteralPath $Arguments.PreviewPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $approval = Get-Content $Arguments.ApprovalPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        & $script:changeCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:changeCommand -Stage Apply @Arguments -Apply -Confirm:$false
        $readback = [pscustomobject]@{
            Assignments = @(Get-ManagementRoleAssignment -ResultSize Unlimited)
            ManagementScopes = @(Get-ManagementScope -ResultSize Unlimited)
        }
        $reprobes = @(
            Test-ServicePrincipalAuthorization -Identity $script:applicationId -Resource 'approved@contoso.example'
            Test-ServicePrincipalAuthorization -Identity $script:applicationId -Resource 'denied@contoso.example'
        )
        $writesAfterApply = $global:adapterCalls.Count

        $repeatArguments = New-ApplicationAssignmentScopeFixture -ChangeId 'APP-SCOPE-T02-REPEAT'
        Approve-ApplicationAssignmentScopeFixture -Arguments $repeatArguments
        & $script:changeCommand -Stage Validate @repeatArguments | Out-Null
        $repeat = & $script:changeCommand -Stage Apply @repeatArguments -Apply -Confirm:$false
        $repeatWrites = $global:adapterCalls.Count - $writesAfterApply

        $global:adapterState.ManagementScope[0].RecipientRestrictionFilter = "CustomAttribute1 -eq 'Drift'"
        $writesBeforeDrift = $global:adapterCalls.Count
        $drift = $null
        try { & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false | Out-Null } catch { $drift = $_ }
        $driftWrites = $global:adapterCalls.Count - $writesBeforeDrift
        $global:adapterState.ManagementScope[0].RecipientRestrictionFilter = "CustomAttribute1 -eq 'ApprovedApp'"

        $rollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false

        [pscustomobject]@{
            Before = $before
            PreviewHash = $previewHash
            ApprovedPreviewHash = [string]$approval.PreviewHash
            Apply = $apply
            Readback = $readback
            Reprobes = $reprobes
            Repeat = $repeat
            RepeatWrites = $repeatWrites
            Drift = $drift
            DriftWrites = $driftWrites
            Rollback = $rollback
            Restored = Get-ApplicationAssignmentScopeSnapshot
        }
    }
}

Describe 'EXR-007-A03-T02 approved application assignment and scope lifecycle' {
    BeforeEach {
        Initialize-ApplicationAssignmentScopeDoubles
        Mock Test-BaselineDetachedCmsSignature -ModuleName ExchangeOnlineBaseline.Common {
            param($CanonicalBytes, $Signature)
            $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($CanonicalBytes), $true)
            $cms.Decode([Convert]::FromBase64String($Signature.Value))
            $cms.CheckSignature($true)
            @{
                Verified = $true
                SignerSubject = $cms.SignerInfos[0].Certificate.Subject
                SigningTimeUtc = [datetimeoffset]::UtcNow
                CertificateNotBeforeUtc = [datetimeoffset]::UtcNow.AddDays(-1)
                CertificateNotAfterUtc = [datetimeoffset]::UtcNow.AddDays(1)
                ChainTrusted = $true
                RevocationStatus = 'Good'
            }
        }
    }

    Context 'Negative: authorization and evidence must bind the exact signed lifecycle' {
        It 'refuses apply when approval is missing' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            & $script:changeCommand -Stage Preview @arguments -Scope ApplicationAssignmentScope -Confirm:$false | Out-Null

            # Act
            $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeApprovalMissing*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses apply when approval is stale' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            Approve-ApplicationAssignmentScopeFixture -Arguments $arguments
            $approval = Get-Content $arguments.ApprovalPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $approval.ApprovalTimeUtc = [datetimeoffset]::UtcNow.AddDays(-8).ToString('o')
            $approval | ConvertTo-Json -Depth 30 | Set-Content $arguments.ApprovalPath

            # Act
            $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeApproval*Stale*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses apply when approval is bound to a different preview' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            Approve-ApplicationAssignmentScopeFixture -Arguments $arguments
            $approval = Get-Content $arguments.ApprovalPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $approval.PreviewHash = 'F' * 64
            $approval | ConvertTo-Json -Depth 30 | Set-Content $arguments.ApprovalPath

            # Act
            $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeApproval*PreviewHash*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a missing T01 authorization assessment before writes' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            $options = New-ApplicationAssignmentScopeOptions
            $options.assessment = $null
            Set-ApplicationAssignmentScopeOptions -Arguments $arguments -Options $options

            # Act
            $invoke = { Invoke-ApplicationAssignmentScopePreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ApplicationAuthorizationAssessmentMissing*EXR-007-A03-T01*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a stale T01 authorization assessment before writes' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            $options = New-ApplicationAssignmentScopeOptions
            $options.assessment.AssessedAtUtc = [datetimeoffset]::UtcNow.AddDays(-2).ToString('o')
            Set-ApplicationAssignmentScopeOptions -Arguments $arguments -Options $options

            # Act
            $invoke = { Invoke-ApplicationAssignmentScopePreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ApplicationAuthorizationAssessmentStale*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a T01 assessment bound to different inputs before writes' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            $options = New-ApplicationAssignmentScopeOptions
            $options.assessment.InputHash = 'F' * 64
            Set-ApplicationAssignmentScopeOptions -Arguments $arguments -Options $options

            # Act
            $invoke = { Invoke-ApplicationAssignmentScopePreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ApplicationAuthorizationAssessmentMismatch*InputHash*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses additive evidence not bound to the assessed application inputs before writes' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            $options = New-ApplicationAssignmentScopeOptions
            $options.additiveEntraEvidence.InputHash = 'E' * 64
            Set-ApplicationAssignmentScopeOptions -Arguments $arguments -Options $options

            # Act
            $invoke = { Invoke-ApplicationAssignmentScopePreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*AdditiveEntraEvidenceMismatch*InputHash*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an unsupported application assignment before writes' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            $options = New-ApplicationAssignmentScopeOptions
            $options.assignments[0].role = 'Application Mail.ReadWrite'
            Set-ApplicationAssignmentScopeOptions -Arguments $arguments -Options $options

            # Act
            $invoke = { Invoke-ApplicationAssignmentScopePreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ApplicationAssignmentUnsupported*Application Mail.ReadWrite*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a rights-expanding organization scope before writes' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            $options = New-ApplicationAssignmentScopeOptions
            $options.assignments[0].recipientReadScope = 'Organization'
            $options.assignments[0].customResourceScope = $null
            Set-ApplicationAssignmentScopeOptions -Arguments $arguments -Options $options

            # Act
            $invoke = { Invoke-ApplicationAssignmentScopePreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ApplicationAssignmentScopeRightsExpansion*Organization*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an incomplete independent raw assignment readback' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            Approve-ApplicationAssignmentScopeFixture -Arguments $arguments
            $global:applicationScopeCollectionPartial = 'ManagementRoleAssignment'

            # Act
            $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*ManagementRoleAssignment*'
            @($global:adapterCalls).Count | Should -BeGreaterThan 0
        }

        It 'refuses stale independent raw scope readback' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            Approve-ApplicationAssignmentScopeFixture -Arguments $arguments
            $global:applicationScopeReadbackStale = $true

            # Act
            $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ApplicationAssignmentScopeReadbackStale*'
            @($global:adapterCalls).Count | Should -BeGreaterThan 0
        }

        It 'refuses unintended authorization of a denied mailbox' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            Approve-ApplicationAssignmentScopeFixture -Arguments $arguments
            $global:applicationScopeProbeOverride['denied@contoso.example'] = $true

            # Act
            $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*UnintendedMailboxAuthorization*denied@contoso.example*'
            @($global:applicationScopeProbes | Where-Object Resource -EQ 'denied@contoso.example').Count | Should -Be 1
        }

        It 'refuses a missing allowed-mailbox re-probe' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            Approve-ApplicationAssignmentScopeFixture -Arguments $arguments
            $global:applicationScopeProbeOmission = 'approved@contoso.example'

            # Act
            $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*AllowedMailboxReprobeMissing*approved@contoso.example*'
            @($global:applicationScopeProbes | Where-Object Resource -EQ 'approved@contoso.example').Count | Should -Be 1
        }

        It 'refuses a missing denied-mailbox re-probe' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            Approve-ApplicationAssignmentScopeFixture -Arguments $arguments
            $global:applicationScopeProbeOmission = 'denied@contoso.example'

            # Act
            $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*DeniedMailboxReprobeMissing*denied@contoso.example*'
            @($global:applicationScopeProbes | Where-Object Resource -EQ 'denied@contoso.example').Count | Should -Be 1
        }

        It 'refuses omission of assignment and scope propagation limits before writes' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            $options = New-ApplicationAssignmentScopeOptions
            $options.propagation = $null
            Set-ApplicationAssignmentScopeOptions -Arguments $arguments -Options $options

            # Act
            $invoke = { Invoke-ApplicationAssignmentScopePreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*AuthorizationPropagationLimitMissing*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses apply when independent raw readback differs from the approved state' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            Approve-ApplicationAssignmentScopeFixture -Arguments $arguments
            $global:applicationScopeReadbackMismatch = $true

            # Act
            $invoke = { & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ApplicationAssignmentScopeApplyReadbackMismatch*'
            @($global:adapterCalls).Count | Should -BeGreaterThan 0
        }

        It 'refuses repeat-run writes after the approved state is reached' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            Approve-ApplicationAssignmentScopeFixture -Arguments $arguments
            & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false | Out-Null
            $repeatArguments = New-ApplicationAssignmentScopeFixture -ChangeId 'APP-SCOPE-T02-REPEAT-NEGATIVE'
            Approve-ApplicationAssignmentScopeFixture -Arguments $repeatArguments
            $writesBeforeRepeat = $global:adapterCalls.Count

            # Act
            $repeat = & $script:changeCommand -Stage Apply @repeatArguments -Apply -Confirm:$false

            # Assert
            $repeat.Status | Should -BeExactly 'NoOp'
            ($global:adapterCalls.Count - $writesBeforeRepeat) | Should -Be 0
        }

        It 'refuses rollback after approved state drift without writes' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            Approve-ApplicationAssignmentScopeFixture -Arguments $arguments
            & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false | Out-Null
            $global:adapterState.ManagementScope[0].RecipientRestrictionFilter = "CustomAttribute1 -eq 'Drift'"
            $writesBeforeRollback = $global:adapterCalls.Count

            # Act
            $invoke = { & $script:changeCommand -Stage Rollback @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeStateDrift*'
            ($global:adapterCalls.Count - $writesBeforeRollback) | Should -Be 0
        }

        It 'reports rollback failure and does not claim the prior typed scope was restored' {
            # Arrange
            $arguments = New-ApplicationAssignmentScopeFixture
            Approve-ApplicationAssignmentScopeFixture -Arguments $arguments
            & $script:changeCommand -Stage Apply @arguments -Apply -Confirm:$false | Out-Null
            $global:adapterWriteFault = 'Set-ManagementScope'

            # Act
            $invoke = { & $script:changeCommand -Stage Rollback @arguments -Apply -Confirm:$false }

            # Assert
            $invoke | Should -Throw '*ChangeRollbackFailed*Set-ManagementScope*'
            $global:adapterState.ManagementScope[0].RecipientRestrictionFilter | Should -BeExactly "CustomAttribute1 -eq 'ApprovedApp'"
        }
    }

    It 'runs one signed approved lifecycle with independent readback, re-probes, propagation, no-op, drift refusal, and typed rollback' {
        # Arrange
        $arguments = New-ApplicationAssignmentScopeFixture

        # Act
        $result = Invoke-ApplicationAssignmentScopeLifecycle -Arguments $arguments

        # Assert
        $result.PreviewHash | Should -BeExactly $result.ApprovedPreviewHash
        $result.Apply.Status | Should -BeExactly 'Applied'
        $result.Apply.ExternalReadiness | Should -BeExactly 'Unverified'
        $result.Apply.ReleaseReady | Should -BeFalse
        $result.Apply.Propagation.MaximumDelay | Should -BeExactly 'PT2H'
        $result.Apply.Limitations | Should -Contain 'Exchange probes cannot prove absence of tenant-wide Entra grants.'
        @($result.Readback.Assignments).Count | Should -Be 1
        @($result.Readback.ManagementScopes).Count | Should -Be 1
        $result.Readback.Assignments[0].Identity | Should -BeExactly $script:approvedAssignment
        $result.Readback.Assignments[0].CustomResourceScope | Should -BeExactly $script:approvedScope
        $result.Readback.ManagementScopes[0].RecipientRestrictionFilter | Should -BeExactly "CustomAttribute1 -eq 'ApprovedApp'"
        @($result.Reprobes | Where-Object { $_.Resource -eq 'approved@contoso.example' -and $_.Authorized }).Count | Should -Be 1
        @($result.Reprobes | Where-Object { $_.Resource -eq 'denied@contoso.example' -and -not $_.Authorized }).Count | Should -Be 1
        $result.Repeat.Status | Should -BeExactly 'NoOp'
        $result.RepeatWrites | Should -Be 0
        $result.Drift.Exception.Message | Should -BeLike '*ChangeStateDrift*'
        $result.DriftWrites | Should -Be 0
        $result.Rollback.Status | Should -BeExactly 'RolledBack'
        $result.Restored | Should -BeExactly $result.Before
        $restoredScope = @($global:adapterState.ManagementScope)[0]
        $restoredScope.RecipientRoot | Should -BeOfType [string]
        $restoredScope.RecipientRestrictionFilter | Should -BeOfType [string]
        $restoredScope.ServerRestrictionFilter | Should -BeNullOrEmpty
        $restoredScope.Exclusive | Should -BeOfType [bool]
        @($global:adapterCalls | Where-Object Command -Match 'Application|ServicePrincipal|Consent|Grant').Count | Should -Be 0
    }
}