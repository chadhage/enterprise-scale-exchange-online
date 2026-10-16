#requires -Version 7.0

BeforeAll {
    $script:sampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:adapterRoot = $script:sampleRoot
    $script:changeCommand = Join-Path $script:sampleRoot 'scripts/Invoke-ExchangeOnlineChange.ps1'
    Import-Module (Join-Path $script:sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking
    . (Join-Path $PSScriptRoot '../helpers/ApprovedAdapterDoubles.ps1')

    $script:signingKey = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Offline Adapter',
        $script:signingKey,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $script:signingCertificate = $request.CreateSelfSigned(
        [datetimeoffset]::UtcNow.AddMinutes(-1),
        [datetimeoffset]::UtcNow.AddDays(1)
    )

    function New-SharingDisclosureApproval {
        @{
            Reference = 'SYNTHETIC-EXR007-A04-T01'
            Owner = 'privacy@contoso.example'
            ExpiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
            EnterpriseApplicability = @{
                Decision = 'Applicable'
                Rationale = 'Enterprise sharing is explicitly approved for the named partner.'
            }
            EducationGuidance = @{
                Treatment = 'ContextOnly'
                Rationale = 'Education guidance neither permits nor prohibits enterprise sharing.'
            }
            PartnerDomains = @('approved.partner.example')
            AllowWildcard = $false
            AllowAnonymous = $false
            MaximumDetail = 'CalendarSharingFreeBusySimple'
            DefaultPolicy = 'Approved Partner Sharing'
            ExplicitMailboxBindings = @{
                'executive@contoso.example' = 'Approved Partner Sharing'
            }
            Complete = $true
            IndependentlyApproved = $true
        }
    }

    function New-SharingPolicyBindingOptions {
        @{
            applicability = @{
                enterprise = @{
                    decision = 'Applicable'
                    rationale = 'Enterprise sharing is explicitly approved for the named partner.'
                }
                educationGuidance = @{
                    treatment = 'ContextOnly'
                    rationale = 'Education guidance neither permits nor prohibits enterprise sharing.'
                }
            }
            policies = @(@{
                identity = 'Approved Partner Sharing'
                domains = @('approved.partner.example: CalendarSharingFreeBusySimple')
                enabled = $true
                isDefault = $true
            })
            defaultMailboxPolicy = 'Approved Partner Sharing'
            explicitMailboxBindings = @(@{
                identity = 'executive@contoso.example'
                sharingPolicy = 'Approved Partner Sharing'
            })
            disclosureApproval = New-SharingDisclosureApproval
            partnerReadiness = 'Unverified'
        }
    }

    function Initialize-SharingPolicyBindingDoubles {
        Initialize-AdapterDoubles
        $global:sharingPolicyCollectionMode = 'Complete'
        $global:mailboxBindingCollectionMode = 'Complete'
        $global:sharingPolicyState = @(
            @{
                Identity = 'Approved Partner Sharing'
                Name = 'Approved Partner Sharing'
                Domains = @('approved.partner.example: CalendarSharingFreeBusyReviewer')
                Enabled = $true
                IsDefault = $false
            },
            @{
                Identity = 'Legacy Default Sharing'
                Name = 'Legacy Default Sharing'
                Domains = @('legacy.partner.example: CalendarSharingFreeBusySimple')
                Enabled = $true
                IsDefault = $true
            }
        )
        $global:mailboxBindingState = @(
            @{
                Identity = 'default@contoso.example'
                PrimarySmtpAddress = 'default@contoso.example'
                SharingPolicy = 'Legacy Default Sharing'
                UsesDefaultSharingPolicy = $true
            },
            @{
                Identity = 'executive@contoso.example'
                PrimarySmtpAddress = 'executive@contoso.example'
                SharingPolicy = 'Legacy Default Sharing'
                UsesDefaultSharingPolicy = $false
            }
        )
        $global:sharingPolicyReads = [Collections.Generic.List[object]]::new()
        $global:mailboxBindingReads = [Collections.Generic.List[object]]::new()

        function global:Get-SharingPolicy {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            $global:sharingPolicyReads.Add(@{ Command = 'Get-SharingPolicy'; Parameters = @{} + $PSBoundParameters })
            $rows = @($global:sharingPolicyState | Where-Object {
                    [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -ceq $Identity
                })
            if ($global:sharingPolicyCollectionMode -ceq 'PartialAmbiguousPageFailure') {
                [pscustomobject]$rows[0].Clone()
                [pscustomobject]$rows[0].Clone()
                throw 'SharingPolicyInventoryIncomplete: page 2 failed after an ambiguous duplicate policy.'
            }
            foreach ($row in $rows) { [pscustomobject]$row.Clone() }
        }

        function global:Set-SharingPolicy {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [string[]]$Domains,
                [bool]$Enabled,
                [bool]$Default
            )

            $global:adapterCalls.Add(@{ Command = 'Set-SharingPolicy'; Parameters = @{} + $PSBoundParameters })
            $row = @($global:sharingPolicyState | Where-Object Identity -CEQ $Identity)
            if ($row.Count -ne 1) { throw "Offline target not unique: Set-SharingPolicy ($($row.Count))." }
            if ($PSBoundParameters.ContainsKey('Domains')) { $row[0].Domains = @($Domains) }
            if ($PSBoundParameters.ContainsKey('Enabled')) { $row[0].Enabled = $Enabled }
            if ($PSBoundParameters.ContainsKey('Default')) {
                foreach ($policy in $global:sharingPolicyState) { $policy.IsDefault = $false }
                $row[0].IsDefault = $Default
                if ($Default) { foreach ($mailbox in $global:mailboxBindingState | Where-Object UsesDefaultSharingPolicy) { $mailbox.SharingPolicy = $row[0].Identity } }
            }
        }

        function global:Get-Mailbox {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            $global:mailboxBindingReads.Add(@{ Command = 'Get-Mailbox'; Parameters = @{} + $PSBoundParameters })
            $rows = @($global:mailboxBindingState | Where-Object {
                    [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -ceq $Identity
                })
            if ($global:mailboxBindingCollectionMode -ceq 'PartialAmbiguousPageFailure') {
                [pscustomobject]$rows[0].Clone()
                [pscustomobject]$rows[0].Clone()
                throw 'SharingPolicyBindingInventoryIncomplete: page 2 failed after an ambiguous duplicate mailbox.'
            }
            foreach ($row in $rows) { [pscustomobject]$row.Clone() }
        }

        function global:Set-Mailbox {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [Parameter(Mandatory)][string]$SharingPolicy
            )

            $global:adapterCalls.Add(@{ Command = 'Set-Mailbox'; Parameters = @{} + $PSBoundParameters })
            $row = @($global:mailboxBindingState | Where-Object Identity -CEQ $Identity)
            if ($row.Count -ne 1) { throw "Offline target not unique: Set-Mailbox ($($row.Count))." }
            $row[0].SharingPolicy = $SharingPolicy
        }

        foreach ($command in @('Get-SharingPolicy', 'Set-SharingPolicy', 'Get-Mailbox', 'Set-Mailbox')) {
            if ($command -notin $global:adapterCommands) { $global:adapterCommands.Add($command) }
        }
    }

    function Get-SharingPolicyBindingDecision {
        param(
            [hashtable]$Approval = (New-SharingDisclosureApproval),
            [hashtable]$Applicability = @{
                Enterprise = @{ Decision = 'Applicable'; Rationale = 'Enterprise decision recorded.' }
                EducationGuidance = @{ Treatment = 'ContextOnly'; Rationale = 'Context only.' }
            }
        )

        $evidence = Get-SharingPolicyBindingEvidence `
            -PolicyCollection { @(Get-SharingPolicy -ResultSize Unlimited) } `
            -MailboxCollection { @(Get-Mailbox -ResultSize Unlimited) }
        Test-SharingPolicyBindingControl -Evidence $evidence -Approval $Approval -Applicability $Applicability
    }

    function Set-SharingPolicyBindingOptions {
        param($Arguments, [hashtable]$Options = (New-SharingPolicyBindingOptions))

        $parameters = Get-Content $Arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions.sharingPolicyBinding = $Options
        $parameters | ConvertTo-Json -Depth 40 | Set-Content $Arguments.ParameterPath
    }

    function New-SharingPolicyBindingFixture {
        param([string]$ChangeId = 'EXR007-A04-T01', [Parameter(Mandatory)][string]$TestRoot)

        $TestDrive = $TestRoot
        $arguments = New-StatefulAdapterFixture -Scope SharingPolicyBinding
        $arguments.ChangeId = $ChangeId
        $arguments.PreviewPath = Join-Path $arguments.ArtifactRoot "preview-$ChangeId.json"
        $arguments.ApprovalPath = Join-Path $arguments.ArtifactRoot "approval-$ChangeId.json"
        Set-SharingPolicyBindingOptions -Arguments $arguments
        $arguments
    }

    function Approve-SharingPolicyBindingFixture {
        param($Arguments)

        & $script:changeCommand -Stage Preview @Arguments -Scope SharingPolicyBinding -Confirm:$false | Out-Null
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
    }

    function Get-SharingPolicyBindingSnapshot {
        ConvertTo-CanonicalJson ([ordered]@{
            Mailboxes = @($global:mailboxBindingState)
            Policies = @($global:sharingPolicyState)
        })
    }

    function Invoke-SharingPolicyBindingLifecycle {
        param($Arguments, [Parameter(Mandatory)][string]$TestRoot)

        $before = Get-SharingPolicyBindingSnapshot
        Approve-SharingPolicyBindingFixture -Arguments $Arguments
        & $script:changeCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:changeCommand -Stage Apply @Arguments -Apply -Confirm:$false
        $readback = Get-SharingPolicyBindingDecision
        $applied = Get-SharingPolicyBindingSnapshot
        $writesAfterApply = $global:adapterCalls.Count

        $repeatArguments = New-SharingPolicyBindingFixture -ChangeId 'EXR007-A04-T01-REPEAT' -TestRoot $TestRoot
        Approve-SharingPolicyBindingFixture -Arguments $repeatArguments
        & $script:changeCommand -Stage Validate @repeatArguments | Out-Null
        $repeat = & $script:changeCommand -Stage Apply @repeatArguments -Apply -Confirm:$false
        $repeatWrites = $global:adapterCalls.Count - $writesAfterApply

        $global:sharingPolicyState[0].Domains = @('drift.partner.example: CalendarSharingFreeBusySimple')
        $writesBeforeDrift = $global:adapterCalls.Count
        $drift = $null
        try { & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false | Out-Null } catch { $drift = $_ }
        $driftWrites = $global:adapterCalls.Count - $writesBeforeDrift
        $drifted = Get-SharingPolicyBindingSnapshot
        $global:sharingPolicyState[0].Domains = @('approved.partner.example: CalendarSharingFreeBusySimple')

        $callsBeforeRollback = $global:adapterCalls.Count
        $rollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false
        $rollbackCalls = @($global:adapterCalls | Select-Object -Skip $callsBeforeRollback)

        [pscustomobject]@{
            Before = $before
            ApplyStatus = $apply.Status
            Applied = $applied
            Readback = $readback
            RepeatStatus = $repeat.Status
            RepeatWrites = $repeatWrites
            DriftMessage = $drift.Exception.Message
            DriftWrites = $driftWrites
            Drifted = $drifted
            RollbackStatus = $rollback.Status
            RollbackCalls = $rollbackCalls
            Restored = Get-SharingPolicyBindingSnapshot
        }
    }
}

AfterAll {
    foreach ($name in @('Get-SharingPolicy', 'Set-SharingPolicy', 'Get-Mailbox', 'Set-Mailbox')) {
        Remove-Item "Function:global:$name" -ErrorAction SilentlyContinue
    }
    foreach ($name in @($global:adapterCommands) + @('Get-ConnectionInformation', 'Invoke-OfflineAdapterCommand')) {
        Remove-Item "Function:global:$name" -ErrorAction SilentlyContinue
    }
    $script:signingCertificate.Dispose()
    $script:signingKey.Dispose()
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-007-A04-T01 sharing policy and mailbox binding lifecycle' {
    BeforeEach {
        Initialize-SharingPolicyBindingDoubles
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

    Context 'Negative 01: enterprise applicability must be explicit and education guidance is contextual only' {
        It 'refuses ambiguous applicability with missing rationale and education guidance used as universal permission' {
            # Arrange
            $applicability = @{
                Enterprise = @{ Decision = 'Ambiguous'; Rationale = '' }
                EducationGuidance = @{ Treatment = 'UniversalPermission'; Rationale = 'Education guidance was treated as permission.' }
            }

            # Act
            $result = Get-SharingPolicyBindingDecision -Applicability $applicability

            # Assert
            ('{0}|{1}|golive={2}' -f $result.Status, $result.Reason, $result.GoLiveSuccess) |
                Should -BeExactly 'Fail|SharingPolicyEnterpriseApplicabilityInvalid|golive=False'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 02: wildcard sharing requires specific disclosure approval' {
        It 'refuses an enabled wildcard domain scope when wildcard disclosure is not approved' {
            # Arrange
            $global:sharingPolicyState[0].Domains = @('*: CalendarSharingFreeBusySimple')

            # Act
            $result = Get-SharingPolicyBindingDecision

            # Assert
            ('{0}|{1}|golive={2}' -f $result.Status, $result.Reason, $result.GoLiveSuccess) |
                Should -BeExactly 'Fail|SharingPolicyWildcardScopeUnapproved|golive=False'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 03: anonymous sharing requires specific disclosure approval' {
        It 'refuses an enabled anonymous scope when anonymous disclosure is not approved' {
            # Arrange
            $global:sharingPolicyState[0].Domains = @('Anonymous: CalendarSharingFreeBusySimple')

            # Act
            $result = Get-SharingPolicyBindingDecision

            # Assert
            ('{0}|{1}|golive={2}' -f $result.Status, $result.Reason, $result.GoLiveSuccess) |
                Should -BeExactly 'Fail|SharingPolicyAnonymousScopeUnapproved|golive=False'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 04: sharing detail cannot exceed independent disclosure approval' {
        It 'refuses reviewer detail when only simple free-busy disclosure is approved' {
            # Arrange
            $global:sharingPolicyState[0].Domains = @('approved.partner.example: CalendarSharingFreeBusyReviewer')

            # Act
            $result = Get-SharingPolicyBindingDecision

            # Assert
            ('{0}|{1}|golive={2}' -f $result.Status, $result.Reason, $result.GoLiveSuccess) |
                Should -BeExactly 'Fail|SharingPolicyDisclosureDetailExcessive|golive=False'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 05: the default mailbox policy binding must resolve' {
        It 'refuses a missing default mailbox binding to the approved policy' {
            # Arrange
            $global:mailboxBindingState[0].SharingPolicy = ''
            $global:sharingPolicyState[0].IsDefault = $false
            $global:sharingPolicyState[1].IsDefault = $false

            # Act
            $result = Get-SharingPolicyBindingDecision

            # Assert
            ('{0}|{1}|golive={2}' -f $result.Status, $result.Reason, $result.GoLiveSuccess) |
                Should -BeExactly 'Fail|SharingPolicyDefaultMailboxBindingMissing|golive=False'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 06: every explicit mailbox binding must exist and resolve to an approved policy' {
        It 'refuses an applicable explicit mailbox bound outside the approved policy set' {
            # Arrange
            $global:mailboxBindingState[1].SharingPolicy = 'Unresolved Partner Policy'

            # Act
            $result = Get-SharingPolicyBindingDecision

            # Assert
            ('{0}|{1}|golive={2}' -f $result.Status, $result.Reason, $result.GoLiveSuccess) |
                Should -BeExactly 'Fail|SharingPolicyExplicitMailboxBindingUnresolved|golive=False'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 07: policy and binding inventory must be complete and unambiguous' {
        It 'refuses partial policy and mailbox pages containing ambiguous duplicate identities' {
            # Arrange
            $global:sharingPolicyCollectionMode = 'PartialAmbiguousPageFailure'
            $global:mailboxBindingCollectionMode = 'PartialAmbiguousPageFailure'

            # Act
            $result = Get-SharingPolicyBindingDecision

            # Assert
            ('{0}|{1}|golive={2}' -f $result.Status, $result.Reason, $result.GoLiveSuccess) |
                Should -BeExactly 'Error|SharingPolicyBindingInventoryIncomplete|golive=False'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative 08: local sharing configuration is not independent disclosure approval' {
        It 'refuses partner detail and bindings when independent disclosure approval is absent' {
            # Arrange
            $approval = New-SharingDisclosureApproval
            $approval.IndependentlyApproved = $false
            $approval.Reference = ''

            # Act
            $result = Get-SharingPolicyBindingDecision -Approval $approval

            # Assert
            ('{0}|{1}|readiness={2}|golive={3}' -f $result.Status, $result.Reason, $result.PartnerReadiness, $result.GoLiveSuccess) |
                Should -BeExactly 'Fail|SharingPolicyDisclosureApprovalMissing|readiness=Unverified|golive=False'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Positive 01: signed partner-only policy and bindings remain bounded by external readiness' {
        It 'sets and reads back partner-only state, repeats without writes, refuses drift, and performs typed rollback' {
            # Arrange
            $arguments = New-SharingPolicyBindingFixture -TestRoot $TestDrive

            # Act
            $result = Invoke-SharingPolicyBindingLifecycle -Arguments $arguments -TestRoot $TestDrive

            # Assert
            $result.ApplyStatus | Should -BeExactly 'Succeeded'
            $result.Applied | Should -BeLike '*approved.partner.example: CalendarSharingFreeBusySimple*'
            $result.Applied | Should -Not -BeLike '*Anonymous:*'
            $result.Applied | Should -Not -BeLike '"*:*'
            $result.Readback.Status | Should -BeExactly 'Pass'
            $result.Readback.PartnerReadiness | Should -BeExactly 'Unverified'
            $result.Readback.GoLiveSuccess | Should -BeFalse
            $result.RepeatStatus | Should -BeExactly 'Succeeded'
            $result.RepeatWrites | Should -Be 0
            $result.DriftMessage | Should -BeLike '*ChangeStateDrift*'
            (($result.Drifted | ConvertFrom-Json).Mailboxes |
                Where-Object { $_.Identity -ceq 'executive@contoso.example' }).SharingPolicy |
                Should -BeExactly 'Approved Partner Sharing'
            $result.DriftWrites | Should -Be 0
            $result.RollbackStatus | Should -BeExactly 'Succeeded'
            @($result.RollbackCalls.Command | Sort-Object -Unique) |
                Should -BeExactly @('Set-Mailbox', 'Set-SharingPolicy')
            @($result.RollbackCalls | Where-Object Command -CEQ 'Set-SharingPolicy').Parameters.Identity |
                Should -Contain 'Approved Partner Sharing'
            @($result.RollbackCalls | Where-Object Command -CEQ 'Set-Mailbox').Parameters.Identity |
                Should -Contain 'executive@contoso.example'
            $result.Restored | Should -BeExactly $result.Before
        }
    }
}
