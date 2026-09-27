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

    function Initialize-OrganizationRelationshipDoubles {
        $global:organizationRelationshipReads = [Collections.Generic.List[object]]::new()
        $global:organizationRelationshipCollectionMode = 'Complete'
        $global:organizationRelationshipState = @(
            [pscustomobject]@{
                Identity = 'Approved partner'
                Enabled = $true
                DomainNames = @('approved.partner.example')
                FreeBusyAccessEnabled = $true
                FreeBusyAccessLevel = 'AvailabilityOnly'
                FreeBusyAccessScope = 'Approved sharing group'
            },
            [pscustomobject]@{
                Identity = 'Disabled historical partner'
                Enabled = $false
                DomainNames = @('historical.partner.example')
                FreeBusyAccessEnabled = $false
                FreeBusyAccessLevel = 'None'
                FreeBusyAccessScope = $null
            }
        )

        function global:Get-OrganizationRelationship {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            $global:organizationRelationshipReads.Add(@{ Command = 'Get-OrganizationRelationship'; Parameters = @{} + $PSBoundParameters })
            $rows = @($global:organizationRelationshipState | Where-Object {
                    [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -ceq $Identity
                })
            if ($global:organizationRelationshipCollectionMode -ceq 'PartialAmbiguousPageFailure') {
                $rows[0]
                $rows[0]
                throw 'OrganizationRelationshipEvidenceIncomplete: page 2 failed after an ambiguous duplicate relationship.'
            }
            $rows
        }

        function global:Set-OrganizationRelationship {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [bool]$Enabled,
                [string[]]$DomainNames,
                [bool]$FreeBusyAccessEnabled,
                [string]$FreeBusyAccessLevel,
                [AllowNull()][object]$FreeBusyAccessScope
            )

            $global:adapterCalls.Add(@{ Command = 'Set-OrganizationRelationship'; Parameters = @{} + $PSBoundParameters })
            $row = @($global:organizationRelationshipState | Where-Object Identity -CEQ $Identity)
            if ($row.Count -ne 1) { throw "Offline target not unique: Set-OrganizationRelationship ($($row.Count))." }
            foreach ($field in @('Enabled','DomainNames','FreeBusyAccessEnabled','FreeBusyAccessLevel','FreeBusyAccessScope')) {
                if ($PSBoundParameters.ContainsKey($field)) { $row[0].$field = $PSBoundParameters[$field] }
            }
        }
    }

    function New-OrganizationRelationshipApproval {
        [pscustomobject]@{
            PartnerDomains = @('approved.partner.example', 'historical.partner.example')
            FreeBusyAccessLevel = 'AvailabilityOnly'
            FreeBusyAccessScope = 'Approved sharing group'
        }
    }

    function Invoke-OrganizationRelationshipDecision {
        param([Parameter(Mandatory)]$Approval)

        $evidence = Get-OrganizationRelationshipEvidence -Collection {
            Get-OrganizationRelationship -ResultSize Unlimited
        }
        Test-OrganizationRelationshipControl -Evidence $evidence -Approval $Approval
    }

    function New-OrganizationRelationshipLifecycleFixture {
        param([string]$ChangeId = 'EXR007-A06')

        $arguments = New-StatefulAdapterFixture -Scope OrganizationRelationship
        $arguments.ChangeId = $ChangeId
        $arguments.PreviewPath = Join-Path $arguments.ArtifactRoot "preview-$ChangeId.json"
        $arguments.ApprovalPath = Join-Path $arguments.ArtifactRoot "approval-$ChangeId.json"
        $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions = @{
            organizationRelationships = @(@{
                identity = 'Approved partner'
                enabled = $true
                partnerDomains = @('approved.partner.example')
                freeBusyAccessEnabled = $true
                freeBusyAccessLevel = 'AvailabilityOnly'
                freeBusyAccessScope = 'Approved sharing group'
                approval = @{ reference = 'SYNTHETIC-EXR007-A06'; owner = 'security@contoso.example'; expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o') }
                partnerAttestation = @{ status = 'Unverified' }
            })
        }
        $parameters | ConvertTo-Json -Depth 30 | Set-Content $arguments.ParameterPath
        $arguments
    }

    function Approve-OrganizationRelationshipFixture {
        param($Arguments)

        & $script:changeCommand -Stage Preview @Arguments -Scope OrganizationRelationship -Confirm:$false | Out-Null
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
    }

    function Invoke-OrganizationRelationshipLifecycle {
        param($Arguments)

        $before = @($global:organizationRelationshipState | ConvertTo-Json -Depth 10)
        Approve-OrganizationRelationshipFixture -Arguments $Arguments
        & $script:changeCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:changeCommand -Stage Apply @Arguments -Apply -Confirm:$false
        $readback = Invoke-OrganizationRelationshipDecision -Approval (New-OrganizationRelationshipApproval)
        $writesAfterApply = $global:adapterCalls.Count

        $repeatArguments = New-OrganizationRelationshipLifecycleFixture -ChangeId 'EXR007-A06-REPEAT'
        Approve-OrganizationRelationshipFixture -Arguments $repeatArguments
        & $script:changeCommand -Stage Validate @repeatArguments | Out-Null
        $repeat = & $script:changeCommand -Stage Apply @repeatArguments -Apply -Confirm:$false
        $repeatWrites = $global:adapterCalls.Count - $writesAfterApply

        $approvedState = @($global:organizationRelationshipState | ConvertTo-Json -Depth 10)
        $global:organizationRelationshipState[0].FreeBusyAccessScope = 'Drifted sharing group'
        $writesBeforeDrift = $global:adapterCalls.Count
        $drift = $null
        try { & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false | Out-Null } catch { $drift = $_ }
        $driftWrites = $global:adapterCalls.Count - $writesBeforeDrift
        $global:organizationRelationshipState = @($approvedState | ConvertFrom-Json)
        $rollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false

        [pscustomobject]@{
            ApplyStatus = $apply.Status
            Readback = $readback
            Applied = @($global:organizationRelationshipState | Where-Object Identity -CEQ 'Approved partner')[0]
            RepeatStatus = $repeat.Status
            RepeatWrites = $repeatWrites
            DriftMessage = $drift.Exception.Message
            DriftWrites = $driftWrites
            RollbackStatus = $rollback.Status
            Restored = @($global:organizationRelationshipState | ConvertTo-Json -Depth 10)
            Before = $before
        }
    }
}

AfterAll {
    Remove-Item Function:\Get-OrganizationRelationship -ErrorAction SilentlyContinue
    Remove-Item Function:\Set-OrganizationRelationship -ErrorAction SilentlyContinue
    foreach ($name in @($global:adapterCommands) + @('Get-ConnectionInformation','Invoke-OfflineAdapterCommand')) {
        Remove-Item "Function:global:$name" -ErrorAction SilentlyContinue
    }
    $script:signingCertificate.Dispose()
    $script:signingKey.Dispose()
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-007-A06 organization-relationship disclosure' {
    BeforeEach {
        Initialize-AdapterDoubles
        Initialize-OrganizationRelationshipDoubles
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

    Context 'Negative 01: an unknown partner domain has no disclosure approval' {
        It 'rejects an enabled relationship whose partner domain is not independently approved' {
            # Arrange
            $global:organizationRelationshipState[0].DomainNames = @('unknown.partner.example')
            $approval = New-OrganizationRelationshipApproval

            # Act
            $result = Invoke-OrganizationRelationshipDecision -Approval $approval

            # Assert
            ('{0}|{1}|golive={2}' -f $result.Status, $result.Reason, $result.GoLiveSuccess) |
                Should -BeExactly 'Fail|OrganizationRelationshipDomainUnapproved|golive=False'
        }
    }

    Context 'Negative 02: free-busy detail cannot exceed disclosure approval' {
        It 'rejects LimitedDetails when only availability disclosure is approved' {
            # Arrange
            $global:organizationRelationshipState[0].FreeBusyAccessLevel = 'LimitedDetails'
            $approval = New-OrganizationRelationshipApproval

            # Act
            $result = Invoke-OrganizationRelationshipDecision -Approval $approval

            # Assert
            ('{0}|{1}|golive={2}' -f $result.Status, $result.Reason, $result.GoLiveSuccess) |
                Should -BeExactly 'Fail|OrganizationRelationshipFreeBusyDetailExcessive|golive=False'
        }
    }

    Context 'Negative 03: free-busy access cannot be broader than disclosure approval' {
        It 'rejects tenant-wide access when approval is limited to one local scope' {
            # Arrange
            $global:organizationRelationshipState[0].FreeBusyAccessScope = $null
            $approval = New-OrganizationRelationshipApproval

            # Act
            $result = Invoke-OrganizationRelationshipDecision -Approval $approval

            # Assert
            ('{0}|{1}|golive={2}' -f $result.Status, $result.Reason, $result.GoLiveSuccess) |
                Should -BeExactly 'Fail|OrganizationRelationshipScopeOverbroad|golive=False'
        }
    }

    Context 'Negative 04: incomplete relationship evidence cannot support a disclosure decision' {
        It 'rejects a failed later page that leaves a partial and ambiguous relationship inventory' {
            # Arrange
            $global:organizationRelationshipCollectionMode = 'PartialAmbiguousPageFailure'
            $approval = New-OrganizationRelationshipApproval

            # Act
            $result = Invoke-OrganizationRelationshipDecision -Approval $approval

            # Assert
            ('{0}|{1}|golive={2}' -f $result.Status, $result.Reason, $result.GoLiveSuccess) |
                Should -BeExactly 'Error|OrganizationRelationshipEvidenceIncomplete|golive=False'
        }
    }

    Context 'Positive 01: an approved local organization relationship remains bounded by external readiness' {
        It 'round trips signed local domain detail and scope without claiming partner readiness' {
            # Arrange
            $global:organizationRelationshipState[0].Enabled = $false
            $global:organizationRelationshipState[0].FreeBusyAccessEnabled = $false
            $global:organizationRelationshipState[0].FreeBusyAccessLevel = 'None'
            $global:organizationRelationshipState[0].FreeBusyAccessScope = $null
            $arguments = New-OrganizationRelationshipLifecycleFixture

            # Act
            $result = Invoke-OrganizationRelationshipLifecycle -Arguments $arguments

            # Assert
            $result.ApplyStatus | Should -BeExactly 'Succeeded'
            $result.Applied.Enabled | Should -BeTrue
            @($result.Applied.DomainNames) | Should -BeExactly @('approved.partner.example')
            $result.Applied.FreeBusyAccessEnabled | Should -BeTrue
            $result.Applied.FreeBusyAccessLevel | Should -BeExactly 'AvailabilityOnly'
            $result.Applied.FreeBusyAccessScope | Should -BeExactly 'Approved sharing group'
            $result.Readback.Status | Should -BeExactly 'Pass'
            $result.Readback.PartnerReadiness | Should -BeExactly 'Unverified'
            $result.Readback.GoLiveSuccess | Should -BeFalse
            $result.RepeatStatus | Should -BeExactly 'Succeeded'
            $result.RepeatWrites | Should -Be 0
            $result.DriftMessage | Should -BeLike '*ChangeStateDrift*'
            $result.DriftWrites | Should -Be 0
            $result.RollbackStatus | Should -BeExactly 'Succeeded'
            $result.Restored | Should -BeExactly $result.Before
        }
    }
}