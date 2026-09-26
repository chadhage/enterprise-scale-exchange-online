#requires -Version 7.0

BeforeAll {
    $script:adapterRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:changeCommand = Join-Path $script:adapterRoot 'scripts/Invoke-ExchangeOnlineChange.ps1'
    Import-Module (Join-Path $script:adapterRoot 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking
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

    function New-FullAccessPermission {
        param(
            [string]$Mailbox,
            [string]$User,
            [string[]]$AccessRights = @('FullAccess'),
            [bool]$IsInherited = $false,
            [bool]$Deny = $false
        )

        @{
            Identity = "$Mailbox\$User"
            Mailbox = $Mailbox
            User = $User
            AccessRights = @($AccessRights)
            IsInherited = $IsInherited
            Deny = $Deny
        }
    }

    function Initialize-FullAccessDoubles {
        Initialize-AdapterDoubles
        $global:adapterState.Mailbox = @(
            @{ Identity = 'user@contoso.example'; PrimarySmtpAddress = 'user@contoso.example'; RecipientTypeDetails = 'UserMailbox'; GrantSendOnBehalfTo = @('existing-behalf@contoso.example') }
            @{ Identity = 'shared@contoso.example'; PrimarySmtpAddress = 'shared@contoso.example'; RecipientTypeDetails = 'SharedMailbox'; GrantSendOnBehalfTo = @() }
        )
        $global:adapterState.MailboxPermission = @(
            (New-FullAccessPermission -Mailbox 'user@contoso.example' -User 'NT AUTHORITY\SELF' -IsInherited $true)
            (New-FullAccessPermission -Mailbox 'shared@contoso.example' -User 'NT AUTHORITY\SELF' -IsInherited $true)
        )
        $global:adapterState.RecipientPermission = @(
            @{ Identity = 'user@contoso.example\existing-send@contoso.example'; TrustIdentity = 'user@contoso.example'; Trustee = 'existing-send@contoso.example'; AccessRights = @('SendAs'); IsInherited = $false }
        )
        $global:fullAccessReads = [Collections.Generic.List[object]]::new()
        $global:fullAccessCollectionFailure = ''
        $global:fullAccessCollectionPartial = $false

        function global:Get-Mailbox {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            foreach ($mailbox in @($global:adapterState.Mailbox | Where-Object {
                        [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -eq $Identity
                    })) {
                [pscustomobject]$mailbox.Clone()
            }
        }
        function global:Get-MailboxPermission {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            $global:fullAccessReads.Add(@{} + $PSBoundParameters)
            $rows = @($global:adapterState.MailboxPermission | Where-Object {
                    [string]::IsNullOrWhiteSpace($Identity) -or $_.Mailbox -eq $Identity
                })
            if ($global:fullAccessCollectionPartial -and $rows.Count) {
                [pscustomobject]$rows[0].Clone()
                throw 'ChangeReadIncomplete: Get-MailboxPermission returned a partial paged result.'
            }
            if (-not [string]::IsNullOrWhiteSpace($global:fullAccessCollectionFailure)) {
                throw "ChangeReadIncomplete: Get-MailboxPermission failed: $global:fullAccessCollectionFailure"
            }
            foreach ($row in $rows) { [pscustomobject]$row.Clone() }
        }
        function global:Add-MailboxPermission {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [Parameter(Mandatory)][string]$User,
                [Parameter(Mandatory)][string[]]$AccessRights,
                [string]$InheritanceType,
                [bool]$AutoMapping
            )

            $bound = @{} + $PSBoundParameters
            $global:adapterCalls.Add(@{ Command = 'Add-MailboxPermission'; Parameters = $bound })
            if ($global:adapterWriteFault -eq 'Add-MailboxPermission') { throw 'Offline write refused: Add-MailboxPermission' }
            $global:adapterState.MailboxPermission += New-FullAccessPermission -Mailbox $Identity -User $User -AccessRights $AccessRights
        }
        function global:Remove-MailboxPermission {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [Parameter(Mandatory)][string]$User,
                [Parameter(Mandatory)][string[]]$AccessRights
            )

            $bound = @{} + $PSBoundParameters
            $global:adapterCalls.Add(@{ Command = 'Remove-MailboxPermission'; Parameters = $bound })
            if ($global:adapterWriteFault -eq 'Remove-MailboxPermission') { throw 'Offline write refused: Remove-MailboxPermission' }
            $global:adapterState.MailboxPermission = @($global:adapterState.MailboxPermission | Where-Object {
                    -not ($_.Mailbox -eq $Identity -and $_.User -eq $User -and 'FullAccess' -in $_.AccessRights)
                })
        }
        function global:Get-RecipientPermission {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            foreach ($row in @($global:adapterState.RecipientPermission | Where-Object {
                        [string]::IsNullOrWhiteSpace($Identity) -or $_.TrustIdentity -eq $Identity
                    })) {
                [pscustomobject]$row.Clone()
            }
        }
        function global:Add-RecipientPermission {
            [CmdletBinding(SupportsShouldProcess)]
            param([string]$Identity, [string]$Trustee, [string[]]$AccessRights)
            $global:adapterCalls.Add(@{ Command = 'Add-RecipientPermission'; Parameters = @{} + $PSBoundParameters })
        }
        function global:Remove-RecipientPermission {
            [CmdletBinding(SupportsShouldProcess)]
            param([string]$Identity, [string]$Trustee, [string[]]$AccessRights)
            $global:adapterCalls.Add(@{ Command = 'Remove-RecipientPermission'; Parameters = @{} + $PSBoundParameters })
        }
        foreach ($command in @('Get-MailboxPermission','Add-MailboxPermission','Remove-MailboxPermission','Get-RecipientPermission','Add-RecipientPermission','Remove-RecipientPermission')) {
            $global:adapterCommands.Add($command)
        }
    }

    function Set-FullAccessDelegations {
        param($Arguments, [object[]]$Delegations)

        $parameters = Get-Content $Arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions.fullAccessDelegations = @($Delegations)
        $parameters | ConvertTo-Json -Depth 40 | Set-Content $Arguments.ParameterPath
    }

    function New-ApprovedFullAccessDelegation {
        param(
            [string]$Mailbox = 'user@contoso.example',
            [string]$MailboxType = 'UserMailbox',
            [string]$Delegate = 'analyst@contoso.example'
        )

        @{
            mailbox = $Mailbox
            mailboxType = $MailboxType
            delegate = $Delegate
            delegateType = 'User'
            owner = 'mailbox-owner@contoso.example'
            approval = 'CHG-FULLACCESS-001'
            expiresOn = [datetimeoffset]::UtcNow.AddDays(7).ToString('o')
            identityEvidence = @{
                source = 'SyntheticOffline'
                reference = "fixture:identity:$Delegate"
                resolved = $true
            }
            ownershipEvidence = @{
                source = 'SyntheticOffline'
                reference = "fixture:owner:$Mailbox"
                resolved = $true
            }
        }
    }

    function New-FullAccessFixture {
        param([string]$ChangeId = 'FULLACCESS-T01')

        $arguments = New-StatefulAdapterFixture -Scope FullAccess
        $arguments.ChangeId = $ChangeId
        $arguments.PreviewPath = Join-Path $arguments.ArtifactRoot "preview-$ChangeId.json"
        $arguments.ApprovalPath = Join-Path $arguments.ArtifactRoot "approval-$ChangeId.json"
        Set-FullAccessDelegations -Arguments $arguments -Delegations @(
            (New-ApprovedFullAccessDelegation)
            (New-ApprovedFullAccessDelegation -Mailbox 'shared@contoso.example' -MailboxType 'SharedMailbox')
        )
        $arguments
    }

    function Approve-FullAccessFixture {
        param($Arguments)

        & $script:changeCommand -Stage Preview @Arguments -Scope FullAccess -Confirm:$false | Out-Null
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
    }

    function Invoke-FullAccessPreview {
        param($Arguments)
        & $script:changeCommand -Stage Preview @Arguments -Scope FullAccess -Confirm:$false
    }

    function Get-FullAccessStateSnapshot {
        ConvertTo-CanonicalJson ([ordered]@{
            MailboxPermission = @($global:adapterState.MailboxPermission)
            RecipientPermission = @($global:adapterState.RecipientPermission)
            SendOnBehalf = @($global:adapterState.Mailbox | ForEach-Object {
                    [ordered]@{ Identity = $_.Identity; GrantSendOnBehalfTo = @($_.GrantSendOnBehalfTo) }
                })
        })
    }

    function Invoke-FullAccessLifecycle {
        param($Arguments)

        $before = Get-FullAccessStateSnapshot
        & $script:changeCommand -Stage Preview @Arguments -Scope FullAccess -Confirm:$false | Out-Null
        $previewHash = (Get-FileHash -LiteralPath $Arguments.PreviewPath -Algorithm SHA256).Hash
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
        $approval = Get-Content $Arguments.ApprovalPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        & $script:changeCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:changeCommand -Stage Apply @Arguments -Apply -Confirm:$false

        $mailboxes = @(Get-Mailbox -ResultSize Unlimited)
        $rawReadback = @(foreach ($mailbox in $mailboxes) {
                Get-MailboxPermission -Identity $mailbox.PrimarySmtpAddress -ResultSize Unlimited
            })
        $sendAsAfterApply = ConvertTo-CanonicalJson @($global:adapterState.RecipientPermission)
        $sendOnBehalfAfterApply = ConvertTo-CanonicalJson @($global:adapterState.Mailbox | ForEach-Object {
                [ordered]@{ Identity = $_.Identity; GrantSendOnBehalfTo = @($_.GrantSendOnBehalfTo) }
            })
        $writesAfterApply = $global:adapterCalls.Count

        $repeatArguments = New-FullAccessFixture -ChangeId 'FULLACCESS-T01-REPEAT'
        Approve-FullAccessFixture -Arguments $repeatArguments
        & $script:changeCommand -Stage Validate @repeatArguments | Out-Null
        $repeat = & $script:changeCommand -Stage Apply @repeatArguments -Apply -Confirm:$false
        $repeatWrites = $global:adapterCalls.Count - $writesAfterApply

        $driftArguments = New-FullAccessFixture -ChangeId 'FULLACCESS-T01-DRIFT'
        Approve-FullAccessFixture -Arguments $driftArguments
        $removed = @($global:adapterState.MailboxPermission | Where-Object User -EQ 'analyst@contoso.example')[0]
        $global:adapterState.MailboxPermission = @($global:adapterState.MailboxPermission | Where-Object { $_ -ne $removed })
        $writesBeforeDrift = $global:adapterCalls.Count
        $drift = $null
        try { & $script:changeCommand -Stage Apply @driftArguments -Apply -Confirm:$false | Out-Null } catch { $drift = $_ }
        $driftWrites = $global:adapterCalls.Count - $writesBeforeDrift
        $global:adapterState.MailboxPermission += $removed

        $writesBeforeRollback = $global:adapterCalls.Count
        $rollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false
        $rollbackCalls = @($global:adapterCalls | Select-Object -Skip $writesBeforeRollback)

        [pscustomobject]@{
            PreviewHash = $previewHash
            ApprovedPreviewHash = [string]$approval.PreviewHash
            Apply = $apply
            Mailboxes = $mailboxes
            RawReadback = $rawReadback
            ReadRequests = @($global:fullAccessReads)
            Repeat = $repeat
            RepeatWrites = $repeatWrites
            Drift = $drift
            DriftWrites = $driftWrites
            Rollback = $rollback
            RollbackCalls = $rollbackCalls
            Restored = Get-FullAccessStateSnapshot
            Before = $before
            SendAsAfterApply = $sendAsAfterApply
            SendOnBehalfAfterApply = $sendOnBehalfAfterApply
            SendMutationCalls = @($global:adapterCalls | Where-Object {
                    $_.Command -in @('Add-RecipientPermission','Remove-RecipientPermission') -or
                    ($_.Command -eq 'Set-Mailbox' -and $_.Parameters.ContainsKey('GrantSendOnBehalfTo'))
                })
        }
    }
}

Describe 'EXR-007-A05-T01 FullAccess delegation lifecycle' {
    BeforeEach {
        Initialize-FullAccessDoubles
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

    Context 'Negative: explicit grants require exact authorization and complete recipient coverage' {
        It 'refuses an unauthorized explicit FullAccess grant before writes' {
            # Arrange
            $arguments = New-FullAccessFixture
            $global:adapterState.MailboxPermission += New-FullAccessPermission -Mailbox 'user@contoso.example' -User 'rogue@contoso.example'

            # Act
            $invoke = { Invoke-FullAccessPreview $arguments }

            # Assert
            $invoke | Should -Throw '*FullAccessUnauthorized*rogue@contoso.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an inventory that omits an applicable shared mailbox before writes' {
            # Arrange
            $arguments = New-FullAccessFixture
            $global:adapterState.Mailbox = @($global:adapterState.Mailbox | Where-Object RecipientTypeDetails -NE 'SharedMailbox')

            # Act
            $invoke = { Invoke-FullAccessPreview $arguments }

            # Assert
            $invoke | Should -Throw '*FullAccessMailboxInventoryIncomplete*shared@contoso.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a nested principal whose supplied ownership evidence is unresolved before writes' {
            # Arrange
            $arguments = New-FullAccessFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.fullAccessDelegations[0].delegateType = 'NestedGroup'
            $parameters.workflowOptions.fullAccessDelegations[0].ownershipEvidence.resolved = $false
            $parameters.workflowOptions.fullAccessDelegations[0].ownershipEvidence.reference = 'fixture:unresolved-nested-owner'
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-FullAccessPreview $arguments }

            # Assert
            $invoke | Should -Throw '*FullAccessPrincipalOwnershipUnresolved*analyst@contoso.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an inherited system entry misclassified as an explicit delegate before writes' {
            # Arrange
            $arguments = New-FullAccessFixture
            $global:adapterState.MailboxPermission[0].IsInherited = $false

            # Act
            $invoke = { Invoke-FullAccessPreview $arguments }

            # Assert
            $invoke | Should -Throw '*FullAccessEntryClassificationInvalid*NT AUTHORITY\SELF*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: every requested grant requires current owner approval' {
        It 'refuses a FullAccess request without an owner before writes' {
            # Arrange
            $arguments = New-FullAccessFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.fullAccessDelegations[0].owner = ''
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-FullAccessPreview $arguments }

            # Assert
            $invoke | Should -Throw '*FullAccessOwnerRequired*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a FullAccess request without an approval reference before writes' {
            # Arrange
            $arguments = New-FullAccessFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.fullAccessDelegations[0].approval = ''
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-FullAccessPreview $arguments }

            # Assert
            $invoke | Should -Throw '*FullAccessApprovalRequired*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a FullAccess request whose approval is expired before writes' {
            # Arrange
            $arguments = New-FullAccessFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.fullAccessDelegations[0].expiresOn = '2000-01-01T00:00:00Z'
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-FullAccessPreview $arguments }

            # Assert
            $invoke | Should -Throw '*FullAccessApprovalExpired*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: independent raw reads must be complete and unambiguous' {
        It 'refuses partial output followed by a mailbox-permission paging failure before writes' {
            # Arrange
            $arguments = New-FullAccessFixture
            $global:fullAccessCollectionPartial = $true

            # Act
            $invoke = { Invoke-FullAccessPreview $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*partial paged result*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a mailbox-permission collection error before writes' {
            # Arrange
            $arguments = New-FullAccessFixture
            $global:fullAccessCollectionFailure = 'Access is denied.'

            # Act
            $invoke = { Invoke-FullAccessPreview $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*Get-MailboxPermission failed*Access is denied*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses duplicate normalized mailbox-permission identities before writes' {
            # Arrange
            $arguments = New-FullAccessFixture
            $permission = New-FullAccessPermission -Mailbox 'user@contoso.example' -User 'rogue@contoso.example'
            $duplicate = $permission.Clone()
            $duplicate.Identity = ' USER@CONTOSO.EXAMPLE\ROGUE@CONTOSO.EXAMPLE '
            $duplicate.Mailbox = ' USER@CONTOSO.EXAMPLE '
            $duplicate.User = ' ROGUE@CONTOSO.EXAMPLE '
            $global:adapterState.MailboxPermission += @($permission, $duplicate)

            # Act
            $invoke = { Invoke-FullAccessPreview $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*duplicate*permission*identity*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: mailbox access is never equivalent to send permission' {
        It 'refuses a declaration that treats SendAs or SendOnBehalf as FullAccess evidence before writes' {
            # Arrange
            $arguments = New-FullAccessFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.fullAccessDelegations[0].equivalentPermission = @('SendAs','SendOnBehalf')
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-FullAccessPreview $arguments }

            # Assert
            $invoke | Should -Throw '*FullAccessPermissionTypeBoundary*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Positive: signed least-privilege FullAccess lifecycle' {
        It 'applies user and shared grants, reads raw state, no-ops, refuses drift, and rolls back typed access without send mutation' {
            # Arrange
            $arguments = New-FullAccessFixture
            $sendAsBefore = ConvertTo-CanonicalJson @($global:adapterState.RecipientPermission)
            $sendOnBehalfBefore = ConvertTo-CanonicalJson @($global:adapterState.Mailbox | ForEach-Object {
                    [ordered]@{ Identity = $_.Identity; GrantSendOnBehalfTo = @($_.GrantSendOnBehalfTo) }
                })

            # Act
            $result = Invoke-FullAccessLifecycle -Arguments $arguments

            # Assert
            $result.ApprovedPreviewHash | Should -BeExactly $result.PreviewHash
            $result.Apply.Status | Should -BeExactly 'Succeeded'
            @($result.Mailboxes | ForEach-Object RecipientTypeDetails | Sort-Object) | Should -Be @('SharedMailbox','UserMailbox')
            @($result.RawReadback | Where-Object { -not $_.IsInherited -and 'FullAccess' -in $_.AccessRights } |
                    ForEach-Object { '{0}|{1}' -f $_.Mailbox, $_.User } | Sort-Object) |
                Should -Be @('shared@contoso.example|analyst@contoso.example','user@contoso.example|analyst@contoso.example')
            @($result.ReadRequests | Where-Object ResultSize -CEQ 'Unlimited').Count | Should -BeGreaterOrEqual 2
            $result.Repeat.Status | Should -BeExactly 'Succeeded'
            $result.RepeatWrites | Should -Be 0
            $result.Drift.Exception.Message | Should -BeLike '*ChangeStateDrift*'
            $result.DriftWrites | Should -Be 0
            $result.Rollback.Status | Should -BeExactly 'Succeeded'
            @($result.RollbackCalls | Where-Object Command -CEQ 'Remove-MailboxPermission').Count | Should -Be 2
            @($result.RollbackCalls | Where-Object { $_.Parameters.AccessRights -contains 'FullAccess' }).Count | Should -Be 2
            $result.Restored | Should -BeExactly $result.Before
            $result.SendAsAfterApply | Should -BeExactly $sendAsBefore
            $result.SendOnBehalfAfterApply | Should -BeExactly $sendOnBehalfBefore
            $result.SendMutationCalls.Count | Should -Be 0
        }
    }
}

AfterAll {
    foreach ($name in @($global:adapterCommands) + @('Get-ConnectionInformation','Invoke-OfflineAdapterCommand')) {
        Remove-Item "Function:global:$name" -ErrorAction SilentlyContinue
    }
    $script:signingCertificate.Dispose()
    $script:signingKey.Dispose()
    Get-Variable -Name 'adapter*','fullAccess*' -Scope Global | Remove-Variable -Scope Global
    Remove-Module ExchangeOnlineBaseline.Common -Force -ErrorAction SilentlyContinue
}