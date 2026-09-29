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

    function New-SendAsPermission {
        param(
            [string]$Recipient,
            [string]$Trustee,
            [string[]]$AccessRights = @('SendAs'),
            [bool]$IsInherited = $false
        )

        @{
            Identity = "$Recipient\$Trustee"
            TrustIdentity = $Recipient
            Trustee = $Trustee
            AccessRights = @($AccessRights)
            IsInherited = $IsInherited
        }
    }

    function Initialize-SendAsDoubles {
        Initialize-AdapterDoubles
        $global:adapterState.Mailbox = @(
            @{ Identity = 'user@contoso.example'; PrimarySmtpAddress = 'user@contoso.example'; RecipientTypeDetails = 'UserMailbox'; GrantSendOnBehalfTo = @('existing-behalf@contoso.example') }
            @{ Identity = 'shared@contoso.example'; PrimarySmtpAddress = 'shared@contoso.example'; RecipientTypeDetails = 'SharedMailbox'; GrantSendOnBehalfTo = @() }
        )
        $global:adapterState.MailboxPermission = @(
            @{ Identity = 'user@contoso.example\existing-access@contoso.example'; Mailbox = 'user@contoso.example'; User = 'existing-access@contoso.example'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false }
        )
        $global:adapterState.RecipientPermission = @(
            (New-SendAsPermission -Recipient 'user@contoso.example' -Trustee 'NT AUTHORITY\SELF' -IsInherited $true)
            (New-SendAsPermission -Recipient 'shared@contoso.example' -Trustee 'NT AUTHORITY\SELF' -IsInherited $true)
        )
        $global:sendAsReads = [Collections.Generic.List[object]]::new()
        $global:sendAsCollectionFailure = ''
        $global:sendAsCollectionPartial = $false

        function global:Get-Mailbox {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            foreach ($mailbox in @($global:adapterState.Mailbox | Where-Object {
                        [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -eq $Identity
                    })) {
                [pscustomobject]$mailbox.Clone()
            }
        }
        function global:Get-RecipientPermission {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            $global:sendAsReads.Add(@{} + $PSBoundParameters)
            $rows = @($global:adapterState.RecipientPermission | Where-Object {
                    [string]::IsNullOrWhiteSpace($Identity) -or $_.TrustIdentity -eq $Identity
                })
            if ($global:sendAsCollectionPartial -and $rows.Count) {
                [pscustomobject]$rows[0].Clone()
                throw 'ChangeReadIncomplete: Get-RecipientPermission returned a partial paged result.'
            }
            if (-not [string]::IsNullOrWhiteSpace($global:sendAsCollectionFailure)) {
                throw "ChangeReadIncomplete: Get-RecipientPermission failed: $global:sendAsCollectionFailure"
            }
            foreach ($row in $rows) { [pscustomobject]$row.Clone() }
        }
        function global:Add-RecipientPermission {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [Parameter(Mandatory)][string]$Trustee,
                [Parameter(Mandatory)][string[]]$AccessRights
            )

            $bound = @{} + $PSBoundParameters
            $global:adapterCalls.Add(@{ Command = 'Add-RecipientPermission'; Parameters = $bound })
            if ($global:adapterWriteFault -eq 'Add-RecipientPermission') { throw 'Offline write refused: Add-RecipientPermission' }
            $global:adapterState.RecipientPermission += New-SendAsPermission -Recipient $Identity -Trustee $Trustee -AccessRights $AccessRights
        }
        function global:Remove-RecipientPermission {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [Parameter(Mandatory)][string]$Trustee,
                [Parameter(Mandatory)][string[]]$AccessRights
            )

            $bound = @{} + $PSBoundParameters
            $global:adapterCalls.Add(@{ Command = 'Remove-RecipientPermission'; Parameters = $bound })
            if ($global:adapterWriteFault -eq 'Remove-RecipientPermission') { throw 'Offline write refused: Remove-RecipientPermission' }
            $global:adapterState.RecipientPermission = @($global:adapterState.RecipientPermission | Where-Object {
                    -not ($_.TrustIdentity -eq $Identity -and $_.Trustee -eq $Trustee -and 'SendAs' -in $_.AccessRights)
                })
        }
        function global:Get-MailboxPermission {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)
            foreach ($row in @($global:adapterState.MailboxPermission | Where-Object {
                        [string]::IsNullOrWhiteSpace($Identity) -or $_.Mailbox -eq $Identity
                    })) { [pscustomobject]$row.Clone() }
        }
        function global:Set-Mailbox {
            [CmdletBinding(SupportsShouldProcess)]
            param([string]$Identity, [AllowEmptyCollection()][string[]]$GrantSendOnBehalfTo)
            $global:adapterCalls.Add(@{ Command = 'Set-Mailbox'; Parameters = @{} + $PSBoundParameters })
        }
        foreach ($command in @('Get-RecipientPermission','Add-RecipientPermission','Remove-RecipientPermission','Get-MailboxPermission')) {
            $global:adapterCommands.Add($command)
        }
    }

    function Set-SendAsDelegations {
        param($Arguments, [object[]]$Delegations)

        $parameters = Get-Content $Arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions.sendAsDelegations = @($Delegations)
        $parameters | ConvertTo-Json -Depth 40 | Set-Content $Arguments.ParameterPath
    }

    function New-ApprovedSendAsDelegation {
        param(
            [string]$Recipient = 'user@contoso.example',
            [string]$RecipientType = 'UserMailbox',
            [string]$Trustee = 'sender@contoso.example'
        )

        @{
            recipient = $Recipient
            recipientType = $RecipientType
            trustee = $Trustee
            principalType = 'User'
            owner = 'mailbox-owner@contoso.example'
            approval = 'CHG-SENDAS-001'
            expiresOn = [datetimeoffset]::UtcNow.AddDays(7).ToString('o')
            identityEvidence = @{
                source = 'SyntheticOffline'
                reference = "fixture:identity:$Trustee"
                resolved = $true
            }
            ownershipEvidence = @{
                source = 'SyntheticOffline'
                reference = "fixture:owner:$Recipient"
                resolved = $true
            }
        }
    }

    function New-SendAsFixture {
        param([string]$ChangeId = 'SENDAS-T02')

        $arguments = New-StatefulAdapterFixture -Scope SendAs
        $arguments.ChangeId = $ChangeId
        $arguments.PreviewPath = Join-Path $arguments.ArtifactRoot "preview-$ChangeId.json"
        $arguments.ApprovalPath = Join-Path $arguments.ArtifactRoot "approval-$ChangeId.json"
        Set-SendAsDelegations -Arguments $arguments -Delegations @(
            (New-ApprovedSendAsDelegation)
            (New-ApprovedSendAsDelegation -Recipient 'shared@contoso.example' -RecipientType 'SharedMailbox')
        )
        $arguments
    }

    function Approve-SendAsFixture {
        param($Arguments)

        & $script:changeCommand -Stage Preview @Arguments -Scope SendAs -Confirm:$false | Out-Null
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
    }

    function Invoke-SendAsPreview {
        param($Arguments)
        & $script:changeCommand -Stage Preview @Arguments -Scope SendAs -Confirm:$false
    }

    function Get-SendAsStateSnapshot {
        ConvertTo-CanonicalJson ([ordered]@{
            RecipientPermission = @($global:adapterState.RecipientPermission)
            MailboxPermission = @($global:adapterState.MailboxPermission)
            SendOnBehalf = @($global:adapterState.Mailbox | ForEach-Object {
                    [ordered]@{ Identity = $_.Identity; GrantSendOnBehalfTo = @($_.GrantSendOnBehalfTo) }
                })
        })
    }

    function Invoke-SendAsLifecycle {
        param($Arguments)

        $before = Get-SendAsStateSnapshot
        $fullAccessBefore = ConvertTo-CanonicalJson @($global:adapterState.MailboxPermission)
        $sendOnBehalfBefore = ConvertTo-CanonicalJson @($global:adapterState.Mailbox | ForEach-Object {
                [ordered]@{ Identity = $_.Identity; GrantSendOnBehalfTo = @($_.GrantSendOnBehalfTo) }
            })
        & $script:changeCommand -Stage Preview @Arguments -Scope SendAs -Confirm:$false | Out-Null
        $previewHash = (Get-FileHash -LiteralPath $Arguments.PreviewPath -Algorithm SHA256).Hash.ToLowerInvariant()
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
        $approval = Get-Content $Arguments.ApprovalPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        & $script:changeCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:changeCommand -Stage Apply @Arguments -Apply -Confirm:$false

        $mailboxes = @(Get-Mailbox -ResultSize Unlimited)
        $rawReadback = @(foreach ($mailbox in $mailboxes) {
                Get-RecipientPermission -Identity $mailbox.PrimarySmtpAddress -ResultSize Unlimited
            })
        $writesAfterApply = $global:adapterCalls.Count

        $repeatArguments = New-SendAsFixture -ChangeId 'SENDAS-T02-REPEAT'
        Approve-SendAsFixture -Arguments $repeatArguments
        & $script:changeCommand -Stage Validate @repeatArguments | Out-Null
        $repeat = & $script:changeCommand -Stage Apply @repeatArguments -Apply -Confirm:$false
        $repeatWrites = $global:adapterCalls.Count - $writesAfterApply

        $driftArguments = New-SendAsFixture -ChangeId 'SENDAS-T02-DRIFT'
        Approve-SendAsFixture -Arguments $driftArguments
        $removed = @($global:adapterState.RecipientPermission | Where-Object Trustee -EQ 'sender@contoso.example')[0]
        $global:adapterState.RecipientPermission = @($global:adapterState.RecipientPermission | Where-Object { $_ -ne $removed })
        $writesBeforeDrift = $global:adapterCalls.Count
        $drift = $null
        try { & $script:changeCommand -Stage Apply @driftArguments -Apply -Confirm:$false | Out-Null } catch { $drift = $_ }
        $driftWrites = $global:adapterCalls.Count - $writesBeforeDrift
        $global:adapterState.RecipientPermission += $removed

        $writesBeforeRollback = $global:adapterCalls.Count
        $rollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false
        $rollbackCalls = @($global:adapterCalls | Select-Object -Skip $writesBeforeRollback)

        [pscustomobject]@{
            PreviewHash = $previewHash
            ApprovedPreviewHash = [string]$approval.PreviewHash
            Apply = $apply
            Mailboxes = $mailboxes
            RawReadback = $rawReadback
            ReadRequests = @($global:sendAsReads)
            Repeat = $repeat
            RepeatWrites = $repeatWrites
            Drift = $drift
            DriftWrites = $driftWrites
            Rollback = $rollback
            RollbackCalls = $rollbackCalls
            Restored = Get-SendAsStateSnapshot
            Before = $before
            FullAccessBefore = $fullAccessBefore
            FullAccessAfter = ConvertTo-CanonicalJson @($global:adapterState.MailboxPermission)
            SendOnBehalfBefore = $sendOnBehalfBefore
            SendOnBehalfAfter = ConvertTo-CanonicalJson @($global:adapterState.Mailbox | ForEach-Object {
                    [ordered]@{ Identity = $_.Identity; GrantSendOnBehalfTo = @($_.GrantSendOnBehalfTo) }
                })
            OtherPermissionMutationCalls = @($global:adapterCalls | Where-Object {
                    $_.Command -in @('Add-MailboxPermission','Remove-MailboxPermission') -or
                    ($_.Command -eq 'Set-Mailbox' -and $_.Parameters.ContainsKey('GrantSendOnBehalfTo'))
                })
        }
    }
}

Describe 'EXR-007-A05-T02 SendAs delegation lifecycle' {
    BeforeEach {
        Initialize-SendAsDoubles
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

    Context 'Negative: explicit SendAs grants require exact authorization and complete recipient coverage' {
        It 'refuses an unauthorized explicit SendAs grant before writes' {
            # Arrange
            $arguments = New-SendAsFixture
            $global:adapterState.RecipientPermission += New-SendAsPermission -Recipient 'user@contoso.example' -Trustee 'rogue@contoso.example'

            # Act
            $invoke = { Invoke-SendAsPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendAsUnauthorized*rogue@contoso.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an inventory that omits an applicable shared recipient before writes' {
            # Arrange
            $arguments = New-SendAsFixture
            $global:adapterState.Mailbox = @($global:adapterState.Mailbox | Where-Object RecipientTypeDetails -NE 'SharedMailbox')

            # Act
            $invoke = { Invoke-SendAsPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendAsRecipientInventoryIncomplete*shared@contoso.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a nested principal whose independently supplied ownership evidence is unresolved before writes' {
            # Arrange
            $arguments = New-SendAsFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.sendAsDelegations[0].principalType = 'NestedGroup'
            $parameters.workflowOptions.sendAsDelegations[0].ownershipEvidence.resolved = $false
            $parameters.workflowOptions.sendAsDelegations[0].ownershipEvidence.reference = 'fixture:unresolved-nested-owner'
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-SendAsPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendAsPrincipalOwnershipUnresolved*sender@contoso.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an inherited system entry misclassified as an explicit SendAs grant before writes' {
            # Arrange
            $arguments = New-SendAsFixture
            $global:adapterState.RecipientPermission[0].IsInherited = $false

            # Act
            $invoke = { Invoke-SendAsPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendAsEntryClassificationInvalid*NT AUTHORITY\SELF*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: every requested SendAs grant requires independent identity, owner, and approval evidence' {
        It 'refuses a SendAs request without independently supplied owner evidence before writes' {
            # Arrange
            $arguments = New-SendAsFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.sendAsDelegations[0].ownershipEvidence = $null
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-SendAsPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendAsPrincipalOwnershipUnresolved*sender@contoso.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a SendAs request without independently supplied identity evidence before writes' {
            # Arrange
            $arguments = New-SendAsFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.sendAsDelegations[0].identityEvidence = $null
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-SendAsPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendAsPrincipalIdentityUnresolved*sender@contoso.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a SendAs request without an approval reference before writes' {
            # Arrange
            $arguments = New-SendAsFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.sendAsDelegations[0].approval = ''
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-SendAsPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendAsApprovalRequired*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a SendAs request whose approval is expired before writes' {
            # Arrange
            $arguments = New-SendAsFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.sendAsDelegations[0].expiresOn = '2000-01-01T00:00:00Z'
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-SendAsPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendAsApprovalExpired*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: independent raw SendAs reads must be complete and unambiguous' {
        It 'refuses partial output followed by a recipient-permission paging failure before writes' {
            # Arrange
            $arguments = New-SendAsFixture
            $global:sendAsCollectionPartial = $true

            # Act
            $invoke = { Invoke-SendAsPreview $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*partial paged result*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a recipient-permission collection error before writes' {
            # Arrange
            $arguments = New-SendAsFixture
            $global:sendAsCollectionFailure = 'Access is denied.'

            # Act
            $invoke = { Invoke-SendAsPreview $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*Get-RecipientPermission failed*Access is denied*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses duplicate normalized SendAs recipient and trustee identities before writes' {
            # Arrange
            $arguments = New-SendAsFixture
            $permission = New-SendAsPermission -Recipient 'user@contoso.example' -Trustee 'rogue@contoso.example'
            $duplicate = $permission.Clone()
            $duplicate.Identity = ' USER@CONTOSO.EXAMPLE\ROGUE@CONTOSO.EXAMPLE '
            $duplicate.TrustIdentity = ' USER@CONTOSO.EXAMPLE '
            $duplicate.Trustee = ' ROGUE@CONTOSO.EXAMPLE '
            $global:adapterState.RecipientPermission += @($permission, $duplicate)

            # Act
            $invoke = { Invoke-SendAsPreview $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*duplicate*recipient*trustee*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: FullAccess and SendOnBehalf are never SendAs authorization' {
        It 'refuses a declaration that infers SendAs from FullAccess or SendOnBehalf before writes' {
            # Arrange
            $arguments = New-SendAsFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.sendAsDelegations[0].equivalentPermission = @('FullAccess','SendOnBehalf')
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-SendAsPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendAsPermissionTypeBoundary*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Positive: signed least-privilege SendAs lifecycle' {
        It 'applies exact user and shared grants, reads back, no-ops, refuses drift, and rolls back typed grants while preserving other permissions' {
            # Arrange
            $arguments = New-SendAsFixture

            # Act
            $result = Invoke-SendAsLifecycle -Arguments $arguments

            # Assert
            $result.ApprovedPreviewHash | Should -BeExactly $result.PreviewHash
            $result.Apply.Status | Should -BeExactly 'Succeeded'
            @($result.Mailboxes | ForEach-Object RecipientTypeDetails | Sort-Object) | Should -Be @('SharedMailbox','UserMailbox')
            @($result.RawReadback | Where-Object { -not $_.IsInherited -and 'SendAs' -in $_.AccessRights } |
                    ForEach-Object { '{0}|{1}' -f $_.TrustIdentity, $_.Trustee } | Sort-Object) |
                Should -Be @('shared@contoso.example|sender@contoso.example','user@contoso.example|sender@contoso.example')
            @($result.ReadRequests | Where-Object ResultSize -CEQ 'Unlimited').Count | Should -BeGreaterOrEqual 2
            @($result.Apply.Operations | Where-Object { $_.ControlId -eq 'EXR-007-A05-T02' }).Count | Should -Be 2
            @($result.Apply.Operations | Where-Object { $_.Source -eq 'Get-RecipientPermission' }).Count | Should -Be 2
            @($result.Apply.Operations | Where-Object { $_.Evidence -like '*SendAs*' }).Count | Should -Be 2
            @($result.Apply.Operations | Where-Object { $_.Runbook -like '*EXCHANGE-ADMINISTRATOR-JOURNEY*' }).Count | Should -Be 2
            $result.Repeat.Status | Should -BeExactly 'Succeeded'
            $result.RepeatWrites | Should -Be 0
            $result.Drift.Exception.Message | Should -BeLike '*ChangeStateDrift*'
            $result.DriftWrites | Should -Be 0
            $result.Rollback.Status | Should -BeExactly 'Succeeded'
            @($result.RollbackCalls | Where-Object Command -CEQ 'Remove-RecipientPermission').Count | Should -Be 2
            @($result.RollbackCalls | Where-Object { $_.Parameters.AccessRights -contains 'SendAs' }).Count | Should -Be 2
            $result.Restored | Should -BeExactly $result.Before
            $result.FullAccessAfter | Should -BeExactly $result.FullAccessBefore
            $result.SendOnBehalfAfter | Should -BeExactly $result.SendOnBehalfBefore
            $result.OtherPermissionMutationCalls.Count | Should -Be 0
        }
    }
}

AfterAll {
    foreach ($name in @($global:adapterCommands) + @('Get-ConnectionInformation','Invoke-OfflineAdapterCommand')) {
        Remove-Item "Function:global:$name" -ErrorAction SilentlyContinue
    }
    $script:signingCertificate.Dispose()
    $script:signingKey.Dispose()
    Get-Variable -Name 'adapter*','sendAs*' -Scope Global | Remove-Variable -Scope Global
    Remove-Module ExchangeOnlineBaseline.Common -Force -ErrorAction SilentlyContinue
}
