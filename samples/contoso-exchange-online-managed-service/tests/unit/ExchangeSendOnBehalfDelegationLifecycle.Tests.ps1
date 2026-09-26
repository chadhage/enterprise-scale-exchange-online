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

    function Initialize-SendOnBehalfDoubles {
        Initialize-AdapterDoubles
        $global:adapterState.Mailbox = @(
            @{ Identity = 'user@contoso.example'; PrimarySmtpAddress = 'user@contoso.example'; RecipientTypeDetails = 'UserMailbox'; GrantSendOnBehalfTo = @('existing@contoso.example') }
            @{ Identity = 'shared@contoso.example'; PrimarySmtpAddress = 'shared@contoso.example'; RecipientTypeDetails = 'SharedMailbox'; GrantSendOnBehalfTo = @() }
        )
        $global:adapterState.MailboxPermission = @(
            @{ Identity = 'user@contoso.example\existing-access@contoso.example'; Mailbox = 'user@contoso.example'; User = 'existing-access@contoso.example'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false }
        )
        $global:adapterState.RecipientPermission = @(
            @{ Identity = 'user@contoso.example\existing-send@contoso.example'; TrustIdentity = 'user@contoso.example'; Trustee = 'existing-send@contoso.example'; AccessRights = @('SendAs'); IsInherited = $false }
        )
        $global:sendOnBehalfReads = [Collections.Generic.List[object]]::new()
        $global:sendOnBehalfCollectionFailure = ''
        $global:sendOnBehalfCollectionPartial = $false

        function global:Get-Mailbox {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            $global:sendOnBehalfReads.Add(@{} + $PSBoundParameters)
            $rows = @($global:adapterState.Mailbox | Where-Object {
                    [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -eq $Identity
                })
            if ($global:sendOnBehalfCollectionPartial -and $rows.Count) {
                [pscustomobject]$rows[0].Clone()
                throw 'ChangeReadIncomplete: Get-Mailbox returned a partial paged result.'
            }
            if (-not [string]::IsNullOrWhiteSpace($global:sendOnBehalfCollectionFailure)) {
                throw "ChangeReadIncomplete: Get-Mailbox failed: $global:sendOnBehalfCollectionFailure"
            }
            foreach ($row in $rows) { [pscustomobject]$row.Clone() }
        }
        function global:Set-Mailbox {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [AllowEmptyCollection()][string[]]$GrantSendOnBehalfTo
            )

            $bound = @{} + $PSBoundParameters
            $global:adapterCalls.Add(@{ Command = 'Set-Mailbox'; Parameters = $bound })
            if ($global:adapterWriteFault -eq 'Set-Mailbox') { throw 'Offline write refused: Set-Mailbox' }
            $mailbox = @($global:adapterState.Mailbox | Where-Object Identity -EQ $Identity)
            if ($mailbox.Count -ne 1) { throw "Offline target not unique: Set-Mailbox ($($mailbox.Count))." }
            $mailbox[0].GrantSendOnBehalfTo = @($GrantSendOnBehalfTo)
        }
        function global:Get-MailboxPermission {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)
            foreach ($row in @($global:adapterState.MailboxPermission | Where-Object {
                        [string]::IsNullOrWhiteSpace($Identity) -or $_.Mailbox -eq $Identity
                    })) { [pscustomobject]$row.Clone() }
        }
        function global:Get-RecipientPermission {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)
            foreach ($row in @($global:adapterState.RecipientPermission | Where-Object {
                        [string]::IsNullOrWhiteSpace($Identity) -or $_.TrustIdentity -eq $Identity
                    })) { [pscustomobject]$row.Clone() }
        }
        foreach ($command in @('Get-MailboxPermission','Get-RecipientPermission')) {
            $global:adapterCommands.Add($command)
        }
    }

    function Set-SendOnBehalfDelegations {
        param($Arguments, [object[]]$Delegations)

        $parameters = Get-Content $Arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions.sendOnBehalfDelegations = @($Delegations)
        $parameters | ConvertTo-Json -Depth 40 | Set-Content $Arguments.ParameterPath
    }

    function New-ApprovedSendOnBehalfDelegation {
        param(
            [string]$Mailbox = 'user@contoso.example',
            [string]$MailboxType = 'UserMailbox',
            [string]$Delegate = 'delegate@contoso.example'
        )

        @{
            mailbox = $Mailbox
            mailboxType = $MailboxType
            delegate = $Delegate
            delegateType = 'User'
            owner = 'mailbox-owner@contoso.example'
            approval = 'CHG-SENDONBEHALF-001'
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

    function New-SendOnBehalfFixture {
        param([string]$ChangeId = 'SENDONBEHALF-T03')

        $arguments = New-StatefulAdapterFixture -Scope SendOnBehalf
        $arguments.ChangeId = $ChangeId
        $arguments.PreviewPath = Join-Path $arguments.ArtifactRoot "preview-$ChangeId.json"
        $arguments.ApprovalPath = Join-Path $arguments.ArtifactRoot "approval-$ChangeId.json"
        Set-SendOnBehalfDelegations -Arguments $arguments -Delegations @(
            (New-ApprovedSendOnBehalfDelegation)
            (New-ApprovedSendOnBehalfDelegation -Mailbox 'shared@contoso.example' -MailboxType 'SharedMailbox')
        )
        $arguments
    }

    function Approve-SendOnBehalfFixture {
        param($Arguments)

        & $script:changeCommand -Stage Preview @Arguments -Scope SendOnBehalf -Confirm:$false | Out-Null
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
    }

    function Invoke-SendOnBehalfPreview {
        param($Arguments)
        & $script:changeCommand -Stage Preview @Arguments -Scope SendOnBehalf -Confirm:$false
    }

    function Get-SendOnBehalfStateSnapshot {
        ConvertTo-CanonicalJson ([ordered]@{
            Mailbox = @($global:adapterState.Mailbox | ForEach-Object {
                    [ordered]@{ Identity = $_.Identity; GrantSendOnBehalfTo = @($_.GrantSendOnBehalfTo) }
                })
            MailboxPermission = @($global:adapterState.MailboxPermission)
            RecipientPermission = @($global:adapterState.RecipientPermission)
        })
    }

    function Invoke-SendOnBehalfLifecycle {
        param($Arguments)

        $before = Get-SendOnBehalfStateSnapshot
        $fullAccessBefore = ConvertTo-CanonicalJson @($global:adapterState.MailboxPermission)
        $sendAsBefore = ConvertTo-CanonicalJson @($global:adapterState.RecipientPermission)
        & $script:changeCommand -Stage Preview @Arguments -Scope SendOnBehalf -Confirm:$false | Out-Null
        $previewHash = (Get-FileHash -LiteralPath $Arguments.PreviewPath -Algorithm SHA256).Hash.ToLowerInvariant()
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
        $approval = Get-Content $Arguments.ApprovalPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        & $script:changeCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:changeCommand -Stage Apply @Arguments -Apply -Confirm:$false

        $mailboxes = @(Get-Mailbox -ResultSize Unlimited)
        $rawReadback = @($mailboxes | ForEach-Object {
                [ordered]@{ Identity = $_.PrimarySmtpAddress; GrantSendOnBehalfTo = @($_.GrantSendOnBehalfTo) }
            })
        $writesAfterApply = $global:adapterCalls.Count

        $repeatArguments = New-SendOnBehalfFixture -ChangeId 'SENDONBEHALF-T03-REPEAT'
        Approve-SendOnBehalfFixture -Arguments $repeatArguments
        & $script:changeCommand -Stage Validate @repeatArguments | Out-Null
        $repeat = & $script:changeCommand -Stage Apply @repeatArguments -Apply -Confirm:$false
        $repeatWrites = $global:adapterCalls.Count - $writesAfterApply

        $driftArguments = New-SendOnBehalfFixture -ChangeId 'SENDONBEHALF-T03-DRIFT'
        Approve-SendOnBehalfFixture -Arguments $driftArguments
        $global:adapterState.Mailbox[0].GrantSendOnBehalfTo = @('drift@contoso.example')
        $writesBeforeDrift = $global:adapterCalls.Count
        $drift = $null
        try { & $script:changeCommand -Stage Apply @driftArguments -Apply -Confirm:$false | Out-Null } catch { $drift = $_ }
        $driftWrites = $global:adapterCalls.Count - $writesBeforeDrift
        $global:adapterState.Mailbox[0].GrantSendOnBehalfTo = @('existing@contoso.example','delegate@contoso.example')

        $writesBeforeRollback = $global:adapterCalls.Count
        $rollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false
        $rollbackCalls = @($global:adapterCalls | Select-Object -Skip $writesBeforeRollback)

        [pscustomobject]@{
            PreviewHash = $previewHash
            ApprovedPreviewHash = [string]$approval.PreviewHash
            Apply = $apply
            Mailboxes = $mailboxes
            RawReadback = $rawReadback
            ReadRequests = @($global:sendOnBehalfReads)
            Repeat = $repeat
            RepeatWrites = $repeatWrites
            Drift = $drift
            DriftWrites = $driftWrites
            Rollback = $rollback
            RollbackCalls = $rollbackCalls
            Restored = Get-SendOnBehalfStateSnapshot
            Before = $before
            FullAccessBefore = $fullAccessBefore
            FullAccessAfter = ConvertTo-CanonicalJson @($global:adapterState.MailboxPermission)
            SendAsBefore = $sendAsBefore
            SendAsAfter = ConvertTo-CanonicalJson @($global:adapterState.RecipientPermission)
            OtherPermissionMutationCalls = @($global:adapterCalls | Where-Object Command -In @(
                    'Add-MailboxPermission','Remove-MailboxPermission','Add-RecipientPermission','Remove-RecipientPermission'
                ))
        }
    }
}

Describe 'EXR-007-A05-T03 SendOnBehalf delegation lifecycle' {
    BeforeEach {
        Initialize-SendOnBehalfDoubles
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

    Context 'Negative: explicit delegates require exact authorization and complete recipient coverage' {
        It 'refuses an unauthorized explicit SendOnBehalf delegate before writes' {
            # Arrange
            $arguments = New-SendOnBehalfFixture
            $global:adapterState.Mailbox[0].GrantSendOnBehalfTo += 'rogue@contoso.example'

            # Act
            $invoke = { Invoke-SendOnBehalfPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendOnBehalfUnauthorized*rogue@contoso.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an inventory that omits an applicable shared recipient before writes' {
            # Arrange
            $arguments = New-SendOnBehalfFixture
            $global:adapterState.Mailbox = @($global:adapterState.Mailbox | Where-Object RecipientTypeDetails -NE 'SharedMailbox')

            # Act
            $invoke = { Invoke-SendOnBehalfPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendOnBehalfMailboxInventoryIncomplete*shared@contoso.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a nested principal whose supplied ownership evidence is unresolved before writes' {
            # Arrange
            $arguments = New-SendOnBehalfFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.sendOnBehalfDelegations[0].delegateType = 'NestedGroup'
            $parameters.workflowOptions.sendOnBehalfDelegations[0].ownershipEvidence.resolved = $false
            $parameters.workflowOptions.sendOnBehalfDelegations[0].ownershipEvidence.reference = 'fixture:unresolved-nested-owner'
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-SendOnBehalfPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendOnBehalfPrincipalOwnershipUnresolved*delegate@contoso.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an inherited system entry misclassified as an explicit delegate before writes' {
            # Arrange
            $arguments = New-SendOnBehalfFixture
            $global:adapterState.Mailbox[0].GrantSendOnBehalfTo += 'NT AUTHORITY\SELF'

            # Act
            $invoke = { Invoke-SendOnBehalfPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendOnBehalfEntryClassificationInvalid*NT AUTHORITY\SELF*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: every requested delegation requires current owner approval' {
        It 'refuses a SendOnBehalf request without independent owner evidence before writes' {
            # Arrange
            $arguments = New-SendOnBehalfFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.sendOnBehalfDelegations[0].ownershipEvidence = $null
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-SendOnBehalfPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendOnBehalfPrincipalOwnershipUnresolved*delegate@contoso.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a SendOnBehalf request without an approval reference before writes' {
            # Arrange
            $arguments = New-SendOnBehalfFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.sendOnBehalfDelegations[0].approval = ''
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-SendOnBehalfPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendOnBehalfApprovalRequired*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a SendOnBehalf request whose approval is expired before writes' {
            # Arrange
            $arguments = New-SendOnBehalfFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.sendOnBehalfDelegations[0].expiresOn = '2000-01-01T00:00:00Z'
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-SendOnBehalfPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendOnBehalfApprovalExpired*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: independent raw reads must be complete and unambiguous' {
        It 'refuses partial output followed by a mailbox paging failure before writes' {
            # Arrange
            $arguments = New-SendOnBehalfFixture
            $global:sendOnBehalfCollectionPartial = $true

            # Act
            $invoke = { Invoke-SendOnBehalfPreview $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*partial paged result*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a mailbox collection error before writes' {
            # Arrange
            $arguments = New-SendOnBehalfFixture
            $global:sendOnBehalfCollectionFailure = 'Access is denied.'

            # Act
            $invoke = { Invoke-SendOnBehalfPreview $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*Get-Mailbox failed*Access is denied*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses duplicate normalized SendOnBehalf delegate identities before writes' {
            # Arrange
            $arguments = New-SendOnBehalfFixture
            $global:adapterState.Mailbox[0].GrantSendOnBehalfTo = @(
                'rogue@contoso.example',
                ' ROGUE@CONTOSO.EXAMPLE '
            )

            # Act
            $invoke = { Invoke-SendOnBehalfPreview $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*duplicate*delegate*identity*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: mailbox access and SendAs are never SendOnBehalf authorization' {
        It 'refuses a declaration that infers SendOnBehalf from FullAccess or SendAs before writes' {
            # Arrange
            $arguments = New-SendOnBehalfFixture
            $parameters = Get-Content $arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            $parameters.workflowOptions.sendOnBehalfDelegations[0].equivalentPermission = @('FullAccess','SendAs')
            $parameters | ConvertTo-Json -Depth 40 | Set-Content $arguments.ParameterPath

            # Act
            $invoke = { Invoke-SendOnBehalfPreview $arguments }

            # Assert
            $invoke | Should -Throw '*SendOnBehalfPermissionTypeBoundary*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Positive: signed least-privilege SendOnBehalf lifecycle' {
        It 'applies user and shared delegates, reads raw state, no-ops, refuses drift, and rolls back typed values without other permission mutation' {
            # Arrange
            $arguments = New-SendOnBehalfFixture

            # Act
            $result = Invoke-SendOnBehalfLifecycle -Arguments $arguments

            # Assert
            $result.ApprovedPreviewHash | Should -BeExactly $result.PreviewHash
            $result.Apply.Status | Should -BeExactly 'Succeeded'
            @($result.Mailboxes | ForEach-Object RecipientTypeDetails | Sort-Object) | Should -Be @('SharedMailbox','UserMailbox')
            @($result.RawReadback | ForEach-Object {
                    $mailbox = $_.Identity
                    @($_.GrantSendOnBehalfTo | Where-Object { $_ -eq 'delegate@contoso.example' } | ForEach-Object { "$mailbox|$_" })
                } | Sort-Object) | Should -Be @(
                    'shared@contoso.example|delegate@contoso.example',
                    'user@contoso.example|delegate@contoso.example'
                )
            @($result.ReadRequests | Where-Object ResultSize -CEQ 'Unlimited').Count | Should -BeGreaterOrEqual 1
            @($result.Apply.Operations | Where-Object { $_.ControlId -eq 'EXR-007-A05-T03' }).Count | Should -Be 2
            @($result.Apply.Operations | Where-Object { $_.Source -eq 'Get-Mailbox' }).Count | Should -Be 2
            @($result.Apply.Operations | Where-Object { $_.Evidence -like '*GrantSendOnBehalfTo*' }).Count | Should -Be 2
            @($result.Apply.Operations | Where-Object { $_.Runbook -like '*EXCHANGE-ADMINISTRATOR-JOURNEY*' }).Count | Should -Be 2
            $result.Repeat.Status | Should -BeExactly 'Succeeded'
            $result.RepeatWrites | Should -Be 0
            $result.Drift.Exception.Message | Should -BeLike '*ChangeStateDrift*'
            $result.DriftWrites | Should -Be 0
            $result.Rollback.Status | Should -BeExactly 'Succeeded'
            @($result.RollbackCalls | Where-Object Command -CEQ 'Set-Mailbox').Count | Should -Be 2
            @($result.RollbackCalls | Where-Object { $_.Parameters.ContainsKey('GrantSendOnBehalfTo') }).Count | Should -Be 2
            $result.Restored | Should -BeExactly $result.Before
            $result.FullAccessAfter | Should -BeExactly $result.FullAccessBefore
            $result.SendAsAfter | Should -BeExactly $result.SendAsBefore
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
    Get-Variable -Name 'adapter*','sendOnBehalf*' -Scope Global | Remove-Variable -Scope Global
    Remove-Module ExchangeOnlineBaseline.Common -Force -ErrorAction SilentlyContinue
}