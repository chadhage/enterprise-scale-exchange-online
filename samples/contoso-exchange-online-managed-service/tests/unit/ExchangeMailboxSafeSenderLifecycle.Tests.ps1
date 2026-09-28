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

    function Initialize-MailboxSafeSenderDoubles {
        Initialize-AdapterDoubles
        $global:adapterState.Mailbox = @(
            @{ Identity = 'user@contoso.example'; PrimarySmtpAddress = 'user@contoso.example'; RecipientTypeDetails = 'UserMailbox' }
            @{ Identity = 'shared@contoso.example'; PrimarySmtpAddress = 'shared@contoso.example'; RecipientTypeDetails = 'SharedMailbox' }
            @{ Identity = 'room@contoso.example'; PrimarySmtpAddress = 'room@contoso.example'; RecipientTypeDetails = 'RoomMailbox' }
        )
        $global:adapterState.MailboxJunkEmailConfiguration = @(
            @{ Identity = 'user@contoso.example'; TrustedSendersAndDomains = @('personal.example'); Enabled = $true }
            @{ Identity = 'shared@contoso.example'; TrustedSendersAndDomains = @('existing@partner.example'); Enabled = $true }
            @{ Identity = 'room@contoso.example'; TrustedSendersAndDomains = @('facilities.example'); Enabled = $true }
        )
        $global:adapterState.HostedContentFilterPolicy = @(@{
                Identity = 'Default'
                AllowedSenders = @('organization-sender@partner.example')
                AllowedSenderDomains = @('organization.example')
            })
        $global:adapterState.TenantAllowBlockListItems = @(@{
                Identity = 'tabl-allow'
                Value = 'tabl.example'
                ListType = 'Sender'
                Action = 'Allow'
                ExpirationDate = [datetimeoffset]::UtcNow.AddDays(30).ToString('o')
            })
        $global:mailboxSafeSenderReads = [Collections.Generic.List[object]]::new()
        $global:mailboxSafeSenderCollectionFailure = ''
        $global:mailboxSafeSenderCollectionPartial = $false
        $global:mailboxSafeSenderReadbackMismatch = $false

        function global:Get-Mailbox {
            [CmdletBinding()]
            param([string]$Identity, [string]$ResultSize)

            foreach ($mailbox in @($global:adapterState.Mailbox | Where-Object {
                        [string]::IsNullOrWhiteSpace($Identity) -or $_.Identity -eq $Identity
                    })) {
                [pscustomobject]$mailbox.Clone()
            }
        }
        function global:Get-MailboxJunkEmailConfiguration {
            [CmdletBinding()]
            param([Parameter(Mandatory)][string]$Identity)

            $global:mailboxSafeSenderReads.Add(@{} + $PSBoundParameters)
            $rows = @($global:adapterState.MailboxJunkEmailConfiguration | Where-Object Identity -EQ $Identity)
            if ($global:mailboxSafeSenderCollectionPartial -and $rows.Count) {
                [pscustomobject]$rows[0].Clone()
                throw 'ChangeReadIncomplete: Get-MailboxJunkEmailConfiguration returned a partial paged result.'
            }
            if (-not [string]::IsNullOrWhiteSpace($global:mailboxSafeSenderCollectionFailure)) {
                throw "ChangeReadIncomplete: Get-MailboxJunkEmailConfiguration failed: $global:mailboxSafeSenderCollectionFailure"
            }
            foreach ($row in $rows) {
                $copy = $row.Clone()
                if ($global:mailboxSafeSenderReadbackMismatch -and $global:adapterCalls.Count -gt 0 -and
                    $copy.Identity -eq 'user@contoso.example') {
                    $copy.TrustedSendersAndDomains = @('unexpected-readback.example')
                }
                [pscustomobject]$copy
            }
        }
        function global:Set-MailboxJunkEmailConfiguration {
            [CmdletBinding(SupportsShouldProcess)]
            param(
                [Parameter(Mandatory)][string]$Identity,
                [Parameter(Mandatory)][string[]]$TrustedSendersAndDomains
            )

            $bound = @{} + $PSBoundParameters
            $bound.TrustedSendersAndDomains = @($TrustedSendersAndDomains)
            $global:adapterCalls.Add(@{ Command = 'Set-MailboxJunkEmailConfiguration'; Parameters = $bound })
            if ($global:adapterWriteFault -eq 'Set-MailboxJunkEmailConfiguration') {
                throw 'Offline write refused: Set-MailboxJunkEmailConfiguration'
            }
            $target = @($global:adapterState.MailboxJunkEmailConfiguration | Where-Object Identity -EQ $Identity)
            if ($target.Count -ne 1) {
                throw "Offline target not unique: Set-MailboxJunkEmailConfiguration ($($target.Count))."
            }
            $target[0].TrustedSendersAndDomains = @($TrustedSendersAndDomains)
        }
        foreach ($command in @('Get-MailboxJunkEmailConfiguration','Set-MailboxJunkEmailConfiguration')) {
            $global:adapterCommands.Add($command)
        }
    }

    function New-MailboxSafeSenderEntry {
        param(
            [Parameter(Mandatory)][ValidateSet('Sender','Domain')][string]$Kind,
            [Parameter(Mandatory)][string]$Value,
            [string]$Owner = 'mailbox-owner@contoso.example',
            [string]$Approval = 'CHG-SAFESENDER-001',
            [string]$ExpiresOn = [datetimeoffset]::UtcNow.AddDays(7).ToString('o')
        )

        @{
            kind = $Kind
            value = $Value
            owner = $Owner
            approval = $Approval
            expiresOn = $ExpiresOn
        }
    }

    function New-MailboxSafeSenderDeclaration {
        param(
            [string]$Mailbox = 'user@contoso.example',
            [string]$MailboxType = 'UserMailbox',
            [object[]]$Senders = @((New-MailboxSafeSenderEntry -Kind Sender -Value 'approved-sender@partner.example')),
            [object[]]$Domains = @((New-MailboxSafeSenderEntry -Kind Domain -Value 'approved.partner.example'))
        )

        @{
            mailbox = $Mailbox
            mailboxType = $MailboxType
            senders = @($Senders)
            domains = @($Domains)
        }
    }

    function Set-MailboxSafeSenderOptions {
        param(
            $Arguments,
            [object[]]$Declarations = @(
                (New-MailboxSafeSenderDeclaration)
                (New-MailboxSafeSenderDeclaration -Mailbox 'shared@contoso.example' -MailboxType 'SharedMailbox')
            )
        )

        $parameters = Get-Content $Arguments.ParameterPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $parameters.workflowOptions.mailboxSafeSenders = @($Declarations)
        $parameters | ConvertTo-Json -Depth 40 | Set-Content $Arguments.ParameterPath
    }

    function New-MailboxSafeSenderFixture {
        param([string]$ChangeId = 'MAILBOX-SAFE-SENDER-T03')

        $arguments = New-StatefulAdapterFixture -Scope MailboxSafeSender
        $arguments.ChangeId = $ChangeId
        $arguments.PreviewPath = Join-Path $arguments.ArtifactRoot "preview-$ChangeId.json"
        $arguments.ApprovalPath = Join-Path $arguments.ArtifactRoot "approval-$ChangeId.json"
        Set-MailboxSafeSenderOptions -Arguments $arguments
        $arguments
    }

    function Approve-MailboxSafeSenderFixture {
        param($Arguments)

        & $script:changeCommand -Stage Preview @Arguments -Scope MailboxSafeSender -Confirm:$false | Out-Null
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
    }

    function Invoke-MailboxSafeSenderPreview {
        param($Arguments)
        & $script:changeCommand -Stage Preview @Arguments -Scope MailboxSafeSender -Confirm:$false
    }

    function Invoke-MailboxSafeSenderApply {
        param($Arguments)
        & $script:changeCommand -Stage Validate @Arguments | Out-Null
        & $script:changeCommand -Stage Apply @Arguments -Apply -Confirm:$false
    }

    function Get-MailboxSafeSenderStateSnapshot {
        ConvertTo-CanonicalJson @($global:adapterState.MailboxJunkEmailConfiguration | ForEach-Object {
                [ordered]@{
                    Identity = $_.Identity
                    TrustedSendersAndDomains = @($_.TrustedSendersAndDomains)
                    Enabled = $_.Enabled
                }
            })
    }

    function Get-MailboxSafeSenderBoundarySnapshot {
        ConvertTo-CanonicalJson ([ordered]@{
                HostedContentFilterPolicy = @($global:adapterState.HostedContentFilterPolicy)
                TenantAllowBlockListItems = @($global:adapterState.TenantAllowBlockListItems)
            })
    }

    function Get-IndependentMailboxSafeSenderReadback {
        $mailboxes = @(Get-Mailbox -ResultSize Unlimited | Where-Object RecipientTypeDetails -In @('UserMailbox','SharedMailbox'))
        @($mailboxes | ForEach-Object {
                $row = @(Get-MailboxJunkEmailConfiguration -Identity $_.PrimarySmtpAddress)
                if ($row.Count -ne 1) {
                    throw "ChangeReadIncomplete: mailbox Safe Senders readback was not unique for $($_.PrimarySmtpAddress)."
                }
                [pscustomobject]@{
                    Identity = [string]$row[0].Identity
                    TrustedSendersAndDomains = @($row[0].TrustedSendersAndDomains)
                }
            })
    }

    function Invoke-MailboxSafeSenderRollbackAfterDrift {
        param($Arguments)

        Approve-MailboxSafeSenderFixture -Arguments $Arguments
        Invoke-MailboxSafeSenderApply -Arguments $Arguments | Out-Null
        $global:adapterState.MailboxJunkEmailConfiguration[0].TrustedSendersAndDomains = @('post-apply-drift.example')
        $writesBeforeRollback = $global:adapterCalls.Count
        $errorRecord = $null
        try {
            & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false | Out-Null
        } catch {
            $errorRecord = $_
        }
        [pscustomobject]@{
            ErrorRecord = $errorRecord
            Writes = $global:adapterCalls.Count - $writesBeforeRollback
        }
    }

    function Invoke-MailboxSafeSenderLifecycle {
        param($Arguments)

        $before = Get-MailboxSafeSenderStateSnapshot
        $boundariesBefore = Get-MailboxSafeSenderBoundarySnapshot
        $roomBefore = ConvertTo-CanonicalJson @($global:adapterState.MailboxJunkEmailConfiguration | Where-Object Identity -EQ 'room@contoso.example')

        & $script:changeCommand -Stage Preview @Arguments -Scope MailboxSafeSender -Confirm:$false | Out-Null
        $previewHash = (Get-FileHash -LiteralPath $Arguments.PreviewPath -Algorithm SHA256).Hash.ToLowerInvariant()
        & $script:changeCommand -Stage Approve @Arguments -ApprovalIdentity 'reviewer@example.test' -SigningCertificate $script:signingCertificate -Confirm:$false | Out-Null
        $approval = Get-Content $Arguments.ApprovalPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        & $script:changeCommand -Stage Validate @Arguments | Out-Null
        $apply = & $script:changeCommand -Stage Apply @Arguments -Apply -Confirm:$false
        $rawReadback = Get-IndependentMailboxSafeSenderReadback
        $roomAfterApply = ConvertTo-CanonicalJson @($global:adapterState.MailboxJunkEmailConfiguration | Where-Object Identity -EQ 'room@contoso.example')
        $writesBeforeRollback = $global:adapterCalls.Count
        $rollback = & $script:changeCommand -Stage Rollback @Arguments -Apply -Confirm:$false
        $rollbackCalls = @($global:adapterCalls | Select-Object -Skip $writesBeforeRollback)

        [pscustomobject]@{
            PreviewHash = $previewHash
            ApprovedPreviewHash = [string]$approval.PreviewHash
            Apply = $apply
            RawReadback = $rawReadback
            ReadRequests = @($global:mailboxSafeSenderReads)
            Rollback = $rollback
            RollbackCalls = $rollbackCalls
            Restored = Get-MailboxSafeSenderStateSnapshot
            Before = $before
            BoundariesBefore = $boundariesBefore
            BoundariesAfter = Get-MailboxSafeSenderBoundarySnapshot
            RoomBefore = $roomBefore
            RoomAfterApply = $roomAfterApply
        }
    }
}

Describe 'EXR-007-A02-T03 per-mailbox Safe Senders lifecycle' {
    BeforeEach {
        Initialize-MailboxSafeSenderDoubles
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

    Context 'Negative: applicable mailbox inventory is complete and unambiguous' {
        It 'refuses an omitted applicable mailbox before writes' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture
            Set-MailboxSafeSenderOptions -Arguments $arguments -Declarations @(
                (New-MailboxSafeSenderDeclaration)
            )

            # Act
            $invoke = { Invoke-MailboxSafeSenderPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*MailboxSafeSenderMailboxOmitted*shared@contoso.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an ambiguous normalized mailbox identity before writes' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture
            $global:adapterState.Mailbox += @{
                Identity = ' SHARED@CONTOSO.EXAMPLE '
                PrimarySmtpAddress = ' SHARED@CONTOSO.EXAMPLE '
                RecipientTypeDetails = 'SharedMailbox'
            }

            # Act
            $invoke = { Invoke-MailboxSafeSenderPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*MailboxSafeSenderMailboxIdentityAmbiguous*shared@contoso.example*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: independent per-mailbox collection must be complete' {
        It 'refuses an incomplete mailbox junk-email row before writes' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture
            $global:adapterState.MailboxJunkEmailConfiguration[0].Remove('TrustedSendersAndDomains')

            # Act
            $invoke = { Invoke-MailboxSafeSenderPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*MailboxJunkEmailConfiguration*TrustedSendersAndDomains*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses partial output followed by a paging failure before writes' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture
            $global:mailboxSafeSenderCollectionPartial = $true

            # Act
            $invoke = { Invoke-MailboxSafeSenderPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*Get-MailboxJunkEmailConfiguration*partial paged result*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a mailbox junk-email collection error before writes' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture
            $global:mailboxSafeSenderCollectionFailure = 'Access is denied.'

            # Act
            $invoke = { Invoke-MailboxSafeSenderPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadIncomplete*Get-MailboxJunkEmailConfiguration failed*Access is denied*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: Safe Sender trust is narrow and independently approved' {
        It 'refuses broad mailbox Safe Sender trust before writes' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture
            Set-MailboxSafeSenderOptions -Arguments $arguments -Declarations @(
                (New-MailboxSafeSenderDeclaration -Domains @(
                        (New-MailboxSafeSenderEntry -Kind Domain -Value '*')
                    ))
                (New-MailboxSafeSenderDeclaration -Mailbox 'shared@contoso.example' -MailboxType 'SharedMailbox')
            )

            # Act
            $invoke = { Invoke-MailboxSafeSenderPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*MailboxSafeSenderTrustTooBroad***'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an unapproved sender entry before writes' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture
            Set-MailboxSafeSenderOptions -Arguments $arguments -Declarations @(
                (New-MailboxSafeSenderDeclaration -Senders @(
                        (New-MailboxSafeSenderEntry -Kind Sender -Value 'approved-sender@partner.example' -Approval '')
                    ))
                (New-MailboxSafeSenderDeclaration -Mailbox 'shared@contoso.example' -MailboxType 'SharedMailbox')
            )

            # Act
            $invoke = { Invoke-MailboxSafeSenderPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*MailboxSafeSenderApprovalRequired*approved-sender@partner.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an unapproved domain entry before writes' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture
            Set-MailboxSafeSenderOptions -Arguments $arguments -Declarations @(
                (New-MailboxSafeSenderDeclaration -Domains @(
                        (New-MailboxSafeSenderEntry -Kind Domain -Value 'approved.partner.example' -Approval '')
                    ))
                (New-MailboxSafeSenderDeclaration -Mailbox 'shared@contoso.example' -MailboxType 'SharedMailbox')
            )

            # Act
            $invoke = { Invoke-MailboxSafeSenderPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*MailboxSafeSenderApprovalRequired*approved.partner.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a sender entry without an owner before writes' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture
            Set-MailboxSafeSenderOptions -Arguments $arguments -Declarations @(
                (New-MailboxSafeSenderDeclaration -Senders @(
                        (New-MailboxSafeSenderEntry -Kind Sender -Value 'approved-sender@partner.example' -Owner '')
                    ))
                (New-MailboxSafeSenderDeclaration -Mailbox 'shared@contoso.example' -MailboxType 'SharedMailbox')
            )

            # Act
            $invoke = { Invoke-MailboxSafeSenderPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*MailboxSafeSenderOwnerRequired*approved-sender@partner.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses a domain entry without an owner before writes' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture
            Set-MailboxSafeSenderOptions -Arguments $arguments -Declarations @(
                (New-MailboxSafeSenderDeclaration -Domains @(
                        (New-MailboxSafeSenderEntry -Kind Domain -Value 'approved.partner.example' -Owner '')
                    ))
                (New-MailboxSafeSenderDeclaration -Mailbox 'shared@contoso.example' -MailboxType 'SharedMailbox')
            )

            # Act
            $invoke = { Invoke-MailboxSafeSenderPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*MailboxSafeSenderOwnerRequired*approved.partner.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an expired sender entry before writes' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture
            Set-MailboxSafeSenderOptions -Arguments $arguments -Declarations @(
                (New-MailboxSafeSenderDeclaration -Senders @(
                        (New-MailboxSafeSenderEntry -Kind Sender -Value 'approved-sender@partner.example' -ExpiresOn '2000-01-01T00:00:00Z')
                    ))
                (New-MailboxSafeSenderDeclaration -Mailbox 'shared@contoso.example' -MailboxType 'SharedMailbox')
            )

            # Act
            $invoke = { Invoke-MailboxSafeSenderPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*MailboxSafeSenderApprovalExpired*approved-sender@partner.example*'
            $global:adapterCalls.Count | Should -Be 0
        }

        It 'refuses an expired domain entry before writes' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture
            Set-MailboxSafeSenderOptions -Arguments $arguments -Declarations @(
                (New-MailboxSafeSenderDeclaration -Domains @(
                        (New-MailboxSafeSenderEntry -Kind Domain -Value 'approved.partner.example' -ExpiresOn '2000-01-01T00:00:00Z')
                    ))
                (New-MailboxSafeSenderDeclaration -Mailbox 'shared@contoso.example' -MailboxType 'SharedMailbox')
            )

            # Act
            $invoke = { Invoke-MailboxSafeSenderPreview -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*MailboxSafeSenderApprovalExpired*approved.partner.example*'
            $global:adapterCalls.Count | Should -Be 0
        }
    }

    Context 'Negative: readback and recovery are fail closed' {
        It 'refuses a raw per-mailbox readback mismatch after a write' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture
            Approve-MailboxSafeSenderFixture -Arguments $arguments
            $global:mailboxSafeSenderReadbackMismatch = $true

            # Act
            $invoke = { Invoke-MailboxSafeSenderApply -Arguments $arguments }

            # Assert
            $invoke | Should -Throw '*ChangeReadbackMismatch*MailboxSafeSender*user@contoso.example*'
        }

        It 'refuses rollback after post-apply Safe Sender drift without recovery writes' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture

            # Act
            $result = Invoke-MailboxSafeSenderRollbackAfterDrift -Arguments $arguments

            # Assert
            $result.ErrorRecord.Exception.Message | Should -BeLike '*ChangeStateDrift*'
            $result.Writes | Should -Be 0
        }
    }

    Context 'Positive: one narrow approved per-mailbox Safe Sender lifecycle' {
        It 'applies approved sender and domain entries, independently reads them back, preserves other mailboxes, and rolls back typed state' {
            # Arrange
            $arguments = New-MailboxSafeSenderFixture

            # Act
            $result = Invoke-MailboxSafeSenderLifecycle -Arguments $arguments

            # Assert
            $result.ApprovedPreviewHash | Should -BeExactly $result.PreviewHash
            $result.Apply.Status | Should -BeExactly 'Succeeded'
            @($result.RawReadback | ForEach-Object Identity | Sort-Object) |
                Should -Be @('shared@contoso.example','user@contoso.example')
            @($result.RawReadback | Where-Object Identity -EQ 'user@contoso.example').TrustedSendersAndDomains |
                Should -Be @('approved-sender@partner.example','approved.partner.example','personal.example')
            @($result.RawReadback | Where-Object Identity -EQ 'shared@contoso.example').TrustedSendersAndDomains |
                Should -Be @('approved-sender@partner.example','approved.partner.example','existing@partner.example')
            @($result.ReadRequests | Where-Object Identity -In @('user@contoso.example','shared@contoso.example')).Count |
                Should -BeGreaterOrEqual 2
            $result.RoomAfterApply | Should -BeExactly $result.RoomBefore
            $result.BoundariesAfter | Should -BeExactly $result.BoundariesBefore
            $result.Rollback.Status | Should -BeExactly 'Succeeded'
            @($result.RollbackCalls | Where-Object Command -CEQ 'Set-MailboxJunkEmailConfiguration').Count | Should -Be 2
            @($result.RollbackCalls | Where-Object { $_.Parameters.ContainsKey('TrustedSendersAndDomains') }).Count | Should -Be 2
            $result.Restored | Should -BeExactly $result.Before
            @($global:adapterCalls | Where-Object Command -Match 'HostedContentFilterPolicy|TenantAllowBlockList').Count | Should -Be 0
        }
    }
}

AfterAll {
    foreach ($name in @($global:adapterCommands) + @('Get-ConnectionInformation','Invoke-OfflineAdapterCommand')) {
        Remove-Item "Function:global:$name" -ErrorAction SilentlyContinue
    }
    $script:signingCertificate.Dispose()
    $script:signingKey.Dispose()
    Get-Variable -Name 'adapter*','mailboxSafeSender*' -Scope Global | Remove-Variable -Scope Global
    Remove-Module ExchangeOnlineBaseline.Common -Force -ErrorAction SilentlyContinue
}
