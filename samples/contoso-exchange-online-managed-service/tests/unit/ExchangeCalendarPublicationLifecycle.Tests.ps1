#requires -Version 7.0

Describe 'EXR-007-A04-T02 calendar publication lifecycle contract' {
    BeforeAll {
        $script:sampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        Import-Module (Join-Path $script:sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking
        $script:publicationIdentity = 'executive@contoso.example:\Calendar'

        function Get-Mailbox {
            throw 'Unmocked Get-Mailbox call.'
        }

        function Get-MailboxCalendarFolder {
            throw 'Unmocked Get-MailboxCalendarFolder call.'
        }

        function Set-MailboxCalendarFolder {
            throw 'Unmocked Set-MailboxCalendarFolder call.'
        }

        $script:calendarFolderReader = {
            param([Parameter(Mandatory)][string]$Identity)

            Get-MailboxCalendarFolder -Identity $Identity -ErrorAction Stop
        }
        $script:calendarFolderWriter = {
            param(
                [Parameter(Mandatory)][string]$Identity,
                [Parameter(Mandatory)][bool]$PublishEnabled,
                [Parameter(Mandatory)][string]$DetailLevel
            )

            Set-MailboxCalendarFolder -Identity $Identity -PublishEnabled $PublishEnabled -DetailLevel $DetailLevel -ErrorAction Stop
        }
        $script:subject = {
            param(
                [Parameter(Mandatory)]$InputObject,
                [switch]$Apply,
                [switch]$Rollback
            )

            Invoke-ExchangeCalendarPublicationLifecycle `
                -InputObject $InputObject `
                -Apply:$Apply `
                -Rollback:$Rollback `
                -CalendarFolderReader $script:calendarFolderReader `
                -CalendarFolderWriter $script:calendarFolderWriter
        }

        function New-CalendarPublicationInput {
            [pscustomobject]@{
                ApplicableMailboxes = @('executive@contoso.example')
                CalendarInventory = @(
                    [pscustomobject]@{
                        Mailbox = 'executive@contoso.example'
                        FolderIdentity = $script:publicationIdentity
                        CollectionComplete = $true
                    }
                )
                PublicationState = @(
                    [pscustomobject]@{
                        Mailbox = 'executive@contoso.example'
                        FolderIdentity = $script:publicationIdentity
                        PublishEnabled = $false
                        DetailLevel = 'AvailabilityOnly'
                        PublishedCalendarUrl = $null
                        PublishedICalUrl = $null
                        CollectionComplete = $true
                    }
                )
                Approval = [pscustomobject]@{
                    Reference = 'SYNTHETIC-EXR007-A04-T02'
                    ApprovedMailboxes = @('executive@contoso.example')
                    ApprovedAudience = 'NamedExternalPartner'
                    ApprovedPartnerDomains = @('approved.partner.example')
                    AllowAnonymous = $false
                    MaximumDetail = 'AvailabilityOnly'
                    IndependentlyApproved = $true
                    BoundPublicationIdentity = $script:publicationIdentity
                    ReadyForChange = $true
                }
                RequestedState = [pscustomobject]@{
                    Mailbox = 'executive@contoso.example'
                    FolderIdentity = $script:publicationIdentity
                    PublishEnabled = $true
                    DetailLevel = 'AvailabilityOnly'
                    Audience = 'NamedExternalPartner'
                    PartnerDomains = @('approved.partner.example')
                }
                PreChangeState = [pscustomobject]@{
                    Mailbox = 'executive@contoso.example'
                    FolderIdentity = $script:publicationIdentity
                    PublishEnabled = $false
                    DetailLevel = 'AvailabilityOnly'
                    PublishedCalendarUrl = $null
                    PublishedICalUrl = $null
                }
                ExpectedReadback = [pscustomobject]@{
                    Mailbox = 'executive@contoso.example'
                    FolderIdentity = $script:publicationIdentity
                    PublishEnabled = $true
                    DetailLevel = 'AvailabilityOnly'
                }
                ExpectedRollbackReadback = [pscustomobject]@{
                    Mailbox = 'executive@contoso.example'
                    FolderIdentity = $script:publicationIdentity
                    PublishEnabled = $false
                    DetailLevel = 'AvailabilityOnly'
                    PublishedCalendarUrl = $null
                    PublishedICalUrl = $null
                }
                PartnerReadiness = 'Unverified'
                IndependentPartnerAttestation = $null
                SharingPolicyBindingEvidence = [pscustomobject]@{
                    Exists = $true
                    Reference = 'SYNTHETIC-EXR007-A04-T01'
                }
            }
        }
    }

    BeforeEach {
        Mock Get-Mailbox {
            [pscustomobject]@{ PrimarySmtpAddress = 'executive@contoso.example' }
        }
        Mock Get-MailboxCalendarFolder {
            [pscustomobject]@{
                Identity = $script:publicationIdentity
                PublishEnabled = $false
                DetailLevel = 'AvailabilityOnly'
                PublishedCalendarUrl = $null
                PublishedICalUrl = $null
            }
        }
        Mock Set-MailboxCalendarFolder {}
    }

    Context 'negative calendar publication evidence and lifecycle boundaries' {
        It 'rejects missing applicable mailbox inventory even when T01 policy evidence exists' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.ApplicableMailboxes = @()

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarInventoryMissing*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects missing calendar inventory even when T01 policy evidence exists' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.CalendarInventory = @()

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarInventoryMissing*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects missing calendar publication state' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.PublicationState = @()

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarPublicationStateMissing*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects an incomplete calendar publication collection row' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.PublicationState[0].CollectionComplete = $false

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarPublicationEvidenceIncomplete*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects a calendar publication row missing a required field' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.PublicationState[0].PSObject.Properties.Remove('DetailLevel')

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarPublicationEvidenceIncomplete*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects collection or read failure instead of reporting compliance' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            Mock Get-MailboxCalendarFolder { throw 'Synthetic calendar publication read failure.' }

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarPublicationCollectionFailed*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 1 -Exactly
        }

        It 'rejects publication enabled without independently approved disclosure' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.PublicationState[0].PublishEnabled = $true
            $inputObject.Approval.IndependentlyApproved = $false

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarDisclosureApprovalRequired*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects an unauthorized anonymous disclosure audience' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.RequestedState.Audience = 'Anonymous'

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarDisclosureAudienceUnauthorized*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects an unapproved external partner domain' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.RequestedState.PartnerDomains = @('unapproved.partner.example')

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarDisclosureAudienceUnauthorized*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects disclosure detail broader than the approved maximum' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.RequestedState.DetailLevel = 'LimitedDetails'

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarDisclosureDetailExceedsApproval*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects approval not bound to the publication identity' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.Approval.BoundPublicationIdentity = $null

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarApprovalNotBoundOrReady*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects approval not ready for the publication change' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.Approval.ReadyForChange = $false

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarApprovalNotBoundOrReady*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects local readback as certification of an external partner' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.PartnerReadiness = 'Verified'
            $inputObject.IndependentPartnerAttestation = $null

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*IndependentPartnerAttestationRequired*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects missing prechange state required for reversible handling' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.PreChangeState = $null

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarReversibleStateRequired*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects missing expected apply readback required for reversible handling' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.ExpectedReadback = $null

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarReversibleStateRequired*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects state drift before apply without an unauthorized write' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            Mock Get-MailboxCalendarFolder {
                [pscustomobject]@{
                    Identity = $script:publicationIdentity
                    PublishEnabled = $true
                    DetailLevel = 'LimitedDetails'
                    PublishedCalendarUrl = 'https://example.invalid/drifted'
                    PublishedICalUrl = 'https://example.invalid/drifted.ics'
                }
            }

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarPublicationStateDrift*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 1 -Exactly
        }

        It 'rejects state drift before rollback without an unauthorized write' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $script:calendarRead = 0
            Mock Get-MailboxCalendarFolder {
                $script:calendarRead++
                if ($script:calendarRead -eq 1) {
                    return $inputObject.PreChangeState
                }
                if ($script:calendarRead -eq 2) {
                    return $inputObject.ExpectedReadback
                }
                [pscustomobject]@{
                    Identity = $script:publicationIdentity
                    PublishEnabled = $true
                    DetailLevel = 'LimitedDetails'
                    PublishedCalendarUrl = 'https://example.invalid/drifted'
                    PublishedICalUrl = 'https://example.invalid/drifted.ics'
                }
            }

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarPublicationStateDrift*'
            Should -Invoke Set-MailboxCalendarFolder -Times 1 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 3 -Exactly
        }
    }

    Context 'negative rollback-preflight consistency checks' {
        It 'rejects incomplete rollback readback during rollback-preflight consistency checking' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.ExpectedRollbackReadback.PSObject.Properties.Remove('DetailLevel')

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarRollbackReadbackMismatch*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }

        It 'rejects mismatched rollback readback during rollback-preflight consistency checking' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $inputObject.ExpectedRollbackReadback.DetailLevel = 'LimitedDetails'

            # Act
            $act = { & $script:subject -InputObject $inputObject -Apply -Rollback }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CalendarRollbackReadbackMismatch*'
            Should -Invoke Set-MailboxCalendarFolder -Times 0 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 0 -Exactly
        }
    }

    Context 'approved reversible calendar publication' {
        It 'sets reads back and rolls back independently approved publication while partner readiness remains literal Unverified without independent attestation' {
            # Arrange
            $inputObject = New-CalendarPublicationInput
            $script:calendarRead = 0
            Mock Get-MailboxCalendarFolder {
                $script:calendarRead++
                if ($script:calendarRead -eq 1) {
                    return $inputObject.PreChangeState
                }
                if ($script:calendarRead -in @(2, 3)) {
                    return $inputObject.ExpectedReadback
                }
                $inputObject.ExpectedRollbackReadback
            }

            # Act
            $result = & $script:subject -InputObject $inputObject -Apply -Rollback

            # Assert
            $result.ApplyReadback.PublishEnabled | Should -BeTrue
            $result.ApplyReadback.DetailLevel | Should -BeExactly 'AvailabilityOnly'
            $result.RollbackReadback | Should -Be $inputObject.ExpectedRollbackReadback
            $result.PartnerReadiness | Should -BeExactly 'Unverified'
            $result.IndependentPartnerAttestation | Should -BeNullOrEmpty
            Should -Invoke Set-MailboxCalendarFolder -Times 2 -Exactly
            Should -Invoke Get-MailboxCalendarFolder -Times 4 -Exactly
        }
    }
}
