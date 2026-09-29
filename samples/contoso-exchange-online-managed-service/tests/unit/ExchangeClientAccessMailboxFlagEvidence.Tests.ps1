#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonManifestPath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psd1'
    Import-Module -Name $script:CommonManifestPath -Force -DisableNameChecking -ErrorAction Stop

    function Copy-ClientAccessFixture {
        param([Parameter(Mandatory)][object]$InputObject)

        $InputObject | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
    }

    function Get-ClientAccessFixtureHash {
        param([Parameter(Mandatory)][object]$InputObject)

        $json = $InputObject | ConvertTo-Json -Depth 20 -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        ([System.Security.Cryptography.SHA256]::HashData($bytes) | ForEach-Object ToString x2) -join ''
    }

    function New-ClientAccessMailbox {
        param(
            [string]$Identity = 'alex.wilber@contoso.example',
            [string]$RecipientTypeDetails = 'UserMailbox',
            [string]$MailboxPlan = 'ExchangeOnlineEnterprise',
            [object]$ActiveSyncEnabled = $true,
            [object]$MAPIEnabled = $true,
            [object]$OWAEnabled = $true
        )

        [pscustomobject][ordered]@{
            Identity = $Identity
            ExternalDirectoryObjectId = '00000000-0000-0000-0000-000000000101'
            PrimarySmtpAddress = $Identity
            RecipientTypeDetails = $RecipientTypeDetails
            MailboxPlan = $MailboxPlan
            ActiveSyncEnabled = $ActiveSyncEnabled
            MAPIEnabled = $MAPIEnabled
            OWAEnabled = $OWAEnabled
        }
    }

    function New-ClientAccessPlan {
        param(
            [string]$Identity = 'ExchangeOnlineEnterprise',
            [object]$ActiveSyncEnabled = $true,
            [object]$MAPIEnabled = $true,
            [object]$OWAEnabled = $true
        )

        [pscustomobject][ordered]@{
            Identity = $Identity
            Name = $Identity
            ActiveSyncEnabled = $ActiveSyncEnabled
            MAPIEnabled = $MAPIEnabled
            OWAEnabled = $OWAEnabled
        }
    }

    function New-ClientAccessReaders {
        param(
            [object[]]$Mailboxes = @(
                (New-ClientAccessMailbox),
                (New-ClientAccessMailbox -Identity 'shared.operations@contoso.example' -RecipientTypeDetails 'SharedMailbox'),
                (New-ClientAccessMailbox -Identity 'boardroom@contoso.example' -RecipientTypeDetails 'RoomMailbox'),
                (New-ClientAccessMailbox -Identity 'projector@contoso.example' -RecipientTypeDetails 'EquipmentMailbox')
            ),
            [object[]]$Plans = @((New-ClientAccessPlan))
        )

        @{
            MailboxReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($Mailboxes); Complete = $true; NextLink = $null }
            }.GetNewClosure()
            PlanReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($Plans); Complete = $true; NextLink = $null }
            }.GetNewClosure()
        }
    }

    function Invoke-ClientAccessEvidenceFixture {
        param(
            [AllowNull()][scriptblock]$MailboxReader,
            [AllowNull()][scriptblock]$PlanReader
        )

        Get-ExchangeClientAccessMailboxFlagEvidence -MailboxReader $MailboxReader -PlanReader $PlanReader
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-007-A08-T01 complete raw mailbox and mailbox-plan flag evidence' {
    Context 'Negative: ActiveSync schema boundaries and collection failures' {
        It '01 refuses a mailbox row without ActiveSyncEnabled' {
            # Arrange
            $readers = New-ClientAccessReaders
            $mailbox = New-ClientAccessMailbox
            $mailbox.PSObject.Properties.Remove('ActiveSyncEnabled')
            $mailboxReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($mailbox); Complete = $true; NextLink = $null }
            }.GetNewClosure()

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $mailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'MailboxSchemaInvalid:ActiveSyncEnabled'
        }

        It '02 refuses a mailbox-plan row without ActiveSyncEnabled' {
            # Arrange
            $readers = New-ClientAccessReaders
            $plan = New-ClientAccessPlan
            $plan.PSObject.Properties.Remove('ActiveSyncEnabled')
            $planReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($plan); Complete = $true; NextLink = $null }
            }.GetNewClosure()

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $planReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PlanSchemaInvalid:ActiveSyncEnabled'
        }

        It '03 records mailbox collection failure without presenting partial evidence' {
            # Arrange
            $readers = New-ClientAccessReaders
            $mailboxReader = { param($NextLink) throw 'SyntheticMailboxReadFailure' }

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $mailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeLike 'MailboxCollectionFailed:*SyntheticMailboxReadFailure*'
        }

        It '04 records mailbox-plan collection failure without presenting partial evidence' {
            # Arrange
            $readers = New-ClientAccessReaders
            $planReader = { param($NextLink) throw 'SyntheticPlanReadFailure' }

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $planReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeLike 'PlanCollectionFailed:*SyntheticPlanReadFailure*'
        }
    }

    Context 'Negative: completeness, paging, and additional flag boundaries' {
        It '05 refuses a mailbox page declared incomplete without a continuation' {
            # Arrange
            $readers = New-ClientAccessReaders
            $mailboxReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @(); Complete = $false; NextLink = $null }
            }

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $mailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'MailboxCollectionIncomplete'
        }

        It '06 refuses a mailbox-plan page declared incomplete without a continuation' {
            # Arrange
            $readers = New-ClientAccessReaders
            $planReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @(); Complete = $false; NextLink = $null }
            }

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $planReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PlanCollectionIncomplete'
        }

        It '07 refuses a mailbox-plan row without OWAEnabled' {
            # Arrange
            $readers = New-ClientAccessReaders
            $plan = New-ClientAccessPlan
            $plan.PSObject.Properties.Remove('OWAEnabled')
            $planReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($plan); Complete = $true; NextLink = $null }
            }.GetNewClosure()

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $planReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PlanSchemaInvalid:OWAEnabled'
        }

        It '08 refuses a non-Boolean mailbox ActiveSyncEnabled value' {
            # Arrange
            $readers = New-ClientAccessReaders -Mailboxes @((New-ClientAccessMailbox -ActiveSyncEnabled 'true'))

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'MailboxBooleanInvalid:ActiveSyncEnabled'
        }

        It '09 refuses a repeated mailbox continuation token' {
            # Arrange
            $readers = New-ClientAccessReaders
            $mailboxReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @(); Complete = $false; NextLink = 'mailbox:cycle' }
            }

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $mailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'MailboxPagingCycle'
        }

        It '10 refuses a repeated mailbox-plan continuation token' {
            # Arrange
            $readers = New-ClientAccessReaders
            $planReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @(); Complete = $false; NextLink = 'plan:cycle' }
            }

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $planReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PlanPagingCycle'
        }
    }

    Context 'Negative: identity and supported raw-field schema boundaries' {
        It '11 refuses a non-Boolean mailbox-plan ActiveSyncEnabled value' {
            # Arrange
            $readers = New-ClientAccessReaders -Plans @((New-ClientAccessPlan -ActiveSyncEnabled 'enabled'))

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PlanBooleanInvalid:ActiveSyncEnabled'
        }

        It '12 refuses a non-Boolean mailbox-plan OWAEnabled value' {
            # Arrange
            $readers = New-ClientAccessReaders -Plans @((New-ClientAccessPlan -OWAEnabled 1))

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PlanBooleanInvalid:OWAEnabled'
        }

        It '13 refuses a mailbox row without Identity' {
            # Arrange
            $readers = New-ClientAccessReaders
            $mailbox = New-ClientAccessMailbox
            $mailbox.PSObject.Properties.Remove('Identity')
            $mailboxReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($mailbox); Complete = $true; NextLink = $null }
            }.GetNewClosure()

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $mailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'MailboxSchemaInvalid:Identity'
        }

        It '14 refuses a mailbox row without RecipientTypeDetails' {
            # Arrange
            $readers = New-ClientAccessReaders
            $mailbox = New-ClientAccessMailbox
            $mailbox.PSObject.Properties.Remove('RecipientTypeDetails')
            $mailboxReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($mailbox); Complete = $true; NextLink = $null }
            }.GetNewClosure()

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $mailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'MailboxSchemaInvalid:RecipientTypeDetails'
        }

        It '15 refuses a mailbox row without MAPIEnabled' {
            # Arrange
            $readers = New-ClientAccessReaders
            $mailbox = New-ClientAccessMailbox
            $mailbox.PSObject.Properties.Remove('MAPIEnabled')
            $mailboxReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($mailbox); Complete = $true; NextLink = $null }
            }.GetNewClosure()

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $mailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'MailboxSchemaInvalid:MAPIEnabled'
        }

        It '16 refuses a mailbox row without OWAEnabled' {
            # Arrange
            $readers = New-ClientAccessReaders
            $mailbox = New-ClientAccessMailbox
            $mailbox.PSObject.Properties.Remove('OWAEnabled')
            $mailboxReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($mailbox); Complete = $true; NextLink = $null }
            }.GetNewClosure()

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $mailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'MailboxSchemaInvalid:OWAEnabled'
        }

        It '17 refuses a mailbox-plan row without Identity' {
            # Arrange
            $readers = New-ClientAccessReaders
            $plan = New-ClientAccessPlan
            $plan.PSObject.Properties.Remove('Identity')
            $planReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($plan); Complete = $true; NextLink = $null }
            }.GetNewClosure()

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $planReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PlanSchemaInvalid:Identity'
        }

        It '18 refuses a mailbox-plan row without Name' {
            # Arrange
            $readers = New-ClientAccessReaders
            $plan = New-ClientAccessPlan
            $plan.PSObject.Properties.Remove('Name')
            $planReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($plan); Complete = $true; NextLink = $null }
            }.GetNewClosure()

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $planReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PlanSchemaInvalid:Name'
        }

        It '19 refuses a mailbox row with a blank MailboxPlan' {
            # Arrange
            $readers = New-ClientAccessReaders
            $mailbox = New-ClientAccessMailbox -MailboxPlan ' '
            $mailboxReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($mailbox); Complete = $true; NextLink = $null }
            }.GetNewClosure()

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $mailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'MailboxSchemaInvalid:MailboxPlan'
        }

        It '20 refuses a mailbox-plan row without MAPIEnabled' {
            # Arrange
            $readers = New-ClientAccessReaders
            $plan = New-ClientAccessPlan
            $plan.PSObject.Properties.Remove('MAPIEnabled')
            $planReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($plan); Complete = $true; NextLink = $null }
            }.GetNewClosure()

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $planReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PlanSchemaInvalid:MAPIEnabled'
        }
    }

    Context 'Negative: Boolean, duplicate, mailbox-class, and safety boundaries' {
        It '21 refuses a non-Boolean mailbox MAPIEnabled value' {
            # Arrange
            $readers = New-ClientAccessReaders -Mailboxes @((New-ClientAccessMailbox -MAPIEnabled 'true'))

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'MailboxBooleanInvalid:MAPIEnabled'
        }

        It '22 refuses a non-Boolean mailbox OWAEnabled value' {
            # Arrange
            $readers = New-ClientAccessReaders -Mailboxes @((New-ClientAccessMailbox -OWAEnabled 1))

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'MailboxBooleanInvalid:OWAEnabled'
        }

        It '23 refuses a non-Boolean mailbox-plan MAPIEnabled value' {
            # Arrange
            $readers = New-ClientAccessReaders -Plans @((New-ClientAccessPlan -MAPIEnabled 'enabled'))

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PlanBooleanInvalid:MAPIEnabled'
        }

        It '24 refuses duplicate mailbox identities case-insensitively' {
            # Arrange
            $readers = New-ClientAccessReaders -Mailboxes @(
                (New-ClientAccessMailbox -Identity 'alex.wilber@contoso.example'),
                (New-ClientAccessMailbox -Identity 'ALEX.WILBER@contoso.example')
            )

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'DuplicateMailboxIdentity:alex.wilber@contoso.example'
        }

        It '25 refuses duplicate tenant-discovered mailbox-plan identities case-insensitively' {
            # Arrange
            $readers = New-ClientAccessReaders -Plans @(
                (New-ClientAccessPlan -Identity 'ExchangeOnlineEnterprise'),
                (New-ClientAccessPlan -Identity 'exchangeonlineenterprise')
            )

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'DuplicatePlanIdentity:ExchangeOnlineEnterprise'
        }

        It '26 explicitly excludes unsupported GroupMailbox rows without treating them as supported' {
            # Arrange
            $readers = New-ClientAccessReaders -Mailboxes @(
                (New-ClientAccessMailbox),
                (New-ClientAccessMailbox -Identity 'group@contoso.example' -RecipientTypeDetails 'GroupMailbox')
            )

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $readers.PlanReader

            # Assert
            @($result.Value.Mailboxes | Where-Object Disposition -eq 'Included').Count | Should -Be 1
            @($result.Value.Mailboxes | Where-Object { $_.Identity -eq 'group@contoso.example' -and $_.Disposition -eq 'Excluded' -and $_.Reason -eq 'UnsupportedMailboxClass' }).Count | Should -Be 1
        }

        It '27 preserves reader-owned objects and binds the hash to supported raw fields only' {
            # Arrange
            $mailbox = New-ClientAccessMailbox -MAPIEnabled $false
            $plan = New-ClientAccessPlan
            $mailboxBefore = $mailbox | ConvertTo-Json -Depth 20 -Compress
            $planBefore = $plan | ConvertTo-Json -Depth 20 -Compress
            $expectedRaw = [ordered]@{ Mailboxes = @($mailbox); Plans = @($plan) }
            $expectedHash = Get-ClientAccessFixtureHash -InputObject $expectedRaw
            $readers = New-ClientAccessReaders -Mailboxes @($mailbox) -Plans @($plan)

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $readers.PlanReader

            # Assert
            ($mailbox | ConvertTo-Json -Depth 20 -Compress) | Should -BeExactly $mailboxBefore
            ($plan | ConvertTo-Json -Depth 20 -Compress) | Should -BeExactly $planBefore
            $result.RawHash | Should -BeExactly $expectedHash
        }
    }

    Context 'Positive: complete synthetic supported evidence' {
        It '28 records all supported mailbox classes and tenant-discovered plans deterministically' {
            # Arrange
            $mailboxes = @(
                (New-ClientAccessMailbox -Identity 'user@contoso.example' -RecipientTypeDetails 'UserMailbox' -MailboxPlan 'TenantDiscovered-Plan-A' -ActiveSyncEnabled $false),
                (New-ClientAccessMailbox -Identity 'shared@contoso.example' -RecipientTypeDetails 'SharedMailbox' -MailboxPlan 'TenantDiscovered-Plan-B' -MAPIEnabled $false),
                (New-ClientAccessMailbox -Identity 'room@contoso.example' -RecipientTypeDetails 'RoomMailbox' -MailboxPlan 'TenantDiscovered-Plan-A' -OWAEnabled $false),
                (New-ClientAccessMailbox -Identity 'equipment@contoso.example' -RecipientTypeDetails 'EquipmentMailbox' -MailboxPlan 'TenantDiscovered-Plan-B')
            )
            $plans = @(
                (New-ClientAccessPlan -Identity 'TenantDiscovered-Plan-B' -OWAEnabled $false),
                (New-ClientAccessPlan -Identity 'TenantDiscovered-Plan-A' -ActiveSyncEnabled $false -MAPIEnabled $false)
            )
            $expectedRaw = [ordered]@{ Mailboxes = @($mailboxes); Plans = @($plans) }
            $expectedHash = Get-ClientAccessFixtureHash -InputObject $expectedRaw
            $readers = New-ClientAccessReaders -Mailboxes $mailboxes -Plans $plans

            # Act
            $result = Invoke-ClientAccessEvidenceFixture -MailboxReader $readers.MailboxReader -PlanReader $readers.PlanReader

            # Assert
            $result.Collected | Should -BeTrue
            $result.FailureReason | Should -BeNullOrEmpty
            $result.Source | Should -BeExactly 'InjectedExchangeMailboxAndPlanReaders'
            @($result.Value.Mailboxes).Count | Should -Be 4
            @($result.Value.MailboxPlans).Count | Should -Be 2
            @($result.Value.Mailboxes.RecipientTypeDetails) | Should -Be @('EquipmentMailbox', 'RoomMailbox', 'SharedMailbox', 'UserMailbox')
            @($result.Value.Mailboxes.MailboxPlan) | Should -Be @('TenantDiscovered-Plan-B', 'TenantDiscovered-Plan-A', 'TenantDiscovered-Plan-B', 'TenantDiscovered-Plan-A')
            @($result.Value.MailboxPlans.Identity) | Should -Be @('TenantDiscovered-Plan-A', 'TenantDiscovered-Plan-B')
            @($result.Value.Mailboxes[0].PSObject.Properties.Name) | Should -Contain 'MailboxPlan'
            @($result.Value.Mailboxes[0].PSObject.Properties.Name) | Should -Contain 'ActiveSyncEnabled'
            @($result.Value.Mailboxes[0].PSObject.Properties.Name) | Should -Contain 'MAPIEnabled'
            @($result.Value.Mailboxes[0].PSObject.Properties.Name) | Should -Contain 'OWAEnabled'
            @($result.Value.MailboxPlans[0].PSObject.Properties.Name) | Should -Contain 'ActiveSyncEnabled'
            @($result.Value.MailboxPlans[0].PSObject.Properties.Name) | Should -Contain 'MAPIEnabled'
            @($result.Value.MailboxPlans[0].PSObject.Properties.Name) | Should -Contain 'OWAEnabled'
            @($result.Value.Mailboxes | Where-Object Disposition -ne 'Included').Count | Should -Be 0
            $result.RawHash | Should -BeExactly $expectedHash
            $result.ActualClientBehavior | Should -BeExactly 'Unverified'
        }
    }
}
