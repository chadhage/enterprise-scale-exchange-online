#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psd1'

    # Fail fast: these contract tests are meaningless unless the common module loads.
    if (-not (Test-Path -LiteralPath $script:CommonModulePath -PathType Leaf)) {
        throw "Common module manifest is required: $script:CommonModulePath"
    }
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-SyntheticClientAccessPolicy {
        [CmdletBinding()]
        param(
            [string[]]$Omit = @(),
            [hashtable]$Replace = @{}
        )

        # This is deliberately synthetic and non-authoritative. It is test input, not a checked-in
        # tenant policy/catalog and must never be interpreted as approval to change a tenant.
        $policy = [ordered]@{
            FixtureAuthority = 'SyntheticNonAuthoritative'
            ContractVersion  = '1.0'
            PolicyVersion    = '2026-09-29.1'
            SemanticAuthority = [ordered]@{
                AuthorityId = 'synthetic-authority-for-tests-only'
                Decision    = 'Approved'
            }
            Approval = [ordered]@{
                ApprovalId  = 'synthetic-approval-for-tests-only'
                ApprovedBy  = 'fixture-owner@example.invalid'
                ApprovedUtc = '2026-09-28T12:00:00Z'
                ExpiresUtc  = '2026-10-31T00:00:00Z'
            }
            EffectiveUtc = '2026-09-29T00:00:00Z'
            ContentHash  = 'SHA256:SYNTHETIC-CLIENT-ACCESS-POLICY-V1'
            Evidence = [ordered]@{
                EvidenceId = 'synthetic-evidence-for-tests-only'
                ContentHash = 'SHA256:SYNTHETIC-CLIENT-ACCESS-POLICY-V1'
            }
            ClassDisposition = @(
                [ordered]@{ RecipientTypeDetails = 'UserMailbox';      Disposition = 'Included' }
                [ordered]@{ RecipientTypeDetails = 'SharedMailbox';    Disposition = 'Included' }
                [ordered]@{ RecipientTypeDetails = 'RoomMailbox';      Disposition = 'Excluded' }
                [ordered]@{ RecipientTypeDetails = 'EquipmentMailbox'; Disposition = 'Excluded' }
            )
            PlanDisposition = @(
                [ordered]@{ MailboxPlan = 'Tenant-Frontline'; Disposition = 'Included' }
                [ordered]@{ MailboxPlan = 'Tenant-Enterprise'; Disposition = 'Included' }
            )
            DesiredFlags = [ordered]@{
                ActiveSyncEnabled  = $false
                MAPIEnabled        = $true
                OWAEnabled         = $false
            }
            ClientImpact = [ordered]@{
                OutlookOnTheWeb = [ordered]@{
                    Impact = 'Disabled'
                }
                NewOutlookForWindows = [ordered]@{
                    Impact = 'Disabled'
                }
                OtherClients = [ordered]@{
                    Inventory    = @('OutlookForWindowsMAPI')
                    ExplicitNone = $false
                    MAPIWhenTrue = 'Enabled'
                }
                OwnerAcceptance = [ordered]@{
                    Decision    = 'Accepted'
                    AcceptedBy  = 'fixture-owner@example.invalid'
                    AcceptedUtc = '2026-09-28T12:00:00Z'
                }
            }
        }

        foreach ($name in $Omit) {
            $policy.Remove($name)
        }
        foreach ($name in $Replace.Keys) {
            $policy[$name] = $Replace[$name]
        }

        return [pscustomobject]$policy
    }

    function New-DiscoveredMailbox {
        [CmdletBinding()]
        param(
            [string]$Identity = 'alex@example.invalid',
            [string]$RecipientTypeDetails = 'UserMailbox',
            [string]$MailboxPlan = 'Tenant-Enterprise',
            [bool]$ActiveSyncEnabled = $true,
            [bool]$MAPIEnabled = $false,
            [bool]$OWAEnabled = $true
        )

        return [pscustomobject][ordered]@{
            Identity              = $Identity
            RecipientTypeDetails  = $RecipientTypeDetails
            MailboxPlan           = $MailboxPlan
            ActiveSyncEnabled     = $ActiveSyncEnabled
            MAPIEnabled           = $MAPIEnabled
            OWAEnabled            = $OWAEnabled
        }
    }

    function New-DiscoveredPlan {
        return @(
            [pscustomobject][ordered]@{ Identity = 'Tenant-Enterprise'; Source = 'TenantDiscovery' }
            [pscustomobject][ordered]@{ Identity = 'Tenant-Frontline'; Source = 'TenantDiscovery' }
        )
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-007-A08-T01 approved client-access mailbox-flag planning' {
    Context 'Negative: every supported class has one explicit disposition' {
        It 'refuses duplicate class rules even when their dispositions agree' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $policy.ClassDisposition += [ordered]@{ RecipientTypeDetails = 'UserMailbox'; Disposition = 'Included' }

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox @(New-DiscoveredMailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessClassDispositionDuplicate*UserMailbox*'
        }

        It 'refuses unsupported GroupMailbox input even when a policy attempts to include it' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $policy.ClassDisposition += [ordered]@{ RecipientTypeDetails = 'GroupMailbox'; Disposition = 'Included' }
            $mailbox = @(New-DiscoveredMailbox -RecipientTypeDetails 'GroupMailbox')

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox $mailbox -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxClassUnsupported*GroupMailbox*'
        }
    }

    Context 'Negative: plans are exact tenant-discovered identities' {
        It 'refuses a hard-coded policy plan absent from tenant discovery' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $policy.PlanDisposition += [ordered]@{ MailboxPlan = 'Universal-Enterprise'; Disposition = 'Included' }

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox @(New-DiscoveredMailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxPlanNotDiscovered*Universal-Enterprise*'
        }

        It 'refuses a discovered plan without an exact policy mapping' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $policy.PlanDisposition = @($policy.PlanDisposition | Where-Object MailboxPlan -ne 'Tenant-Frontline')

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox @(New-DiscoveredMailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxPlanDispositionMissing*Tenant-Frontline*'
        }

        It 'refuses duplicate policy plan rules even when their dispositions agree' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $policy.PlanDisposition += [ordered]@{ MailboxPlan = 'Tenant-Enterprise'; Disposition = 'Included' }

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox @(New-DiscoveredMailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxPlanDispositionDuplicate*Tenant-Enterprise*'
        }

        It 'refuses duplicate discovered plan identities' {
            # Arrange
            $discoveredPlan = @(
                New-DiscoveredPlan
                [pscustomobject][ordered]@{ Identity = 'Tenant-Enterprise'; Source = 'TenantDiscovery' }
            )

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy (New-SyntheticClientAccessPolicy) -DiscoveredPlan $discoveredPlan -Mailbox @(New-DiscoveredMailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessDiscoveredMailboxPlanIdentityDuplicate*Tenant-Enterprise*'
        }
    }

    Context 'Negative: desired and observed flag tuples are Boolean and semantically exact' {
        It 'refuses non-Boolean <Tuple> <Flag>' -ForEach @(
            @{ Tuple = 'desired';  Flag = 'ActiveSyncEnabled'; Error = 'ClientAccessDesiredFlagNotBoolean' }
            @{ Tuple = 'desired';  Flag = 'MAPIEnabled';       Error = 'ClientAccessDesiredFlagNotBoolean' }
            @{ Tuple = 'desired';  Flag = 'OWAEnabled';        Error = 'ClientAccessDesiredFlagNotBoolean' }
            @{ Tuple = 'observed'; Flag = 'ActiveSyncEnabled'; Error = 'ClientAccessObservedFlagNotBoolean' }
            @{ Tuple = 'observed'; Flag = 'MAPIEnabled';       Error = 'ClientAccessObservedFlagNotBoolean' }
            @{ Tuple = 'observed'; Flag = 'OWAEnabled';        Error = 'ClientAccessObservedFlagNotBoolean' }
        ) {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $mailbox = New-DiscoveredMailbox
            if ($Tuple -eq 'desired') {
                $policy.DesiredFlags[$Flag] = 'false'
            }
            else {
                $mailbox.$Flag = 'false'
            }

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox @($mailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage "$Error*$Flag*"
        }

        It 'refuses a policy that treats MAPI true as disabled' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $policy.ClientImpact.OtherClients.MAPIWhenTrue = 'Disabled'

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox @(New-DiscoveredMailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMAPITrueMustMeanEnabled*'
        }
    }

    Context 'Negative: OWA disablement requires accepted client impact' {
        It 'refuses OWA disablement without Outlook on the web impact' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $policy.ClientImpact.Remove('OutlookOnTheWeb')

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox @(New-DiscoveredMailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessOutlookOnTheWebImpactRequired*'
        }

        It 'refuses OWA disablement without new Outlook for Windows impact' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $policy.ClientImpact.Remove('NewOutlookForWindows')

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox @(New-DiscoveredMailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessNewOutlookForWindowsImpactRequired*'
        }

        It 'refuses an invalid Outlook on the web impact value' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $policy.ClientImpact.OutlookOnTheWeb.Impact = 'Degraded'

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox @(New-DiscoveredMailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessOutlookOnTheWebImpactInvalid*Degraded*'
        }

        It 'refuses an invalid new Outlook for Windows impact value' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $policy.ClientImpact.NewOutlookForWindows.Impact = 'Degraded'

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox @(New-DiscoveredMailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessNewOutlookForWindowsImpactInvalid*Degraded*'
        }

        It 'refuses OWA disablement without other-client inventory or explicit none confirmation' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $policy.ClientImpact.OtherClients.Inventory = @()
            $policy.ClientImpact.OtherClients.ExplicitNone = $false

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox @(New-DiscoveredMailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessOtherClientInventoryOrNoneConfirmationRequired*'
        }

        It 'refuses explicit-none confirmation with a nonempty other-client inventory' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $policy.ClientImpact.OtherClients.ExplicitNone = $true

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox @(New-DiscoveredMailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessOtherClientExplicitNoneContradictsInventory*'
        }

        It 'refuses OWA disablement without owner acceptance' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $policy.ClientImpact.Remove('OwnerAcceptance')

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox @(New-DiscoveredMailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessOwnerAcceptanceRequired*'
        }

        It 'refuses an owner decision other than Accepted' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $policy.ClientImpact.OwnerAcceptance.Decision = 'Pending'

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox @(New-DiscoveredMailbox) -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessOwnerAcceptanceDecisionInvalid*Pending*'
        }
    }

    Context 'Negative: output rows must have a deterministic Changed or NoOp decision' {
        It 'refuses duplicate discovered mailbox identities that would make row decisions non-deterministic' {
            # Arrange
            $mailbox = @(
                New-DiscoveredMailbox -Identity 'duplicate@example.invalid' -MAPIEnabled $false
                New-DiscoveredMailbox -Identity 'duplicate@example.invalid' -MAPIEnabled $true
            )

            # Act
            $act = { New-ExchangeClientAccessMailboxFlagPlan -Policy (New-SyntheticClientAccessPolicy) -DiscoveredPlan (New-DiscoveredPlan) -Mailbox $mailbox -AsOfUtc '2026-09-29T12:00:00Z' }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ClientAccessMailboxIdentityDuplicate*duplicate@example.invalid*'
        }
    }

    Context 'Positive: exact class, plan, Boolean, impact and decision mapping' {
        It 'returns deterministic Changed and NoOp rows from the approved synthetic contract' {
            # Arrange
            $policy = New-SyntheticClientAccessPolicy
            $mailbox = @(
                New-DiscoveredMailbox -Identity 'alex@example.invalid' -RecipientTypeDetails 'UserMailbox' -MailboxPlan 'Tenant-Enterprise' -ActiveSyncEnabled $true -MAPIEnabled $false -OWAEnabled $true
                New-DiscoveredMailbox -Identity 'shared@example.invalid' -RecipientTypeDetails 'SharedMailbox' -MailboxPlan 'Tenant-Frontline' -ActiveSyncEnabled $false -MAPIEnabled $true -OWAEnabled $false
                New-DiscoveredMailbox -Identity 'room@example.invalid' -RecipientTypeDetails 'RoomMailbox' -MailboxPlan 'Tenant-Enterprise' -ActiveSyncEnabled $true -MAPIEnabled $true -OWAEnabled $true
                New-DiscoveredMailbox -Identity 'equipment@example.invalid' -RecipientTypeDetails 'EquipmentMailbox' -MailboxPlan 'Tenant-Frontline' -ActiveSyncEnabled $true -MAPIEnabled $true -OWAEnabled $true
            )
            $expected = @(
                'alex@example.invalid|UserMailbox|Tenant-Enterprise|Included|True,False,True|False,True,False|Changed|Unverified|Disabled|Disabled|Accepted'
                'shared@example.invalid|SharedMailbox|Tenant-Frontline|Included|False,True,False|False,True,False|NoOp|Unverified|Disabled|Disabled|Accepted'
                'room@example.invalid|RoomMailbox|Tenant-Enterprise|Excluded|True,True,True|False,True,False|NoOp|Unverified|Disabled|Disabled|Accepted'
                'equipment@example.invalid|EquipmentMailbox|Tenant-Frontline|Excluded|True,True,True|False,True,False|NoOp|Unverified|Disabled|Disabled|Accepted'
            )

            # Act
            $actual = @(New-ExchangeClientAccessMailboxFlagPlan -Policy $policy -DiscoveredPlan (New-DiscoveredPlan) -Mailbox $mailbox -AsOfUtc '2026-09-29T12:00:00Z' | ForEach-Object {
                    '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}|{9}|{10}' -f
                    $_.Identity,
                    $_.RecipientTypeDetails,
                    $_.MailboxPlan,
                    $_.Disposition,
                    (@($_.CurrentFlags.ActiveSyncEnabled, $_.CurrentFlags.MAPIEnabled, $_.CurrentFlags.OWAEnabled) -join ','),
                    (@($_.DesiredFlags.ActiveSyncEnabled, $_.DesiredFlags.MAPIEnabled, $_.DesiredFlags.OWAEnabled) -join ','),
                    $_.Decision,
                    $_.ActualClientBehavior,
                    $_.ClientImpact.OutlookOnTheWeb.Impact,
                    $_.ClientImpact.NewOutlookForWindows.Impact,
                    $_.ClientImpact.OwnerAcceptance.Decision
                })

            # Assert
            $actual | Should -BeExactly $expected
        }
    }
}
