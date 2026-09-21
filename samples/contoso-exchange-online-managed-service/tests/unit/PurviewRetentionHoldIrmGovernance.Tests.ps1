#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:CommonModule = Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop -PassThru

    function Invoke-GovernanceModuleCommand {
        param(
            [Parameter(Mandatory)][string]$Name,
            [Parameter(Mandatory)][hashtable]$Argument
        )
        & $script:CommonModule {
            param($CommandName, $CommandArgument)
            & $CommandName @CommandArgument
        } $Name $Argument
    }

    function Get-MailboxRetentionEvidence {
        param([scriptblock]$MailboxCollection, [scriptblock]$RetentionPolicyCollection, [scriptblock]$DistributionCollection, [datetime]$CollectedAtUtc)
        Invoke-GovernanceModuleCommand -Name $MyInvocation.MyCommand.Name -Argument $PSBoundParameters
    }
    function Test-MailboxRetentionControl {
        param([object]$Evidence, [object]$DesiredState, [object]$EntitlementVerdict, [datetime]$AsOfUtc, [timespan]$MaximumEvidenceAge)
        Invoke-GovernanceModuleCommand -Name $MyInvocation.MyCommand.Name -Argument $PSBoundParameters
    }
    function Get-LitigationHoldEvidence {
        param([scriptblock]$MailboxCollection, [scriptblock]$PriorityIdentityCollection, [scriptblock]$CustodianCollection, [datetime]$CollectedAtUtc)
        Invoke-GovernanceModuleCommand -Name $MyInvocation.MyCommand.Name -Argument $PSBoundParameters
    }
    function Test-LitigationHoldControl {
        param([object]$Evidence, [object]$DesiredState, [object]$EntitlementVerdict, [datetime]$AsOfUtc, [timespan]$MaximumEvidenceAge)
        Invoke-GovernanceModuleCommand -Name $MyInvocation.MyCommand.Name -Argument $PSBoundParameters
    }
    function Get-InformationRightsManagementEvidence {
        param([scriptblock]$IrmConfigurationCollection, [scriptblock]$OmeFunctionalEvidenceCollection, [datetime]$CollectedAtUtc)
        Invoke-GovernanceModuleCommand -Name $MyInvocation.MyCommand.Name -Argument $PSBoundParameters
    }
    function Test-InformationRightsManagementControl {
        param([object]$Evidence, [object]$DesiredState, [object]$EntitlementVerdict, [datetime]$AsOfUtc, [timespan]$MaximumEvidenceAge)
        Invoke-GovernanceModuleCommand -Name $MyInvocation.MyCommand.Name -Argument $PSBoundParameters
    }

    $script:AsOfUtc = [datetime]::SpecifyKind([datetime]'2026-09-19T12:00:00', [System.DateTimeKind]::Utc)
    $script:MaximumAge = [timespan]::FromHours(24)
    $script:DesiredRetention = [pscustomobject]@{
        requiredServicePlan = 'EXCHANGE_S_ENTERPRISE'
        policyName = 'Regulatory Retention'
        requireCompleteMailboxCoverage = $true
        requireSuccessfulDistribution = $true
    }
    $script:DesiredHold = [pscustomobject]@{
        requiredServicePlan = 'EXCHANGE_S_ENTERPRISE'
        enabled = $true
        priorityIdentities = @('chief@contoso.example', 'cfo@contoso.example')
        custodians = @('custodian@contoso.example')
    }
    $script:DesiredIrm = [pscustomobject]@{
        requiredServicePlan = 'EXCHANGE_S_ENTERPRISE'
        internalLicensingEnabled = $true
        azureRmsLicensingEnabled = $true
        transportDecryptionSetting = 'Mandatory'
        journalReportDecryptionEnabled = $true
        licensingLocation = 'NorthAmerica'
        omeFunctionalTest = 'EncryptedMessageRoundTrip'
    }

    function New-GovernanceEntitlement {
        param([string]$Status = 'Pass')
        [pscustomobject]@{
            RequiredServicePlanName = 'EXCHANGE_S_ENTERPRISE'
            Status = $Status
            Reason = if ($Status -ceq 'Pass') { 'E3 entitlement resolved.' } else { 'E3 entitlement is absent.' }
        }
    }

    function New-GovernanceFixture {
        param(
            [switch]$IncompleteMailboxes,
            [switch]$MissingRetentionPolicy,
            [switch]$RetentionDistributionFailed,
            [switch]$RetentionDrift,
            [switch]$UnresolvedPriority,
            [switch]$MissingPriorityHold,
            [switch]$MissingCustodianHold,
            [switch]$PartialIrm,
            [switch]$IrmDrift,
            [switch]$OmeDrift,
            [switch]$Stale,
            [switch]$RetentionRefusal,
            [switch]$HoldRefusal,
            [switch]$IrmRefusal
        )

        $collectedAt = if ($Stale) { $script:AsOfUtc.AddDays(-2) } else { $script:AsOfUtc.AddMinutes(-5) }
        $mailboxes = @(
            [pscustomobject]@{ PrimarySmtpAddress = 'chief@contoso.example'; RetentionPolicy = if ($RetentionDrift) { 'Legacy' } else { 'Regulatory Retention' }; LitigationHoldEnabled = -not $MissingPriorityHold }
            [pscustomobject]@{ PrimarySmtpAddress = 'cfo@contoso.example'; RetentionPolicy = 'Regulatory Retention'; LitigationHoldEnabled = $true }
            [pscustomobject]@{ PrimarySmtpAddress = 'custodian@contoso.example'; RetentionPolicy = 'Regulatory Retention'; LitigationHoldEnabled = -not $MissingCustodianHold }
            [pscustomobject]@{ PrimarySmtpAddress = 'user@contoso.example'; RetentionPolicy = 'Regulatory Retention'; LitigationHoldEnabled = $false }
        )
        $mailboxPage = [pscustomobject]@{ Complete = -not $IncompleteMailboxes; Mailboxes = $mailboxes }
        $policy = if ($MissingRetentionPolicy) { @() } else { @([pscustomobject]@{ Name = 'Regulatory Retention' }) }
        $distribution = [pscustomobject]@{
            PolicyName = 'Regulatory Retention'
            Status = if ($RetentionDistributionFailed) { 'Pending' } else { 'Success' }
            CoveredMailboxes = @($mailboxes.PrimarySmtpAddress)
        }
        $priority = if ($UnresolvedPriority) {
            [pscustomobject]@{ Resolved = $false; Identities = @('chief@contoso.example'); Unresolved = @('priority-group') }
        }
        else {
            [pscustomobject]@{ Resolved = $true; Identities = @('chief@contoso.example', 'cfo@contoso.example'); Unresolved = @() }
        }
        $custodians = [pscustomobject]@{ Resolved = $true; Identities = @('custodian@contoso.example'); Unresolved = @() }
        $irm = if ($PartialIrm) {
            [pscustomobject]@{ InternalLicensingEnabled = $true }
        }
        else {
            [pscustomobject]@{
                InternalLicensingEnabled = -not $IrmDrift
                AzureRMSLicensingEnabled = $true
                TransportDecryptionSetting = 'Mandatory'
                JournalReportDecryptionEnabled = $true
                LicensingLocation = 'NorthAmerica'
            }
        }
        $ome = [pscustomobject]@{
            TestName = 'EncryptedMessageRoundTrip'
            Succeeded = -not $OmeDrift
            Protected = $true
            DecryptedByAuthorizedRecipient = $true
            RejectedUnauthorizedRecipient = $true
        }

        $retentionEvidence = if ($RetentionRefusal) {
            Get-MailboxRetentionEvidence -MailboxCollection { throw 'retention mailbox paging refused' } `
                -RetentionPolicyCollection { $policy }.GetNewClosure() -DistributionCollection { $distribution }.GetNewClosure() `
                -CollectedAtUtc $collectedAt
        }
        else {
            Get-MailboxRetentionEvidence -MailboxCollection { $mailboxPage }.GetNewClosure() `
                -RetentionPolicyCollection { $policy }.GetNewClosure() -DistributionCollection { $distribution }.GetNewClosure() `
                -CollectedAtUtc $collectedAt
        }
        $holdEvidence = if ($HoldRefusal) {
            Get-LitigationHoldEvidence -MailboxCollection { throw 'hold mailbox paging refused' } `
                -PriorityIdentityCollection { $priority }.GetNewClosure() -CustodianCollection { $custodians }.GetNewClosure() `
                -CollectedAtUtc $collectedAt
        }
        else {
            Get-LitigationHoldEvidence -MailboxCollection { $mailboxPage }.GetNewClosure() `
                -PriorityIdentityCollection { $priority }.GetNewClosure() -CustodianCollection { $custodians }.GetNewClosure() `
                -CollectedAtUtc $collectedAt
        }
        $irmEvidence = if ($IrmRefusal) {
            Get-InformationRightsManagementEvidence -IrmConfigurationCollection { throw 'IRM collection refused' } `
                -OmeFunctionalEvidenceCollection { $ome }.GetNewClosure() -CollectedAtUtc $collectedAt
        }
        else {
            Get-InformationRightsManagementEvidence -IrmConfigurationCollection { $irm }.GetNewClosure() `
                -OmeFunctionalEvidenceCollection { $ome }.GetNewClosure() -CollectedAtUtc $collectedAt
        }

        return [pscustomobject]@{
            Retention = $retentionEvidence
            Hold = $holdEvidence
            Irm = $irmEvidence
        }
    }

    function Invoke-GovernanceFixture {
        param(
            [Parameter(Mandatory)][object]$Fixture,
            [object]$Entitlement = (New-GovernanceEntitlement)
        )

        @(
            Test-MailboxRetentionControl -Evidence $Fixture.Retention -DesiredState $script:DesiredRetention `
                -EntitlementVerdict $Entitlement -AsOfUtc $script:AsOfUtc -MaximumEvidenceAge $script:MaximumAge
            Test-LitigationHoldControl -Evidence $Fixture.Hold -DesiredState $script:DesiredHold `
                -EntitlementVerdict $Entitlement -AsOfUtc $script:AsOfUtc -MaximumEvidenceAge $script:MaximumAge
            Test-InformationRightsManagementControl -Evidence $Fixture.Irm -DesiredState $script:DesiredIrm `
                -EntitlementVerdict $Entitlement -AsOfUtc $script:AsOfUtc -MaximumEvidenceAge $script:MaximumAge
        )
    }

    function Get-GovernanceFold {
        param([object[]]$Result)
        @($Result | ForEach-Object { '{0}:{1}:{2}' -f $_.ControlId, $_.Status, $_.Reason }) -join '|'
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GOV-003 through GOV-005 Purview retention, hold and IRM governance' {
    Context 'Negative: collection refusal is named and fail closed' {
        It 'reports retention collection refusal against GOV-003' {
            # Arrange
            $fixture = New-GovernanceFixture -RetentionRefusal

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            (Get-GovernanceFold $result) | Should -BeLike 'GOV-003:Error:EvidenceCollectionFailed:*retention mailbox paging refused*'
        }

        It 'reports hold collection refusal against GOV-004' {
            # Arrange
            $fixture = New-GovernanceFixture -HoldRefusal

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            (Get-GovernanceFold $result) | Should -BeLike '*GOV-004:Error:EvidenceCollectionFailed:*hold mailbox paging refused*'
        }

        It 'reports IRM collection refusal against GOV-005' {
            # Arrange
            $fixture = New-GovernanceFixture -IrmRefusal

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            (Get-GovernanceFold $result) | Should -BeLike '*GOV-005:Error:EvidenceCollectionFailed:*IRM collection refused*'
        }
    }

    Context 'Negative: mailbox retention requires complete coverage and successful distribution' {
        It 'refuses an incomplete mailbox population' {
            # Arrange
            $fixture = New-GovernanceFixture -IncompleteMailboxes

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            (Get-GovernanceFold $result) | Should -BeLike 'GOV-003:Error:MailboxRetentionEvidenceIncomplete:*'
        }

        It 'fails a missing declared retention policy' {
            # Arrange
            $fixture = New-GovernanceFixture -MissingRetentionPolicy

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            (Get-GovernanceFold $result) | Should -BeLike 'GOV-003:Fail:MailboxRetentionPolicyMissing:*Regulatory Retention*'
        }

        It 'fails retention distribution that has not succeeded' {
            # Arrange
            $fixture = New-GovernanceFixture -RetentionDistributionFailed

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            (Get-GovernanceFold $result) | Should -BeLike 'GOV-003:Fail:MailboxRetentionDistributionFailed:*Pending*'
        }

        It 'fails one mailbox drifting from the declared retention policy' {
            # Arrange
            $fixture = New-GovernanceFixture -RetentionDrift

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            (Get-GovernanceFold $result) | Should -BeLike 'GOV-003:Fail:MailboxRetentionDrift:*chief@contoso.example*Legacy*Regulatory Retention*'
        }
    }

    Context 'Negative: litigation hold covers every resolved priority identity and custodian' {
        It 'refuses an unresolved priority population' {
            # Arrange
            $fixture = New-GovernanceFixture -UnresolvedPriority

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            (Get-GovernanceFold $result) | Should -BeLike '*GOV-004:Error:LitigationHoldIdentityResolutionFailed:*priority-group*'
        }

        It 'fails a priority identity without litigation hold' {
            # Arrange
            $fixture = New-GovernanceFixture -MissingPriorityHold

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            (Get-GovernanceFold $result) | Should -BeLike '*GOV-004:Fail:LitigationHoldMissing:*chief@contoso.example*priority*'
        }

        It 'fails a named custodian without litigation hold' {
            # Arrange
            $fixture = New-GovernanceFixture -MissingCustodianHold

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            (Get-GovernanceFold $result) | Should -BeLike '*GOV-004:Fail:LitigationHoldMissing:*custodian@contoso.example*custodian*'
        }
    }

    Context 'Negative: IRM and OME require exact configuration and functional evidence' {
        It 'errors on partial IRM configuration evidence' {
            # Arrange
            $fixture = New-GovernanceFixture -PartialIrm

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            (Get-GovernanceFold $result) | Should -BeLike '*GOV-005:Error:InformationRightsManagementEvidenceIncomplete:*AzureRMSLicensingEnabled*'
        }

        It 'fails exact IRM configuration drift' {
            # Arrange
            $fixture = New-GovernanceFixture -IrmDrift

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            (Get-GovernanceFold $result) | Should -BeLike '*GOV-005:Fail:InformationRightsManagementDrift:*InternalLicensingEnabled*False*True*'
        }

        It 'fails an OME functional test that did not succeed' {
            # Arrange
            $fixture = New-GovernanceFixture -OmeDrift

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            (Get-GovernanceFold $result) | Should -BeLike '*GOV-005:Fail:OmeFunctionalEvidenceFailed:*EncryptedMessageRoundTrip*'
        }
    }

    Context 'Negative: entitlement and freshness are authoritative' {
        It 'returns only NotApplicable when E3 is not entitled' {
            # Arrange
            $fixture = New-GovernanceFixture
            $unentitled = New-GovernanceEntitlement -Status 'NotEntitled'

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture -Entitlement $unentitled

            # Assert
            @($result.Status) | Should -Be @('NotApplicable', 'NotApplicable', 'NotApplicable')
        }

        It 'errors each applicable control when its evidence is stale' {
            # Arrange
            $fixture = New-GovernanceFixture -Stale

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            @($result.Reason | Where-Object { $_ -like '*EvidenceStale*' }).Count | Should -Be 3
        }
    }

    Context 'Positive: one fully entitled complete governance fixture' {
        It 'passes retention, litigation hold and IRM with exact complete evidence' {
            # Arrange
            $fixture = New-GovernanceFixture

            # Act
            $result = Invoke-GovernanceFixture -Fixture $fixture

            # Assert
            @($result | ForEach-Object { '{0}:{1}:{2}' -f $_.ControlId, $_.Status, $_.GoLiveSuccess }) |
                Should -Be @('GOV-003:Pass:True', 'GOV-004:Pass:True', 'GOV-005:Pass:True')
        }
    }
}