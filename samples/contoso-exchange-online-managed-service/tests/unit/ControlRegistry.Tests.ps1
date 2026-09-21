#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph and ExchangeOnlineManagement are not installed and must never be imported.
    # The registry is a declaration, so nothing here reaches a service: every fixture is a literal.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-ControlDefinitionEntry {
        [CmdletBinding()]
        param(
            [string]$ControlId = 'EXO-002',
            [hashtable]$Override = @{},
            [string[]]$Remove = @()
        )

        $entry = [ordered]@{
            ControlId         = $ControlId
            Priority          = 'MUST'
            ApplicableProfile = @('Native', 'Gateway')
            Prerequisite      = @('EOP')
            Collector         = 'Get-SmtpAuthenticationEvidence'
            Evaluator         = 'Test-SmtpAuthenticationControl'
            EvidencePath      = 'exchangeOnline.transportConfig'
        }

        foreach ($name in $Override.Keys) { $entry[$name] = $Override[$name] }
        foreach ($name in $Remove) { $entry.Remove($name) }

        return , $entry
    }

    function Get-RegistryFold {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Registry
        )

        return (@(foreach ($entry in $Registry) {
                    '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f `
                        $entry.ControlId,
                    $entry.Priority,
                    (@($entry.ApplicableProfile) -join '+'),
                    (@($entry.Prerequisite) -join '+'),
                    $entry.Collector,
                    $entry.Evaluator,
                    $entry.EvidencePath
                }) -join [Environment]::NewLine)
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EVD-002-A control registry' {

    Context 'Negative: a registry is built from declared entries and nothing else' {

        It 'refuses a registry built from no definition' {
            # Arrange
            $noDefinition = $null

            # Act
            $result = { New-BaselineControlRegistry -Definition $noDefinition }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlDefinitionRequired*' -Because 'a registry built from nothing registers no control, and a run that evaluates no control reports a tenant with nothing wrong with it'
        }

        It 'refuses a registry built from an empty definition' {
            # Arrange
            $emptyDefinition = @()

            # Act
            $result = { New-BaselineControlRegistry -Definition $emptyDefinition }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlDefinitionRequired*' -Because 'an empty definition is the same silent pass as no definition at all'
        }

        It 'refuses an entry that is not a record' {
            # Arrange
            $notARecord = @('EXO-002')

            # Act
            $result = { New-BaselineControlRegistry -Definition $notARecord }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlDefinitionNotRecognized*' -Because 'a bare identifier names a control without saying how it is collected or decided, so it would register a control nobody can run'
        }

        It 'refuses an entry declaring a member the registry contract does not name' {
            # Arrange
            $undeclaredMember = New-ControlDefinitionEntry -Override @{ Severity = 'High' }

            # Act
            $result = { New-BaselineControlRegistry -Definition $undeclaredMember }

            # Assert
            $result | Should -Throw -ExpectedMessage 'UnknownControlRegistryMember*' -Because 'a member nothing reads is a setting an operator believes is in force, and the belief outlives the release that ignored it'
        }
    }

    Context 'Negative: every entry names its control and the priority it is gated at' {

        It 'refuses an entry with no control identifier' {
            # Arrange
            $noControlId = New-ControlDefinitionEntry -Remove 'ControlId'

            # Act
            $result = { New-BaselineControlRegistry -Definition $noControlId }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlIdRequired*' -Because 'an entry that names no control cannot be matched to a catalog row, so the control it was meant to register is simply never collected'
        }

        It 'refuses an entry whose control identifier is blank' {
            # Arrange
            $blankControlId = New-ControlDefinitionEntry -Override @{ ControlId = '  ' }

            # Act
            $result = { New-BaselineControlRegistry -Definition $blankControlId }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlIdRequired*' -Because 'whitespace names no control any more than nothing does'
        }

        It 'refuses an entry with no priority' {
            # Arrange
            $noPriority = New-ControlDefinitionEntry -Remove 'Priority'

            # Act
            $result = { New-BaselineControlRegistry -Definition $noPriority }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlPriorityRequired*' -Because 'go-live blocks on a failed MUST and accepts a documented SHOULD, so an entry with no priority leaves the gate unable to decide which it is'
        }

        It 'refuses an entry whose priority is outside the catalog vocabulary' {
            # Arrange
            $unknownPriority = New-ControlDefinitionEntry -Override @{ Priority = 'NICE' }

            # Act
            $result = { New-BaselineControlRegistry -Definition $unknownPriority }

            # Assert
            $result | Should -Throw -ExpectedMessage 'UnknownControlPriority*' -Because 'a priority the gate does not recognise is treated as neither blocking nor waivable, which quietly demotes a mandatory control'
        }
    }

    Context 'Negative: every entry names where it applies and what entitles it' {

        It 'refuses an entry with no applicable profile' {
            # Arrange
            $noProfile = New-ControlDefinitionEntry -Remove 'ApplicableProfile'

            # Act
            $result = { New-BaselineControlRegistry -Definition $noProfile }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlProfileRequired*' -Because 'a control that declares no profile is either skipped everywhere or enforced where it does not belong, and both read as a clean run'
        }

        It 'refuses an entry whose applicable profile is empty' {
            # Arrange
            $emptyProfile = New-ControlDefinitionEntry -Override @{ ApplicableProfile = @() }

            # Act
            $result = { New-BaselineControlRegistry -Definition $emptyProfile }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlProfileRequired*' -Because 'an empty profile list applies to no deployment, so the control is registered and never evaluated'
        }

        It 'refuses an entry whose profile is not a declared deployment profile' {
            # Arrange
            $unknownProfile = New-ControlDefinitionEntry -Override @{ ApplicableProfile = @('Native', 'Hybrid') }

            # Act
            $result = { New-BaselineControlRegistry -Definition $unknownProfile }

            # Assert
            $result | Should -Throw -ExpectedMessage 'UnknownControlProfile*' -Because 'a profile no run is ever executed under silently excludes the control from every run'
        }

        It 'refuses an entry with no prerequisite' {
            # Arrange
            $noPrerequisite = New-ControlDefinitionEntry -Remove 'Prerequisite'

            # Act
            $result = { New-BaselineControlRegistry -Definition $noPrerequisite }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlPrerequisiteRequired*' -Because 'an unentitled control must report NotEntitled rather than Fail, and an entry that names no prerequisite gives the licensing gate nothing to decide that on'
        }

        It 'refuses an entry whose prerequisite list is empty' {
            # Arrange
            $emptyPrerequisite = New-ControlDefinitionEntry -Override @{ Prerequisite = @() }

            # Act
            $result = { New-BaselineControlRegistry -Definition $emptyPrerequisite }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlPrerequisiteRequired*' -Because 'an empty prerequisite list claims the control needs no licence, which turns a licensing gap into a compliance failure against a tenant that was never entitled'
        }

        It 'refuses an entry whose prerequisite is not a declared licence tier' {
            # Arrange
            $unknownPrerequisite = New-ControlDefinitionEntry -Override @{ Prerequisite = @('MDO P9') }

            # Act
            $result = { New-BaselineControlRegistry -Definition $unknownPrerequisite }

            # Assert
            $result | Should -Throw -ExpectedMessage 'UnknownControlPrerequisite*' -Because 'a tier the licensing gate cannot resolve is a prerequisite it can never confirm, so the control is entitled or not by accident'
        }
    }

    Context 'Negative: every entry names how it is collected, decided and recorded' {

        It 'refuses an entry with no collector' {
            # Arrange
            $noCollector = New-ControlDefinitionEntry -Remove 'Collector'

            # Act
            $result = { New-BaselineControlRegistry -Definition $noCollector }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlCollectorRequired*' -Because 'a registered control with no collector is never observed, and a control that is never observed is reported as missing rather than as failing'
        }

        It 'refuses an entry whose collector is blank' {
            # Arrange
            $blankCollector = New-ControlDefinitionEntry -Override @{ Collector = ' ' }

            # Act
            $result = { New-BaselineControlRegistry -Definition $blankCollector }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlCollectorRequired*' -Because 'a blank collector names no command, so nothing can be resolved and run for the control'
        }

        It 'refuses an entry with no evaluator' {
            # Arrange
            $noEvaluator = New-ControlDefinitionEntry -Remove 'Evaluator'

            # Act
            $result = { New-BaselineControlRegistry -Definition $noEvaluator }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlEvaluatorRequired*' -Because 'evidence with nothing to decide it produces no result, and a control with no result cannot fail the gate'
        }

        It 'refuses an entry whose evaluator is blank' {
            # Arrange
            $blankEvaluator = New-ControlDefinitionEntry -Override @{ Evaluator = '   ' }

            # Act
            $result = { New-BaselineControlRegistry -Definition $blankEvaluator }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlEvaluatorRequired*' -Because 'a blank evaluator names no command, so the collected evidence is never turned into a verdict'
        }

        It 'refuses an entry with no evidence path' {
            # Arrange
            $noEvidencePath = New-ControlDefinitionEntry -Remove 'EvidencePath'

            # Act
            $result = { New-BaselineControlRegistry -Definition $noEvidencePath }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlEvidencePathRequired*' -Because 'evidence written to an unnamed place cannot be found by a reviewer, so the observation exists and proves nothing'
        }

        It 'refuses an entry whose evidence path is blank' {
            # Arrange
            $blankEvidencePath = New-ControlDefinitionEntry -Override @{ EvidencePath = '' }

            # Act
            $result = { New-BaselineControlRegistry -Definition $blankEvidencePath }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlEvidencePathRequired*' -Because 'a blank path is an unnamed place'
        }
    }

    Context 'Negative: one control is registered once and records to one place' {

        It 'refuses two entries naming one control' {
            # Arrange
            $duplicateControl = @(
                (New-ControlDefinitionEntry -ControlId 'EXO-002')
                (New-ControlDefinitionEntry -ControlId 'EXO-002' -Override @{ EvidencePath = 'exchangeOnline.organizationConfig' })
            )

            # Act
            $result = { New-BaselineControlRegistry -Definition $duplicateControl }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlDuplicated*' -Because 'one control decided twice can be decided two ways, and which verdict reaches the gate then depends on the order the registry happened to be written in'
        }

        It 'refuses two entries claiming one evidence path' {
            # Arrange
            $duplicatePath = @(
                (New-ControlDefinitionEntry -ControlId 'EXO-002')
                (New-ControlDefinitionEntry -ControlId 'EXO-005' -Override @{ Collector = 'Get-ExternalPostmasterEvidence'; Evaluator = 'Test-ExternalPostmasterControl' })
            )

            # Act
            $result = { New-BaselineControlRegistry -Definition $duplicatePath }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EvidencePathDuplicated*' -Because 'two controls writing to one slot means the second overwrites the first, and the control that lost its evidence still reports against whatever the survivor collected'
        }
    }

    Context 'Negative: the registry cannot be edited after it is built' {

        It 'returns a registry that rejects assignment' {
            # Arrange
            $registry = New-BaselineControlRegistry -Definition (New-ControlDefinitionEntry)

            # Act
            $act = { $registry[0] = 'replaced' }

            # Assert
            $act | Should -Throw -Because 'a registry an evaluator can rewrite while the run is in flight cannot prove which controls the run was actually scoped to'
        }

        It 'returns an entry that rejects assignment' {
            # Arrange
            $registry = New-BaselineControlRegistry -Definition (New-ControlDefinitionEntry)

            # Act
            $act = { $registry[0].Priority = 'SHOULD' }

            # Assert
            $act | Should -Throw -Because 'a MUST that can be demoted to a SHOULD in memory is a gate that can be opened without changing the catalog or the code'
        }

        It 'returns an entry that rejects a new member' {
            # Arrange
            $registry = New-BaselineControlRegistry -Definition (New-ControlDefinitionEntry)

            # Act
            $act = { $registry[0].Waived = $true }

            # Assert
            $act | Should -Throw -Because 'a member added at runtime is a setting no review ever saw, and the next reader cannot tell it from a declared one'
        }
    }

    Context 'Negative: building the registry reaches no service' {

        AfterEach {
            Remove-Item -Path 'function:global:Connect-ExchangeOnline', 'function:global:Get-TransportConfig', 'function:global:Connect-MgGraph', 'function:global:Get-MgSubscribedSku' -ErrorAction SilentlyContinue
        }

        It 'does not reach a live service command while building the registry' {
            # Arrange
            $script:RegistryCommandInvocation = [System.Collections.Generic.List[string]]::new()
            function global:Connect-ExchangeOnline { $script:RegistryCommandInvocation.Add('Connect-ExchangeOnline') }
            function global:Get-TransportConfig { $script:RegistryCommandInvocation.Add('Get-TransportConfig') }
            function global:Connect-MgGraph { $script:RegistryCommandInvocation.Add('Connect-MgGraph') }
            function global:Get-MgSubscribedSku { $script:RegistryCommandInvocation.Add('Get-MgSubscribedSku') }

            # Act
            $null = New-BaselineControlRegistry -Definition (New-ControlDefinitionEntry)

            # Assert
            $script:RegistryCommandInvocation | Should -BeNullOrEmpty -Because 'a declaration that connects to a tenant to describe itself cannot be read, reviewed, or diffed offline'
        }
    }

    Context 'Positive: the shipped registry holds one entry per catalog control' {

        It 'returns one entry per catalog control naming its priority, its profiles, its prerequisites, its collector, its evaluator and its evidence path' {
            # Arrange
            $expected = @(
                'EXO-001|MUST|Native+Gateway|EOP|Get-AcceptedDomainEvidence|Test-AcceptedDomainControl|exchangeOnline.acceptedDomain'
                'EXO-002|MUST|Native+Gateway|EOP|Get-SmtpAuthenticationEvidence|Test-SmtpAuthenticationControl|exchangeOnline.transportConfig'
                'EXO-003|MUST|Native+Gateway|EOP|Get-ConditionalAccessEvidence|Test-ConditionalAccessControl|graph.conditionalAccessPolicy'
                'EXO-004|MUST|Native+Gateway|EOP|Get-OutboundForwardingEvidence|Test-OutboundForwardingControl|exchangeOnline.outboundSpamFilterPolicy'
                'EXO-005|SHOULD|Native+Gateway|EOP|Get-ExternalPostmasterEvidence|Test-ExternalPostmasterControl|exchangeOnline.externalPostmaster'
                'EXO-006|MUST|Native+Gateway|EOP|Get-MailboxAuditingEvidence|Test-MailboxAuditingControl|exchangeOnline.mailboxAudit'
                'EXO-007|MUST|Native+Gateway|EOP|Get-ExternalSenderTagEvidence|Test-ExternalSenderTagControl|exchangeOnline.externalInOutlook'
                'EXO-008|MUST|Native+Gateway|EOP|Get-RemoteDomainEvidence|Test-RemoteDomainControl|exchangeOnline.remoteDomain'
                'EXO-009|MUST|Native+Gateway|EOP|Get-ClientProtocolEvidence|Test-ClientProtocolControl|exchangeOnline.clientProtocol'
                'EXO-010|MUST|Native+Gateway|EOP|Get-ExchangeRoleAssignmentEvidence|Test-ExchangeRoleAssignmentControl|exchangeOnline.roleAssignment'
                'EXO-011|SHOULD|Native+Gateway|EOP|Get-MtaStsEvidence|Test-MtaStsControl|dns.mtaSts'
                'EXO-012|SHOULD|Native+Gateway|EOP|Get-AddInAcquisitionEvidence|Test-AddInAcquisitionControl|exchangeOnline.roleAssignmentPolicy'
                'MDO-001|MUST|Native+Gateway|EOP|Get-StandardPresetEvidence|Test-StandardPresetControl|defender.standardPreset'
                'MDO-002|MUST|Native+Gateway|EOP|Get-StrictPresetEvidence|Test-StrictPresetControl|defender.strictPreset'
                'MDO-003|MUST|Native+Gateway|MDO P1|Get-BuiltInProtectionEvidence|Test-BuiltInProtectionControl|defender.builtInProtection'
                'MDO-004|MUST|Native+Gateway|MDO P1|Get-SafeAttachmentsEvidence|Test-SafeAttachmentsControl|defender.atpPolicyForO365'
                'MDO-005|SHOULD|Native+Gateway|MDO P2|Get-SafeDocumentsEvidence|Test-SafeDocumentsControl|defender.safeDocuments'
                'MDO-006|MUST|Native+Gateway|EOP|Get-ReportSubmissionEvidence|Test-ReportSubmissionControl|defender.reportSubmissionPolicy'
                'MDO-007|MUST|Native+Gateway|EOP|Get-TenantAllowBlockListEvidence|Test-TenantAllowBlockListControl|defender.tenantAllowBlockList'
                'MDO-008|MUST|Native+Gateway|EOP|Get-QuarantinePolicyEvidence|Test-QuarantinePolicyControl|defender.quarantinePolicy'
                'MDO-009|SHOULD|Native+Gateway|MDO P2|Get-PriorityAccountEvidence|Test-PriorityAccountControl|defender.priorityAccount'
                'PP-001|MUST|Gateway|EOP|Get-GatewayInboundConnectorEvidence|Test-GatewayInboundConnectorControl|exchangeOnline.inboundConnector'
                'PP-002|MUST|Gateway|EOP|Get-EnhancedFilteringEvidence|Test-EnhancedFilteringControl|exchangeOnline.enhancedFiltering'
                'PP-003|MUST|Gateway|EOP|Get-GatewayOutboundConnectorEvidence|Test-GatewayOutboundConnectorControl|exchangeOnline.outboundConnector'
                'PP-004|SHOULD|Gateway|EOP|Get-TrustedArcSealerEvidence|Test-TrustedArcSealerControl|exchangeOnline.arcConfig'
                'PP-005|MUST|Native|EOP|Get-PartnerInboundConnectorEvidence|Test-PartnerInboundConnectorControl|exchangeOnline.partnerInboundConnector'
                'AUTH-001|MUST|Native+Gateway|EOP|Get-DkimEvidence|Test-DkimControl|dns.dkim'
                'AUTH-002|MUST|Native+Gateway|EOP|Get-SpfEvidence|Test-SpfControl|dns.spf'
                'AUTH-003|MUST|Native+Gateway|EOP|Get-DmarcEvidence|Test-DmarcControl|dns.dmarc'
                'ABN-001|MUST|Gateway|EOP|Get-AbnormalIntegrationEvidence|Test-AbnormalIntegrationControl|graph.abnormalIntegration'
                'ABN-002|MUST|Gateway|EOP|Get-AbnormalPermissionEvidence|Test-AbnormalPermissionControl|graph.abnormalPermission'
                'MON-001|MUST|Native+Gateway|EOP|Get-TelemetrySourceEvidence|Test-TelemetrySourceControl|monitoring.telemetrySource'
                'MON-002|MUST|Native+Gateway|EOP|Get-UnifiedAuditEvidence|Test-UnifiedAuditControl|purview.unifiedAudit'
                'MON-003|MUST|Native+Gateway|EOP|Get-DriftEvidenceEvidence|Test-DriftEvidenceControl|monitoring.driftEvidence'
                'OPS-001|MUST|Native+Gateway|EOP|Get-ChangeSafetyEvidence|Test-ChangeSafetyControl|operations.changeSafety'
                'OPS-002|SHOULD|Native+Gateway|MDO P2|Get-IncidentExerciseEvidence|Test-IncidentExerciseControl|operations.incidentExercise'
                'GOV-001|MUST|Native+Gateway|E5 Compliance|Get-AuditRetentionEvidence|Test-AuditRetentionControl|purview.auditRetention'
                'GOV-002|MUST|Native+Gateway|E3|Get-DataLossPreventionEvidence|Test-DataLossPreventionControl|purview.dlpPolicy'
                'GOV-003|MUST|Native+Gateway|E3|Get-MailboxRetentionEvidence|Test-MailboxRetentionControl|purview.retentionPolicy'
                'GOV-004|MUST|Native+Gateway|E3|Get-LitigationHoldEvidence|Test-LitigationHoldControl|purview.litigationHold'
                'GOV-005|SHOULD|Native+Gateway|E3|Get-InformationRightsManagementEvidence|Test-InformationRightsManagementControl|purview.irmConfiguration'
                'GOV-006|SHOULD|Native+Gateway|E5 Compliance|Get-SensitivityLabelEvidence|Test-SensitivityLabelControl|purview.sensitivityLabel'
                'GOV-007|SHOULD|Native+Gateway|E5 Compliance|Get-EDiscoveryReadinessEvidence|Test-EDiscoveryReadinessControl|purview.eDiscoveryCase'
            ) -join [Environment]::NewLine

            # Act
            $registry = Get-BaselineControlRegistry -Profile Historical

            # Assert
            (Get-RegistryFold -Registry $registry) |
                Should -BeExactly $expected `
                    -Because 'a registry is only complete when every catalog control appears exactly once and each entry says how it is collected, how it is decided, what entitles it, where it applies and where its evidence lands'
        }
    }
}
