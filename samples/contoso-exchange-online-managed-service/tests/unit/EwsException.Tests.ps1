BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $script:SampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force
    $script:Now = [datetimeoffset]'2026-09-20T12:00:00Z'
    function New-EwsDesired {
        @{
            ewsEnabled = $true
            ewsApplicationAccessPolicy = 'EnforceAllowList'
            ewsAllowList = @('ApprovedArchiver/1.0')
            ewsAllowedAppIds = @('11111111-2222-3333-4444-555555555555')
            ewsException = @{
                owner = 'Exchange service owner'; approval = 'CHG-003'
                expiresAt = '2026-12-01T00:00:00Z'; cloud = 'Worldwide'
                rollback = 'DisableEws'; clientImpact = 'Archive ingestion pauses on rollback'
            }
            popEnabledByDefault = $false; imapEnabledByDefault = $false
        }
    }
    function New-EwsPayload {
        @{
            OrganizationConfig = @{
                EwsEnabled = $true; EwsApplicationAccessPolicy = 'EnforceAllowList'
                EwsAllowList = @('ApprovedArchiver/1.0')
                EwsAllowedAppIDs = @('11111111-2222-3333-4444-555555555555')
            }
            CasMailboxPlan = @(@{ Identity = 'Plan'; PopEnabled = $false; ImapEnabled = $false })
            CasMailbox = @(@{
                Identity = 'archive@example.test'; EwsEnabled = $null
                EwsApplicationAccessPolicy = $null; EwsAllowList = @()
                PopEnabled = $false; ImapEnabled = $false
            })
        }
    }
    function New-EwsEvidence {
        param($Payload)
        Get-ClientProtocolEvidence -OrganizationConfigCollection { $Payload.OrganizationConfig }.GetNewClosure() `
            -CasMailboxPlanCollection { $Payload.CasMailboxPlan }.GetNewClosure() `
            -CasMailboxCollection { $Payload.CasMailbox }.GetNewClosure()
    }
}

Describe 'EXR-003 EWS exception admission' {
    It 'rejects invalid desired <Label>' -ForEach @(
        @{ Label = 'missing mode'; Key = 'ewsApplicationAccessPolicy'; Value = $null; Reason = 'EwsEnforcementRequired' }
        @{ Label = 'block list mode'; Key = 'ewsApplicationAccessPolicy'; Value = 'EnforceBlockList'; Reason = 'EwsEnforcementRequired' }
        @{ Label = 'empty user agents'; Key = 'ewsAllowList'; Value = @(); Reason = 'EwsAllowListInvalid' }
        @{ Label = 'wildcard all agents'; Key = 'ewsAllowList'; Value = @('*'); Reason = 'EwsAllowListInvalid' }
        @{ Label = 'blank agent'; Key = 'ewsAllowList'; Value = @(' '); Reason = 'EwsAllowListInvalid' }
        @{ Label = 'duplicate agents'; Key = 'ewsAllowList'; Value = @('Agent','Agent'); Reason = 'EwsAllowListInvalid' }
        @{ Label = 'missing application IDs'; Key = 'ewsAllowedAppIds'; Value = @(); Reason = 'EwsApplicationIdentityRequired' }
        @{ Label = 'user agent as app ID'; Key = 'ewsAllowedAppIds'; Value = @('ApprovedArchiver/*'); Reason = 'EwsApplicationIdentityRequired' }
        @{ Label = 'absent exception'; Key = 'ewsException'; Value = $null; Reason = 'EwsExceptionRequired' }
        @{ Label = 'string enabled'; Key = 'ewsEnabled'; Value = 'true'; Reason = 'EwsEnabledInvalid' }
    ) {
        # Arrange
        $desired = New-EwsDesired
        $desired[$Key] = $Value
        # Act
        $act = { Resolve-BaselineEwsPolicy -DesiredState $desired -Now $script:Now }
        # Assert
        $act | Should -Throw "*$Reason*"
    }

    It 'rejects exception <Label>' -ForEach @(
        @{ Label = 'missing owner'; Key = 'owner'; Value = ''; Reason = 'EwsExceptionOwnerRequired' }
        @{ Label = 'missing approval'; Key = 'approval'; Value = ''; Reason = 'EwsExceptionApprovalRequired' }
        @{ Label = 'missing impact'; Key = 'clientImpact'; Value = ''; Reason = 'EwsClientImpactRequired' }
        @{ Label = 'unsafe rollback'; Key = 'rollback'; Value = 'EnableAll'; Reason = 'EwsRollbackRequired' }
        @{ Label = 'expired'; Key = 'expiresAt'; Value = '2026-09-20T12:00:00Z'; Reason = 'EwsExceptionExpired' }
        @{ Label = 'malformed expiry'; Key = 'expiresAt'; Value = 'next year'; Reason = 'EwsExceptionExpiryInvalid' }
        @{ Label = 'timezone-free expiry'; Key = 'expiresAt'; Value = '2026-12-01T00:00:00'; Reason = 'EwsExceptionExpiryInvalid' }
        @{ Label = 'unbounded after retirement'; Key = 'expiresAt'; Value = '2027-04-02T00:00:00Z'; Reason = 'EwsRetirementUnsupported' }
        @{ Label = 'unverified sovereign cloud'; Key = 'cloud'; Value = 'GCC'; Reason = 'EwsRetirementUnsupported' }
    ) {
        # Arrange
        $desired = New-EwsDesired
        $desired.ewsException[$Key] = $Value
        # Act
        $act = { Resolve-BaselineEwsPolicy -DesiredState $desired -Now $script:Now }
        # Assert
        $act | Should -Throw "*$Reason*"
    }

    It 'rejects an enabled exception at final shutdown even with a future approval' {
        # Arrange
        $desired = New-EwsDesired
        $desired.ewsException.expiresAt = '2027-05-01T00:00:00Z'
        # Act
        $act = { Resolve-BaselineEwsPolicy -DesiredState $desired -Now ([datetimeoffset]'2027-04-01T00:00:00Z') }
        # Assert
        $act | Should -Throw '*EwsRetirementUnsupported*'
    }
    It 'admits one owned bounded exception with separate user-agent and application-ID controls' {
        # Arrange
        $desired = New-EwsDesired
        # Act
        $policy = Resolve-BaselineEwsPolicy -DesiredState $desired -Now $script:Now
        # Assert
        $policy.EwsEnabled | Should -BeTrue
        $policy.EwsApplicationAccessPolicy | Should -BeExactly EnforceAllowList
        $policy.EwsAllowList | Should -BeExactly 'ApprovedArchiver/1.0'
        $policy.EwsAllowedAppIDs | Should -BeExactly '11111111-2222-3333-4444-555555555555'
    }
}

Describe 'EXR-003 effective EWS exception readback' {
    It 'refuses an empty mailbox enumeration for an enabled application exception' {
        # Arrange
        $desired = New-EwsDesired
        $payload = New-EwsPayload
        $payload.CasMailbox = @()
        # Act
        $result = Test-BaselineEwsState -DesiredState $desired -ObservedState $payload -Now $script:Now
        # Assert
        $result.Reason | Should -BeLike 'EwsEvidenceIncomplete:*'
    }
    It 'fails unsafe observed <Label>' -ForEach @(
        @{ Label = 'missing organization enforcement'; Scope = 'OrganizationConfig'; Key = 'EwsApplicationAccessPolicy'; Value = $null; Reason = 'EwsEnforcementMismatch' }
        @{ Label = 'surplus user agent'; Scope = 'OrganizationConfig'; Key = 'EwsAllowList'; Value = @('ApprovedArchiver/1.0','Other/*'); Reason = 'EwsAllowListMismatch' }
        @{ Label = 'missing user agent'; Scope = 'OrganizationConfig'; Key = 'EwsAllowList'; Value = @(); Reason = 'EwsAllowListMismatch' }
        @{ Label = 'surplus identity'; Scope = 'OrganizationConfig'; Key = 'EwsAllowedAppIDs'; Value = @('11111111-2222-3333-4444-555555555555','aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'); Reason = 'EwsApplicationIdentityMismatch' }
        @{ Label = 'retirement disabled organization'; Scope = 'OrganizationConfig'; Key = 'EwsEnabled'; Value = $false; Reason = 'EwsEnabledMismatch' }
        @{ Label = 'mailbox block policy'; Scope = 'CasMailbox'; Key = 'EwsApplicationAccessPolicy'; Value = 'EnforceBlockList'; Reason = 'EwsMailboxOverrideConflict' }
        @{ Label = 'mailbox surplus agent'; Scope = 'CasMailbox'; Key = 'EwsAllowList'; Value = @('Other/*'); Reason = 'EwsMailboxOverrideConflict' }
        @{ Label = 'malformed mailbox switch'; Scope = 'CasMailbox'; Key = 'EwsEnabled'; Value = 'true'; Reason = 'EwsEvidenceIncomplete' }
        @{ Label = 'blank mailbox identity'; Scope = 'CasMailbox'; Key = 'Identity'; Value = ''; Reason = 'EwsEvidenceIncomplete' }
    ) {
        # Arrange
        $desired = New-EwsDesired
        $payload = New-EwsPayload
        $node = if ($Scope -eq 'CasMailbox') { $payload.CasMailbox[0] } else { $payload.OrganizationConfig }
        $node[$Key] = $Value
        # Act
        $result = Test-BaselineEwsState -DesiredState $desired -ObservedState $payload -Now $script:Now
        # Assert
        $result.Reason | Should -BeLike "$Reason`:*"
        $result.Status | Should -BeIn @('Fail','Error')
    }

    It 'refuses missing raw mailbox <Member>' -ForEach @(
        @{ Member = 'EwsEnabled' }, @{ Member = 'EwsApplicationAccessPolicy' }, @{ Member = 'EwsAllowList' }
    ) {
        # Arrange
        $desired = New-EwsDesired
        $payload = New-EwsPayload
        $payload.CasMailbox[0].Remove($Member)
        # Act
        $result = Test-BaselineEwsState -DesiredState $desired -ObservedState $payload -Now $script:Now
        # Assert
        $result.Reason | Should -BeLike "EwsEvidenceIncomplete:*$Member*"
    }
    It 'verifies inherited, exact overridden and explicitly disabled mailboxes for one approved exception' {
        # Arrange
        $desired = New-EwsDesired
        $payload = New-EwsPayload
        $payload.CasMailbox += @{
            Identity = 'explicit@example.test'; EwsEnabled = $true
            EwsApplicationAccessPolicy = 'EnforceAllowList'; EwsAllowList = @('ApprovedArchiver/1.0')
            PopEnabled = $false; ImapEnabled = $false
        }
        $payload.CasMailbox += @{
            Identity = 'blocked@example.test'; EwsEnabled = $false
            EwsApplicationAccessPolicy = 'EnforceBlockList'; EwsAllowList = @('Inactive/*')
            PopEnabled = $false; ImapEnabled = $false
        }
        # Act
        $result = Test-BaselineEwsState -DesiredState $desired -ObservedState $payload -Now $script:Now
        # Assert
        $result.Status | Should -BeExactly Pass
        $result.Reason | Should -BeLike 'EwsApprovedException:*CHG-003*'
    }
}

Describe 'EXR-003 EWS control dispatch' {
    It 'does not downgrade an approved exception in the actual Exchange registry wrapper' {
        # Arrange
        $desired = New-EwsDesired
        $evidence = New-EwsEvidence (New-EwsPayload)
        InModuleScope ExchangeOnlineBaseline.Common -Parameters @{ Desired = $desired; Collected = $evidence } {
            param($Desired, $Collected)
            $configuration = Get-Content (Join-Path $ExecutionContext.SessionState.Module.ModuleBase '../config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
            foreach ($key in $Desired.Keys) { $configuration.controls['EXO-009'][$key] = $Desired[$key] }
            $context = @{ Configuration = $configuration; Parameters = @{ PRIMARY_SMTP_DOMAIN = 'example.test' }; Entitlement = @{ servicePlans = @('EXCHANGE_S_ENTERPRISE') } }
            $registry = Get-BaselineControlRegistry
            foreach ($entry in $registry) {
                if ($entry.ControlId -eq 'EXO-009') { continue }
                Mock $entry.Collector { throw 'UnrelatedCollectorBlocked' }
            }
            Mock Get-ClientProtocolEvidence { $Collected }
            # Act
            $execution = @(Invoke-BaselineExchangeRegistry -Context $context)
            # Assert
            $result = ($execution | Where-Object ControlId -EQ 'EXO-009').Result
            $result.Status | Should -BeExactly ApprovedException
            $result.Reason | Should -BeLike 'EwsApprovedException:*CHG-003*'
        }
    }
    It 'does not hide missing enforcement behind empty-list pipeline unrolling' {
        # Arrange
        $desired = [pscustomobject](New-EwsDesired)
        $desired.ewsAllowList = @()
        $desired.ewsApplicationAccessPolicy = $null
        $payload = New-EwsPayload
        $evidence = New-EwsEvidence $payload
        # Act
        $act = { Test-ClientProtocolControl -DesiredState $desired -Evidence $evidence -Now $script:Now }
        # Assert
        $act | Should -Throw '*EwsEnforcementRequired*'
    }
    It 'does not report an approved EWS deviation as disabled-default conformance' {
        # Arrange
        $desired = New-EwsDesired
        $evidence = New-EwsEvidence (New-EwsPayload)
        # Act
        $result = Test-ClientProtocolControl -DesiredState $desired -Evidence $evidence -Now $script:Now
        # Assert
        $result.Status | Should -Not -Be Pass
    }
    It 'rejects missing enforcement through the registered evaluator' {
        # Arrange
        $desired = New-EwsDesired
        $payload = New-EwsPayload
        $payload.OrganizationConfig.EwsApplicationAccessPolicy = $null
        $evidence = New-EwsEvidence $payload
        # Act
        $result = Test-ClientProtocolControl -DesiredState $desired -Evidence $evidence -Now $script:Now
        # Assert
        $result.Reason | Should -BeLike 'EwsEnforcementMismatch:*'
    }
    It 'verifies the exact approved EWS state with POP and IMAP disabled through the registry evaluator' {
        # Arrange
        $desired = New-EwsDesired
        $evidence = New-EwsEvidence (New-EwsPayload)
        # Act
        $result = Test-ClientProtocolControl -DesiredState $desired -Evidence $evidence -Now $script:Now
        # Assert
        $result.Status | Should -BeExactly ApprovedException
        $result.Reason | Should -BeLike 'EwsApprovedException:*'
    }
}

Describe 'EXR-003 EWS raw AppID retrieval' {
    It 'does not omit AppIDs from the scoped EXO-009 raw collector' {
        # Arrange
        $payload = New-EwsPayload
        InModuleScope ExchangeOnlineBaseline.Common -Parameters @{ Payload = $payload } {
            param($Payload)
            function Get-OrganizationConfig {
                [CmdletBinding()] param([switch]$RetrieveEwsOperationAccessPolicy)
                $observed = $Payload.OrganizationConfig.Clone()
                if (-not $RetrieveEwsOperationAccessPolicy) { $observed.Remove('EwsAllowedAppIDs') }
                $observed
            }
            function Get-CASMailboxPlan { [CmdletBinding()] param($ResultSize) $Payload.CasMailboxPlan }
            function Get-CASMailbox { [CmdletBinding()] param($ResultSize) $Payload.CasMailbox }
            $configuration = Get-Content (Join-Path $ExecutionContext.SessionState.Module.ModuleBase '../config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
            $context = @{ Configuration = $configuration; Parameters = @{ PRIMARY_SMTP_DOMAIN = 'example.test' }; Entitlement = @{ servicePlans = @('EXCHANGE_S_ENTERPRISE') } }
            $registry = Get-BaselineControlRegistry
            foreach ($entry in $registry) {
                if ($entry.ControlId -eq 'EXO-009') { continue }
                Mock $entry.Collector { throw 'UnrelatedCollectorBlocked' }
            }
            # Act
            $execution = @(Invoke-BaselineExchangeRegistry -Context $context)
            # Assert
            $raw = ($execution | Where-Object ControlId -EQ 'EXO-009').Evidence.Value.OrganizationConfig
            $raw['EwsAllowedAppIDs'] | Should -BeExactly '11111111-2222-3333-4444-555555555555'
        }
    }

    It 'does not omit AppIDs from the <Source> readback command' -ForEach @(
        @{ Source = 'historical collector' }, @{ Source = 'active runbook' }
    ) {
        # Arrange
        $text = if ($Source -eq 'historical collector') {
            Get-Content (Join-Path $script:SampleRoot 'scripts/Test-ExchangeOnlineBaseline.ps1') -Raw
        } else {
            $document = Get-Content (Join-Path $script:SampleRoot 'docs/RUNBOOKS.md') -Raw
            $section = ($document -split '### R-EXO-009 Legacy protocol restriction')[1] -split '### R-EXO-010' | Select-Object -First 1
            ([regex]::Matches($section, '(?s)```powershell\s*(.*?)```') | ForEach-Object { $_.Groups[1].Value }) -join "`n"
        }
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
        $read = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Get-OrganizationConfig' }, $true)
        $command = [scriptblock]::Create($read.Parent.Extent.Text)
        function Get-OrganizationConfig {
            [CmdletBinding()] param([switch]$RetrieveEwsOperationAccessPolicy)
            if ($RetrieveEwsOperationAccessPolicy) { [pscustomobject]@{ EwsAllowedAppIDs = '11111111-2222-3333-4444-555555555555' } }
            else { [pscustomobject]@{ EwsEnabled = $true } }
        }
        # Act
        $observed = & $command
        # Assert
        $observed.EwsAllowedAppIDs | Should -BeExactly '11111111-2222-3333-4444-555555555555'
    }
}

Describe 'EXR-003 EWS main deployment ordering' {
    BeforeAll {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SampleRoot 'scripts/Deploy-ExchangeOnlineBaseline.ps1'), [ref]$tokens, [ref]$errors)
        $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Set-OrganizationControls' }, $true)
        . ([scriptblock]::Create($definition.Extent.Text))
        $statements = @($ast.EndBlock.Statements)
        $start = @($statements | Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq '$context' })[0].Extent.StartOffset
        $end = @($statements | Where-Object { $_.Extent.Text -like 'Set-DomainAuthentication -Configuration*' })[0].Extent.EndOffset
        $script:EwsOrchestration = [scriptblock]::Create($ast.Extent.Text.Substring($start, $end - $start))
        $mutators = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -match '^(Set|New|Remove|Disable|Enable)-' }, $true) | ForEach-Object { $_.GetCommandName() } | Sort-Object -Unique)
        foreach ($mutator in $mutators) {
            if ($mutator -in @('Set-OrganizationControls','Set-StrictMode')) { continue }
            Set-Item -Path "Function:$mutator" -Value ([scriptblock]::Create("`$script:MutationTrace.Add('$mutator')"))
        }
        function Add-Outcome { }
        function Get-CASMailbox { [CmdletBinding()] param($ResultSize) if ($script:MailboxFault) { throw 'EwsMailboxCollectionDenied' }; $script:Mailboxes }
    }
    It 'refuses <Case> before any <Profile> mutator' -ForEach @(
        @{ Case = 'invalid enforcement'; Profile = 'Native'; Reason = 'EwsEnforcementRequired' }
        @{ Case = 'expired exception'; Profile = 'Native'; Reason = 'EwsExceptionExpired' }
        @{ Case = 'mailbox contradiction'; Profile = 'Native'; Reason = 'EwsMailboxOverrideConflict' }
        @{ Case = 'collection failure'; Profile = 'Native'; Reason = 'EwsMailboxCollectionDenied' }
        @{ Case = 'invalid enforcement'; Profile = 'ExchangeOnly'; Reason = 'EwsEnforcementRequired' }
        @{ Case = 'expired exception'; Profile = 'ExchangeOnly'; Reason = 'EwsExceptionExpired' }
        @{ Case = 'mailbox contradiction'; Profile = 'ExchangeOnly'; Reason = 'EwsMailboxOverrideConflict' }
        @{ Case = 'collection failure'; Profile = 'ExchangeOnly'; Reason = 'EwsMailboxCollectionDenied' }
        @{ Case = 'mailbox contradiction'; Profile = 'Gateway'; Reason = 'EwsMailboxOverrideConflict' }
    ) {
        # Arrange
        $configuration = Get-Content (Join-Path $script:SampleRoot 'config/exchange-online-secure-baseline.microsoft-native.json') -Raw | ConvertFrom-Json -AsHashtable
        $configuration.desiredState.exchangeOnline.protocolRestriction = New-EwsDesired
        $configuration.desiredState.exchangeOnline.protocolRestriction.ewsException.expiresAt = '2027-03-01T00:00:00Z'
        $script:Mailboxes = (New-EwsPayload).CasMailbox
        $script:MailboxFault = $Case -eq 'collection failure'
        switch ($Case) {
            'invalid enforcement' { $configuration.desiredState.exchangeOnline.protocolRestriction.ewsApplicationAccessPolicy = $null }
            'expired exception' { $configuration.desiredState.exchangeOnline.protocolRestriction.ewsException.expiresAt = '2020-01-01T00:00:00Z' }
            'mailbox contradiction' { $script:Mailboxes[0].EwsApplicationAccessPolicy = 'EnforceBlockList' }
        }
        $selectedProfile = $Profile
        $exchangeContext = @{
            DeploymentConfiguration = $configuration; DeploymentEntitlement = @{ Source = 'OfflineTest'; Capability = @(); NotEntitled = @() }
            GatewayDeclared = $Profile -eq 'Gateway'; Algorithm = 'SHA256'; Hash = 'offline'
        }
        $runtimeMutationPlan = @()
        $graphRequest = $null
        $Apply = $false
        $EnableDkim = $false
        $script:MutationTrace = [System.Collections.Generic.List[string]]::new()
        $failure = $null
        # Act
        try { & $script:EwsOrchestration } catch { $failure = $_ }
        # Assert
        $failure.Exception.Message | Should -BeLike "*$Reason*"
        @($script:MutationTrace) | Should -HaveCount 0 -Because 'EWS admission must precede every mutation helper and Exchange mutator'
    }
    It 'admits one supported exception before dispatching the native mutation helpers' {
        # Arrange
        $configuration = Get-Content (Join-Path $script:SampleRoot 'config/exchange-online-secure-baseline.microsoft-native.json') -Raw | ConvertFrom-Json -AsHashtable
        $configuration.desiredState.exchangeOnline.protocolRestriction = New-EwsDesired
        $configuration.desiredState.exchangeOnline.protocolRestriction.ewsException.expiresAt = '2027-03-01T00:00:00Z'
        $script:Mailboxes = (New-EwsPayload).CasMailbox
        $script:MailboxFault = $false
        $script:MutationTrace = [System.Collections.Generic.List[string]]::new()
        $selectedProfile = 'Native'
        $exchangeContext = @{
            DeploymentConfiguration = $configuration; DeploymentEntitlement = @{ Source = 'OfflineTest'; Capability = @(); NotEntitled = @() }
            GatewayDeclared = $false; Algorithm = 'SHA256'; Hash = 'offline'
        }
        $runtimeMutationPlan = @()
        $graphRequest = $null
        $Apply = $false
        $EnableDkim = $false
        Mock Get-CASMailbox {
            $script:MutationTrace.Add('EwsMailboxAdmission')
            $script:Mailboxes
        }
        Mock Set-OrganizationControls { $script:MutationTrace.Add('Set-OrganizationControls') }
        # Act
        & $script:EwsOrchestration
        # Assert
        @($script:MutationTrace) | Should -Be @('EwsMailboxAdmission','Set-PresetProtection','Set-OrganizationControls','Set-DomainAuthentication')
        Should -Invoke Get-CASMailbox -Times 1 -Exactly -ParameterFilter { $ResultSize -eq 'Unlimited' -and $ErrorAction -eq 'Stop' }
    }
}

Describe 'EXR-003 EWS deployment admission' {
    BeforeAll {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SampleRoot 'scripts/Deploy-ExchangeOnlineBaseline.ps1'), [ref]$tokens, [ref]$errors)
        $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Set-OrganizationControls' }, $true)
        . ([scriptblock]::Create($definition.Extent.Text))
        function Add-Outcome { }
        function Get-RemoteDomain { [pscustomobject]@{ Identity = 'Default'; DomainName = '*'; AllowedOOFType = 'None' } }
        function Get-CASMailbox { [CmdletBinding()] param($ResultSize) $script:Mailboxes }
        function Set-TransportConfig { $script:OtherWrites++ }
        function Set-HostedOutboundSpamFilterPolicy { }
        function Set-OrganizationConfig {
            param($AuditDisabled, $EwsEnabled, $EwsApplicationAccessPolicy, $EwsAllowList, $EwsAllowedAppIDs, $WhatIf)
            if ($PSBoundParameters.ContainsKey('EwsEnabled')) { $script:EwsWrites += $PSBoundParameters }
        }
        function Set-ExternalInOutlook { }
        function Set-RemoteDomain { }
        function Get-CASMailboxPlan { }
        function Set-QuarantinePolicy { }
    }
    BeforeEach {
        $script:Configuration = Get-Content (Join-Path $script:SampleRoot 'config/exchange-online-secure-baseline.microsoft-native.json') -Raw | ConvertFrom-Json -AsHashtable
        $script:Configuration.desiredState.exchangeOnline.protocolRestriction = New-EwsDesired
        $script:Configuration.desiredState.exchangeOnline.protocolRestriction.ewsException.expiresAt = '2027-03-01T00:00:00Z'
        $script:EwsWrites = @()
        $script:OtherWrites = 0
        $script:Mailboxes = (New-EwsPayload).CasMailbox
    }
    It 'refuses <Label> before organization writes' -ForEach @(
        @{ Label = 'missing mode'; Key = 'ewsApplicationAccessPolicy'; Value = $null; Reason = 'EwsEnforcementRequired' }
        @{ Label = 'unidentified applications'; Key = 'ewsAllowedAppIds'; Value = @(); Reason = 'EwsApplicationIdentityRequired' }
    ) {
        # Arrange
        $script:Configuration.desiredState.exchangeOnline.protocolRestriction[$Key] = $Value
        # Act
        $act = { Set-OrganizationControls -Configuration $script:Configuration -UseWhatIf $true -ExchangeOnly }
        # Assert
        $act | Should -Throw "*$Reason*"
        $script:OtherWrites | Should -Be 0
        $script:EwsWrites.Count | Should -Be 0
    }
    It 'refuses contradictory mailbox override before enabling EWS' {
        # Arrange
        $script:Mailboxes[0].EwsApplicationAccessPolicy = 'EnforceBlockList'
        # Act
        $act = { Set-OrganizationControls -Configuration $script:Configuration -UseWhatIf $true -ExchangeOnly }
        # Assert
        $act | Should -Throw '*EwsMailboxOverrideConflict*'
        $script:OtherWrites | Should -Be 0
        $script:EwsWrites.Count | Should -Be 0
    }
    It 'refuses collection failure before enabling EWS' {
        # Arrange
        Mock Get-CASMailbox { throw 'EWS mailbox collection denied' }
        # Act
        $act = { Set-OrganizationControls -Configuration $script:Configuration -UseWhatIf $true -ExchangeOnly }
        # Assert
        $act | Should -Throw '*EWS mailbox collection denied*'
        $script:OtherWrites | Should -Be 0
        $script:EwsWrites.Count | Should -Be 0
    }
    It 'passes the exact exception controls as one organization update after mailbox admission' {
        # Arrange
        Mock Get-CASMailbox { $script:Mailboxes }
        # Act
        Set-OrganizationControls -Configuration $script:Configuration -UseWhatIf $true -ExchangeOnly
        # Assert
        Should -Invoke Get-CASMailbox -Times 1 -Exactly -ParameterFilter { $ResultSize -eq 'Unlimited' }
        $script:EwsWrites.Count | Should -Be 1
        $script:EwsWrites[0].EwsEnabled | Should -BeTrue
        $script:EwsWrites[0].EwsApplicationAccessPolicy | Should -BeExactly EnforceAllowList
        $script:EwsWrites[0].EwsAllowList | Should -BeExactly 'ApprovedArchiver/1.0'
        $script:EwsWrites[0].EwsAllowedAppIDs | Should -BeExactly '11111111-2222-3333-4444-555555555555'
        $script:EwsWrites[0].WhatIf | Should -BeTrue
    }
}

Describe 'EXR-003 EWS documented disabled policy' {
    It 'does not ship a disabled command without an explicit empty enforced list' {
        # Arrange
        $text = Get-Content (Join-Path $script:SampleRoot 'docs/RUNBOOKS.md') -Raw
        $section = ($text -split '### R-EXO-009 Legacy protocol restriction')[1] -split '### R-EXO-010' | Select-Object -First 1
        $block = [regex]::Match($section, '(?s)```powershell\s*(.*?)```').Groups[1].Value
        $script:DocumentedEws = $null
        function Set-OrganizationConfig { param($EwsEnabled, $EwsApplicationAccessPolicy, $EwsAllowList) $script:DocumentedEws = $PSBoundParameters }
        # Act
        & ([scriptblock]::Create($block))
        # Assert
        $script:DocumentedEws.EwsApplicationAccessPolicy | Should -BeExactly EnforceAllowList
    }
    It 'executes the documented disable command as the shipped default and rollback target' {
        # Arrange
        $text = Get-Content (Join-Path $script:SampleRoot 'docs/RUNBOOKS.md') -Raw
        $section = ($text -split '### R-EXO-009 Legacy protocol restriction')[1] -split '### R-EXO-010' | Select-Object -First 1
        $block = [regex]::Match($section, '(?s)```powershell\s*(.*?)```').Groups[1].Value
        $script:DocumentedEws = $null
        function Set-OrganizationConfig { param($EwsEnabled, $EwsApplicationAccessPolicy, $EwsAllowList) $script:DocumentedEws = $PSBoundParameters }
        # Act
        & ([scriptblock]::Create($block))
        # Assert
        $script:DocumentedEws.EwsEnabled | Should -BeFalse
        $script:DocumentedEws.EwsApplicationAccessPolicy | Should -BeExactly EnforceAllowList
        @($script:DocumentedEws.EwsAllowList).Count | Should -Be 0
    }
}

Describe 'EXR-003 EWS historical public readback' {
    BeforeAll {
        $commandText = Get-Content (Join-Path $script:SampleRoot 'scripts/Test-ExchangeOnlineBaseline.ps1') -Raw
        $start = $commandText.IndexOf("Add-Result 'EXO-009 legacyProtocolsRestricted'")
        if ($start -lt 0) { $start = $commandText.IndexOf('$clientProtocolEvidence =') }
        $end = $commandText.IndexOf('$rbacPimFallback =', $start)
        $script:EwsReadback = [scriptblock]::Create('param($configuration, $evidence)' + [Environment]::NewLine + $commandText.Substring($start, $end - $start))
        function Add-Result { param($Name, $Passed) [pscustomobject]@{ Status = $(if ($Passed) { 'Pass' } else { 'Fail' }); Reason = '' } }
        function Add-Check { param($Name, $Status, $Reason) [pscustomobject]@{ Status = $Status; Reason = $Reason } }
    }
    It 'reports the named enforcement failure instead of a switch-only result' {
        # Arrange
        $desired = New-EwsDesired
        $payload = New-EwsPayload
        $payload.OrganizationConfig.EwsApplicationAccessPolicy = $null
        $configuration = @{ desiredState = @{ exchangeOnline = @{ protocolRestriction = $desired } } }
        $evidence = @{ organization = $payload.OrganizationConfig; casMailboxPlans = $payload.CasMailboxPlan; casMailboxes = $payload.CasMailbox }
        # Act
        $result = & $script:EwsReadback $configuration $evidence
        # Assert
        $result.Reason | Should -BeLike 'EwsEnforcementMismatch:*'
    }
    It 'reports one verified temporary exception through the historical command block' {
        # Arrange
        $desired = New-EwsDesired
        $payload = New-EwsPayload
        $configuration = @{ desiredState = @{ exchangeOnline = @{ protocolRestriction = $desired } } }
        $evidence = @{ organization = $payload.OrganizationConfig; casMailboxPlans = $payload.CasMailboxPlan; casMailboxes = $payload.CasMailbox }
        # Act
        $result = & $script:EwsReadback $configuration $evidence
        # Assert
        $result.Status | Should -BeExactly ApprovedException
        $result.Reason | Should -BeLike 'EwsApprovedException:*'
    }
}

Describe 'EXR-003 EWS disabled effective state' {
    It 'rejects an unknown organization switch: <Label>' -ForEach @(
        @{ Label = 'null'; Value = $null }, @{ Label = 'text'; Value = 'false' }
    ) {
        # Arrange
        $desired = @{ ewsEnabled = $false; ewsAllowList = @(); ewsApplicationAccessPolicy = 'EnforceAllowList' }
        $payload = @{ OrganizationConfig = @{ EwsEnabled = $Value } }
        # Act
        $result = Test-BaselineEwsState -DesiredState $desired -ObservedState $payload -Now $script:Now
        # Assert
        $result.Status | Should -BeExactly Error
        $result.Reason | Should -BeLike 'EwsEvidenceIncomplete:*'
    }
    It 'proves the shipped organization disable overrides an enabled mailbox and dormant lists' {
        # Arrange
        $desired = (Get-Content (Join-Path $script:SampleRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json).controls.'EXO-009'
        $payload = New-EwsPayload
        $payload.OrganizationConfig.EwsEnabled = $false
        $payload.CasMailbox[0].EwsEnabled = $true
        $evidence = New-EwsEvidence $payload
        # Act
        $result = Test-ClientProtocolControl -DesiredState $desired -Evidence $evidence -Now $script:Now
        # Assert
        $result.Status | Should -BeExactly Pass
        $result.Reason | Should -BeLike 'EwsDisabled:*'
    }
}

Describe 'EXR-003 EWS configuration schema' {
    It 'rejects an enabled configuration missing <Member>' -ForEach @(
        @{ Member = 'ewsApplicationAccessPolicy' }, @{ Member = 'ewsAllowedAppIds' }, @{ Member = 'ewsException' }
    ) {
        # Arrange
        $configuration = Get-Content (Join-Path $script:SampleRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
        $desired = New-EwsDesired
        $desired.Remove($Member)
        $configuration.controls['EXO-009'] = $desired
        # Act
        $valid = Test-Json -Json ($configuration | ConvertTo-Json -Depth 50) -SchemaFile (Join-Path $script:SampleRoot 'config/exchange-only.schema.v1.json') -ErrorAction SilentlyContinue
        # Assert
        $valid | Should -BeFalse
    }
    It 'rejects exception metadata missing <Member>' -ForEach @(
        @{ Member = 'owner' }, @{ Member = 'approval' }, @{ Member = 'expiresAt' },
        @{ Member = 'rollback' }, @{ Member = 'clientImpact' }, @{ Member = 'cloud' }
    ) {
        # Arrange
        $configuration = Get-Content (Join-Path $script:SampleRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
        $desired = New-EwsDesired
        $desired.ewsException.Remove($Member)
        $configuration.controls['EXO-009'] = $desired
        # Act
        $valid = Test-Json -Json ($configuration | ConvertTo-Json -Depth 50) -SchemaFile (Join-Path $script:SampleRoot 'config/exchange-only.schema.v1.json') -ErrorAction SilentlyContinue
        # Assert
        $valid | Should -BeFalse
    }
    It 'accepts one complete bounded EWS exception document' {
        # Arrange
        $configuration = Get-Content (Join-Path $script:SampleRoot 'config/exchange-only.v1.json') -Raw | ConvertFrom-Json -AsHashtable
        $configuration.controls['EXO-009'] = New-EwsDesired
        # Act
        $valid = Test-Json -Json ($configuration | ConvertTo-Json -Depth 50) -SchemaFile (Join-Path $script:SampleRoot 'config/exchange-only.schema.v1.json') -ErrorAction SilentlyContinue
        # Assert
        $valid | Should -BeTrue
    }
}