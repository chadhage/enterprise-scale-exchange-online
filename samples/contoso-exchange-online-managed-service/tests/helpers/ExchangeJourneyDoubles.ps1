function Initialize-JourneyDoubles {
    param([hashtable]$InputData, [string]$Fault, [string]$Directory)
    . (Join-Path $script:sampleRoot 'tests/helpers/ApprovedAdapterDoubles.ps1')
    . (Join-Path $script:sampleRoot 'tests/helpers/ExchangeGovernanceRawFixture.ps1')
    Initialize-AdapterDoubles
    $global:journeyState = @{
        Fault = $Fault; Calls = [Collections.Generic.List[string]]::new(); Writes = [Collections.Generic.List[string]]::new()
        Forbidden = [Collections.Generic.List[string]]::new(); Functions = [Collections.Generic.List[string]]::new()
        Tenant = $InputData.TenantId; Operator = $InputData.Operator; InputData = $InputData
        Members = @(); Shared = $null; Group = $null; Collecting = $false; Collections = 0; PortalInitialized = $false
    }
    $global:journeyState.Functions.AddRange([string[]]$global:adapterCommands)
    $global:journeyState.Functions.Add('Get-ConnectionInformation')
    $working = Join-Path $Directory ([guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $working
    $InputData.ArtifactRoot = Join-Path $working 'change'
    $InputData.ParameterPath = Join-Path $working 'parameters.json'
    $InputData.AuthorityPath = Join-Path $working 'authority.json'
    $parameters = Get-Content (Join-Path $script:sampleRoot 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
    $parameters.MICROSOFT_ENTRA_TENANT_GUID = $InputData.TenantId
    $parameters.entitlement.tenantId = $InputData.TenantId
    $parameters.entitlement.verified = $true
    $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
    $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE','THREAT_INTELLIGENCE')
    $governance = New-ExchangeGovernanceRawFixture $parameters
    $pilot = $InputData.Mailboxes[0]
    $shared = $InputData.OperationsMailbox
    $governance.Raw['Get-Mailbox'].Items[0].Identity = $pilot
    $governance.Raw['Get-Mailbox'].Items[0].PrimarySmtpAddress = $pilot
    $governance.Configuration.controls['EXO-010'].mailboxPolicies = @(
        @{ mailbox = $pilot; policy = 'Default Role Assignment Policy' }
        @{ mailbox = $shared; policy = 'Default Role Assignment Policy' }
    )
    $governance.Configuration.controls['GOV-003'].mailboxEntitlement = @(
        @{ identity = $pilot; archive = $true }
        @{ identity = $shared; archive = $true }
    )
    $governance.Configuration.controls['GOV-004'].custodians = @($pilot)
    $governance.Configuration.controls['GOV-004'].holds[0].mailbox = $pilot
    $governance.Configuration.controls['GOV-005'].messageClasses[0].recipients = @($pilot)
    $governance.Raw['Get-TransportRule'].Items[0].SentTo = @($pilot)
    $governance.RecipientFlows[0].Recipient = $pilot
    $parameters.governanceEvidence = @{ recipientFlows = $governance.RecipientFlows }
    $InputData.ConfigurationPath = Join-Path $working 'governance-configuration.json'
    $governance.Configuration | ConvertTo-Json -Depth 60 | Set-Content $InputData.ConfigurationPath
    $parameters | ConvertTo-Json -Depth 40 | Set-Content $InputData.ParameterPath
    Microsoft.PowerShell.Core\Import-Module (Join-Path $script:sampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force -DisableNameChecking
    $global:journeyState.ModuleFunctions = & (Microsoft.PowerShell.Core\Get-Module ExchangeOnlineBaseline.Common) {
        $originalFunctions = @{}
        foreach ($name in 'Test-BaselineDetachedCmsSignature','New-BaselineEvidenceCertificateChain') {
            $originalFunctions[$name] = (Microsoft.PowerShell.Management\Get-Item "Function:\$name").ScriptBlock
        }
        $originalFunctions
    }
    $context = Get-BaselineExchangeContext -ParameterPath $InputData.ParameterPath -ConfigurationPath $InputData.ConfigurationPath
    $InputData.ConfigurationHash = $context.Hash
    $global:journeyState.Raw = $governance.Raw
    $managed = @('TransportConfig','OrganizationConfig','ExternalInOutlook','RemoteDomain','CASMailbox','CASMailboxPlan','HostedOutboundSpamFilterPolicy','AcceptedDomain','EOPProtectionPolicyRule','ATPProtectionPolicyRule')
    foreach ($noun in @($global:adapterState.Keys)) {
        if ($noun -notin $managed -and $global:journeyState.Raw.ContainsKey("Get-$noun")) {
            $global:adapterState[$noun] = @($global:journeyState.Raw["Get-$noun"].Items | ForEach-Object { $_.Clone() })
        }
    }
    $global:adapterState.OrganizationConfig[0].EwsAllowedAppIDs = @()
    $global:adapterState.OrganizationConfig[0].ElcProcessingDisabled = $false
    $global:adapterState.HostedOutboundSpamFilterPolicy[0].Name = 'Default'
    $global:adapterState.CASMailbox[0].Identity = $InputData.Mailboxes[0]
    $global:adapterState.CASMailbox[0].PrimarySmtpAddress = $InputData.Mailboxes[0]
    $global:adapterState.CASMailbox[0].SmtpClientAuthenticationDisabled = $null
    $global:adapterState.CASMailbox[0].EwsEnabled = $null
    $global:adapterState.CASMailbox[0].EwsApplicationAccessPolicy = $null
    $global:adapterState.CASMailbox[0].EwsAllowList = @()
    $global:adapterState.EOPProtectionPolicyRule = @()
    $global:adapterState.ATPProtectionPolicyRule = @()
    $key = [Security.Cryptography.RSA]::Create(2048)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=EXR008 offline only', $key, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$false,0,$true))
    $certificate = $request.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(1))
    $global:journeyState.Certificate = $certificate
    $global:journeyState.Key = $key
    $InputData.CertificateThumbprint = $certificate.Thumbprint
    @(@{ Identity = $InputData.ApprovalIdentity; Subject = $certificate.Subject; Thumbprint = $certificate.Thumbprint; Authority = 'ExchangeOnlineChangeApproval' }) | ConvertTo-Json -AsArray | Set-Content $InputData.AuthorityPath
    $generated = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o')
    $payloads = @{
        'MON-003' = @{ Complete = $true; Refused = @(); GeneratedAtUtc = $generated; ScheduledCollection = $true; CollectionFrequencyHours = 1; RetentionDays = 3650; DriftDetected = $false; Findings = @() }
        'OPS-001' = @{ Complete = $true; Refused = @(); ChangeId = 'CHG008'; GeneratedAtUtc = $generated }
        'OPS-002' = @{ ExerciseId = 'OFFLINE-008'; CompletedAtUtc = $generated; ExerciseTypes = @($context.Configuration.controls['OPS-002'].exerciseTypes); Owners = @($context.Configuration.controls['OPS-002'].owners); Actions = @(@{ ActionId = 'OFFLINE-A1'; Owner = $parameters.SECURITY_OPERATIONS_MAILBOX; Status = 'Closed'; TrackingReference = 'OFFLINE-008' }) }
    }
    foreach ($phase in @('Preview','Pilot','Approval','Rollback','PostChange')) { $payloads['OPS-001'][$phase] = @{ Completed = $true; ChangeId = 'CHG008' } }
    $rootPath = Join-Path $working 'test-public-root.cer'
    [IO.File]::WriteAllBytes($rootPath, $certificate.RawData)
    $parameters.operationalEvidence = @{}
    foreach ($controlId in $payloads.Keys) {
        $document = @{ ControlId = $controlId; TenantId = $InputData.TenantId; DeploymentProfile = 'ExchangeOnly'; ConfigurationHash = $context.Hash; ManifestHash = $context.Manifest.Hash; GeneratedAtUtc = $generated; Payload = $payloads[$controlId] }
        $content = [Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson -InputObject $document))
        $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($content), $true)
        $cms.ComputeSignature([Security.Cryptography.Pkcs.CmsSigner]::new($certificate))
        $document.Signature = @{ Model = 'DetachedCms'; Value = [Convert]::ToBase64String($cms.Encode()) }
        $artifactPath = Join-Path $working "$controlId.json"
        $document | ConvertTo-Json -Depth 50 | Set-Content $artifactPath
        $parameters.operationalEvidence[$controlId] = @{ path = $artifactPath; signerIdentity = $InputData.ApprovalIdentity; authorizedSigner = @(@{ Identity = $InputData.ApprovalIdentity; Subject = $certificate.Subject; Authority = 'ExchangeOnlineChangeApproval' }); trustedRoot = @{ path = $rootPath; sha256 = (Get-FileHash $rootPath).Hash } }
    }
    $parameters | ConvertTo-Json -Depth 60 | Set-Content $InputData.ParameterPath
    $InputData.Handoffs.Dns.CutoverApproved = $true
    $InputData.Validation = @(foreach ($kind in 'Inbound','Outbound','Internal','OWA','Outlook') {
        @{
            Kind = $kind; Passed = $true; Owner = 'Offline client owner'; Reference = "OFFLINE-$kind"
            TenantId = $InputData.TenantId; Mailbox = $InputData.Mailboxes[0]; ObservedUtc = $generated
            Sender = $(if ($kind -eq 'Inbound') { 'external@example.test' } else { $InputData.Mailboxes[0] })
            Recipient = $(if ($kind -eq 'Internal') { $InputData.OperationsMailbox } elseif ($kind -eq 'Inbound') { $InputData.Mailboxes[0] } else { 'external@example.test' })
            MessageId = "<OFFLINE-$kind@example.test>"; StartUtc = [datetimeoffset]::UtcNow.AddMinutes(-30).ToString('o'); EndUtc = $generated
        }
    })
    switch ($Fault) {
        MissingParameter { $InputData.ParameterPath = Join-Path $working 'absent.json' }
        UnverifiedEntitlement { $parameters.entitlement.verified = $false; $parameters | ConvertTo-Json -Depth 60 | Set-Content $InputData.ParameterPath }
        ParameterMismatch { $parameters.SECURITY_OPERATIONS_MAILBOX = 'other@contoso.example'; $parameters | ConvertTo-Json -Depth 60 | Set-Content $InputData.ParameterPath }
        ConfigurationMismatch { $InputData.ConfigurationHash = 'b' * 64 }
        DnsCutoverUnapproved { $InputData.Handoffs.Dns.CutoverApproved = $false }
        ValidationMissing { $InputData.Validation = @() }
        ClientFailed { $InputData.Validation[4].Passed = $false }
    }
    $signatures = @{
        'Get-Module' = '[string]$Name,[switch]$ListAvailable'
        'Import-Module' = '[Parameter(Position=0)]$Name,[switch]$Force,[switch]$DisableNameChecking,[version]$MinimumVersion'
        'Connect-ExchangeOnline' = '[Parameter(Mandatory)][string]$UserPrincipalName,[Parameter(Mandatory)][ValidateSet("O365Default")][string]$ExchangeEnvironmentName,[bool]$ShowBanner'
        'Get-ConnectionInformation' = ''
        'Get-Command' = '[Parameter(Position=0)][string]$Name'
        'Get-AcceptedDomain' = '[string]$Identity'
        'Get-RemoteDomain' = '[string]$Identity,[string]$ResultSize'
        'Set-AcceptedDomain' = '[Parameter(Mandatory)][string]$Identity,[Parameter(Mandatory)][ValidateSet("Authoritative")][string]$DomainType'
        'Get-Mailbox' = '[string]$Identity,[string]$ResultSize,[switch]$InactiveMailboxOnly,[switch]$SoftDeletedMailbox'
        'Get-MailboxStatistics' = '[string]$Identity,[switch]$IncludeSoftDeletedRecipients'
        'Export-MailboxDiagnosticLogs' = '[string]$Identity,[switch]$ExtendedProperties'
        'Get-ManagementRoleAssignment' = '[string]$Identity,[switch]$GetEffectiveUsers'
        'Get-TransportRule' = '[string]$Identity,[string]$ResultSize'
        'Get-InboxRule' = '[Parameter(Mandatory)][string]$Mailbox,[string]$Identity,[string]$ResultSize,[switch]$IncludeHidden'
        'Get-Recipient' = '[Parameter(Mandatory)][ValidateSet("Unlimited")][string]$ResultSize'
        'New-Mailbox' = '[Parameter(Mandatory)][switch]$Shared,[Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][string]$Alias,[Parameter(Mandatory)][string]$PrimarySmtpAddress'
        'Get-DistributionGroup' = '[string]$Identity,[string]$ResultSize'
        'New-DistributionGroup' = '[Parameter(Mandatory)][ValidateSet("Security")][string]$Type,[Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][string]$Alias,[Parameter(Mandatory)][string]$PrimarySmtpAddress,[Parameter(Mandatory)][string]$ManagedBy,[Parameter(Mandatory)][ValidateSet("Closed")][string]$MemberJoinRestriction,[Parameter(Mandatory)][ValidateSet("Closed")][string]$MemberDepartRestriction'
        'Get-DistributionGroupMember' = '[Parameter(Mandatory)][string]$Identity,[Parameter(Mandatory)][ValidateSet("Unlimited")][string]$ResultSize'
        'Add-DistributionGroupMember' = '[Parameter(Mandatory)][string]$Identity,[Parameter(Mandatory)][string]$Member,[Parameter(Mandatory)][switch]$BypassSecurityGroupManagerCheck'
        'Get-EOPProtectionPolicyRule' = '[string]$Identity'
        'Get-ATPProtectionPolicyRule' = '[string]$Identity'
        'Get-Item' = '[Parameter(Mandatory)][string]$LiteralPath'
        'Read-Host' = '[string]$Prompt'
        'Get-MessageTraceV2' = '[Parameter(Mandatory)][string]$MessageId,[Parameter(Mandatory)][string]$SenderAddress,[Parameter(Mandatory)][string]$RecipientAddress,[Parameter(Mandatory)][datetime]$StartDate,[Parameter(Mandatory)][datetime]$EndDate,[Parameter(Mandatory)][ValidateRange(1,5000)][int]$ResultSize'
    }
    foreach ($name in $global:journeyState.Raw.Keys) {
        if ($signatures.ContainsKey($name)) { continue }
        if ($name -in $global:adapterCommands) { continue }
        $signatures[$name] = switch ($name) {
            'Get-ExoSecOpsOverrideRule' { '[string]$Identity,[string]$Policy' }
            'Test-IRMConfiguration' { '[string]$Sender,[string]$Recipient' }
            'Get-MailboxAuditBypassAssociation' { '[string]$Identity,[string]$ResultSize' }
            'Get-RoleGroup' { '[string]$Identity,[string]$ResultSize' }
            'Get-RoleGroupMember' { '[string]$Identity,[string]$ResultSize' }
            default { '[string]$Identity' }
        }
    }
    $signatures['Get-OrganizationConfig'] = '[switch]$RetrieveEwsOperationAccessPolicy'
    $signatures['Get-QuarantinePolicy'] = '[string]$Identity,[string]$QuarantinePolicyType'
    $signatures['Get-TenantAllowBlockListItems'] = '[Parameter(Mandatory)][ValidateSet("Sender","Url","FileHash","IP")][string]$ListType,[switch]$Allow,[switch]$Block'
    foreach ($name in $signatures.Keys) {
        Set-Item "Function:global:$name" ([scriptblock]::Create("[CmdletBinding()]param($($signatures[$name])) Invoke-JourneyDouble '$name' `$PSBoundParameters"))
        $global:journeyState.Functions.Add($name)
    }
    foreach ($name in @('Connect-MgGraph','Invoke-MgGraphRequest','New-MgUser','Set-MgUserLicense','New-MgDomain','Confirm-MgDomain','Connect-IPPSSession','New-DlpCompliancePolicy','Set-DnsClientServerAddress','Add-DnsServerResourceRecord','New-EOPProtectionPolicyRule','New-ATPProtectionPolicyRule')) {
        Set-Item "Function:global:$name" ([scriptblock]::Create("`$global:journeyState.Forbidden.Add('$name'); throw 'Forbidden:$name'"))
        $global:journeyState.Functions.Add($name)
    }
}

function Clear-JourneyDoubles {
    if (Get-Variable journeyState -Scope Global -ErrorAction SilentlyContinue) {
        foreach ($name in @($global:journeyState.Functions)) { Remove-Item "Function:\$name" -ErrorAction SilentlyContinue }
        if ($global:journeyState.ModuleFunctions) {
            & (Microsoft.PowerShell.Core\Get-Module ExchangeOnlineBaseline.Common) {
                param($originalFunctions)
                foreach ($name in $originalFunctions.Keys) { Set-Item "Function:script:$name" $originalFunctions[$name] }
            } $global:journeyState.ModuleFunctions
        }
        if ($global:journeyState.Certificate) { $global:journeyState.Certificate.Dispose(); $global:journeyState.Key.Dispose() }
        Remove-Item Function:\Invoke-OfflineAdapterCommand -ErrorAction SilentlyContinue
        Get-Variable -Name 'adapter*' -Scope Global -ErrorAction SilentlyContinue | Remove-Variable -Scope Global
    }
    Remove-Variable journeyState -Scope Global -ErrorAction SilentlyContinue
}

function global:Invoke-JourneyDouble {
    param([string]$Name, [Collections.IDictionary]$Bound)
    $state = $global:journeyState
    $state.Calls.Add($Name)
    switch ($Name) {
        'Get-Module' {
            if ($Bound.Name -eq 'ExchangeOnlineManagement') {
                if ($state.Fault -eq 'ModuleMissing') { return }
                [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]$(if ($state.Fault -eq 'ModuleOld') { '3.0.0' } else { '3.7.0' }) }; return
            }
            Microsoft.PowerShell.Core\Get-Module @Bound; return
        }
        'Import-Module' {
            if ($Bound.Name -eq 'ExchangeOnlineManagement') { return }
            if ([string]$Bound.Name -notlike '*ExchangeOnlineBaseline.Common.ps*') { $state.Forbidden.Add('Import:' + $Bound.Name); throw 'Unexpected module' }
            Microsoft.PowerShell.Core\Import-Module @Bound
            & (Microsoft.PowerShell.Core\Get-Module ExchangeOnlineBaseline.Common) {
                function script:New-BaselineEvidenceCertificateChain {
                    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
                    $chain.ChainPolicy.TrustMode = [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
                    $null = $chain.ChainPolicy.CustomTrustStore.Add($global:journeyState.Certificate)
                    $chain
                }
                if ($global:journeyState.Collecting) { return }
                function script:Test-BaselineDetachedCmsSignature {
                    param([byte[]]$CanonicalBytes,$Signature,[scriptblock]$VerificationScript)
                    $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($CanonicalBytes),$true)
                    $cms.Decode([Convert]::FromBase64String($Signature.Value))
                    $cms.CheckSignature($true)
                    $signerCertificate = $cms.SignerInfos[0].Certificate
                    $chain = New-BaselineEvidenceCertificateChain
                    $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                    $chain.ChainPolicy.DisableCertificateDownloads = $true
                    try { if (-not $chain.Build($signerCertificate)) { throw 'OfflineTestChainUntrusted' } }
                    finally { $chain.Dispose() }
                    @{ Verified = $true; SignerSubject = $signerCertificate.Subject; SigningTimeUtc = [datetimeoffset]::UtcNow; CertificateNotBeforeUtc = $signerCertificate.NotBefore; CertificateNotAfterUtc = $signerCertificate.NotAfter; ChainTrusted = $true; RevocationStatus = 'Good' }
                }
            }
            return
        }
        'Get-Command' {
            if ($state.Fault -eq 'RoleMissing' -and $Bound.Name -eq 'New-Mailbox') { return }
            if ($state.Fault -eq 'RoleParameterMissing' -and $Bound.Name -eq 'New-Mailbox') {
                $command = Microsoft.PowerShell.Core\Get-Command @Bound
                $parameters = @{}
                foreach ($parameterName in $command.Parameters.Keys) {
                    if ($parameterName -ne 'Shared') { $parameters[$parameterName] = $command.Parameters[$parameterName] }
                }
                [pscustomobject]@{ Name = $command.Name; Parameters = $parameters }; return
            }
            Microsoft.PowerShell.Core\Get-Command @Bound; return
        }
        'Connect-ExchangeOnline' { if ($Bound.UserPrincipalName -ne $state.Operator) { throw 'Offline operator mismatch' }; return }
        'Get-ConnectionInformation' {
            $row = [pscustomobject]@{ TenantID = $(if ($state.Fault -eq 'WrongTenant') { 'other-tenant' } else { $state.Tenant }); State = 'Connected'; UserPrincipalName = $state.Operator }
            $row
            if ($state.Fault -eq 'MultipleSessions') { $row }
            return
        }
        'Get-AcceptedDomain' {
            if ($state.Fault -eq 'DomainReadDenied') { throw 'OfflineAccessDenied' }
            if ($state.Fault -eq 'DomainMissing') { return }
            [pscustomobject]$global:adapterState.AcceptedDomain[0].Clone()
            if ($state.Fault -eq 'DomainDuplicate') { [pscustomobject]$global:adapterState.AcceptedDomain[0].Clone() }
            return
        }
        'Set-AcceptedDomain' {
            $state.Writes.Add($Name)
            if ($state.Fault -ne 'DomainReadback') { $global:adapterState.AcceptedDomain[0].DomainType = $Bound.DomainType }
            return
        }
        'Get-Mailbox' {
            if ($Bound['InactiveMailboxOnly'] -or $Bound['SoftDeletedMailbox']) { return }
            if ($Bound['Identity'] -eq $state.InputData.OperationsMailbox) {
                if ($state.Shared) { [pscustomobject]$state.Shared.Clone() }; return
            }
            if (-not $Bound['Identity'] -and $state.Shared) { [pscustomobject]$state.Shared.Clone() }
            if ($state.Fault -eq 'MailboxMissing') { return }
            $pilot = $state.Raw['Get-Mailbox'].Items[0].Clone()
            $pilot.RecipientTypeDetails = $(if ($state.Fault -eq 'MailboxWrongType') { 'MailUser' } else { 'UserMailbox' })
            [pscustomobject]$pilot
            return
        }
        'Get-Recipient' {
            if ($state.Shared) { [pscustomobject]($state.Shared + @{ EmailAddresses = @('smtp:' + $state.Shared.PrimarySmtpAddress) }) }
            if ($state.Group) { [pscustomobject]($state.Group + @{ EmailAddresses = @('smtp:' + $state.Group.PrimarySmtpAddress) }) }
            if ($state.Fault -eq 'SharedCollision') { [pscustomobject]@{ PrimarySmtpAddress = $state.InputData.OperationsMailbox; RecipientTypeDetails = 'MailContact'; EmailAddresses = @() } }
            if ($state.Fault -eq 'GroupCollision') { [pscustomobject]@{ PrimarySmtpAddress = $state.InputData.PriorityGroup; RecipientTypeDetails = 'UserMailbox'; EmailAddresses = @() } }
            return
        }
        'New-Mailbox' {
            if ($state.Shared -or $Bound.PrimarySmtpAddress -ne $state.InputData.OperationsMailbox) { throw 'Offline unexpected mailbox create' }
            $state.Writes.Add($Name)
            $state.Shared = @{ Identity = $Bound.PrimarySmtpAddress; PrimarySmtpAddress = $Bound.PrimarySmtpAddress; RecipientTypeDetails = $(if ($state.Fault -eq 'SharedReadback') { 'UserMailbox' } else { 'SharedMailbox' }); ForwardingAddress = $null; ForwardingSmtpAddress = $null; RetentionPolicy = $state.Raw['Get-Mailbox'].Items[0].RetentionPolicy; LitigationHoldEnabled = $false }
            foreach ($property in @('RoleAssignmentPolicy','RetentionHoldEnabled','ElcProcessingDisabled','ArchiveStatus','RecoverableItemsQuota')) {
                $state.Shared[$property] = $state.Raw['Get-Mailbox'].Items[0][$property]
            }
            $state.Shared.ExchangeGuid = '00000000-0000-0000-0000-000000000008'
            $state.Shared.LitigationHoldDuration = 'Unlimited'
            $state.Shared.LitigationHoldOwner = ''
            $sharedProtocols = $global:adapterState.CASMailbox[0].Clone()
            $sharedProtocols.Identity = $Bound.PrimarySmtpAddress
            $sharedProtocols.PrimarySmtpAddress = $Bound.PrimarySmtpAddress
            $global:adapterState.CASMailbox += $sharedProtocols
            return
        }
        'New-DistributionGroup' {
            if (-not $state.Shared -or $state.Group -or $Bound.ManagedBy -ne $state.InputData.GroupOwner) { throw 'Offline group ordering/owner error' }
            $state.Writes.Add($Name)
            $state.Group = @{ Identity = $Bound.PrimarySmtpAddress; PrimarySmtpAddress = $Bound.PrimarySmtpAddress; RecipientTypeDetails = $(if ($state.Fault -eq 'GroupReadback') { 'MailUniversalDistributionGroup' } else { 'MailUniversalSecurityGroup' }) }
            return
        }
        'Get-DistributionGroup' { if ($state.Group) { [pscustomobject]$state.Group.Clone() }; return }
        'Get-DistributionGroupMember' {
            foreach ($member in $state.Members) { [pscustomobject]@{ PrimarySmtpAddress = $member } }
            if ($state.Fault -eq 'ExtraMember') { [pscustomobject]@{ PrimarySmtpAddress = 'surplus@contoso.example' } }
            return
        }
        'Add-DistributionGroupMember' {
            if (-not $state.Group -or $Bound.Member -notin $state.InputData.PriorityMembers -or $Bound.Member -in $state.Members) { throw 'Offline invalid membership' }
            $state.Writes.Add($Name)
            if ($state.Fault -ne 'MembershipReadback') { $state.Members += $Bound.Member }
            return
        }
        'Get-Item' {
            if ($Bound.LiteralPath -like 'Cert:*') {
                if ($Bound.LiteralPath -notlike "*$($state.Certificate.Thumbprint)") { throw 'Offline certificate not found' }
                $state.Certificate; return
            }
            Microsoft.PowerShell.Management\Get-Item @Bound; return
        }
        'Read-Host' { return 'Offline independent reviewer event' }
        'Get-MessageTraceV2' {
            if ($state.Fault -eq 'TraceMissing') { return }
            $record = @($state.InputData.Validation | Where-Object MessageId -EQ $Bound.MessageId)
            if ($record.Count -ne 1 -or $record[0].Sender -ne $Bound.SenderAddress -or $record[0].Recipient -ne $Bound.RecipientAddress) { throw 'Offline trace binding failed' }
            [pscustomobject]@{ MessageId = $record[0].MessageId; SenderAddress = $record[0].Sender; RecipientAddress = $record[0].Recipient; Status = 'Delivered' }; return
        }
    }
    $noun = $Name -replace '^Get-',''
    if ($noun -eq 'RemoteDomain') {
        foreach ($row in @($global:adapterState.RemoteDomain | Where-Object { -not $Bound['Identity'] -or $_.Identity -eq $Bound['Identity'] })) { [pscustomobject]$row.Clone() }
        return
    }
    if ($noun -in @('EOPProtectionPolicyRule','ATPProtectionPolicyRule')) {
        if ($state.Fault -eq 'PresetReadDenied') { throw 'OfflinePresetAccessDenied' }
        if ($state.Fault -eq 'PresetMissing') {
            if ($Bound['Identity']) { throw 'OfflinePresetIdentityNotFound' }
            return
        }
        foreach ($row in @($global:adapterState[$noun] | Where-Object { -not $Bound['Identity'] -or $_.Identity -eq $Bound['Identity'] })) { [pscustomobject]($row.Clone() + @{ Name = $row.Identity }) }
        return
    }
    if ($Name -eq 'Get-OrganizationConfig') {
        [pscustomobject]$global:adapterState.OrganizationConfig[0].Clone(); return
    }
    if ($state.Raw.ContainsKey($Name)) {
        if ($Name -eq 'Get-MailboxAuditBypassAssociation' -and $state.Collecting) { $state.Collections++ }
        $response = $state.Raw[$Name]
        $rows = $response.Items
        if ($Name -eq 'Get-ManagementRoleAssignment' -and $Bound['GetEffectiveUsers']) { $rows = $response.Effective }
        if ($response.ContainsKey('ByType') -and $Bound['QuarantinePolicyType']) { $rows = $response.ByType[$Bound['QuarantinePolicyType']] }
        foreach ($row in @($rows)) { [pscustomobject]$row.Clone() }
        return
    }
    throw "Offline unexpected command:$Name"
}

function Invoke-JourneyPortalInitialization {
    $state = $global:journeyState
    if (-not $state.Group -or $state.Members.Count -eq 0) { throw 'Offline portal ordering violation' }
    $state.Calls.Add('PortalPresetInitialization')
    if ($state.Fault -eq 'PresetMissing') { return }
    foreach ($noun in 'EOPProtectionPolicyRule','ATPProtectionPolicyRule') {
        $global:adapterState[$noun] = @(
            @{ Identity = 'Standard Preset Security Policy'; State = $(if ($state.Fault -eq 'PresetDisabled') { 'Disabled' } else { 'Enabled' }); SentTo = @(); RecipientDomainIs = @($state.InputData.Domain); ExceptIfSentToMemberOf = @(); ExceptIfSentTo = @() }
            @{ Identity = 'Strict Preset Security Policy'; State = 'Enabled'; SentToMemberOf = @($state.InputData.PriorityGroup); SentTo = @(); RecipientDomainIs = @() }
        )
    }
    $state.PortalInitialized = $true
}