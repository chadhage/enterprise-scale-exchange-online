#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ChangeId = 'CHG0012345'
    $script:Tenant = 'contoso.onmicrosoft.com'
    $script:Profile = 'ThirdPartyGateway'
    $script:ConfigurationHash = 'a3f1c0de5b7288119ce2a6d4f0b9e7a15d3c48b6720fe9134a8c5d6e7f809123'
    $script:GeneratedOn = [datetime]::new(2026, 9, 18, 7, 30, 0, [System.DateTimeKind]::Utc)
    $script:AsOf = [datetime]::new(2026, 9, 18, 9, 0, 0, [System.DateTimeKind]::Utc)
    $script:RequestedBy = 'operator@contoso.com'
    $script:Approver = 'approver@contoso.com'
    $script:Authority = 'ExchangeOnlineChangeApproval'

    function Write-Text {
        param([string]$Path, [string]$Text)

        $directory = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        [System.IO.File]::WriteAllBytes($Path, [System.Text.UTF8Encoding]::new($false).GetBytes($Text))
    }

    # One change on disk: a preview, and an approval whose hash is taken over the preview bytes
    # exactly as they were written. Every negative is this change with one thing changed.
    function New-ApprovedChange {
        param(
            [hashtable]$PreviewOverride = @{},
            [hashtable]$ApprovalOverride = @{},
            [string]$PreviewText,
            [string]$ApprovalText,
            [switch]$NoPreviewFile,
            [switch]$NoApprovalFile,
            [switch]$TamperPreview
        )

        $root = Join-Path ([System.IO.Path]::GetTempPath()) ('change-approval-' + [guid]::NewGuid().ToString('N'))
        $set = New-BaselineChangeArtifactSet -ChangeId $script:ChangeId -Root $root
        $previewPath = [string](@($set) | Where-Object { [string]$_['Artifact'] -eq 'Preview' })['Path']
        $approvalPath = [string](@($set) | Where-Object { [string]$_['Artifact'] -eq 'Approval' })['Path']

        $preview = [ordered]@{
            SchemaVersion          = '1.0.0'
            ChangeId               = $script:ChangeId
            Tenant                 = $script:Tenant
            DeploymentProfile      = $script:Profile
            ConfigurationAlgorithm = 'SHA256'
            ConfigurationHash      = $script:ConfigurationHash
            Operation              = @(
                [ordered]@{ Sequence = 1; OperationId = 'op-1'; Command = 'Set-TransportConfig'; Identity = 'Default'; Before = [ordered]@{ Exists = $true; Value = 'False' }; After = [ordered]@{ Exists = $true; Value = 'True' }; DependsOn = @() }
            )
            GeneratedOn            = $script:GeneratedOn.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
            ExpiresOn              = $script:GeneratedOn.AddHours(24).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
            ToolVersion            = '1.0.0'
        }
        foreach ($name in $PreviewOverride.Keys) { $preview[$name] = $PreviewOverride[$name] }

        $previewBody = if ($PSBoundParameters.ContainsKey('PreviewText')) { $PreviewText } else { ConvertTo-CanonicalJson -InputObject $preview }
        if (-not $NoPreviewFile) { Write-Text -Path $previewPath -Text $previewBody }

        $previewHash = [System.Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData([System.Text.UTF8Encoding]::new($false).GetBytes($previewBody))).ToLowerInvariant()

        $approval = [ordered]@{
            SchemaVersion     = '1.0.0'
            ChangeId          = $script:ChangeId
            Tenant            = $script:Tenant
            DeploymentProfile = $script:Profile
            PreviewHash       = $previewHash
            ApprovalIdentity  = $script:Approver
            ApprovalAuthority = $script:Authority
            ApprovalTimeUtc   = $script:GeneratedOn.AddMinutes(10).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
            Signature         = [ordered]@{ Model = 'DetachedCms'; Value = 'MIIBogYJKoZIhvcNAQcCoIIBkzCCAY8CAQ' }
        }
        foreach ($name in $ApprovalOverride.Keys) { $approval[$name] = $ApprovalOverride[$name] }

        $approvalBody = if ($PSBoundParameters.ContainsKey('ApprovalText')) { $ApprovalText } else { ConvertTo-CanonicalJson -InputObject $approval }
        if (-not $NoApprovalFile) { Write-Text -Path $approvalPath -Text $approvalBody }

        if ($TamperPreview) { Write-Text -Path $previewPath -Text ($previewBody + ' ') }

        return @{ PreviewPath = $previewPath; ApprovalPath = $approvalPath }
    }

    function Invoke-Gate {
        param([hashtable]$Change, [hashtable]$Override = @{})

        $argument = @{
            PreviewPath       = $Change.PreviewPath
            ApprovalPath      = $Change.ApprovalPath
            Tenant            = $script:Tenant
            DeploymentProfile = $script:Profile
            ConfigurationHash = $script:ConfigurationHash
            RequestedBy       = $script:RequestedBy
            AsOf              = $script:AsOf
        }
        foreach ($name in $Override.Keys) { $argument[$name] = $Override[$name] }

        return Test-BaselineChangeApproval @argument
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-003-A approved immutable preview gate' {

    Context 'Negative: the artifacts the decision is made from are not there' {

        It 'refuses a preview path that was never supplied' {
            # Arrange
            $change = New-ApprovedChange

            # Act
            $decision = Invoke-Gate -Change $change -Override @{ PreviewPath = '' }

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalPreviewPathNotSupplied*').Count |
                Should -BeExactly 'False|1' -Because 'an apply with no plan to point at is an apply from configuration alone'
        }

        It 'refuses an approval path that was never supplied' {
            # Arrange
            $change = New-ApprovedChange

            # Act
            $decision = Invoke-Gate -Change $change -Override @{ ApprovalPath = '   ' }

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalPathNotSupplied*').Count |
                Should -BeExactly 'False|1' -Because 'a plan nobody signed is a plan nobody approved'
        }

        It 'refuses a preview path that names no file' {
            # Arrange
            $change = New-ApprovedChange -NoPreviewFile

            # Act
            $decision = Invoke-Gate -Change $change

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalPreviewNotFound*').Count |
                Should -BeExactly 'False|1' -Because 'an approval quoting a preview that is not on disk cannot be checked against anything'
        }

        It 'refuses an approval path that names no file' {
            # Arrange
            $change = New-ApprovedChange -NoApprovalFile

            # Act
            $decision = Invoke-Gate -Change $change

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalNotFound*').Count |
                Should -BeExactly 'False|1' -Because 'a missing approval is a refusal, not an absence of opinion'
        }

        It 'refuses a preview that is not readable as a preview' {
            # Arrange
            $change = New-ApprovedChange -PreviewText 'this is not a preview'

            # Act
            $decision = Invoke-Gate -Change $change

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalPreviewNotReadable*').Count |
                Should -BeExactly 'False|1' -Because 'a file the gate cannot read is a plan the gate cannot hold the run to'
        }

        It 'refuses a preview that is JSON but carries no expiry' {
            # Arrange
            $incomplete = [ordered]@{ ChangeId = $script:ChangeId; Tenant = $script:Tenant; DeploymentProfile = $script:Profile; ConfigurationHash = $script:ConfigurationHash; Operation = @() }
            $change = New-ApprovedChange -PreviewText (ConvertTo-CanonicalJson -InputObject $incomplete)

            # Act
            $decision = Invoke-Gate -Change $change

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalPreviewNotReadable*').Count |
                Should -BeExactly 'False|1' -Because 'a preview with no expiry never stops being true'
        }

        It 'refuses an approval that is not readable as an approval' {
            # Arrange
            $change = New-ApprovedChange -ApprovalText '<approval/>'

            # Act
            $decision = Invoke-Gate -Change $change

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalNotReadable*').Count |
                Should -BeExactly 'False|1' -Because 'an approval the gate cannot read grants nothing'
        }
    }

    Context 'Negative: the approval is not an approval of this preview' {

        It 'refuses an approval whose preview hash is not the hash of the preview on disk' {
            # Arrange
            $change = New-ApprovedChange -TamperPreview

            # Act
            $decision = Invoke-Gate -Change $change

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalPreviewTampered*').Count |
                Should -BeExactly 'False|1' -Because 'a preview edited after it was signed is a plan nobody approved'
        }

        It 'refuses an approval raised for another change' {
            # Arrange
            $change = New-ApprovedChange -ApprovalOverride @{ ChangeId = 'CHG0099999' }

            # Act
            $decision = Invoke-Gate -Change $change

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalChangeMismatch*').Count |
                Should -BeExactly 'False|1' -Because 'an approval for one change reused for another authorises mutations nobody reviewed'
        }

        It 'refuses an approval raised for another tenant' {
            # Arrange
            $change = New-ApprovedChange -ApprovalOverride @{ Tenant = 'fabrikam.onmicrosoft.com' }

            # Act
            $decision = Invoke-Gate -Change $change

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalTenantMismatch*').Count |
                Should -BeExactly 'False|1' -Because 'an approval for one tenant applied to another is a change into a tenant nobody reviewed'
        }

        It 'refuses a preview built for a tenant other than the one the run is connected to' {
            # Arrange
            $change = New-ApprovedChange

            # Act
            $decision = Invoke-Gate -Change $change -Override @{ Tenant = 'fabrikam.onmicrosoft.com' }

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalTenantMismatch*').Count |
                Should -BeExactly 'False|1' -Because 'a plan reviewed against one tenant says nothing about the tenant this run is about to change'
        }

        It 'refuses an approval raised for another deployment profile' {
            # Arrange
            $change = New-ApprovedChange -ApprovalOverride @{ DeploymentProfile = 'MicrosoftNative' }

            # Act
            $decision = Invoke-Gate -Change $change

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalProfileMismatch*').Count |
                Should -BeExactly 'False|1' -Because 'a gateway plan approved as a Microsoft-native plan is a different change from the one reviewed'
        }

        It 'refuses a preview built for a deployment profile other than the one the run resolved' {
            # Arrange
            $change = New-ApprovedChange

            # Act
            $decision = Invoke-Gate -Change $change -Override @{ DeploymentProfile = 'MicrosoftNative' }

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalProfileMismatch*').Count |
                Should -BeExactly 'False|1' -Because 'a run that resolved another profile is applying a plan nobody built for it'
        }
    }

    Context 'Negative: the desired state moved after the plan was approved' {

        It 'refuses a preview whose configuration hash is not the hash this run resolved' {
            # Arrange
            $change = New-ApprovedChange

            # Act
            $decision = Invoke-Gate -Change $change -Override @{ ConfigurationHash = ('0' * 64) }

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalConfigurationMismatch*').Count |
                Should -BeExactly 'False|1' -Because 'a configuration edited after approval turns an approved plan into an unreviewed one'
        }
    }

    Context 'Negative: the approval is no longer or was never in force' {

        It 'refuses a preview that has expired at the decision instant' {
            # Arrange
            $change = New-ApprovedChange

            # Act
            $decision = Invoke-Gate -Change $change -Override @{ AsOf = $script:GeneratedOn.AddHours(25) }

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalPreviewExpired*').Count |
                Should -BeExactly 'False|1' -Because 'a plan reviewed against a tenant that has since moved on is a plan about a tenant that no longer exists'
        }

        It 'refuses a preview at the exact instant it expires' {
            # Arrange
            $change = New-ApprovedChange

            # Act
            $decision = Invoke-Gate -Change $change -Override @{ AsOf = $script:GeneratedOn.AddHours(24) }

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalPreviewExpired*').Count |
                Should -BeExactly 'False|1' -Because 'an expiry that is still valid at the instant it names is an expiry nobody can reason about'
        }

        It 'refuses an approval carrying no signature value' {
            # Arrange
            $change = New-ApprovedChange -ApprovalOverride @{ Signature = [ordered]@{ Model = 'DetachedCms'; Value = '' } }

            # Act
            $decision = Invoke-Gate -Change $change

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalUnsigned*').Count |
                Should -BeExactly 'False|1' -Because 'an unsigned approval binds these bytes to nobody'
        }

        It 'refuses an approval signed under a model the signature contract does not select' {
            # Arrange
            $change = New-ApprovedChange -ApprovalOverride @{ Signature = [ordered]@{ Model = 'EmailConfirmation'; Value = 'looks-fine-to-me' } }

            # Act
            $decision = Invoke-Gate -Change $change

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalSignatureModelNotApproved*').Count |
                Should -BeExactly 'False|1' -Because 'a signature model nobody selected is a signature nobody can verify'
        }

        It 'refuses an approval granted by an authority other than the declared change-approval role' {
            # Arrange
            $change = New-ApprovedChange -ApprovalOverride @{ ApprovalAuthority = 'ServiceDeskShiftLead' }

            # Act
            $decision = Invoke-Gate -Change $change

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalAuthorityNotApproved*').Count |
                Should -BeExactly 'False|1' -Because 'an approval from somebody who does not hold the role is not an approval'
        }

        It 'refuses an approval whose approver is the operator requesting the change' {
            # Arrange
            $change = New-ApprovedChange -ApprovalOverride @{ ApprovalIdentity = $script:RequestedBy }

            # Act
            $decision = Invoke-Gate -Change $change

            # Assert
            '{0}|{1}' -f $decision['Permitted'], (@($decision['Finding']) -like 'ChangeApprovalSelfApproved*').Count |
                Should -BeExactly 'False|1' -Because 'an operator who approves their own change has removed the review entirely'
        }
    }

    Context 'Negative: the decision hides what else was wrong or can be rewritten' {

        It 'collects every refusal rather than returning the first' {
            # Arrange
            $change = New-ApprovedChange -ApprovalOverride @{
                ChangeId          = 'CHG0099999'
                ApprovalAuthority = 'ServiceDeskShiftLead'
                ApprovalIdentity  = $script:RequestedBy
            }

            # Act
            $decision = Invoke-Gate -Change $change

            # Assert
            @($decision['Finding']).Count | Should -BeGreaterOrEqual 3 -Because 'an operator handed one blocker at a time has to run the whole gate again to learn what else was already wrong'
        }

        It 'refuses assignment to the decision verdict' {
            # Arrange
            $decision = Invoke-Gate -Change (New-ApprovedChange)

            # Act
            $act = { $decision['Permitted'] = $true }

            # Assert
            $act | Should -Throw -Because 'a verdict a caller can rewrite is a gate that permits whatever the caller wanted'
        }

        It 'refuses assignment to the collected findings' {
            # Arrange
            $decision = Invoke-Gate -Change (New-ApprovedChange -ApprovalOverride @{ ApprovalIdentity = $script:RequestedBy })

            # Act
            $act = { $decision['Finding'][0] = 'resolved' }

            # Assert
            $act | Should -Throw -Because 'a refusal a caller can edit away is a refusal that never happened'
        }
    }

    Context 'Positive: a matching, unexpired, independently signed approval permits the apply' {

        It 'permits the apply and names the preview it permits it from, with no refusal collected' {
            # Arrange
            $change = New-ApprovedChange
            Mock Test-BaselineDetachedCmsSignature -ModuleName ExchangeOnlineBaseline.Common {
                @{ Verified = $true; SignerSubject = 'CN=Offline Approver'; SigningTimeUtc = '2026-09-18T07:40:00Z'; CertificateNotBeforeUtc = '2026-01-01T00:00:00Z'; CertificateNotAfterUtc = '2027-01-01T00:00:00Z'; ChainTrusted = $true; RevocationStatus = 'Good' }
            }
            $authorizedSigner = @(@{ Identity = $script:Approver; Subject = 'CN=Offline Approver'; Authority = $script:Authority })

            # Act
            $decision = Invoke-Gate -Change $change -Override @{ AuthorizedSigner = $authorizedSigner }

            # Assert
            '{0}|{1}|{2}|{3}' -f $decision['Permitted'], $decision['ChangeId'], $decision['PreviewPath'], @($decision['Finding']).Count |
                Should -BeExactly ('True|{0}|{1}|0' -f $script:ChangeId, $change.PreviewPath) -Because 'an apply that cannot name the approved plan it is running is an apply from configuration alone'
        }
    }
}
