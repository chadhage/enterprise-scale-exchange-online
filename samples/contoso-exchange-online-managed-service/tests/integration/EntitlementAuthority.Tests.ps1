#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:DeploymentScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'
    $script:EvidenceScriptPath = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'

    # The shipped gateway baseline declares messagingTier MDO_P2. That declaration is exactly what
    # the live defect turned into a Safe Documents entitlement, so it is the baseline this
    # assertion measures the entry scripts against.
    $script:GatewayConfigurationPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'
    $script:GatewayParameterPath = Join-Path $script:SampleRoot 'tests' 'fixtures' 'com003' 'parameters.gateway.complete.json'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ExchangePlanId = 'efb87545-963c-4e0d-99df-69c6916d9eb0'
    $script:AtpPlanId = 'f20fedf3-f3c3-43c3-8267-2bfdd51c0939'
    $script:ThreatIntelligencePlanId = '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'
    $script:SafeDocumentsPlanId = 'bf6f5520-59e3-4f82-974b-7dbbc4fd27c7'

    # A tier comparison is the shape of the defect: a capability decided from planning metadata
    # rather than from a service plan the tenant actually holds.
    $script:DeclaredTierComparisonPattern = "-(eq|ne|in)\s*@?\(?\s*'(EOP|MDO_P1|MDO_P2|E3|E5Compliance)'"
    $script:DeclaredTierReadPattern = 'licensing\.(messagingTier|complianceTier)'
    $script:SafeDocumentsPlanJustificationPattern = '(?i)Safe Documents[^\r\n]*(Plan 2|Defender suite)'
    $script:CapabilityRequiredMember = @('Name', 'RequiredServicePlanName', 'RequiredServicePlanId', 'Entitled', 'Reason')

    function Get-EntitlementAuthorityResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$DeploymentScriptPath,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$EvidenceScriptPath,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$ModulePath,

            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Entitlement,

            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$UncollectedEntitlement
        )

        $result = [ordered]@{
            Satisfied  = $false
            Reason     = $null
            Violations = @()
        }

        if ([string]::IsNullOrWhiteSpace($DeploymentScriptPath) -or -not (Test-Path -LiteralPath $DeploymentScriptPath -PathType Leaf)) {
            $result.Reason = 'DeploymentScriptMissing'
            return [pscustomobject]$result
        }

        if ([string]::IsNullOrWhiteSpace($EvidenceScriptPath) -or -not (Test-Path -LiteralPath $EvidenceScriptPath -PathType Leaf)) {
            $result.Reason = 'EvidenceScriptMissing'
            return [pscustomobject]$result
        }

        if ([string]::IsNullOrWhiteSpace($ModulePath) -or -not (Test-Path -LiteralPath $ModulePath -PathType Leaf)) {
            $result.Reason = 'SharedModuleMissing'
            return [pscustomobject]$result
        }

        if ($null -eq $Entitlement) {
            $result.Reason = 'EntitlementNotCollected'
            return [pscustomobject]$result
        }

        if ([string](Get-MemberValue -Node $Entitlement -Name 'Source') -ne 'GraphSubscribedSkus') {
            $result.Reason = 'EntitlementSourceNotGraph'
            $result.Violations = @([string](Get-MemberValue -Node $Entitlement -Name 'Source'))
            return [pscustomobject]$result
        }

        if (-not [bool](Get-MemberValue -Node $Entitlement -Name 'Determined')) {
            $result.Reason = 'EntitlementNotDetermined'
            return [pscustomobject]$result
        }

        $capability = Get-MemberValue -Node $Entitlement -Name 'Capability'
        if ($null -eq $capability -or $capability -isnot [System.Collections.IList] -or @($capability).Count -eq 0) {
            $result.Reason = 'CapabilityContractViolation'
            return [pscustomobject]$result
        }

        foreach ($row in @($capability)) {
            foreach ($member in $script:CapabilityRequiredMember) {
                if ($null -eq (Get-MemberValue -Node $row -Name $member)) {
                    $result.Reason = 'CapabilityContractViolation'
                    $result.Violations = @($member)
                    return [pscustomobject]$result
                }
            }
        }

        $enabled = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $enabledPlan = Get-MemberValue -Node $Entitlement -Name 'EnabledServicePlanId'
        foreach ($identifier in @($enabledPlan)) {
            if (-not [string]::IsNullOrWhiteSpace($identifier)) { $null = $enabled.Add([string]$identifier) }
        }

        # The defect signature: a capability reported entitled that no enabled service plan backs.
        $unbacked = [System.Collections.Generic.List[string]]::new()
        foreach ($row in @($capability)) {
            if (-not [bool](Get-MemberValue -Node $row -Name 'Entitled')) { continue }

            $planId = [string](Get-MemberValue -Node $row -Name 'RequiredServicePlanId')
            if ([string]::IsNullOrWhiteSpace($planId) -or -not $enabled.Contains($planId)) {
                $unbacked.Add(('{0}:{1}' -f (Get-MemberValue -Node $row -Name 'Name'), (Get-MemberValue -Node $row -Name 'RequiredServicePlanName')))
            }
        }

        if ($unbacked.Count -gt 0) {
            $result.Reason = 'CapabilityNotServicePlanDerived'
            $result.Violations = @($unbacked)
            return [pscustomobject]$result
        }

        if ($null -eq $UncollectedEntitlement) {
            $result.Reason = 'UncollectedEntitlementMissing'
            return [pscustomobject]$result
        }

        $uncollectedCapability = Get-MemberValue -Node $UncollectedEntitlement -Name 'Capability'
        $uncollected = @($uncollectedCapability)
        $leaked = @($uncollected | Where-Object { [bool](Get-MemberValue -Node $_ -Name 'Entitled') } | ForEach-Object { [string](Get-MemberValue -Node $_ -Name 'Name') })
        if ([bool](Get-MemberValue -Node $UncollectedEntitlement -Name 'Determined') -or $leaked.Count -gt 0) {
            $result.Reason = 'UncollectedEntitlementNotFailClosed'
            $result.Violations = @($leaked)
            return [pscustomobject]$result
        }

        $moduleContent = Get-Content -LiteralPath $ModulePath -Raw
        $moduleTierDecision = @([regex]::Matches($moduleContent, $script:DeclaredTierComparisonPattern) | ForEach-Object { $_.Value.Trim() })
        if ($moduleTierDecision.Count -gt 0) {
            $result.Reason = 'DeclaredTierEntitlementInModule'
            $result.Violations = @($moduleTierDecision | Sort-Object -Unique)
            return [pscustomobject]$result
        }

        $entryScript = @(
            [pscustomobject]@{ Name = 'Deploy-ExchangeOnlineBaseline.ps1'; Path = $DeploymentScriptPath }
            [pscustomobject]@{ Name = 'Test-ExchangeOnlineBaseline.ps1'; Path = $EvidenceScriptPath }
        )

        foreach ($script in $entryScript) {
            $content = Get-Content -LiteralPath $script.Path -Raw

            if ($content -match $script:DeclaredTierComparisonPattern -or $content -match $script:DeclaredTierReadPattern) {
                $result.Reason = 'ScriptComputesEntitlement'
                $result.Violations = @($script.Name)
                return [pscustomobject]$result
            }

            if ($content -notmatch '\$context\.Entitlement') {
                $result.Reason = 'EntitlementNotConsumedFromContext'
                $result.Violations = @($script.Name)
                return [pscustomobject]$result
            }

            $contextCall = @([regex]::Matches($content, 'Get-BaselineContext[^\r\n]*') | ForEach-Object { $_.Value })
            if ($contextCall.Count -eq 0 -or @($contextCall | Where-Object { $_ -match '-GraphRequest' }).Count -eq 0) {
                $result.Reason = 'GraphSeamNotSupplied'
                $result.Violations = @($script.Name)
                return [pscustomobject]$result
            }

            if ($content -match $script:SafeDocumentsPlanJustificationPattern) {
                $result.Reason = 'SafeDocumentsJustifiedByPlan'
                $result.Violations = @($script.Name)
                return [pscustomobject]$result
            }
        }

        $evidenceContent = Get-Content -LiteralPath $EvidenceScriptPath -Raw
        $licensingSection = [regex]::Match($evidenceContent, 'licensing\s*=\s*\[ordered\]@\{(.*?)\}', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        $missingMember = @('Source', 'EnabledServicePlanId', 'Capability' | Where-Object { $licensingSection.Groups[1].Value -notmatch ('\$entitlement\.{0}\b' -f $_) })
        if (-not $licensingSection.Success -or $missingMember.Count -gt 0) {
            $result.Reason = 'EvidenceLicensingSectionStale'
            $result.Violations = @($missingMember)
            return [pscustomobject]$result
        }

        $result.Satisfied = $true
        $result.Reason = 'EntitlementAuthoritySatisfied'
        $result.Violations = @()
        return [pscustomobject]$result
    }

    function Get-MemberValue {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Node,

            [Parameter(Mandatory)]
            [string]$Name
        )

        if ($null -eq $Node) { return $null }
        if ($Node -is [System.Collections.IDictionary]) {
            if ($Node.Contains($Name)) { return , $Node[$Name] }
            return $null
        }

        if ($Node.PSObject.Properties.Match($Name).Count -gt 0) { return , $Node.$Name }
        return $null
    }

    function New-CapabilityRow {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Name,

            [Parameter(Mandatory)]
            [string]$RequiredServicePlanName,

            [Parameter(Mandatory)]
            [string]$RequiredServicePlanId,

            [bool]$Entitled = $true,
            [string]$Reason = 'fixture',
            [string[]]$Omit = @()
        )

        $member = [ordered]@{
            Name                    = $Name
            RequiredServicePlanName = $RequiredServicePlanName
            RequiredServicePlanId   = $RequiredServicePlanId
            Entitled                = $Entitled
            Reason                  = $Reason
        }

        foreach ($name in $Omit) { $member.Remove($name) }

        return [pscustomobject]$member
    }

    function New-ConsumedEntitlement {
        [CmdletBinding()]
        param(
            [string]$Source = 'GraphSubscribedSkus',
            [bool]$Determined = $true,

            [AllowNull()]
            [object[]]$Capability,

            [AllowNull()]
            [AllowEmptyCollection()]
            [string[]]$EnabledServicePlanId
        )

        if (-not $PSBoundParameters.ContainsKey('EnabledServicePlanId')) {
            $EnabledServicePlanId = @($script:ExchangePlanId, $script:AtpPlanId, $script:ThreatIntelligencePlanId)
        }

        if (-not $PSBoundParameters.ContainsKey('Capability')) {
            $Capability = @(
                New-CapabilityRow -Name 'EopPresets' -RequiredServicePlanName 'EXCHANGE_S_ENTERPRISE' -RequiredServicePlanId $script:ExchangePlanId
                New-CapabilityRow -Name 'AtpPresets' -RequiredServicePlanName 'ATP_ENTERPRISE' -RequiredServicePlanId $script:AtpPlanId
                New-CapabilityRow -Name 'SafeDocuments' -RequiredServicePlanName 'SAFEDOCS' -RequiredServicePlanId $script:SafeDocumentsPlanId -Entitled $false
            )
        }

        return [pscustomobject]@{
            Source               = $Source
            Determined           = $Determined
            EnabledServicePlanId = @($EnabledServicePlanId)
            Capability           = @($Capability)
        }
    }

    function New-UncollectedEntitlement {
        [CmdletBinding()]
        param(
            [bool]$Determined = $false,
            [bool]$SafeDocumentsEntitled = $false
        )

        return [pscustomobject]@{
            Source               = 'NotCollected'
            Determined           = $Determined
            EnabledServicePlanId = @()
            Capability           = @(
                New-CapabilityRow -Name 'SafeDocuments' -RequiredServicePlanName 'SAFEDOCS' -RequiredServicePlanId $script:SafeDocumentsPlanId -Entitled $SafeDocumentsEntitled
            )
        }
    }

    function New-EntitlementAuthorityFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Root,

            [switch]$OmitDeploymentScript,
            [switch]$OmitEvidenceScript,
            [switch]$OmitSharedModule,
            [switch]$DeriveEntitlementFromTierInModule,
            [switch]$DeploymentReadsDeclaredTier,
            [switch]$EvidenceReadsDeclaredTier,
            [switch]$OmitDeploymentGraphSeam,
            [switch]$OmitEvidenceGraphSeam,
            [switch]$DeploymentJustifiesSafeDocumentsByPlan,
            [switch]$OmitDeploymentEntitlementConsumption,
            [switch]$StaleEvidenceLicensingSection
        )

        $fixtureRoot = Join-Path $Root ([guid]::NewGuid().ToString('N'))
        $scriptDirectory = Join-Path $fixtureRoot 'scripts'
        New-Item -ItemType Directory -Path $scriptDirectory -Force | Out-Null

        $modulePath = Join-Path $scriptDirectory 'ExchangeOnlineBaseline.Common.psm1'
        $moduleLines = [System.Collections.Generic.List[string]]::new()
        $moduleLines.Add('function Resolve-BaselineEntitlement { param($Configuration, $TenantServicePlan) }')
        $moduleLines.Add('function Get-BaselineContext { param($ConfigurationPath, $GraphRequest) }')
        if ($DeriveEntitlementFromTierInModule) {
            $moduleLines.Add('$safeDocuments = $messaging -eq ''MDO_P2''')
        }

        if (-not $OmitSharedModule) {
            Set-Content -LiteralPath $modulePath -Value ($moduleLines -join [Environment]::NewLine) -Encoding utf8
        }

        $contextCall = '$context = Get-BaselineContext -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath -SchemaPath $SchemaPath -GraphRequest $GraphRequest'

        $deploymentLines = [System.Collections.Generic.List[string]]::new()
        if ($OmitDeploymentGraphSeam) {
            $deploymentLines.Add('$context = Get-BaselineContext -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath -SchemaPath $SchemaPath')
        }
        else {
            $deploymentLines.Add($contextCall)
        }

        if ($OmitDeploymentEntitlementConsumption) {
            $deploymentLines.Add('$entitlement = [pscustomobject]@{ SafeDocuments = $true }')
        }
        else {
            $deploymentLines.Add('$entitlement = $context.Entitlement')
        }

        if ($DeploymentReadsDeclaredTier) {
            $deploymentLines.Add('$tier = $context.Configuration.licensing.messagingTier')
        }

        if ($DeploymentJustifiesSafeDocumentsByPlan) {
            $deploymentLines.Add('Write-Host ''Safe Documents requires Defender for Office 365 Plan 2 or the Defender suite''')
        }
        else {
            $deploymentLines.Add('Write-Host ''Safe Documents requires an enabled SAFEDOCS service plan''')
        }

        $deploymentLines.Add('if ($entitlement.SafeDocuments) { Set-AtpPolicyForO365 -EnableSafeDocs $true }')

        $evidenceLines = [System.Collections.Generic.List[string]]::new()
        if ($OmitEvidenceGraphSeam) {
            $evidenceLines.Add('$context = Get-BaselineContext -ConfigurationPath $ConfigurationPath -ParameterPath $ParameterPath -SchemaPath $SchemaPath')
        }
        else {
            $evidenceLines.Add($contextCall)
        }

        $evidenceLines.Add('$entitlement = $context.Entitlement')
        if ($EvidenceReadsDeclaredTier) {
            $evidenceLines.Add('$tier = $context.Configuration.licensing.complianceTier')
        }

        $evidenceLines.Add('$evidence = [ordered]@{')
        if ($StaleEvidenceLicensingSection) {
            $evidenceLines.Add('    licensing = [ordered]@{')
            $evidenceLines.Add('        messagingTier  = $entitlement.DeclaredMessagingTier')
            $evidenceLines.Add('        complianceTier = $entitlement.DeclaredComplianceTier')
            $evidenceLines.Add('    }')
        }
        else {
            $evidenceLines.Add('    licensing = [ordered]@{')
            $evidenceLines.Add('        declaredMessagingTier = $entitlement.DeclaredMessagingTier')
            $evidenceLines.Add('        entitlementSource     = $entitlement.Source')
            $evidenceLines.Add('        enabledServicePlanId  = @($entitlement.EnabledServicePlanId)')
            $evidenceLines.Add('        capability            = @($entitlement.Capability)')
            $evidenceLines.Add('    }')
        }
        $evidenceLines.Add('}')

        $deploymentPath = Join-Path $scriptDirectory 'Deploy-ExchangeOnlineBaseline.ps1'
        $evidencePath = Join-Path $scriptDirectory 'Test-ExchangeOnlineBaseline.ps1'

        if (-not $OmitDeploymentScript) {
            Set-Content -LiteralPath $deploymentPath -Value ($deploymentLines -join [Environment]::NewLine) -Encoding utf8
        }

        if (-not $OmitEvidenceScript) {
            Set-Content -LiteralPath $evidencePath -Value ($evidenceLines -join [Environment]::NewLine) -Encoding utf8
        }

        return [pscustomobject]@{
            DeploymentScriptPath = $deploymentPath
            EvidenceScriptPath   = $evidencePath
            ModulePath           = $modulePath
        }
    }

    function Get-FixtureAuthorityResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Fixture,

            [AllowNull()]
            [object]$Entitlement,

            [AllowNull()]
            [object]$UncollectedEntitlement
        )

        if (-not $PSBoundParameters.ContainsKey('Entitlement')) { $Entitlement = New-ConsumedEntitlement }
        if (-not $PSBoundParameters.ContainsKey('UncollectedEntitlement')) { $UncollectedEntitlement = New-UncollectedEntitlement }

        return Get-EntitlementAuthorityResult -DeploymentScriptPath $Fixture.DeploymentScriptPath `
            -EvidenceScriptPath $Fixture.EvidenceScriptPath -ModulePath $Fixture.ModulePath `
            -Entitlement $Entitlement -UncollectedEntitlement $UncollectedEntitlement
    }

    # The tenant the shipped MDO_P2 baseline is measured against: Defender for Office 365 Plan 2
    # with no SAFEDOCS service plan at all. Microsoft.Graph is never imported; the response is
    # canned and handed to the module through its injected request seam.
    function New-SubscribedSkuSeam {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [AllowEmptyCollection()]
            [object[]]$ServicePlan
        )

        if (-not $PSBoundParameters.ContainsKey('ServicePlan')) {
            $ServicePlan = @(
                [pscustomobject]@{ servicePlanId = $script:ExchangePlanId; servicePlanName = 'EXCHANGE_S_ENTERPRISE'; provisioningStatus = 'Success' }
                [pscustomobject]@{ servicePlanId = $script:AtpPlanId; servicePlanName = 'ATP_ENTERPRISE'; provisioningStatus = 'Success' }
                [pscustomobject]@{ servicePlanId = $script:ThreatIntelligencePlanId; servicePlanName = 'THREAT_INTELLIGENCE'; provisioningStatus = 'Success' }
            )
        }

        $response = [pscustomobject]@{
            value = @(
                [pscustomobject]@{
                    skuId            = '26124093-3d78-432b-b5dc-48bf992543d5'
                    skuPartNumber    = 'THREAT_INTELLIGENCE'
                    capabilityStatus = 'Enabled'
                    servicePlans     = @($ServicePlan)
                }
            )
        }

        return { param($Resource) return $response }.GetNewClosure()
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'LIC-008-A2 the entitlement authority the entry scripts consume' {

    Context 'Negative: the solution under assertion must be present' {

        It 'reports DeploymentScriptMissing when the deployment entry script is absent' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive -OmitDeploymentScript

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture

            # Assert
            $result.Reason | Should -Be 'DeploymentScriptMissing' -Because 'the script that applies the baseline is half of what consumes the entitlement'
        }

        It 'reports EvidenceScriptMissing when the evidence entry script is absent' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive -OmitEvidenceScript

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture

            # Assert
            $result.Reason | Should -Be 'EvidenceScriptMissing' -Because 'the script that reports the baseline is the other half'
        }

        It 'reports SharedModuleMissing when the shared module is absent' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive -OmitSharedModule

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture

            # Assert
            $result.Reason | Should -Be 'SharedModuleMissing' -Because 'the entitlement both scripts consume is owned by the module'
        }
    }

    Context 'Negative: the consumed entitlement must be Graph-derived' {

        It 'reports EntitlementNotCollected when the context reports no entitlement at all' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture -Entitlement $null

            # Assert
            $result.Reason | Should -Be 'EntitlementNotCollected' -Because 'a missing entitlement is not an entitled tenant'
        }

        It 'reports EntitlementSourceNotGraph when the consumed entitlement was derived from the declared tier' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive
            $declared = New-ConsumedEntitlement -Source 'DeclaredLicensingTier'

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture -Entitlement $declared

            # Assert
            $result.Reason | Should -Be 'EntitlementSourceNotGraph' -Because 'DES-003 makes the runtime Graph inventory the only authority'
        }

        It 'reports EntitlementNotDetermined when the consumed entitlement was never decided' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive
            $undecided = New-ConsumedEntitlement -Determined $false

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture -Entitlement $undecided

            # Assert
            $result.Reason | Should -Be 'EntitlementNotDetermined' -Because 'an undecided entitlement must never be consumed as a decision'
        }

        It 'reports CapabilityContractViolation when the consumed entitlement carries no per-capability verdicts' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive
            $summaryOnly = New-ConsumedEntitlement -Capability @()

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture -Entitlement $summaryOnly

            # Assert
            $result.Reason | Should -Be 'CapabilityContractViolation' -Because 'a boolean with no service plan behind it is exactly the defect this card removes'
        }

        It 'reports CapabilityContractViolation when a verdict does not name the service plan it was decided from' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive
            $unnamed = New-ConsumedEntitlement -Capability @(
                New-CapabilityRow -Name 'SafeDocuments' -RequiredServicePlanName 'SAFEDOCS' -RequiredServicePlanId $script:SafeDocumentsPlanId -Omit @('RequiredServicePlanId')
            )

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture -Entitlement $unnamed

            # Assert
            $result.Violations | Should -Be @('RequiredServicePlanId') -Because 'a verdict that cannot be traced to a plan cannot be audited'
        }

        It 'reports CapabilityNotServicePlanDerived when Safe Documents is entitled without an enabled SAFEDOCS plan' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive
            $defect = New-ConsumedEntitlement -EnabledServicePlanId @($script:ExchangePlanId, $script:AtpPlanId, $script:ThreatIntelligencePlanId) -Capability @(
                New-CapabilityRow -Name 'SafeDocuments' -RequiredServicePlanName 'SAFEDOCS' -RequiredServicePlanId $script:SafeDocumentsPlanId -Entitled $true
            )

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture -Entitlement $defect

            # Assert
            $result.Violations | Should -Be @('SafeDocuments:SAFEDOCS') -Because 'Defender for Office 365 Plan 2 is not the Safe Documents service plan'
        }

        It 'reports CapabilityNotServicePlanDerived when the Defender presets are entitled without an enabled ATP_ENTERPRISE plan' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive
            $defect = New-ConsumedEntitlement -EnabledServicePlanId @($script:ExchangePlanId) -Capability @(
                New-CapabilityRow -Name 'AtpPresets' -RequiredServicePlanName 'ATP_ENTERPRISE' -RequiredServicePlanId $script:AtpPlanId -Entitled $true
            )

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture -Entitlement $defect

            # Assert
            $result.Violations | Should -Be @('AtpPresets:ATP_ENTERPRISE') -Because 'a declared tier must never grant a preset the tenant does not hold'
        }
    }

    Context 'Negative: an entitlement that was never collected must be fail-closed' {

        It 'reports UncollectedEntitlementMissing when no uncollected entitlement is reported at all' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture -UncollectedEntitlement $null

            # Assert
            $result.Reason | Should -Be 'UncollectedEntitlementMissing' -Because 'a context that cannot reach Graph still owes its caller a verdict shape'
        }

        It 'reports UncollectedEntitlementNotFailClosed when a context built with no Graph seam still entitles a capability' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive
            $leaking = New-UncollectedEntitlement -SafeDocumentsEntitled $true

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture -UncollectedEntitlement $leaking

            # Assert
            $result.Violations | Should -Be @('SafeDocuments') -Because 'silence from Graph is not evidence of a licence'
        }

        It 'reports UncollectedEntitlementNotFailClosed when a context with no Graph seam reports itself determined' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive
            $overstated = New-UncollectedEntitlement -Determined $true

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture -UncollectedEntitlement $overstated

            # Assert
            $result.Reason | Should -Be 'UncollectedEntitlementNotFailClosed' -Because 'a verdict nobody collected must never present itself as decided'
        }
    }

    Context 'Negative: no declared tier may decide a capability anywhere in the shipping path' {

        It 'reports DeclaredTierEntitlementInModule when the module compares a declared tier to grant a capability' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive -DeriveEntitlementFromTierInModule

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture

            # Assert
            $result.Violations | Should -Be @("-eq 'MDO_P2'") -Because 'this is the exact expression that shipped the defect'
        }

        It 'reports ScriptComputesEntitlement when the deployment script reads the declared messaging tier' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive -DeploymentReadsDeclaredTier

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture

            # Assert
            $result.Violations | Should -Be @('Deploy-ExchangeOnlineBaseline.ps1') -Because 'planning metadata read at the point of decision becomes a decision'
        }

        It 'reports ScriptComputesEntitlement when the evidence script reads the declared compliance tier' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive -EvidenceReadsDeclaredTier

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture

            # Assert
            $result.Violations | Should -Be @('Test-ExchangeOnlineBaseline.ps1') -Because 'evidence that grades itself on the plan rather than the tenant proves nothing'
        }
    }

    Context 'Negative: both entry scripts must consume the Graph-derived context' {

        It 'reports EntitlementNotConsumedFromContext when the deployment script builds an entitlement of its own' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive -OmitDeploymentEntitlementConsumption

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture

            # Assert
            $result.Violations | Should -Be @('Deploy-ExchangeOnlineBaseline.ps1') -Because 'two entitlement sources are two different tenants'
        }

        It 'reports GraphSeamNotSupplied when the deployment script builds the context without a Graph request' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive -OmitDeploymentGraphSeam

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture

            # Assert
            $result.Violations | Should -Be @('Deploy-ExchangeOnlineBaseline.ps1') -Because 'a context with no Graph seam can only ever fall back to what was declared'
        }

        It 'reports GraphSeamNotSupplied when the evidence script builds the context without a Graph request' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive -OmitEvidenceGraphSeam

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture

            # Assert
            $result.Violations | Should -Be @('Test-ExchangeOnlineBaseline.ps1') -Because 'evidence must be graded against the tenant inventory it collected'
        }

        It 'reports SafeDocumentsJustifiedByPlan when a script explains Safe Documents by a Defender plan' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive -DeploymentJustifiesSafeDocumentsByPlan

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture

            # Assert
            $result.Violations | Should -Be @('Deploy-ExchangeOnlineBaseline.ps1') -Because 'an operator told to buy Plan 2 will still not have Safe Documents'
        }
    }

    Context 'Negative: the evidence licensing section must report what was collected' {

        It 'reports EvidenceLicensingSectionStale when the licensing evidence carries only the declared tiers' {
            # Arrange
            $fixture = New-EntitlementAuthorityFixture -Root $TestDrive -StaleEvidenceLicensingSection

            # Act
            $result = Get-FixtureAuthorityResult -Fixture $fixture

            # Assert
            $result.Violations | Should -Be @('Source', 'EnabledServicePlanId', 'Capability') -Because 'evidence that records only the plan cannot be audited against the tenant'
        }
    }

    Context 'Positive: the shipped scripts consume one Graph-derived entitlement' {

        It 'decides Safe Documents from the enabled SAFEDOCS plan alone for the shipped MDO_P2 baseline' {
            # Arrange
            $seam = New-SubscribedSkuSeam
            $collected = (Get-BaselineContext -ConfigurationPath $script:GatewayConfigurationPath -ParameterPath $script:GatewayParameterPath -SchemaPath $script:SchemaPath -GraphRequest $seam).Entitlement
            $uncollected = (Get-BaselineContext -ConfigurationPath $script:GatewayConfigurationPath -ParameterPath $script:GatewayParameterPath -SchemaPath $script:SchemaPath).Entitlement

            # Act
            $result = Get-EntitlementAuthorityResult -DeploymentScriptPath $script:DeploymentScriptPath -EvidenceScriptPath $script:EvidenceScriptPath `
                -ModulePath $script:CommonModulePath -Entitlement $collected -UncollectedEntitlement $uncollected

            # Assert
            '{0}|{1}|{2}|{3}|{4}' -f $result.Satisfied, $result.Reason, $collected.Source, $collected.SafeDocuments, $collected.AtpPresets |
                Should -Be 'True|EntitlementAuthoritySatisfied|GraphSubscribedSkus|False|True' -Because 'the tenant holds Defender for Office 365 Plan 2 and no SAFEDOCS plan, and the entitlement the entry scripts consume must say so'
        }
    }
}
