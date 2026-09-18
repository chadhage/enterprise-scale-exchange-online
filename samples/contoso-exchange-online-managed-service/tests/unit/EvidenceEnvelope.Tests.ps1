#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:CommonManifestPath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psd1'

    # Microsoft.Graph and ExchangeOnlineManagement are not installed and must never be imported.
    # The envelope is assembled from a context, a parameter file and records already in hand.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:Secret = 'never-published-secret'

    function New-ParameterFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Name
        )

        $path = Join-Path $TestDrive $Name
        Set-Content -LiteralPath $path -Encoding utf8 -Value (
            '{{ "primaryDomain": "contoso.com", "clientSecret": "{0}" }}' -f $script:Secret)
        return $path
    }

    function New-ContextFixture {
        [CmdletBinding()]
        param(
            [string]$DeploymentProfile = 'MicrosoftNative',

            [switch]$WithoutHash,

            [switch]$WithoutProfile,

            [switch]$WithoutEntitlement
        )

        $member = [ordered]@{
            DeploymentProfile = $DeploymentProfile
            Algorithm         = 'SHA256'
            Hash              = 'a1b2c3'
            Entitlement       = [pscustomobject]@{
                Source               = 'TenantServicePlanInventory'
                Determined           = $true
                EnabledServicePlanId = @('efb87545-963c-4e0d-99df-69c6916d9eb0', '8e0c0a52-6a6c-4d40-8370-dd62790dcd70')
                Capability           = @([pscustomobject]@{ Name = 'AtpPresets'; Entitled = $true })
                NotEntitled          = @('SafeDocuments')
            }
        }

        if ($WithoutHash) { $member.Remove('Hash') }
        if ($WithoutProfile) { $member['DeploymentProfile'] = '  ' }
        if ($WithoutEntitlement) { $member.Remove('Entitlement') }

        return [pscustomobject]$member
    }

    function New-EvidenceFixture {
        [CmdletBinding()]
        param()

        return @(
            New-BaselineEvidence -ControlId 'EXO-001' -Source 'ExchangeOnline' -Command 'Get-AcceptedDomain' -Value @{ domainType = 'Authoritative' }
            New-BaselineEvidence -ControlId 'EXO-002' -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value @{ smtpClientAuthenticationDisabled = $true }
        )
    }

    function New-CheckFixture {
        [CmdletBinding()]
        param()

        return @(
            New-ControlResult -ControlId 'EXO-001' -Status 'Pass'
            New-ControlResult -ControlId 'EXO-002' -Status 'Fail' -Reason 'SMTP AUTH is enabled at the organization.'
        )
    }

    function New-EnvelopeArgument {
        [CmdletBinding()]
        param()

        return @{
            Context          = New-ContextFixture
            TenantId         = 'f1a3b5c7-0000-4000-8000-0123456789ab'
            OrganizationName = 'contoso.onmicrosoft.com'
            ParameterPath    = (New-ParameterFixture -Name 'envelope-parameters.json')
            Evidence         = (New-EvidenceFixture)
            Check            = (New-CheckFixture)
        }
    }

    function Get-EnvelopeFold {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Envelope
        )

        return @(
            'members=' + (@($Envelope.Keys) -join ',')
            'schemaVersion=' + $Envelope.SchemaVersion
            'baselineVersion=' + $Envelope.BaselineVersion
            'collectedAtUtcIsRoundTripUtc=' + ($Envelope.CollectedAtUtc -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$')
            'tenantId=' + $Envelope.TenantId
            'organizationName=' + $Envelope.OrganizationName
            'deploymentProfile=' + $Envelope.DeploymentProfile
            'configurationHash=' + $Envelope.ConfigurationHash
            'parameterHash=' + $Envelope.ParameterHash
            'redactedParameter=' + (@($Envelope.RedactedParameter) -join '+')
            'collectorVersion=' + $Envelope.CollectorVersion
            'moduleVersion=' + $Envelope.ModuleVersion
            'previewId=' + $Envelope.PreviewId
            'changeId=' + $Envelope.ChangeId
            'servicePlanSource=' + $Envelope.ServicePlan.Source
            'servicePlanDetermined=' + $Envelope.ServicePlan.Determined
            'enabledServicePlanId=' + (@($Envelope.ServicePlan.EnabledServicePlanId) -join '+')
            'notEntitled=' + (@($Envelope.ServicePlan.NotEntitled) -join '+')
            'evidence=' + (@($Envelope.Evidence | ForEach-Object { '{0}:{1}' -f $_.ControlId, $_.Command }) -join '+')
            'check=' + (@($Envelope.Check | ForEach-Object { '{0}:{1}' -f $_.ControlId, $_.Status }) -join '+')
        ) -join "`n"
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EVD-004-A2 evidence envelope' {

    Context 'Negative: the envelope must be built from a context that identifies the run' {

        It 'refuses an envelope built from no context' {
            # Arrange
            $argument = New-EnvelopeArgument
            $argument.Context = $null

            # Act
            $result = { New-BaselineEvidenceEnvelope @argument }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EnvelopeContextRequired*' -Because 'evidence that cannot say which resolved configuration produced it proves nothing about the tenant it was collected from'
        }

        It 'refuses a context that carries no configuration hash' {
            # Arrange
            $argument = New-EnvelopeArgument
            $argument.Context = New-ContextFixture -WithoutHash

            # Act
            $result = { New-BaselineEvidenceEnvelope @argument }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EnvelopeConfigurationHashRequired*' -Because 'the go-live gate compares evidence to an expected configuration hash, and an envelope with no hash would silently skip that comparison'
        }

        It 'refuses a context that names no deployment profile' {
            # Arrange
            $argument = New-EnvelopeArgument
            $argument.Context = New-ContextFixture -WithoutProfile

            # Act
            $result = { New-BaselineEvidenceEnvelope @argument }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EnvelopeDeploymentProfileRequired*' -Because 'the native and gateway profiles are held to different controls, so evidence that does not say which one ran cannot be judged against either'
        }

        It 'refuses a context that carries no entitlement' {
            # Arrange
            $argument = New-EnvelopeArgument
            $argument.Context = New-ContextFixture -WithoutEntitlement

            # Act
            $result = { New-BaselineEvidenceEnvelope @argument }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EnvelopeEntitlementRequired*' -Because 'a NotEntitled verdict is only defensible beside the service plans the tenant actually held, and without them an unlicensed run is indistinguishable from a compliant one'
        }
    }

    Context 'Negative: the envelope must name the tenant it describes' {

        It 'refuses a blank tenant identifier' {
            # Arrange
            $argument = New-EnvelopeArgument
            $argument.TenantId = '   '

            # Act
            $result = { New-BaselineEvidenceEnvelope @argument }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EnvelopeTenantRequired*' -Because 'evidence from one tenant presented for another is the single cheapest way to pass a go-live gate that was never run'
        }

        It 'refuses a blank organization name' {
            # Arrange
            $argument = New-EnvelopeArgument
            $argument.OrganizationName = ''

            # Act
            $result = { New-BaselineEvidenceEnvelope @argument }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EnvelopeOrganizationRequired*' -Because 'a directory identifier alone is unreadable to the approver who has to sign the evidence off'
        }
    }

    Context 'Negative: the envelope must carry the observations and the verdicts it claims' {

        It 'refuses an envelope carrying no evidence' {
            # Arrange
            $argument = New-EnvelopeArgument
            $argument.Evidence = $null

            # Act
            $result = { New-BaselineEvidenceEnvelope @argument }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EnvelopeEvidenceRequired*' -Because 'verdicts with no raw evidence behind them cannot be re-examined, so a wrong verdict can never be found'
        }

        It 'refuses an envelope carrying an empty evidence set' {
            # Arrange
            $argument = New-EnvelopeArgument
            $argument.Evidence = @()

            # Act
            $result = { New-BaselineEvidenceEnvelope @argument }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EnvelopeEvidenceRequired*' -Because 'an empty set is the same silent absence as no set at all'
        }

        It 'refuses an evidence entry that is not an evidence record' {
            # Arrange
            $argument = New-EnvelopeArgument
            $argument.Evidence = @(New-EvidenceFixture) + @([pscustomobject]@{ ControlId = 'EXO-003'; Value = 'observed' })

            # Act
            $result = { New-BaselineEvidenceEnvelope @argument }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EnvelopeEvidenceNotRecognized*' -Because 'a hand-built record carries no collection outcome and no collection time, so a failed collection inside it would be read as a successful observation'
        }

        It 'refuses an envelope carrying no checks' {
            # Arrange
            $argument = New-EnvelopeArgument
            $argument.Check = $null

            # Act
            $result = { New-BaselineEvidenceEnvelope @argument }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EnvelopeCheckRequired*' -Because 'an envelope with no verdicts has nothing for the gate to fail on, so it reads as a clean run'
        }

        It 'refuses an envelope carrying an empty check set' {
            # Arrange
            $argument = New-EnvelopeArgument
            $argument.Check = @()

            # Act
            $result = { New-BaselineEvidenceEnvelope @argument }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EnvelopeCheckRequired*' -Because 'an empty set is the same silent absence as no set at all'
        }

        It 'refuses a check entry that is not a control result' {
            # Arrange
            $argument = New-EnvelopeArgument
            $argument.Check = @(New-CheckFixture) + @([pscustomobject]@{ ControlId = 'EXO-003'; status = 'Pass' })

            # Act
            $result = { New-BaselineEvidenceEnvelope @argument }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EnvelopeCheckNotRecognized*' -Because 'a verdict that never passed through the result contract can carry a status the contract never declared, and the gate has no rule for it'
        }
    }

    Context 'Negative: the applied preview and change identifiers must be honest' {

        It 'refuses a change identifier that names no preview' {
            # Arrange
            $argument = New-EnvelopeArgument
            $argument.ChangeId = 'chg-0042'

            # Act
            $result = { New-BaselineEvidenceEnvelope @argument }

            # Assert
            $result | Should -Throw -ExpectedMessage 'EnvelopePreviewRequired*' -Because 'a change applied without an approved preview is the exact state change safety exists to prevent, and evidence must not record it as ordinary'
        }

        It 'names the preview and change identifiers even when no change was applied' {
            # Arrange
            $argument = New-EnvelopeArgument

            # Act
            $envelope = New-BaselineEvidenceEnvelope @argument

            # Assert
            ('{0}|{1}' -f $envelope.Keys.Contains('PreviewId'), $envelope.Keys.Contains('ChangeId')) |
                Should -BeExactly 'True|True' `
                    -Because 'a reader cannot tell an omitted member from a run that applied nothing, so a verification-only run must say so rather than stay silent'
        }
    }

    Context 'Negative: the envelope must not publish what it was given to redact' {

        It 'carries no sensitive parameter value anywhere in the artifact it is published as' {
            # Arrange
            $argument = New-EnvelopeArgument
            $envelope = New-BaselineEvidenceEnvelope @argument

            # Act
            $published = $envelope | ConvertTo-Json -Depth 20

            # Assert
            $published | Should -Not -BeLike "*$script:Secret*" -Because 'the envelope is the artifact that leaves the tenant boundary, so a credential inside it is disclosed to everyone the evidence is shown to'
        }
    }

    Context 'Negative: the envelope cannot be edited after it is built' {

        It 'returns an envelope that rejects assignment' {
            # Arrange
            $argument = New-EnvelopeArgument
            $envelope = New-BaselineEvidenceEnvelope @argument

            # Act
            $act = { $envelope.ConfigurationHash = 'sha256:0' }

            # Assert
            $act | Should -Throw -Because 'an envelope a caller can rewrite lets a failing run be presented as a passing one without recollecting anything'
        }

        It 'returns an envelope that rejects a new member' {
            # Arrange
            $argument = New-EnvelopeArgument
            $envelope = New-BaselineEvidenceEnvelope @argument

            # Act
            $act = { $envelope.Waived = $true }

            # Assert
            $act | Should -Throw -Because 'a member added after collection is a claim the collection never made, and the next reader cannot tell it from a collected one'
        }
    }

    Context 'Positive: one envelope carries everything a reviewer needs to re-decide the run' {

        It 'names the schema, the tenant, the profile, both hashes, both versions, the applied change, the service plans, the evidence and the checks' {
            # Arrange
            $argument = New-EnvelopeArgument
            $argument.PreviewId = 'preview-0007'
            $argument.ChangeId = 'chg-0042'
            $parameterHash = Get-BaselineParameterHash -Path $argument.ParameterPath
            $expected = @(
                'members=SchemaVersion,BaselineVersion,CollectedAtUtc,TenantId,OrganizationName,DeploymentProfile,ConfigurationHash,ParameterHash,RedactedParameter,CollectorVersion,ModuleVersion,PreviewId,ChangeId,ServicePlan,Evidence,Check'
                'schemaVersion=1.0.0'
                'baselineVersion=1.0.0'
                'collectedAtUtcIsRoundTripUtc=True'
                'tenantId=f1a3b5c7-0000-4000-8000-0123456789ab'
                'organizationName=contoso.onmicrosoft.com'
                'deploymentProfile=MicrosoftNative'
                'configurationHash=sha256:a1b2c3'
                "parameterHash=sha256:$($parameterHash.Hash)"
                'redactedParameter=clientSecret'
                'collectorVersion=1.0.0'
                "moduleVersion=$((Import-PowerShellDataFile -LiteralPath $script:CommonManifestPath).ModuleVersion)"
                'previewId=preview-0007'
                'changeId=chg-0042'
                'servicePlanSource=TenantServicePlanInventory'
                'servicePlanDetermined=True'
                'enabledServicePlanId=efb87545-963c-4e0d-99df-69c6916d9eb0+8e0c0a52-6a6c-4d40-8370-dd62790dcd70'
                'notEntitled=SafeDocuments'
                'evidence=EXO-001:Get-AcceptedDomain+EXO-002:Get-TransportConfig'
                'check=EXO-001:Pass+EXO-002:Fail'
            ) -join "`n"

            # Act
            $envelope = New-BaselineEvidenceEnvelope @argument

            # Assert
            (Get-EnvelopeFold -Envelope $envelope) |
                Should -BeExactly $expected `
                    -Because 'the envelope is the only artifact a reviewer holds, so every fact needed to re-decide the run must be in it and none of them may be inferred'
        }
    }
}
