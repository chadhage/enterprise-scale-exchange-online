#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:TenantId = 'f1a3b5c7-0000-4000-8000-0123456789ab'
    $script:DeploymentProfile = 'MicrosoftNative'
    $script:ConfigurationHash = 'a3f1c9d2b4e6708192a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f809'

    function New-UnresolvedCatalog {
        param([string[]]$ControlId = @('EXO-001', 'EXO-002'))

        $path = Join-Path $TestDrive ('catalog-{0}.md' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $path -Encoding utf8 -Value (@(
                '| ID | Priority | Profile | Licence | Control | Desired state | Evidence | Runbook |'
                '| --- | --- | --- | --- | --- | --- | --- | --- |'
            ) + @($ControlId | ForEach-Object {
                    '| {0} | MUST | Both | EOP | Control | Desired | `Get-Control` | R-{0} |' -f $_
                }))
        return $path
    }

    function New-UnresolvedParameter {
        $path = Join-Path $TestDrive ('parameters-{0}.json' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $path -Encoding utf8 -Value '{ "primaryDomain": "contoso.com" }'
        return $path
    }

    function New-UnresolvedEvidence {
        param([Parameter(Mandatory)][string]$ControlId)

        return New-BaselineEvidence -ControlId $ControlId -Source 'SyntheticOfflineEvidence' -Command 'Fixture' -Value @{ observed = $true }
    }

    function New-UnresolvedEnvelope {
        param(
            [object[]]$Evidence = @((New-UnresolvedEvidence -ControlId 'EXO-001'), (New-UnresolvedEvidence -ControlId 'EXO-002')),
            [object[]]$Check = @(
                (New-ControlResult -ControlId 'EXO-001' -Status 'Pass'),
                (New-ControlResult -ControlId 'EXO-002' -Status 'Pass')
            )
        )

        if (@($Evidence).Count -gt 0) {
            return New-BaselineEvidenceEnvelope -Context ([pscustomobject]@{
                    DeploymentProfile = $script:DeploymentProfile
                    Algorithm         = 'SHA256'
                    Hash              = $script:ConfigurationHash
                    Entitlement       = [pscustomobject]@{
                        Source               = 'SyntheticOfflineEntitlement'
                        Determined           = $true
                        EnabledServicePlanId = @('efb87545-963c-4e0d-99df-69c6916d9eb0')
                        Capability           = @()
                        NotEntitled          = @()
                    }
                }) `
                -TenantId $script:TenantId `
                -OrganizationName 'contoso.onmicrosoft.com' `
                -ParameterPath (New-UnresolvedParameter) `
                -Evidence @($Evidence) `
                -Check @($Check)
        }

        return [pscustomobject]@{
            CollectedAtUtc    = [datetime]::UtcNow.ToString('o')
            TenantId          = $script:TenantId
            DeploymentProfile = $script:DeploymentProfile
            ConfigurationHash = 'sha256:{0}' -f $script:ConfigurationHash
            ServicePlan       = [pscustomobject]@{ NotEntitled = @() }
            Evidence          = @()
            Check             = @($Check)
        }
    }

    function Invoke-UnresolvedGate {
        param(
            [Parameter(Mandatory)][object]$Envelope,
            [string]$CatalogPath = (New-UnresolvedCatalog)
        )

        $signature = [pscustomobject]@{
            Model       = 'DetachedCms'
            Value       = 'MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExDzANBglghkgBZQMEAgEFADA='
            ContentHash = [string](Get-BaselineEvidenceContentHash -Envelope $Envelope).Hash
        }

        return Test-BaselineGoLive -Envelope $Envelope `
            -CatalogPath $CatalogPath `
            -ExpectedTenantId $script:TenantId `
            -ExpectedDeploymentProfile $script:DeploymentProfile `
            -ExpectedConfigurationHash $script:ConfigurationHash `
            -MaximumEvidenceAge ([timespan]::FromDays(7)) `
            -Signature $signature `
            -AsOf ([datetime]::UtcNow)
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GATE-007 unresolved evidence and status refusal' {

    Context 'Negative: unresolved control statuses cannot become successful outcomes' {

        It 'preserves <_> as unresolved and unsuccessful' -ForEach @('Manual', 'NotEntitled', 'Unverified') {
            # Arrange
            $status = $_
            $unresolved = New-ControlResult -ControlId 'EXO-002' -Status $status -Reason "$status evidence remains unresolved."
            $envelope = New-UnresolvedEnvelope -Check @(
                (New-ControlResult -ControlId 'EXO-001' -Status 'Pass'),
                $unresolved
            )

            # Act
            $decision = Invoke-UnresolvedGate -Envelope $envelope

            # Assert
            ('SourceStatus={0};Normalized={1};SourceSuccess={2};Admitted={3};ResultStatus={4};ResultSuccess={5};Manufactured={6};Finding={7}' -f `
                    $unresolved.Status,
                    $unresolved.Normalized,
                    $unresolved.GoLiveSuccess,
                    $decision.Admitted,
                    $decision.Result.Status,
                    $decision.Result.GoLiveSuccess,
                    ($decision.Result.Status -cin @('Pass', 'NotApplicable', 'ApprovedException')),
                    (@($decision.Finding) -join '|')) |
                Should -BeLike "SourceStatus=$status;Normalized=False;SourceSuccess=False;Admitted=False;ResultStatus=Fail;ResultSuccess=False;Manufactured=False;Finding=*ControlNotPassed:*EXO-002*$status*"
        }
    }

    Context 'Negative: every passing check must retain its evidence' {

        It 'refuses absent evidence for each named catalog control' {
            # Arrange
            $envelope = New-UnresolvedEnvelope -Evidence @()

            # Act
            $decision = Invoke-UnresolvedGate -Envelope $envelope

            # Assert
            ('Admitted={0};Status={1};Success={2};Finding={3}' -f $decision.Admitted, $decision.Result.Status, $decision.Result.GoLiveSuccess, (@($decision.Finding) -join '|')) |
                Should -BeLike 'Admitted=False;Status=Fail;Success=False;Finding=*EvidenceControlMissing:*EXO-001*EvidenceControlMissing:*EXO-002*'
        }

        It 'refuses partial evidence and names the control whose observation is absent' {
            # Arrange
            $envelope = New-UnresolvedEnvelope -Evidence @((New-UnresolvedEvidence -ControlId 'EXO-001'))

            # Act
            $decision = Invoke-UnresolvedGate -Envelope $envelope

            # Assert
            ('Admitted={0};Status={1};Success={2};Finding={3}' -f $decision.Admitted, $decision.Result.Status, $decision.Result.GoLiveSuccess, (@($decision.Finding) -join '|')) |
                Should -BeLike 'Admitted=False;Status=Fail;Success=False;Finding=*EvidenceControlMissing:*EXO-002*'
        }
    }

    Context 'Positive: complete evaluated evidence remains eligible for admission' {

        It 'admits one fully observed and evaluated passing control' {
            # Arrange
            $envelope = New-UnresolvedEnvelope `
                -Evidence @((New-UnresolvedEvidence -ControlId 'EXO-001')) `
                -Check @((New-ControlResult -ControlId 'EXO-001' -Status 'Pass'))
            $catalog = New-UnresolvedCatalog -ControlId @('EXO-001')

            # Act
            $decision = Invoke-UnresolvedGate -Envelope $envelope -CatalogPath $catalog

            # Assert
            ('Admitted={0};Status={1};Success={2};Finding={3}' -f $decision.Admitted, $decision.Result.Status, $decision.Result.GoLiveSuccess, (@($decision.Finding) -join '|')) |
                Should -BeExactly 'Admitted=True;Status=Pass;Success=True;Finding='
        }
    }
}