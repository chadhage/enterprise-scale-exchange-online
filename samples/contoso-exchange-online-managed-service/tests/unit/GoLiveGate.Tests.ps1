#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph and ExchangeOnlineManagement are not installed and must never be imported.
    # The gate is decided from an envelope, a catalog and a clock already in hand.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:TenantId = 'f1a3b5c7-0000-4000-8000-0123456789ab'
    $script:DeploymentProfile = 'MicrosoftNative'
    $script:ConfigurationHash = 'a3f1c9d2b4e6708192a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f809'
    $script:RequestedBy = 'operator@contoso.example'
    $script:MaximumEvidenceAge = [timespan]::FromDays(7)

    function New-GateCatalog {
        [CmdletBinding()]
        param([string[]]$ControlId = @('EXO-001', 'EXO-002'))

        $path = Join-Path $TestDrive ('catalog-{0}.md' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $path -Encoding utf8 -Value (@(
                '| ID | Priority | Profile | Licence | Control | Desired state | Evidence | Runbook |'
                '| --- | --- | --- | --- | --- | --- | --- | --- |'
            ) + @($ControlId | ForEach-Object {
                    '| {0} | MUST | Both | EOP | Control | Desired | `Get-TransportConfig` | R-{0} |' -f $_
                }))

        return $path
    }

    function New-GateParameter {
        [CmdletBinding()]
        param()

        $path = Join-Path $TestDrive ('parameters-{0}.json' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $path -Encoding utf8 -Value '{ "primaryDomain": "contoso.com" }'
        return $path
    }

    function New-GateContext {
        [CmdletBinding()]
        param(
            [string]$DeploymentProfile = $script:DeploymentProfile,
            [string]$Hash = $script:ConfigurationHash,
            [string[]]$NotEntitled = @()
        )

        return [pscustomobject]@{
            DeploymentProfile = $DeploymentProfile
            Algorithm         = 'SHA256'
            Hash              = $Hash
            Entitlement       = [pscustomobject]@{
                Source               = 'TenantServicePlanInventory'
                Determined           = $true
                EnabledServicePlanId = @('efb87545-963c-4e0d-99df-69c6916d9eb0')
                Capability           = @()
                NotEntitled          = @($NotEntitled)
            }
        }
    }

    function New-GateEvidence {
        [CmdletBinding()]
        param([Parameter(Mandatory)][string]$ControlId)

        return New-BaselineEvidence -ControlId $ControlId -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value @{ observed = $true }
    }

    # A status outside the result contract cannot be built through New-ControlResult, which is the
    # point of that guard, so the one negative that needs one shapes the record by hand.
    function New-GateCheck {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$ControlId,
            [string]$Status = 'Pass',
            [switch]$Undeclared
        )

        if ($Undeclared) {
            return [pscustomobject]@{
                ControlId      = $ControlId
                Status         = $Status
                Normalized     = $false
                GoLiveSuccess  = $false
                Reason         = "The evaluator reported '$Status'."
                Evidence       = $null
                EvaluatedAtUtc = [datetime]::UtcNow
            }
        }

        if ($Status -ceq 'Pass') {
            return New-ControlResult -ControlId $ControlId -Status 'Pass'
        }

        return New-ControlResult -ControlId $ControlId -Status $Status -Reason "The evaluator reported '$Status'."
    }

    function New-GateEnvelope {
        [CmdletBinding()]
        param(
            [object[]]$Check = @((New-GateCheck -ControlId 'EXO-001'), (New-GateCheck -ControlId 'EXO-002')),
            [object]$Context = (New-GateContext)
        )

        $evidence = @(@($Check) | ForEach-Object { [string]$_.ControlId } | Select-Object -Unique | ForEach-Object { New-GateEvidence -ControlId $_ })

        return New-BaselineEvidenceEnvelope -Context $Context `
            -TenantId $script:TenantId `
            -OrganizationName 'contoso.onmicrosoft.com' `
            -ParameterPath (New-GateParameter) `
            -Evidence $evidence `
            -Check @($Check)
    }

    function New-GateSignature {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][object]$Envelope,
            [string]$Model = 'DetachedCms',
            [string]$Value = 'MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExDzANBglghkgBZQMEAgEFADA=',
            [AllowEmptyString()][string]$ContentHash = ''
        )

        if ([string]::IsNullOrEmpty($ContentHash)) {
            $ContentHash = [string](Get-BaselineEvidenceContentHash -Envelope $Envelope).Hash
        }

        return [pscustomobject]@{
            Model       = $Model
            Value       = $Value
            ContentHash = $ContentHash
        }
    }

    function New-GateTargetEntitlement {
        [CmdletBinding()]
        param([object[]]$Missing = @())

        return [pscustomobject]@{
            Source     = 'GraphUserAssignedPlans'
            Target     = @('priority@contoso.example')
            Assignment = @()
            Missing    = @($Missing)
            Entitled   = (@($Missing).Count -eq 0)
        }
    }

    function Invoke-GateTest {
        [CmdletBinding()]
        param(
            [AllowNull()][object]$Envelope,
            [AllowNull()][AllowEmptyString()][string]$CatalogPath,
            [AllowNull()][AllowEmptyString()][string]$ExpectedTenantId = $script:TenantId,
            [AllowNull()][AllowEmptyString()][string]$ExpectedDeploymentProfile = $script:DeploymentProfile,
            [AllowNull()][AllowEmptyString()][string]$ExpectedConfigurationHash = $script:ConfigurationHash,
            [timespan]$MaximumEvidenceAge = $script:MaximumEvidenceAge,
            [AllowNull()][object]$Signature,
            [AllowNull()][object]$TargetEntitlement = (New-GateTargetEntitlement),
            [datetime]$AsOf = [datetime]::UtcNow
        )

        if (-not $PSBoundParameters.ContainsKey('Envelope')) { $Envelope = New-GateEnvelope }
        if (-not $PSBoundParameters.ContainsKey('CatalogPath')) { $CatalogPath = New-GateCatalog }
        if (-not $PSBoundParameters.ContainsKey('Signature') -and $null -ne $Envelope) { $Signature = New-GateSignature -Envelope $Envelope }

        return Test-BaselineGoLive -Envelope $Envelope `
            -CatalogPath $CatalogPath `
            -ExpectedTenantId $ExpectedTenantId `
            -ExpectedDeploymentProfile $ExpectedDeploymentProfile `
            -ExpectedConfigurationHash $ExpectedConfigurationHash `
            -MaximumEvidenceAge $MaximumEvidenceAge `
            -RequestedBy $script:RequestedBy `
            -Signature $Signature `
            -TargetEntitlement $TargetEntitlement `
            -AsOf $AsOf
    }

    function Get-GateFinding {
        [CmdletBinding()]
        param([Parameter(Mandatory)][object]$Decision)

        return (@($Decision.Finding) -join ' | ')
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GATE-003-A1 the fail-closed go-live decision' {

    Context 'Negative: the decision refuses input it cannot decide from' {

        It 'refuses to decide with no envelope' {
            # Arrange
            $missing = $null

            # Act
            $act = { Invoke-GateTest -Envelope $missing }

            # Assert
            $act | Should -Throw -ExpectedMessage '*GoLiveEnvelopeRequired*' -Because 'a gate handed no evidence has nothing to fail on and would admit everything'
        }

        It 'refuses to decide with no catalog path' {
            # Arrange
            $missing = ''

            # Act
            $act = { Invoke-GateTest -CatalogPath $missing }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CatalogPathRequired*' -Because 'a gate that is told nothing to cover is covered by anything'
        }

        It 'refuses to decide with a catalog path naming no file' {
            # Arrange
            $absent = Join-Path $TestDrive 'no-such-catalog.md'

            # Act
            $act = { Invoke-GateTest -CatalogPath $absent }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CatalogNotFound*' -Because 'a catalog that is not there cannot be the catalog the run was held to'
        }

        It 'refuses to decide with no expected <_>' -ForEach @('TenantId', 'DeploymentProfile', 'ConfigurationHash') {
            # Arrange
            $parameter = @{ ('Expected' + $_) = '' }

            # Act
            $act = { Invoke-GateTest @parameter }

            # Assert
            $act | Should -Throw -ExpectedMessage "*GoLiveExpected$($_)Required*" -Because 'a binding the caller never stated is a binding that matches whatever the envelope happens to say'
        }
    }

    Context 'Negative: a control that did not pass never admits go-live' {

        It 'refuses a run in which a control was decided <_>' -ForEach @('Fail', 'Error', 'Manual', 'NotEntitled', 'Unverified') {
            # Arrange
            $envelope = New-GateEnvelope -Check @((New-GateCheck -ControlId 'EXO-001'), (New-GateCheck -ControlId 'EXO-002' -Status $_))

            # Act
            $decision = Invoke-GateTest -Envelope $envelope

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike "Admitted=False:Finding=*ControlNotPassed:*EXO-002*$_*" -Because "a '$_' verdict is a control nobody proved, and a gate that admits it is a gate that proves nothing"
        }

        It 'refuses a status the result contract never declared and names the status' {
            # Arrange
            $envelope = New-GateEnvelope -Check @((New-GateCheck -ControlId 'EXO-001'), (New-GateCheck -ControlId 'EXO-002' -Status 'ProbablyFine' -Undeclared))

            # Act
            $decision = Invoke-GateTest -Envelope $envelope

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike 'Admitted=False:Finding=*UnknownControlStatus:*EXO-002*ProbablyFine*' -Because 'a status nothing declared is a status nothing can reason about, and a gate that skips what it does not recognize passes it'
        }
    }

    Context 'Negative: the catalog must be exactly covered' {

        It 'refuses a catalog control no check decided and names the control' {
            # Arrange
            $envelope = New-GateEnvelope -Check @((New-GateCheck -ControlId 'EXO-001'))

            # Act
            $decision = Invoke-GateTest -Envelope $envelope

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike 'Admitted=False:Finding=*CatalogControlMissing:*EXO-002*' -Because 'a control nobody decided is indistinguishable from a control that failed, until somebody looks'
        }

        It 'refuses a check naming a control the catalog never declared and names the control' {
            # Arrange
            $envelope = New-GateEnvelope -Check @((New-GateCheck -ControlId 'EXO-001'), (New-GateCheck -ControlId 'EXO-002'), (New-GateCheck -ControlId 'EXO-099'))

            # Act
            $decision = Invoke-GateTest -Envelope $envelope

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike 'Admitted=False:Finding=*CatalogControlUnknown:*EXO-099*' -Because 'the artifact and the agreement have stopped being the same document, and the gate is the last place that can be noticed'
        }

        It 'refuses one control decided twice' {
            # Arrange
            $envelope = New-GateEnvelope -Check @((New-GateCheck -ControlId 'EXO-001'), (New-GateCheck -ControlId 'EXO-002'), (New-GateCheck -ControlId 'EXO-002'))

            # Act
            $decision = Invoke-GateTest -Envelope $envelope

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike 'Admitted=False:Finding=*CatalogControlDuplicated:*EXO-002*' -Because 'two answers for one control lets a reader keep whichever one suits them'
        }
    }

    Context 'Negative: the envelope must be the run the caller asked about' {

        It 'refuses an envelope raised for another tenant and names both' {
            # Arrange
            $other = '99999999-8888-7777-6666-555555555555'

            # Act
            $decision = Invoke-GateTest -ExpectedTenantId $other

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike "Admitted=False:Finding=*GoLiveTenantMismatch:*$($script:TenantId)*$other*" -Because 'evidence from the wrong tenant is evidence about somebody else'
        }

        It 'refuses an envelope raised under another deployment profile and names both' {
            # Arrange
            $other = 'ThirdPartyGateway'

            # Act
            $decision = Invoke-GateTest -ExpectedDeploymentProfile $other

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike "Admitted=False:Finding=*GoLiveProfileMismatch:*$($script:DeploymentProfile)*$other*" -Because 'the native and gateway profiles are held to different controls, so a clean run under one says nothing about the other'
        }

        It 'refuses an envelope raised against another configuration hash and names both' {
            # Arrange
            $other = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'

            # Act
            $decision = Invoke-GateTest -ExpectedConfigurationHash $other

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike "Admitted=False:Finding=*GoLiveConfigurationHashMismatch:*$($script:ConfigurationHash)*$other*" -Because 'evidence for one resolved configuration cannot admit a different one to production'
        }
    }

    Context 'Negative: evidence must be recent enough to still describe the tenant' {

        It 'refuses evidence collected longer ago than the maximum evidence age and names the age and the limit' {
            # Arrange
            $envelope = New-GateEnvelope

            # Act
            $decision = Invoke-GateTest -Envelope $envelope -AsOf ([datetime]::UtcNow.AddDays(30))

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike 'Admitted=False:Finding=*GoLiveEvidenceStale:*30*7*' -Because 'a tenant can be reconfigured the day after it was measured, so old evidence is a claim about the past'
        }

        It 'refuses an envelope whose collection time is not a timestamp at all' {
            # Arrange
            $envelope = [pscustomobject]@{
                TenantId          = $script:TenantId
                DeploymentProfile = $script:DeploymentProfile
                ConfigurationHash = 'sha256:{0}' -f $script:ConfigurationHash
                CollectedAtUtc    = 'recently'
                ServicePlan       = [pscustomobject]@{ NotEntitled = @() }
                Evidence          = @(New-GateEvidence -ControlId 'EXO-001')
                Check             = @((New-GateCheck -ControlId 'EXO-001'), (New-GateCheck -ControlId 'EXO-002'))
            }

            # Act
            $decision = Invoke-GateTest -Envelope $envelope -Signature (New-GateSignature -Envelope $envelope)

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike 'Admitted=False:Finding=*GoLiveCollectionTimeUnreadable:*recently*' -Because 'a collection time nobody can compare against a clock is evidence that can never go stale'
        }
    }

    Context 'Negative: a licensing gap is a control nobody could have proved' {

        It 'refuses a tenant service plan the run reported unentitled and names the plan' {
            # Arrange
            $envelope = New-GateEnvelope -Context (New-GateContext -NotEntitled @('SafeDocuments'))

            # Act
            $decision = Invoke-GateTest -Envelope $envelope -Signature (New-GateSignature -Envelope $envelope)

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike 'Admitted=False:Finding=*GoLiveTenantNotEntitled:*SafeDocuments*' -Because 'a capability the tenant does not hold is a control the run could not have verified, whatever the verdict says'
        }

        It 'refuses a target user missing a required service plan and names the user and the plan' {
            # Arrange
            $gap = New-GateTargetEntitlement -Missing @([pscustomobject]@{
                    UserPrincipalName = 'priority@contoso.example'
                    ServicePlanId     = 'efb87545-963c-4e0d-99df-69c6916d9eb0'
                    ServicePlanName   = 'THREAT_INTELLIGENCE'
                    State             = 'NotAssigned'
                    Entitled          = $false
                })

            # Act
            $decision = Invoke-GateTest -TargetEntitlement $gap

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike 'Admitted=False:Finding=*GoLiveTargetNotEntitled:*priority@contoso.example*THREAT_INTELLIGENCE*' -Because 'a tenant-wide licence says nothing about whether the people the baseline protects are covered'
        }
    }

    Context 'Negative: unsigned or tampered evidence is not evidence' {

        It 'refuses an envelope carrying no signature at all' {
            # Arrange
            $unsigned = $null

            # Act
            $decision = Invoke-GateTest -Signature $unsigned

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike 'Admitted=False:Finding=*GoLiveEvidenceUnsigned:*' -Because 'an unsigned artifact is one anybody on the path could have written'
        }

        It 'refuses a signature whose model is not the selected model' {
            # Arrange
            $envelope = New-GateEnvelope

            # Act
            $decision = Invoke-GateTest -Envelope $envelope -Signature (New-GateSignature -Envelope $envelope -Model 'ExternalTicketEvidence')

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike 'Admitted=False:Finding=*GoLiveSignatureModelNotApproved:*ExternalTicketEvidence*' -Because 'a ticket number is a claim that somebody approved, not proof that these bytes are the ones they saw'
        }

        It 'refuses a signature carrying no value' {
            # Arrange
            $envelope = New-GateEnvelope

            # Act
            $decision = Invoke-GateTest -Envelope $envelope -Signature (New-GateSignature -Envelope $envelope -Value '')

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike 'Admitted=False:Finding=*GoLiveEvidenceUnsigned:*' -Because 'a signature record with nothing in it is the shape of a signature without the fact'
        }

        It 'refuses a signature whose content hash does not match the envelope as it now stands' {
            # Arrange
            $envelope = New-GateEnvelope

            # Act
            $decision = Invoke-GateTest -Envelope $envelope -Signature (New-GateSignature -Envelope $envelope -ContentHash 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')

            # Assert
            ('Admitted={0}:Finding={1}' -f $decision.Admitted, (Get-GateFinding -Decision $decision)) |
                Should -BeLike 'Admitted=False:Finding=*GoLiveEvidenceTampered:*' -Because 'evidence that no longer hashes to what was signed has been edited since somebody vouched for it'
        }
    }

    Context 'Negative: a refusal must be a verdict nothing downstream can read as success' {

        It 'records the refusal as a result the contract admits to no successful go-live' {
            # Arrange
            $envelope = New-GateEnvelope -Check @((New-GateCheck -ControlId 'EXO-001'), (New-GateCheck -ControlId 'EXO-002' -Status 'Fail'))

            # Act
            $decision = Invoke-GateTest -Envelope $envelope

            # Assert
            ('Status={0}:GoLiveSuccess={1}' -f $decision.Result.Status, $decision.Result.GoLiveSuccess) |
                Should -BeExactly 'Status=Fail:GoLiveSuccess=False' -Because 'a refusal the result contract still counts as a successful go-live is not a refusal'
        }

        It 'refuses assignment to the decision it produced' {
            # Arrange
            $decision = Invoke-GateTest

            # Act
            $act = { $decision.Admitted = $false }

            # Assert
            $act | Should -Throw -Because 'a gate verdict a later stage can rewrite is a gate a later stage can open'
        }
    }

    Context 'Positive: a clean, bound, fresh, entitled and signed run admits go-live' {

        It 'admits go-live when every check passed and every binding holds' {
            # Arrange
            $envelope = New-GateEnvelope

            # Act
            $decision = Invoke-GateTest -Envelope $envelope -Signature (New-GateSignature -Envelope $envelope)

            # Assert
            ('Admitted={0}:Status={1}:Finding={2}' -f $decision.Admitted, $decision.Result.Status, (Get-GateFinding -Decision $decision)) |
                Should -BeExactly 'Admitted=True:Status=Pass:Finding=' -Because 'a gate that never admits anything is a gate everybody routes around'
        }
    }
}
