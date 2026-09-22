#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph and ExchangeOnlineManagement are not installed and must never be imported.
    # An exception is decided from a document, a clock and an envelope already in hand.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:TenantId = 'f1a3b5c7-0000-4000-8000-0123456789ab'
    $script:DeploymentProfile = 'MicrosoftNative'
    $script:ConfigurationHash = 'a3f1c9d2b4e6708192a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f809'
    $script:RequestedBy = 'operator@contoso.example'
    $script:MaximumEvidenceAge = [timespan]::FromDays(7)
    $script:AsOf = [datetime]::UtcNow.AddMinutes(1)
    $script:ExcusedControlId = 'EXO-002'

    function New-ExceptionCatalog {
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

    function New-ExceptionParameter {
        [CmdletBinding()]
        param()

        $path = Join-Path $TestDrive ('parameters-{0}.json' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $path -Encoding utf8 -Value '{ "primaryDomain": "contoso.com" }'
        return $path
    }

    function New-ExceptionContext {
        [CmdletBinding()]
        param()

        return [pscustomobject]@{
            DeploymentProfile = $script:DeploymentProfile
            Algorithm         = 'SHA256'
            Hash              = $script:ConfigurationHash
            Entitlement       = [pscustomobject]@{
                Source               = 'TenantServicePlanInventory'
                Determined           = $true
                EnabledServicePlanId = @('efb87545-963c-4e0d-99df-69c6916d9eb0')
                Capability           = @()
                NotEntitled          = @()
            }
        }
    }

    function New-ExceptionCheck {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$ControlId,
            [string]$Status = 'Pass'
        )

        if ($Status -ceq 'Pass') {
            return New-ControlResult -ControlId $ControlId -Status 'Pass'
        }

        return New-ControlResult -ControlId $ControlId -Status $Status -Reason "The evaluator reported '$Status'."
    }

    function New-ExceptionEnvelope {
        [CmdletBinding()]
        param(
            [string]$ExcusedStatus = 'Fail',
            [string]$OtherStatus = 'Pass'
        )

        $check = @(
            (New-ExceptionCheck -ControlId 'EXO-001' -Status $OtherStatus),
            (New-ExceptionCheck -ControlId $script:ExcusedControlId -Status $ExcusedStatus)
        )

        $evidence = @(@($check) | ForEach-Object {
                New-BaselineEvidence -ControlId ([string]$_.ControlId) -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value @{ observed = $true }
            })

        return New-BaselineEvidenceEnvelope -Context (New-ExceptionContext) `
            -TenantId $script:TenantId `
            -OrganizationName 'contoso.onmicrosoft.com' `
            -ParameterPath (New-ExceptionParameter) `
            -Evidence $evidence `
            -Check $check
    }

    function New-ExceptionSignature {
        [CmdletBinding()]
        param([Parameter(Mandatory)][object]$Envelope)

        return [pscustomobject]@{
            Model       = 'DetachedCms'
            Value       = 'MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExDzANBglghkgBZQMEAgEFADA='
            ContentHash = [string](Get-BaselineEvidenceContentHash -Envelope $Envelope).Hash
        }
    }

    function New-ExceptionAcceptance {
        [CmdletBinding()]
        param(
            [string]$ControlId = $script:ExcusedControlId,
            [hashtable]$Override = @{}
        )

        $member = [ordered]@{
            ControlId           = $ControlId
            TenantId            = $script:TenantId
            ConfigurationHash   = $script:ConfigurationHash
            Owner               = 'messaging-lead@contoso.example'
            Justification       = 'The legacy archive connector cannot honour this control until it is retired in CHG0012345.'
            CompensatingControl = @('Daily forwarding report reviewed by SecOps')
            ExternalReference   = 'CHG0012345'
            ApprovalIdentity    = 'ciso@contoso.example'
            ApprovalAuthority   = 'ExchangeOnlineChangeApproval'
            ApprovalTimeUtc     = $script:AsOf.AddDays(-8)
            EffectiveTimeUtc    = $script:AsOf.AddDays(-7)
            ExpiryTimeUtc       = $script:AsOf.AddDays(30)
            Signature           = [pscustomobject]@{
                Model = 'DetachedCms'
                Value = 'MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExDzANBglghkgBZQMEAgEFADA='
            }
        }

        foreach ($name in $Override.Keys) { $member[$name] = $Override[$name] }

        return [pscustomobject]$member
    }

    function Invoke-ExceptionTest {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][object]$Envelope,
            [AllowNull()][object[]]$RiskAcceptance
        )

        return Test-BaselineGoLive -Envelope $Envelope `
            -CatalogPath (New-ExceptionCatalog) `
            -ExpectedTenantId $script:TenantId `
            -ExpectedDeploymentProfile $script:DeploymentProfile `
            -ExpectedConfigurationHash $script:ConfigurationHash `
            -MaximumEvidenceAge $script:MaximumEvidenceAge `
            -RequestedBy $script:RequestedBy `
            -Signature (New-ExceptionSignature -Envelope $Envelope) `
            -RiskAcceptance $RiskAcceptance `
            -AsOf $script:AsOf
    }

    function Get-ExceptionFinding {
        [CmdletBinding()]
        param([Parameter(Mandatory)][object]$Decision)

        return (@($Decision.Finding) -join ' | ')
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GATE-003-A2 the approved exception the go-live decision honours' {

    Context 'Negative: an exception that is not in force excuses nothing' {

        # Each case is a different way an exception stops being an approval, and each must leave
        # the failing control exactly as refused as it was before anybody filed the paperwork.
        It 'refuses a failing control whose risk acceptance <_.Case>, naming the control and the reason' -ForEach @(
            @{ Case = 'has expired'; Override = @{ ExpiryTimeUtc = [datetime]::UtcNow.AddDays(-1) }; Token = 'Expired' }
            @{ Case = 'is not yet effective'; Override = @{ EffectiveTimeUtc = [datetime]::UtcNow.AddDays(3) }; Token = 'NotYetEffective' }
            @{ Case = 'was approved by the operator requesting the change'; Override = @{ ApprovalIdentity = 'operator@contoso.example' }; Token = 'SelfApproved' }
            @{ Case = 'was approved outside the declared change-approval role'; Override = @{ ApprovalAuthority = 'ServiceDeskApproval' }; Token = 'RiskAcceptanceSchemaViolation' }
            @{ Case = 'is bound to another configuration'; Override = @{ ConfigurationHash = ('b' * 64) }; Token = 'ConfigurationHashMismatch' }
            @{ Case = 'is refused by the published schema'; Override = @{ Justification = 'Too short.' }; Token = 'RiskAcceptanceSchemaViolation' }
        ) {
            # Arrange
            $envelope = New-ExceptionEnvelope -ExcusedStatus 'Fail'
            $acceptance = New-ExceptionAcceptance -Override $_.Override

            # Act
            $decision = Invoke-ExceptionTest -Envelope $envelope -RiskAcceptance @($acceptance)

            # Assert
            ('Admitted={0}:Excused={1}:Finding={2}' -f $decision.Admitted, (@($decision.Exception).ControlId -join ','), (Get-ExceptionFinding -Decision $decision)) |
                Should -BeLike ('Admitted=False:Excused=:Finding=*GoLiveExceptionRefused*{0}*{1}*' -f $script:ExcusedControlId, $_.Token) -Because 'an exception nobody can rely on must be refused in terms the operator holding it can act on'
        }

        It 'refuses a failing control when the only valid risk acceptance was raised for another failing control' {
            # Arrange: both controls failed and the one acceptance in hand names only EXO-001.
            $envelope = New-ExceptionEnvelope -ExcusedStatus 'Fail' -OtherStatus 'Fail'
            $acceptance = New-ExceptionAcceptance -ControlId 'EXO-001'

            # Act
            $decision = Invoke-ExceptionTest -Envelope $envelope -RiskAcceptance @($acceptance)

            # Assert
            ('Admitted={0}:Excused={1}:Finding={2}' -f $decision.Admitted, (@($decision.Exception).ControlId -join ','), (Get-ExceptionFinding -Decision $decision)) |
                Should -BeLike ('Admitted=False:Excused=EXO-001:Finding=*{0}*' -f $script:ExcusedControlId) -Because 'an exception that excuses whichever control happens to be failing is an exception that names no control at all'
        }
    }

    Context 'Negative: only a control decided Fail can be excused' {

        It 'refuses a control decided <_> that a valid risk acceptance was raised for' -ForEach @('Error', 'Manual', 'NotEntitled', 'Unverified') {
            # Arrange
            $envelope = New-ExceptionEnvelope -ExcusedStatus $_
            $acceptance = New-ExceptionAcceptance

            # Act
            $decision = Invoke-ExceptionTest -Envelope $envelope -RiskAcceptance @($acceptance)

            # Assert
            ('Admitted={0}:Excused={1}:Finding={2}' -f $decision.Admitted, (@($decision.Exception).ControlId -join ','), (Get-ExceptionFinding -Decision $decision)) |
                Should -BeLike ('Admitted=False:Excused=:Finding=*GoLiveExceptionNotApplicable*{0}*{1}*' -f $script:ExcusedControlId, $_) -Because 'accepting a risk nobody measured is not accepting a risk, it is declining to look'
        }
    }

    Context 'Negative: exception authority must be unambiguous' {

        It 'refuses two risk acceptances raised for the same failing control' {
            # Arrange
            $envelope = New-ExceptionEnvelope -ExcusedStatus 'Fail'
            $acceptance = New-ExceptionAcceptance

            # Act
            $decision = Invoke-ExceptionTest -Envelope $envelope -RiskAcceptance @($acceptance, $acceptance)

            # Assert
            ('Admitted={0}:Excused={1}:Finding={2}' -f $decision.Admitted, (@($decision.Exception).ControlId -join ','), (Get-ExceptionFinding -Decision $decision)) |
                Should -BeLike ('Admitted=False:Excused=:Finding=*GoLiveExceptionDuplicated*{0}*' -f $script:ExcusedControlId) -Because 'two approvals for one control make authority depend on input order and let a caller place a weaker document first'
        }
    }

    Context 'Negative: the exception report is not something a later stage can rewrite' {

        It 'refuses assignment to the approved exception it reported' {
            # Arrange
            $envelope = New-ExceptionEnvelope -ExcusedStatus 'Fail'
            $decision = Invoke-ExceptionTest -Envelope $envelope -RiskAcceptance @((New-ExceptionAcceptance))

            # Act
            $act = { @($decision.Exception)[0].Status = 'Pass' }

            # Assert
            $act | Should -Throw -Because 'an exception a later stage can relabel a pass is an exception nobody has to retire'
        }
    }

    Context 'Positive: a complete, in-window, independently approved, correctly bound exception admits go-live' {

        It 'admits go-live and reports the excused control as an approved exception rather than as a pass' {
            # Arrange
            $envelope = New-ExceptionEnvelope -ExcusedStatus 'Fail'

            # Act
            $decision = Invoke-ExceptionTest -Envelope $envelope -RiskAcceptance @((New-ExceptionAcceptance))

            # Assert
            ('Admitted={0}:Finding={1}:Excused={2}:ExcusedStatus={3}' -f
                $decision.Admitted,
                (Get-ExceptionFinding -Decision $decision),
                (@($decision.Exception)[0].ControlId),
                (@($decision.Exception)[0].Status)) |
                Should -BeExactly ('Admitted=True:Finding=:Excused={0}:ExcusedStatus=ApprovedException' -f $script:ExcusedControlId) -Because 'a risk that was accepted rather than removed must stay visible as an accepted risk'
        }
    }
}
