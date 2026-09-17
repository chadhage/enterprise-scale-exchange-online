#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ControlId = 'EXO-004'
    $script:TenantId = '00000000-1111-2222-3333-444444444444'
    $script:ConfigurationHash = 'a3f1c9d2b4e6708192a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f809'
    $script:RequestedBy = 'operator@contoso.example'
    $script:AsOf = [datetime]::new(2026, 9, 17, 12, 0, 0, [System.DateTimeKind]::Utc)

    function New-RiskAcceptance {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{},
            [string[]]$Omit = @()
        )

        $member = [ordered]@{
            ControlId           = $script:ControlId
            TenantId            = $script:TenantId
            ConfigurationHash   = $script:ConfigurationHash
            Owner               = 'messaging-lead@contoso.example'
            Justification       = 'The legacy archive connector cannot honour the forwarding block until it is retired.'
            CompensatingControl = @('Daily forwarding report reviewed by SecOps', 'Conditional Access blocks legacy clients')
            ExternalReference   = 'CHG0012345'
            ApprovalIdentity    = 'ciso@contoso.example'
            ApprovalAuthority   = 'ExchangeOnlineChangeApproval'
            ApprovalTimeUtc     = [datetime]::new(2026, 9, 10, 9, 0, 0, [System.DateTimeKind]::Utc)
            EffectiveTimeUtc    = [datetime]::new(2026, 9, 11, 0, 0, 0, [System.DateTimeKind]::Utc)
            ExpiryTimeUtc       = [datetime]::new(2026, 12, 11, 0, 0, 0, [System.DateTimeKind]::Utc)
            Signature           = [pscustomobject]@{
                Model = 'DetachedCms'
                Value = 'MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExDzANBglghkgBZQMEAgEFADA='
            }
        }

        foreach ($name in $Omit) {
            $member.Remove($name)
        }

        foreach ($name in $Override.Keys) {
            $member[$name] = $Override[$name]
        }

        return [pscustomobject]$member
    }

    function Invoke-RiskAcceptanceTest {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [object]$RiskAcceptance
        )

        return Test-RiskAcceptance -RiskAcceptance $RiskAcceptance -ControlId $script:ControlId -TenantId $script:TenantId -ConfigurationHash $script:ConfigurationHash -RequestedBy $script:RequestedBy -AsOf $script:AsOf
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'COM-005-A3 risk acceptance validation' {

    Context 'Negative: the validation must refuse input it cannot read' {

        It 'fails with RiskAcceptanceNotProvided when the risk acceptance is null' {
            # Arrange
            $missing = $null

            # Act
            $act = { Invoke-RiskAcceptanceTest -RiskAcceptance $missing }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RiskAcceptanceNotProvided*'
        }

        It 'fails with RiskAcceptanceNotAnObject when the risk acceptance is not an object' {
            # Arrange
            $notAnObject = 'CHG0012345'

            # Act
            $act = { Invoke-RiskAcceptanceTest -RiskAcceptance $notAnObject }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RiskAcceptanceNotAnObject*'
        }
    }

    Context 'Negative: an incomplete risk acceptance is never valid' {

        It 'rejects a risk acceptance that omits <_>' -ForEach @(
            'Owner'
            'Justification'
            'CompensatingControl'
            'ExternalReference'
            'ApprovalIdentity'
            'ApprovalAuthority'
            'ApprovalTimeUtc'
        ) {
            # Arrange
            $riskAcceptance = New-RiskAcceptance -Omit @($_)

            # Act
            $result = Invoke-RiskAcceptanceTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Reason | Should -BeExactly ('IncompleteRiskAcceptance: the risk acceptance does not declare ''{0}''.' -f $_)
        }
    }

    Context 'Negative: a risk acceptance bound elsewhere is never valid' {

        It 'rejects a risk acceptance raised for another control' {
            # Arrange
            $riskAcceptance = New-RiskAcceptance -Override @{ ControlId = 'EXO-009' }

            # Act
            $result = Invoke-RiskAcceptanceTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Valid | Should -BeFalse
        }

        It 'rejects a risk acceptance raised for another tenant' {
            # Arrange
            $riskAcceptance = New-RiskAcceptance -Override @{ TenantId = '99999999-8888-7777-6666-555555555555' }

            # Act
            $result = Invoke-RiskAcceptanceTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Valid | Should -BeFalse
        }

        It 'rejects a risk acceptance raised against another configuration hash' {
            # Arrange
            $riskAcceptance = New-RiskAcceptance -Override @{ ConfigurationHash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' }

            # Act
            $result = Invoke-RiskAcceptanceTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Valid | Should -BeFalse
        }
    }

    Context 'Negative: approval authority must be independent and approved' {

        It 'rejects a risk acceptance approved outside the change-approval role' {
            # Arrange
            $riskAcceptance = New-RiskAcceptance -Override @{ ApprovalAuthority = 'ServiceDeskTeamLead' }

            # Act
            $result = Invoke-RiskAcceptanceTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Valid | Should -BeFalse
        }

        It 'rejects a risk acceptance approved by the operator requesting the change' {
            # Arrange
            $riskAcceptance = New-RiskAcceptance -Override @{ ApprovalIdentity = $script:RequestedBy }

            # Act
            $result = Invoke-RiskAcceptanceTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Valid | Should -BeFalse
        }
    }

    Context 'Negative: a risk acceptance outside its window is never valid' {

        It 'rejects a risk acceptance that is not yet effective at the evaluation time' {
            # Arrange
            $riskAcceptance = New-RiskAcceptance -Override @{ EffectiveTimeUtc = $script:AsOf.AddDays(1) }

            # Act
            $result = Invoke-RiskAcceptanceTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Valid | Should -BeFalse
        }

        It 'rejects a risk acceptance that has expired at the evaluation time' {
            # Arrange
            $riskAcceptance = New-RiskAcceptance -Override @{ ExpiryTimeUtc = $script:AsOf.AddSeconds(-1) }

            # Act
            $result = Invoke-RiskAcceptanceTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Valid | Should -BeFalse
        }
    }

    Context 'Negative: the signature must match the selected model' {

        It 'rejects a risk acceptance that carries no signature' {
            # Arrange
            $riskAcceptance = New-RiskAcceptance -Omit @('Signature')

            # Act
            $result = Invoke-RiskAcceptanceTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Valid | Should -BeFalse
        }

        It 'rejects a risk acceptance signed with a model other than the selected model' {
            # Arrange
            $riskAcceptance = New-RiskAcceptance -Override @{ Signature = [pscustomobject]@{ Model = 'ExternalTicketEvidence'; Value = 'CHG0012345' } }

            # Act
            $result = Invoke-RiskAcceptanceTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Valid | Should -BeFalse
        }

        It 'rejects a risk acceptance whose signature carries no value' {
            # Arrange
            $riskAcceptance = New-RiskAcceptance -Override @{ Signature = [pscustomobject]@{ Model = 'DetachedCms'; Value = '' } }

            # Act
            $result = Invoke-RiskAcceptanceTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Valid | Should -BeFalse
        }
    }

    Context 'Positive: a complete, bound, in-window, independently approved exception is honoured' {

        It 'judges a correctly signed risk acceptance valid and yields the approved exception status' {
            # Arrange
            $riskAcceptance = New-RiskAcceptance

            # Act
            $result = Invoke-RiskAcceptanceTest -RiskAcceptance $riskAcceptance

            # Assert
            ('{0}:Valid={1}:Status={2}' -f $result.ControlId, $result.Valid, $result.Status) | Should -BeExactly 'EXO-004:Valid=True:Status=ApprovedException'
        }
    }
}
