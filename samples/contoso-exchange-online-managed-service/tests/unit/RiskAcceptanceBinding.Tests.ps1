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
    $script:DeploymentProfile = 'MicrosoftNative'
    $script:BaselineVersion = [string](Get-ArtifactVersionContract).BaselineVersion

    function New-BoundRiskAcceptance {
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
            CompensatingControl = @('Daily forwarding report reviewed by SecOps')
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

        foreach ($name in $Omit) { $member.Remove($name) }
        foreach ($name in $Override.Keys) { $member[$name] = $Override[$name] }

        return [pscustomobject]$member
    }

    function New-BoundedApplicability {
        [CmdletBinding()]
        param(
            [string]$DeploymentProfile = $script:DeploymentProfile,
            [string]$BaselineVersion = $script:BaselineVersion,
            [string[]]$BoundedBy = @('Legacy archive connector retirement, tracked under CHG0012345')
        )

        return [pscustomobject]@{
            DeploymentProfile = $DeploymentProfile
            BaselineVersion   = $BaselineVersion
            BoundedBy         = @($BoundedBy)
        }
    }

    function Invoke-BindingTest {
        [CmdletBinding()]
        param(
            [AllowNull()]
            [object]$RiskAcceptance
        )

        return Test-RiskAcceptance -RiskAcceptance $RiskAcceptance `
            -ControlId $script:ControlId `
            -TenantId $script:TenantId `
            -ConfigurationHash $script:ConfigurationHash `
            -RequestedBy $script:RequestedBy `
            -AsOf $script:AsOf `
            -DeploymentProfile $script:DeploymentProfile `
            -BaselineVersion $script:BaselineVersion
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GATE-002-A3 bounded applicability in place of the configuration hash' {

    Context 'the published schema is consulted by the validation itself' {
        It 'refuses an acceptance the published schema rejects' {
            # Arrange
            $riskAcceptance = New-BoundRiskAcceptance -Override @{ PermanentWaiver = $true }

            # Act
            $result = Invoke-BindingTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Reason | Should -BeLike 'RiskAcceptanceSchemaViolation:*' -Because 'a validation that never applies the published schema leaves the schema as documentation nobody enforces'
        }
    }

    Context 'an acceptance bound to nothing' {
        It 'refuses an acceptance carrying neither a configuration hash nor a bounded applicability' {
            # Arrange
            $riskAcceptance = New-BoundRiskAcceptance -Omit @('ConfigurationHash')

            # Act
            $result = Invoke-BindingTest -RiskAcceptance $riskAcceptance

            # Assert
            ('Valid={0}:Reason={1}' -f $result.Valid, $result.Reason) | Should -BeLike 'Valid=False:Reason=RiskAcceptanceSchemaViolation:*' -Because 'an exception bound to nothing at all applies to every configuration this tenant will ever hold, and the schema is where that rule is published'
        }
    }

    Context 'an applicability that does not cover this run' {
        It 'refuses a bounded applicability naming another deployment profile' {
            # Arrange
            $riskAcceptance = New-BoundRiskAcceptance -Omit @('ConfigurationHash') -Override @{
                AppliesTo = New-BoundedApplicability -DeploymentProfile 'ThirdPartyGateway'
            }

            # Act
            $result = Invoke-BindingTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Reason | Should -BeLike 'ApplicabilityProfileMismatch:*' -Because 'the native and gateway profiles are held to different controls, so an exception raised under one says nothing about the other'
        }

        It 'names both the profile the acceptance is bound to and the profile the run is' {
            # Arrange
            $riskAcceptance = New-BoundRiskAcceptance -Omit @('ConfigurationHash') -Override @{
                AppliesTo = New-BoundedApplicability -DeploymentProfile 'ThirdPartyGateway'
            }

            # Act
            $result = Invoke-BindingTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Reason | Should -BeLike "*ThirdPartyGateway*$($script:DeploymentProfile)*" -Because 'a refusal that names neither side leaves the reader to guess which of the two is wrong'
        }

        It 'refuses a bounded applicability naming another baseline version' {
            # Arrange
            $riskAcceptance = New-BoundRiskAcceptance -Omit @('ConfigurationHash') -Override @{
                AppliesTo = New-BoundedApplicability -BaselineVersion '9.9.9'
            }

            # Act
            $result = Invoke-BindingTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Reason | Should -BeLike 'ApplicabilityBaselineMismatch:*' -Because 'an exception that outlives the baseline it was raised against is an exception nobody re-reviewed'
        }

        It 'refuses a bounded applicability whose boundary names nothing at all' {
            # Arrange
            $riskAcceptance = New-BoundRiskAcceptance -Omit @('ConfigurationHash') -Override @{
                AppliesTo = New-BoundedApplicability -BoundedBy @()
            }

            # Act
            $result = Invoke-BindingTest -RiskAcceptance $riskAcceptance

            # Assert
            ('Valid={0}:Reason={1}' -f $result.Valid, $result.Reason) | Should -BeLike 'Valid=False:Reason=RiskAcceptanceSchemaViolation:*' -Because 'an empty boundary is the word bounded without the fact, and the schema is where that rule is published'
        }
    }

    Context 'an applicability the run cannot be measured against' {
        It 'refuses an applicability-bound acceptance when the run states no deployment profile or baseline version' {
            # Arrange
            $riskAcceptance = New-BoundRiskAcceptance -Omit @('ConfigurationHash') -Override @{ AppliesTo = New-BoundedApplicability }

            # Act
            $result = Test-RiskAcceptance -RiskAcceptance $riskAcceptance `
                -ControlId $script:ControlId `
                -TenantId $script:TenantId `
                -ConfigurationHash $script:ConfigurationHash `
                -RequestedBy $script:RequestedBy `
                -AsOf $script:AsOf

            # Assert
            $result.Reason | Should -BeLike 'ApplicabilityRunContextRequired:*' -Because 'an applicability measured against a run that names neither profile nor baseline is an applicability measured against nothing'
        }
    }

    Context 'an applicability cannot rescue a hash bound elsewhere' {
        It 'refuses an acceptance whose configuration hash is bound to another configuration even when its applicability matches' {
            # Arrange
            $riskAcceptance = New-BoundRiskAcceptance -Override @{
                ConfigurationHash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
                AppliesTo         = New-BoundedApplicability
            }

            # Act
            $result = Invoke-BindingTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Reason | Should -BeLike "ConfigurationHashMismatch:*ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff*$($script:ConfigurationHash)*" -Because 'the looser of two stated bindings must never be able to excuse the tighter one failing, and a refusal that names neither hash cannot be acted on'
        }
    }

    Context 'the configuration-hash binding still holds' {
        It 'refuses an acceptance raised against another configuration hash' {
            # Arrange
            $riskAcceptance = New-BoundRiskAcceptance -Override @{ ConfigurationHash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' }

            # Act
            $result = Invoke-BindingTest -RiskAcceptance $riskAcceptance

            # Assert
            $result.Valid | Should -BeFalse -Because 'making applicability an alternative must not quietly stop the hash from being checked'
        }
    }

    Context 'an acceptance bound by applicability alone' {
        It 'honours an acceptance whose applicability is explicitly bounded to this run' {
            # Arrange
            $riskAcceptance = New-BoundRiskAcceptance -Omit @('ConfigurationHash') -Override @{ AppliesTo = New-BoundedApplicability }

            # Act
            $result = Invoke-BindingTest -RiskAcceptance $riskAcceptance

            # Assert
            ('Valid={0}:Status={1}' -f $result.Valid, $result.Status) | Should -BeExactly 'Valid=True:Status=ApprovedException' -Because "an exception bound to this profile and this baseline is bound to this run, but it reported '$($result.Reason)'"
        }
    }
}
