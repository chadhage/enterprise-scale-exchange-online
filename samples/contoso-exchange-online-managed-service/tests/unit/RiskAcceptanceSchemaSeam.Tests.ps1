#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:ShippedSchemaPath = Join-Path $script:SampleRoot 'config' 'risk-acceptance.schema.json'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-ConformingRiskAcceptance {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{},
            [string[]]$Omit = @()
        )

        $member = [ordered]@{
            ControlId           = 'EXO-004'
            TenantId            = '00000000-1111-2222-3333-444444444444'
            ConfigurationHash   = 'a3f1c9d2b4e6708192a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f809'
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
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GATE-002-A2 the risk-acceptance schema seam' {
    BeforeAll {
        $script:FixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('risk-acceptance-seam-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:FixtureRoot -Force | Out-Null
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:FixtureRoot) {
            Remove-Item -LiteralPath $script:FixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'the seam must refuse input it cannot read' {
        It 'refuses a check that is handed no acceptance' {
            # Arrange
            $missing = $null

            # Act
            $act = { Test-RiskAcceptanceDocument -RiskAcceptance $missing -SchemaPath $script:ShippedSchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RiskAcceptanceNotProvided*'
        }

        It 'refuses an acceptance that is not an object at all' {
            # Arrange
            $notAnObject = 'CHG0012345'

            # Act
            $act = { Test-RiskAcceptanceDocument -RiskAcceptance $notAnObject -SchemaPath $script:ShippedSchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RiskAcceptanceNotAnObject*'
        }

        It 'refuses a check that names no schema' {
            # Arrange
            $riskAcceptance = New-ConformingRiskAcceptance

            # Act
            $act = { Test-RiskAcceptanceDocument -RiskAcceptance $riskAcceptance -SchemaPath '' }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RiskAcceptanceSchemaPathRequired*'
        }

        It 'refuses a schema path that names no file' {
            # Arrange
            $absent = Join-Path $script:FixtureRoot 'no-such-schema.json'

            # Act
            $act = { Test-RiskAcceptanceDocument -RiskAcceptance (New-ConformingRiskAcceptance) -SchemaPath $absent }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RiskAcceptanceSchemaNotFound*'
        }

        It 'refuses a schema file that is not valid JSON' {
            # Arrange
            $broken = Join-Path $script:FixtureRoot 'broken-schema.json'
            Set-Content -LiteralPath $broken -Value '{ "type": "object", ' -Encoding utf8

            # Act
            $act = { Test-RiskAcceptanceDocument -RiskAcceptance (New-ConformingRiskAcceptance) -SchemaPath $broken }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RiskAcceptanceSchemaJsonInvalid*'
        }

        It 'refuses a schema file that is not a usable JSON Schema' {
            # Arrange
            $notASchema = Join-Path $script:FixtureRoot 'not-a-schema.json'
            Set-Content -LiteralPath $notASchema -Value '{ "type": 42 }' -Encoding utf8

            # Act
            $act = { Test-RiskAcceptanceDocument -RiskAcceptance (New-ConformingRiskAcceptance) -SchemaPath $notASchema }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RiskAcceptanceSchemaNotUsable*'
        }
    }

    Context 'an acceptance the published schema rejects' {
        It 'reports an acceptance missing a demanded field as not conforming' {
            # Arrange
            $riskAcceptance = New-ConformingRiskAcceptance -Omit @('CompensatingControl')

            # Act
            $result = Test-RiskAcceptanceDocument -RiskAcceptance $riskAcceptance -SchemaPath $script:ShippedSchemaPath

            # Assert
            $result.Conforms | Should -BeFalse -Because 'the seam exists so that a document the schema refuses never reaches the semantic checks looking like an acceptance'
        }

        It 'reports an acceptance carrying a member the schema never declared as not conforming' {
            # Arrange
            $riskAcceptance = New-ConformingRiskAcceptance -Override @{ PermanentWaiver = $true }

            # Act
            $result = Test-RiskAcceptanceDocument -RiskAcceptance $riskAcceptance -SchemaPath $script:ShippedSchemaPath

            # Assert
            $result.Conforms | Should -BeFalse -Because 'a surplus member is a term nobody agreed to and no reader is looking for'
        }

        It 'carries the violation the schema reported back to the caller' {
            # Arrange
            $riskAcceptance = New-ConformingRiskAcceptance -Omit @('CompensatingControl')

            # Act
            $result = Test-RiskAcceptanceDocument -RiskAcceptance $riskAcceptance -SchemaPath $script:ShippedSchemaPath

            # Assert
            $result.Violation | Should -Not -BeNullOrEmpty -Because 'a refusal that will not say what it refused cannot be acted on by the person holding the document'
        }

        It 'names the schema it held the acceptance to' {
            # Arrange
            $riskAcceptance = New-ConformingRiskAcceptance -Omit @('CompensatingControl')

            # Act
            $result = Test-RiskAcceptanceDocument -RiskAcceptance $riskAcceptance -SchemaPath $script:ShippedSchemaPath

            # Assert
            $result.SchemaPath | Should -BeLike '*risk-acceptance.schema.json' -Because 'a verdict that does not say which contract it applied cannot be re-decided by a reviewer'
        }
    }

    Context 'the verdict is a record nothing downstream can edit' {
        It 'refuses assignment to the conformance verdict' {
            # Arrange
            $result = Test-RiskAcceptanceDocument -RiskAcceptance (New-ConformingRiskAcceptance) -SchemaPath $script:ShippedSchemaPath

            # Act
            $act = { $result.Conforms = $false }

            # Assert
            $act | Should -Throw -Because 'a schema verdict a later stage can rewrite is a verdict nobody can rely on'
        }
    }

    Context 'a conforming acceptance' {
        It 'reports a complete, correctly shaped acceptance as conforming' {
            # Arrange
            $riskAcceptance = New-ConformingRiskAcceptance

            # Act
            $result = Test-RiskAcceptanceDocument -RiskAcceptance $riskAcceptance -SchemaPath $script:ShippedSchemaPath

            # Assert
            $result.Conforms | Should -BeTrue -Because "a seam that refuses every acceptance blocks every exception ever raised, but this one reported '$($result.Violation -join '; ')'"
        }
    }
}
