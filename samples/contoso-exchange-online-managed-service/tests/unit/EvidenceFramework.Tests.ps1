#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph and ExchangeOnlineManagement are not installed and must never be imported.
    # The framework check is decided from an envelope and a catalog already in hand.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-FrameworkCatalog {
        [CmdletBinding()]
        param()

        $path = Join-Path $TestDrive ('catalog-{0}.md' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $path -Encoding utf8 -Value @(
            '| ID | Priority | Profile | Licence | Control | Desired state | Evidence | Runbook |'
            '| --- | --- | --- | --- | --- | --- | --- | --- |'
            '| EXO-001 | MUST | Both | EOP | Accepted domain | Authoritative | `Get-AcceptedDomain` | R-EXO-001 |'
            '| EXO-002 | MUST | Both | EOP | SMTP AUTH | Disabled | `Get-TransportConfig` | R-EXO-002 |'
        )

        return $path
    }

    function New-FrameworkParameter {
        [CmdletBinding()]
        param()

        $path = Join-Path $TestDrive ('parameters-{0}.json' -f [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $path -Encoding utf8 -Value '{ "primaryDomain": "contoso.com" }'
        return $path
    }

    function New-FrameworkContext {
        [CmdletBinding()]
        param()

        return [pscustomobject]@{
            DeploymentProfile = 'MicrosoftNative'
            Algorithm         = 'SHA256'
            Hash              = 'a1b2c3'
            Entitlement       = [pscustomobject]@{
                Source               = 'TenantServicePlanInventory'
                Determined           = $true
                EnabledServicePlanId = @('efb87545-963c-4e0d-99df-69c6916d9eb0')
                Capability           = @()
                NotEntitled          = @()
            }
        }
    }

    function New-FrameworkEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ControlId,

            [switch]$Failed
        )

        if ($Failed) {
            return New-BaselineEvidence -ControlId $ControlId -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value $null `
                -Failed -FailureReason "CollectionFailed: 'Get-TransportConfig' did not complete for '$ControlId'."
        }

        return New-BaselineEvidence -ControlId $ControlId -Source 'ExchangeOnline' -Command 'Get-TransportConfig' -Value @{ observed = $true }
    }

    function New-FrameworkCheck {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ControlId
        )

        return New-ControlResult -ControlId $ControlId -Status 'Pass'
    }

    function New-FrameworkEnvelope {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object[]]$Evidence,

            [Parameter(Mandatory)]
            [object[]]$Check
        )

        return New-BaselineEvidenceEnvelope -Context (New-FrameworkContext) `
            -TenantId 'f1a3b5c7-0000-4000-8000-0123456789ab' `
            -OrganizationName 'contoso.onmicrosoft.com' `
            -ParameterPath (New-FrameworkParameter) `
            -Evidence $Evidence `
            -Check $Check
    }

    function Get-FrameworkFold {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Finding
        )

        return @(
            'satisfied=' + $Finding.Satisfied
            'missingCollector=' + (@($Finding.MissingCollector) -join '+')
            'duplicatedControl=' + (@($Finding.DuplicatedControl) -join '+')
            'catalogDrift=' + (@($Finding.CatalogDrift) -join '+')
            'status=' + $Finding.Result.Status
            'goLiveSuccess=' + $Finding.Result.GoLiveSuccess
        ) -join "`n"
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EVD-005-A evidence-framework drift detection' {

    Context 'Negative: the framework check must be given something it can decide' {

        It 'refuses a check that names no catalog' {
            # Arrange
            $envelope = New-FrameworkEnvelope -Evidence @(New-FrameworkEvidence -ControlId 'EXO-001') -Check @(New-FrameworkCheck -ControlId 'EXO-001')

            # Act
            $result = { Test-BaselineEvidenceFramework -CatalogPath '  ' -Envelope $envelope }

            # Assert
            $result | Should -Throw -ExpectedMessage 'CatalogPathRequired*' -Because 'a drift check with nothing to drift from is satisfied by every run, including one that proved nothing'
        }

        It 'refuses a check that is handed no envelope' {
            # Arrange
            $catalog = New-FrameworkCatalog

            # Act
            $result = { Test-BaselineEvidenceFramework -CatalogPath $catalog -Envelope $null }

            # Assert
            $result | Should -Throw -ExpectedMessage 'FrameworkEnvelopeRequired*' -Because 'a run that produced no envelope has not covered the catalog, it has failed to start, and must never be reported as covering it'
        }

        It 'refuses an envelope that carries no evidence' {
            # Arrange
            $catalog = New-FrameworkCatalog
            $envelope = [pscustomobject]@{ Check = @(New-FrameworkCheck -ControlId 'EXO-001') }

            # Act
            $result = { Test-BaselineEvidenceFramework -CatalogPath $catalog -Envelope $envelope }

            # Assert
            $result | Should -Throw -ExpectedMessage 'FrameworkEvidenceRequired*' -Because 'verdicts with no observations behind them cannot be re-examined, so drift inside them can never be found'
        }

        It 'refuses an envelope that carries an empty evidence set' {
            # Arrange
            $catalog = New-FrameworkCatalog
            $envelope = [pscustomobject]@{ Evidence = @(); Check = @(New-FrameworkCheck -ControlId 'EXO-001') }

            # Act
            $result = { Test-BaselineEvidenceFramework -CatalogPath $catalog -Envelope $envelope }

            # Assert
            $result | Should -Throw -ExpectedMessage 'FrameworkEvidenceRequired*' -Because 'an empty set is the same silent absence as no set at all'
        }

        It 'refuses an envelope that carries no checks' {
            # Arrange
            $catalog = New-FrameworkCatalog
            $envelope = [pscustomobject]@{ Evidence = @(New-FrameworkEvidence -ControlId 'EXO-001') }

            # Act
            $result = { Test-BaselineEvidenceFramework -CatalogPath $catalog -Envelope $envelope }

            # Assert
            $result | Should -Throw -ExpectedMessage 'FrameworkCheckRequired*' -Because 'an envelope with no verdicts has nothing for the gate to fail on, so it reads as a clean run'
        }

        It 'refuses an envelope that carries an empty check set' {
            # Arrange
            $catalog = New-FrameworkCatalog
            $envelope = [pscustomobject]@{ Evidence = @(New-FrameworkEvidence -ControlId 'EXO-001'); Check = @() }

            # Act
            $result = { Test-BaselineEvidenceFramework -CatalogPath $catalog -Envelope $envelope }

            # Assert
            $result | Should -Throw -ExpectedMessage 'FrameworkCheckRequired*' -Because 'an empty set is the same silent absence as no set at all'
        }
    }

    Context 'Negative: a collector that did not run is never a clean control' {

        It 'names the control whose collector did not run and refuses it a successful go-live' {
            # Arrange
            $catalog = New-FrameworkCatalog
            $envelope = New-FrameworkEnvelope `
                -Evidence @((New-FrameworkEvidence -ControlId 'EXO-001'), (New-FrameworkEvidence -ControlId 'EXO-002' -Failed)) `
                -Check @((New-FrameworkCheck -ControlId 'EXO-001'), (New-FrameworkCheck -ControlId 'EXO-002'))
            $expected = @(
                'satisfied=False'
                'missingCollector=EXO-002'
                'duplicatedControl='
                'catalogDrift='
                'status=Error'
                'goLiveSuccess=False'
            ) -join "`n"

            # Act
            $finding = Test-BaselineEvidenceFramework -CatalogPath $catalog -Envelope $envelope

            # Assert
            (Get-FrameworkFold -Finding $finding) |
                Should -BeExactly $expected `
                    -Because 'a control whose collector failed was never observed, and a verdict reached over nothing is indistinguishable from a verdict reached over a compliant tenant'
        }
    }

    Context 'Negative: a control is observed once and decided once' {

        It 'names a control observed twice in the same envelope' {
            # Arrange
            $catalog = New-FrameworkCatalog
            $envelope = New-FrameworkEnvelope `
                -Evidence @((New-FrameworkEvidence -ControlId 'EXO-001'), (New-FrameworkEvidence -ControlId 'EXO-001'), (New-FrameworkEvidence -ControlId 'EXO-002')) `
                -Check @((New-FrameworkCheck -ControlId 'EXO-001'), (New-FrameworkCheck -ControlId 'EXO-002'))
            $expected = @(
                'satisfied=False'
                'missingCollector='
                'duplicatedControl=EXO-001'
                'catalogDrift='
                'status=Error'
                'goLiveSuccess=False'
            ) -join "`n"

            # Act
            $finding = Test-BaselineEvidenceFramework -CatalogPath $catalog -Envelope $envelope

            # Assert
            (Get-FrameworkFold -Finding $finding) |
                Should -BeExactly $expected `
                    -Because 'two observations of one control let a reader choose the one that suits them, and nothing in the artifact says which one the verdict was reached from'
        }

        It 'names a control decided twice in the same envelope' {
            # Arrange
            $catalog = New-FrameworkCatalog
            $envelope = New-FrameworkEnvelope `
                -Evidence @((New-FrameworkEvidence -ControlId 'EXO-001'), (New-FrameworkEvidence -ControlId 'EXO-002')) `
                -Check @((New-FrameworkCheck -ControlId 'EXO-001'), (New-FrameworkCheck -ControlId 'EXO-002'), (New-FrameworkCheck -ControlId 'EXO-002'))
            $expected = @(
                'satisfied=False'
                'missingCollector='
                'duplicatedControl=EXO-002'
                'catalogDrift='
                'status=Error'
                'goLiveSuccess=False'
            ) -join "`n"

            # Act
            $finding = Test-BaselineEvidenceFramework -CatalogPath $catalog -Envelope $envelope

            # Assert
            (Get-FrameworkFold -Finding $finding) |
                Should -BeExactly $expected `
                    -Because 'one control carrying two verdicts means the gate can be handed whichever verdict lets the release through'
        }
    }

    Context 'Negative: the envelope and the catalog must declare the same controls' {

        It 'names a catalog control the envelope never observed' {
            # Arrange
            $catalog = New-FrameworkCatalog
            $envelope = New-FrameworkEnvelope `
                -Evidence @(New-FrameworkEvidence -ControlId 'EXO-001') `
                -Check @((New-FrameworkCheck -ControlId 'EXO-001'), (New-FrameworkCheck -ControlId 'EXO-002'))
            $expected = @(
                'satisfied=False'
                'missingCollector='
                'duplicatedControl='
                'catalogDrift=EvidenceMissing:EXO-002'
                'status=Error'
                'goLiveSuccess=False'
            ) -join "`n"

            # Act
            $finding = Test-BaselineEvidenceFramework -CatalogPath $catalog -Envelope $envelope

            # Assert
            (Get-FrameworkFold -Finding $finding) |
                Should -BeExactly $expected `
                    -Because 'a catalog control nobody collected is the cheapest way to pass a baseline: remove the collector and the control stops failing'
        }

        It 'names a catalog control the envelope never decided' {
            # Arrange
            $catalog = New-FrameworkCatalog
            $envelope = New-FrameworkEnvelope `
                -Evidence @((New-FrameworkEvidence -ControlId 'EXO-001'), (New-FrameworkEvidence -ControlId 'EXO-002')) `
                -Check @(New-FrameworkCheck -ControlId 'EXO-001')
            $expected = @(
                'satisfied=False'
                'missingCollector='
                'duplicatedControl='
                'catalogDrift=CheckMissing:EXO-002'
                'status=Error'
                'goLiveSuccess=False'
            ) -join "`n"

            # Act
            $finding = Test-BaselineEvidenceFramework -CatalogPath $catalog -Envelope $envelope

            # Assert
            (Get-FrameworkFold -Finding $finding) |
                Should -BeExactly $expected `
                    -Because 'a control that was observed and never decided reads to the gate exactly like a control that was decided and passed'
        }

        It 'names an observed control the catalog never declared' {
            # Arrange
            $catalog = New-FrameworkCatalog
            $envelope = New-FrameworkEnvelope `
                -Evidence @((New-FrameworkEvidence -ControlId 'EXO-001'), (New-FrameworkEvidence -ControlId 'EXO-002'), (New-FrameworkEvidence -ControlId 'BAD-001')) `
                -Check @((New-FrameworkCheck -ControlId 'EXO-001'), (New-FrameworkCheck -ControlId 'EXO-002'))
            $expected = @(
                'satisfied=False'
                'missingCollector='
                'duplicatedControl='
                'catalogDrift=EvidenceUnknown:BAD-001'
                'status=Error'
                'goLiveSuccess=False'
            ) -join "`n"

            # Act
            $finding = Test-BaselineEvidenceFramework -CatalogPath $catalog -Envelope $envelope

            # Assert
            (Get-FrameworkFold -Finding $finding) |
                Should -BeExactly $expected `
                    -Because 'evidence for a control no reviewer ever approved is evidence nobody agreed to be held to, and it dilutes the controls that were'
        }

        It 'names a decided control the catalog never declared' {
            # Arrange
            $catalog = New-FrameworkCatalog
            $envelope = New-FrameworkEnvelope `
                -Evidence @((New-FrameworkEvidence -ControlId 'EXO-001'), (New-FrameworkEvidence -ControlId 'EXO-002')) `
                -Check @((New-FrameworkCheck -ControlId 'EXO-001'), (New-FrameworkCheck -ControlId 'EXO-002'), (New-FrameworkCheck -ControlId 'BAD-001'))
            $expected = @(
                'satisfied=False'
                'missingCollector='
                'duplicatedControl='
                'catalogDrift=CheckUnknown:BAD-001'
                'status=Error'
                'goLiveSuccess=False'
            ) -join "`n"

            # Act
            $finding = Test-BaselineEvidenceFramework -CatalogPath $catalog -Envelope $envelope

            # Assert
            (Get-FrameworkFold -Finding $finding) |
                Should -BeExactly $expected `
                    -Because 'a verdict on a control the catalog never declared inflates the pass count with work nobody asked for while a declared control goes undecided'
        }
    }

    Context 'Negative: the finding cannot be edited after it is decided' {

        It 'returns a finding that rejects assignment' {
            # Arrange
            $catalog = New-FrameworkCatalog
            $envelope = New-FrameworkEnvelope `
                -Evidence @((New-FrameworkEvidence -ControlId 'EXO-001'), (New-FrameworkEvidence -ControlId 'EXO-002' -Failed)) `
                -Check @((New-FrameworkCheck -ControlId 'EXO-001'), (New-FrameworkCheck -ControlId 'EXO-002'))
            $finding = Test-BaselineEvidenceFramework -CatalogPath $catalog -Envelope $envelope

            # Act
            $act = { $finding.Satisfied = $true }

            # Assert
            $act | Should -Throw -Because 'a finding a caller can rewrite turns a failed framework into a passing one without recollecting anything'
        }
    }

    Context 'Positive: a complete, duplicate-free, catalog-exact envelope is the only clean framework' {

        It 'reports no finding and a go-live-successful result' {
            # Arrange
            $catalog = New-FrameworkCatalog
            $envelope = New-FrameworkEnvelope `
                -Evidence @((New-FrameworkEvidence -ControlId 'EXO-001'), (New-FrameworkEvidence -ControlId 'EXO-002')) `
                -Check @((New-FrameworkCheck -ControlId 'EXO-001'), (New-FrameworkCheck -ControlId 'EXO-002'))
            $expected = @(
                'satisfied=True'
                'missingCollector='
                'duplicatedControl='
                'catalogDrift='
                'status=Pass'
                'goLiveSuccess=True'
            ) -join "`n"

            # Act
            $finding = Test-BaselineEvidenceFramework -CatalogPath $catalog -Envelope $envelope

            # Assert
            (Get-FrameworkFold -Finding $finding) |
                Should -BeExactly $expected `
                    -Because 'every catalog control was observed once by a collector that ran and decided once, which is the whole of what the framework claims'
        }
    }
}
