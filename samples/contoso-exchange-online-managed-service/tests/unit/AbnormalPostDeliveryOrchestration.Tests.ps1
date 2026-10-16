#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:EvidenceScript = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:ManifestPath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psd1'
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
    $script:GatewayProfilePath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'
    $script:NativeProfilePath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.microsoft-native.json'
    $script:ExpectedControl = @('ABN-001', 'ABN-002')
    $script:ExpectedCollector = @('Get-AbnormalIntegrationEvidence', 'Get-AbnormalPermissionEvidence')
    $script:ExpectedEvaluator = @('Test-AbnormalIntegrationControl', 'Test-AbnormalPermissionControl')

    function Get-AbnormalPostDeliveryBlock {
        $text = Get-Content -LiteralPath $script:EvidenceScript -Raw
        $start = $text.IndexOf('# ABN post-delivery orchestration:')
        $end = $text.IndexOf('# End ABN post-delivery orchestration', $start + 1)
        if ($start -ge 0 -and $end -gt $start) { return $text.Substring($start, $end - $start) }
        return ''
    }

    function Get-AbnormalPostDeliveryFold {
        $block = Get-AbnormalPostDeliveryBlock
        $gatewayStart = $block.IndexOf('if ($gatewayDeclared)')
        $nativeStart = $block.IndexOf('else {', $gatewayStart + 1)
        $mapStart = $block.IndexOf('$abnormalEvidenceById = @{')
        $gateway = if ($gatewayStart -ge 0 -and $nativeStart -gt $gatewayStart) { $block.Substring($gatewayStart, $nativeStart - $gatewayStart) } else { '' }
        $native = if ($nativeStart -ge 0 -and $mapStart -gt $nativeStart) { $block.Substring($nativeStart, $mapStart - $nativeStart) } else { '' }
        $map = if ($mapStart -ge 0) { $block.Substring($mapStart) } else { '' }
        [pscustomobject]@{
            Block = $block
            Gateway = $gateway
            Native = $native
            Collector = @([regex]::Matches($gateway, '(?m)\bGet-Abnormal(?:Integration|Permission)Evidence\b') | ForEach-Object Value)
            Evaluator = @([regex]::Matches($gateway, '(?m)\bTest-Abnormal(?:Integration|Permission)Control\b') | ForEach-Object Value)
            GatewayResultId = @([regex]::Matches($gateway, '(?m)Add-Check\s+[''"](?<id>ABN-[0-9]{3})[^''"]*[''"]\s+\$[^\r\n]+\.Status\s+\$[^\r\n]+\.Reason') | ForEach-Object { $_.Groups['id'].Value })
            NativeResultId = @([regex]::Matches($native, '(?m)Add-Check\s+[''"](?<id>ABN-[0-9]{3})[^''"]*[''"]\s+[''"]NotApplicable[''"]') | ForEach-Object { $_.Groups['id'].Value })
            AllId = @([regex]::Matches($block, 'ABN-[0-9]{3}') | ForEach-Object Value | Sort-Object -Unique)
            MappedId = @([regex]::Matches($map, "'(?<id>ABN-[0-9]{3})'") | ForEach-Object { $_.Groups['id'].Value })
            Manual = [regex]::Matches($block, '(?m)Add-Check\s+[''"]ABN-[0-9]{3}[^''"]*[''"]\s+[''"]Manual[''"]').Count
            Inline = [regex]::Matches($block, '(?m)Add-Result\s+[''"]ABN-[0-9]{3}').Count
        }
    }

    function Invoke-AbnormalPostDeliveryFixture {
        param(
            [Parameter(Mandatory)]
            [object]$Fixture,

            [Parameter(Mandatory)]
            [object]$GatewayConfiguration,

            [Parameter(Mandatory)]
            [datetime]$AsOfUtc
        )

        Import-Module $script:ModulePath -Force -DisableNameChecking
        $integrationEvidence = Get-AbnormalIntegrationEvidence `
            -AbnormalIntegrationImportDecision $Fixture.IntegrationDecision `
            -CollectedAtUtc $AsOfUtc.AddMinutes(-10)
        $integrationResult = Test-AbnormalIntegrationControl -Evidence $integrationEvidence `
            -DesiredState $GatewayConfiguration.desiredState.abnormalSecurity.integration -AsOfUtc $AsOfUtc

        $permissionEvidence = Get-AbnormalPermissionEvidence `
            -AbnormalPermissionImportDecision $Fixture.PermissionDecision `
            -CollectedAtUtc $AsOfUtc.AddMinutes(-10)
        $permissionResult = Test-AbnormalPermissionControl -Evidence $permissionEvidence `
            -DesiredState $GatewayConfiguration.desiredState.abnormalSecurity.permissions -AsOfUtc $AsOfUtc

        [pscustomobject]@{
            Result = @($integrationResult, $permissionResult)
            Fold = Get-AbnormalPostDeliveryFold
        }
    }
}

Describe 'ABN-003 parent configuration and public surface' {
    Context 'Negative: the parent composes both sibling contracts and exports both operation pairs' {
        It 'rejects an abnormalSecurity parent that does not require exactly integration and permissions' {
            # Arrange
            $schema = Get-Content -LiteralPath $script:SchemaPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100

            # Act
            $actual = $schema.properties.desiredState.properties.abnormalSecurity

            # Assert
            @($actual.required | Sort-Object) | Should -Be @('integration', 'permissions')
            @($actual.properties.Keys) | Should -Contain 'integration'
            @($actual.properties.Keys) | Should -Contain 'permissions'
        }

        It 'rejects a shared ABN collector or evaluator missing from either export declaration' {
            # Arrange
            $manifest = Import-PowerShellDataFile -LiteralPath $script:ManifestPath
            $moduleText = Get-Content -LiteralPath $script:ModulePath -Raw
            $exportText = $moduleText.Substring($moduleText.LastIndexOf('Export-ModuleMember -Function @('))
            $expected = @($script:ExpectedCollector + $script:ExpectedEvaluator | Sort-Object)

            # Act
            $manifestActual = @($expected | Where-Object { $_ -cin @($manifest.FunctionsToExport) })
            $moduleActual = @($expected | Where-Object { $exportText -match "'$([regex]::Escape($_))'" })

            # Assert
            $manifestActual | Should -Be $expected
            $moduleActual | Should -Be $expected
        }
    }

    Context 'Positive: one complete composed and exported ABN surface' {
        It 'composes both sibling contracts and exports both operation pairs' {
            # Arrange
            $schema = Get-Content -LiteralPath $script:SchemaPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100
            $manifest = Import-PowerShellDataFile -LiteralPath $script:ManifestPath
            $moduleText = Get-Content -LiteralPath $script:ModulePath -Raw
            $parent = $schema.properties.desiredState.properties.abnormalSecurity
            $expectedOperation = @($script:ExpectedCollector + $script:ExpectedEvaluator | Sort-Object)

            # Act
            $actual = 'required={0};integration={1};permissions={2};manifest={3};module={4}' -f `
                (@($parent.required | Sort-Object) -join ','),
                $parent.properties.ContainsKey('integration'),
                $parent.properties.ContainsKey('permissions'),
                (@($expectedOperation | Where-Object { $_ -cin @($manifest.FunctionsToExport) }) -join ','),
                (@($expectedOperation | Where-Object { $moduleText.Substring($moduleText.LastIndexOf('Export-ModuleMember -Function @(')) -match "'$([regex]::Escape($_))'" }) -join ',')

            # Assert
            $actual | Should -BeExactly ('required=integration,permissions;integration=True;permissions=True;manifest={0};module={0}' -f ($expectedOperation -join ','))
        }
    }
}

Describe 'ABN-003 Gateway-only applicability' {
    Context 'Negative: ABN applies only to the Gateway profile' {
        It 'rejects Native ABN results that are not exclusively NotApplicable' {
            # Arrange
            $fold = Get-AbnormalPostDeliveryFold

            # Act
            $actual = @($fold.NativeResultId | Sort-Object) -join ','

            # Assert
            $actual | Should -BeExactly ($script:ExpectedControl -join ',')
            $fold.Native | Should -Not -Match '\b(Get|Test)-Abnormal(?:Integration|Permission)(?:Evidence|Control)\b'
        }
    }

    Context 'Positive: one exact Gateway and Native applicability projection' {
        It 'assigns both controls only to Gateway and emits only Native NotApplicable results' {
            # Arrange
            Import-Module $script:ModulePath -Force -DisableNameChecking
            $registry = @(Get-BaselineControlRegistry -Profile Historical)[0]
            $gateway = Get-Content -LiteralPath $script:GatewayProfilePath -Raw | ConvertFrom-Json -Depth 100
            $native = Get-Content -LiteralPath $script:NativeProfilePath -Raw | ConvertFrom-Json -Depth 100
            $fold = Get-AbnormalPostDeliveryFold

            # Act
            $actual = 'registry={0};gateway={1};native={2};nativeResult={3}' -f `
                (@($registry | Where-Object ControlId -like 'ABN-*' | ForEach-Object { '{0}|{1}' -f $_.ControlId, (@($_.ApplicableProfile) -join ',') } | Sort-Object) -join ','),
                (@($gateway.desiredState.PSObject.Properties.Name) -ccontains 'abnormalSecurity'),
                (@($native.desiredState.PSObject.Properties.Name) -ccontains 'abnormalSecurity'),
                (@($fold.NativeResultId | Sort-Object) -join ',')

            # Assert
            $actual | Should -BeExactly 'registry=ABN-001|Gateway,ABN-002|Gateway;gateway=True;native=False;nativeResult=ABN-001,ABN-002'
        }
    }
}

Describe 'ABN-003 exact public orchestration' {
    Context 'Negative: every Gateway result uses one registered pair and one evidence record' {
        It 'rejects missing or duplicate ABN collectors' {
            # Arrange
            $fold = Get-AbnormalPostDeliveryFold

            # Act
            $actual = @($fold.Collector | Sort-Object) -join ','

            # Assert
            $actual | Should -BeExactly ($script:ExpectedCollector -join ',')
        }

        It 'rejects missing or duplicate ABN evaluators' {
            # Arrange
            $fold = Get-AbnormalPostDeliveryFold

            # Act
            $actual = @($fold.Evaluator | Sort-Object) -join ','

            # Assert
            $actual | Should -BeExactly ($script:ExpectedEvaluator -join ',')
        }

        It 'rejects missing, duplicate, or unknown Gateway ABN results' {
            # Arrange
            $fold = Get-AbnormalPostDeliveryFold

            # Act
            $actual = @($fold.GatewayResultId | Sort-Object) -join ','

            # Assert
            $actual | Should -BeExactly ($script:ExpectedControl -join ',')
            (@($fold.AllId) -join ',') | Should -BeExactly ($script:ExpectedControl -join ',')
        }

        It 'rejects a missing or duplicate ABN evidence-map entry' {
            # Arrange
            $fold = Get-AbnormalPostDeliveryFold

            # Act
            $actual = @($fold.MappedId | Sort-Object) -join ','

            # Assert
            $actual | Should -BeExactly ($script:ExpectedControl -join ',')
        }

        It 'rejects inline or Manual ABN verdicts' {
            # Arrange
            $fold = Get-AbnormalPostDeliveryFold

            # Act
            $actual = 'manual={0};inline={1};evaluated={2}' -f $fold.Manual, $fold.Inline, $fold.Evaluator.Count

            # Assert
            $actual | Should -BeExactly 'manual=0;inline=0;evaluated=2'
        }
    }

    Context 'Positive: one complete admitted signed Gateway fixture' {
        It 'passes both controls through one exact collector/evaluator and evidence-map dispatch' {
            # Arrange
            $asOfUtc = [datetime]::new(2026, 9, 19, 12, 0, 0, [System.DateTimeKind]::Utc)
            $gateway = Get-Content -LiteralPath $script:GatewayProfilePath -Raw | ConvertFrom-Json -Depth 100
            $fixture = [pscustomobject]@{
                IntegrationDecision = [pscustomobject]@{
                    Satisfied = $true
                    Refused = @()
                    Admitted = @([pscustomobject]@{
                            EvidenceId = 'evd-abn-001-signed'
                            Evidence = [pscustomobject]@{
                                ControlId = 'ABN-001'
                                Payload = [pscustomobject]@{
                                    Complete = $true
                                    Integration = [pscustomobject]@{ Mode = 'Microsoft API post-delivery'; SmtpConnectorCreated = $false; JournalRuleCreated = $false; SclBypassCreated = $false; TransportExceptionCreated = $false }
                                    VendorHealth = [pscustomobject]@{ Status = 'Healthy'; CheckedAtUtc = $asOfUtc.AddMinutes(-30) }
                                    FunctionalTest = [pscustomobject]@{ TestedAtUtc = $asOfUtc.AddHours(-2); Detection = $true; Removal = $true; Restoration = $true; AuditAttribution = $true; AuditActor = 'abnormal-service-principal'; AuditRecordId = 'audit-abn-001' }
                                }
                            }
                        })
                }
                PermissionDecision = [pscustomobject]@{
                    Satisfied = $true
                    Refused = @()
                    Admitted = @([pscustomobject]@{
                            EvidenceId = 'evd-abn-002-signed'
                            Evidence = [pscustomobject]@{
                                ControlId = 'ABN-002'
                                Payload = [pscustomobject]@{
                                    ApplicationPermissions = @('Mail.ReadWrite', 'User.Read.All')
                                    DelegatedPermissions = @('openid', 'profile')
                                    Consent = [pscustomobject]@{ AdministratorConsentGranted = $true; UserConsentAllowed = $false; UserConsentGrants = @() }
                                    AccessReview = [pscustomobject]@{ Owner = 'identity-owner@contoso.example'; ReviewedAtUtc = $asOfUtc.AddDays(-30); Status = 'Completed' }
                                }
                            }
                        })
                }
            }

            # Act
            $actual = Invoke-AbnormalPostDeliveryFixture -Fixture $fixture -GatewayConfiguration $gateway -AsOfUtc $asOfUtc

            # Assert
            @($actual.Result.ControlId) | Should -Be $script:ExpectedControl
            @($actual.Result.Status) | Should -Be @('Pass', 'Pass')
            (@($actual.Fold.Collector | Sort-Object) -join ',') | Should -BeExactly ($script:ExpectedCollector -join ',')
            (@($actual.Fold.Evaluator | Sort-Object) -join ',') | Should -BeExactly ($script:ExpectedEvaluator -join ',')
            (@($actual.Fold.GatewayResultId | Sort-Object) -join ',') | Should -BeExactly ($script:ExpectedControl -join ',')
            (@($actual.Fold.MappedId | Sort-Object) -join ',') | Should -BeExactly ($script:ExpectedControl -join ',')
            $actual.Fold.Manual | Should -Be 0
            $actual.Fold.Inline | Should -Be 0
        }
    }
}