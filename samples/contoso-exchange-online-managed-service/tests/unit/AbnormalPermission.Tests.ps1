#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
    $script:GatewayProfilePath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'
    Import-Module -Name $script:ModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-AbnormalPermissionDesiredState {
        [ordered]@{
            applicationPermissionAllowList = @('Mail.ReadWrite', 'User.Read.All')
            delegatedPermissionAllowList = @('openid', 'profile')
            administratorConsentRequired = $true
            userConsentAllowed = $false
            maximumAccessReviewAgeDays = 90
            maximumEvidenceAgeDays = 7
            requireSignedEvidence = $true
        }
    }

    function New-AbnormalPermissionPayload {
        param(
            [string[]]$ApplicationPermission = @('Mail.ReadWrite', 'User.Read.All'),
            [string[]]$DelegatedPermission = @('openid', 'profile'),
            [bool]$AdministratorConsentGranted = $true,
            [bool]$UserConsentAllowed = $false,
            [object[]]$UserConsentGrant = @(),
            [string]$ReviewOwner = 'identity-owner@contoso.example',
            [datetime]$ReviewedAtUtc = [datetime]::UtcNow.AddDays(-30),
            [string]$ReviewStatus = 'Completed'
        )
        [pscustomobject]@{
            ApplicationPermissions = @($ApplicationPermission)
            DelegatedPermissions = @($DelegatedPermission)
            Consent = [pscustomobject]@{
                AdministratorConsentGranted = $AdministratorConsentGranted
                UserConsentAllowed = $UserConsentAllowed
                UserConsentGrants = @($UserConsentGrant)
            }
            AccessReview = [pscustomobject]@{
                Owner = $ReviewOwner
                ReviewedAtUtc = $ReviewedAtUtc
                Status = $ReviewStatus
            }
        }
    }

    function New-AbnormalPermissionDecision {
        param(
            [bool]$Satisfied = $true,
            [object[]]$Admitted = @(),
            [object[]]$Refused = @()
        )
        if ($Admitted.Count -eq 0 -and $Satisfied) {
            $Admitted = @([pscustomobject]@{
                    Evidence = [pscustomobject]@{
                        ControlId = 'ABN-002'
                        Payload = New-AbnormalPermissionPayload
                    }
                })
        }
        [pscustomobject]@{ Satisfied = $Satisfied; Admitted = @($Admitted); Refused = @($Refused) }
    }

    function New-AbnormalPermissionRecord {
        param(
            [object]$Decision = (New-AbnormalPermissionDecision),
            [datetime]$CollectedAtUtc = [datetime]::UtcNow
        )
        New-BaselineEvidence -ControlId 'ABN-002' -Source 'ExternalEvidence' `
            -Command 'Import-BaselineExternalEvidence' -CollectedAtUtc $CollectedAtUtc `
            -Value ([ordered]@{ AbnormalPermissionImportDecision = $Decision })
    }

    function Test-GatewayPermissionSchema {
        param([object]$Profile)
        $schema = Get-Content -LiteralPath $script:SchemaPath -Raw | ConvertFrom-Json -Depth 100
        $permissionSchema = $schema.properties.desiredState.properties.abnormalSecurity.properties.permissions
        $candidate = Join-Path $TestDrive 'gateway-permissions.json'
        $subschema = Join-Path $TestDrive 'gateway-permissions.schema.json'
        $Profile.desiredState.abnormalSecurity.permissions | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $candidate -Encoding utf8NoBOM
        $permissionSchema | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $subschema -Encoding utf8NoBOM
        Test-Json -Path $candidate -SchemaFile $subschema -ErrorAction SilentlyContinue
    }

    function Get-GatewayProfileWithPermissionContract {
        $profile = Get-Content -LiteralPath $script:GatewayProfilePath -Raw | ConvertFrom-Json -Depth 100
        $profile.desiredState.abnormalSecurity | Add-Member -NotePropertyName permissions -NotePropertyValue ([pscustomobject](New-AbnormalPermissionDesiredState)) -Force
        $profile
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'ABN-002 Gateway permission desired-state contract' {
    Context 'Negative: absent, partial, permissive or invalid permission declarations' {
        It 'refuses a permissions subtree missing a contracted-feature application allow list' {
            # Arrange
            $profile = Get-GatewayProfileWithPermissionContract
            $profile.desiredState.abnormalSecurity.permissions.PSObject.Properties.Remove('applicationPermissionAllowList')

            # Act
            $actual = Test-GatewayPermissionSchema -Profile $profile

            # Assert
            $actual | Should -BeFalse
        }

        It 'refuses a permissions subtree that permits user consent' {
            # Arrange
            $profile = Get-GatewayProfileWithPermissionContract
            $profile.desiredState.abnormalSecurity.permissions.userConsentAllowed = $true

            # Act
            $actual = Test-GatewayPermissionSchema -Profile $profile

            # Assert
            $actual | Should -BeFalse
        }

        It 'refuses an access-review age beyond 90 days' {
            # Arrange
            $profile = Get-GatewayProfileWithPermissionContract
            $profile.desiredState.abnormalSecurity.permissions.maximumAccessReviewAgeDays = 91

            # Act
            $actual = Test-GatewayPermissionSchema -Profile $profile

            # Assert
            $actual | Should -BeFalse
        }
    }

    Context 'Positive: exact Gateway permission contract' {
        It 'admits the shipped Gateway profile with exact allow lists and a 90-day review bound' {
            # Arrange
            $profile = Get-Content -LiteralPath $script:GatewayProfilePath -Raw | ConvertFrom-Json -Depth 100

            # Act
            $actual = Test-GatewayPermissionSchema -Profile $profile

            # Assert
            $actual | Should -BeTrue
            @($profile.desiredState.abnormalSecurity.permissions.applicationPermissionAllowList) | Should -Be @('Mail.ReadWrite', 'User.Read.All')
            @($profile.desiredState.abnormalSecurity.permissions.delegatedPermissionAllowList) | Should -Be @('openid', 'profile')
            $profile.desiredState.abnormalSecurity.permissions.maximumAccessReviewAgeDays | Should -Be 90
        }
    }
}

Describe 'ABN-002 admitted permission evidence collection' {
    Context 'Negative: missing or refused signed evidence' {
        It 'refuses a missing EVD-008 import decision' {
            # Arrange
            $decision = $null

            # Act
            $act = { Get-AbnormalPermissionEvidence -AbnormalPermissionImportDecision $decision }

            # Assert
            $act | Should -Throw '*AbnormalPermissionImportDecisionRequired*'
        }

        It 'preserves a named unsigned-evidence refusal for evaluation' {
            # Arrange
            $decision = New-AbnormalPermissionDecision -Satisfied $false -Refused @([pscustomobject]@{ Reason = 'ExternalEvidenceSignatureMissing: detached CMS signature is absent.' })

            # Act
            $actual = Get-AbnormalPermissionEvidence -AbnormalPermissionImportDecision $decision

            # Assert
            $actual.ControlId | Should -BeExactly 'ABN-002'
            $actual.Value.AbnormalPermissionImportDecision.Refused[0].Reason | Should -Match '^ExternalEvidenceSignatureMissing:'
        }
    }

    Context 'Positive: one admitted signed permission decision' {
        It 'preserves the complete EVD-008 decision without manufacturing a verdict' {
            # Arrange
            $decision = New-AbnormalPermissionDecision

            # Act
            $actual = Get-AbnormalPermissionEvidence -AbnormalPermissionImportDecision $decision

            # Assert
            $actual.ControlId | Should -BeExactly 'ABN-002'
            $actual.Source | Should -BeExactly 'ExternalEvidence'
            $actual.Command | Should -BeExactly 'Import-BaselineExternalEvidence'
            $actual.Value.AbnormalPermissionImportDecision.Satisfied | Should -BeTrue
            $actual.Value.AbnormalPermissionImportDecision.Admitted[0].Evidence.ControlId | Should -BeExactly 'ABN-002'
        }
    }
}

Describe 'ABN-002 consent, least-privilege and access-review evaluation' {
    Context 'Negative: missing, partial, excessive, user-consented, stale or refused evidence' {
        It 'returns Error for partial evidence without an import decision' {
            # Arrange
            $evidence = New-BaselineEvidence -ControlId 'ABN-002' -Source 'ExternalEvidence' -Command 'Import-BaselineExternalEvidence' -Value ([ordered]@{})

            # Act
            $actual = Test-AbnormalPermissionControl -Evidence $evidence -DesiredState (New-AbnormalPermissionDesiredState) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^AbnormalPermissionEvidenceIncomplete:'
        }

        It 'returns Error with the named unsigned signed-evidence refusal' {
            # Arrange
            $decision = New-AbnormalPermissionDecision -Satisfied $false -Refused @([pscustomobject]@{ Reason = 'ExternalEvidenceSignatureMissing: detached CMS signature is absent.' })
            $evidence = New-AbnormalPermissionRecord -Decision $decision

            # Act
            $actual = Test-AbnormalPermissionControl -Evidence $evidence -DesiredState (New-AbnormalPermissionDesiredState) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^AbnormalPermissionEvidenceRefused:.*ExternalEvidenceSignatureMissing'
        }

        It 'returns Error with a non-signature EVD-008 refusal' {
            # Arrange
            $decision = New-AbnormalPermissionDecision -Satisfied $false -Refused @([pscustomobject]@{ Reason = 'ExternalEvidenceSignerUnauthorized: signer is not authorized.' })
            $evidence = New-AbnormalPermissionRecord -Decision $decision

            # Act
            $actual = Test-AbnormalPermissionControl -Evidence $evidence -DesiredState (New-AbnormalPermissionDesiredState) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^AbnormalPermissionEvidenceRefused:.*ExternalEvidenceSignerUnauthorized'
        }

        It 'returns Error for a partial admitted permission payload' {
            # Arrange
            $payload = New-AbnormalPermissionPayload
            $payload.PSObject.Properties.Remove('ApplicationPermissions')
            $decision = New-AbnormalPermissionDecision -Admitted @([pscustomobject]@{ Evidence = [pscustomobject]@{ ControlId = 'ABN-002'; Payload = $payload } })
            $evidence = New-AbnormalPermissionRecord -Decision $decision

            # Act
            $actual = Test-AbnormalPermissionControl -Evidence $evidence -DesiredState (New-AbnormalPermissionDesiredState) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^AbnormalPermissionEvidenceIncomplete:.*ApplicationPermissions'
        }

        It 'returns Error for stale collected evidence' {
            # Arrange
            $asOf = [datetime]::UtcNow
            $evidence = New-AbnormalPermissionRecord -CollectedAtUtc $asOf.AddDays(-8)

            # Act
            $actual = Test-AbnormalPermissionControl -Evidence $evidence -DesiredState (New-AbnormalPermissionDesiredState) -AsOfUtc $asOf

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^AbnormalPermissionEvidenceStale:'
        }

        It 'fails naming a missing contracted application permission' {
            # Arrange
            $payload = New-AbnormalPermissionPayload -ApplicationPermission @('Mail.ReadWrite')
            $decision = New-AbnormalPermissionDecision -Admitted @([pscustomobject]@{ Evidence = [pscustomobject]@{ ControlId = 'ABN-002'; Payload = $payload } })
            $evidence = New-AbnormalPermissionRecord -Decision $decision

            # Act
            $actual = Test-AbnormalPermissionControl -Evidence $evidence -DesiredState (New-AbnormalPermissionDesiredState) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^AbnormalPermissionGrantDrift:.*User\.Read\.All'
        }

        It 'fails naming an excessive delegated permission' {
            # Arrange
            $payload = New-AbnormalPermissionPayload -DelegatedPermission @('openid', 'profile', 'Mail.Read')
            $decision = New-AbnormalPermissionDecision -Admitted @([pscustomobject]@{ Evidence = [pscustomobject]@{ ControlId = 'ABN-002'; Payload = $payload } })
            $evidence = New-AbnormalPermissionRecord -Decision $decision

            # Act
            $actual = Test-AbnormalPermissionControl -Evidence $evidence -DesiredState (New-AbnormalPermissionDesiredState) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^AbnormalPermissionGrantDrift:.*Mail\.Read'
        }

        It 'fails when administrator consent has not been granted' {
            # Arrange
            $payload = New-AbnormalPermissionPayload -AdministratorConsentGranted $false
            $decision = New-AbnormalPermissionDecision -Admitted @([pscustomobject]@{ Evidence = [pscustomobject]@{ ControlId = 'ABN-002'; Payload = $payload } })
            $evidence = New-AbnormalPermissionRecord -Decision $decision

            # Act
            $actual = Test-AbnormalPermissionControl -Evidence $evidence -DesiredState (New-AbnormalPermissionDesiredState) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^AbnormalPermissionConsentDrift:.*administrator consent'
        }

        It 'fails when user consent is allowed or a user-consented grant survives' {
            # Arrange
            $payload = New-AbnormalPermissionPayload -UserConsentAllowed $true -UserConsentGrant @([pscustomobject]@{ Principal = 'user@contoso.example'; Scope = 'Mail.Read' })
            $decision = New-AbnormalPermissionDecision -Admitted @([pscustomobject]@{ Evidence = [pscustomobject]@{ ControlId = 'ABN-002'; Payload = $payload } })
            $evidence = New-AbnormalPermissionRecord -Decision $decision

            # Act
            $actual = Test-AbnormalPermissionControl -Evidence $evidence -DesiredState (New-AbnormalPermissionDesiredState) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^AbnormalPermissionConsentDrift:.*user consent'
        }

        It 'fails when the access review names no owner' {
            # Arrange
            $payload = New-AbnormalPermissionPayload -ReviewOwner ''
            $decision = New-AbnormalPermissionDecision -Admitted @([pscustomobject]@{ Evidence = [pscustomobject]@{ ControlId = 'ABN-002'; Payload = $payload } })
            $evidence = New-AbnormalPermissionRecord -Decision $decision

            # Act
            $actual = Test-AbnormalPermissionControl -Evidence $evidence -DesiredState (New-AbnormalPermissionDesiredState) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^AbnormalPermissionAccessReviewDrift:.*owner'
        }

        It 'fails when the access review is older than 90 days' {
            # Arrange
            $asOf = [datetime]::UtcNow
            $payload = New-AbnormalPermissionPayload -ReviewedAtUtc $asOf.AddDays(-91)
            $decision = New-AbnormalPermissionDecision -Admitted @([pscustomobject]@{ Evidence = [pscustomobject]@{ ControlId = 'ABN-002'; Payload = $payload } })
            $evidence = New-AbnormalPermissionRecord -Decision $decision -CollectedAtUtc $asOf

            # Act
            $actual = Test-AbnormalPermissionControl -Evidence $evidence -DesiredState (New-AbnormalPermissionDesiredState) -AsOfUtc $asOf

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^AbnormalPermissionAccessReviewStale:'
        }
    }

    Context 'Positive: exact grants, administrator consent and current named-owner review' {
        It 'passes one complete admitted record matching the contracted-feature allow lists' {
            # Arrange
            $evidence = New-AbnormalPermissionRecord

            # Act
            $actual = Test-AbnormalPermissionControl -Evidence $evidence -DesiredState (New-AbnormalPermissionDesiredState) -AsOfUtc ([datetime]::UtcNow)

            # Assert
            $actual.ControlId | Should -BeExactly 'ABN-002'
            $actual.Status | Should -BeExactly 'Pass'
            $actual.GoLiveSuccess | Should -BeTrue
        }
    }
}