#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:TenantId = '00000000-1111-2222-3333-444444444444'
    $script:ConfigurationHash = 'a3f1c9d2b4e6708192a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f809'
    $script:AsOf = [datetimeoffset]::new(2026, 9, 19, 12, 0, 0, [timespan]::Zero)

    function New-RbacPimFallbackFixture {
        param([hashtable]$Override = @{})

        $payload = [ordered]@{
            SchemaVersion = '1.0.0'
            TenantId = $script:TenantId
                GeneratedAtUtc = $script:AsOf.AddMinutes(-5).UtcDateTime.ToString('o')
            RoleGroup = @([ordered]@{
                    Name = 'Organization Management'
                    Members = @('admin@contoso.example')
                    WhenChangedUtc = $script:AsOf.AddDays(-1).UtcDateTime.ToString('o')
                })
            ManagementRoleAssignment = @([ordered]@{
                    Role = 'Organization Management'
                    RoleAssigneeName = 'Organization Management'
                    RoleAssigneeType = 'RoleGroup'
                    RecipientWriteScope = 'Organization'
                })
            ActivePimAssignment = @([ordered]@{
                    PrincipalId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
                    RoleDefinitionId = 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff'
                    EndDateTime = $script:AsOf.AddHours(1).UtcDateTime.ToString('o')
                    MemberType = 'Direct'
                })
            EligiblePimAssignment = @([ordered]@{
                    PrincipalId = 'cccccccc-dddd-4eee-8fff-000000000000'
                    RoleDefinitionId = 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff'
                    StartDateTime = $script:AsOf.AddDays(-30).UtcDateTime.ToString('o')
                })
            AccessReview = @([ordered]@{
                    DisplayName = 'exchange-rbac-quarterly'
                    ScopeRoleDefinitionId = 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff'
                    LastCompletedDateTime = $script:AsOf.AddDays(-15).UtcDateTime.ToString('o')
                    CreatedBy = 'identity-governance@contoso.example'
                })
        }
        $document = [ordered]@{
            SchemaVersion = '1.0.0'
            EvidenceId = '11111111-2222-4333-8444-555555555555'
            TenantId = $script:TenantId
            DeploymentProfile = 'MicrosoftNative'
            ConfigurationHash = $script:ConfigurationHash
            ControlId = 'EXO-010'
            Collector = [ordered]@{ Identity = 'Get-ExchangeRoleAssignmentEvidence'; Version = '1.0.0' }
            GeneratedAtUtc = $script:AsOf.AddMinutes(-5).UtcDateTime.ToString('o')
            PayloadHash = Get-BaselineExternalEvidencePayloadHash -Payload $payload
            Payload = $payload
            Signature = [ordered]@{
                Model = 'DetachedCms'
                MediaType = 'application/pkcs7-signature'
                Value = 'synthetic-signature'
            }
        }

        foreach ($name in $Override.Keys) { $document[$name] = $Override[$name] }
        return [pscustomobject]$document
    }

    function New-RbacPimRegistryFixture {
        return @([pscustomobject]@{
                ControlId = 'EXO-010'
                Collector = 'Get-ExchangeRoleAssignmentEvidence'
            })
    }

    function Invoke-RbacPimFallbackImport {
        param(
            [object[]]$Evidence = @((New-RbacPimFallbackFixture)),
            [scriptblock]$DocumentValidator = { param($Document) [pscustomobject]@{ Satisfied = $true; Reason = @() } },
            [scriptblock]$ExternalEvidenceImporter = {
                param($Argument)
                [pscustomobject]@{
                    Satisfied = $true
                    Admitted = @([pscustomobject]@{
                            EvidenceId = $Argument.Evidence[0].EvidenceId
                            ControlId = $Argument.Evidence[0].ControlId
                            Evidence = $Argument.Evidence[0]
                        })
                    Refused = @()
                }
            },
            [string[]]$ReplayEvidenceId = @(),
            [object[]]$AdmittedEvidence = @(),
            [scriptblock]$CmsVerificationScript,
            [object[]]$AuthorizedSigner = @(),
            [string]$DeclaredSignerIdentity = ''
        )

        $argument = @{
            Evidence = $Evidence
            TenantId = $script:TenantId
            DeploymentProfile = 'MicrosoftNative'
            ConfigurationHash = $script:ConfigurationHash
            Registry = (New-RbacPimRegistryFixture)
            MaximumAge = [timespan]::FromHours(24)
            AsOf = $script:AsOf
            ReplayEvidenceId = $ReplayEvidenceId
            AdmittedEvidence = $AdmittedEvidence
            DocumentValidator = $DocumentValidator
            ExternalEvidenceImporter = $ExternalEvidenceImporter
            AuthorizedSigner = $AuthorizedSigner
            DeclaredSignerIdentity = $DeclaredSignerIdentity
        }
        if ($PSBoundParameters.ContainsKey('CmsVerificationScript')) {
            $argument.CmsVerificationScript = $CmsVerificationScript
        }

        return Import-BaselineRbacPimFallback @argument
    }

    function Get-FallbackRefusalReason {
        param([Parameter(Mandatory)][object]$Decision)
        return @($Decision.Refused | ForEach-Object { @($_.Reason) })
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXO-014 signed RBAC/PIM fallback ingestion' {
    Context 'Negative: detached CMS and signer authority refusals' {
        It 'refuses unsigned fallback evidence for its named reason' {
            # Arrange
            $evidence = New-RbacPimFallbackFixture
            $reason = 'ExternalEvidenceUnsigned: detached CMS signature is required.'
            $importer = { param($Argument) [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ EvidenceId = $Argument.Evidence[0].EvidenceId; ControlId = $Argument.Evidence[0].ControlId; Reason = @($reason) }) } }.GetNewClosure()

            # Act
            $decision = Invoke-RbacPimFallbackImport -Evidence $evidence -ExternalEvidenceImporter $importer

            # Assert
            Get-FallbackRefusalReason -Decision $decision | Should -Contain $reason
        }

        It 'refuses tampered fallback evidence for its named reason' {
            # Arrange
            $evidence = New-RbacPimFallbackFixture
            $reason = 'ExternalEvidenceSignatureTampered: detached CMS does not verify over the canonical document bytes.'
            $importer = { param($Argument) [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ EvidenceId = $Argument.Evidence[0].EvidenceId; ControlId = $Argument.Evidence[0].ControlId; Reason = @($reason) }) } }.GetNewClosure()

            # Act
            $decision = Invoke-RbacPimFallbackImport -Evidence $evidence -ExternalEvidenceImporter $importer

            # Assert
            Get-FallbackRefusalReason -Decision $decision | Should -Contain $reason
        }

        It 'refuses an unauthorized fallback signer for its named reason' {
            # Arrange
            $evidence = New-RbacPimFallbackFixture
            $reason = 'ExternalEvidenceSignerUnauthorized: signer lacks the declared external-evidence authority.'
            $importer = { param($Argument) [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ EvidenceId = $Argument.Evidence[0].EvidenceId; ControlId = $Argument.Evidence[0].ControlId; Reason = @($reason) }) } }.GetNewClosure()

            # Act
            $decision = Invoke-RbacPimFallbackImport -Evidence $evidence -ExternalEvidenceImporter $importer

            # Assert
            Get-FallbackRefusalReason -Decision $decision | Should -Contain $reason
        }
    }

    Context 'Negative: tenant, time, uniqueness, and replay binding refusals' {
        It 'refuses fallback evidence raised for another tenant' {
            # Arrange
            $evidence = New-RbacPimFallbackFixture
            $reason = "ExternalEvidenceTenantMismatch: evidence tenant 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' does not match run tenant '$($script:TenantId)'."
            $importer = { param($Argument) [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ EvidenceId = $Argument.Evidence[0].EvidenceId; ControlId = $Argument.Evidence[0].ControlId; Reason = @($reason) }) } }.GetNewClosure()

            # Act
            $decision = Invoke-RbacPimFallbackImport -Evidence $evidence -ExternalEvidenceImporter $importer

            # Assert
            Get-FallbackRefusalReason -Decision $decision | Should -Contain $reason
        }

        It 'refuses fallback evidence generated in the future' {
            # Arrange
            $evidence = New-RbacPimFallbackFixture
            $reason = 'ExternalEvidenceFromFuture: fallback evidence was generated after the decision time.'
            $importer = { param($Argument) [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ EvidenceId = $Argument.Evidence[0].EvidenceId; ControlId = $Argument.Evidence[0].ControlId; Reason = @($reason) }) } }.GetNewClosure()

            # Act
            $decision = Invoke-RbacPimFallbackImport -Evidence $evidence -ExternalEvidenceImporter $importer

            # Assert
            Get-FallbackRefusalReason -Decision $decision | Should -Contain $reason
        }

        It 'refuses stale fallback evidence' {
            # Arrange
            $evidence = New-RbacPimFallbackFixture
            $reason = 'ExternalEvidenceStale: fallback evidence is outside the maximum age.'
            $importer = { param($Argument) [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ EvidenceId = $Argument.Evidence[0].EvidenceId; ControlId = $Argument.Evidence[0].ControlId; Reason = @($reason) }) } }.GetNewClosure()

            # Act
            $decision = Invoke-RbacPimFallbackImport -Evidence $evidence -ExternalEvidenceImporter $importer

            # Assert
            Get-FallbackRefusalReason -Decision $decision | Should -Contain $reason
        }

        It 'refuses duplicate fallback evidence' {
            # Arrange
            $evidence = New-RbacPimFallbackFixture
            $reason = "ExternalEvidenceIdDuplicated: evidence ID '$($evidence.EvidenceId)' occurs more than once in this import."
            $importer = { param($Argument) [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ EvidenceId = $Argument.Evidence[0].EvidenceId; ControlId = $Argument.Evidence[0].ControlId; Reason = @($reason) }) } }.GetNewClosure()

            # Act
            $decision = Invoke-RbacPimFallbackImport -Evidence @($evidence, $evidence) -ExternalEvidenceImporter $importer

            # Assert
            Get-FallbackRefusalReason -Decision $decision | Should -Contain $reason
        }

        It 'refuses replayed fallback evidence' {
            # Arrange
            $evidence = New-RbacPimFallbackFixture
            $reason = "ExternalEvidenceReplayed: evidence ID '$($evidence.EvidenceId)' was already consumed."
            $importer = { param($Argument) [pscustomobject]@{ Satisfied = $false; Admitted = @(); Refused = @([pscustomobject]@{ EvidenceId = $Argument.Evidence[0].EvidenceId; ControlId = $Argument.Evidence[0].ControlId; Reason = @($reason) }) } }.GetNewClosure()

            # Act
            $decision = Invoke-RbacPimFallbackImport -Evidence $evidence -ReplayEvidenceId @($evidence.EvidenceId) -ExternalEvidenceImporter $importer

            # Assert
            Get-FallbackRefusalReason -Decision $decision | Should -Contain $reason
        }
    }

    Context 'Negative: fallback payload verdict refusals' {
        It 'refuses a payload rejected by the published fallback schema' {
            # Arrange
            $evidence = New-RbacPimFallbackFixture
            $reason = 'RbacPimFallbackSchemaViolation: the fallback payload does not conform.'
            $validator = { param($Document) [pscustomobject]@{ Satisfied = $false; Reason = @($reason) } }.GetNewClosure()

            # Act
            $decision = Invoke-RbacPimFallbackImport -Evidence $evidence -DocumentValidator $validator

            # Assert
            Get-FallbackRefusalReason -Decision $decision | Should -Contain $reason
        }

        It 'refuses a partial fallback payload' {
            # Arrange
            $evidence = New-RbacPimFallbackFixture
            $reason = 'RbacPimFallbackPartial: role-group, active-PIM, eligible-PIM, and access-review payloads are all required.'
            $validator = { param($Document) [pscustomobject]@{ Satisfied = $false; Reason = @($reason) } }.GetNewClosure()

            # Act
            $decision = Invoke-RbacPimFallbackImport -Evidence $evidence -DocumentValidator $validator

            # Assert
            Get-FallbackRefusalReason -Decision $decision | Should -Contain $reason
        }

        It 'refuses a mutable fallback payload verdict' {
            # Arrange
            $evidence = New-RbacPimFallbackFixture
            $reason = 'RbacPimFallbackMutable: fallback document verdicts must be immutable.'
            $validator = { param($Document) [pscustomobject]@{ Satisfied = $false; Reason = @($reason) } }.GetNewClosure()

            # Act
            $decision = Invoke-RbacPimFallbackImport -Evidence $evidence -DocumentValidator $validator

            # Assert
            Get-FallbackRefusalReason -Decision $decision | Should -Contain $reason
        }
    }

    Context 'Positive: one authorized fresh tenant-bound fallback is admitted' {
        It 'admits one complete signed fallback through EVD-008 as an immutable tenant-bound record' {
            # Arrange
            $script:CmsVerificationCall = 0
            $evidence = New-RbacPimFallbackFixture -Override @{
                Signature = [ordered]@{
                    Model = 'DetachedCms'
                    MediaType = 'application/pkcs7-signature'
                    Value = 'AQIDBA=='
                }
            }
            $cmsVerifier = {
                param([byte[]]$CanonicalBytes, [byte[]]$SignatureBytes)
                $script:CmsVerificationCall++
                [pscustomobject]@{
                    ContentMatched = $CanonicalBytes.Count -gt 0
                    SignatureValid = $SignatureBytes.Count -gt 0
                    SignerSubject = 'CN=Contoso RBAC Evidence Approver'
                    SigningTimeUtc = [datetimeoffset]'2026-09-19T11:59:00Z'
                    CertificateNotBeforeUtc = [datetimeoffset]'2026-01-01T00:00:00Z'
                    CertificateNotAfterUtc = [datetimeoffset]'2027-01-01T00:00:00Z'
                    ChainTrusted = $true
                    RevocationStatus = 'Good'
                }
            }
            $authorizedSigner = [pscustomobject]@{
                Identity = 'rbac-evidence-approver@contoso.example'
                Subject = 'CN=Contoso RBAC Evidence Approver'
                Authority = 'ExchangeOnlineChangeApproval'
            }

            # Act
            $decision = Invoke-RbacPimFallbackImport `
                -Evidence $evidence `
                -DocumentValidator $null `
                -ExternalEvidenceImporter $null `
                -CmsVerificationScript $cmsVerifier `
                -AuthorizedSigner @($authorizedSigner) `
                -DeclaredSignerIdentity $authorizedSigner.Identity

            # Assert
            ('satisfied={0};admitted={1};refused={2};tenant={3};cms={4}' -f
                $decision.Satisfied,
                @($decision.Admitted).Count,
                @($decision.Refused).Count,
                $decision.Admitted[0].Evidence.Payload.TenantId,
                $script:CmsVerificationCall) | Should -BeExactly "satisfied=True;admitted=1;refused=0;tenant=$($script:TenantId);cms=1" `
                -Because ($decision | ConvertTo-Json -Depth 12 -Compress)
            { $decision.Admitted[0].Evidence.Payload.RoleGroup[0].Name = 'Changed' } | Should -Throw
        }
    }
}