#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'rbac-pim-fallback.schema.json'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-RbacPimFallbackDocument {
        [CmdletBinding()]
        param(
            [hashtable]$Override = @{},
            [string[]]$Omit = @()
        )

        $document = [ordered]@{
            SchemaVersion           = '1.0.0'
            TenantId                = '00000000-1111-4222-8333-444444444444'
            GeneratedAtUtc          = '2026-09-19T12:34:56Z'
            RoleGroup               = @(
                [ordered]@{
                    Name           = 'Organization Management'
                    Members        = @('principal-001')
                    WhenChangedUtc = '2026-09-01T08:00:00Z'
                }
            )
            ManagementRoleAssignment = @(
                [ordered]@{
                    Role                = 'Mailbox Import Export'
                    RoleAssigneeName    = 'Organization Management'
                    RoleAssigneeType    = 'RoleGroup'
                    RecipientWriteScope = 'Organization'
                }
            )
            ActivePimAssignment     = @(
                [ordered]@{
                    PrincipalId     = 'b5d1f9a0-3c2e-4a77-9f81-6d0c4e2b8a13'
                    RoleDefinitionId = '29232cdf-9323-42fd-ade2-1d097af3e4de'
                    EndDateTime     = '2026-09-30T00:00:00Z'
                    MemberType      = 'Direct'
                }
            )
            EligiblePimAssignment   = @(
                [ordered]@{
                    PrincipalId      = 'c7e2a418-5b9d-4f60-8a31-2f4c6d9e1b05'
                    RoleDefinitionId = '29232cdf-9323-42fd-ade2-1d097af3e4de'
                    StartDateTime    = '2026-01-05T00:00:00Z'
                }
            )
            AccessReview            = @(
                [ordered]@{
                    DisplayName           = 'Exchange administrators quarterly review'
                    ScopeRoleDefinitionId = '29232cdf-9323-42fd-ade2-1d097af3e4de'
                    LastCompletedDateTime = '2026-08-20T00:00:00Z'
                    CreatedBy             = 'governance-principal-001'
                }
            )
        }

        foreach ($name in $Omit) { $document.Remove($name) }
        foreach ($name in $Override.Keys) { $document[$name] = $Override[$name] }

        return [pscustomobject]$document
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXO-014 RBAC and PIM fallback payload contract' {
    Context 'absent malformed and unusable schema inputs are refused' {
        It 'refuses a missing fallback document' {
            # Arrange
            $document = $null

            # Act
            $act = { Test-BaselineRbacPimFallbackDocument -Document $document -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RbacPimFallbackDocumentNotProvided*'
        }

        It 'refuses a fallback document that is not an object' {
            # Arrange
            $document = 'all assignments reviewed'

            # Act
            $act = { Test-BaselineRbacPimFallbackDocument -Document $document -SchemaPath $script:SchemaPath }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RbacPimFallbackDocumentNotAnObject*'
        }

        It 'refuses a check that names no schema' {
            # Arrange
            $document = New-RbacPimFallbackDocument

            # Act
            $act = { Test-BaselineRbacPimFallbackDocument -Document $document -SchemaPath '' }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RbacPimFallbackSchemaPathRequired*'
        }

        It 'refuses a schema path that names no file' {
            # Arrange
            $absent = Join-Path $TestDrive 'absent.schema.json'

            # Act
            $act = { Test-BaselineRbacPimFallbackDocument -Document (New-RbacPimFallbackDocument) -SchemaPath $absent }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RbacPimFallbackSchemaNotFound*'
        }

        It 'refuses a schema file that is not valid JSON' {
            # Arrange
            $broken = Join-Path $TestDrive 'broken.schema.json'
            Set-Content -LiteralPath $broken -Value '{ "type": "object", ' -Encoding utf8

            # Act
            $act = { Test-BaselineRbacPimFallbackDocument -Document (New-RbacPimFallbackDocument) -SchemaPath $broken }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RbacPimFallbackSchemaJsonInvalid*'
        }

        It 'refuses a schema file that is not a usable JSON Schema' {
            # Arrange
            $unusable = Join-Path $TestDrive 'unusable.schema.json'
            Set-Content -LiteralPath $unusable -Value '{ "type": 42 }' -Encoding utf8

            # Act
            $act = { Test-BaselineRbacPimFallbackDocument -Document (New-RbacPimFallbackDocument) -SchemaPath $unusable }

            # Assert
            $act | Should -Throw -ExpectedMessage '*RbacPimFallbackSchemaNotUsable*'
        }
    }

    Context 'required and declared members are enforced' {
        It 'schema-refuses a fallback document missing <_>' -ForEach @(
            'SchemaVersion'
            'TenantId'
            'GeneratedAtUtc'
            'RoleGroup'
            'ManagementRoleAssignment'
            'ActivePimAssignment'
            'EligiblePimAssignment'
            'AccessReview'
        ) {
            # Arrange
            $document = New-RbacPimFallbackDocument -Omit @($_)

            # Act
            $result = Test-BaselineRbacPimFallbackDocument -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Conforms | Should -BeFalse -Because "fallback evidence without $_ is partial"
            $result.Violation | Should -Not -BeNullOrEmpty
        }

        It 'schema-refuses an undeclared top-level member' {
            # Arrange
            $document = New-RbacPimFallbackDocument -Override @{ TrustFallback = $true }

            # Act
            $result = Test-BaselineRbacPimFallbackDocument -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Conforms | Should -BeFalse
        }

        It 'schema-refuses an undeclared nested member' {
            # Arrange
            $document = New-RbacPimFallbackDocument -Override @{
                RoleGroup = @([ordered]@{ Name = 'Organization Management'; Members = @('principal-001'); WhenChangedUtc = '2026-09-01T08:00:00Z'; Approved = $true })
            }

            # Act
            $result = Test-BaselineRbacPimFallbackDocument -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Conforms | Should -BeFalse
        }
    }

    Context 'tenant and generation bindings are exact' {
        It 'schema-refuses an invalid tenant identifier' {
            # Arrange
            $document = New-RbacPimFallbackDocument -Override @{ TenantId = 'tenant-one' }

            # Act
            $result = Test-BaselineRbacPimFallbackDocument -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Conforms | Should -BeFalse
        }

        It 'schema-refuses a malformed generation time' {
            # Arrange
            $document = New-RbacPimFallbackDocument -Override @{ GeneratedAtUtc = 'today' }

            # Act
            $result = Test-BaselineRbacPimFallbackDocument -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Conforms | Should -BeFalse
        }

        It 'schema-refuses a generation time without an explicit UTC designator' {
            # Arrange
            $document = New-RbacPimFallbackDocument -Override @{ GeneratedAtUtc = '2026-09-19T12:34:56' }

            # Act
            $result = Test-BaselineRbacPimFallbackDocument -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Conforms | Should -BeFalse
        }
    }

    Context 'the schema verdict is immutable' {
        It 'refuses assignment to the conformance verdict' {
            # Arrange
            $result = Test-BaselineRbacPimFallbackDocument -Document (New-RbacPimFallbackDocument) -SchemaPath $script:SchemaPath

            # Act
            $act = { $result.Conforms = $false }

            # Assert
            $act | Should -Throw -Because 'a mutable schema verdict could be rewritten before ingestion applies it'
        }

        It 'refuses assignment to the violation collection' {
            # Arrange
            $result = Test-BaselineRbacPimFallbackDocument -Document (New-RbacPimFallbackDocument -Omit @('AccessReview')) -SchemaPath $script:SchemaPath

            # Act
            $act = { $result.Violation[0] = 'admitted later' }

            # Assert
            $act | Should -Throw -Because 'a mutable refusal reason cannot support an auditable ingestion decision'
        }
    }

    Context 'one complete sanitized RBAC and PIM fallback document' {
        It 'admits the complete fallback document' {
            # Arrange
            $document = New-RbacPimFallbackDocument

            # Act
            $result = Test-BaselineRbacPimFallbackDocument -Document $document -SchemaPath $script:SchemaPath

            # Assert
            $result.Conforms | Should -BeTrue -Because "the complete sanitized fallback should conform, but the contract reported '$($result.Violation -join '; ')'"
        }
    }
}