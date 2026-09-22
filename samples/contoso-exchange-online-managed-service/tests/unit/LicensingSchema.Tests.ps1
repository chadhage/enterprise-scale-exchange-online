#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'

    # LIC-001 and DES-003: a declared tier is planning metadata. It may be present, but the schema
    # must not require it and must not fix it, because the tenant service-plan inventory decides
    # entitlement at run time.
    $script:PlanningOnlyTier = @('messagingTier', 'complianceTier')

    # The licensing members the schema must define for the runtime decision.
    $script:ServicePlanEntryMember = @('servicePlanId', 'servicePlanName')
    $script:TargetValidationMode = @('TenantOnly', 'TenantAndAnyTarget', 'TenantAndEveryTarget')
    $script:ProvisioningState = @('disabled', 'suspended', 'pending')
    $script:ProvisioningStateBehaviour = @('TreatAsNotEntitled', 'TreatAsFail', 'TreatAsError')
    $script:SafeDocumentsServicePlan = 'SAFEDOCS'

    function Get-SchemaNode {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Document,

            [Parameter(Mandatory)]
            [string[]]$Path
        )

        $current = $Document
        foreach ($segment in $Path) {
            if ($current -isnot [System.Collections.IDictionary] -or -not $current.Contains($segment)) { return $null }
            $current = $current[$segment]
        }

        return $current
    }

    function Test-SameSet {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Actual,

            [Parameter(Mandatory)]
            [string[]]$Expected
        )

        if ($null -eq $Actual -or $Actual -isnot [System.Collections.IList]) { return $false }

        $left = @($Actual | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        $right = @($Expected | Sort-Object -Unique)

        if ($left.Count -ne $right.Count) { return $false }
        return @(Compare-Object -ReferenceObject $left -DifferenceObject $right).Count -eq 0
    }

    function Get-LicensingSchemaResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$SchemaPath
        )

        $result = [ordered]@{
            Satisfied  = $false
            Reason     = $null
            Violations = @()
        }

        if ([string]::IsNullOrWhiteSpace($SchemaPath) -or -not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) {
            $result.Reason = 'SchemaFileMissing'
            return [pscustomobject]$result
        }

        try {
            $document = Get-Content -LiteralPath $SchemaPath -Raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        }
        catch {
            $result.Reason = 'SchemaJsonInvalid'
            return [pscustomobject]$result
        }

        $licensing = Get-SchemaNode -Document $document -Path @('properties', 'licensing')
        if ($null -eq $licensing) {
            $result.Reason = 'LicensingSectionMissing'
            return [pscustomobject]$result
        }

        $licensingRequired = @(Get-SchemaNode -Document $licensing -Path @('required'))
        $licensingProperties = Get-SchemaNode -Document $licensing -Path @('properties')

        foreach ($tier in $script:PlanningOnlyTier) {
            if ($tier -in $licensingRequired) {
                $result.Reason = 'DeclaredTierRequired'
                $result.Violations = @($tier)
                return [pscustomobject]$result
            }

            $tierNode = Get-SchemaNode -Document $licensingProperties -Path @($tier)
            if ($tierNode -is [System.Collections.IDictionary] -and $tierNode.Contains('const')) {
                $result.Reason = 'DeclaredTierConstrained'
                $result.Violations = @($tier)
                return [pscustomobject]$result
            }
        }

        $requiredServicePlans = Get-SchemaNode -Document $licensingProperties -Path @('requiredServicePlans')
        if ($null -eq $requiredServicePlans) {
            $result.Reason = 'RequiredServicePlansMissing'
            return [pscustomobject]$result
        }

        if ('requiredServicePlans' -notin $licensingRequired) {
            $result.Reason = 'RequiredServicePlansNotRequired'
            return [pscustomobject]$result
        }

        if ((Get-SchemaNode -Document $requiredServicePlans -Path @('type')) -ne 'array') {
            $result.Reason = 'RequiredServicePlansNotArray'
            return [pscustomobject]$result
        }

        $entryRequired = @(Get-SchemaNode -Document $requiredServicePlans -Path @('items', 'required'))
        $missingEntryMember = @($script:ServicePlanEntryMember | Where-Object { $_ -notin $entryRequired })
        if ($missingEntryMember.Count -gt 0) {
            $result.Reason = 'ServicePlanEntryWithoutIdentifier'
            $result.Violations = $missingEntryMember
            return [pscustomobject]$result
        }

        $targetValidationMode = Get-SchemaNode -Document $licensingProperties -Path @('targetValidationMode')
        if ($null -eq $targetValidationMode) {
            $result.Reason = 'TargetValidationModeMissing'
            return [pscustomobject]$result
        }

        if ('targetValidationMode' -notin $licensingRequired) {
            $result.Reason = 'TargetValidationModeNotRequired'
            return [pscustomobject]$result
        }

        if (-not (Test-SameSet -Actual (Get-SchemaNode -Document $targetValidationMode -Path @('enum')) -Expected $script:TargetValidationMode)) {
            $result.Reason = 'TargetValidationModeVocabularyUndeclared'
            $result.Violations = $script:TargetValidationMode
            return [pscustomobject]$result
        }

        $behaviour = Get-SchemaNode -Document $licensingProperties -Path @('servicePlanProvisioningStateBehavior')
        if ($null -eq $behaviour) {
            $result.Reason = 'ProvisioningStateBehaviourMissing'
            return [pscustomobject]$result
        }

        if ('servicePlanProvisioningStateBehavior' -notin $licensingRequired) {
            $result.Reason = 'ProvisioningStateBehaviourNotRequired'
            return [pscustomobject]$result
        }

        $behaviourRequired = @(Get-SchemaNode -Document $behaviour -Path @('required'))
        $undefinedState = @($script:ProvisioningState | Where-Object { $_ -notin $behaviourRequired })
        if ($undefinedState.Count -gt 0) {
            $result.Reason = 'ProvisioningStateUndefined'
            $result.Violations = $undefinedState
            return [pscustomobject]$result
        }

        foreach ($state in $script:ProvisioningState) {
            $stateNode = Get-SchemaNode -Document $behaviour -Path @('properties', $state)
            if (-not (Test-SameSet -Actual (Get-SchemaNode -Document $stateNode -Path @('enum')) -Expected $script:ProvisioningStateBehaviour)) {
                $result.Reason = 'ProvisioningStateBehaviourVocabularyUndeclared'
                $result.Violations = @($state)
                return [pscustomobject]$result
            }
        }

        $safeDocuments = Get-SchemaNode -Document $document -Path @('properties', 'desiredState', 'properties', 'defenderForOffice365', 'properties', 'safeDocuments')
        if ($null -eq $safeDocuments) {
            $result.Reason = 'SafeDocumentsSectionMissing'
            return [pscustomobject]$result
        }

        if ('requiredServicePlan' -notin @(Get-SchemaNode -Document $safeDocuments -Path @('required'))) {
            $result.Reason = 'SafeDocumentsServicePlanNotRequired'
            return [pscustomobject]$result
        }

        $safeDocumentsPlan = Get-SchemaNode -Document $safeDocuments -Path @('properties', 'requiredServicePlan', 'const')
        if ($safeDocumentsPlan -ne $script:SafeDocumentsServicePlan) {
            $result.Reason = 'SafeDocumentsServicePlanNotSafeDocs'
            $result.Violations = @($script:SafeDocumentsServicePlan)
            return [pscustomobject]$result
        }

        $result.Satisfied = $true
        $result.Reason = 'LicensingSchemaSatisfied'
        $result.Violations = @()
        return [pscustomobject]$result
    }

    function New-MutatedSchemaFile {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Directory,

            [Parameter(Mandatory)]
            [scriptblock]$Mutate
        )

        $document = Get-Content -LiteralPath $script:SchemaPath -Raw | ConvertFrom-Json -AsHashtable
        & $Mutate $document

        $path = Join-Path $Directory ('Schema-{0}.json' -f [guid]::NewGuid().ToString('N'))
        $document | ConvertTo-Json -Depth 64 | Set-Content -LiteralPath $path -Encoding utf8
        return $path
    }
}

Describe 'LIC-001-A licensing schema contract' {

    Context 'Negative: the schema document must be usable' {

        It 'reports SchemaFileMissing when the schema file is absent' {
            # Arrange
            $absentSchema = Join-Path $TestDrive 'absent-schema.json'

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $absentSchema

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an absent schema declares nothing'
            $result.Reason | Should -Be 'SchemaFileMissing'
        }

        It 'reports SchemaJsonInvalid when the schema file is malformed JSON' {
            # Arrange
            $malformedSchema = Join-Path $TestDrive 'malformed-schema.json'
            Set-Content -LiteralPath $malformedSchema -Value '{ "properties": ' -Encoding utf8

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $malformedSchema

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a malformed schema declares nothing'
            $result.Reason | Should -Be 'SchemaJsonInvalid'
        }

        It 'reports LicensingSectionMissing when the schema declares no licensing section' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['properties'].Remove('licensing')
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'there is no licensing contract without a licensing section'
            $result.Reason | Should -Be 'LicensingSectionMissing'
        }
    }

    Context 'Negative: a declared tier must stay planning metadata' {

        It 'reports DeclaredTierRequired when the messaging tier is a required member' -ForEach @(
            @{ Tier = 'messagingTier' }
            @{ Tier = 'complianceTier' }
        ) {
            # Arrange
            $required = $Tier
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $document['properties']['licensing']['required'] = @($required)
            }.GetNewClosure()

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a required tier is treated as authoritative rather than as a planning expectation'
            $result.Reason | Should -Be 'DeclaredTierRequired'
        }

        It 'reports DeclaredTierConstrained when a declared tier is fixed by the schema' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $document['properties']['licensing']['properties']['messagingTier'] = @{ const = 'MDO_P2' }
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a fixed tier would override the tenant service-plan inventory'
            $result.Reason | Should -Be 'DeclaredTierConstrained'
        }

        It 'names the tier that stopped being planning metadata' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $document['properties']['licensing']['properties']['complianceTier'] = @{ const = 'E5Compliance' }
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Violations | Should -Contain 'complianceTier'
        }
    }

    Context 'Negative: the required service plans must be declared' {

        It 'reports RequiredServicePlansMissing when the schema declares no required service plans' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['properties']['licensing']['properties'].Remove('requiredServicePlans')
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'entitlement cannot be decided without the service plans a control needs'
            $result.Reason | Should -Be 'RequiredServicePlansMissing'
        }

        It 'reports RequiredServicePlansNotRequired when required service plans are optional' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $document['properties']['licensing']['required'] = @($document['properties']['licensing']['required'] | Where-Object { $_ -ne 'requiredServicePlans' })
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an optional service-plan list lets a baseline ship with no entitlement contract'
            $result.Reason | Should -Be 'RequiredServicePlansNotRequired'
        }

        It 'reports RequiredServicePlansNotArray when the required service plans are not a list' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $document['properties']['licensing']['properties']['requiredServicePlans']['type'] = 'string'
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a control may require more than one service plan'
            $result.Reason | Should -Be 'RequiredServicePlansNotArray'
        }

        It 'reports ServicePlanEntryWithoutIdentifier when an entry may omit its service-plan identifier' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $document['properties']['licensing']['properties']['requiredServicePlans']['items']['required'] = @('servicePlanName')
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a service plan is matched by its identifier, not by its display name'
            $result.Reason | Should -Be 'ServicePlanEntryWithoutIdentifier'
        }
    }

    Context 'Negative: the target validation mode must be declared' {

        It 'reports TargetValidationModeMissing when the schema declares no target validation mode' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['properties']['licensing']['properties'].Remove('targetValidationMode')
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'the breadth of the licensing check must be declared, not assumed'
            $result.Reason | Should -Be 'TargetValidationModeMissing'
        }

        It 'reports TargetValidationModeNotRequired when the target validation mode is optional' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $document['properties']['licensing']['required'] = @($document['properties']['licensing']['required'] | Where-Object { $_ -ne 'targetValidationMode' })
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an omitted mode would leave the licensing gate undefined'
            $result.Reason | Should -Be 'TargetValidationModeNotRequired'
        }

        It 'reports TargetValidationModeVocabularyUndeclared when the mode admits a value outside the declared vocabulary' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $document['properties']['licensing']['properties']['targetValidationMode'] = @{ type = 'string' }
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an unconstrained mode admits a gate the solution cannot evaluate'
            $result.Reason | Should -Be 'TargetValidationModeVocabularyUndeclared'
        }
    }

    Context 'Negative: the behaviour for a non-enabled service plan must be defined' {

        It 'reports ProvisioningStateBehaviourMissing when the schema defines no provisioning-state behaviour' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['properties']['licensing']['properties'].Remove('servicePlanProvisioningStateBehavior')
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an assigned plan that is not enabled must have defined behaviour'
            $result.Reason | Should -Be 'ProvisioningStateBehaviourMissing'
        }

        It 'reports ProvisioningStateBehaviourNotRequired when the provisioning-state behaviour is optional' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $document['properties']['licensing']['required'] = @($document['properties']['licensing']['required'] | Where-Object { $_ -ne 'servicePlanProvisioningStateBehavior' })
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'undefined behaviour for a suspended plan would default to silence'
            $result.Reason | Should -Be 'ProvisioningStateBehaviourNotRequired'
        }

        It 'reports ProvisioningStateUndefined when a provisioning state has no defined behaviour' -ForEach @(
            @{ State = 'disabled' }
            @{ State = 'suspended' }
            @{ State = 'pending' }
        ) {
            # Arrange
            $removed = $State
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $behaviour = $document['properties']['licensing']['properties']['servicePlanProvisioningStateBehavior']
                $behaviour['required'] = @($behaviour['required'] | Where-Object { $_ -ne $removed })
            }.GetNewClosure()

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because "the behaviour for a $removed service plan must be defined"
            $result.Reason | Should -Be 'ProvisioningStateUndefined'
        }

        It 'reports ProvisioningStateBehaviourVocabularyUndeclared when a state admits a behaviour outside the declared vocabulary' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $document['properties']['licensing']['properties']['servicePlanProvisioningStateBehavior']['properties']['suspended'] = @{ type = 'string' }
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an unconstrained behaviour admits an outcome the go-live gate cannot classify'
            $result.Reason | Should -Be 'ProvisioningStateBehaviourVocabularyUndeclared'
        }
    }

    Context 'Negative: Safe Documents must carry its own service plan' {

        It 'reports SafeDocumentsSectionMissing when the schema constrains no Safe Documents section' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties'].Remove('safeDocuments')
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'Safe Documents is gated by its own service plan and must be constrained'
            $result.Reason | Should -Be 'SafeDocumentsSectionMissing'
        }

        It 'reports SafeDocumentsServicePlanNotRequired when the Safe Documents service plan is optional' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $safeDocuments = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['safeDocuments']
                $safeDocuments['required'] = @($safeDocuments['required'] | Where-Object { $_ -ne 'requiredServicePlan' })
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'Safe Documents must never be applied without naming the plan it needs'
            $result.Reason | Should -Be 'SafeDocumentsServicePlanNotRequired'
        }

        It 'reports SafeDocumentsServicePlanNotSafeDocs when the Safe Documents plan is not fixed to SAFEDOCS' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $safeDocuments = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['safeDocuments']
                $safeDocuments['properties']['requiredServicePlan'] = @{ const = 'THREAT_INTELLIGENCE' }
            }

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'Safe Documents is granted by SAFEDOCS, not by a Defender plan bundle'
            $result.Reason | Should -Be 'SafeDocumentsServicePlanNotSafeDocs'
        }
    }

    Context 'Positive: the shipped schema defines the licensing contract' {

        It 'treats every declared tier as planning metadata and defines required service plans, target validation mode, provisioning-state behaviour and the SAFEDOCS requirement' {
            # Arrange
            $schemaPath = $script:SchemaPath

            # Act
            $result = Get-LicensingSchemaResult -SchemaPath $schemaPath

            # Assert
            $result.Satisfied | Should -BeTrue -Because "the shipped schema must satisfy LIC-001 but reported '$($result.Reason)' for '$($result.Violations -join ', ')'"
            $result.Reason | Should -Be 'LicensingSchemaSatisfied'
        }
    }
}
