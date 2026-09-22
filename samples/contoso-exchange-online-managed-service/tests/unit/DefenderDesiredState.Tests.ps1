#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:SchemaPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.schema.json'
    $script:GatewayConfigurationPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.json'
    $script:NativeConfigurationPath = Join-Path $script:SampleRoot 'config' 'exchange-online-secure-baseline.microsoft-native.json'

    # Both shipped profiles run the same Defender service, so both must resolve the same desired
    # state. The contract is decided over both documents in one pass rather than one document at a
    # time, because a member defined for only one profile is a gap the other profile ships with.
    $script:ShippedConfigurationPath = @($script:GatewayConfigurationPath, $script:NativeConfigurationPath)

    # MDO-001: the Defender desired state the later MDO controls are decided against. Each of these
    # sections answers a question the shipped baseline could not previously answer at all.
    $script:DefenderSection = @(
        'impersonationProtection'
        'userSubmissions'
        'advancedDelivery'
        'tenantAllowBlockList'
        'quarantinePolicies'
    )

    $script:ImpersonationMember = @('protectedUsers', 'protectedDomains', 'approvedExceptions')
    $script:ImpersonationExceptionField = @('value', 'owner', 'ticket', 'expirationDateTime')
    $script:TenantAllowBlockListMember = @(
        'registerLocation'
        'allowEntryMaximumDurationDays'
        'blockEntryRetentionDays'
        'requiredEntryFields'
        'blockEntriesRequireExpiryAndTicket'
    )

    $script:QuarantineCategoryPermissionMember = @('category', 'accessLevel')
    $script:AdminOnlyCategory = @('Malware', 'HighConfidencePhish')
    $script:AdminOnlyAccessLevel = 'AdminOnlyAccess'

    function Get-SchemaNode {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Document,

            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [string[]]$Path
        )

        $current = $Document
        foreach ($segment in $Path) {
            if ($current -isnot [System.Collections.IDictionary] -or -not $current.Contains($segment)) { return $null }
            $current = $current[$segment]
        }

        return $current
    }

    function Test-VocabularyDeclared {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Node
        )

        if ($Node -isnot [System.Collections.IDictionary]) { return $false }
        if ($Node.Contains('const')) { return $true }
        return ($Node.Contains('enum') -and @($Node['enum']).Count -gt 0)
    }

    function Test-NodeMemberPresent {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Node,

            [Parameter(Mandatory)]
            [string]$Name
        )

        return ($Node -is [System.Collections.IDictionary] -and $Node.Contains($Name))
    }

    # A one-element JSON array comes back from Get-SchemaNode as a bare string, because PowerShell
    # unwraps it on return, so every list read here is re-wrapped before it is counted.
    function Get-NodeItem {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Node
        )

        return , @(@($Node) | Where-Object { $null -ne $_ })
    }

    function Test-NonEmptyStringList {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Node
        )

        $populated = @((Get-NodeItem -Node $Node) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        return $populated.Count -gt 0
    }

    function Get-DefenderSchemaViolation {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Document
        )

        $defender = Get-SchemaNode -Document $Document -Path @('properties', 'desiredState', 'properties', 'defenderForOffice365')
        if ($null -eq $defender) {
            return [ordered]@{ Reason = 'DefenderSchemaMissing'; Violations = @() }
        }

        $defenderRequired = @(Get-SchemaNode -Document $defender -Path @('required'))
        $defenderProperties = Get-SchemaNode -Document $defender -Path @('properties')

        foreach ($section in $script:DefenderSection) {
            if ($null -eq (Get-SchemaNode -Document $defenderProperties -Path @($section))) {
                return [ordered]@{ Reason = 'DefenderMemberSchemaMissing'; Violations = @($section) }
            }

            if ($section -notin $defenderRequired) {
                return [ordered]@{ Reason = 'DefenderMemberNotRequired'; Violations = @($section) }
            }
        }

        $impersonation = Get-SchemaNode -Document $defenderProperties -Path @('impersonationProtection')
        $impersonationRequired = @(Get-SchemaNode -Document $impersonation -Path @('required'))
        foreach ($member in $script:ImpersonationMember) {
            if ($member -notin $impersonationRequired) {
                return [ordered]@{ Reason = 'ImpersonationMemberNotRequired'; Violations = @($member) }
            }
        }

        $exceptionRequired = @(Get-SchemaNode -Document $impersonation -Path @('properties', 'approvedExceptions', 'items', 'required'))
        foreach ($field in $script:ImpersonationExceptionField) {
            if ($field -notin $exceptionRequired) {
                return [ordered]@{ Reason = 'ImpersonationExceptionFieldNotRequired'; Violations = @($field) }
            }
        }

        $submissions = Get-SchemaNode -Document $defenderProperties -Path @('userSubmissions')
        $submissionsRequired = @(Get-SchemaNode -Document $submissions -Path @('required'))
        $reportingDestination = Get-SchemaNode -Document $submissions -Path @('properties', 'reportingDestination')
        if ($null -eq $reportingDestination) {
            return [ordered]@{ Reason = 'ReportingDestinationSchemaMissing'; Violations = @() }
        }

        if ('reportingDestination' -notin $submissionsRequired) {
            return [ordered]@{ Reason = 'ReportingDestinationNotRequired'; Violations = @() }
        }

        if (-not (Test-VocabularyDeclared -Node $reportingDestination)) {
            return [ordered]@{ Reason = 'ReportingDestinationVocabularyUndeclared'; Violations = @() }
        }

        if ('reportingMailbox' -notin $submissionsRequired) {
            return [ordered]@{ Reason = 'ReportingMailboxNotRequired'; Violations = @() }
        }

        $advancedDelivery = Get-SchemaNode -Document $defenderProperties -Path @('advancedDelivery')
        if ($null -eq (Get-SchemaNode -Document $advancedDelivery -Path @('properties', 'secOpsMailbox'))) {
            return [ordered]@{ Reason = 'AdvancedDeliverySecOpsMailboxSchemaMissing'; Violations = @() }
        }

        if ('secOpsMailbox' -notin @(Get-SchemaNode -Document $advancedDelivery -Path @('required'))) {
            return [ordered]@{ Reason = 'AdvancedDeliverySecOpsMailboxNotRequired'; Violations = @() }
        }

        $tabl = Get-SchemaNode -Document $defenderProperties -Path @('tenantAllowBlockList')
        $tablRequired = @(Get-SchemaNode -Document $tabl -Path @('required'))
        foreach ($member in $script:TenantAllowBlockListMember) {
            if ($member -notin $tablRequired) {
                return [ordered]@{ Reason = 'TenantAllowBlockListMemberNotRequired'; Violations = @($member) }
            }
        }

        $expiryAndTicket = Get-SchemaNode -Document $tabl -Path @('properties', 'blockEntriesRequireExpiryAndTicket', 'const')
        if ($expiryAndTicket -ne $true) {
            return [ordered]@{ Reason = 'TenantAllowBlockListExpiryAndTicketNotFixed'; Violations = @() }
        }

        $quarantine = Get-SchemaNode -Document $defenderProperties -Path @('quarantinePolicies')
        $quarantineRequired = @(Get-SchemaNode -Document $quarantine -Path @('required'))
        $notificationInterval = Get-SchemaNode -Document $quarantine -Path @('properties', 'endUserSpamNotificationFrequencyInDays')
        if ($null -eq $notificationInterval) {
            return [ordered]@{ Reason = 'QuarantineNotificationIntervalSchemaMissing'; Violations = @() }
        }

        if ('endUserSpamNotificationFrequencyInDays' -notin $quarantineRequired) {
            return [ordered]@{ Reason = 'QuarantineNotificationIntervalNotRequired'; Violations = @() }
        }

        if (-not (Test-VocabularyDeclared -Node $notificationInterval)) {
            return [ordered]@{ Reason = 'QuarantineNotificationIntervalVocabularyUndeclared'; Violations = @() }
        }

        $categoryPermissions = Get-SchemaNode -Document $quarantine -Path @('properties', 'categoryPermissions')
        if ($null -eq $categoryPermissions) {
            return [ordered]@{ Reason = 'QuarantineCategoryPermissionsSchemaMissing'; Violations = @() }
        }

        if ('categoryPermissions' -notin $quarantineRequired) {
            return [ordered]@{ Reason = 'QuarantineCategoryPermissionsNotRequired'; Violations = @() }
        }

        $permissionRequired = @(Get-SchemaNode -Document $categoryPermissions -Path @('items', 'required'))
        foreach ($member in $script:QuarantineCategoryPermissionMember) {
            if ($member -notin $permissionRequired) {
                return [ordered]@{ Reason = 'QuarantineCategoryPermissionMemberNotRequired'; Violations = @($member) }
            }
        }

        $accessLevel = Get-SchemaNode -Document $categoryPermissions -Path @('items', 'properties', 'accessLevel')
        if (-not (Test-VocabularyDeclared -Node $accessLevel)) {
            return [ordered]@{ Reason = 'QuarantineAccessLevelVocabularyUndeclared'; Violations = @() }
        }

        return $null
    }

    function Get-DefenderConfigurationViolation {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Document
        )

        $defender = Get-SchemaNode -Document $Document -Path @('desiredState', 'defenderForOffice365')
        if ($null -eq $defender) {
            return [ordered]@{ Reason = 'DefenderDesiredStateMissing'; Violations = @() }
        }

        foreach ($section in $script:DefenderSection) {
            if ($null -eq (Get-SchemaNode -Document $defender -Path @($section))) {
                return [ordered]@{ Reason = 'DefenderMemberUndefined'; Violations = @($section) }
            }
        }

        $impersonation = Get-SchemaNode -Document $defender -Path @('impersonationProtection')
        if (-not (Test-NonEmptyStringList -Node (Get-SchemaNode -Document $impersonation -Path @('protectedUsers')))) {
            return [ordered]@{ Reason = 'ImpersonationProtectedUsersEmpty'; Violations = @() }
        }

        if (-not (Test-NonEmptyStringList -Node (Get-SchemaNode -Document $impersonation -Path @('protectedDomains')))) {
            return [ordered]@{ Reason = 'ImpersonationProtectedDomainsEmpty'; Violations = @() }
        }

        $approvedException = Get-SchemaNode -Document $impersonation -Path @('approvedExceptions')
        if (-not (Test-NodeMemberPresent -Node $impersonation -Name 'approvedExceptions')) {
            return [ordered]@{ Reason = 'ImpersonationExceptionsUndefined'; Violations = @() }
        }

        foreach ($entry in (Get-NodeItem -Node $approvedException)) {
            foreach ($field in $script:ImpersonationExceptionField) {
                $value = Get-SchemaNode -Document $entry -Path @($field)
                if ([string]::IsNullOrWhiteSpace([string]$value)) {
                    return [ordered]@{ Reason = 'ImpersonationExceptionIncomplete'; Violations = @($field) }
                }
            }
        }

        $submissions = Get-SchemaNode -Document $defender -Path @('userSubmissions')
        if ([string]::IsNullOrWhiteSpace([string](Get-SchemaNode -Document $submissions -Path @('reportingDestination')))) {
            return [ordered]@{ Reason = 'ReportingDestinationUndefined'; Violations = @() }
        }

        if ([string]::IsNullOrWhiteSpace([string](Get-SchemaNode -Document $submissions -Path @('reportingMailbox')))) {
            return [ordered]@{ Reason = 'ReportingMailboxUndefined'; Violations = @() }
        }

        $advancedDelivery = Get-SchemaNode -Document $defender -Path @('advancedDelivery')
        if (-not (Test-NonEmptyStringList -Node (Get-SchemaNode -Document $advancedDelivery -Path @('secOpsMailbox')))) {
            return [ordered]@{ Reason = 'AdvancedDeliverySecOpsMailboxEmpty'; Violations = @() }
        }

        $tabl = Get-SchemaNode -Document $defender -Path @('tenantAllowBlockList')
        if ([string]::IsNullOrWhiteSpace([string](Get-SchemaNode -Document $tabl -Path @('registerLocation')))) {
            return [ordered]@{ Reason = 'TenantAllowBlockListRegisterLocationUndefined'; Violations = @() }
        }

        $permanentAllow = Get-NodeItem -Node (Get-SchemaNode -Document $tabl -Path @('permanentAllowEntries'))
        if ($permanentAllow.Count -gt 0) {
            return [ordered]@{ Reason = 'TenantAllowBlockListPermanentAllowEntryPresent'; Violations = @() }
        }

        $allowDuration = Get-SchemaNode -Document $tabl -Path @('allowEntryMaximumDurationDays')
        $blockRetention = Get-SchemaNode -Document $tabl -Path @('blockEntryRetentionDays')
        if ($null -eq $allowDuration -or $null -eq $blockRetention -or [int]$blockRetention -le [int]$allowDuration) {
            return [ordered]@{ Reason = 'TenantAllowBlockListBlockRetentionNotSeparate'; Violations = @() }
        }

        $quarantine = Get-SchemaNode -Document $defender -Path @('quarantinePolicies')
        $interval = Get-SchemaNode -Document $quarantine -Path @('endUserSpamNotificationFrequencyInDays')
        if ($null -eq $interval) {
            return [ordered]@{ Reason = 'QuarantineNotificationIntervalUndefined'; Violations = @() }
        }

        $categoryPermission = Get-NodeItem -Node (Get-SchemaNode -Document $quarantine -Path @('categoryPermissions'))
        foreach ($category in $script:AdminOnlyCategory) {
            $declared = @($categoryPermission | Where-Object { [string](Get-SchemaNode -Document $_ -Path @('category')) -eq $category })
            if ($declared.Count -eq 0) {
                return [ordered]@{ Reason = 'QuarantineCategoryPermissionMissing'; Violations = @($category) }
            }

            $access = [string](Get-SchemaNode -Document $declared[0] -Path @('accessLevel'))
            if ($access -cne $script:AdminOnlyAccessLevel) {
                return [ordered]@{ Reason = 'QuarantineHighRiskNotAdminOnly'; Violations = @($category) }
            }
        }

        return $null
    }

    function Get-DefenderDesiredStateResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$SchemaPath,

            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [string[]]$ConfigurationPath
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
            $schema = Get-Content -LiteralPath $SchemaPath -Raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        }
        catch {
            $result.Reason = 'SchemaJsonInvalid'
            return [pscustomobject]$result
        }

        $schemaViolation = Get-DefenderSchemaViolation -Document $schema
        if ($null -ne $schemaViolation) {
            $result.Reason = $schemaViolation.Reason
            $result.Violations = @($schemaViolation.Violations)
            return [pscustomobject]$result
        }

        foreach ($path in @($ConfigurationPath)) {
            if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
                $result.Reason = 'ConfigurationFileMissing'
                return [pscustomobject]$result
            }

            try {
                $document = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
            }
            catch {
                $result.Reason = 'ConfigurationJsonInvalid'
                return [pscustomobject]$result
            }

            $configurationViolation = Get-DefenderConfigurationViolation -Document $document
            if ($null -ne $configurationViolation) {
                $result.Reason = $configurationViolation.Reason
                $result.Violations = @($configurationViolation.Violations) + @([System.IO.Path]::GetFileName($path))
                return [pscustomobject]$result
            }
        }

        $result.Satisfied = $true
        $result.Reason = 'DefenderDesiredStateSatisfied'
        $result.Violations = @()
        return [pscustomobject]$result
    }

    function New-MutatedJsonFile {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$SourcePath,

            [Parameter(Mandatory)]
            [string]$Directory,

            [Parameter(Mandatory)]
            [scriptblock]$Mutate
        )

        $document = Get-Content -LiteralPath $SourcePath -Raw | ConvertFrom-Json -AsHashtable
        & $Mutate $document

        $path = Join-Path $Directory ('Mutated-{0}.json' -f [guid]::NewGuid().ToString('N'))
        $document | ConvertTo-Json -Depth 64 | Set-Content -LiteralPath $path -Encoding utf8
        return $path
    }

    function New-MutatedSchemaFile {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Directory,

            [Parameter(Mandatory)]
            [scriptblock]$Mutate
        )

        return New-MutatedJsonFile -SourcePath $script:SchemaPath -Directory $Directory -Mutate $Mutate
    }

    function New-MutatedConfigurationFile {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Directory,

            [Parameter(Mandatory)]
            [scriptblock]$Mutate
        )

        return New-MutatedJsonFile -SourcePath $script:GatewayConfigurationPath -Directory $Directory -Mutate $Mutate
    }
}

Describe 'MDO-001-A Defender desired-state contract' {

    Context 'Negative: the schema document must be usable' {

        It 'reports SchemaFileMissing when the schema file is absent' {
            # Arrange
            $absentSchema = Join-Path $TestDrive 'absent-schema.json'

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $absentSchema -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an absent schema constrains nothing'
            $result.Reason | Should -Be 'SchemaFileMissing'
        }

        It 'reports SchemaJsonInvalid when the schema file is malformed JSON' {
            # Arrange
            $malformedSchema = Join-Path $TestDrive 'malformed-schema.json'
            Set-Content -LiteralPath $malformedSchema -Value '{ "properties": ' -Encoding utf8

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $malformedSchema -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a malformed schema constrains nothing'
            $result.Reason | Should -Be 'SchemaJsonInvalid'
        }

        It 'reports DefenderSchemaMissing when the schema constrains no Defender desired state' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['properties']['desiredState']['properties'].Remove('defenderForOffice365')
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an unconstrained Defender section admits any desired state at all'
            $result.Reason | Should -Be 'DefenderSchemaMissing'
        }
    }

    Context 'Negative: every Defender section the MDO controls decide must be constrained and required' {

        It 'reports DefenderMemberSchemaMissing when the schema constrains no <Section>' -ForEach @(
            @{ Section = 'impersonationProtection' }
            @{ Section = 'userSubmissions' }
            @{ Section = 'advancedDelivery' }
            @{ Section = 'tenantAllowBlockList' }
            @{ Section = 'quarantinePolicies' }
        ) {
            # Arrange
            $removed = $Section
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties'].Remove($removed)
            }.GetNewClosure()

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an unconstrained section admits a desired state the control cannot decide'
            $result.Reason | Should -Be 'DefenderMemberSchemaMissing'
            $result.Violations | Should -Contain $Section
        }

        It 'reports DefenderMemberNotRequired when <Section> is optional' -ForEach @(
            @{ Section = 'impersonationProtection' }
            @{ Section = 'userSubmissions' }
            @{ Section = 'advancedDelivery' }
            @{ Section = 'tenantAllowBlockList' }
            @{ Section = 'quarantinePolicies' }
        ) {
            # Arrange
            $optional = $Section
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $defender = $document['properties']['desiredState']['properties']['defenderForOffice365']
                $defender['required'] = @($defender['required'] | Where-Object { $_ -ne $optional })
            }.GetNewClosure()

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an optional section lets a baseline ship with no desired state for it'
            $result.Reason | Should -Be 'DefenderMemberNotRequired'
            $result.Violations | Should -Contain $Section
        }
    }

    Context 'Negative: impersonation protection must name who and what it protects' {

        It 'reports ImpersonationMemberNotRequired when <Member> is optional' -ForEach @(
            @{ Member = 'protectedUsers' }
            @{ Member = 'protectedDomains' }
            @{ Member = 'approvedExceptions' }
        ) {
            # Arrange
            $optional = $Member
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $impersonation = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['impersonationProtection']
                $impersonation['required'] = @($impersonation['required'] | Where-Object { $_ -ne $optional })
            }.GetNewClosure()

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'impersonation protection that omits this member protects nobody the control can name'
            $result.Reason | Should -Be 'ImpersonationMemberNotRequired'
            $result.Violations | Should -Contain $Member
        }

        It 'reports ImpersonationExceptionFieldNotRequired when an approved exception may omit its <Field>' -ForEach @(
            @{ Field = 'value' }
            @{ Field = 'owner' }
            @{ Field = 'ticket' }
            @{ Field = 'expirationDateTime' }
        ) {
            # Arrange
            $optional = $Field
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $items = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['impersonationProtection']['properties']['approvedExceptions']['items']
                $items['required'] = @($items['required'] | Where-Object { $_ -ne $optional })
            }.GetNewClosure()

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an exception nobody owns, tickets or expires is a permanent unreviewed hole'
            $result.Reason | Should -Be 'ImpersonationExceptionFieldNotRequired'
            $result.Violations | Should -Contain $Field
        }
    }

    Context 'Negative: the reporting destination must be exact' {

        It 'reports ReportingDestinationSchemaMissing when the schema constrains no reporting destination' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['userSubmissions']['properties'].Remove('reportingDestination')
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a report that goes somewhere undeclared cannot be verified as exact'
            $result.Reason | Should -Be 'ReportingDestinationSchemaMissing'
        }

        It 'reports ReportingDestinationNotRequired when the reporting destination is optional' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $submissions = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['userSubmissions']
                $submissions['required'] = @($submissions['required'] | Where-Object { $_ -ne 'reportingDestination' })
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an omitted destination leaves user submissions going wherever the tenant happens to send them'
            $result.Reason | Should -Be 'ReportingDestinationNotRequired'
        }

        It 'reports ReportingDestinationVocabularyUndeclared when the destination admits a value outside the declared vocabulary' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['userSubmissions']['properties']['reportingDestination'] = @{ type = 'string' }
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an unconstrained destination admits a state the control cannot compare against'
            $result.Reason | Should -Be 'ReportingDestinationVocabularyUndeclared'
        }

        It 'reports ReportingMailboxNotRequired when the reporting mailbox is optional' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $submissions = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['userSubmissions']
                $submissions['required'] = @($submissions['required'] | Where-Object { $_ -ne 'reportingMailbox' })
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a destination that names no mailbox cannot be compared to the one the tenant reports to'
            $result.Reason | Should -Be 'ReportingMailboxNotRequired'
        }
    }

    Context 'Negative: Advanced Delivery must register the SecOps mailbox' {

        It 'reports AdvancedDeliverySecOpsMailboxSchemaMissing when the schema constrains no SecOps mailbox' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['advancedDelivery']['properties'].Remove('secOpsMailbox')
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'Advanced Delivery exists to exempt a named mailbox, so the mailbox must be declared'
            $result.Reason | Should -Be 'AdvancedDeliverySecOpsMailboxSchemaMissing'
        }

        It 'reports AdvancedDeliverySecOpsMailboxNotRequired when the SecOps mailbox is optional' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $advancedDelivery = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['advancedDelivery']
                $advancedDelivery['required'] = @($advancedDelivery['required'] | Where-Object { $_ -ne 'secOpsMailbox' })
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an optional mailbox lets Advanced Delivery ship exempting nothing'
            $result.Reason | Should -Be 'AdvancedDeliverySecOpsMailboxNotRequired'
        }
    }

    Context 'Negative: the tenant allow/block list must declare its register and its policy' {

        It 'reports TenantAllowBlockListMemberNotRequired when <Member> is optional' -ForEach @(
            @{ Member = 'registerLocation' }
            @{ Member = 'allowEntryMaximumDurationDays' }
            @{ Member = 'blockEntryRetentionDays' }
            @{ Member = 'requiredEntryFields' }
            @{ Member = 'blockEntriesRequireExpiryAndTicket' }
        ) {
            # Arrange
            $optional = $Member
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $tabl = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['tenantAllowBlockList']
                $tabl['required'] = @($tabl['required'] | Where-Object { $_ -ne $optional })
            }.GetNewClosure()

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an allow entry with no declared register, duration or evidence rule is an unreviewed bypass'
            $result.Reason | Should -Be 'TenantAllowBlockListMemberNotRequired'
            $result.Violations | Should -Contain $Member
        }

        It 'reports TenantAllowBlockListExpiryAndTicketNotFixed when the expiry-and-ticket rule may be turned off' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['tenantAllowBlockList']['properties']['blockEntriesRequireExpiryAndTicket'] = @{ type = 'boolean' }
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a rule a baseline may switch off is not a rule'
            $result.Reason | Should -Be 'TenantAllowBlockListExpiryAndTicketNotFixed'
        }
    }

    Context 'Negative: quarantine cadence and category permissions must be exact' {

        It 'reports QuarantineNotificationIntervalSchemaMissing when the schema constrains no notification interval' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['quarantinePolicies']['properties'].Remove('endUserSpamNotificationFrequencyInDays')
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an undeclared cadence cannot be verified as exact'
            $result.Reason | Should -Be 'QuarantineNotificationIntervalSchemaMissing'
        }

        It 'reports QuarantineNotificationIntervalNotRequired when the notification interval is optional' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $quarantine = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['quarantinePolicies']
                $quarantine['required'] = @($quarantine['required'] | Where-Object { $_ -ne 'endUserSpamNotificationFrequencyInDays' })
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an omitted cadence leaves end users notified on whatever schedule the tenant defaults to'
            $result.Reason | Should -Be 'QuarantineNotificationIntervalNotRequired'
        }

        It 'reports QuarantineNotificationIntervalVocabularyUndeclared when the interval admits a value the service does not support' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['quarantinePolicies']['properties']['endUserSpamNotificationFrequencyInDays'] = @{ type = 'integer' }
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an unconstrained interval admits a cadence the service will never report back'
            $result.Reason | Should -Be 'QuarantineNotificationIntervalVocabularyUndeclared'
        }

        It 'reports QuarantineCategoryPermissionsSchemaMissing when the schema constrains no category permissions' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['quarantinePolicies']['properties'].Remove('categoryPermissions')
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a quarantine desired state that names no category decides no category'
            $result.Reason | Should -Be 'QuarantineCategoryPermissionsSchemaMissing'
        }

        It 'reports QuarantineCategoryPermissionsNotRequired when the category permissions are optional' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $quarantine = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['quarantinePolicies']
                $quarantine['required'] = @($quarantine['required'] | Where-Object { $_ -ne 'categoryPermissions' })
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'optional category permissions let the high-risk categories go undeclared'
            $result.Reason | Should -Be 'QuarantineCategoryPermissionsNotRequired'
        }

        It 'reports QuarantineCategoryPermissionMemberNotRequired when a category permission may omit its <Member>' -ForEach @(
            @{ Member = 'category' }
            @{ Member = 'accessLevel' }
        ) {
            # Arrange
            $optional = $Member
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $items = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['quarantinePolicies']['properties']['categoryPermissions']['items']
                $items['required'] = @($items['required'] | Where-Object { $_ -ne $optional })
            }.GetNewClosure()

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a permission that names no category or no access level grants nothing decidable'
            $result.Reason | Should -Be 'QuarantineCategoryPermissionMemberNotRequired'
            $result.Violations | Should -Contain $Member
        }

        It 'reports QuarantineAccessLevelVocabularyUndeclared when the access level admits a value outside the declared vocabulary' {
            # Arrange
            $schemaPath = New-MutatedSchemaFile -Directory $TestDrive -Mutate {
                param($document)
                $items = $document['properties']['desiredState']['properties']['defenderForOffice365']['properties']['quarantinePolicies']['properties']['categoryPermissions']['items']
                $items['properties']['accessLevel'] = @{ type = 'string' }
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $script:ShippedConfigurationPath

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an unconstrained access level admits a permission the control cannot classify'
            $result.Reason | Should -Be 'QuarantineAccessLevelVocabularyUndeclared'
        }
    }

    Context 'Negative: the shipped configuration document must be usable' {

        It 'reports ConfigurationFileMissing when a shipped configuration document is absent' {
            # Arrange
            $absentConfiguration = Join-Path $TestDrive 'absent-configuration.json'

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($absentConfiguration)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an absent document resolves no desired state'
            $result.Reason | Should -Be 'ConfigurationFileMissing'
        }

        It 'reports ConfigurationJsonInvalid when a shipped configuration document is malformed JSON' {
            # Arrange
            $malformedConfiguration = Join-Path $TestDrive 'malformed-configuration.json'
            Set-Content -LiteralPath $malformedConfiguration -Value '{ "desiredState": ' -Encoding utf8

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($malformedConfiguration)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a malformed document resolves no desired state'
            $result.Reason | Should -Be 'ConfigurationJsonInvalid'
        }

        It 'reports DefenderDesiredStateMissing when a shipped configuration document declares no Defender desired state' {
            # Arrange
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['desiredState'].Remove('defenderForOffice365')
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a profile that declares no Defender desired state ships with none'
            $result.Reason | Should -Be 'DefenderDesiredStateMissing'
        }

        It 'reports DefenderMemberUndefined when a shipped configuration document defines no <Section>' -ForEach @(
            @{ Section = 'impersonationProtection' }
            @{ Section = 'userSubmissions' }
            @{ Section = 'advancedDelivery' }
            @{ Section = 'tenantAllowBlockList' }
            @{ Section = 'quarantinePolicies' }
        ) {
            # Arrange
            $removed = $Section
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['desiredState']['defenderForOffice365'].Remove($removed)
            }.GetNewClosure()

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a section the document never defines cannot be compared to the tenant'
            $result.Reason | Should -Be 'DefenderMemberUndefined'
            $result.Violations | Should -Contain $Section
        }
    }

    Context 'Negative: the shipped configuration must name what impersonation protection covers' {

        It 'reports ImpersonationProtectedUsersEmpty when the document names no protected user' {
            # Arrange
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $document['desiredState']['defenderForOffice365']['impersonationProtection']['protectedUsers'] = @()
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'impersonation protection that names no user protects no user'
            $result.Reason | Should -Be 'ImpersonationProtectedUsersEmpty'
        }

        It 'reports ImpersonationProtectedDomainsEmpty when the document names no custom protected domain' {
            # Arrange
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $document['desiredState']['defenderForOffice365']['impersonationProtection']['protectedDomains'] = @()
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'the owned domains are exactly the ones Defender does not protect by default'
            $result.Reason | Should -Be 'ImpersonationProtectedDomainsEmpty'
        }

        It 'reports ImpersonationExceptionsUndefined when the document defines no approved-exception member' {
            # Arrange
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['desiredState']['defenderForOffice365']['impersonationProtection'].Remove('approvedExceptions')
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an undefined exception list cannot be compared to the trusted senders the tenant actually holds'
            $result.Reason | Should -Be 'ImpersonationExceptionsUndefined'
        }

        It 'reports ImpersonationExceptionIncomplete when an approved exception names no <Field>' -ForEach @(
            @{ Field = 'value' }
            @{ Field = 'owner' }
            @{ Field = 'ticket' }
            @{ Field = 'expirationDateTime' }
        ) {
            # Arrange
            $omitted = $Field
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $entry = [ordered]@{
                    exceptionType      = 'TrustedSender'
                    value              = 'partner@fabrikam.example'
                    owner              = 'secops.owner@contoso.example'
                    ticket             = 'CHG0012345'
                    expirationDateTime = '2026-12-31T00:00:00Z'
                    justification      = 'Approved partner bulk sender'
                }
                $entry[$omitted] = ''
                $document['desiredState']['defenderForOffice365']['impersonationProtection']['approvedExceptions'] = @($entry)
            }.GetNewClosure()

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an exception that omits this field cannot be reviewed or retired'
            $result.Reason | Should -Be 'ImpersonationExceptionIncomplete'
            $result.Violations | Should -Contain $Field
        }
    }

    Context 'Negative: the shipped configuration must name the reporting destination and the Advanced Delivery mailbox' {

        It 'reports ReportingDestinationUndefined when the document names no reporting destination' {
            # Arrange
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['desiredState']['defenderForOffice365']['userSubmissions'].Remove('reportingDestination')
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'the destination is the member the report submission policy is compared against'
            $result.Reason | Should -Be 'ReportingDestinationUndefined'
        }

        It 'reports ReportingMailboxUndefined when the document names no reporting mailbox' {
            # Arrange
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $document['desiredState']['defenderForOffice365']['userSubmissions']['reportingMailbox'] = '   '
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a destination with no mailbox names nowhere for a reported message to land'
            $result.Reason | Should -Be 'ReportingMailboxUndefined'
        }

        It 'reports AdvancedDeliverySecOpsMailboxEmpty when the document registers no SecOps mailbox' {
            # Arrange
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $document['desiredState']['defenderForOffice365']['advancedDelivery']['secOpsMailbox'] = @()
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an unregistered SecOps mailbox has its simulated phish filtered like any other mailbox'
            $result.Reason | Should -Be 'AdvancedDeliverySecOpsMailboxEmpty'
        }
    }

    Context 'Negative: the shipped configuration must declare the tenant allow/block register and policy' {

        It 'reports TenantAllowBlockListRegisterLocationUndefined when the document names no register location' {
            # Arrange
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['desiredState']['defenderForOffice365']['tenantAllowBlockList'].Remove('registerLocation')
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an entry with no register of record cannot be traced to the approval that created it'
            $result.Reason | Should -Be 'TenantAllowBlockListRegisterLocationUndefined'
        }

        It 'reports TenantAllowBlockListPermanentAllowEntryPresent when the document ships a permanent allow entry' {
            # Arrange
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $document['desiredState']['defenderForOffice365']['tenantAllowBlockList']['permanentAllowEntries'] = @('fabrikam.example')
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a permanent allow entry is a filtering bypass that never expires'
            $result.Reason | Should -Be 'TenantAllowBlockListPermanentAllowEntryPresent'
        }

        It 'reports TenantAllowBlockListBlockRetentionNotSeparate when a block entry is not retained longer than an allow entry may live' {
            # Arrange
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $tabl = $document['desiredState']['defenderForOffice365']['tenantAllowBlockList']
                $tabl['blockEntryRetentionDays'] = $tabl['allowEntryMaximumDurationDays']
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a block must outlive the allow window it exists to override'
            $result.Reason | Should -Be 'TenantAllowBlockListBlockRetentionNotSeparate'
        }
    }

    Context 'Negative: the shipped configuration must fix the quarantine cadence and the high-risk categories' {

        It 'reports QuarantineNotificationIntervalUndefined when the document names no notification interval' {
            # Arrange
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $null = $document['desiredState']['defenderForOffice365']['quarantinePolicies'].Remove('endUserSpamNotificationFrequencyInDays')
            }

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'the interval is the exact cadence the quarantine control compares against'
            $result.Reason | Should -Be 'QuarantineNotificationIntervalUndefined'
        }

        It 'reports QuarantineCategoryPermissionMissing when the document declares no permission for <Category>' -ForEach @(
            @{ Category = 'Malware' }
            @{ Category = 'HighConfidencePhish' }
        ) {
            # Arrange
            $dropped = $Category
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $quarantine = $document['desiredState']['defenderForOffice365']['quarantinePolicies']
                $quarantine['categoryPermissions'] = @($quarantine['categoryPermissions'] | Where-Object { $_['category'] -ne $dropped })
            }.GetNewClosure()

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an undeclared high-risk category is released on whatever the tenant defaults to'
            $result.Reason | Should -Be 'QuarantineCategoryPermissionMissing'
            $result.Violations | Should -Contain $Category
        }

        It 'reports QuarantineHighRiskNotAdminOnly when <Category> is quarantined at anything other than admin-only access' -ForEach @(
            @{ Category = 'Malware' }
            @{ Category = 'HighConfidencePhish' }
        ) {
            # Arrange
            $relaxed = $Category
            $configurationPath = New-MutatedConfigurationFile -Directory $TestDrive -Mutate {
                param($document)
                $quarantine = $document['desiredState']['defenderForOffice365']['quarantinePolicies']
                $quarantine['categoryPermissions'] = @($quarantine['categoryPermissions'] | ForEach-Object {
                        if ($_['category'] -eq $relaxed) { $_['accessLevel'] = 'LimitedAccess' }
                        $_
                    })
            }.GetNewClosure()

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $script:SchemaPath -ConfigurationPath @($configurationPath)

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an end user who can release malware or high-confidence phish is the delivery mechanism'
            $result.Reason | Should -Be 'QuarantineHighRiskNotAdminOnly'
            $result.Violations | Should -Contain $Category
        }
    }

    Context 'Positive: the shipped schema and both shipped configuration documents define the Defender desired state' {

        It 'constrains impersonation protection, the reporting destination, the Advanced Delivery mailbox, the tenant allow/block register and the quarantine cadence and category permissions, and both shipped profiles define every one of them' {
            # Arrange
            $schemaPath = $script:SchemaPath
            $configurationPath = $script:ShippedConfigurationPath

            # Act
            $result = Get-DefenderDesiredStateResult -SchemaPath $schemaPath -ConfigurationPath $configurationPath

            # Assert
            $result.Satisfied | Should -BeTrue -Because "the shipped artifacts must satisfy MDO-001 but reported '$($result.Reason)' for '$($result.Violations -join ', ')'"
            $result.Reason | Should -Be 'DefenderDesiredStateSatisfied'
        }
    }
}
