#requires -Version 7.0

# Discovery-scope copies so the per-input and per-source negative cases can be expanded by -ForEach.
$ApplicabilityInputs = @('DeploymentProfile', 'ActualServicePlan', 'CatalogControlPriority')
$AuthoritySources = @('RuntimeGraphServicePlan', 'DeclaredLicensingMetadata')

BeforeAll {
    $script:ApplicabilityInputs = @('DeploymentProfile', 'ActualServicePlan', 'CatalogControlPriority')
    $script:AuthoritySources = @('RuntimeGraphServicePlan', 'DeclaredLicensingMetadata')
    $script:RuntimeSource = 'RuntimeGraphServicePlan'
    $script:DeclaredSource = 'DeclaredLicensingMetadata'
    $script:RequiredConflictResolution = 'RuntimeGraphWins'

    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    function Get-ApplicabilityContractVerdict {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            $Contract
        )

        $verdict = [ordered]@{
            Satisfied  = $false
            Reason     = $null
            Violations = @()
        }

        if ($null -eq $Contract) {
            $verdict.Reason = 'ContractMissing'
            return [pscustomobject]$verdict
        }

        foreach ($property in @('ApplicabilityInput', 'Authority', 'ConflictResolution')) {
            if ($null -eq $Contract.PSObject.Properties[$property]) {
                $verdict.Reason = 'ContractMissing'
                $verdict.Violations = @($property)
                return [pscustomobject]$verdict
            }
        }

        $inputs = @($Contract.ApplicabilityInput)
        $authority = @($Contract.Authority)

        $missingInputs = @($script:ApplicabilityInputs | Where-Object { $_ -notin $inputs })
        if ($missingInputs.Count -gt 0) {
            $verdict.Reason = 'ApplicabilityInputMissing'
            $verdict.Violations = $missingInputs
            return [pscustomobject]$verdict
        }

        $unknownInputs = @($inputs | Where-Object { $_ -notin $script:ApplicabilityInputs })
        if ($unknownInputs.Count -gt 0) {
            $verdict.Reason = 'UnknownApplicabilityInput'
            $verdict.Violations = $unknownInputs
            return [pscustomobject]$verdict
        }

        $declaredSources = @($authority | ForEach-Object { $_.Source })
        $missingSources = @($script:AuthoritySources | Where-Object { $_ -notin $declaredSources })
        if ($missingSources.Count -gt 0) {
            $verdict.Reason = 'AuthoritySourceMissing'
            $verdict.Violations = $missingSources
            return [pscustomobject]$verdict
        }

        $runtime = $authority | Where-Object { $_.Source -eq $script:RuntimeSource } | Select-Object -First 1
        $declared = $authority | Where-Object { $_.Source -eq $script:DeclaredSource } | Select-Object -First 1

        if (-not $runtime.Authoritative) {
            $verdict.Reason = 'RuntimeGraphNotAuthoritative'
            $verdict.Violations = @($script:RuntimeSource)
            return [pscustomobject]$verdict
        }

        if ($declared.Authoritative) {
            $verdict.Reason = 'DeclaredMetadataAuthoritative'
            $verdict.Violations = @($script:DeclaredSource)
            return [pscustomobject]$verdict
        }

        if ($runtime.Precedence -ge $declared.Precedence) {
            $verdict.Reason = 'RuntimeGraphNotHighestPrecedence'
            $verdict.Violations = @("$($runtime.Precedence)", "$($declared.Precedence)")
            return [pscustomobject]$verdict
        }

        if ([string]::IsNullOrWhiteSpace($Contract.ConflictResolution)) {
            $verdict.Reason = 'ConflictResolutionMissing'
            return [pscustomobject]$verdict
        }

        if ($Contract.ConflictResolution -ne $script:RequiredConflictResolution) {
            $verdict.Reason = 'ConflictResolutionFavoursDeclaredMetadata'
            $verdict.Violations = @($Contract.ConflictResolution)
            return [pscustomobject]$verdict
        }

        $verdict.Satisfied = $true
        $verdict.Reason = 'ApplicabilityContractSatisfied'
        return [pscustomobject]$verdict
    }

    function New-ApplicabilityContractFixture {
        [CmdletBinding()]
        param(
            [string]$OmitInput,
            [string]$AddInput,
            [string]$OmitSource,
            [switch]$RuntimeNotAuthoritative,
            [switch]$DeclaredAuthoritative,
            [switch]$InvertPrecedence,
            [AllowEmptyString()]
            [string]$ConflictResolution = 'RuntimeGraphWins'
        )

        $inputs = [System.Collections.Generic.List[string]]::new()
        foreach ($name in $script:ApplicabilityInputs) {
            if ($name -eq $OmitInput) { continue }
            $inputs.Add($name)
        }
        if ($AddInput) { $inputs.Add($AddInput) }

        $runtimePrecedence = if ($InvertPrecedence) { 2 } else { 1 }
        $declaredPrecedence = if ($InvertPrecedence) { 1 } else { 2 }

        $authority = [System.Collections.Generic.List[object]]::new()
        if ($OmitSource -ne $script:RuntimeSource) {
            $authority.Add([pscustomobject]@{
                    Source        = $script:RuntimeSource
                    Precedence    = $runtimePrecedence
                    Authoritative = (-not $RuntimeNotAuthoritative)
                })
        }
        if ($OmitSource -ne $script:DeclaredSource) {
            $authority.Add([pscustomobject]@{
                    Source        = $script:DeclaredSource
                    Precedence    = $declaredPrecedence
                    Authoritative = [bool]$DeclaredAuthoritative
                })
        }

        return [pscustomobject]@{
            ApplicabilityInput = @($inputs)
            Authority          = @($authority)
            ConflictResolution = $ConflictResolution
        }
    }
}

Describe 'DES-003-A applicability and entitlement authority contract' {

    Context 'Negative: the contract is not satisfied' {

        It 'reports ContractMissing when no contract is published' {
            # Arrange
            $contract = $null

            # Act
            $verdict = Get-ApplicabilityContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'an absent contract defines no applicability authority'
            $verdict.Reason | Should -Be 'ContractMissing'
        }

        It "reports ApplicabilityInputMissing when '<_>' is not an applicability input" -ForEach $ApplicabilityInputs {
            # Arrange
            $applicabilityInput = $_
            $contract = New-ApplicabilityContractFixture -OmitInput $applicabilityInput

            # Act
            $verdict = Get-ApplicabilityContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because "$applicabilityInput is a required applicability input"
            $verdict.Reason | Should -Be 'ApplicabilityInputMissing'
            $verdict.Violations | Should -Be @($applicabilityInput)
        }

        It 'reports UnknownApplicabilityInput when an undeclared input is published' {
            # Arrange
            $contract = New-ApplicabilityContractFixture -AddInput 'OperatorOpinion'

            # Act
            $verdict = Get-ApplicabilityContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'applicability uses only the declared inputs'
            $verdict.Reason | Should -Be 'UnknownApplicabilityInput'
            $verdict.Violations | Should -Be @('OperatorOpinion')
        }

        It "reports AuthoritySourceMissing when '<_>' is not an authority source" -ForEach $AuthoritySources {
            # Arrange
            $source = $_
            $contract = New-ApplicabilityContractFixture -OmitSource $source

            # Act
            $verdict = Get-ApplicabilityContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because "$source must be ranked by the contract"
            $verdict.Reason | Should -Be 'AuthoritySourceMissing'
            $verdict.Violations | Should -Be @($source)
        }

        It 'reports RuntimeGraphNotAuthoritative when runtime Graph results are advisory' {
            # Arrange
            $contract = New-ApplicabilityContractFixture -RuntimeNotAuthoritative

            # Act
            $verdict = Get-ApplicabilityContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'runtime Graph service plans are the entitlement authority'
            $verdict.Reason | Should -Be 'RuntimeGraphNotAuthoritative'
        }

        It 'reports DeclaredMetadataAuthoritative when declared licensing metadata is authoritative' {
            # Arrange
            $contract = New-ApplicabilityContractFixture -DeclaredAuthoritative

            # Act
            $verdict = Get-ApplicabilityContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'declared licensing metadata is a planning expectation only'
            $verdict.Reason | Should -Be 'DeclaredMetadataAuthoritative'
        }

        It 'reports RuntimeGraphNotHighestPrecedence when declared metadata outranks runtime Graph results' {
            # Arrange
            $contract = New-ApplicabilityContractFixture -InvertPrecedence

            # Act
            $verdict = Get-ApplicabilityContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'runtime Graph results must outrank declared metadata'
            $verdict.Reason | Should -Be 'RuntimeGraphNotHighestPrecedence'
        }

        It 'reports ConflictResolutionMissing when conflict resolution is not declared' {
            # Arrange
            $contract = New-ApplicabilityContractFixture -ConflictResolution ''

            # Act
            $verdict = Get-ApplicabilityContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'conflicts between sources must resolve deterministically'
            $verdict.Reason | Should -Be 'ConflictResolutionMissing'
        }

        It 'reports ConflictResolutionFavoursDeclaredMetadata when declared metadata wins conflicts' {
            # Arrange
            $contract = New-ApplicabilityContractFixture -ConflictResolution 'DeclaredMetadataWins'

            # Act
            $verdict = Get-ApplicabilityContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'runtime Graph results override declared licensing metadata'
            $verdict.Reason | Should -Be 'ConflictResolutionFavoursDeclaredMetadata'
            $verdict.Violations | Should -Be @('DeclaredMetadataWins')
        }
    }

    Context 'Positive: the contract is satisfied' {

        It 'declares profile, actual service plans, and catalog priority as inputs with runtime Graph results overriding declared metadata' {
            # Arrange
            Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking
            $contract = Get-ApplicabilityAuthorityContract

            # Act
            $verdict = Get-ApplicabilityContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeTrue -Because "contract violation: $($verdict.Reason) $($verdict.Violations -join ', ')"
        }
    }
}
