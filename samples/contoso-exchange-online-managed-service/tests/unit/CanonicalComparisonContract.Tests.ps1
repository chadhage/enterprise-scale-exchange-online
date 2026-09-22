#requires -Version 7.0

# Discovery-scope copy so the per-kind negative cases can be expanded by -ForEach.
$CanonicalKinds = @('SmtpAddress', 'Domain', 'Group', 'IpAddress', 'Identity')

BeforeAll {
    $script:CanonicalKinds = @('SmtpAddress', 'Domain', 'Group', 'IpAddress', 'Identity')
    $script:RequiredCollectionEquality = 'NormalizedSetEquality'

    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    function Get-CanonicalContractVerdict {
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

        foreach ($property in @('Kind', 'CollectionEquality')) {
            if ($null -eq $Contract.PSObject.Properties[$property]) {
                $verdict.Reason = 'ContractMissing'
                $verdict.Violations = @($property)
                return [pscustomobject]$verdict
            }
        }

        $kinds = @($Contract.Kind)
        $declaredNames = @($kinds | ForEach-Object { $_.Kind })

        $missingKinds = @($script:CanonicalKinds | Where-Object { $_ -notin $declaredNames })
        if ($missingKinds.Count -gt 0) {
            $verdict.Reason = 'CanonicalKindMissing'
            $verdict.Violations = $missingKinds
            return [pscustomobject]$verdict
        }

        $unknownKinds = @($declaredNames | Where-Object { $_ -notin $script:CanonicalKinds })
        if ($unknownKinds.Count -gt 0) {
            $verdict.Reason = 'UnknownCanonicalKind'
            $verdict.Violations = $unknownKinds
            return [pscustomobject]$verdict
        }

        $orderSensitive = @($kinds | Where-Object { $_.Ordered } | ForEach-Object { $_.Kind })
        if ($orderSensitive.Count -gt 0) {
            $verdict.Reason = 'OrderSensitiveKind'
            $verdict.Violations = $orderSensitive
            return [pscustomobject]$verdict
        }

        $caseSensitive = @($kinds | Where-Object { -not $_.CaseInsensitive } | ForEach-Object { $_.Kind })
        if ($caseSensitive.Count -gt 0) {
            $verdict.Reason = 'CaseSensitiveKind'
            $verdict.Violations = $caseSensitive
            return [pscustomobject]$verdict
        }

        $withoutRules = @($kinds | Where-Object { @($_.NormalizationRule).Count -eq 0 } | ForEach-Object { $_.Kind })
        if ($withoutRules.Count -gt 0) {
            $verdict.Reason = 'NormalizationRuleMissing'
            $verdict.Violations = $withoutRules
            return [pscustomobject]$verdict
        }

        if ([string]::IsNullOrWhiteSpace($Contract.CollectionEquality)) {
            $verdict.Reason = 'CollectionEqualityMissing'
            return [pscustomobject]$verdict
        }

        if ($Contract.CollectionEquality -ne $script:RequiredCollectionEquality) {
            $verdict.Reason = 'CollectionEqualityNotNormalized'
            $verdict.Violations = @($Contract.CollectionEquality)
            return [pscustomobject]$verdict
        }

        $verdict.Satisfied = $true
        $verdict.Reason = 'CanonicalContractSatisfied'
        return [pscustomobject]$verdict
    }

    function New-CanonicalContractFixture {
        [CmdletBinding()]
        param(
            [string]$OmitKind,
            [string]$AddKind,
            [string]$OrderedKind,
            [string]$CaseSensitiveKind,
            [string]$WithoutNormalizationRuleKind,
            [AllowEmptyString()]
            [string]$CollectionEquality = 'NormalizedSetEquality'
        )

        $kinds = [System.Collections.Generic.List[object]]::new()
        foreach ($name in $script:CanonicalKinds) {
            if ($name -eq $OmitKind) { continue }

            $kinds.Add([pscustomobject]@{
                    Kind              = $name
                    Ordered           = ($name -eq $OrderedKind)
                    CaseInsensitive   = ($name -ne $CaseSensitiveKind)
                    NormalizationRule = if ($name -eq $WithoutNormalizationRuleKind) { @() } else { @('Trim', 'LowerInvariant', 'RemoveEmptyEntry', 'RemoveDuplicate') }
                })
        }

        if ($AddKind) {
            $kinds.Add([pscustomobject]@{
                    Kind              = $AddKind
                    Ordered           = $false
                    CaseInsensitive   = $true
                    NormalizationRule = @('Trim')
                })
        }

        return [pscustomobject]@{
            Kind               = @($kinds)
            CollectionEquality = $CollectionEquality
        }
    }
}

Describe 'DES-002-A canonical comparison contract' {

    Context 'Negative: the contract is not satisfied' {

        It 'reports ContractMissing when no contract is published' {
            # Arrange
            $contract = $null

            # Act
            $verdict = Get-CanonicalContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'an absent contract defines no canonical rules'
            $verdict.Reason | Should -Be 'ContractMissing'
        }

        It "reports CanonicalKindMissing when '<_>' has no canonical rule" -ForEach $CanonicalKinds {
            # Arrange
            $kind = $_
            $contract = New-CanonicalContractFixture -OmitKind $kind

            # Act
            $verdict = Get-CanonicalContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because "$kind requires a canonical rule"
            $verdict.Reason | Should -Be 'CanonicalKindMissing'
            $verdict.Violations | Should -Be @($kind)
        }

        It 'reports UnknownCanonicalKind when an undeclared kind is published' {
            # Arrange
            $contract = New-CanonicalContractFixture -AddKind 'Freeform'

            # Act
            $verdict = Get-CanonicalContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'only the declared canonical kinds may carry comparison rules'
            $verdict.Reason | Should -Be 'UnknownCanonicalKind'
            $verdict.Violations | Should -Be @('Freeform')
        }

        It 'reports OrderSensitiveKind when a canonical kind compares in order' {
            # Arrange
            $contract = New-CanonicalContractFixture -OrderedKind 'SmtpAddress'

            # Act
            $verdict = Get-CanonicalContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'canonical comparison is unordered'
            $verdict.Reason | Should -Be 'OrderSensitiveKind'
            $verdict.Violations | Should -Be @('SmtpAddress')
        }

        It 'reports CaseSensitiveKind when a canonical kind compares case sensitively' {
            # Arrange
            $contract = New-CanonicalContractFixture -CaseSensitiveKind 'Domain'

            # Act
            $verdict = Get-CanonicalContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'canonical comparison ignores case'
            $verdict.Reason | Should -Be 'CaseSensitiveKind'
            $verdict.Violations | Should -Be @('Domain')
        }

        It 'reports NormalizationRuleMissing when a canonical kind declares no normalization' {
            # Arrange
            $contract = New-CanonicalContractFixture -WithoutNormalizationRuleKind 'IpAddress'

            # Act
            $verdict = Get-CanonicalContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'every canonical kind needs explicit normalization'
            $verdict.Reason | Should -Be 'NormalizationRuleMissing'
            $verdict.Violations | Should -Be @('IpAddress')
        }

        It 'reports CollectionEqualityMissing when collection equality is not declared' {
            # Arrange
            $contract = New-CanonicalContractFixture -CollectionEquality ''

            # Act
            $verdict = Get-CanonicalContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'collection equality must be declared'
            $verdict.Reason | Should -Be 'CollectionEqualityMissing'
        }

        It 'reports CollectionEqualityNotNormalized when collection equality is not normalized set equality' {
            # Arrange
            $contract = New-CanonicalContractFixture -CollectionEquality 'ReferenceEquality'

            # Act
            $verdict = Get-CanonicalContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'collections compare as normalized sets'
            $verdict.Reason | Should -Be 'CollectionEqualityNotNormalized'
            $verdict.Violations | Should -Be @('ReferenceEquality')
        }
    }

    Context 'Positive: the contract is satisfied' {

        It 'declares unordered case-insensitive normalization for every canonical kind and normalized set equality' {
            # Arrange
            Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking
            $contract = Get-CanonicalComparisonContract

            # Act
            $verdict = Get-CanonicalContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeTrue -Because "contract violation: $($verdict.Reason) $($verdict.Violations -join ', ')"
        }
    }
}
