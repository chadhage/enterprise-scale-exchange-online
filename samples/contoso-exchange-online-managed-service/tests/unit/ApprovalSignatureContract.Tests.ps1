#requires -Version 7.0

# Discovery-scope copies so the per-model and per-rule negative cases can be expanded by -ForEach.
$ApprovedSignatureModels = @('DetachedCms', 'EnterpriseCertificate', 'ExternalTicketEvidence')
$RequiredRuleCategories = @('Authority', 'Verification', 'Expiry', 'Revocation')

BeforeAll {
    $script:ApprovedSignatureModels = @('DetachedCms', 'EnterpriseCertificate', 'ExternalTicketEvidence')
    $script:RequiredRuleCategories = @('Authority', 'Verification', 'Expiry', 'Revocation')

    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    function Get-ApprovalSignatureVerdict {
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

        foreach ($property in @('SelectedModel', 'ApprovedModel', 'Rule')) {
            if ($null -eq $Contract.PSObject.Properties[$property]) {
                $verdict.Reason = 'ContractMissing'
                $verdict.Violations = @($property)
                return [pscustomobject]$verdict
            }
        }

        $selected = @($Contract.SelectedModel | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($selected.Count -eq 0) {
            $verdict.Reason = 'SignatureModelNotSelected'
            return [pscustomobject]$verdict
        }

        if ($selected.Count -gt 1) {
            $verdict.Reason = 'MultipleSignatureModelsSelected'
            $verdict.Violations = $selected
            return [pscustomobject]$verdict
        }

        $approved = @($Contract.ApprovedModel)

        $unapproved = @($selected | Where-Object { $_ -notin $approved })
        if ($unapproved.Count -gt 0) {
            $verdict.Reason = 'UnapprovedSignatureModel'
            $verdict.Violations = $unapproved
            return [pscustomobject]$verdict
        }

        $missingApproved = @($script:ApprovedSignatureModels | Where-Object { $_ -notin $approved })
        if ($missingApproved.Count -gt 0) {
            $verdict.Reason = 'ApprovedModelMissing'
            $verdict.Violations = $missingApproved
            return [pscustomobject]$verdict
        }

        $unknownApproved = @($approved | Where-Object { $_ -notin $script:ApprovedSignatureModels })
        if ($unknownApproved.Count -gt 0) {
            $verdict.Reason = 'UnknownApprovedModel'
            $verdict.Violations = $unknownApproved
            return [pscustomobject]$verdict
        }

        $rules = @($Contract.Rule)
        $declaredCategories = @($rules | ForEach-Object { $_.Category })

        $missingCategories = @($script:RequiredRuleCategories | Where-Object { $_ -notin $declaredCategories })
        if ($missingCategories.Count -gt 0) {
            $verdict.Reason = 'RuleCategoryMissing'
            $verdict.Violations = $missingCategories
            return [pscustomobject]$verdict
        }

        $unknownCategories = @($declaredCategories | Where-Object { $_ -notin $script:RequiredRuleCategories })
        if ($unknownCategories.Count -gt 0) {
            $verdict.Reason = 'UnknownRuleCategory'
            $verdict.Violations = $unknownCategories
            return [pscustomobject]$verdict
        }

        $withoutRequirement = @($rules | Where-Object { [string]::IsNullOrWhiteSpace($_.Requirement) } | ForEach-Object { $_.Category })
        if ($withoutRequirement.Count -gt 0) {
            $verdict.Reason = 'RuleRequirementMissing'
            $verdict.Violations = $withoutRequirement
            return [pscustomobject]$verdict
        }

        $verdict.Satisfied = $true
        $verdict.Reason = 'ApprovalSignatureContractSatisfied'
        return [pscustomobject]$verdict
    }

    function New-ApprovalSignatureFixture {
        [CmdletBinding()]
        param(
            [AllowEmptyCollection()]
            [string[]]$SelectedModel = @('DetachedCms'),
            [string]$OmitApprovedModel,
            [string]$AddApprovedModel,
            [string]$OmitRuleCategory,
            [string]$AddRuleCategory,
            [string]$WithoutRequirementCategory
        )

        $approvedModels = @($script:ApprovedSignatureModels | Where-Object { $_ -ne $OmitApprovedModel })
        if ($AddApprovedModel) { $approvedModels += $AddApprovedModel }

        $rules = [System.Collections.Generic.List[object]]::new()
        foreach ($category in $script:RequiredRuleCategories) {
            if ($category -eq $OmitRuleCategory) { continue }

            $requirement = "$category requirement"
            if ($category -eq $WithoutRequirementCategory) { $requirement = '' }

            $rules.Add([pscustomobject]@{
                    Category    = $category
                    Requirement = $requirement
                })
        }

        if ($AddRuleCategory) {
            $rules.Add([pscustomobject]@{
                    Category    = $AddRuleCategory
                    Requirement = "$AddRuleCategory requirement"
                })
        }

        return [pscustomobject]@{
            SelectedModel = @($SelectedModel)
            ApprovedModel = @($approvedModels)
            Rule          = @($rules)
        }
    }
}

Describe 'DES-005-A approval signature model contract' {

    Context 'Negative: the contract is not satisfied' {

        It 'reports ContractMissing when no contract is published' {
            # Arrange
            $contract = $null

            # Act
            $verdict = Get-ApprovalSignatureVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'an absent contract selects no approval signature model'
            $verdict.Reason | Should -Be 'ContractMissing'
        }

        It 'reports SignatureModelNotSelected when no model is selected' {
            # Arrange
            $contract = New-ApprovalSignatureFixture -SelectedModel @()

            # Act
            $verdict = Get-ApprovalSignatureVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'an approval signature model must be selected'
            $verdict.Reason | Should -Be 'SignatureModelNotSelected'
        }

        It 'reports MultipleSignatureModelsSelected when more than one model is selected' {
            # Arrange
            $contract = New-ApprovalSignatureFixture -SelectedModel @('DetachedCms', 'EnterpriseCertificate')

            # Act
            $verdict = Get-ApprovalSignatureVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'exactly one approval signature model governs verification'
            $verdict.Reason | Should -Be 'MultipleSignatureModelsSelected'
        }

        It 'reports UnapprovedSignatureModel when the selected model is outside the approved set' {
            # Arrange
            $contract = New-ApprovalSignatureFixture -SelectedModel @('SelfAsserted')

            # Act
            $verdict = Get-ApprovalSignatureVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'only approved models may be selected'
            $verdict.Reason | Should -Be 'UnapprovedSignatureModel'
            $verdict.Violations | Should -Be @('SelfAsserted')
        }

        It "reports ApprovedModelMissing when '<_>' is not an approved model" -ForEach $ApprovedSignatureModels {
            # Arrange
            $model = $_
            $stillApproved = @($script:ApprovedSignatureModels | Where-Object { $_ -ne $model })[0]
            $contract = New-ApprovalSignatureFixture -SelectedModel @($stillApproved) -OmitApprovedModel $model

            # Act
            $verdict = Get-ApprovalSignatureVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because "$model is one of the three approved approval signature models"
            $verdict.Reason | Should -Be 'ApprovedModelMissing'
            $verdict.Violations | Should -Be @($model)
        }

        It 'reports UnknownApprovedModel when an unapproved model is listed as approved' {
            # Arrange
            $contract = New-ApprovalSignatureFixture -AddApprovedModel 'EmailConfirmation'

            # Act
            $verdict = Get-ApprovalSignatureVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'the approved set is closed'
            $verdict.Reason | Should -Be 'UnknownApprovedModel'
            $verdict.Violations | Should -Be @('EmailConfirmation')
        }

        It "reports RuleCategoryMissing when no '<_>' rule is declared" -ForEach $RequiredRuleCategories {
            # Arrange
            $category = $_
            $contract = New-ApprovalSignatureFixture -OmitRuleCategory $category

            # Act
            $verdict = Get-ApprovalSignatureVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because "$category rules are mandatory for the selected model"
            $verdict.Reason | Should -Be 'RuleCategoryMissing'
            $verdict.Violations | Should -Be @($category)
        }

        It 'reports UnknownRuleCategory when an undeclared rule category is published' {
            # Arrange
            $contract = New-ApprovalSignatureFixture -AddRuleCategory 'Courtesy'

            # Act
            $verdict = Get-ApprovalSignatureVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'only the mandated rule categories are published'
            $verdict.Reason | Should -Be 'UnknownRuleCategory'
            $verdict.Violations | Should -Be @('Courtesy')
        }

        It 'reports RuleRequirementMissing when a rule declares no requirement' {
            # Arrange
            $contract = New-ApprovalSignatureFixture -WithoutRequirementCategory 'Revocation'

            # Act
            $verdict = Get-ApprovalSignatureVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'a rule without a requirement cannot be enforced'
            $verdict.Reason | Should -Be 'RuleRequirementMissing'
            $verdict.Violations | Should -Be @('Revocation')
        }
    }

    Context 'Positive: the contract is satisfied' {

        It 'selects exactly one approved signature model with authority, verification, expiry, and revocation rules' {
            # Arrange
            Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking
            $contract = Get-ApprovalSignatureContract

            # Act
            $verdict = Get-ApprovalSignatureVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeTrue -Because "contract violation: $($verdict.Reason) $($verdict.Violations -join ', ')"
        }
    }
}
