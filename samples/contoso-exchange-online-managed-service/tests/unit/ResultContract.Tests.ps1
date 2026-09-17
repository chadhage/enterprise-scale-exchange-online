#requires -Version 7.0

# Discovery-scope copies so the per-status negative cases can be expanded by -ForEach.
$NormalizedStatuses = @('Pass', 'Fail', 'ApprovedException', 'NotApplicable', 'Error')
$NonNormalizedStatuses = @('Manual', 'NotEntitled', 'Unverified')

BeforeAll {
    $script:NormalizedStatuses = @('Pass', 'Fail', 'ApprovedException', 'NotApplicable', 'Error')
    $script:NonNormalizedStatuses = @('Manual', 'NotEntitled', 'Unverified')
    $script:FailureStatuses = @('Fail', 'Error')

    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    function Get-ResultContractVerdict {
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

        foreach ($property in @('NormalizedStatus', 'NonNormalizedStatus', 'GoLiveSuccessStatus')) {
            if ($null -eq $Contract.PSObject.Properties[$property]) {
                $verdict.Reason = 'ContractMissing'
                $verdict.Violations = @($property)
                return [pscustomobject]$verdict
            }
        }

        $normalized = @($Contract.NormalizedStatus)
        $nonNormalized = @($Contract.NonNormalizedStatus)
        $goLiveSuccess = @($Contract.GoLiveSuccessStatus)

        $missingNormalized = @($script:NormalizedStatuses | Where-Object { $_ -notin $normalized })
        if ($missingNormalized.Count -gt 0) {
            $verdict.Reason = 'NormalizedStatusMissing'
            $verdict.Violations = $missingNormalized
            return [pscustomobject]$verdict
        }

        $normalizedNonNormalized = @($script:NonNormalizedStatuses | Where-Object { $_ -in $normalized })
        if ($normalizedNonNormalized.Count -gt 0) {
            $verdict.Reason = 'NonNormalizedStatusTreatedAsNormalized'
            $verdict.Violations = $normalizedNonNormalized
            return [pscustomobject]$verdict
        }

        $unknownNormalized = @($normalized | Where-Object { $_ -notin $script:NormalizedStatuses })
        if ($unknownNormalized.Count -gt 0) {
            $verdict.Reason = 'UnknownNormalizedStatus'
            $verdict.Violations = $unknownNormalized
            return [pscustomobject]$verdict
        }

        $missingNonNormalized = @($script:NonNormalizedStatuses | Where-Object { $_ -notin $nonNormalized })
        if ($missingNonNormalized.Count -gt 0) {
            $verdict.Reason = 'NonNormalizedStatusMissing'
            $verdict.Violations = $missingNonNormalized
            return [pscustomobject]$verdict
        }

        $unnormalizedSuccess = @($goLiveSuccess | Where-Object { $_ -notin $normalized })
        if ($unnormalizedSuccess.Count -gt 0) {
            $verdict.Reason = 'GoLiveSuccessOutsideNormalized'
            $verdict.Violations = $unnormalizedSuccess
            return [pscustomobject]$verdict
        }

        $failureSuccess = @($goLiveSuccess | Where-Object { $_ -in $script:FailureStatuses })
        if ($failureSuccess.Count -gt 0) {
            $verdict.Reason = 'GoLiveSuccessIncludesFailureStatus'
            $verdict.Violations = $failureSuccess
            return [pscustomobject]$verdict
        }

        $verdict.Satisfied = $true
        $verdict.Reason = 'ResultContractSatisfied'
        return [pscustomobject]$verdict
    }

    function New-ResultContractFixture {
        [CmdletBinding()]
        param(
            [string[]]$NormalizedStatus = @('Pass', 'Fail', 'ApprovedException', 'NotApplicable', 'Error'),
            [string[]]$NonNormalizedStatus = @('Manual', 'NotEntitled', 'Unverified'),
            [string[]]$GoLiveSuccessStatus = @('Pass', 'ApprovedException', 'NotApplicable')
        )

        return [pscustomobject]@{
            NormalizedStatus    = @($NormalizedStatus)
            NonNormalizedStatus = @($NonNormalizedStatus)
            GoLiveSuccessStatus = @($GoLiveSuccessStatus)
        }
    }
}

Describe 'DES-001-A result and go-live status contract' {

    Context 'Negative: the contract is not satisfied' {

        It 'reports ContractMissing when no contract is published' {
            # Arrange
            $contract = $null

            # Act
            $verdict = Get-ResultContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'an absent contract defines no result semantics'
            $verdict.Reason | Should -Be 'ContractMissing'
        }

        It "reports NormalizedStatusMissing when '<_>' is not a normalized status" -ForEach $NormalizedStatuses {
            # Arrange
            $status = $_
            $contract = New-ResultContractFixture -NormalizedStatus @($script:NormalizedStatuses | Where-Object { $_ -ne $status }) -GoLiveSuccessStatus @('Pass')

            # Act
            $verdict = Get-ResultContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because "$status is a required normalized status"
            $verdict.Reason | Should -Be 'NormalizedStatusMissing'
            $verdict.Violations | Should -Be @($status)
        }

        It 'reports UnknownNormalizedStatus when an extra status is normalized' {
            # Arrange
            $contract = New-ResultContractFixture -NormalizedStatus (@($script:NormalizedStatuses) + 'Skipped')

            # Act
            $verdict = Get-ResultContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'only the five declared statuses may be normalized'
            $verdict.Reason | Should -Be 'UnknownNormalizedStatus'
            $verdict.Violations | Should -Be @('Skipped')
        }

        It "reports NonNormalizedStatusMissing when '<_>' is not declared non-normalized" -ForEach $NonNormalizedStatuses {
            # Arrange
            $status = $_
            $contract = New-ResultContractFixture -NonNormalizedStatus @($script:NonNormalizedStatuses | Where-Object { $_ -ne $status })

            # Act
            $verdict = Get-ResultContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because "$status must be declared as a non-normalized status"
            $verdict.Reason | Should -Be 'NonNormalizedStatusMissing'
            $verdict.Violations | Should -Be @($status)
        }

        It 'reports NonNormalizedStatusTreatedAsNormalized when Manual is normalized' {
            # Arrange
            $contract = New-ResultContractFixture -NormalizedStatus (@($script:NormalizedStatuses) + 'Manual')

            # Act
            $verdict = Get-ResultContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'Manual is never a normalized status'
            $verdict.Reason | Should -Be 'NonNormalizedStatusTreatedAsNormalized'
            $verdict.Violations | Should -Be @('Manual')
        }

        It 'reports GoLiveSuccessOutsideNormalized when a non-normalized status is a go-live success' {
            # Arrange
            $contract = New-ResultContractFixture -GoLiveSuccessStatus @('Pass', 'NotEntitled')

            # Act
            $verdict = Get-ResultContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'NotEntitled can never be a successful go-live outcome'
            $verdict.Reason | Should -Be 'GoLiveSuccessOutsideNormalized'
            $verdict.Violations | Should -Be @('NotEntitled')
        }

        It 'reports GoLiveSuccessIncludesFailureStatus when Fail is a go-live success' {
            # Arrange
            $contract = New-ResultContractFixture -GoLiveSuccessStatus @('Pass', 'Fail')

            # Act
            $verdict = Get-ResultContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeFalse -Because 'a failing control can never be a successful go-live outcome'
            $verdict.Reason | Should -Be 'GoLiveSuccessIncludesFailureStatus'
            $verdict.Violations | Should -Be @('Fail')
        }
    }

    Context 'Positive: the contract is satisfied' {

        It 'publishes exactly the normalized, non-normalized, and go-live success status sets' {
            # Arrange
            Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking
            $contract = Get-BaselineResultContract

            # Act
            $verdict = Get-ResultContractVerdict -Contract $contract

            # Assert
            $verdict.Satisfied | Should -BeTrue -Because "contract violation: $($verdict.Reason) $($verdict.Violations -join ', ')"
        }
    }
}
