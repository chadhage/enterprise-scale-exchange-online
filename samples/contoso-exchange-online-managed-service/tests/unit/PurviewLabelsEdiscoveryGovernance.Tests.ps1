#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-GovEntitlement {
        param([string]$Status = 'Pass', [string]$Plan = 'E5 Compliance')
        [pscustomobject]@{ Status = $Status; RequiredServicePlanName = $Plan; Reason = "Entitlement is $Status." }
    }

    function New-LabelEvidence {
        param(
            [object[]]$Label = @([pscustomobject]@{ Name = 'Confidential'; EncryptionEnabled = $true }),
            [object[]]$Policy = @([pscustomobject]@{ Name = 'Messaging labels'; Labels = @('Confidential'); ExchangeLocation = @('user1@contoso.example', 'user2@contoso.example') }),
            [datetime]$CollectedAtUtc = [datetime]::UtcNow
        )
        New-BaselineEvidence -ControlId 'GOV-006' -Source 'Purview' -Command 'Get-Label;Get-LabelPolicy' -CollectedAtUtc $CollectedAtUtc -Value ([ordered]@{
                SensitivityLabel = $Label
                LabelPolicy = $Policy
            })
    }

    function New-LabelDesiredState {
        [ordered]@{
            requiredServicePlan = 'E5 Compliance'
            encryptionLabelNames = @('Confidential')
            messagingTargets = @('user1@contoso.example', 'user2@contoso.example')
            maximumEvidenceAgeDays = 7
        }
    }

    function New-EDiscoveryEvidence {
        param(
            [object[]]$Case = @([pscustomobject]@{ Name = 'Quarterly readiness'; Status = 'Active'; Owners = @('owner1@contoso.example', 'owner2@contoso.example') }),
            [object[]]$RoleMember = @([pscustomobject]@{ PrimarySmtpAddress = 'owner1@contoso.example' }, [pscustomobject]@{ PrimarySmtpAddress = 'owner2@contoso.example' }),
            [object[]]$AccessReview = @([pscustomobject]@{ RoleGroup = 'eDiscovery Manager'; Status = 'Completed'; ReviewedAtUtc = [datetime]::UtcNow.AddDays(-10); ReviewedMembers = @('owner1@contoso.example', 'owner2@contoso.example') }),
            [datetime]$CollectedAtUtc = [datetime]::UtcNow
        )
        New-BaselineEvidence -ControlId 'GOV-007' -Source 'Purview' -Command 'Get-ComplianceCase;Get-RoleGroupMember;Get-AccessReview' -CollectedAtUtc $CollectedAtUtc -Value ([ordered]@{
                ComplianceCase = $Case
                RoleGroupMember = $RoleMember
                AccessReview = $AccessReview
            })
    }

    function New-EDiscoveryDesiredState {
        [ordered]@{
            requiredServicePlan = 'E5 Compliance'
            caseOwners = @('owner1@contoso.example', 'owner2@contoso.example')
            roleGroupIdentity = 'eDiscovery Manager'
            maximumAccessReviewAgeDays = 90
            maximumEvidenceAgeDays = 7
        }
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GOV-006 sensitivity-label evidence collection' {
    Context 'Negative: collection prerequisites and refusal' {
        It 'refuses a missing sensitivity-label collection' {
            # Arrange
            $policyCollection = { @() }

            # Act
            $act = { Get-SensitivityLabelEvidence -SensitivityLabelCollection $null -LabelPolicyCollection $policyCollection }

            # Assert
            $act | Should -Throw '*SensitivityLabelCollectionRequired*'
        }

        It 'refuses a missing label-policy collection' {
            # Arrange
            $labelCollection = { @() }

            # Act
            $act = { Get-SensitivityLabelEvidence -SensitivityLabelCollection $labelCollection -LabelPolicyCollection $null }

            # Assert
            $act | Should -Throw '*LabelPolicyCollectionRequired*'
        }

        It 'records a named Purview collection failure instead of throwing or passing' {
            # Arrange
            $labelCollection = { throw 'Purview label endpoint refused the request' }

            # Act
            $actual = Get-SensitivityLabelEvidence -SensitivityLabelCollection $labelCollection -LabelPolicyCollection { @() }

            # Assert
            $actual.ControlId | Should -BeExactly 'GOV-006'
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -Match 'CollectionFailed.*Purview label endpoint refused'
        }
    }

    Context 'Positive: one complete sensitivity-label collection' {
        It 'preserves the complete Purview label and publication payload' {
            # Arrange
            $labels = @([pscustomobject]@{ Name = 'Confidential'; EncryptionEnabled = $true; Extra = 'preserved' })
            $policies = @([pscustomobject]@{ Name = 'Messaging labels'; Labels = @('Confidential'); ExchangeLocation = @('user1@contoso.example') })

            # Act
            $actual = Get-SensitivityLabelEvidence -SensitivityLabelCollection { $labels }.GetNewClosure() -LabelPolicyCollection { $policies }.GetNewClosure()

            # Assert
            $actual.ControlId | Should -BeExactly 'GOV-006'
            $actual.Source | Should -BeExactly 'Purview'
            $actual.Command | Should -BeExactly 'Get-Label;Get-LabelPolicy'
            @($actual.Value.SensitivityLabel)[0].Extra | Should -BeExactly 'preserved'
            @($actual.Value.LabelPolicy)[0].Name | Should -BeExactly 'Messaging labels'
        }
    }
}

Describe 'GOV-006 sensitivity-label governance evaluation' {
    Context 'Negative: entitlement, freshness, encryption and publication coverage' {
        It 'returns NotApplicable only for a resolved unentitled verdict' {
            # Arrange
            $evidence = New-LabelEvidence -Label @() -Policy @()

            # Act
            $actual = Test-SensitivityLabelControl -Evidence $evidence -DesiredState (New-LabelDesiredState) -EntitlementVerdict (New-GovEntitlement -Status NotEntitled) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'NotApplicable'
            $actual.Reason | Should -Match '^SensitivityLabelsNotEntitled:'
        }

        It 'returns Error when entitlement is unresolved rather than NotApplicable' {
            # Arrange
            $evidence = New-LabelEvidence

            # Act
            $actual = Test-SensitivityLabelControl -Evidence $evidence -DesiredState (New-LabelDesiredState) -EntitlementVerdict (New-GovEntitlement -Status Error) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^SensitivityLabelsEntitlementUnresolved:'
        }

        It 'returns Error for stale sensitivity-label evidence' {
            # Arrange
            $asOf = [datetime]::UtcNow
            $evidence = New-LabelEvidence -CollectedAtUtc $asOf.AddDays(-8)

            # Act
            $actual = Test-SensitivityLabelControl -Evidence $evidence -DesiredState (New-LabelDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf $asOf

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^SensitivityLabelsEvidenceStale:'
        }

        It 'returns Error for a partial record missing label-policy evidence' {
            # Arrange
            $evidence = New-BaselineEvidence -ControlId 'GOV-006' -Source 'Purview' -Command 'Get-Label;Get-LabelPolicy' -Value ([ordered]@{ SensitivityLabel = @() })

            # Act
            $actual = Test-SensitivityLabelControl -Evidence $evidence -DesiredState (New-LabelDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^SensitivityLabelsEvidenceIncomplete:'
        }

        It 'fails when no required label is encryption-capable' {
            # Arrange
            $label = @([pscustomobject]@{ Name = 'Confidential'; EncryptionEnabled = $false })
            $evidence = New-LabelEvidence -Label $label

            # Act
            $actual = Test-SensitivityLabelControl -Evidence $evidence -DesiredState (New-LabelDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^SensitivityLabelsEncryptionDrift:.*Confidential'
        }

        It 'fails when an encryption label is not published' {
            # Arrange
            $policy = @([pscustomobject]@{ Name = 'Messaging labels'; Labels = @('Public'); ExchangeLocation = @('user1@contoso.example', 'user2@contoso.example') })
            $evidence = New-LabelEvidence -Policy $policy

            # Act
            $actual = Test-SensitivityLabelControl -Evidence $evidence -DesiredState (New-LabelDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^SensitivityLabelsPublicationDrift:.*Confidential'
        }

        It 'fails naming every resolved messaging target missing from publication' {
            # Arrange
            $policy = @([pscustomobject]@{ Name = 'Messaging labels'; Labels = @('Confidential'); ExchangeLocation = @('user1@contoso.example') })
            $evidence = New-LabelEvidence -Policy $policy

            # Act
            $actual = Test-SensitivityLabelControl -Evidence $evidence -DesiredState (New-LabelDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^SensitivityLabelsTargetDrift:.*user2@contoso\.example'
        }

        It 'passes through a named collection refusal as Error' {
            # Arrange
            $evidence = New-BaselineEvidence -ControlId 'GOV-006' -Source 'Purview' -Command 'Get-Label;Get-LabelPolicy' -Value $null -Failed -FailureReason 'CollectionFailed: Purview refused labels.'

            # Act
            $actual = Test-SensitivityLabelControl -Evidence $evidence -DesiredState (New-LabelDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match 'EvidenceCollectionFailed:.*Purview refused labels'
        }
    }

    Context 'Positive: one fully entitled sensitivity-label fixture' {
        It 'passes when an encryption label is published to every resolved messaging target' {
            # Arrange
            $evidence = New-LabelEvidence

            # Act
            $actual = Test-SensitivityLabelControl -Evidence $evidence -DesiredState (New-LabelDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.ControlId | Should -BeExactly 'GOV-006'
            $actual.Status | Should -BeExactly 'Pass'
            $actual.GoLiveSuccess | Should -BeTrue
        }
    }
}

Describe 'GOV-007 eDiscovery readiness evidence collection' {
    Context 'Negative: collection prerequisites and refusal' {
        It 'refuses any missing eDiscovery collection seam' {
            # Arrange
            $caseCollection = { @() }
            $roleCollection = { @() }

            # Act
            $act = { Get-EDiscoveryReadinessEvidence -ComplianceCaseCollection $caseCollection -RoleGroupMemberCollection $roleCollection -AccessReviewCollection $null }

            # Assert
            $act | Should -Throw '*AccessReviewCollectionRequired*'
        }

        It 'records a named case collection failure' {
            # Arrange
            $caseCollection = { throw 'Compliance case endpoint refused the request' }

            # Act
            $actual = Get-EDiscoveryReadinessEvidence -ComplianceCaseCollection $caseCollection -RoleGroupMemberCollection { @() } -AccessReviewCollection { @() }

            # Assert
            $actual.ControlId | Should -BeExactly 'GOV-007'
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -Match 'CollectionFailed.*Compliance case endpoint refused'
        }

        It 'records a named role membership collection failure' {
            # Arrange
            $roleCollection = { throw 'eDiscovery role membership refused the request' }

            # Act
            $actual = Get-EDiscoveryReadinessEvidence -ComplianceCaseCollection { @() } -RoleGroupMemberCollection $roleCollection -AccessReviewCollection { @() }

            # Assert
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -Match 'CollectionFailed.*role membership refused'
        }

        It 'records a named access-review collection failure' {
            # Arrange
            $reviewCollection = { throw 'Access review endpoint refused the request' }

            # Act
            $actual = Get-EDiscoveryReadinessEvidence -ComplianceCaseCollection { @() } -RoleGroupMemberCollection { @() } -AccessReviewCollection $reviewCollection

            # Assert
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -Match 'CollectionFailed.*Access review endpoint refused'
        }
    }

    Context 'Positive: one complete eDiscovery collection' {
        It 'preserves cases, current role membership, and access-review evidence' {
            # Arrange
            $cases = @([pscustomobject]@{ Name = 'Ready'; Owners = @('owner1@contoso.example') })
            $members = @([pscustomobject]@{ PrimarySmtpAddress = 'owner1@contoso.example' })
            $reviews = @([pscustomobject]@{ RoleGroup = 'eDiscovery Manager'; Status = 'Completed' })

            # Act
            $actual = Get-EDiscoveryReadinessEvidence -ComplianceCaseCollection { $cases }.GetNewClosure() -RoleGroupMemberCollection { $members }.GetNewClosure() -AccessReviewCollection { $reviews }.GetNewClosure()

            # Assert
            $actual.ControlId | Should -BeExactly 'GOV-007'
            $actual.Source | Should -BeExactly 'Purview'
            @($actual.Value.ComplianceCase)[0].Name | Should -BeExactly 'Ready'
            @($actual.Value.RoleGroupMember)[0].PrimarySmtpAddress | Should -BeExactly 'owner1@contoso.example'
            @($actual.Value.AccessReview)[0].Status | Should -BeExactly 'Completed'
        }
    }
}

Describe 'GOV-007 eDiscovery readiness evaluation' {
    Context 'Negative: entitlement, freshness, ownership and reviewed RBAC' {
        It 'returns NotApplicable only for a resolved unentitled verdict' {
            # Arrange
            $evidence = New-EDiscoveryEvidence -Case @() -RoleMember @() -AccessReview @()

            # Act
            $actual = Test-EDiscoveryReadinessControl -Evidence $evidence -DesiredState (New-EDiscoveryDesiredState) -EntitlementVerdict (New-GovEntitlement -Status NotEntitled) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'NotApplicable'
            $actual.Reason | Should -Match '^EDiscoveryNotEntitled:'
        }

        It 'returns Error when entitlement is unresolved rather than NotApplicable' {
            # Arrange
            $evidence = New-EDiscoveryEvidence

            # Act
            $actual = Test-EDiscoveryReadinessControl -Evidence $evidence -DesiredState (New-EDiscoveryDesiredState) -EntitlementVerdict (New-GovEntitlement -Status Error) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^EDiscoveryEntitlementUnresolved:'
        }

        It 'returns Error for stale eDiscovery evidence' {
            # Arrange
            $asOf = [datetime]::UtcNow
            $evidence = New-EDiscoveryEvidence -CollectedAtUtc $asOf.AddDays(-8)

            # Act
            $actual = Test-EDiscoveryReadinessControl -Evidence $evidence -DesiredState (New-EDiscoveryDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf $asOf

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^EDiscoveryEvidenceStale:'
        }

        It 'returns Error for partial evidence missing access reviews' {
            # Arrange
            $evidence = New-BaselineEvidence -ControlId 'GOV-007' -Source 'Purview' -Command 'Get-ComplianceCase;Get-RoleGroupMember;Get-AccessReview' -Value ([ordered]@{ ComplianceCase = @(); RoleGroupMember = @() })

            # Act
            $actual = Test-EDiscoveryReadinessControl -Evidence $evidence -DesiredState (New-EDiscoveryDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match '^EDiscoveryEvidenceIncomplete:'
        }

        It 'fails naming a configured owner who owns no active case' {
            # Arrange
            $case = @([pscustomobject]@{ Name = 'Quarterly readiness'; Status = 'Active'; Owners = @('owner1@contoso.example') })
            $evidence = New-EDiscoveryEvidence -Case $case

            # Act
            $actual = Test-EDiscoveryReadinessControl -Evidence $evidence -DesiredState (New-EDiscoveryDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^EDiscoveryOwnerDrift:.*owner2@contoso\.example'
        }

        It 'fails naming a configured owner missing from current role membership' {
            # Arrange
            $member = @([pscustomobject]@{ PrimarySmtpAddress = 'owner1@contoso.example' })
            $evidence = New-EDiscoveryEvidence -RoleMember $member

            # Act
            $actual = Test-EDiscoveryReadinessControl -Evidence $evidence -DesiredState (New-EDiscoveryDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^EDiscoveryRoleMembershipDrift:.*owner2@contoso\.example'
        }

        It 'fails naming a stale eDiscovery RBAC review' {
            # Arrange
            $review = @([pscustomobject]@{ RoleGroup = 'eDiscovery Manager'; Status = 'Completed'; ReviewedAtUtc = [datetime]::UtcNow.AddDays(-91); ReviewedMembers = @('owner1@contoso.example', 'owner2@contoso.example') })
            $evidence = New-EDiscoveryEvidence -AccessReview $review

            # Act
            $actual = Test-EDiscoveryReadinessControl -Evidence $evidence -DesiredState (New-EDiscoveryDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^EDiscoveryAccessReviewStale:'
        }

        It 'fails when the completed review does not cover current role membership' {
            # Arrange
            $review = @([pscustomobject]@{ RoleGroup = 'eDiscovery Manager'; Status = 'Completed'; ReviewedAtUtc = [datetime]::UtcNow.AddDays(-10); ReviewedMembers = @('owner1@contoso.example') })
            $evidence = New-EDiscoveryEvidence -AccessReview $review

            # Act
            $actual = Test-EDiscoveryReadinessControl -Evidence $evidence -DesiredState (New-EDiscoveryDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Fail'
            $actual.Reason | Should -Match '^EDiscoveryAccessReviewCoverageDrift:.*owner2@contoso\.example'
        }

        It 'passes through a named collection refusal as Error' {
            # Arrange
            $evidence = New-BaselineEvidence -ControlId 'GOV-007' -Source 'Purview' -Command 'Get-ComplianceCase;Get-RoleGroupMember;Get-AccessReview' -Value $null -Failed -FailureReason 'CollectionFailed: Purview refused eDiscovery.'

            # Act
            $actual = Test-EDiscoveryReadinessControl -Evidence $evidence -DesiredState (New-EDiscoveryDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.Status | Should -BeExactly 'Error'
            $actual.Reason | Should -Match 'EvidenceCollectionFailed:.*Purview refused eDiscovery'
        }
    }

    Context 'Positive: one fully entitled eDiscovery fixture' {
        It 'passes when every owner is active, in role, and covered by a current completed review' {
            # Arrange
            $evidence = New-EDiscoveryEvidence

            # Act
            $actual = Test-EDiscoveryReadinessControl -Evidence $evidence -DesiredState (New-EDiscoveryDesiredState) -EntitlementVerdict (New-GovEntitlement) -AsOf ([datetime]::UtcNow)

            # Assert
            $actual.ControlId | Should -BeExactly 'GOV-007'
            $actual.Status | Should -BeExactly 'Pass'
            $actual.GoLiveSuccess | Should -BeTrue
        }
    }
}