#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:EvidenceCommandPath = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:GovernedRoleId = '29232cdf-9323-42fd-ade2-1d097af3e4de'
    $script:AsAtUtc = [datetime]::new(2026, 9, 19, 0, 0, 0, [System.DateTimeKind]::Utc)

    function New-CompleteRbacPimPayload {
        param([switch]$Drift)

        return [ordered]@{
            RoleGroup                = @([pscustomobject]@{
                    Name = 'Organization Management'
                    Members = if ($Drift) { @('standing.admin@contoso.com') } else { @('break.glass@contoso.com') }
                })
            ManagementRoleAssignment = @([pscustomobject]@{
                    Role = 'Mailbox Import Export'
                    RoleAssigneeName = 'Organization Management'
                    RoleAssigneeType = 'RoleGroup'
                })
            ActivePimAssignment      = @([pscustomobject]@{
                    principalId = 'b5d1f9a0-3c2e-4a77-9f81-6d0c4e2b8a13'
                    roleDefinitionId = $script:GovernedRoleId
                    endDateTime = '2026-09-30T00:00:00Z'
                })
            EligiblePimAssignment    = @([pscustomobject]@{
                    principalId = 'c7e2a418-5b9d-4f60-8a31-2f4c6d9e1b05'
                    roleDefinitionId = $script:GovernedRoleId
                })
            AccessReview             = @([pscustomobject]@{
                    displayName = 'Exchange administrators quarterly review'
                    scopeRoleDefinitionId = $script:GovernedRoleId
                    lastCompletedDateTime = '2026-08-20T00:00:00Z'
                })
        }
    }

    function New-RbacPimFallbackDecision {
        param(
            [ValidateSet('Admitted', 'Refused')]
            [string]$State = 'Admitted',
            [string]$ControlId = 'EXO-010',
            [object]$Payload = (New-CompleteRbacPimPayload)
        )

        if ($State -eq 'Refused') {
            return [pscustomobject]@{
                Satisfied = $false
                Admitted = @()
                Refused = @([pscustomobject]@{ ControlId = $ControlId; Reason = @('RbacPimFallbackSignatureUnverified') })
            }
        }

        return [pscustomobject]@{
            Satisfied = $true
            Admitted = @([pscustomobject]@{
                    ControlId = $ControlId
                    EvidenceId = '77777777-2222-4333-8444-555555555555'
                    Evidence = [pscustomobject]@{ ControlId = $ControlId; Payload = $Payload }
                })
            Refused = @()
        }
    }

    function New-LiveCollectionArgument {
        param([switch]$Refused, [object]$RoleGroup)

        $roleGroupCollection = if ($Refused) {
            { throw 'Authorization_RequestDenied: live PIM collection was refused.' }
        }
        elseif ($PSBoundParameters.ContainsKey('RoleGroup')) {
            { @($RoleGroup) }.GetNewClosure()
        }
        else {
            { @((New-CompleteRbacPimPayload).RoleGroup) }
        }

        return @{
            RoleGroupCollection = $roleGroupCollection
            ManagementRoleAssignmentCollection = { @((New-CompleteRbacPimPayload).ManagementRoleAssignment) }
            ActivePimAssignmentCollection = { @((New-CompleteRbacPimPayload).ActivePimAssignment) }
            EligiblePimAssignmentCollection = { @((New-CompleteRbacPimPayload).EligiblePimAssignment) }
            AccessReviewCollection = { @((New-CompleteRbacPimPayload).AccessReview) }
        }
    }

    function Invoke-RbacPimEvaluation {
        param([object]$Evidence, [object]$FallbackEvidence)

        return Test-ExchangeRoleAssignmentControl -Evidence $Evidence -FallbackEvidence $FallbackEvidence `
            -PrivilegedRoleGroup @('Organization Management') `
            -ApprovedMember @('break.glass@contoso.com') `
            -GovernedRole @($script:GovernedRoleId) `
            -MaximumReviewAgeDay 90 `
            -AsAtUtc $script:AsAtUtc
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXO-014 signed RBAC and PIM fallback orchestration' {
    Context 'Negative: live complete evidence remains authoritative' {
        It 'does not replace a complete live drift observation with an admitted fallback pass' {
            # Arrange
            $fallback = New-RbacPimFallbackDecision
            $liveArgument = New-LiveCollectionArgument -RoleGroup ([pscustomobject]@{
                    Name = 'Organization Management'
                    Members = @('standing.admin@contoso.com')
                })

            # Act
            $evidence = Get-ExchangeRoleAssignmentEvidence @liveArgument -FallbackEvidence $fallback
            $result = Invoke-RbacPimEvaluation -Evidence $evidence -FallbackEvidence $fallback

            # Assert
            ('{0}|{1}|{2}' -f $evidence.Source, $result.Status, $result.Reason) |
                Should -BeLike 'ExchangeOnline,MicrosoftGraph|Fail|PrivilegeUngoverned:*standing.admin@contoso.com*'
        }
    }

    Context 'Negative: fallback is available only after a live refusal and only when admitted' {
        It 'returns Error when live collection is refused and no fallback was supplied' {
            # Arrange
            $liveArgument = New-LiveCollectionArgument -Refused

            # Act
            $evidence = Get-ExchangeRoleAssignmentEvidence @liveArgument
            $result = Invoke-RbacPimEvaluation -Evidence $evidence -FallbackEvidence $null

            # Assert
            $result.Status | Should -BeExactly 'Error'
        }

        It 'returns Error when live collection is refused and fallback import was refused' {
            # Arrange
            $fallback = New-RbacPimFallbackDecision -State Refused
            $liveArgument = New-LiveCollectionArgument -Refused

            # Act
            $evidence = Get-ExchangeRoleAssignmentEvidence @liveArgument -FallbackEvidence $fallback
            $result = Invoke-RbacPimEvaluation -Evidence $evidence -FallbackEvidence $fallback

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) |
                Should -BeLike 'Error|*RbacPimFallbackSignatureUnverified*'
        }

        It 'returns Error when the admitted fallback is bound to another control' {
            # Arrange
            $fallback = New-RbacPimFallbackDecision -ControlId 'EXO-011'
            $liveArgument = New-LiveCollectionArgument -Refused

            # Act
            $evidence = Get-ExchangeRoleAssignmentEvidence @liveArgument -FallbackEvidence $fallback
            $result = Invoke-RbacPimEvaluation -Evidence $evidence -FallbackEvidence $fallback

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) |
                Should -BeLike 'Error|*RbacPimFallbackControlMismatch*EXO-011*EXO-010*'
        }
    }

    Context 'Negative: admitted fallback preserves EXO-010 drift semantics' {
        It 'fails standing privileged membership instead of treating admission as compliance' {
            # Arrange
            $fallback = New-RbacPimFallbackDecision -Payload (New-CompleteRbacPimPayload -Drift)
            $liveArgument = New-LiveCollectionArgument -Refused

            # Act
            $evidence = Get-ExchangeRoleAssignmentEvidence @liveArgument -FallbackEvidence $fallback
            $result = Invoke-RbacPimEvaluation -Evidence $evidence -FallbackEvidence $fallback

            # Assert
            ('{0}|{1}' -f $result.Status, $result.Reason) |
                Should -BeLike 'Fail|PrivilegeUngoverned:*standing.admin@contoso.com*'
        }

        It 'does not expose mutable fallback payload as authoritative evidence' {
            # Arrange
            $fallback = New-RbacPimFallbackDecision
            $liveArgument = New-LiveCollectionArgument -Refused
            $evidence = Get-ExchangeRoleAssignmentEvidence @liveArgument -FallbackEvidence $fallback

            # Act
            $act = { $evidence.Value['RoleGroup'] = @() }

            # Assert
            $act | Should -Throw
        }
    }

    Context 'Negative: the public applicable EXO result surface is fail closed' {
        It 'emits EXO-010 only from its evaluator and never as a literal Manual verdict' {
            # Arrange
            $scriptText = Get-Content -LiteralPath $script:EvidenceCommandPath -Raw

            # Act
            $hasCollector = $scriptText -match 'Get-ExchangeRoleAssignmentEvidence'
            $hasEvaluator = $scriptText -match 'Test-ExchangeRoleAssignmentControl'
            $hasEvaluatorStatus = $scriptText.Contains("Add-Check 'EXO-010 rbacHygiene' `$roleAssignmentResult.Status `$roleAssignmentResult.Reason")
            $hasManualStatus = $scriptText -match "Add-Check\s+'EXO-010[^']*'\s+'Manual'"

            # Assert
            ('collector={0};evaluator={1};evaluatorStatus={2};manual={3}' -f $hasCollector, $hasEvaluator, $hasEvaluatorStatus, $hasManualStatus) |
                Should -BeExactly 'collector=True;evaluator=True;evaluatorStatus=True;manual=False'
        }
    }

    Context 'Positive: one complete admitted fallback decides EXO-010' {
        It 'passes a complete governed fallback only after live collection was refused' {
            # Arrange
            $fallback = New-RbacPimFallbackDecision
            $liveArgument = New-LiveCollectionArgument -Refused

            # Act
            $evidence = Get-ExchangeRoleAssignmentEvidence @liveArgument -FallbackEvidence $fallback
            $result = Invoke-RbacPimEvaluation -Evidence $evidence -FallbackEvidence $fallback

            # Assert
            ('{0}|{1}|{2}|{3}' -f $evidence.Source, $result.ControlId, $result.Status, $result.GoLiveSuccess) |
                Should -BeExactly 'SignedRbacPimFallback|EXO-010|Pass|True'
        }
    }
}