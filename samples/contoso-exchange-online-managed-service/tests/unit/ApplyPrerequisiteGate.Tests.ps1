#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ChangeId = 'CHG0077889'

    function New-ApprovalDecision {
        param(
            [bool]$Permitted = $true,
            [string[]]$Finding = @()
        )

        return [ordered]@{
            Permitted = $Permitted
            ChangeId  = $script:ChangeId
            Finding   = @($Finding)
        }
    }

    function Invoke-Prerequisite {
        param([hashtable]$Override = @{})

        $argument = @{
            Apply            = $true
            PreviewPath      = 'C:\change\preview-CHG0077889.json'
            ApprovalPath     = 'C:\change\approval-CHG0077889.json'
            ArtifactRoot     = 'C:\change'
            ApprovalDecision = (New-ApprovalDecision)
        }
        foreach ($name in $Override.Keys) { $argument[$name] = $Override[$name] }

        return Test-BaselineApplyPrerequisite @argument
    }

    function Format-Refusal {
        param([object]$Decision, [string]$Prefix)

        return '{0}|{1}' -f $Decision['Permitted'], [bool](@($Decision['Finding']) | Where-Object { $_ -like "$Prefix*" })
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-007-A1 apply prerequisite gate' {

    Context 'Negative: an apply run is admitted with nothing behind it to apply from' {

        It 'does not admit an apply run carrying no preview path' {
            # Arrange
            $override = @{ PreviewPath = '   ' }

            # Act
            $decision = Invoke-Prerequisite -Override $override

            # Assert
            (Format-Refusal -Decision $decision -Prefix 'ApplyPreviewPathNotSupplied') |
                Should -BeExactly 'False|True' -Because 'a run that applies without naming the plan it was reviewed against is a run applying whatever the configuration happens to say today'
        }

        It 'does not admit an apply run carrying no approval path' {
            # Arrange
            $override = @{ ApprovalPath = '   ' }

            # Act
            $decision = Invoke-Prerequisite -Override $override

            # Assert
            (Format-Refusal -Decision $decision -Prefix 'ApplyApprovalPathNotSupplied') |
                Should -BeExactly 'False|True' -Because 'a preview nobody approved is a plan, and a plan is not permission to change a tenant'
        }

        It 'does not admit an apply run carrying no artifact root' {
            # Arrange
            $override = @{ ArtifactRoot = '   ' }

            # Act
            $decision = Invoke-Prerequisite -Override $override

            # Assert
            (Format-Refusal -Decision $decision -Prefix 'ApplyArtifactRootNotSupplied') |
                Should -BeExactly 'False|True' -Because 'a change with nowhere to write its pre-change state, its outcome and its rollback is a change no audit can reconstruct and no operator can undo'
        }
    }

    Context 'Negative: the approval behind the apply was never actually decided' {

        It 'does not admit an apply run with no approval decision behind it at all' {
            # Arrange
            $override = @{ ApprovalDecision = $null }

            # Act
            $decision = Invoke-Prerequisite -Override $override

            # Assert
            (Format-Refusal -Decision $decision -Prefix 'ApplyApprovalNotDecided') |
                Should -BeExactly 'False|True' -Because 'two paths on a command line prove that two files were named, not that anything read them'
        }

        It 'does not read an approval decision that reached no conclusion as one that permitted the apply' {
            # Arrange
            $override = @{ ApprovalDecision = [ordered]@{ ChangeId = $script:ChangeId; Finding = @() } }

            # Act
            $decision = Invoke-Prerequisite -Override $override

            # Assert
            (Format-Refusal -Decision $decision -Prefix 'ApplyApprovalDecidedNothing') |
                Should -BeExactly 'False|True' -Because 'a gate that reached no conclusion has not approved anything, and reading its silence as consent removes the review entirely'
        }

        It 'does not admit an apply run whose approval decision refused' {
            # Arrange
            $refused = New-ApprovalDecision -Permitted $false -Finding @('ChangeApprovalExpired: the preview expired at 2026-09-17T00:00:00Z.')

            # Act
            $decision = Invoke-Prerequisite -Override @{ ApprovalDecision = $refused }

            # Assert
            (Format-Refusal -Decision $decision -Prefix 'ApplyApprovalRefused') |
                Should -BeExactly 'False|True' -Because 'an apply that proceeds past a refused approval is the one change the approval gate exists to stop'
        }

        It 'does not omit any reason the approval was refused' {
            # Arrange
            $refused = New-ApprovalDecision -Permitted $false -Finding @(
                'ChangeApprovalExpired: the preview expired at 2026-09-17T00:00:00Z.'
                'ChangeApprovalSelfApproved: the operator both requested and approved this change.'
            )

            # Act
            $decision = Invoke-Prerequisite -Override @{ ApprovalDecision = $refused }

            # Assert
            (@($decision['Finding']) -join ' ') |
                Should -BeLike '*ChangeApprovalExpired*ChangeApprovalSelfApproved*' -Because 'an operator handed one blocker at a time has to obtain a fresh approval to learn what else was already wrong with it'
        }
    }

    Context 'Negative: the gate refuses a run it was never meant to govern' {

        It 'does not refuse an audit run for carrying no preview or approval it never needed' {
            # Arrange
            $override = @{ Apply = $false; PreviewPath = ''; ApprovalPath = ''; ArtifactRoot = ''; ApprovalDecision = $null }

            # Act
            $decision = Invoke-Prerequisite -Override $override

            # Assert
            '{0}|{1}' -f $decision['Permitted'], @($decision['Finding']).Count |
                Should -BeExactly 'True|0' -Because 'a read-only run that demands an approval before it may look at a tenant makes the audit harder to run than the change'
        }

        It 'does not admit a decision a caller can edit after the fact' {
            # Arrange
            $decision = Invoke-Prerequisite

            # Act
            $act = { $decision['Permitted'] = $false }

            # Assert
            $act | Should -Throw -Because 'a permission a caller can rewrite is a permission nobody granted'
        }
    }

    Context 'Positive: an apply run carrying a preview, an approval and somewhere to write its evidence' {

        It 'permits the apply and names the change it permits' {
            # Arrange
            $expected = "True|$script:ChangeId|0"

            # Act
            $decision = Invoke-Prerequisite

            # Assert
            '{0}|{1}|{2}' -f $decision['Permitted'], $decision['ChangeId'], @($decision['Finding']).Count |
                Should -BeExactly $expected -Because 'the only run that may change a tenant is one whose exact plan was previewed, approved and is about to be written down'
        }
    }
}
