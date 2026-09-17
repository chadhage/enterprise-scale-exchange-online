#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:EvaluatedAtUtc = [datetime]::new(2026, 9, 17, 12, 0, 0, [System.DateTimeKind]::Utc)
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'COM-005-A4 normalized control result construction' {

    Context 'Negative: a result must refuse a vocabulary it cannot normalize' {

        It 'fails with ControlIdRequired when the control identifier is empty' {
            # Arrange
            $emptyControlId = '   '

            # Act
            $act = { New-ControlResult -ControlId $emptyControlId -Status 'Pass' -EvaluatedAtUtc $script:EvaluatedAtUtc }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ControlIdRequired*'
        }

        It 'fails with StatusRequired when the status is empty' {
            # Arrange
            $emptyStatus = '   '

            # Act
            $act = { New-ControlResult -ControlId 'EXO-002' -Status $emptyStatus -EvaluatedAtUtc $script:EvaluatedAtUtc }

            # Assert
            $act | Should -Throw -ExpectedMessage '*StatusRequired*'
        }

        It 'fails with UnknownControlStatus when the status is outside the declared vocabulary' {
            # Arrange
            $undeclaredStatus = 'Skipped'

            # Act
            $act = { New-ControlResult -ControlId 'EXO-002' -Status $undeclaredStatus -Reason 'The collector was not run.' -EvaluatedAtUtc $script:EvaluatedAtUtc }

            # Assert
            $act | Should -Throw -ExpectedMessage '*UnknownControlStatus*'
        }

        It 'fails with ReasonRequired when a <_> result carries no reason' -ForEach @(
            'Fail'
            'Error'
            'NotApplicable'
            'ApprovedException'
            'Manual'
            'NotEntitled'
            'Unverified'
        ) {
            # Arrange
            $status = $_

            # Act
            $act = { New-ControlResult -ControlId 'EXO-002' -Status $status -EvaluatedAtUtc $script:EvaluatedAtUtc }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ReasonRequired*'
        }
    }

    Context 'Negative: a non-normalized status can never stand in for a result' {

        It 'does not treat <_> as a normalized status' -ForEach @('Manual', 'NotEntitled', 'Unverified') {
            # Arrange
            $status = $_

            # Act
            $result = New-ControlResult -ControlId 'EXO-010' -Status $status -Reason 'Evaluation could not conclude.' -EvaluatedAtUtc $script:EvaluatedAtUtc

            # Assert
            $result.Normalized | Should -BeFalse
        }

        It 'does not treat <_> as a go-live success' -ForEach @('Manual', 'NotEntitled', 'Unverified') {
            # Arrange
            $status = $_

            # Act
            $result = New-ControlResult -ControlId 'EXO-010' -Status $status -Reason 'Evaluation could not conclude.' -EvaluatedAtUtc $script:EvaluatedAtUtc

            # Assert
            $result.GoLiveSuccess | Should -BeFalse
        }
    }

    Context 'Negative: a failing result can never be a go-live success' {

        It 'does not treat <_> as a go-live success' -ForEach @('Fail', 'Error') {
            # Arrange
            $status = $_

            # Act
            $result = New-ControlResult -ControlId 'EXO-004' -Status $status -Reason 'A mailbox forwards externally.' -EvaluatedAtUtc $script:EvaluatedAtUtc

            # Assert
            $result.GoLiveSuccess | Should -BeFalse
        }
    }

    Context 'Negative: a result must not be rewritten after it is recorded' {

        It 'rejects assignment to the status of a recorded result' {
            # Arrange
            $result = New-ControlResult -ControlId 'EXO-004' -Status 'Fail' -Reason 'A mailbox forwards externally.' -EvaluatedAtUtc $script:EvaluatedAtUtc

            # Act
            $act = { $result.Status = 'Pass' }

            # Assert
            $act | Should -Throw
        }
    }

    Context 'Positive: a passing result is normalized and admits go-live' {

        It 'records the control identifier, a passing status, normalization and go-live success' {
            # Arrange
            $controlId = 'EXO-002'

            # Act
            $result = New-ControlResult -ControlId $controlId -Status 'Pass' -EvaluatedAtUtc $script:EvaluatedAtUtc

            # Assert
            ('{0}:{1}:Normalized={2}:GoLive={3}:At={4}' -f $result.ControlId, $result.Status, $result.Normalized, $result.GoLiveSuccess, $result.EvaluatedAtUtc.ToString('o')) |
                Should -BeExactly 'EXO-002:Pass:Normalized=True:GoLive=True:At=2026-09-17T12:00:00.0000000Z'
        }
    }
}
