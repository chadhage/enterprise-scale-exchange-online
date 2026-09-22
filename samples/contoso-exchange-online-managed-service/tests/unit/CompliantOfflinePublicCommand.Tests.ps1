#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:HarnessPath = Join-Path $script:SampleRoot 'tests' 'helpers' 'Tst006PublicCommandHarness.ps1'
    $script:CommandPath = Join-Path $script:SampleRoot 'scripts' 'Test-ExchangeOnlineBaseline.ps1'
    $script:FixtureRoot = Join-Path $script:SampleRoot 'tests' 'fixtures' 'tst006'

    if (Test-Path -LiteralPath $script:HarnessPath -PathType Leaf) {
        . $script:HarnessPath
    }

    function Invoke-PublicCommandHarnessUnderTest {
        param(
            [Parameter(Mandatory)][string]$CommandPath,
            [Parameter(Mandatory)][string]$FixtureRoot,
            [Parameter(Mandatory)][string]$OutputPath
        )

        $command = Get-Command -Name Invoke-Tst006PublicCommand -CommandType Function -ErrorAction Stop
        & $command -CommandPath $CommandPath -FixtureRoot $FixtureRoot -OutputPath $OutputPath
    }
}

Describe 'TST-006 shipped public-command offline invocation' {
    Context 'Negative: the harness refuses an invocation it cannot prove came from shipped inputs' {
        It 'refuses a public-command path that names no file' {
            # Arrange
            $commandPath = Join-Path $TestDrive 'Missing-Test-ExchangeOnlineBaseline.ps1'

            # Act
            $act = { Invoke-PublicCommandHarnessUnderTest -CommandPath $commandPath -FixtureRoot $script:FixtureRoot -OutputPath (Join-Path $TestDrive 'output') }

            # Assert
            $act | Should -Throw -ExpectedMessage 'Tst006PublicCommandMissing:*'
        }

        It 'refuses a fixture root that names no directory' {
            # Arrange
            $fixtureRoot = Join-Path $TestDrive 'missing-fixture'

            # Act
            $act = { Invoke-PublicCommandHarnessUnderTest -CommandPath $script:CommandPath -FixtureRoot $fixtureRoot -OutputPath (Join-Path $TestDrive 'output') }

            # Assert
            $act | Should -Throw -ExpectedMessage 'Tst006FixtureRootMissing:*'
        }

        It 'refuses a fixture root that carries no compliant Microsoft-native fixture' {
            # Arrange
            $fixtureRoot = Join-Path $TestDrive 'incomplete-fixture'
            $null = New-Item -ItemType Directory -Path $fixtureRoot

            # Act
            $act = { Invoke-PublicCommandHarnessUnderTest -CommandPath $script:CommandPath -FixtureRoot $fixtureRoot -OutputPath (Join-Path $TestDrive 'output') }

            # Assert
            $act | Should -Throw -ExpectedMessage 'Tst006CompliantFixtureMissing:*'
        }
    }

    Context 'Positive: one compliant fixture runs the shipped public command offline' {
        It 'exits zero through one real go-live decision and one real run outcome without credentials or tenant activity' {
            # Arrange
            $outputPath = Join-Path $TestDrive 'compliant-output'

            # Act
            $actual = Invoke-PublicCommandHarnessUnderTest -CommandPath $script:CommandPath `
                -FixtureRoot $script:FixtureRoot -OutputPath $outputPath

            # Assert
            $actual.CommandPath | Should -BeExactly $script:CommandPath
            $actual.ProcessExitCode | Should -BeExactly 0
            $actual.GoLiveDecision.Admitted | Should -BeTrue
            $actual.Outcome.ExitCode | Should -BeExactly 0
            $actual.GoLiveInvocationCount | Should -BeExactly 1
            $actual.RunOutcomeInvocationCount | Should -BeExactly 1
            $actual.ConnectionAttempt | Should -BeNullOrEmpty
            $actual.MutationAttempt | Should -BeNullOrEmpty
            $actual.CredentialAccess | Should -BeNullOrEmpty
        }
    }
}