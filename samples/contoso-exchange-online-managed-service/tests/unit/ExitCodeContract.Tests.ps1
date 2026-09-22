#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # The six ways a run can fail that an automation caller has to tell apart, plus the one way it
    # can succeed. Named here rather than read off the contract, so a contract that quietly drops
    # an outcome is a failure rather than a smaller expectation.
    $script:FaultOutcome = @('Configuration', 'Connection', 'Collection', 'Compliance', 'Approval', 'Internal')
    $script:DeclaredOutcome = @('Success') + $script:FaultOutcome

    function Get-ExitCodeMember {
        [CmdletBinding()]
        param([Parameter(Mandatory)][object]$Contract)

        if ($Contract -is [System.Collections.IDictionary]) { return @($Contract.Keys) }

        return @($Contract.PSObject.Properties | Where-Object { $_.MemberType -ne 'Method' } | ForEach-Object { $_.Name })
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'GATE-004-A1 the exit-code contract' {

    Context 'Negative: an outcome an automation caller cannot reach is an outcome nobody handles' {

        It 'declares the <_> outcome' -ForEach @('Success', 'Configuration', 'Connection', 'Collection', 'Compliance', 'Approval', 'Internal') {
            # Arrange
            $contract = Get-BaselineExitCodeContract

            # Act
            $declared = (Get-ExitCodeMember -Contract $contract)

            # Assert
            $declared | Should -Contain $_ -Because 'a fault class the contract never names is one every caller has to guess at'
        }

        It 'declares no outcome beyond the ones the contract is defined by' {
            # Arrange
            $contract = Get-BaselineExitCodeContract

            # Act
            $surplus = @((Get-ExitCodeMember -Contract $contract) | Where-Object { $_ -notin $script:DeclaredOutcome })

            # Assert
            ($surplus -join ',') | Should -BeExactly '' -Because 'an outcome nothing declared is a code no caller was told to expect'
        }
    }

    Context 'Negative: a code that is not automation-safe is a code that lies to the caller' {

        It 'resolves success to zero' {
            # Arrange
            $contract = Get-BaselineExitCodeContract

            # Act
            $code = $contract.Success

            # Assert
            $code | Should -BeExactly 0 -Because 'a success an automation caller reads as a failure stops every pipeline that obeys it'
        }

        It 'never resolves the <_> fault to zero' -ForEach @('Configuration', 'Connection', 'Collection', 'Compliance', 'Approval', 'Internal') {
            # Arrange
            $contract = Get-BaselineExitCodeContract

            # Act
            $code = $contract.$_

            # Assert
            $code | Should -Not -BeExactly 0 -Because 'a failure that exits zero is a failure nothing downstream will ever notice'
        }

        It 'resolves the <_> outcome to a whole number inside the range an exit status survives' -ForEach @('Success', 'Configuration', 'Connection', 'Collection', 'Compliance', 'Approval', 'Internal') {
            # Arrange
            $contract = Get-BaselineExitCodeContract

            # Act
            $code = $contract.$_

            # Assert
            ('Type={0}:InRange={1}' -f $code.GetType().Name, ($code -ge 0 -and $code -le 125)) |
                Should -BeExactly 'Type=Int32:InRange=True' -Because '126, 127 and anything above them are already spoken for by the shell and by signals, and a negative code is truncated on its way out'
        }

        It 'resolves no two outcomes to the same code' {
            # Arrange
            $contract = Get-BaselineExitCodeContract

            # Act
            $code = @((Get-ExitCodeMember -Contract $contract) | ForEach-Object { $contract.$_ })

            # Assert
            ('Declared={0}:Distinct={1}' -f $code.Count, (@($code | Select-Object -Unique).Count)) |
                Should -BeExactly ('Declared={0}:Distinct={0}' -f $script:DeclaredOutcome.Count) -Because 'two fault classes sharing a code are one fault class with two names'
        }
    }

    Context 'Negative: the contract is not something a caller can rewrite' {

        It 'refuses assignment to a declared code' {
            # Arrange
            $contract = Get-BaselineExitCodeContract

            # Act
            $act = { $contract.Compliance = 0 }

            # Assert
            $act | Should -Throw -Because 'a contract a caller can edit at runtime is a contract that says whatever the caller needs it to say'
        }
    }

    Context 'Positive: every declared outcome resolves to its own automation-safe code' {

        It 'resolves the whole contract to distinct automation-safe codes with success at zero' {
            # Arrange
            $expected = $script:DeclaredOutcome

            # Act
            $contract = Get-BaselineExitCodeContract

            # Assert
            ('Outcome={0}:Success={1}:Distinct={2}:Safe={3}' -f
                ((Get-ExitCodeMember -Contract $contract | Sort-Object) -join ','),
                $contract.Success,
                (@($expected | ForEach-Object { $contract.$_ } | Select-Object -Unique).Count),
                (@($expected | Where-Object { $contract.$_ -isnot [int] -or $contract.$_ -lt 0 -or $contract.$_ -gt 125 }).Count)) |
                Should -BeExactly ('Outcome={0}:Success=0:Distinct={1}:Safe=0' -f (($expected | Sort-Object) -join ','), $expected.Count) -Because 'an automation caller has to be able to act on which kind of failure this was, not merely that there was one'
        }
    }
}
