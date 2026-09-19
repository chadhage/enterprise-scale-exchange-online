#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:GateToken = 'Test-BaselineApplyPrerequisite'

    # Every fixture is a synthetic script written to $TestDrive and only ever parsed, never run.
    function New-OrderFixture {
        param([string]$Root, [string[]]$Line)

        $path = Join-Path $Root ('apply-order-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
        $text = ($Line -join [System.Environment]::NewLine) + [System.Environment]::NewLine
        [System.IO.File]::WriteAllBytes($path, [System.Text.UTF8Encoding]::new($false).GetBytes($text))

        return $path
    }

    # The line the gate decides on. Pinned from the fixture rather than hard-coded so that an
    # analyzer which cannot find the gate at all fails the absence cases instead of passing them.
    function Get-FixtureGateLine {
        param([string]$Path)

        $match = @(Get-Content -LiteralPath $Path | Select-String -SimpleMatch $script:GateToken)

        return [int]$match[0].LineNumber
    }

    # '<GateLine>|<the code was raised>'. Carrying the gate line into every assertion is what keeps
    # 'no such finding' from meaning 'no such gate'.
    function Format-ApplyOrder {
        param([object]$Node, [string]$Code)

        return '{0}|{1}' -f [int]$Node['GateLine'],
            [bool](@($Node['Finding']) | Where-Object { $_ -like "$Code*" })
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

# Ordering rule this partition pins down, and every fixture below exists to hold it in place:
#
#   GateLine  is the start line of the Test-BaselineApplyPrerequisite invocation.
#   A site's effective line is its own start line, unless the site sits lexically inside a
#   function definition, in which case it is the earliest start line at which that function is
#   invoked - a mutation cannot run before the call that reaches it.
#   A site is BEFORE the gate when, and only when, effective line < GateLine. Strictly less: a
#   site on the gate's own line runs after the gate decided on that line, and is not a violation.
Describe 'SAFE-007-A2 nothing happens before the apply gate decides' {

    Context 'Negative: the script opens a tenant connection before the gate decides' {

        It 'refuses a connection opened above the gate' {
            # Arrange
            $path = New-OrderFixture -Root $TestDrive -Line @(
                'param([switch]$Apply)'
                ''
                'Import-Module ExchangeOnlineManagement'
                'Connect-ExchangeOnline -ShowBanner:$false'
                ''
                '$decision = Test-BaselineApplyPrerequisite -Apply:$Apply.IsPresent'
            )
            $gateLine = Get-FixtureGateLine -Path $path

            # Act
            $order = Test-BaselineDeploymentApplyOrder -ScriptPath $path

            # Assert
            (Format-ApplyOrder -Node $order -Code 'ApplyOrderConnectionBeforeGate') |
                Should -BeExactly ('{0}|True' -f $gateLine) -Because 'a run that signs into the tenant before it knows whether it is allowed to apply has already spent the credential the gate exists to withhold'
        }

        It 'refuses a connection reached through a helper called above the gate' {
            # Arrange
            $path = New-OrderFixture -Root $TestDrive -Line @(
                'param([switch]$Apply)'
                ''
                'function Open-TenantSession {'
                '    Connect-ExchangeOnline -ShowBanner:$false'
                '    Connect-MgGraph -Scopes ''Organization.Read.All'' -NoWelcome'
                '}'
                ''
                'Open-TenantSession'
                ''
                '$decision = Test-BaselineApplyPrerequisite -Apply:$Apply.IsPresent'
            )
            $gateLine = Get-FixtureGateLine -Path $path

            # Act
            $order = Test-BaselineDeploymentApplyOrder -ScriptPath $path

            # Assert
            (Format-ApplyOrder -Node $order -Code 'ApplyOrderConnectionBeforeGate') |
                Should -BeExactly ('{0}|True' -f $gateLine) -Because 'a connection is no later for being one call deep, and an order check that only reads top-level lines is evaded by moving the sign-in into a helper'
        }

        It 'does not refuse a connection on the gate''s own line' {
            # Arrange
            $path = New-OrderFixture -Root $TestDrive -Line @(
                'param([switch]$Apply)'
                ''
                '$decision = Test-BaselineApplyPrerequisite -Apply:$Apply.IsPresent; Connect-ExchangeOnline -ShowBanner:$false'
            )
            $gateLine = Get-FixtureGateLine -Path $path

            # Act
            $order = Test-BaselineDeploymentApplyOrder -ScriptPath $path

            # Assert
            (Format-ApplyOrder -Node $order -Code 'ApplyOrderConnectionBeforeGate') |
                Should -BeExactly ('{0}|False' -f $gateLine) -Because 'the gate is evaluated first on the line it shares, so a rule using <= instead of < condemns a correctly ordered script'
        }

        It 'does not refuse a connection on the line immediately after the gate' {
            # Arrange
            $path = New-OrderFixture -Root $TestDrive -Line @(
                'param([switch]$Apply)'
                ''
                '$decision = Test-BaselineApplyPrerequisite -Apply:$Apply.IsPresent'
                'Connect-ExchangeOnline -ShowBanner:$false'
            )
            $gateLine = Get-FixtureGateLine -Path $path

            # Act
            $order = Test-BaselineDeploymentApplyOrder -ScriptPath $path

            # Assert
            (Format-ApplyOrder -Node $order -Code 'ApplyOrderConnectionBeforeGate') |
                Should -BeExactly ('{0}|False' -f $gateLine) -Because 'connecting once the gate has admitted the run is the order this card is asking for, and reporting it leaves no ordering a script can adopt'
        }

        It 'does not refuse a connection in a helper defined above the gate but called only below it' {
            # Arrange
            $path = New-OrderFixture -Root $TestDrive -Line @(
                'param([switch]$Apply)'
                ''
                'function Open-TenantSession {'
                '    Connect-ExchangeOnline -ShowBanner:$false'
                '}'
                ''
                '$decision = Test-BaselineApplyPrerequisite -Apply:$Apply.IsPresent'
                'Open-TenantSession'
            )
            $gateLine = Get-FixtureGateLine -Path $path

            # Act
            $order = Test-BaselineDeploymentApplyOrder -ScriptPath $path

            # Assert
            (Format-ApplyOrder -Node $order -Code 'ApplyOrderConnectionBeforeGate') |
                Should -BeExactly ('{0}|False' -f $gateLine) -Because 'a function definition runs nothing, so judging a helper by where it is written rather than where it is called forbids declaring helpers at the top of a script'
        }
    }

    Context 'Negative: a tenant mutation sits before the gate decides' {

        It 'refuses a tenant mutation above the gate' {
            # Arrange
            $path = New-OrderFixture -Root $TestDrive -Line @(
                'param([switch]$Apply)'
                ''
                'Set-TransportConfig -SmtpClientAuthenticationDisabled $true'
                ''
                '$decision = Test-BaselineApplyPrerequisite -Apply:$Apply.IsPresent'
            )
            $gateLine = Get-FixtureGateLine -Path $path

            # Act
            $order = Test-BaselineDeploymentApplyOrder -ScriptPath $path

            # Assert
            (Format-ApplyOrder -Node $order -Code 'ApplyOrderMutationBeforeGate') |
                Should -BeExactly ('{0}|True' -f $gateLine) -Because 'a change made before the gate decides is a change the gate can only refuse retrospectively, which is not a refusal at all'
        }

        It 'refuses a tenant mutation reached through a helper called above the gate' {
            # Arrange
            $path = New-OrderFixture -Root $TestDrive -Line @(
                'param([switch]$Apply)'
                ''
                'function Set-EarlyState {'
                '    Set-OrganizationConfig -AuditDisabled $false'
                '}'
                ''
                'Set-EarlyState'
                ''
                '$decision = Test-BaselineApplyPrerequisite -Apply:$Apply.IsPresent'
            )
            $gateLine = Get-FixtureGateLine -Path $path

            # Act
            $order = Test-BaselineDeploymentApplyOrder -ScriptPath $path

            # Assert
            (Format-ApplyOrder -Node $order -Code 'ApplyOrderMutationBeforeGate') |
                Should -BeExactly ('{0}|True' -f $gateLine) -Because 'the mutation guard report excludes the call to a locally defined function, so a check that only looks at call sites sees nothing while the tenant is changed inside the helper'
        }

        It 'does not refuse a tenant mutation on the gate''s own line' {
            # Arrange
            $path = New-OrderFixture -Root $TestDrive -Line @(
                'param([switch]$Apply)'
                ''
                '$decision = Test-BaselineApplyPrerequisite -Apply:$Apply.IsPresent; Set-TransportConfig -SmtpClientAuthenticationDisabled $true'
            )
            $gateLine = Get-FixtureGateLine -Path $path

            # Act
            $order = Test-BaselineDeploymentApplyOrder -ScriptPath $path

            # Assert
            (Format-ApplyOrder -Node $order -Code 'ApplyOrderMutationBeforeGate') |
                Should -BeExactly ('{0}|False' -f $gateLine) -Because 'sharing a line with the gate is not running before it, and a rule that says otherwise reports a violation no reordering can clear'
        }

        It 'does not refuse a tenant mutation on the line immediately after the gate' {
            # Arrange
            $path = New-OrderFixture -Root $TestDrive -Line @(
                'param([switch]$Apply)'
                ''
                '$decision = Test-BaselineApplyPrerequisite -Apply:$Apply.IsPresent'
                'Set-TransportConfig -SmtpClientAuthenticationDisabled $true'
            )
            $gateLine = Get-FixtureGateLine -Path $path

            # Act
            $order = Test-BaselineDeploymentApplyOrder -ScriptPath $path

            # Assert
            (Format-ApplyOrder -Node $order -Code 'ApplyOrderMutationBeforeGate') |
                Should -BeExactly ('{0}|False' -f $gateLine) -Because 'mutating after the gate has admitted the run is the ordering the card demands, and a check that still reports it cannot be satisfied by any script'
        }

        It 'does not refuse a tenant mutation in a helper defined above the gate but called only below it' {
            # Arrange
            $path = New-OrderFixture -Root $TestDrive -Line @(
                'param([switch]$Apply)'
                ''
                'function Set-BaselineState {'
                '    Set-TransportConfig -SmtpClientAuthenticationDisabled $true'
                '}'
                ''
                '$decision = Test-BaselineApplyPrerequisite -Apply:$Apply.IsPresent'
                'Set-BaselineState'
            )
            $gateLine = Get-FixtureGateLine -Path $path

            # Act
            $order = Test-BaselineDeploymentApplyOrder -ScriptPath $path

            # Assert
            (Format-ApplyOrder -Node $order -Code 'ApplyOrderMutationBeforeGate') |
                Should -BeExactly ('{0}|False' -f $gateLine) -Because 'the mutation guard reports the site at the line it is written on, so attributing an uncalled helper body to that line condemns every script that declares its helpers first'
        }

        It 'does not refuse a local, non-tenant mutating command above the gate' {
            # Arrange
            $path = New-OrderFixture -Root $TestDrive -Line @(
                'param([switch]$Apply)'
                ''
                'New-Item -ItemType Directory -Path $PSScriptRoot/artifact -Force | Out-Null'
                'Set-Variable -Name mode -Value ''audit'''
                'Set-StrictMode -Version Latest'
                ''
                '$decision = Test-BaselineApplyPrerequisite -Apply:$Apply.IsPresent'
            )
            $gateLine = Get-FixtureGateLine -Path $path

            # Act
            $order = Test-BaselineDeploymentApplyOrder -ScriptPath $path

            # Assert
            (Format-ApplyOrder -Node $order -Code 'ApplyOrderMutationBeforeGate') |
                Should -BeExactly ('{0}|False' -f $gateLine) -Because 'the guard contract already excludes these as non-tenant commands, and re-deriving the site list from the verb alone reports creating a local directory as changing the tenant'
        }
    }
}
