#requires -Version 7.0

# Discovery-scope copies so the per-case negatives can be expanded by -ForEach.
$RejectedScriptPath = @(
    @{ Case = 'null'; Value = $null }
    @{ Case = 'empty'; Value = '' }
    @{ Case = 'whitespace'; Value = '   ' }
)

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # Each fixture is a whole script rather than a fragment, because the analyzer decides guarded
    # from where a command sits in the parsed tree and a fragment has no tree to sit in.
    function New-GuardFixture {
        param([string]$Name, [string]$Body)

        $path = Join-Path $TestDrive "$Name.ps1"
        Set-Content -LiteralPath $path -Value $Body -Encoding utf8
        return $path
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-005-A1 mutation guard analyzer' {

    Context 'Negative: a script path that names no script is not an answer about guards' {

        It 'refuses a script path that is <Case>' -ForEach $RejectedScriptPath {
            # Arrange
            $candidate = $Value

            # Act
            $act = { Get-BaselineMutationGuardReport -ScriptPath $candidate }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ScriptPathNotSupplied*' -Because 'a guard report over no script is a clean bill of health nobody earned'
        }

        It 'refuses a script path naming no file' {
            # Arrange
            $missing = Join-Path $TestDrive 'no-such-script.ps1'

            # Act
            $act = { Get-BaselineMutationGuardReport -ScriptPath $missing }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ScriptPathNotFound*' -Because 'a script that is not there cannot be reported as one with no unguarded mutation'
        }

        It 'refuses a script it cannot parse' {
            # Arrange
            $path = New-GuardFixture -Name 'unparsable' -Body 'function Broken { if ($true) { Set-TransportConfig -Confirm:$false'

            # Act
            $act = { Get-BaselineMutationGuardReport -ScriptPath $path }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ScriptNotParsable*' -Because 'a script nobody could parse is a script whose mutations nobody enumerated'
        }
    }

    Context 'Negative: a mutation that no ShouldProcess decision reaches is not guarded' {

        It 'reports a mutation with no guard anywhere in the script' {
            # Arrange
            $path = New-GuardFixture -Name 'bare' -Body 'Set-TransportConfig -SmtpClientAuthenticationDisabled $true'

            # Act
            $report = Get-BaselineMutationGuardReport -ScriptPath $path

            # Assert
            @($report.UnguardedSite).Command | Should -Contain 'Set-TransportConfig' -Because 'a tenant mutation reachable with no decision is the defect this analyzer exists to catch'
        }

        It 'reports a mutation that is unguarded while a ShouldProcess call sits elsewhere in the script' {
            # Arrange
            $body = @'
if ($PSCmdlet.ShouldProcess('mailbox', 'Set audit')) {
    Set-OrganizationConfig -AuditDisabled $false
}
Set-TransportConfig -SmtpClientAuthenticationDisabled $true
'@
            $path = New-GuardFixture -Name 'guard-elsewhere' -Body $body

            # Act
            $report = Get-BaselineMutationGuardReport -ScriptPath $path

            # Assert
            @($report.UnguardedSite).Command | Should -Contain 'Set-TransportConfig' -Because 'one guard somewhere in the file does not cover a mutation it does not enclose'
        }

        It 'reports a mutation sitting in the else branch of a ShouldProcess test' {
            # Arrange
            $body = @'
if ($PSCmdlet.ShouldProcess('transport', 'Disable SMTP AUTH')) {
    Write-Host 'approved'
}
else {
    Set-TransportConfig -SmtpClientAuthenticationDisabled $true
}
'@
            $path = New-GuardFixture -Name 'else-branch' -Body $body

            # Act
            $report = Get-BaselineMutationGuardReport -ScriptPath $path

            # Assert
            @($report.UnguardedSite).Command | Should -Contain 'Set-TransportConfig' -Because 'the else branch is the path the operator declined, so a mutation there runs precisely when it was refused'
        }

        It 'reports a mutation guarded by a condition that is not a ShouldProcess decision' {
            # Arrange
            $body = @'
if ($Apply) {
    Set-TransportConfig -SmtpClientAuthenticationDisabled $true
}
'@
            $path = New-GuardFixture -Name 'not-shouldprocess' -Body $body

            # Act
            $report = Get-BaselineMutationGuardReport -ScriptPath $path

            # Assert
            @($report.UnguardedSite).Command | Should -Contain 'Set-TransportConfig' -Because 'a switch the caller sets is not a decision the caller was asked to confirm'
        }

        It 'reports a mutation guarded by a negated ShouldProcess decision' {
            # Arrange
            $body = @'
if (-not $PSCmdlet.ShouldProcess('transport', 'Disable SMTP AUTH')) {
    Set-TransportConfig -SmtpClientAuthenticationDisabled $true
}
'@
            $path = New-GuardFixture -Name 'negated' -Body $body

            # Act
            $report = Get-BaselineMutationGuardReport -ScriptPath $path

            # Assert
            @($report.UnguardedSite).Command | Should -Contain 'Set-TransportConfig' -Because 'a mutation that runs only when ShouldProcess said no is worse than one with no guard at all'
        }

        It 'reports a mutation guarded by a ShouldProcess call on something that is not $PSCmdlet' {
            # Arrange
            $body = @'
if ($fake.ShouldProcess('transport', 'Disable SMTP AUTH')) {
    Set-TransportConfig -SmtpClientAuthenticationDisabled $true
}
'@
            $path = New-GuardFixture -Name 'foreign-shouldprocess' -Body $body

            # Act
            $report = Get-BaselineMutationGuardReport -ScriptPath $path

            # Assert
            @($report.UnguardedSite).Command | Should -Contain 'Set-TransportConfig' -Because 'an object a script invented can answer ShouldProcess however the script finds convenient'
        }
    }

    Context 'Negative: the analyzer misreads what is not a tenant mutation' {

        It 'does not report a mutation nested deeper inside a guarded block as unguarded' {
            # Arrange
            $body = @'
if ($PSCmdlet.ShouldProcess('mailbox plans', 'Disable POP and IMAP')) {
    foreach ($plan in $plans) {
        Set-CASMailboxPlan -Identity $plan.Identity -PopEnabled $false
    }
}
'@
            $path = New-GuardFixture -Name 'nested' -Body $body

            # Act
            $report = Get-BaselineMutationGuardReport -ScriptPath $path

            # Assert
            @($report.UnguardedSite).Command | Should -Not -Contain 'Set-CASMailboxPlan' -Because 'an analyzer that only sees the first statement under a guard will be worked around by adding a loop'
        }

        It 'does not report a call to a mutating-looking function the script itself defines' {
            # Arrange
            $body = @'
function Set-InboundGatewayConnector {
    param([object]$Configuration)
    Write-Host 'local'
}

Set-InboundGatewayConnector -Configuration $config
'@
            $path = New-GuardFixture -Name 'local-function' -Body $body

            # Act
            $report = Get-BaselineMutationGuardReport -ScriptPath $path

            # Assert
            @($report.MutationSite).Command | Should -Not -Contain 'Set-InboundGatewayConnector' -Because 'a helper the script defines mutates nothing by itself, and flagging it hides the real mutations inside it'
        }

        It 'does not report a command the contract declares non-tenant' {
            # Arrange
            $declared = @((Get-BaselineMutationGuardContract).NonTenantCommand)
            $body = ($declared | ForEach-Object { "$_ -Whatever 1" }) -join "`n"
            $path = New-GuardFixture -Name 'non-tenant' -Body $body

            # Act
            $report = Get-BaselineMutationGuardReport -ScriptPath $path

            # Assert
            @($report.MutationSite).Count | Should -Be 0 -Because 'a command that shapes a local value is not a change anyone has to confirm'
        }
    }

    Context 'Negative: the report does not say what it found or does not stay found' {

        It 'names the command and the line of every unguarded site' {
            # Arrange
            $path = New-GuardFixture -Name 'named' -Body "Write-Host 'one'`nSet-TransportConfig -SmtpClientAuthenticationDisabled `$true"

            # Act
            $site = @((Get-BaselineMutationGuardReport -ScriptPath $path).UnguardedSite)

            # Assert
            ('{0}@{1}' -f $site[0].Command, $site[0].Line) | Should -BeExactly 'Set-TransportConfig@2' -Because 'an unguarded site nobody can locate is a finding nobody can fix'
        }

        It 'refuses assignment to the report' {
            # Arrange
            $path = New-GuardFixture -Name 'immutable' -Body 'Set-TransportConfig -SmtpClientAuthenticationDisabled $true'
            $report = Get-BaselineMutationGuardReport -ScriptPath $path

            # Act
            $act = { $report.UnguardedSite = @() }

            # Assert
            $act | Should -Throw -Because 'a report a caller can empty is a report that clears any script on request'
        }
    }

    Context 'Positive: a script whose every tenant mutation sits under a ShouldProcess decision' {

        It 'reports no unguarded mutation site' {
            # Arrange
            $body = @'
[CmdletBinding(SupportsShouldProcess)]
param()

function Set-Everything {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($PSCmdlet.ShouldProcess('transport', 'Disable SMTP AUTH')) {
        Set-TransportConfig -SmtpClientAuthenticationDisabled $true
    }

    if ($PSCmdlet.ShouldProcess('connector', 'Create inbound connector')) {
        New-InboundConnector -Name 'gateway'
    }

    if ($PSCmdlet.ShouldProcess('preset', 'Enable Standard preset')) {
        foreach ($rule in $rules) {
            Enable-EOPProtectionPolicyRule -Identity $rule
        }
    }
}

Set-Everything
'@
            $path = New-GuardFixture -Name 'fully-guarded' -Body $body

            # Act
            $report = Get-BaselineMutationGuardReport -ScriptPath $path

            # Assert
            ('{0} sites, {1} unguarded' -f @($report.MutationSite).Count, @($report.UnguardedSite).Count) |
                Should -BeExactly '3 sites, 0 unguarded' -Because 'the analyzer has to find every tenant mutation and clear only the ones a ShouldProcess decision encloses'
        }
    }
}
