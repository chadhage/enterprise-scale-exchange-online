#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:DeploymentScriptPath = Join-Path $script:SampleRoot 'scripts' 'Deploy-ExchangeOnlineBaseline.ps1'
    $script:ModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    $script:PreflightFunction = 'Test-BaselineSafeDocumentsPreflight'

    # The members that actually turn Safe Documents on in the tenant. Every one of them must sit
    # behind the preflight verdict, because either alone configures the capability.
    $script:SafeDocumentsMemberPattern = '(?i)^(EnableSafeDocs|AllowSafeDocsOpen)$'

    # A guard is only a preflight guard when it reads MayApply off something named for the
    # preflight. Any other variable carrying a MayApply member is not the verdict this card is about.
    $script:PreflightVerdictPattern = '(?i)\$[A-Za-z0-9_]*preflight[A-Za-z0-9_]*\.MayApply\b'
    $script:PreflightReasonPattern = '(?i)\$[A-Za-z0-9_]*preflight[A-Za-z0-9_]*\.Reason\b'
    $script:TenantCapabilityPattern = '(?i)\$[A-Za-z0-9_]*\.SafeDocuments\b'

    # The defect shape LIC-008 removed: a capability decided from planning metadata instead of a
    # service plan the tenant actually holds.
    $script:DeclaredTierPattern = "(?i)(licensing\.(messagingTier|complianceTier)|-(eq|ne|in)\s*@?\(?\s*'(EOP|MDO_P1|MDO_P2|E3|E5Compliance)')"

    function Get-ScriptAst {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        $tokens = $null
        $errors = $null
        return [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    }

    function Get-AncestorAst {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [System.Management.Automation.Language.Ast]$Node,

            [Parameter(Mandatory)]
            [type]$Type
        )

        $found = [System.Collections.Generic.List[object]]::new()
        $current = $Node.Parent
        while ($null -ne $current) {
            if ($Type.IsInstanceOfType($current)) { $found.Add($current) }
            $current = $current.Parent
        }

        return @($found)
    }

    # Every place the script turns Safe Documents on, whether by assigning a member of a splat
    # table or by declaring the key inside a hashtable literal.
    function Get-SafeDocumentsAssignment {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [System.Management.Automation.Language.Ast]$Ast
        )

        $assignment = [System.Collections.Generic.List[object]]::new()

        $statements = @($Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))
        foreach ($statement in $statements) {
            $leaf = ($statement.Left.Extent.Text -split '\.')[-1].Trim()
            if ($leaf -notmatch $script:SafeDocumentsMemberPattern) { continue }
            $assignment.Add($statement)
        }

        $hashtables = @($Ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.HashtableAst] }, $true))
        foreach ($hashtable in $hashtables) {
            foreach ($pair in $hashtable.KeyValuePairs) {
                if ($pair.Item1.Extent.Text.Trim("'`" ") -notmatch $script:SafeDocumentsMemberPattern) { continue }
                $assignment.Add($pair.Item2)
            }
        }

        return @($assignment)
    }

    function Get-SafeDocumentsGateResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$DeploymentScriptPath,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [string]$ModulePath
        )

        $result = [ordered]@{
            Satisfied  = $false
            Reason     = $null
            Violations = @()
        }

        if ([string]::IsNullOrWhiteSpace($DeploymentScriptPath) -or -not (Test-Path -LiteralPath $DeploymentScriptPath -PathType Leaf)) {
            $result.Reason = 'DeploymentScriptMissing'
            return [pscustomobject]$result
        }

        if ([string]::IsNullOrWhiteSpace($ModulePath) -or -not (Test-Path -LiteralPath $ModulePath -PathType Leaf)) {
            $result.Reason = 'SharedModuleMissing'
            return [pscustomobject]$result
        }

        $exported = @(
            (Get-ScriptAst -Path $ModulePath).FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
                Where-Object { $_.GetCommandName() -eq 'Export-ModuleMember' } |
                Where-Object { $_.Extent.Text -match [regex]::Escape($script:PreflightFunction) }
        )

        if ($exported.Count -eq 0) {
            $result.Reason = 'PreflightNotExported'
            return [pscustomobject]$result
        }

        $ast = Get-ScriptAst -Path $DeploymentScriptPath
        $content = Get-Content -LiteralPath $DeploymentScriptPath -Raw

        $invocation = @(
            $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
                Where-Object { $_.GetCommandName() -eq $script:PreflightFunction }
        )

        if ($invocation.Count -eq 0) {
            $result.Reason = 'PreflightNotInvoked'
            return [pscustomobject]$result
        }

        if ($content -match $script:DeclaredTierPattern) {
            $result.Reason = 'SafeDocumentsDerivedFromDeclaredTier'
            $result.Violations = @($Matches[0])
            return [pscustomobject]$result
        }

        $assignment = Get-SafeDocumentsAssignment -Ast $ast
        if ($assignment.Count -eq 0) {
            $result.Reason = 'SafeDocumentsAssignmentMissing'
            return [pscustomobject]$result
        }

        foreach ($node in $assignment) {
            $scope = @(Get-AncestorAst -Node $node -Type ([System.Management.Automation.Language.ScriptBlockAst]))
            if ($scope.Count -eq 0) {
                $result.Reason = 'SafeDocumentsUnguarded'
                $result.Violations = @($node.Extent.Text)
                return [pscustomobject]$result
            }

            $scopeText = $scope[0].Extent.Text
            $verdictReference = @([regex]::Matches($scopeText, $script:PreflightVerdictPattern))

            if ($verdictReference.Count -eq 0) {
                $result.Reason = if ($scopeText -match $script:TenantCapabilityPattern) { 'SafeDocumentsGuardedByTenantVerdictAlone' } else { 'SafeDocumentsUnguarded' }
                $result.Violations = @($node.Extent.Text)
                return [pscustomobject]$result
            }

            $offsetInScope = $node.Extent.StartOffset - $scope[0].Extent.StartOffset
            if (-not @($verdictReference | Where-Object { $_.Index -lt $offsetInScope })) {
                $result.Reason = 'PreflightReachedAfterMutation'
                $result.Violations = @($node.Extent.Text)
                return [pscustomobject]$result
            }

            $guard = @(
                Get-AncestorAst -Node $node -Type ([System.Management.Automation.Language.IfStatementAst]) |
                    Where-Object { @($_.Clauses | ForEach-Object { $_.Item1.Extent.Text }) -match $script:PreflightVerdictPattern }
            )

            if ($guard.Count -eq 0) {
                $result.Reason = 'SafeDocumentsUnguarded'
                $result.Violations = @($node.Extent.Text)
                return [pscustomobject]$result
            }

            $condition = [string]$guard[0].Clauses[0].Item1.Extent.Text
            $inElse = $null -ne $guard[0].ElseClause -and
            $node.Extent.StartOffset -ge $guard[0].ElseClause.Extent.StartOffset -and
            $node.Extent.EndOffset -le $guard[0].ElseClause.Extent.EndOffset

            if ($condition -match '(?i)(-not\b|!\s*\$)' -or $inElse) {
                $result.Reason = 'SafeDocumentsAppliedAgainstPreflight'
                $result.Violations = @($node.Extent.Text)
                return [pscustomobject]$result
            }
        }

        if ($content -notmatch $script:PreflightReasonPattern) {
            $result.Reason = 'PreflightRefusalNotRecorded'
            return [pscustomobject]$result
        }

        $result.Satisfied = $true
        $result.Reason = 'SafeDocumentsGatedByPreflight'
        return [pscustomobject]$result
    }

    # A minimal deployment script carrying only the Safe Documents decision, so each negative
    # arranges exactly the violation it names instead of inheriting it from unrelated code.
    function New-DeploymentFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path,

            [switch]$OmitPreflightInvocation,
            [switch]$OmitAssignment,
            [switch]$OmitGuard,
            [switch]$GuardOnTenantCapability,
            [switch]$GuardOnDeclaredTier,
            [switch]$CompareDeclaredTierLiteral,
            [switch]$NegateGuard,
            [switch]$AssignInElseBranch,
            [switch]$ConsultPreflightAfterAssignment,
            [switch]$OmitRefusalOutcome,
            [switch]$AssignAllowSafeDocsOpenOnly
        )

        $member = if ($AssignAllowSafeDocsOpenOnly) { 'AllowSafeDocsOpen' } else { 'EnableSafeDocs' }

        $body = if ($OmitAssignment) {
            @'
        Add-Outcome -Control 'MDO-005' -Status 'Planned' -Detail 'nothing to do'
'@
        }
        elseif ($OmitGuard) {
            "        `$atpParameters.$member = `$true"
        }
        elseif ($GuardOnTenantCapability) {
            @"
        if (`$Entitlement.SafeDocuments) {
            `$atpParameters.$member = `$true
        }
"@
        }
        elseif ($GuardOnDeclaredTier) {
            @"
        if (`$Configuration.licensing.messagingTier) {
            `$atpParameters.$member = `$true
        }
"@
        }
        elseif ($CompareDeclaredTierLiteral) {
            @"
        if (`$SafeDocumentsPreflight.MayApply -and `$tier -eq 'MDO_P2') {
            `$atpParameters.$member = `$true
        }
"@
        }
        elseif ($NegateGuard) {
            @"
        if (-not `$SafeDocumentsPreflight.MayApply) {
            `$atpParameters.$member = `$true
        }
"@
        }
        elseif ($AssignInElseBranch) {
            @"
        if (`$SafeDocumentsPreflight.MayApply) {
            Add-Outcome -Control 'MDO-005' -Status 'Planned' -Detail 'gated'
        }
        else {
            `$atpParameters.$member = `$true
        }
"@
        }
        elseif ($ConsultPreflightAfterAssignment) {
            @"
        `$atpParameters.$member = `$true
        if (`$SafeDocumentsPreflight.MayApply) {
            Add-Outcome -Control 'MDO-005' -Status 'Applied' -Detail 'gated'
        }
"@
        }
        else {
            @"
        if (`$SafeDocumentsPreflight.MayApply) {
            `$atpParameters.$member = `$true
        }
"@
        }

        $refusal = if ($OmitRefusalOutcome) {
            "        Add-Outcome -Control 'MDO-005' -Status 'NotEntitled' -Detail 'not applied'"
        }
        else {
            "        Add-Outcome -Control 'MDO-005' -Status 'NotEntitled' -Detail `$SafeDocumentsPreflight.Reason"
        }

        $invocation = if ($OmitPreflightInvocation) {
            '$SafeDocumentsPreflight = $context.Entitlement'
        }
        else {
            '$SafeDocumentsPreflight = Test-BaselineSafeDocumentsPreflight -Configuration $context.Configuration -Entitlement $context.Entitlement -TargetPopulation $population -TargetEntitlement $targetEntitlement'
        }

        $text = @"
[CmdletBinding()]
param()

Import-Module (Join-Path `$PSScriptRoot 'ExchangeOnlineBaseline.Common.psm1') -Force

function Add-Outcome { param([string]`$Control, [string]`$Status, [string]`$Detail) }

function Set-OrganizationControls {
    param([object]`$Configuration, [object]`$Entitlement, [object]`$SafeDocumentsPreflight)

    `$atpParameters = @{ EnableATPForSPOTeamsODB = `$true }

$body

$refusal
}

$invocation

Set-OrganizationControls -Configuration `$context.Configuration -Entitlement `$context.Entitlement -SafeDocumentsPreflight `$SafeDocumentsPreflight
"@

        Set-Content -LiteralPath $Path -Value $text -Encoding utf8
        return $Path
    }

    function New-ModuleFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path,

            [switch]$OmitPreflightExport
        )

        $exported = if ($OmitPreflightExport) { "'Get-BaselineContext'" } else { "'Get-BaselineContext'`n    '$script:PreflightFunction'" }

        $text = @"
function Test-BaselineSafeDocumentsPreflight { param() }

Export-ModuleMember -Function @(
    $exported
)
"@

        Set-Content -LiteralPath $Path -Value $text -Encoding utf8
        return $Path
    }
}

Describe 'LIC-009-A2 Deployment gate on the Safe Documents preflight' {

    Context 'Negative: the gate inputs must be usable' {

        It 'refuses an absent deployment entry script' {
            # Arrange
            $absent = Join-Path $TestDrive 'no-such-deployment.ps1'

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath $absent -ModulePath (New-ModuleFixture -Path (Join-Path $TestDrive 'module.psm1'))

            # Assert
            $gate.Reason | Should -Be 'DeploymentScriptMissing' -Because 'a gate asserted over a script that does not exist proves nothing about the shipped one'
        }

        It 'refuses an absent shared module' {
            # Arrange
            $absentModule = Join-Path $TestDrive 'no-such-module.psm1'

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath (New-DeploymentFixture -Path (Join-Path $TestDrive 'deploy.ps1')) -ModulePath $absentModule

            # Assert
            $gate.Reason | Should -Be 'SharedModuleMissing' -Because 'the preflight the script is required to call has to exist somewhere the script can reach'
        }

        It 'refuses a shared module that does not export the preflight' {
            # Arrange
            $unexported = New-ModuleFixture -Path (Join-Path $TestDrive 'module.psm1') -OmitPreflightExport

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath (New-DeploymentFixture -Path (Join-Path $TestDrive 'deploy.ps1')) -ModulePath $unexported

            # Assert
            $gate.Reason | Should -Be 'PreflightNotExported' -Because 'a preflight the entry script cannot bind to cannot gate anything'
        }
    }

    Context 'Negative: Safe Documents is never applied outside the preflight verdict' {

        It 'refuses a deployment script that never invokes the preflight' {
            # Arrange
            $uncalled = New-DeploymentFixture -Path (Join-Path $TestDrive 'deploy.ps1') -OmitPreflightInvocation

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath $uncalled -ModulePath (New-ModuleFixture -Path (Join-Path $TestDrive 'module.psm1'))

            # Assert
            $gate.Reason | Should -Be 'PreflightNotInvoked' -Because 'a gate nobody calls is not a gate'
        }

        It 'refuses a deployment script that configures no Safe Documents member at all' {
            # Arrange
            $inert = New-DeploymentFixture -Path (Join-Path $TestDrive 'deploy.ps1') -OmitAssignment

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath $inert -ModulePath (New-ModuleFixture -Path (Join-Path $TestDrive 'module.psm1'))

            # Assert
            $gate.Reason | Should -Be 'SafeDocumentsAssignmentMissing' -Because 'a script that never configures Safe Documents would satisfy the gate by doing nothing'
        }

        It 'refuses an unguarded EnableSafeDocs assignment' {
            # Arrange
            $unguarded = New-DeploymentFixture -Path (Join-Path $TestDrive 'deploy.ps1') -OmitGuard

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath $unguarded -ModulePath (New-ModuleFixture -Path (Join-Path $TestDrive 'module.psm1'))

            # Assert
            $gate.Reason | Should -Be 'SafeDocumentsUnguarded' -Because 'EnableSafeDocs turns the capability on by itself and must never be reached outside the verdict'
        }

        It 'refuses an unguarded AllowSafeDocsOpen assignment' {
            # Arrange
            $unguardedBypass = New-DeploymentFixture -Path (Join-Path $TestDrive 'deploy.ps1') -OmitGuard -AssignAllowSafeDocsOpenOnly

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath $unguardedBypass -ModulePath (New-ModuleFixture -Path (Join-Path $TestDrive 'module.psm1'))

            # Assert
            $gate.Reason | Should -Be 'SafeDocumentsUnguarded' -Because 'the bypass setting configures Safe Documents just as the enable setting does'
        }

        It 'refuses a Safe Documents assignment guarded by the tenant capability verdict alone' {
            # Arrange
            $tenantOnly = New-DeploymentFixture -Path (Join-Path $TestDrive 'deploy.ps1') -GuardOnTenantCapability

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath $tenantOnly -ModulePath (New-ModuleFixture -Path (Join-Path $TestDrive 'module.psm1'))

            # Assert
            $gate.Reason | Should -Be 'SafeDocumentsGuardedByTenantVerdictAlone' -Because 'a tenant-wide SAFEDOCS plan says nothing about whether every targeted user holds one'
        }

        It 'refuses a Safe Documents decision read from a declared licensing tier' {
            # Arrange
            $tierRead = New-DeploymentFixture -Path (Join-Path $TestDrive 'deploy.ps1') -GuardOnDeclaredTier

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath $tierRead -ModulePath (New-ModuleFixture -Path (Join-Path $TestDrive 'module.psm1'))

            # Assert
            $gate.Reason | Should -Be 'SafeDocumentsDerivedFromDeclaredTier' -Because 'planning metadata is not evidence of a service plan the tenant holds'
        }

        It 'refuses a Safe Documents decision compared against a declared tier literal' {
            # Arrange
            $tierLiteral = New-DeploymentFixture -Path (Join-Path $TestDrive 'deploy.ps1') -CompareDeclaredTierLiteral

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath $tierLiteral -ModulePath (New-ModuleFixture -Path (Join-Path $TestDrive 'module.psm1'))

            # Assert
            $gate.Reason | Should -Be 'SafeDocumentsDerivedFromDeclaredTier' -Because 'a preflight narrowed by a tier comparison is still a tier decision'
        }

        It 'refuses a Safe Documents assignment made when the preflight refused it' {
            # Arrange
            $negated = New-DeploymentFixture -Path (Join-Path $TestDrive 'deploy.ps1') -NegateGuard

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath $negated -ModulePath (New-ModuleFixture -Path (Join-Path $TestDrive 'module.psm1'))

            # Assert
            $gate.Reason | Should -Be 'SafeDocumentsAppliedAgainstPreflight' -Because 'naming the verdict is not the same as obeying it'
        }

        It 'refuses a Safe Documents assignment made in the branch the preflight refused' {
            # Arrange
            $elseBranch = New-DeploymentFixture -Path (Join-Path $TestDrive 'deploy.ps1') -AssignInElseBranch

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath $elseBranch -ModulePath (New-ModuleFixture -Path (Join-Path $TestDrive 'module.psm1'))

            # Assert
            $gate.Reason | Should -Be 'SafeDocumentsAppliedAgainstPreflight' -Because 'the refused branch is exactly where the capability must not be configured'
        }

        It 'refuses a preflight consulted only after the Safe Documents mutation' {
            # Arrange
            $afterwards = New-DeploymentFixture -Path (Join-Path $TestDrive 'deploy.ps1') -ConsultPreflightAfterAssignment

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath $afterwards -ModulePath (New-ModuleFixture -Path (Join-Path $TestDrive 'module.psm1'))

            # Assert
            $gate.Reason | Should -Be 'PreflightReachedAfterMutation' -Because 'a verdict read after the tenant has already been changed cannot prevent the change'
        }

        It 'refuses a refused preflight that is not recorded with its reason' {
            # Arrange
            $silent = New-DeploymentFixture -Path (Join-Path $TestDrive 'deploy.ps1') -OmitRefusalOutcome

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath $silent -ModulePath (New-ModuleFixture -Path (Join-Path $TestDrive 'module.psm1'))

            # Assert
            $gate.Reason | Should -Be 'PreflightRefusalNotRecorded' -Because 'an operator who is told nothing cannot tell a refusal from a capability that was never attempted'
        }
    }

    Context 'Negative: the gate stays offline' {

        # The stubs are global, so cleanup must survive an Act that throws; otherwise a failing
        # run leaks them into the session and every later test resolves them instead of failing.
        AfterEach {
            Remove-Item -Path 'function:global:Connect-ExchangeOnline', 'function:global:Connect-MgGraph', 'function:global:Set-AtpPolicyForO365', 'function:global:Get-MgSubscribedSku' -ErrorAction SilentlyContinue
        }

        It 'reads the deployment script without running any part of it' {
            # Arrange
            $script:GateCommandInvocation = [System.Collections.Generic.List[string]]::new()
            function global:Connect-ExchangeOnline { $script:GateCommandInvocation.Add('Connect-ExchangeOnline') }
            function global:Connect-MgGraph { $script:GateCommandInvocation.Add('Connect-MgGraph') }
            function global:Set-AtpPolicyForO365 { $script:GateCommandInvocation.Add('Set-AtpPolicyForO365') }
            function global:Get-MgSubscribedSku { $script:GateCommandInvocation.Add('Get-MgSubscribedSku') }

            # Act
            $null = Get-SafeDocumentsGateResult -DeploymentScriptPath $script:DeploymentScriptPath -ModulePath $script:ModulePath

            # Assert
            $script:GateCommandInvocation | Should -BeNullOrEmpty -Because 'the gate is a static reading of the shipped script and must never connect to a tenant'
        }
    }

    Context 'Positive: the shipped deployment script gates Safe Documents on the preflight' {

        It 'applies Safe Documents solely under one preflight verdict obtained from the shared module' {
            # Arrange
            $shippedDeploymentScript = $script:DeploymentScriptPath

            # Act
            $gate = Get-SafeDocumentsGateResult -DeploymentScriptPath $shippedDeploymentScript -ModulePath $script:ModulePath

            # Assert
            '{0}:{1}' -f $gate.Satisfied, $gate.Reason |
                Should -Be 'True:SafeDocumentsGatedByPreflight' -Because 'Safe Documents may reach the tenant only when the tenant and every target hold an enabled SAFEDOCS plan'
        }
    }
}
