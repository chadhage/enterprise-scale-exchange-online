#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # The four artifacts a mutating run leaves behind, named exactly as
    # Get-BaselineChangeArtifactContract names them. Written out here rather than read off the
    # contract, so a contract that quietly drops one of them fails these tests instead of
    # shrinking what they expect. Preview and Approval are excluded on purpose: they are made
    # before the run that mutates, and this partition only judges what the mutation itself emits.
    $script:ChangeArtifact = @('PreChange', 'Apply', 'Rollback', 'PostChange')

    # In contract Sequence order: PreChange 3, Apply 4, Rollback 5, PostChange 6.
    $script:EmissionLine = @{
        PreChange  = '    $prechange = Write-BaselineChangeArtifact -ChangeId $ChangeId -Artifact ''PreChange'' -Root $ArtifactRoot -Content $before'
        Apply      = '    $applied = Write-BaselineChangeArtifact -ChangeId $ChangeId -Artifact ''Apply'' -Root $ArtifactRoot -Content @{ Command = ''Set-TransportConfig'' }'
        Rollback   = '    $rollback = Write-BaselineChangeArtifact -ChangeId $ChangeId -Artifact ''Rollback'' -Root $ArtifactRoot -Content $rollbackScript'
        PostChange = '    $postchange = Write-BaselineChangeArtifact -ChangeId $ChangeId -Artifact ''PostChange'' -Root $ArtifactRoot -Content $after'
    }

    # Every fixture is a synthetic script written to $TestDrive and only ever parsed, never run.
    # Nothing here connects to a tenant, and the shipped script is never written to.
    function New-MutationPlanFixture {
        param([string]$Root, [string[]]$Line)

        $path = Join-Path $Root ('mutation-plan-{0}.ps1' -f [guid]::NewGuid().ToString('N'))
        $text = ($Line -join [System.Environment]::NewLine) + [System.Environment]::NewLine
        [System.IO.File]::WriteAllBytes($path, [System.Text.UTF8Encoding]::new($false).GetBytes($text))

        return $path
    }

    # A correctly shaped mutating run that emits only the artifacts named in -Emit. Building the
    # whole script from one template is what makes 'this artifact is missing' the single
    # difference between the omission cases, so a finding can only be blamed on the omission.
    function New-EmittingFixture {
        param([string]$Root, [string[]]$Emit)

        $line = [System.Collections.Generic.List[string]]::new()
        $line.AddRange([string[]]@(
                'param('
                '    [string]$ConfigurationPath,'
                '    [string]$PreviewPath,'
                '    [string]$ApprovalPath,'
                '    [string]$ChangeId,'
                '    [string]$ArtifactRoot,'
                '    [switch]$Apply'
                ')'
                ''
                'if ($Apply) {'
                '    $decision = Test-BaselineApplyPrerequisite -Apply -PreviewPath $PreviewPath -ApprovalPath $ApprovalPath -ArtifactRoot $ArtifactRoot'
                ''
                '    if (-not $decision.Permitted) {'
                '        throw (''ApplyRefused: {0}'' -f (@($decision.Finding) -join ''; ''))'
                '    }'
                ''
                '    $before = Get-TransportConfig'
                '    $rollbackScript = ''Set-TransportConfig -Identity ''''Default'''' -Confirm:$false'''
                ''
            ))

        if ('PreChange' -in $Emit) { $line.Add($script:EmissionLine['PreChange']) }
        $line.Add('    Set-TransportConfig -Identity ''Default'' -Confirm:$false')
        if ('Apply' -in $Emit) { $line.Add($script:EmissionLine['Apply']) }
        if ('Rollback' -in $Emit) { $line.Add($script:EmissionLine['Rollback']) }
        $line.Add('    $after = Get-TransportConfig')
        if ('PostChange' -in $Emit) { $line.Add($script:EmissionLine['PostChange']) }

        $line.Add('}')

        return New-MutationPlanFixture -Root $Root -Line $line
    }

    # One verdict covering all four artifacts at once: '<artifact>:<its NotEmitted code was
    # raised>' for each, in contract order. A test that only asserted its own artifact would pass
    # an analyzer that condemns all four every time, and a test that only asserted a count would
    # pass one that names the wrong artifact. The vector is what makes 'names exactly the missing
    # one' checkable in a single assertion.
    function Format-MutationPlanArtifact {
        param([object]$Node)

        $finding = @($Node['Finding'])

        return (@(
                $script:ChangeArtifact | ForEach-Object {
                    $code = 'MutationPlanArtifact{0}NotEmitted' -f $_
                    '{0}:{1}' -f $_, [bool](@($finding | Where-Object { $_ -like "$code*" }))
                }
            ) -join '|')
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

# The rule this partition pins down, and every fixture below exists to hold it in place:
#
#   A run that changes the tenant must emit all four of PreChange, Apply, Rollback and PostChange.
#   An artifact is emitted only when the mutation path actually writes it. A name held in a
#   variable, a name promised in a comment, and a write the mutation path can skip are all the
#   same thing to an auditor holding an empty directory, so each of them is 'never emitted'.
#   Each missing artifact is reported by its own code, because one generic 'an artifact is
#   missing' cannot tell an operator which evidence the change failed to leave.
Describe 'SAFE-007-A3 the shipped script emits every change artifact' {

    Context 'Negative: the run omits one of the four change artifacts' {

        It 'refuses a run that never emits the pre-change artifact' {
            # Arrange
            $path = New-EmittingFixture -Root $TestDrive -Emit @('Apply', 'Rollback', 'PostChange')

            # Act
            $plan = Test-BaselineDeploymentMutationPlan -ScriptPath $path

            # Assert
            (Format-MutationPlanArtifact -Node $plan) |
                Should -BeExactly 'PreChange:True|Apply:False|Rollback:False|PostChange:False' -Because 'a change with no record of the state it found cannot be shown to have changed only what it meant to, and naming the three artifacts that are present tells the operator nothing about the one that is not'
        }

        It 'refuses a run that never emits the apply artifact' {
            # Arrange
            $path = New-EmittingFixture -Root $TestDrive -Emit @('PreChange', 'Rollback', 'PostChange')

            # Act
            $plan = Test-BaselineDeploymentMutationPlan -ScriptPath $path

            # Assert
            (Format-MutationPlanArtifact -Node $plan) |
                Should -BeExactly 'PreChange:False|Apply:True|Rollback:False|PostChange:False' -Because 'a mutation that records no account of what it ran leaves the before and after states with nothing between them to explain the difference'
        }

        It 'refuses a run that never emits the rollback artifact' {
            # Arrange
            $path = New-EmittingFixture -Root $TestDrive -Emit @('PreChange', 'Apply', 'PostChange')

            # Act
            $plan = Test-BaselineDeploymentMutationPlan -ScriptPath $path

            # Assert
            (Format-MutationPlanArtifact -Node $plan) |
                Should -BeExactly 'PreChange:False|Apply:False|Rollback:True|PostChange:False' -Because 'a change nobody can undo is a change that has to be survived rather than reversed, and the rollback is the one artifact whose absence is only discovered when it is needed'
        }

        It 'refuses a run that never emits the post-change artifact' {
            # Arrange
            $path = New-EmittingFixture -Root $TestDrive -Emit @('PreChange', 'Apply', 'Rollback')

            # Act
            $plan = Test-BaselineDeploymentMutationPlan -ScriptPath $path

            # Assert
            (Format-MutationPlanArtifact -Node $plan) |
                Should -BeExactly 'PreChange:False|Apply:False|Rollback:False|PostChange:True' -Because 'a run that never records the state it left behind has asserted its own success, and an intended change and a confirmed one are not the same claim'
        }

        It 'names every missing artifact rather than stopping at the first' {
            # Arrange
            $path = New-EmittingFixture -Root $TestDrive -Emit @('PreChange', 'Apply')

            # Act
            $plan = Test-BaselineDeploymentMutationPlan -ScriptPath $path

            # Assert
            (Format-MutationPlanArtifact -Node $plan) |
                Should -BeExactly 'PreChange:False|Apply:False|Rollback:True|PostChange:True' -Because 'an operator who fixes one omission and is handed the next one is made to rediscover the same gap a run at a time, and a check that stops at the first miss hides how much evidence the change is actually short of'
        }
    }

    Context 'Negative: the artifact is spoken of but never written' {

        It 'refuses a run that only names the post-change artifact in a variable and a comment' {
            # Arrange
            $path = New-MutationPlanFixture -Root $TestDrive -Line @(
                'param('
                '    [string]$ChangeId,'
                '    [string]$ArtifactRoot,'
                '    [switch]$Apply'
                ')'
                ''
                '# The post-change artifact records the state this run leaves behind.'
                '$postChangeArtifact = ''PostChange'''
                '$postChangePath = Join-Path $ArtifactRoot (''postchange-{0}.json'' -f $ChangeId)'
                ''
                'if ($Apply) {'
                '    $before = Get-TransportConfig'
                $script:EmissionLine['PreChange']
                '    Set-TransportConfig -Identity ''Default'' -Confirm:$false'
                $script:EmissionLine['Apply']
                '    $rollbackScript = ''Set-TransportConfig -Identity ''''Default'''' -Confirm:$false'''
                $script:EmissionLine['Rollback']
                '    # TODO: emit the PostChange artifact to $postChangePath'
                '}'
            )

            # Act
            $plan = Test-BaselineDeploymentMutationPlan -ScriptPath $path

            # Assert
            (Format-MutationPlanArtifact -Node $plan) |
                Should -BeExactly 'PreChange:False|Apply:False|Rollback:False|PostChange:True' -Because 'a check that searches the script text for the artifact name is satisfied by a comment promising the write and by a variable holding the file name, and neither of those leaves a file behind for anyone to read'
        }
    }

    Context 'Negative: the artifact is written only on a path the mutation can skip' {

        It 'refuses a run whose only rollback emission sits behind an optional switch' {
            # Arrange
            $path = New-MutationPlanFixture -Root $TestDrive -Line @(
                'param('
                '    [string]$ChangeId,'
                '    [string]$ArtifactRoot,'
                '    [switch]$EmitRollback,'
                '    [switch]$Apply'
                ')'
                ''
                'if ($Apply) {'
                '    $before = Get-TransportConfig'
                '    $rollbackScript = ''Set-TransportConfig -Identity ''''Default'''' -Confirm:$false'''
                $script:EmissionLine['PreChange']
                '    Set-TransportConfig -Identity ''Default'' -Confirm:$false'
                $script:EmissionLine['Apply']
                ''
                '    if ($EmitRollback) {'
                '    ' + $script:EmissionLine['Rollback']
                '    }'
                ''
                '    $after = Get-TransportConfig'
                $script:EmissionLine['PostChange']
                '}'
            )

            # Act
            $plan = Test-BaselineDeploymentMutationPlan -ScriptPath $path

            # Assert
            (Format-MutationPlanArtifact -Node $plan) |
                Should -BeExactly 'PreChange:False|Apply:False|Rollback:True|PostChange:True' -Because 'the mutation runs whether or not that switch was passed, so a rollback the caller has to remember to ask for is a rollback the tenant is changed without, and the run reaching the end by a path that also skips the post-change record leaves the same hole twice'
        }

        It 'refuses a run whose only pre-change emission sits on the branch the refusal path skips' {
            # Arrange
            $path = New-MutationPlanFixture -Root $TestDrive -Line @(
                'param('
                '    [string]$PreviewPath,'
                '    [string]$ApprovalPath,'
                '    [string]$ChangeId,'
                '    [string]$ArtifactRoot,'
                '    [switch]$Apply'
                ')'
                ''
                'if ($Apply) {'
                '    $before = Get-TransportConfig'
                '    $rollbackScript = ''Set-TransportConfig -Identity ''''Default'''' -Confirm:$false'''
                '    $decision = Test-BaselineApplyPrerequisite -Apply -PreviewPath $PreviewPath -ApprovalPath $ApprovalPath -ArtifactRoot $ArtifactRoot'
                ''
                '    if ($decision.Permitted) {'
                '    ' + $script:EmissionLine['PreChange']
                '    }'
                '    else {'
                '        throw (''ApplyRefused: {0}'' -f (@($decision.Finding) -join ''; ''))'
                '    }'
                ''
                '    Set-TransportConfig -Identity ''Default'' -Confirm:$false'
                $script:EmissionLine['Apply']
                $script:EmissionLine['Rollback']
                '    $after = Get-TransportConfig'
                $script:EmissionLine['PostChange']
                '}'
            )

            # Act
            $plan = Test-BaselineDeploymentMutationPlan -ScriptPath $path

            # Assert
            (Format-MutationPlanArtifact -Node $plan) |
                Should -BeExactly 'PreChange:True|Apply:False|Rollback:False|PostChange:False' -Because 'a refused run is the run whose pre-change state an investigator most wants, and an emission reached only once the gate has said yes means the refusal leaves nothing at all behind'
        }
    }

    Context 'Negative: a complete run is condemned anyway' {

        It 'raises no missing-artifact finding against a run that emits all four' {
            # Arrange
            $path = New-EmittingFixture -Root $TestDrive -Emit $script:ChangeArtifact

            # Act
            $plan = Test-BaselineDeploymentMutationPlan -ScriptPath $path

            # Assert
            (Format-MutationPlanArtifact -Node $plan) |
                Should -BeExactly 'PreChange:False|Apply:False|Rollback:False|PostChange:False' -Because 'a check that reports all four artifacts missing whatever it is handed leaves no script anyone can write to satisfy it, and it would pass every omission case above for the wrong reason'
        }
    }
}
