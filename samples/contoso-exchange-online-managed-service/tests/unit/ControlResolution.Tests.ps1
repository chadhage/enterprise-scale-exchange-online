#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph and ExchangeOnlineManagement are not installed and must never be imported.
    # Nothing here reaches a service: the check reads two lists of command names and a declaration.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-ResolutionEntry {
        [CmdletBinding()]
        param(
            [string]$ControlId = 'EXO-002',
            [hashtable]$Override = @{},
            [string[]]$Remove = @()
        )

        $entry = [ordered]@{
            ControlId = $ControlId
            Collector = 'Get-ShippedEvidence'
            Evaluator = 'Test-ShippedControl'
        }

        foreach ($name in $Override.Keys) { $entry[$name] = $Override[$name] }
        foreach ($name in $Remove) { $entry.Remove($name) }

        return , $entry
    }

    function Get-ShippedCommandSurface {
        [CmdletBinding()]
        param()

        return , @((Get-Command -Module 'ExchangeOnlineBaseline.Common' -CommandType Function).Name)
    }

    function Get-DefinedCommandSurface {
        [CmdletBinding()]
        param()

        $parseError = $null
        $token = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:CommonModulePath, [ref]$token, [ref]$parseError)
        if ($parseError.Count -gt 0) {
            throw "the module did not parse: $($parseError[0].Message)"
        }

        $isFunction = { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }
        return , @($ast.FindAll($isFunction, $true) | ForEach-Object { $_.Name })
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EVD-006-A control registry resolution' {

    Context 'Negative: the check is held to a registry and to both command surfaces' {

        It 'refuses a resolution check over no registry' {
            # Arrange
            $noRegistry = $null

            # Act
            $result = { Test-BaselineControlResolution -Registry $noRegistry -ExportedCommand @('Get-ShippedEvidence') -DefinedCommand @('Get-ShippedEvidence') }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlRegistryRequired*' -Because 'a resolution check over no registry resolves nothing and reports that nothing is broken, which is exactly the report the four recorded bugs produced'
        }

        It 'refuses a resolution check over an empty registry' {
            # Arrange
            $emptyRegistry = @()

            # Act
            $result = { Test-BaselineControlResolution -Registry $emptyRegistry -ExportedCommand @('Get-ShippedEvidence') -DefinedCommand @('Get-ShippedEvidence') }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlRegistryRequired*' -Because 'an empty registry is satisfied by an empty module, so the guard would stay green while the solution shipped no control at all'
        }

        It 'refuses a registry entry that is not a record' {
            # Arrange
            $notARecord = @('EXO-002')

            # Act
            $result = { Test-BaselineControlResolution -Registry $notARecord -ExportedCommand @('Get-ShippedEvidence') -DefinedCommand @('Get-ShippedEvidence') }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlRegistryEntryNotRecognized*' -Because 'a bare identifier names no collector and no evaluator, so skipping it would quietly exempt it from the guard'
        }

        It 'refuses a registry entry that names no collector' {
            # Arrange
            $noCollector = New-ResolutionEntry -Remove 'Collector'

            # Act
            $result = { Test-BaselineControlResolution -Registry $noCollector -ExportedCommand @('Get-ShippedEvidence') -DefinedCommand @('Get-ShippedEvidence') }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlCollectorRequired*' -Because 'an entry naming no collector has nothing to resolve, and reporting it resolved is the same false clearance the guard exists to stop'
        }

        It 'refuses a registry entry that names no evaluator' {
            # Arrange
            $noEvaluator = New-ResolutionEntry -Override @{ Evaluator = '   ' }

            # Act
            $result = { Test-BaselineControlResolution -Registry $noEvaluator -ExportedCommand @('Get-ShippedEvidence') -DefinedCommand @('Get-ShippedEvidence') }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ControlEvaluatorRequired*' -Because 'whitespace names no evaluator any more than nothing does, and a control decided by nobody is a control that cannot fail'
        }

        It 'refuses a resolution check with no exported command surface' {
            # Arrange
            $noExported = $null

            # Act
            $result = { Test-BaselineControlResolution -Registry (New-ResolutionEntry) -ExportedCommand $noExported -DefinedCommand @('Get-ShippedEvidence') }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ExportedCommandSurfaceRequired*' -Because 'the exported surface is what the guard measures against, and an unsupplied surface would report every entry unresolved or every entry resolved depending only on which way the absence was read'
        }

        It 'refuses a resolution check with an empty exported command surface' {
            # Arrange
            $emptyExported = @()

            # Act
            $result = { Test-BaselineControlResolution -Registry (New-ResolutionEntry) -ExportedCommand $emptyExported -DefinedCommand @('Get-ShippedEvidence') }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ExportedCommandSurfaceRequired*' -Because 'a module that exports nothing is a module nobody could have run, so an empty surface is a broken measurement rather than a finding about the registry'
        }

        It 'refuses a resolution check with no defined command surface' {
            # Arrange
            $noDefined = $null

            # Act
            $result = { Test-BaselineControlResolution -Registry (New-ResolutionEntry) -ExportedCommand @('Get-ShippedEvidence') -DefinedCommand $noDefined }

            # Assert
            $result | Should -Throw -ExpectedMessage 'DefinedCommandSurfaceRequired*' -Because 'without the defined surface a function the module wrote and forgot to export is indistinguishable from one nobody has written, and those are two different defects'
        }

        It 'refuses a resolution check with an empty defined command surface' {
            # Arrange
            $emptyDefined = @()

            # Act
            $result = { Test-BaselineControlResolution -Registry (New-ResolutionEntry) -ExportedCommand @('Get-ShippedEvidence') -DefinedCommand $emptyDefined }

            # Assert
            $result | Should -Throw -ExpectedMessage 'DefinedCommandSurfaceRequired*' -Because 'a module file that defines no function cannot be the file the exported surface came from, so the measurement is wrong before any entry is read'
        }
    }

    Context 'Negative: a half-shipped entry is never reported resolved' {

        It 'refuses to report an entry resolved when its collector is absent and its evaluator is exported' {
            # Arrange
            $halfShipped = New-ResolutionEntry -ControlId 'MDO-005' -Override @{ Collector = 'Get-SafeDocumentsEvidence'; Evaluator = 'Test-ShippedControl' }

            # Act
            $result = Test-BaselineControlResolution -Registry $halfShipped -ExportedCommand @('Test-ShippedControl') -DefinedCommand @('Test-ShippedControl')

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a control that is decided but never collected reaches its evaluator with nothing, which is the shape of the recorded MDO-005 bug'
        }

        It 'refuses to report an entry resolved when its evaluator is absent and its collector is exported' {
            # Arrange
            $halfShipped = New-ResolutionEntry -ControlId 'MDO-005' -Override @{ Collector = 'Get-ShippedEvidence'; Evaluator = 'Test-SafeDocumentsControl' }

            # Act
            $result = Test-BaselineControlResolution -Registry $halfShipped -ExportedCommand @('Get-ShippedEvidence') -DefinedCommand @('Get-ShippedEvidence')

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'MDO-005 was collected every run and decided by nobody, and only that control own card noticed'
        }

        It 'names the control, the member and the command of a half-shipped entry' {
            # Arrange
            $halfShipped = New-ResolutionEntry -ControlId 'MDO-005' -Override @{ Collector = 'Get-ShippedEvidence'; Evaluator = 'Test-SafeDocumentsControl' }

            # Act
            $result = Test-BaselineControlResolution -Registry $halfShipped -ExportedCommand @('Get-ShippedEvidence') -DefinedCommand @('Get-ShippedEvidence')

            # Assert
            @($result.Unresolved) -join '; ' | Should -BeLike "*MDO-005*Evaluator*Test-SafeDocumentsControl*" -Because 'a guard that says only that something is wrong across forty-three entries costs more to act on than the bug it found'
        }
    }

    Context 'Negative: a command the module defines and never exports is never reported resolved' {

        It 'refuses to report an entry resolved when its collector is defined but unexported' {
            # Arrange
            $unexported = New-ResolutionEntry -ControlId 'MDO-005' -Override @{ Collector = 'Get-SafeDocumentsEvidence'; Evaluator = 'Test-ShippedControl' }

            # Act
            $result = Test-BaselineControlResolution -Registry $unexported -ExportedCommand @('Test-ShippedControl') -DefinedCommand @('Get-SafeDocumentsEvidence', 'Test-ShippedControl')

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'a collector the module defines but the export list omits is unreachable from outside, which is exactly how Get-SafeDocumentsEvidence shipped'
        }

        It 'refuses to report an entry resolved when its evaluator is defined but unexported' {
            # Arrange
            $unexported = New-ResolutionEntry -ControlId 'EXO-002' -Override @{ Collector = 'Get-ShippedEvidence'; Evaluator = 'Test-SmtpAuthenticationControl' }

            # Act
            $result = Test-BaselineControlResolution -Registry $unexported -ExportedCommand @('Get-ShippedEvidence') -DefinedCommand @('Get-ShippedEvidence', 'Test-SmtpAuthenticationControl')

            # Assert
            $result.Satisfied | Should -BeFalse -Because 'an evaluator written, reviewed and left out of Export-ModuleMember looks finished in the file and is absent at runtime'
        }

        It 'names the control, the member and the command of an unexported entry' {
            # Arrange
            $unexported = New-ResolutionEntry -ControlId 'EXO-002' -Override @{ Collector = 'Get-ShippedEvidence'; Evaluator = 'Test-SmtpAuthenticationControl' }

            # Act
            $result = Test-BaselineControlResolution -Registry $unexported -ExportedCommand @('Get-ShippedEvidence') -DefinedCommand @('Get-ShippedEvidence', 'Test-SmtpAuthenticationControl')

            # Assert
            @($result.Unexported) -join '; ' | Should -BeLike "*EXO-002*Evaluator*Test-SmtpAuthenticationControl*" -Because 'the fix for this defect is one line in one list, so the report must say which line'
        }

        It 'reports an unexported command as unexported rather than as merely absent' {
            # Arrange
            $unexported = New-ResolutionEntry -ControlId 'EXO-002' -Override @{ Collector = 'Get-ShippedEvidence'; Evaluator = 'Test-SmtpAuthenticationControl' }

            # Act
            $result = Test-BaselineControlResolution -Registry $unexported -ExportedCommand @('Get-ShippedEvidence') -DefinedCommand @('Get-ShippedEvidence', 'Test-SmtpAuthenticationControl')

            # Assert
            @($result.Unresolved).Count | Should -Be 0 -Because 'an unexported function is one line from working and an unwritten one is a card of work, and folding them together sends the reader to the wrong job'
        }
    }

    Context 'Negative: the guard reports only what is actually broken' {

        It 'does not report an entry whose collector and evaluator are both absent as drift' {
            # Arrange
            $unbuilt = New-ResolutionEntry -ControlId 'GOV-007' -Override @{ Collector = 'Get-EDiscoveryReadinessEvidence'; Evaluator = 'Test-EDiscoveryReadinessControl' }

            # Act
            $result = Test-BaselineControlResolution -Registry $unbuilt -ExportedCommand @('Get-ShippedEvidence') -DefinedCommand @('Get-ShippedEvidence')

            # Assert
            $result.Satisfied | Should -BeTrue -Because 'a catalog control nobody has started is backlog the board already tracks, and a guard that is red for unstarted work is a guard everybody learns to ignore'
        }

        It 'reports an entry whose collector and evaluator are both absent as unbuilt' {
            # Arrange
            $unbuilt = New-ResolutionEntry -ControlId 'GOV-007' -Override @{ Collector = 'Get-EDiscoveryReadinessEvidence'; Evaluator = 'Test-EDiscoveryReadinessControl' }

            # Act
            $result = Test-BaselineControlResolution -Registry $unbuilt -ExportedCommand @('Get-ShippedEvidence') -DefinedCommand @('Get-ShippedEvidence')

            # Assert
            @($result.Unbuilt) | Should -Contain 'GOV-007' -Because 'tolerating an unstarted control silently is how twenty-six of them stopped being visible in the first place'
        }

        It 'does not treat a declared command differing only in casing or whitespace as unresolved' {
            # Arrange
            $reformatted = New-ResolutionEntry -ControlId 'EXO-002' -Override @{ Collector = '  get-shippedevidence '; Evaluator = 'TEST-SHIPPEDCONTROL' }

            # Act
            $result = Test-BaselineControlResolution -Registry $reformatted -ExportedCommand @('Get-ShippedEvidence', 'Test-ShippedControl') -DefinedCommand @('Get-ShippedEvidence', 'Test-ShippedControl')

            # Assert
            $result.Satisfied | Should -BeTrue -Because 'PowerShell resolves a command name case-insensitively, so a guard stricter than the runtime reports a defect the runtime does not have'
        }
    }

    Context 'Negative: the result cannot be edited after it is taken' {

        It 'rejects assignment to an existing member' {
            # Arrange
            $result = Test-BaselineControlResolution -Registry (New-ResolutionEntry) -ExportedCommand @('Get-ShippedEvidence', 'Test-ShippedControl') -DefinedCommand @('Get-ShippedEvidence', 'Test-ShippedControl')

            # Act
            $act = { $result.Satisfied = $true }

            # Assert
            $act | Should -Throw -Because 'a guard whose verdict the caller can overwrite is a guard that clears whatever the caller wanted cleared'
        }

        It 'rejects assignment of a new member' {
            # Arrange
            $result = Test-BaselineControlResolution -Registry (New-ResolutionEntry) -ExportedCommand @('Get-ShippedEvidence', 'Test-ShippedControl') -DefinedCommand @('Get-ShippedEvidence', 'Test-ShippedControl')

            # Act
            $act = { $result.Waived = $true }

            # Assert
            $act | Should -Throw -Because 'a member added after the check is a claim the check never made'
        }
    }

    Context 'Positive: the shipped registry resolves against the shipped command surface' {

        It 'resolves every registered control with no half-shipped and no unexported entry' {
            # Arrange
            $registry = Get-BaselineControlRegistry
            $exported = Get-ShippedCommandSurface
            $defined = Get-DefinedCommandSurface

            # Act
            $result = Test-BaselineControlResolution -Registry $registry -ExportedCommand $exported -DefinedCommand $defined

            # Assert
            ('{0}|{1}|{2}' -f $result.Satisfied, (@($result.Unresolved) -join ', '), (@($result.Unexported) -join ', ')) |
                Should -BeExactly 'True||' -Because 'every control the registry declares must be collected and decided by a command the module actually hands out, or it is registered and never runs'
        }
    }
}
