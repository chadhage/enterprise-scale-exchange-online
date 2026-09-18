#requires -Version 7.0

# Discovery-scope copies so the per-case negatives can be expanded by -ForEach.
$BlankValue = @(
    @{ Case = 'null'; Value = $null }
    @{ Case = 'empty'; Value = '' }
    @{ Case = 'whitespace'; Value = '   ' }
)

$RequiredOperationMember = @('OperationId', 'Command', 'Identity', 'Before', 'After')
$RequiredStateMember = @('Exists', 'Value')
$PreviewMember = @(
    'SchemaVersion', 'ChangeId', 'Tenant', 'DeploymentProfile', 'ConfigurationAlgorithm',
    'ConfigurationHash', 'Operation', 'GeneratedOn', 'ExpiresOn', 'ToolVersion'
)

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'
    $script:ManifestPath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psd1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:ChangeId = 'CHG0012345'
    $script:Tenant = 'contoso.onmicrosoft.com'
    $script:GeneratedOn = [datetime]::new(2026, 9, 18, 7, 30, 0, [System.DateTimeKind]::Utc)

    $script:Context = [pscustomobject]@{
        DeploymentProfile = 'ThirdPartyGateway'
        Algorithm         = 'SHA256'
        Hash              = 'a3f1c0de5b7288119ce2a6d4f0b9e7a15d3c48b6720fe9134a8c5d6e7f809123'
    }

    function New-Operation {
        param(
            [string]$OperationId = 'op-1',
            [string]$Command = 'Set-TransportConfig',
            [string]$Identity = 'Default',
            [object[]]$DependsOn = @()
        )

        return [ordered]@{
            OperationId = $OperationId
            Command     = $Command
            Identity    = $Identity
            Before      = [ordered]@{ Exists = $true; Value = [ordered]@{ SmtpClientAuthenticationDisabled = $false } }
            After       = [ordered]@{ Exists = $true; Value = [ordered]@{ SmtpClientAuthenticationDisabled = $true } }
            DependsOn   = $DependsOn
        }
    }

    $script:Operation = @(
        (New-Operation -OperationId 'op-connector' -Command 'New-InboundConnector' -Identity 'Contoso Gateway Inbound')
        (New-Operation -OperationId 'op-transport' -Command 'Set-TransportConfig' -Identity 'Default' -DependsOn @('op-connector'))
    )

    $script:Build = {
        param([hashtable]$Override = @{})

        $argument = @{
            ChangeId    = $script:ChangeId
            Tenant      = $script:Tenant
            Context     = $script:Context
            Operation   = $script:Operation
            GeneratedOn = $script:GeneratedOn
        }
        foreach ($name in $Override.Keys) { $argument[$name] = $Override[$name] }

        New-BaselineChangePreview @argument
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'SAFE-002-A change preview' {

    Context 'Negative: a preview the caller did not fully describe' {

        It 'refuses a change identifier that is <Case>' -ForEach $BlankValue {
            # Arrange
            $override = @{ ChangeId = $Value }

            # Act
            $act = { & $script:Build $override }

            # Assert
            $act | Should -Throw -Because 'a preview that names no change cannot be matched to the approval that authorised it'
        }

        It 'refuses a tenant that is <Case>' -ForEach $BlankValue {
            # Arrange
            $override = @{ Tenant = $Value }

            # Act
            $act = { & $script:Build $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangePreviewTenantNotSupplied*' -Because 'a plan that does not say which tenant it changes can be approved for one tenant and applied to another'
        }

        It 'refuses a null configuration context' {
            # Arrange
            $override = @{ Context = $null }

            # Act
            $act = { & $script:Build $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangePreviewContextNotRecognized*' -Because 'a preview built from no resolved configuration describes no desired state at all'
        }

        It 'refuses a context carrying no configuration hash' {
            # Arrange
            $override = @{ Context = [pscustomobject]@{ DeploymentProfile = 'MicrosoftNative'; Algorithm = 'SHA256' } }

            # Act
            $act = { & $script:Build $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangePreviewContextNotRecognized*' -Because 'a preview with no configuration identity cannot be held to the desired state it was built from'
        }

        It 'refuses a context carrying no deployment profile' {
            # Arrange
            $override = @{ Context = [pscustomobject]@{ Algorithm = 'SHA256'; Hash = $script:Context.Hash } }

            # Act
            $act = { & $script:Build $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangePreviewContextNotRecognized*' -Because 'a gateway plan approved as a Microsoft-native plan is a different change from the one that was reviewed'
        }

        It 'refuses a preview carrying no operation at all' {
            # Arrange
            $override = @{ Operation = @() }

            # Act
            $act = { & $script:Build $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangePreviewOperationNotSupplied*' -Because 'an empty plan approves every mutation the run later invents'
        }

        It 'refuses a generation time that was never supplied' {
            # Arrange
            $override = @{ GeneratedOn = $null }

            # Act
            $act = { & $script:Build $override }

            # Assert
            $act | Should -Throw -Because 'a plan with no timestamp never expires'
        }
    }

    Context 'Negative: an operation the preview cannot describe' {

        It 'refuses an operation carrying no <_>' -ForEach $RequiredOperationMember {
            # Arrange
            $incomplete = New-Operation
            $incomplete.Remove($_)

            # Act
            $act = { & $script:Build @{ Operation = @($incomplete) } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangePreviewOperationNotRecognized*' -Because 'an operation missing part of its description is an operation nobody can review'
        }

        It 'refuses a before state carrying no <_>' -ForEach $RequiredStateMember {
            # Arrange
            $incomplete = New-Operation
            $incomplete.Before.Remove($_)

            # Act
            $act = { & $script:Build @{ Operation = @($incomplete) } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangePreviewStateNotRecognized*' -Because 'a before state that does not say whether the object existed and what it held cannot be restored'
        }

        It 'refuses an after state carrying no <_>' -ForEach $RequiredStateMember {
            # Arrange
            $incomplete = New-Operation
            $incomplete.After.Remove($_)

            # Act
            $act = { & $script:Build @{ Operation = @($incomplete) } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangePreviewStateNotRecognized*' -Because 'an after state nobody stated is a change nobody approved'
        }

        It 'refuses two operations sharing one operation identifier' {
            # Arrange
            $duplicate = @((New-Operation -OperationId 'op-1'), (New-Operation -OperationId 'op-1' -Command 'Set-RemoteDomain'))

            # Act
            $act = { & $script:Build @{ Operation = $duplicate } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangePreviewOperationNotUnique*' -Because 'two operations under one name make every dependency on that name ambiguous'
        }

        It 'refuses an operation that depends on itself' {
            # Arrange
            $circular = @(New-Operation -OperationId 'op-1' -DependsOn @('op-1'))

            # Act
            $act = { & $script:Build @{ Operation = $circular } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangePreviewDependencyNotResolvable*' -Because 'an operation waiting on itself is an operation that never runs'
        }

        It 'refuses an operation that depends on an operation the preview does not carry' {
            # Arrange
            $dangling = @(New-Operation -OperationId 'op-1' -DependsOn @('op-absent'))

            # Act
            $act = { & $script:Build @{ Operation = $dangling } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangePreviewDependencyNotResolvable*' -Because 'a dependency on a mutation that is not in the plan is a mutation nobody approved'
        }

        It 'refuses an operation that depends on an operation declared after it' {
            # Arrange
            $outOfOrder = @(
                (New-Operation -OperationId 'op-1' -DependsOn @('op-2'))
                (New-Operation -OperationId 'op-2')
            )

            # Act
            $act = { & $script:Build @{ Operation = $outOfOrder } }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangePreviewDependencyNotResolvable*' -Because 'an operation that runs before the one it depends on applies to an object that does not exist yet'
        }
    }

    Context 'Negative: the preview does not carry what it was built from' {

        It 'carries every member the preview contract declares' {
            # Arrange
            $expected = $PreviewMember

            # Act
            $preview = & $script:Build

            # Assert
            (@($expected | Where-Object { -not $preview.ContainsKey($_) }) -join ',') |
                Should -BeExactly '' -Because 'a preview missing a member is a plan the approver was never shown'
        }

        It 'carries the tenant, profile, algorithm and hash the context resolved' {
            # Arrange
            $expected = '{0}|{1}|{2}|{3}' -f $script:Tenant, $script:Context.DeploymentProfile, $script:Context.Algorithm, $script:Context.Hash

            # Act
            $preview = & $script:Build

            # Assert
            '{0}|{1}|{2}|{3}' -f $preview['Tenant'], $preview['DeploymentProfile'], $preview['ConfigurationAlgorithm'], $preview['ConfigurationHash'] |
                Should -BeExactly $expected -Because 'a preview that restates the configuration in its own words can be approved against a state that was never resolved'
        }

        It 'carries every operation in the order it was declared' {
            # Arrange
            $expected = (@($script:Operation | ForEach-Object { [string]$_.OperationId }) -join ',')

            # Act
            $preview = & $script:Build

            # Assert
            (@($preview['Operation'] | ForEach-Object { [string]$_['OperationId'] }) -join ',') |
                Should -BeExactly $expected -Because 'operations reordered by the preview describe a change that never happens in that order'
        }

        It 'carries the before and after value of every operation' {
            # Arrange
            $expected = 'False|True'

            # Act
            $preview = & $script:Build

            # Assert
            '{0}|{1}' -f $preview['Operation'][1]['Before']['Value']['SmtpClientAuthenticationDisabled'], $preview['Operation'][1]['After']['Value']['SmtpClientAuthenticationDisabled'] |
                Should -BeExactly $expected -Because 'a plan that does not say what the value is now cannot be reviewed and cannot be reversed'
        }

        It 'carries the declared dependency of every operation' {
            # Arrange
            $expected = 'op-connector'

            # Act
            $preview = & $script:Build

            # Assert
            (@($preview['Operation'][1]['DependsOn']) -join ',') |
                Should -BeExactly $expected -Because 'a plan that drops the ordering between its operations is a plan that can be applied in any order'
        }

        It 'carries the tool version the shipped manifest declares' {
            # Arrange
            $expected = [string](Import-PowerShellDataFile -LiteralPath $script:ManifestPath).ModuleVersion

            # Act
            $preview = & $script:Build

            # Assert
            [string]$preview['ToolVersion'] | Should -BeExactly $expected -Because 'a plan that does not say which build produced it cannot be reproduced when it is questioned'
        }

        It 'carries the schema version the artifact version contract declares for a preview' {
            # Arrange
            $expected = [string](@((Get-ArtifactVersionContract).Artifact) | Where-Object { [string]$_.Artifact -eq 'Preview' }).SchemaVersion

            # Act
            $preview = & $script:Build

            # Assert
            [string]$preview['SchemaVersion'] | Should -BeExactly $expected -Because 'a preview versioned independently of its own contract cannot be read by the approval that quotes it'
        }
    }

    Context 'Negative: the preview does not bound its own validity' {

        It 'records the generation time as a round-trip UTC instant' {
            # Arrange
            $expected = $script:GeneratedOn.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)

            # Act
            $preview = & $script:Build

            # Assert
            [string]$preview['GeneratedOn'] | Should -BeExactly $expected -Because 'a timestamp written in the operator local time is a different instant to every reader of it'
        }

        It 'records an expiry strictly after the generation time' {
            # Arrange
            $generated = $script:GeneratedOn

            # Act
            $preview = & $script:Build

            # Assert
            ([datetime]::Parse([string]$preview['ExpiresOn'], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)) |
                Should -BeGreaterThan $generated -Because 'a plan that expires when it was written can never be applied, and one that never expires can be applied forever'
        }

        It 'refuses a validity period that expires no later than the generation time' {
            # Arrange
            $override = @{ ValidFor = [timespan]::Zero }

            # Act
            $act = { & $script:Build $override }

            # Assert
            $act | Should -Throw -ExpectedMessage 'ChangePreviewValidityNotUsable*' -Because 'an approval window of no width is an approval nobody can act inside'
        }

        It 'records the expiry as the generation time plus the validity period it was given' {
            # Arrange
            $validFor = [timespan]::FromHours(4)

            # Act
            $preview = & $script:Build @{ ValidFor = $validFor }

            # Assert
            [string]$preview['ExpiresOn'] |
                Should -BeExactly ($script:GeneratedOn.Add($validFor).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)) -Because 'an expiry the builder chose for itself is a window nobody agreed to'
        }
    }

    Context 'Negative: the preview is not stable or not fixed' {

        It 'builds one preview from one set of inputs' {
            # Arrange
            $build = $script:Build

            # Act
            $distinct = @(1, 2 | ForEach-Object { ConvertTo-CanonicalJson -InputObject (& $build) } | Select-Object -Unique)

            # Assert
            $distinct.Count | Should -Be 1 -Because 'two previews of one change that disagree cannot both be the plan that was approved'
        }

        It 'refuses assignment to the preview hash' {
            # Arrange
            $preview = & $script:Build

            # Act
            $act = { $preview['ConfigurationHash'] = '0' }

            # Assert
            $act | Should -Throw -Because 'a plan a caller can rewrite after approval is a plan that approves whatever the caller wanted'
        }

        It 'refuses assignment to an operation in the preview' {
            # Arrange
            $preview = & $script:Build

            # Act
            $act = { $preview['Operation'][0] = $null }

            # Assert
            $act | Should -Throw -Because 'an operation a caller can drop after approval is a mutation the approver never saw removed'
        }
    }

    Context 'Positive: one complete preview describes the whole change' {

        It 'carries tenant, profile, hash, every operation with before and after values and dependencies, timestamp, expiry and tool version' {
            # Arrange
            $expected = @(
                $script:Tenant
                'ThirdPartyGateway'
                'SHA256'
                $script:Context.Hash
                'op-connector:New-InboundConnector:Contoso Gateway Inbound:False:True:'
                'op-transport:Set-TransportConfig:Default:False:True:op-connector'
                $script:GeneratedOn.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                $script:GeneratedOn.AddHours(24).ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                [string](Import-PowerShellDataFile -LiteralPath $script:ManifestPath).ModuleVersion
            ) -join '|'

            # Act
            $preview = & $script:Build

            # Assert
            (@(
                [string]$preview['Tenant']
                [string]$preview['DeploymentProfile']
                [string]$preview['ConfigurationAlgorithm']
                [string]$preview['ConfigurationHash']
                (@($preview['Operation'] | ForEach-Object {
                    '{0}:{1}:{2}:{3}:{4}:{5}' -f $_['OperationId'], $_['Command'], $_['Identity'],
                        $_['Before']['Value']['SmtpClientAuthenticationDisabled'],
                        $_['After']['Value']['SmtpClientAuthenticationDisabled'],
                        (@($_['DependsOn']) -join ';')
                }))
                [string]$preview['GeneratedOn']
                [string]$preview['ExpiresOn']
                [string]$preview['ToolVersion']
            ) -join '|') | Should -BeExactly $expected -Because 'a plan that cannot state all of that is a plan no approver can hold the run to'
        }
    }
}
