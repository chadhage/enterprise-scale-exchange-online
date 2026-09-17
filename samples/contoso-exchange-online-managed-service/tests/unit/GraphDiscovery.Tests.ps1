#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph is not installed and must never be imported. Every response is canned and the
    # retry delay is handed to an injected wait, so a throttled resource is exercised without any
    # test sleeping.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:UserResource = 'users'
    $script:UserPageTwoLink = 'https://graph.microsoft.com/v1.0/users?$skiptoken=page2'
    $script:GroupResource = 'groups'
    $script:DomainResource = 'domains'

    function New-GraphPage {
        [CmdletBinding()]
        param(
            [int]$Status = 200,
            [object[]]$Value,
            [string]$NextLink,
            [object]$RetryAfterSeconds
        )

        $page = [ordered]@{ status = $Status }
        if ($PSBoundParameters.ContainsKey('Value')) { $page['value'] = @($Value) }
        if ($PSBoundParameters.ContainsKey('NextLink')) { $page['@odata.nextLink'] = $NextLink }
        if ($PSBoundParameters.ContainsKey('RetryAfterSeconds')) { $page['retryAfterSeconds'] = $RetryAfterSeconds }

        return [pscustomobject]$page
    }

    # A transport keyed by the exact URI it is asked for. A URI mapped to several responses replays
    # them in order, so a resource can be throttled once and then answer, and every URI the
    # discovery asks for is recorded.
    function New-ResourceTransport {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [hashtable]$ResponseByUri,

            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [System.Collections.Generic.List[string]]$RequestLog
        )

        $map = $ResponseByUri
        $log = $RequestLog
        $cursor = @{}
        return {
            param($Uri)

            $key = [string]$Uri
            $log.Add($key)

            if (-not $map.ContainsKey($key)) { throw "FixtureMissingResponse: no canned response for '$key'." }

            $answer = @($map[$key])
            $index = if ($cursor.ContainsKey($key)) { $cursor[$key] } else { 0 }
            $cursor[$key] = [Math]::Min($index + 1, $answer.Count - 1)

            return $answer[[Math]::Min($index, $answer.Count - 1)]
        }.GetNewClosure()
    }

    function New-RecordingWait {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [System.Collections.Generic.List[object]]$WaitLog
        )

        $log = $WaitLog
        return {
            param($Second)

            $log.Add($Second)
        }.GetNewClosure()
    }

    # The shipped partial-failure scenario: one resource pages, one is throttled and then answers,
    # one is permanently refused.
    function New-MixedOutcomeTransport {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [System.Collections.Generic.List[string]]$RequestLog,

            [int]$DomainStatus = 404
        )

        return New-ResourceTransport -RequestLog $RequestLog -ResponseByUri @{
            $script:UserResource    = @((New-GraphPage -Value @('alice', 'bob') -NextLink $script:UserPageTwoLink))
            $script:UserPageTwoLink = @((New-GraphPage -Value @('carol')))
            $script:GroupResource   = @((New-GraphPage -Status 429 -RetryAfterSeconds 2), (New-GraphPage -Value @('sales')))
            $script:DomainResource  = @((New-GraphPage -Status $DomainStatus))
        }
    }

    function New-SinglePageTransport {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [System.Collections.Generic.List[string]]$RequestLog
        )

        return New-ResourceTransport -RequestLog $RequestLog -ResponseByUri @{
            $script:UserResource   = @((New-GraphPage -Value @('alice')))
            $script:GroupResource  = @((New-GraphPage -Value @('sales')))
            $script:DomainResource = @((New-GraphPage -Value @('contoso.example')))
        }
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'LIC-004-A2 deterministic partial-failure Graph discovery' {

    BeforeEach {
        $script:RequestLog = [System.Collections.Generic.List[string]]::new()
        $script:WaitLog = [System.Collections.Generic.List[object]]::new()
        $script:Wait = New-RecordingWait -WaitLog $script:WaitLog
        $script:MixedTransport = New-MixedOutcomeTransport -RequestLog $script:RequestLog
        $script:RequestedResource = @($script:UserResource, $script:GroupResource, $script:DomainResource)
    }

    Context 'Negative: the discovery inputs must be usable' {

        It 'refuses a discovery with no resource' {
            # Arrange
            $transport = $script:MixedTransport

            # Act
            $discover = { Get-BaselineGraphDiscovery -Resource @() -Transport $transport -Wait $script:Wait }

            # Assert
            $discover | Should -Throw -ExpectedMessage 'GraphResourceRequired*' -Because 'a discovery that reads nothing must never be reported as a complete inventory'
        }

        It 'refuses a blank resource' {
            # Arrange
            $transport = $script:MixedTransport

            # Act
            $discover = { Get-BaselineGraphDiscovery -Resource @($script:UserResource, '   ') -Transport $transport -Wait $script:Wait }

            # Assert
            $discover | Should -Throw -ExpectedMessage 'GraphResourceRequired*' -Because 'a blank resource addresses nothing and must not be silently skipped'
        }

        It 'refuses a duplicated resource' {
            # Arrange
            $transport = $script:MixedTransport

            # Act
            $discover = { Get-BaselineGraphDiscovery -Resource @($script:UserResource, $script:UserResource) -Transport $transport -Wait $script:Wait }

            # Assert
            $discover | Should -Throw -ExpectedMessage 'GraphResourceDuplicated*' -Because 'reading one resource twice doubles its items and makes the result depend on the request order'
        }

        It 'refuses a discovery without a transport' {
            # Arrange
            $absentTransport = $null

            # Act
            $discover = { Get-BaselineGraphDiscovery -Resource $script:RequestedResource -Transport $absentTransport -Wait $script:Wait }

            # Assert
            $discover | Should -Throw -ExpectedMessage 'GraphTransportRequired*' -Because 'a discovery with nowhere to send itself has not discovered an empty tenant'
        }

        It 'refuses a discovery without an injected wait' {
            # Arrange
            $transport = $script:MixedTransport

            # Act
            $discover = { Get-BaselineGraphDiscovery -Resource $script:RequestedResource -Transport $transport -Wait $null }

            # Assert
            $discover | Should -Throw -ExpectedMessage 'RetryWaitRequired*' -Because 'retry needs a clock, and the clock is injected before any resource is read'
        }

        It 'refuses a discovery it cannot retry within a usable attempt budget' {
            # Arrange
            $transport = $script:MixedTransport

            # Act
            $discover = { Get-BaselineGraphDiscovery -Resource $script:RequestedResource -Transport $transport -Wait $script:Wait -MaximumAttempt 0 }

            # Assert
            $discover | Should -Throw -ExpectedMessage 'MaximumAttemptOutOfRange*' -Because 'a resource that is never attempted is not a resource that answered'
        }
    }

    Context 'Negative: a failure is recorded, never absorbed' {

        It 'does not report the discovery complete when a resource failed' {
            # Arrange
            $transport = $script:MixedTransport

            # Act
            $discovery = Get-BaselineGraphDiscovery -Resource $script:RequestedResource -Transport $transport -Wait $script:Wait

            # Assert
            $discovery.Complete | Should -BeFalse -Because 'an inventory missing a resource is not the whole inventory'
        }

        It 'does not drop the resource that failed' {
            # Arrange
            $transport = $script:MixedTransport

            # Act
            $discovery = Get-BaselineGraphDiscovery -Resource $script:RequestedResource -Transport $transport -Wait $script:Wait

            # Assert
            @($discovery.Failed).Count | Should -Be 1 -Because 'a failure that is not recorded cannot be acted on'
        }

        It 'names the resource that failed' {
            # Arrange
            $transport = $script:MixedTransport

            # Act
            $discovery = Get-BaselineGraphDiscovery -Resource $script:RequestedResource -Transport $transport -Wait $script:Wait

            # Assert
            @($discovery.Failed | ForEach-Object { $_.Resource }) | Should -Be @($script:DomainResource) -Because 'the operator must be told which resource is missing, not merely that something is'
        }

        It 'names the reason the resource failed' {
            # Arrange
            $transport = $script:MixedTransport

            # Act
            $discovery = Get-BaselineGraphDiscovery -Resource $script:RequestedResource -Transport $transport -Wait $script:Wait

            # Assert
            @($discovery.Failed)[0].Reason | Should -BeLike 'GraphResourceNotFound*' -Because 'a recorded failure without its reason cannot be triaged'
        }

        It 'does not report the failed resource as succeeded' {
            # Arrange
            $transport = $script:MixedTransport

            # Act
            $discovery = Get-BaselineGraphDiscovery -Resource $script:RequestedResource -Transport $transport -Wait $script:Wait

            # Assert
            @($discovery.Succeeded | ForEach-Object { $_.Resource }) | Should -Not -Contain $script:DomainResource -Because 'a resource that was refused returned no items and must not appear to have returned none'
        }

        It 'does not discard the resources that did succeed' {
            # Arrange
            $transport = $script:MixedTransport

            # Act
            $discovery = Get-BaselineGraphDiscovery -Resource $script:RequestedResource -Transport $transport -Wait $script:Wait

            # Assert
            @($discovery.Succeeded).Count | Should -Be 2 -Because 'one unreadable resource must not throw away the inventory that was read'
        }

        It 'does not report any success when every resource failed' {
            # Arrange
            $transport = New-ResourceTransport -RequestLog $script:RequestLog -ResponseByUri @{
                $script:UserResource  = @((New-GraphPage -Status 404))
                $script:GroupResource = @((New-GraphPage -Status 404))
            }

            # Act
            $discovery = Get-BaselineGraphDiscovery -Resource @($script:UserResource, $script:GroupResource) -Transport $transport -Wait $script:Wait

            # Assert
            @($discovery.Succeeded) | Should -BeNullOrEmpty -Because 'a discovery in which nothing answered has discovered nothing'
        }

        It 'does not record a resource as failed when it was merely throttled and then answered' {
            # Arrange
            $transport = New-ResourceTransport -RequestLog $script:RequestLog -ResponseByUri @{
                $script:GroupResource = @((New-GraphPage -Status 429 -RetryAfterSeconds 2), (New-GraphPage -Value @('sales')))
            }

            # Act
            $discovery = Get-BaselineGraphDiscovery -Resource @($script:GroupResource) -Transport $transport -Wait $script:Wait

            # Assert
            @($discovery.Failed) | Should -BeNullOrEmpty -Because 'a throttle that cleared is a delay, not a gap in the inventory'
        }
    }

    Context 'Negative: an authorization failure is not a partial failure' {

        It 'aborts the discovery rather than recording it' -ForEach @(
            @{ Status = 401; Expected = 'GraphRequestUnauthorized*' }
            @{ Status = 403; Expected = 'GraphRequestForbidden*' }
        ) {
            # Arrange
            $transport = New-MixedOutcomeTransport -RequestLog $script:RequestLog -DomainStatus $Status

            # Act
            $discover = { Get-BaselineGraphDiscovery -Resource $script:RequestedResource -Transport $transport -Wait $script:Wait }

            # Assert
            $discover | Should -Throw -ExpectedMessage $Expected -Because "status $Status refuses the caller, not the resource, so every other resource would be refused too and the partial result would be read as a licensing gap"
        }
    }

    Context 'Negative: the discovery is deterministic' {

        It 'does not read a resource more than once' {
            # Arrange
            $transport = New-SinglePageTransport -RequestLog $script:RequestLog

            # Act
            $null = Get-BaselineGraphDiscovery -Resource $script:RequestedResource -Transport $transport -Wait $script:Wait

            # Assert
            @($script:RequestLog) | Should -Be @($script:UserResource, $script:GroupResource, $script:DomainResource) -Because 'each resource is read once, in the order it was asked for'
        }

        It 'does not return the succeeded resources in an order other than the requested order' {
            # Arrange
            $transport = New-SinglePageTransport -RequestLog $script:RequestLog

            # Act
            $discovery = Get-BaselineGraphDiscovery -Resource @($script:DomainResource, $script:UserResource, $script:GroupResource) -Transport $transport -Wait $script:Wait

            # Assert
            @($discovery.Succeeded | ForEach-Object { $_.Resource }) | Should -Be @($script:DomainResource, $script:UserResource, $script:GroupResource) -Because 'a result whose order depends on completion order cannot be compared between runs'
        }
    }

    Context 'Negative: the discovery stays offline' {

        It 'reaches Graph and Exchange Online only through the injected transport' {
            # Arrange
            $script:GraphCommandInvocation = [System.Collections.Generic.List[string]]::new()
            function global:Connect-MgGraph { $script:GraphCommandInvocation.Add('Connect-MgGraph') }
            function global:Invoke-MgGraphRequest { $script:GraphCommandInvocation.Add('Invoke-MgGraphRequest') }
            function global:Get-MgUser { $script:GraphCommandInvocation.Add('Get-MgUser') }
            function global:Get-Mailbox { $script:GraphCommandInvocation.Add('Get-Mailbox') }
            $transport = New-SinglePageTransport -RequestLog $script:RequestLog

            # Act
            $null = Get-BaselineGraphDiscovery -Resource $script:RequestedResource -Transport $transport -Wait $script:Wait

            # Assert
            try {
                $script:GraphCommandInvocation | Should -BeNullOrEmpty -Because 'the discovery must never contact a tenant of its own accord'
            }
            finally {
                Remove-Item -Path 'function:global:Connect-MgGraph', 'function:global:Invoke-MgGraphRequest', 'function:global:Get-MgUser', 'function:global:Get-Mailbox' -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Positive: a mixed-outcome resource set is reported whole and incomplete' {

        It 'returns every succeeded resource in requested order with its complete items and exactly one named failure' {
            # Arrange
            $transport = $script:MixedTransport

            # Act
            $discovery = Get-BaselineGraphDiscovery -Resource $script:RequestedResource -Transport $transport -Wait $script:Wait

            # Assert
            $summary = @(
                'Complete=' + $discovery.Complete
                'Succeeded=' + (@($discovery.Succeeded | ForEach-Object { '{0}:{1}' -f $_.Resource, (@($_.Value) -join ',') }) -join '|')
                'Failed=' + (@($discovery.Failed | ForEach-Object { '{0}:{1}' -f $_.Resource, $_.Reason.Split(':')[0] }) -join '|')
                'Waited=' + (@($script:WaitLog) -join ',')
            ) -join '; '

            $summary | Should -Be (@(
                    'Complete=False'
                    'Succeeded=users:alice,bob,carol|groups:sales'
                    'Failed=domains:GraphResourceNotFound'
                    'Waited=2'
                ) -join '; ') -Because 'a resource set in which one resource pages, one is throttled and one is refused is reported whole, in requested order, and never as complete'
        }
    }
}
