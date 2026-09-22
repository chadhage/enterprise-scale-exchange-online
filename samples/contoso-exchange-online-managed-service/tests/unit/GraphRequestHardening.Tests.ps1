#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph is not installed and must never be imported. Every response is canned and
    # handed to the request through the injected transport, and every retry delay is handed to an
    # injected wait, so a retry is exercised without any test ever sleeping.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:Resource = 'users'
    $script:PageTwoLink = 'https://graph.microsoft.com/v1.0/users?$skiptoken=page2'
    $script:PageThreeLink = 'https://graph.microsoft.com/v1.0/users?$skiptoken=page3'

    function New-GraphPage {
        [CmdletBinding()]
        param(
            [int]$Status = 200,
            [object[]]$Value,
            [string]$NextLink,
            [object]$RetryAfterSeconds,
            [string[]]$Omit = @()
        )

        $page = [ordered]@{ status = $Status }
        if ($PSBoundParameters.ContainsKey('Value')) { $page['value'] = @($Value) }
        if ($PSBoundParameters.ContainsKey('NextLink')) { $page['@odata.nextLink'] = $NextLink }
        if ($PSBoundParameters.ContainsKey('RetryAfterSeconds')) { $page['retryAfterSeconds'] = $RetryAfterSeconds }

        foreach ($name in $Omit) { $page.Remove($name) }

        return [pscustomobject]$page
    }

    # A transport that replays a fixed sequence of responses and records every URI it was asked for,
    # so an assertion can pin the exact number of attempts and the exact continuation links followed.
    function New-SequenceTransport {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]]$Response,

            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [System.Collections.Generic.List[string]]$RequestLog
        )

        $sequence = @($Response)
        $log = $RequestLog
        return {
            param($Uri)

            $log.Add([string]$Uri)
            $index = [Math]::Min($log.Count - 1, $sequence.Count - 1)
            return $sequence[$index]
        }.GetNewClosure()
    }

    # A transport that always answers with the same response, used wherever the assertion is about
    # exhaustion or refusal rather than about a sequence.
    function New-ConstantTransport {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Response,

            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [System.Collections.Generic.List[string]]$RequestLog
        )

        $answer = $Response
        $log = $RequestLog
        return {
            param($Uri)

            $log.Add([string]$Uri)
            return $answer
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
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'LIC-004-A1 hardened single Graph request' {

    BeforeEach {
        $script:RequestLog = [System.Collections.Generic.List[string]]::new()
        $script:WaitLog = [System.Collections.Generic.List[object]]::new()
        $script:Wait = New-RecordingWait -WaitLog $script:WaitLog
    }

    Context 'Negative: the request inputs must be usable' {

        It 'refuses a request without a transport' {
            # Arrange
            $absentTransport = $null

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $absentTransport -Wait $script:Wait }

            # Assert
            $request | Should -Throw -ExpectedMessage 'GraphTransportRequired*' -Because 'a request with nowhere to send itself must never be read as a request that returned nothing'
        }

        It 'refuses a request without a resource' {
            # Arrange
            $transport = New-ConstantTransport -Response (New-GraphPage -Value @()) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource '   ' -Transport $transport -Wait $script:Wait }

            # Assert
            $request | Should -Throw -ExpectedMessage 'GraphResourceRequired*' -Because 'a blank resource addresses nothing and must not be sent'
        }

        It 'refuses a request without an injected wait' {
            # Arrange
            $transport = New-ConstantTransport -Response (New-GraphPage -Value @()) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $null }

            # Assert
            $request | Should -Throw -ExpectedMessage 'RetryWaitRequired*' -Because 'retry needs a clock, and an injected clock is the only clock this module may hold'
        }

        It 'refuses a maximum attempt count below one' {
            # Arrange
            $transport = New-ConstantTransport -Response (New-GraphPage -Value @()) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait -MaximumAttempt 0 }

            # Assert
            $request | Should -Throw -ExpectedMessage 'MaximumAttemptOutOfRange*' -Because 'a request that is never attempted cannot report what the tenant holds'
        }

        It 'refuses a maximum page count below one' {
            # Arrange
            $transport = New-ConstantTransport -Response (New-GraphPage -Value @()) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait -MaximumPage 0 }

            # Assert
            $request | Should -Throw -ExpectedMessage 'MaximumPageOutOfRange*' -Because 'a page budget of zero would return an empty result for a populated tenant'
        }
    }

    Context 'Negative: the response must be usable' {

        It 'refuses a null response' {
            # Arrange
            $transport = New-ConstantTransport -Response $null -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait }

            # Assert
            $request | Should -Throw -ExpectedMessage 'GraphResponseMissing*' -Because 'nothing at all is an error, not an empty collection'
        }

        It 'refuses a response that declares no status' {
            # Arrange
            $transport = New-ConstantTransport -Response (New-GraphPage -Value @() -Omit @('status')) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait }

            # Assert
            $request | Should -Throw -ExpectedMessage 'GraphResponseContractViolation*status*' -Because 'a response whose outcome is unstated cannot be judged succeeded'
        }

        It 'refuses a status outside the handled vocabulary' {
            # Arrange
            $transport = New-ConstantTransport -Response (New-GraphPage -Status 418 -Value @()) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait }

            # Assert
            $request | Should -Throw -ExpectedMessage 'UnexpectedGraphStatus*418*' -Because 'an unrecognized status must never be guessed into a success'
        }

        It 'refuses a successful response that declares no value' {
            # Arrange
            $transport = New-ConstantTransport -Response (New-GraphPage) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait }

            # Assert
            $request | Should -Throw -ExpectedMessage 'GraphResponseContractViolation*value*' -Because 'a page missing its value member is unreadable, not empty'
        }

        It 'refuses a value that is not a collection' {
            # Arrange
            $transport = New-ConstantTransport -Response ([pscustomobject]@{ status = 200; value = 'alice@contoso.example' }) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait }

            # Assert
            $request | Should -Throw -ExpectedMessage 'GraphResponseValueNotACollection*' -Because 'a scalar cannot be enumerated into a page of results'
        }

        It 'refuses a continuation link that is not a resource address' {
            # Arrange
            $transport = New-ConstantTransport -Response ([pscustomobject]@{ status = 200; value = @('alice'); '@odata.nextLink' = 42 }) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait }

            # Assert
            $request | Should -Throw -ExpectedMessage 'GraphNextLinkInvalid*' -Because 'an unfollowable continuation link silently truncates the result'
        }
    }

    Context 'Negative: a refusal is reported, never retried' {

        It 'names the refusal' -ForEach @(
            @{ Status = 400; Expected = 'GraphRequestInvalid*' }
            @{ Status = 401; Expected = 'GraphRequestUnauthorized*' }
            @{ Status = 403; Expected = 'GraphRequestForbidden*' }
            @{ Status = 404; Expected = 'GraphResourceNotFound*' }
        ) {
            # Arrange
            $transport = New-ConstantTransport -Response (New-GraphPage -Status $Status) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait }

            # Assert
            $request | Should -Throw -ExpectedMessage $Expected -Because "status $Status has one deterministic meaning and the caller must be told which"
        }

        It 'does not retry a refusal' -ForEach @(
            @{ Status = 400 }
            @{ Status = 401 }
            @{ Status = 403 }
            @{ Status = 404 }
        ) {
            # Arrange
            $transport = New-ConstantTransport -Response (New-GraphPage -Status $Status) -RequestLog $script:RequestLog

            # Act
            try { $null = Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait } catch { }

            # Assert
            $script:RequestLog.Count | Should -Be 1 -Because "status $Status will not change by asking again, so retrying it only delays the failure"
        }
    }

    Context 'Negative: a transient failure is bounded' {

        It 'reports a throttled resource rather than an empty one when the attempts are exhausted' {
            # Arrange
            $transport = New-ConstantTransport -Response (New-GraphPage -Status 429 -RetryAfterSeconds 1) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait -MaximumAttempt 3 }

            # Assert
            $request | Should -Throw -ExpectedMessage 'GraphThrottled*' -Because 'a tenant that never answered has not reported that it holds nothing'
        }

        It 'reports an unavailable resource rather than an empty one when the attempts are exhausted' {
            # Arrange
            $transport = New-ConstantTransport -Response (New-GraphPage -Status 503) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait -MaximumAttempt 3 }

            # Assert
            $request | Should -Throw -ExpectedMessage 'GraphRequestFailed*503*' -Because 'an unavailable service is an error, not an absence of data'
        }

        It 'does not retry past the maximum attempt count' {
            # Arrange
            $transport = New-ConstantTransport -Response (New-GraphPage -Status 429 -RetryAfterSeconds 1) -RequestLog $script:RequestLog

            # Act
            try { $null = Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait -MaximumAttempt 3 } catch { }

            # Assert
            $script:RequestLog.Count | Should -Be 3 -Because 'an unbounded retry turns one throttled tenant into a hung deployment'
        }

        It 'does not wait a delay the service asked for in the negative' {
            # Arrange
            $transport = New-SequenceTransport -Response @(
                (New-GraphPage -Status 429 -RetryAfterSeconds -5)
                (New-GraphPage -Value @('alice'))
            ) -RequestLog $script:RequestLog

            # Act
            $null = Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait

            # Assert
            @($script:WaitLog) | Should -Be @(1) -Because 'a negative delay is not a delay, so the bounded backoff is used instead'
        }

        It 'does not wait an unbounded delay the service asked for' {
            # Arrange
            $transport = New-SequenceTransport -Response @(
                (New-GraphPage -Status 429 -RetryAfterSeconds 86400)
                (New-GraphPage -Value @('alice'))
            ) -RequestLog $script:RequestLog

            # Act
            $null = Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait

            # Assert
            @($script:WaitLog) | Should -Be @(60) -Because 'a day-long Retry-After must cap, not stall the run'
        }
    }

    Context 'Negative: pagination terminates and never truncates' {

        It 'refuses a continuation link that returns to a page already read' {
            # Arrange
            $transport = New-ConstantTransport -Response (New-GraphPage -Value @('alice') -NextLink $script:Resource) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait }

            # Assert
            $request | Should -Throw -ExpectedMessage 'GraphPaginationLoop*' -Because 'a continuation cycle never terminates and never completes the result'
        }

        It 'refuses to page past the page budget' {
            # Arrange
            $transport = New-SequenceTransport -Response @(
                (New-GraphPage -Value @('alice') -NextLink $script:PageTwoLink)
                (New-GraphPage -Value @('bob') -NextLink $script:PageThreeLink)
                (New-GraphPage -Value @('carol') -NextLink 'https://graph.microsoft.com/v1.0/users?$skiptoken=page4')
            ) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait -MaximumPage 2 }

            # Assert
            $request | Should -Throw -ExpectedMessage 'GraphPageLimitExceeded*' -Because 'silently stopping at the budget would report a partial tenant as the whole tenant'
        }

        It 'does not return the pages it did read when a later page fails' {
            # Arrange
            $transport = New-SequenceTransport -Response @(
                (New-GraphPage -Value @('alice') -NextLink $script:PageTwoLink)
                (New-GraphPage -Status 500)
            ) -RequestLog $script:RequestLog

            # Act
            $request = { Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait -MaximumAttempt 2 }

            # Assert
            $request | Should -Throw -ExpectedMessage 'GraphRequestFailed*' -Because 'a truncated page set is indistinguishable from a small tenant and must never be returned'
        }
    }

    Context 'Negative: the request stays offline' {

        It 'reaches Graph and Exchange Online only through the injected transport' {
            # Arrange
            $script:GraphCommandInvocation = [System.Collections.Generic.List[string]]::new()
            function global:Connect-MgGraph { $script:GraphCommandInvocation.Add('Connect-MgGraph') }
            function global:Invoke-MgGraphRequest { $script:GraphCommandInvocation.Add('Invoke-MgGraphRequest') }
            function global:Get-MgUser { $script:GraphCommandInvocation.Add('Get-MgUser') }
            function global:Get-Mailbox { $script:GraphCommandInvocation.Add('Get-Mailbox') }
            $transport = New-ConstantTransport -Response (New-GraphPage -Value @('alice')) -RequestLog $script:RequestLog

            # Act
            $null = Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait

            # Assert
            try {
                $script:GraphCommandInvocation | Should -BeNullOrEmpty -Because 'the request must never contact a tenant of its own accord'
            }
            finally {
                Remove-Item -Path 'function:global:Connect-MgGraph', 'function:global:Invoke-MgGraphRequest', 'function:global:Get-MgUser', 'function:global:Get-Mailbox' -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Positive: a throttled, paged resource is read whole' {

        It 'returns every item of every page in page order after the expected attempts and the honoured wait' {
            # Arrange
            $transport = New-SequenceTransport -Response @(
                (New-GraphPage -Status 429 -RetryAfterSeconds 2)
                (New-GraphPage -Value @('alice', 'bob') -NextLink $script:PageTwoLink)
                (New-GraphPage -Value @('carol'))
            ) -RequestLog $script:RequestLog

            # Act
            $result = Invoke-BaselineGraphRequest -Resource $script:Resource -Transport $transport -Wait $script:Wait

            # Assert
            $summary = @(
                'Resource=' + $result.Resource
                'Value=' + (@($result.Value) -join ',')
                'PageCount=' + $result.PageCount
                'AttemptCount=' + $result.AttemptCount
                'Requested=' + (@($script:RequestLog) -join ',')
                'Waited=' + (@($script:WaitLog) -join ',')
            ) -join '; '

            $summary | Should -Be (@(
                    'Resource=users'
                    'Value=alice,bob,carol'
                    'PageCount=2'
                    'AttemptCount=3'
                    "Requested=users,users,$($script:PageTwoLink)"
                    'Waited=2'
                ) -join '; ') -Because 'one resource that is throttled once and then paged is read whole, in page order, with exactly one honoured wait'
        }
    }
}
