#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-MailboxPage {
        [CmdletBinding()]
        param(
            [object[]]$Mailbox,
            [object]$ContinuationToken,
            [string[]]$Omit = @()
        )

        $page = [ordered]@{}
        if ($PSBoundParameters.ContainsKey('Mailbox')) { $page['Mailbox'] = @($Mailbox) }
        if ($PSBoundParameters.ContainsKey('ContinuationToken')) { $page['ContinuationToken'] = $ContinuationToken }
        foreach ($member in $Omit) { $page.Remove($member) }
        return [pscustomobject]$page
    }

    function New-MailboxPageCollection {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [object[]]$Page,

            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [System.Collections.Generic.List[object]]$TokenLog
        )

        $pageSequence = @($Page)
        $log = $TokenLog
        return {
            param($ContinuationToken)

            $log.Add($ContinuationToken)
            $index = $log.Count - 1
            if ($index -ge $pageSequence.Count) {
                throw 'MailboxPageFixtureExhausted'
            }

            return $pageSequence[$index]
        }.GetNewClosure()
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXO-013 complete mailbox paging' {

    BeforeEach {
        $script:TokenLog = [System.Collections.Generic.List[object]]::new()
    }

    Context 'Negative: the paging seam and bound must be valid' {

        It 'refuses an absent page collection seam' {
            # Arrange
            $pageCollection = $null

            # Act
            $collection = { Get-BaselineCompleteMailboxCollection -PageCollection $pageCollection }

            # Assert
            $collection | Should -Throw -ExpectedMessage 'MailboxPageCollectionRequired*' -Because 'mailboxes cannot be collected offline or completely without an explicit page seam'
        }

        It 'refuses a page collection value that is not executable' {
            # Arrange
            $pageCollection = 'Get-Mailbox'

            # Act
            $collection = { Get-BaselineCompleteMailboxCollection -PageCollection $pageCollection }

            # Assert
            $collection | Should -Throw -ExpectedMessage 'MailboxPageCollectionInvalid*' -Because 'a command name is not the injected executable seam this offline collector requires'
        }

        It 'refuses a maximum page count below one' {
            # Arrange
            $pageCollection = New-MailboxPageCollection -Page @(
                (New-MailboxPage -Mailbox @())
            ) -TokenLog $script:TokenLog

            # Act
            $collection = { Get-BaselineCompleteMailboxCollection -PageCollection $pageCollection -MaximumPage 0 }

            # Assert
            $collection | Should -Throw -ExpectedMessage 'MailboxMaximumPageOutOfRange*' -Because 'a zero-page budget can only manufacture an empty tenant'
        }
    }

    Context 'Negative: every page must satisfy the paging contract' {

        It 'refuses a null page' {
            # Arrange
            $pageCollection = { return $null }

            # Act
            $collection = { Get-BaselineCompleteMailboxCollection -PageCollection $pageCollection }

            # Assert
            $collection | Should -Throw -ExpectedMessage 'MailboxPageMissing*' -Because 'no response is not evidence that the page contains no mailboxes'
        }

        It 'refuses a page with no mailbox collection' {
            # Arrange
            $pageCollection = New-MailboxPageCollection -Page @(
                (New-MailboxPage -ContinuationToken $null)
            ) -TokenLog $script:TokenLog

            # Act
            $collection = { Get-BaselineCompleteMailboxCollection -PageCollection $pageCollection }

            # Assert
            $collection | Should -Throw -ExpectedMessage 'MailboxPageContractViolation*Mailbox*' -Because 'a missing result member cannot be interpreted as an empty page'
        }

        It 'refuses a mailbox payload that is not a collection' {
            # Arrange
            $pageCollection = { [pscustomobject]@{ Mailbox = 'alice@contoso.example'; ContinuationToken = $null } }

            # Act
            $collection = { Get-BaselineCompleteMailboxCollection -PageCollection $pageCollection }

            # Assert
            $collection | Should -Throw -ExpectedMessage 'MailboxPageValueNotACollection*' -Because 'a scalar mailbox payload is a malformed page, not a one-record page'
        }

        It 'refuses a continuation token that is not a nonblank string' {
            # Arrange
            $pageCollection = New-MailboxPageCollection -Page @(
                [pscustomobject]@{ Mailbox = @(); ContinuationToken = 42 }
            ) -TokenLog $script:TokenLog

            # Act
            $collection = { Get-BaselineCompleteMailboxCollection -PageCollection $pageCollection }

            # Assert
            $collection | Should -Throw -ExpectedMessage 'MailboxContinuationTokenInvalid*' -Because 'an unfollowable token would silently truncate the mailbox population'
        }

        It 'refuses a blank continuation token' {
            # Arrange
            $pageCollection = New-MailboxPageCollection -Page @(
                (New-MailboxPage -Mailbox @() -ContinuationToken '   ')
            ) -TokenLog $script:TokenLog

            # Act
            $collection = { Get-BaselineCompleteMailboxCollection -PageCollection $pageCollection }

            # Assert
            $collection | Should -Throw -ExpectedMessage 'MailboxContinuationTokenInvalid*' -Because 'blank continuation cannot distinguish completion from truncation'
        }
    }

    Context 'Negative: paging must terminate without losing tenant state' {

        It 'refuses a continuation token already followed' {
            # Arrange
            $pageCollection = New-MailboxPageCollection -Page @(
                (New-MailboxPage -Mailbox @([pscustomobject]@{ PrimarySmtpAddress = 'alice@contoso.example' }) -ContinuationToken 'next')
                (New-MailboxPage -Mailbox @([pscustomobject]@{ PrimarySmtpAddress = 'bob@contoso.example' }) -ContinuationToken 'next')
            ) -TokenLog $script:TokenLog

            # Act
            $collection = { Get-BaselineCompleteMailboxCollection -PageCollection $pageCollection }

            # Assert
            $collection | Should -Throw -ExpectedMessage 'MailboxPaginationLoop*next*' -Because 'following the same token twice cannot complete the tenant population'
        }

        It 'refuses a continuation beyond the page limit' {
            # Arrange
            $pageCollection = New-MailboxPageCollection -Page @(
                (New-MailboxPage -Mailbox @([pscustomobject]@{ PrimarySmtpAddress = 'alice@contoso.example' }) -ContinuationToken 'page-2')
                (New-MailboxPage -Mailbox @([pscustomobject]@{ PrimarySmtpAddress = 'bob@contoso.example' }) -ContinuationToken 'page-3')
            ) -TokenLog $script:TokenLog

            # Act
            $collection = { Get-BaselineCompleteMailboxCollection -PageCollection $pageCollection -MaximumPage 2 }

            # Assert
            $collection | Should -Throw -ExpectedMessage 'MailboxPageLimitExceeded*2*' -Because 'the page bound must fail closed instead of returning a truncated tenant'
        }

        It 'refuses duplicate mailbox identities across pages' {
            # Arrange
            $pageCollection = New-MailboxPageCollection -Page @(
                (New-MailboxPage -Mailbox @([pscustomobject]@{ PrimarySmtpAddress = 'Alice@contoso.example'; Marker = 'first' }) -ContinuationToken 'page-2')
                (New-MailboxPage -Mailbox @([pscustomobject]@{ PrimarySmtpAddress = ' alice@contoso.example '; Marker = 'second' }))
            ) -TokenLog $script:TokenLog

            # Act
            $collection = { Get-BaselineCompleteMailboxCollection -PageCollection $pageCollection }

            # Assert
            $collection | Should -Throw -ExpectedMessage 'DuplicateMailboxIdentity*alice@contoso.example*' -Because 'two records for one mailbox make downstream rule coverage ambiguous'
        }

        It 'refuses a mailbox record with no stable identity' {
            # Arrange
            $pageCollection = New-MailboxPageCollection -Page @(
                (New-MailboxPage -Mailbox @([pscustomobject]@{ DisplayName = 'Alice' }))
            ) -TokenLog $script:TokenLog

            # Act
            $collection = { Get-BaselineCompleteMailboxCollection -PageCollection $pageCollection }

            # Assert
            $collection | Should -Throw -ExpectedMessage 'MailboxIdentityMissing*' -Because 'a mailbox that cannot be named cannot be proved unique or handed to rule collection safely'
        }

        It 'does not expose partial success when a later page refuses' {
            # Arrange
            $firstMailbox = [pscustomobject]@{ PrimarySmtpAddress = 'alice@contoso.example'; Marker = 'first' }
            $pageCollection = {
                param($ContinuationToken)

                if ($null -eq $ContinuationToken) {
                    return [pscustomobject]@{ Mailbox = @($firstMailbox); ContinuationToken = 'page-2' }
                }

                throw 'MailboxPageRefused: page-2 is inaccessible'
            }.GetNewClosure()
            $result = 'not-invoked'

            # Act
            try { $result = Get-BaselineCompleteMailboxCollection -PageCollection $pageCollection } catch { $fault = $_ }

            # Assert
            @($fault.Exception.Message, $result) -join '|' |
                Should -Be 'MailboxPageRefused: page-2 is inaccessible|not-invoked' -Because 'a later refusal must throw without publishing the successful prefix as a complete collection'
        }
    }

    Context 'Positive: one complete multi-page mailbox collection' {

        It 'returns every raw mailbox in deterministic page order' {
            # Arrange
            $alice = [pscustomobject]@{ PrimarySmtpAddress = 'alice@contoso.example'; Marker = [pscustomobject]@{ Raw = 'alpha' } }
            $bob = [pscustomobject]@{ PrimarySmtpAddress = 'bob@contoso.example'; Marker = [pscustomobject]@{ Raw = 'beta' } }
            $carol = [pscustomobject]@{ PrimarySmtpAddress = 'carol@contoso.example'; Marker = [pscustomobject]@{ Raw = 'gamma' } }
            $pageCollection = New-MailboxPageCollection -Page @(
                (New-MailboxPage -Mailbox @($alice) -ContinuationToken 'page-2')
                (New-MailboxPage -Mailbox @($bob) -ContinuationToken 'page-3')
                (New-MailboxPage -Mailbox @($carol))
            ) -TokenLog $script:TokenLog

            # Act
            $result = Get-BaselineCompleteMailboxCollection -PageCollection $pageCollection

            # Assert
            $summary = @(
                'PageCount=' + $result.PageCount
                'Tokens=' + (@($script:TokenLog | ForEach-Object { if ($null -eq $_) { '<null>' } else { [string]$_ } }) -join ',')
                'Order=' + (@($result.Mailbox | ForEach-Object PrimarySmtpAddress) -join ',')
                'Raw=' + ([object]::ReferenceEquals($alice, $result.Mailbox[0]) -and [object]::ReferenceEquals($bob, $result.Mailbox[1]) -and [object]::ReferenceEquals($carol, $result.Mailbox[2]))
            ) -join '; '

            $summary | Should -Be 'PageCount=3; Tokens=<null>,page-2,page-3; Order=alice@contoso.example,bob@contoso.example,carol@contoso.example; Raw=True' -Because 'the complete result must preserve each page, mailbox order and untouched mailbox object'
        }
    }
}