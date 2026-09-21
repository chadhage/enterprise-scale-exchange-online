#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'MDO-009 raw Tenant Allow/Block List collection' {
    Context 'Negative: the injected collection seam is the only collection authority' {
        It 'exports the collector declared for MDO-007' {
            # Arrange
            $collectorName = 'Get-TenantAllowBlockListEvidence'

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $collectorName -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count | Should -Be 1
        }

        It 'refuses to manufacture evidence without a collection seam' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-TenantAllowBlockListEvidence -Collection $noCollection }

            # Assert
            $act | Should -Throw -ExpectedMessage 'TenantAllowBlockListCollectionRequired*'
        }
    }

    Context 'Negative: collection refusal is preserved as uncollected evidence' {
        It 'records the refusal and does not fold it into a verdict' {
            # Arrange
            $refusingCollection = { throw 'offline access refused' }

            # Act
            $evidence = Get-TenantAllowBlockListEvidence -Collection $refusingCollection

            # Assert
            $evidence.ControlId | Should -BeExactly 'MDO-007'
            $evidence.Source | Should -BeExactly 'ExchangeOnline'
            $evidence.Command | Should -BeExactly 'Get-TenantAllowBlockListItems'
            $evidence.Collected | Should -BeFalse
            $evidence.FailureReason | Should -BeLike 'CollectionFailed:*offline access refused*'
            @($evidence.Keys) | Should -Not -Contain 'Status'
        }
    }

    Context 'Negative: an empty successful observation remains evidence' {
        It 'records an empty Tenant Allow/Block List without reporting collection failure' {
            # Arrange
            $emptyCollection = { }

            # Act
            $evidence = Get-TenantAllowBlockListEvidence -Collection $emptyCollection

            # Assert
            $evidence.Collected | Should -BeTrue
            $evidence.FailureReason | Should -BeNullOrEmpty
            $evidence.Value | Should -BeNullOrEmpty
            $evidence.ControlId | Should -BeExactly 'MDO-007'
        }
    }

    Context 'Negative: collected evidence is immutable' {
        BeforeEach {
            # Arrange
            $entry = [pscustomobject]@{
                entryType         = 'Sender'
                entryValue        = 'Raw.Sender@Contoso.Example '
                action            = 'Allow'
                owner             = 'Messaging Operations'
                ticket            = 'CHG-1001'
                createdDateTime   = '2026-09-01T00:00:00.0000000Z'
                expirationDateTime = '2026-09-20T00:00:00.0000000Z'
                justification     = 'Temporary sender investigation'
            }
            $script:ImmutableEvidence = Get-TenantAllowBlockListEvidence -Collection { @($entry) }.GetNewClosure()
        }

        It 'rejects replacement of a collected entry' {
            # Arrange
            $evidence = $script:ImmutableEvidence

            # Act
            $replaceEntry = { $evidence.Value[0] = $null }

            # Assert
            $replaceEntry | Should -Throw
        }

        It 'rejects mutation of a collected entry field' {
            # Arrange
            $evidence = $script:ImmutableEvidence

            # Act
            $changeField = { $evidence.Value[0]['entryValue'] = 'normalized@contoso.example' }

            # Assert
            $changeField | Should -Throw
        }
    }

    Context 'Positive: one raw observation preserves every entry whole' {
        It 'returns one immutable evidence record containing every sender, domain, URL and file allow and block entry exactly as collected' {
            # Arrange
            $entries = @(
                [pscustomobject]@{ entryType = 'Sender'; entryValue = ' SMTP:Allow.Me@Contoso.Example '; action = 'Allow'; owner = 'Messaging Operations'; ticket = 'CHG-1001'; createdDateTime = '2026-09-01T01:02:03.0000000Z'; expirationDateTime = '2026-09-20T01:02:03.0000000Z'; justification = 'Sender allow under investigation'; serviceMetadata = 'sender-allow-raw' }
                [pscustomobject]@{ entryType = 'Sender'; entryValue = 'Block.Me@Malicious.Example'; action = 'Block'; owner = 'SOC'; ticket = 'INC-2001'; createdDateTime = '2026-08-01T02:03:04.0000000Z'; expirationDateTime = '2027-08-01T02:03:04.0000000Z'; justification = 'Confirmed sender campaign'; serviceMetadata = 'sender-block-raw' }
                [pscustomobject]@{ entryType = 'Domain'; entryValue = 'Allow.Sub.Example.'; action = 'Allow'; owner = 'Partner Security'; ticket = 'CHG-1002'; createdDateTime = '2026-09-02T03:04:05.0000000Z'; expirationDateTime = '2026-09-21T03:04:05.0000000Z'; justification = 'Exact subdomain repair window'; serviceMetadata = 'domain-allow-raw' }
                [pscustomobject]@{ entryType = 'Domain'; entryValue = '*.Blocked.Example'; action = 'Block'; owner = 'Threat Intelligence'; ticket = 'INC-2002'; createdDateTime = '2026-08-02T04:05:06.0000000Z'; expirationDateTime = '2027-08-02T04:05:06.0000000Z'; justification = 'Registered malicious domain family'; serviceMetadata = 'domain-block-raw' }
                [pscustomobject]@{ entryType = 'URL'; entryValue = 'HTTPS://Portal.Example/CaseSensitive/Path?B=2&A=1'; action = 'Allow'; owner = 'Web Security'; ticket = 'CHG-1003'; createdDateTime = '2026-09-03T05:06:07.0000000Z'; expirationDateTime = '2026-09-22T05:06:07.0000000Z'; justification = 'Exact URL false positive'; serviceMetadata = 'url-allow-raw' }
                [pscustomobject]@{ entryType = 'URL'; entryValue = 'http://malicious.example:80/dropper#fragment'; action = 'Block'; owner = 'SOC'; ticket = 'INC-2003'; createdDateTime = '2026-08-03T06:07:08.0000000Z'; expirationDateTime = '2027-08-03T06:07:08.0000000Z'; justification = 'Observed payload URL'; serviceMetadata = 'url-block-raw' }
                [pscustomobject]@{ entryType = 'File'; entryValue = 'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789'; action = 'Allow'; owner = 'Endpoint Security'; ticket = 'CHG-1004'; createdDateTime = '2026-09-04T07:08:09.0000000Z'; expirationDateTime = '2026-09-23T07:08:09.0000000Z'; justification = 'Exact file hash false positive'; serviceMetadata = 'file-allow-raw' }
                [pscustomobject]@{ entryType = 'File'; entryValue = '00abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567'; action = 'Block'; owner = 'Malware Analysis'; ticket = 'INC-2004'; createdDateTime = '2026-08-04T08:09:10.0000000Z'; expirationDateTime = '2027-08-04T08:09:10.0000000Z'; justification = 'Confirmed malicious file hash'; serviceMetadata = 'file-block-raw' }
            )
            $expected = ConvertTo-CanonicalJson -InputObject $entries

            # Act
            $evidence = Get-TenantAllowBlockListEvidence -Collection { $entries }.GetNewClosure()

            # Assert
            $evidence.ControlId | Should -BeExactly 'MDO-007'
            $evidence.Source | Should -BeExactly 'ExchangeOnline'
            $evidence.Command | Should -BeExactly 'Get-TenantAllowBlockListItems'
            $evidence.Collected | Should -BeTrue
            $evidence.FailureReason | Should -BeNullOrEmpty
            @($evidence.Value).Count | Should -Be 8
            (ConvertTo-CanonicalJson -InputObject $evidence.Value) | Should -BeExactly $expected
            @($evidence.Keys) | Should -Not -Contain 'Status'
        }
    }
}