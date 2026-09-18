#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # Microsoft.Graph and ExchangeOnlineManagement are not installed and must never be imported.
    # A parameter-file hash is decided from a file on disk, so nothing here reaches a service.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-ParameterFixture {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Name,

            [Parameter(Mandatory)]
            [string]$Content
        )

        $path = Join-Path $TestDrive $Name
        Set-Content -LiteralPath $path -Value $Content -Encoding utf8
        return $path
    }

    function Get-ExpectedHash {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [System.Collections.IDictionary]$Record
        )

        $canonical = ConvertTo-CanonicalJson -InputObject $Record
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($canonical)
        return [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EVD-004-A1 non-sensitive parameter-file hash' {

    Context 'Negative: the parameter file must be named, present and readable' {

        It 'refuses a parameter file that is not named' {
            # Arrange
            $noPath = $null

            # Act
            $result = { Get-BaselineParameterHash -Path $noPath }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ParameterPathRequired*' -Because 'an evidence envelope that identifies no parameter file cannot prove which administrator inputs the run was held to'
        }

        It 'refuses a parameter file whose path is blank' {
            # Arrange
            $blankPath = '   '

            # Act
            $result = { Get-BaselineParameterHash -Path $blankPath }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ParameterPathRequired*' -Because 'whitespace names no file any more than nothing does'
        }

        It 'refuses a parameter file that does not exist' {
            # Arrange
            $absentPath = Join-Path $TestDrive 'no-such-parameters.json'

            # Act
            $result = { Get-BaselineParameterHash -Path $absentPath }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ParameterFileNotFound*' -Because 'hashing an absent file would stamp every such run with one identical identity and hide that the inputs were never read'
        }

        It 'refuses a parameter file that is not valid JSON' {
            # Arrange
            $malformedPath = New-ParameterFixture -Name 'malformed-parameters.json' -Content '{ "primaryDomain": '

            # Act
            $result = { Get-BaselineParameterHash -Path $malformedPath }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ParameterJsonInvalid*' -Because 'a truncated file still has bytes to hash, so hashing bytes would report a confident identity for inputs nothing could read'
        }

        It 'refuses a parameter document that is not a JSON object' {
            # Arrange
            $arrayPath = New-ParameterFixture -Name 'array-parameters.json' -Content '[ "contoso.com" ]'

            # Act
            $result = { Get-BaselineParameterHash -Path $arrayPath }

            # Assert
            $result | Should -Throw -ExpectedMessage 'ParameterDocumentNotObject*' -Because 'administrator inputs are named values, and a document with no names has no parameter to redact or to report'
        }
    }

    Context 'Negative: a sensitive value must never reach the hash' {

        It 'returns the same hash when only a sensitive value differs' {
            # Arrange
            $first = New-ParameterFixture -Name 'secret-first.json' -Content '{ "primaryDomain": "contoso.com", "clientSecret": "aaaaaaaaaaaa" }'
            $second = New-ParameterFixture -Name 'secret-second.json' -Content '{ "primaryDomain": "contoso.com", "clientSecret": "bbbbbbbbbbbb" }'
            $firstHash = (Get-BaselineParameterHash -Path $first).Hash

            # Act
            $secondHash = (Get-BaselineParameterHash -Path $second).Hash

            # Assert
            $secondHash | Should -BeExactly $firstHash -Because 'a hash that moves with a secret is an offline oracle for that secret, and the envelope is published to people who are not cleared to hold it'
        }

        It 'names every sensitive parameter it redacted' {
            # Arrange
            $path = New-ParameterFixture -Name 'named-redaction.json' -Content '{ "primaryDomain": "contoso.com", "clientSecret": "s", "signingCertificateThumbprint": "t", "apiToken": "k" }'

            # Act
            $hash = Get-BaselineParameterHash -Path $path

            # Assert
            (@($hash.RedactedParameter) -join '+') |
                Should -BeExactly 'apiToken+clientSecret+signingCertificateThumbprint' `
                    -Because 'a reader who cannot see which inputs were withheld cannot tell a redacted envelope from one whose parameters simply never existed'
        }
    }

    Context 'Negative: everything that is not sensitive must reach the hash' {

        It 'returns a different hash when a non-sensitive value differs' {
            # Arrange
            $first = New-ParameterFixture -Name 'domain-first.json' -Content '{ "primaryDomain": "contoso.com", "clientSecret": "s" }'
            $second = New-ParameterFixture -Name 'domain-second.json' -Content '{ "primaryDomain": "fabrikam.com", "clientSecret": "s" }'
            $firstHash = (Get-BaselineParameterHash -Path $first).Hash

            # Act
            $secondHash = (Get-BaselineParameterHash -Path $second).Hash

            # Assert
            $secondHash | Should -Not -BeExactly $firstHash -Because 'a hash that ignores the inputs is non-sensitive and also worthless, because two runs against different tenants would carry one identity'
        }

        It 'returns a different hash when a sensitive parameter is added' {
            # Arrange
            $without = New-ParameterFixture -Name 'without-secret.json' -Content '{ "primaryDomain": "contoso.com" }'
            $with = New-ParameterFixture -Name 'with-secret.json' -Content '{ "primaryDomain": "contoso.com", "clientSecret": "s" }'
            $withoutHash = (Get-BaselineParameterHash -Path $without).Hash

            # Act
            $withHash = (Get-BaselineParameterHash -Path $with).Hash

            # Assert
            $withHash | Should -Not -BeExactly $withoutHash -Because 'redacting a value is not the same as dropping the parameter, and a run that newly supplies a credential is a different run'
        }

        It 'returns the same hash when the same parameters are written in a different order' {
            # Arrange
            $first = New-ParameterFixture -Name 'order-first.json' -Content '{ "primaryDomain": "contoso.com", "securityGroupName": "Priority" }'
            $second = New-ParameterFixture -Name 'order-second.json' -Content "{`n  `"securityGroupName`":  `"Priority`",`n  `"primaryDomain`": `"contoso.com`"`n}"
            $firstHash = (Get-BaselineParameterHash -Path $first).Hash

            # Act
            $secondHash = (Get-BaselineParameterHash -Path $second).Hash

            # Assert
            $secondHash | Should -BeExactly $firstHash -Because 'hashing the file bytes would make reformatting look like a configuration change and bury the changes that matter in noise'
        }
    }

    Context 'Negative: the hash cannot be edited after it is computed' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $path = New-ParameterFixture -Name 'immutable-hash.json' -Content '{ "primaryDomain": "contoso.com" }'
            $hash = Get-BaselineParameterHash -Path $path

            # Act
            $act = { $hash.Hash = '0' }

            # Assert
            $act | Should -Throw -Because 'an identity a caller can rewrite lets an envelope claim inputs the run never used'
        }

        It 'returns a result that rejects a new member' {
            # Arrange
            $path = New-ParameterFixture -Name 'sealed-hash.json' -Content '{ "primaryDomain": "contoso.com" }'
            $hash = Get-BaselineParameterHash -Path $path

            # Act
            $act = { $hash.PlainText = 'contoso.com' }

            # Assert
            $act | Should -Throw -Because 'a member added after the redaction is a value the redaction never cleared, and it travels in the published envelope'
        }
    }

    Context 'Positive: the hash identifies the parameter file without carrying its secrets' {

        It 'returns the SHA-256 of the canonical parameter record with every sensitive value redacted' {
            # Arrange
            $path = New-ParameterFixture -Name 'positive-parameters.json' -Content '{ "primaryDomain": "contoso.com", "securityGroupName": "Priority Users", "clientSecret": "never-hashed" }'
            $expected = '{0}|redacted={1}|{2}' -f 'SHA256', 'clientSecret', (Get-ExpectedHash -Record ([ordered]@{
                        clientSecret      = '(redacted)'
                        primaryDomain     = 'contoso.com'
                        securityGroupName = 'Priority Users'
                    }))

            # Act
            $hash = Get-BaselineParameterHash -Path $path

            # Assert
            ('{0}|redacted={1}|{2}' -f $hash.Algorithm, (@($hash.RedactedParameter) -join '+'), $hash.Hash) |
                Should -BeExactly $expected `
                    -Because 'the envelope must identify the exact administrator inputs a run used while carrying none of the values that cannot be published'
        }
    }
}
